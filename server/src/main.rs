mod cgroup;
mod protocol;
mod session;

use anyhow::{Context, Result};
use aya::{
    maps::{Array, AsyncPerfEventArray, HashMap as EbpfHashMap},
    programs::{TracePoint, Xdp, XdpFlags},
    Ebpf,
};
use bytes::BytesMut;
use clap::Parser;
use gateway_ebpf_common::AuditEvent;
use quinn::{Endpoint, ServerConfig};
use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    #[arg(long, default_value = "../certs/ca.crt")]
    ca: PathBuf,

    #[arg(long, default_value = "../certs/server.crt")]
    cert: PathBuf,

    #[arg(long, default_value = "../certs/server.key")]
    key: PathBuf,

    #[arg(long, env = "GATEWAY_TOKEN", default_value = "secret-token")]
    token: String,

    #[arg(long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let args = Args::parse();
    let addr = format!("0.0.0.0:{}", args.port).parse::<SocketAddr>()?;

    let token = Arc::new(args.token);

    let server_config = configure_server(&args.ca, &args.cert, &args.key)?;
    let endpoint = Endpoint::server(server_config, addr)?;

    tracing::info!("QUIC Server listening on {}", endpoint.local_addr()?);

    // XDP Loader Routine
    let bpf_path = "target/bpfel-unknown-none/release/gateway-ebpf";
    let mut bpf = Ebpf::load_file(bpf_path).context("Failed to load eBPF XDP program")?;

    let program: &mut Xdp = bpf.program_mut("gateway_ebpf").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&args.iface, XdpFlags::default())
        .context("Failed to attach XDP program")?;
    tracing::info!("XDP Program attached to interface: {}", args.iface);

    // Calculate time offset: UNIX Nano - Uptime Nano
    let uptime_str = fs::read_to_string("/proc/uptime").context("Failed to read uptime")?;
    let uptime_secs: f64 = uptime_str
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let uptime_ns = (uptime_secs * 1_000_000_000.0) as u64;
    let unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let time_delta = unix_ns.saturating_sub(uptime_ns);

    let mut time_delta_map: Array<_, u64> =
        Array::try_from(bpf.map_mut("TIME_DELTA_MAP").unwrap())?;
    time_delta_map.set(0, time_delta, 0)?;
    tracing::info!("TIME_DELTA_MAP initialized with offset: {} ns", time_delta);

    // Load and attach the audit_execve Tracepoint
    let audit_prog: &mut TracePoint = bpf.program_mut("audit_execve").unwrap().try_into()?;
    audit_prog.load()?;
    audit_prog.attach("syscalls", "sys_enter_execve")?;
    tracing::info!("audit_execve tracepoint attached to sys_enter_execve");

    // Leak bpf to make it 'static — it must live for the duration of the process
    let bpf: &'static mut Ebpf = Box::leak(Box::new(bpf));

    // Extract AUDIT_CGROUP_MAP before perf_array borrows bpf, so we can move it to the
    // cgroup registration task independently.
    let audit_cgroup_map: EbpfHashMap<_, u64, u8> = EbpfHashMap::try_from(
        bpf.take_map("AUDIT_CGROUP_MAP")
            .ok_or_else(|| anyhow::anyhow!("AUDIT_CGROUP_MAP not found"))?,
    )?;

    // Consume AuditEvents: spawn one async task per online CPU via AsyncPerfEventArray
    let mut perf_array: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(
        bpf.take_map("AUDIT_EVENTS")
            .ok_or_else(|| anyhow::anyhow!("AUDIT_EVENTS map not found"))?,
    )?;
    let cpus = aya::util::online_cpus().unwrap_or_else(|_| vec![0]);

    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        tokio::spawn(async move {
            let mut buffers: Vec<BytesMut> =
                (0..10).map(|_| BytesMut::with_capacity(512)).collect();
            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(e) => e,
                    Err(_) => break,
                };
                for i in 0..events.read {
                    let bytes = &buffers[i];
                    if bytes.len() >= core::mem::size_of::<AuditEvent>() {
                        let event: AuditEvent = unsafe {
                            core::ptr::read_unaligned(bytes.as_ptr() as *const AuditEvent)
                        };
                        let filename = bytes_to_str(&event.filename);
                        let args_len = (event.args_len as usize).min(256);
                        let args = bytes_to_str(&event.args[..args_len]);
                        tracing::info!(
                            "[AUDIT] cgroup={} uid={} pid={} tid={} exec=\"{}\" argv0=\"{}\"",
                            event.cgroup_id,
                            event.uid,
                            event.pid,
                            event.tid,
                            filename,
                            args
                        );
                    }
                }
            }
        });
    }

    // Spawn Health Server for K8s Probes
    tokio::spawn(async move {
        let health_addr: SocketAddr = "0.0.0.0:8081".parse().unwrap();
        if let Ok(listener) = tokio::net::TcpListener::bind(health_addr).await {
            tracing::info!("Health probe listening on {}", health_addr);
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = [0; 128];
                    // Very simple HTTP check: Read the first few bytes and see if it looks like a GET request
                    if let Ok(Ok(n)) = tokio::time::timeout(
                        std::time::Duration::from_secs(1),
                        stream.read(&mut buf),
                    )
                    .await
                    {
                        if n >= 4 && &buf[0..4] == b"GET " {
                            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                            let _ = stream.write_all(response).await;
                        } else {
                            // If it's not a GET request, just close it or send 400 Bad Request
                            let response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request";
                            let _ = stream.write_all(response).await;
                        }
                    }
                }
            }
        } else {
            tracing::error!("Failed to bind health probe on {}", health_addr);
        }
    });

    // Set up a channel so session handlers can signal new cgroup IDs to be registered
    // in the AUDIT_CGROUP_MAP eBPF map. audit_cgroup_map is moved into this task.
    let (cgroup_tx, mut cgroup_rx) = tokio::sync::mpsc::channel::<u64>(64);
    tokio::spawn(async move {
        let mut cgroup_map = audit_cgroup_map;
        while let Some(cgroup_id) = cgroup_rx.recv().await {
            let _ = cgroup_map.insert(cgroup_id, 1u8, 0);
            tracing::info!(
                "[AUDIT] Registered cgroup_id={} in AUDIT_CGROUP_MAP",
                cgroup_id
            );
        }
    });

    while let Some(conn) = endpoint.accept().await {
        let token_clone = Arc::clone(&token);
        let cgroup_tx_clone = cgroup_tx.clone();
        tokio::spawn(async move {
            let remote = conn.remote_address();
            tracing::info!("Connection initialized from {}", remote);
            let connection = match conn.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Connection failed from {}: {}", remote, e);
                    return;
                }
            };

            // Log Client Auth Info
            if let Some(identity) = connection.peer_identity() {
                if let Some(certs) =
                    identity.downcast_ref::<Vec<rustls::pki_types::CertificateDer>>()
                {
                    if let Some(cert) = certs.first() {
                        tracing::info!(
                            "Client authenticated with cert size: {} bytes",
                            cert.as_ref().len()
                        );
                    }
                }
            } else {
                tracing::warn!("Client connected without identity (should be rejected by rustls)");
            }

            if let Err(e) = handle_connection(connection, &token_clone, cgroup_tx_clone).await {
                tracing::error!("Connection error with {}: {:?}", remote, e);
            }
        });
    }

    Ok(())
}

fn bytes_to_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).unwrap_or("<invalid utf8>")
}

fn configure_server(
    ca_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<ServerConfig> {
    // Read CA cert
    let ca_cert_pem =
        fs::read(ca_path).with_context(|| format!("Failed to read CA cert from {:?}", ca_path))?;
    let mut ca_cert_reader = std::io::BufReader::new(ca_cert_pem.as_slice());
    let ca_certs: Vec<_> = rustls_pemfile::certs(&mut ca_cert_reader).collect::<Result<_, _>>()?;

    let mut roots = rustls::RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert)?;
    }

    // Require client auth using the CA
    let client_auth = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

    // Read Server cert
    let cert_pem = fs::read(cert_path)
        .with_context(|| format!("Failed to read server cert from {:?}", cert_path))?;
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let cert_chain = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    // Read Server key
    let key_pem = fs::read(key_path)
        .with_context(|| format!("Failed to read server key from {:?}", key_path))?;
    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let priv_key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(cert_chain, priv_key)?;
    server_crypto.alpn_protocols = shared::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    // Customize transport config
    let mut transport_config = quinn::TransportConfig::default();
    // 4 hours idle timeout for long-lived PTY sessions
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(4 * 60 * 60).try_into()?,
    ));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

async fn handle_connection(
    connection: quinn::Connection,
    expected_token: &str,
    cgroup_tx: tokio::sync::mpsc::Sender<u64>,
) -> Result<()> {
    // 1. Accept Control Stream FIRST (Uni-directional)
    let control_rx = connection.accept_uni().await?;
    tracing::info!("Control Stream established");

    // 2. Handshake Phase: Verify Token & Collect Configuration
    let (handshake, mut control_rx) =
        protocol::perform_handshake(control_rx, expected_token).await?;
    tracing::info!(
        "Handshake complete: {}x{}",
        handshake.pty_size.rows,
        handshake.pty_size.cols
    );

    // 3. Execution Phase: Spawn PTY with Config
    let session = session::PtySession::new(handshake.pty_size, handshake.env_vars)?;
    let child_pid = session.child_pid;
    let mut child_guard = session.child;

    // 4a. Place the child process in a dedicated cgroupv2 for kernel-level audit
    let session_id = format!("session_{}", child_pid);
    let _session_cgroup = match cgroup::SessionCgroup::create(&session_id, child_pid) {
        Ok(cg) => {
            // Send cgroup_id to the main task, which will insert it into AUDIT_CGROUP_MAP
            cgroup_tx.send(cg.id).await.ok();
            tracing::info!("[AUDIT] Activated kernel probe for cgroup_id={}", cg.id);
            Some(cg)
        }
        Err(e) => {
            // Non-fatal: audit unavailable (e.g. running without root / cgroup support)
            tracing::warn!("[AUDIT] Could not create session cgroup: {:#}", e);
            None
        }
    };

    // We separate the pair manually because we need ownership of master
    let pair = session.pair;
    drop(pair.slave); // Allow close propagation

    let mut master_reader = pair.master.try_clone_reader()?;
    let mut master_writer = pair.master.take_writer()?;
    let pty_master = pair.master;

    // 4. Accept Data Stream (Bi-directional)
    // We expect the client to open this AFTER sending StartShell
    let (mut send, mut recv) = connection.accept_bi().await?;
    tracing::info!("Shell Data Stream established");

    // Use channels to bridge blocking PTY IO with async QUIC streams
    let (to_pty_tx, mut to_pty_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let (from_pty_tx, mut from_pty_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

    // Task 1: QUIC Stream Recv -> to_pty_tx
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if to_pty_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    });

    // Task 2: to_pty_rx -> PTY Writer (Blocking Thread)
    std::thread::spawn(move || {
        while let Some(data) = to_pty_rx.blocking_recv() {
            if master_writer.write_all(&data).is_err() {
                break;
            }
        }
    });

    // Task 3: PTY Reader -> from_pty_tx (Blocking Thread)
    std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match master_reader.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if from_pty_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    });

    // Task 4: from_pty_rx -> QUIC Stream Send
    tokio::spawn(async move {
        while let Some(data) = from_pty_rx.recv().await {
            if send.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
    });

    // 5. Post-Handshake Control Stream Handling (Resize Monitor)
    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<shared::ControlMessage>(16);

    // Async Task: Continue reading Control Stream
    tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        loop {
            match control_rx.read_exact(&mut len_buf).await {
                Ok(_) => {
                    let len = u32::from_be_bytes(len_buf) as usize;
                    let mut body = vec![0u8; len];
                    if control_rx.read_exact(&mut body).await.is_ok() {
                        if let Ok(msg) = serde_json::from_slice::<shared::ControlMessage>(&body) {
                            if ctrl_tx.send(msg).await.is_err() {
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }
                Err(_) => break, // Connection closed
            }
        }
    });

    // Blocking Task: PTY Master Resize
    tokio::task::spawn_blocking(move || {
        while let Some(msg) = ctrl_rx.blocking_recv() {
            match msg {
                shared::ControlMessage::Resize { rows, cols } => {
                    let _ = pty_master.resize(portable_pty::PtySize {
                        rows,
                        cols,
                        pixel_width: 0,
                        pixel_height: 0,
                    });
                }
                _ => {}
            }
        }
    });

    // 6. Supervision Loop (Event Driven)
    loop {
        tokio::select! {
            // A. Connection lost
            _ = connection.closed() => {
                tracing::info!("Supervision: Connection closed by remote. Exiting.");
                break;
            }
            // B. Shell exited
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                 if let Ok(Some(status)) = child_guard.0.try_wait() {
                     tracing::info!("Supervision: Shell exited with status: {:?}", status);
                     break;
                 }
            }
        }
    }

    Ok(())
}
