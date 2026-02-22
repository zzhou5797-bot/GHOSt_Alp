mod cgroup;
mod dataplane;
mod protocol;
mod session;

use anyhow::{Context, Result};
use aya::{
    maps::{Array, AsyncPerfEventArray, HashMap as EbpfHashMap},
    programs::{TracePoint, Xdp, XdpFlags},
    Ebpf, EbpfLoader,
};
use bytes::BytesMut;
use clap::Parser;
use gateway_ebpf_common::{AuditEvent, AuthState};
use quinn::{Endpoint, ServerConfig};
use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc,
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
    if let Ok(cgroup_procs) = std::env::var("INTERNAL_CGROUP_JOIN") {
        if cgroup_procs != "SKIP" {
            let pid = std::process::id();
            if let Err(e) = fs::write(&cgroup_procs, format!("{}\n", pid)) {
                eprintln!("FATAL: Failed to join security cgroup: {}", e);
                std::process::exit(1); // Fail-closed: do not launch an unaudited shell
            }
        }
        let mut cmd = std::process::Command::new("sh");
        let err = std::os::unix::process::CommandExt::exec(&mut cmd);
        eprintln!("Failed to exec shell: {}", err);
        std::process::exit(1);
    }

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

    // ── Map Pinning: persist all BPF maps across server restarts ────────────────────
    // EbpfLoader::map_pin_path() pins every map under /sys/fs/bpf/ghostpty/.
    // On first launch: maps are created, pinned, and loaded into the kernel.
    // On restart:      the pre-existing pinned maps are reused unchanged,
    //                  preserving AUTH_STATE_MAP hash-chain state, token
    //                  buckets, quotas, and ALLOW_LIST_MAP IP bindings.
    // Reference: https://docs.rs/aya/latest/aya/struct.EbpfLoader.html
    let bpf_fs = std::path::PathBuf::from("/sys/fs/bpf/ghostpty");
    std::fs::create_dir_all(&bpf_fs).context("Failed to create /sys/fs/bpf/ghostpty")?;

    let mut bpf = EbpfLoader::new()
        .map_pin_path(&bpf_fs)
        .load_file(bpf_path)
        .context("Failed to load eBPF XDP program")?;

    let program: &mut Xdp = bpf.program_mut("gateway_ebpf").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&args.iface, XdpFlags::default())
        .context("Failed to attach XDP program")?;
    tracing::info!("XDP Program attached to interface: {}", args.iface);

    // ── v1 compat: restore TIME_DELTA_MAP (UNIX_ns − ktime_ns offset) ──────────────────
    // Required for the dual-stack XDP path (handle_v1_knock uses this to convert
    // ktime to unix time for the 60 s recency window). Has zero cost when no v1
    // clients connect; the map slot is simply unused.
    {
        let uptime_str = fs::read_to_string("/proc/uptime").context("read /proc/uptime")?;
        let uptime_secs: f64 = uptime_str
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let uptime_ns = (uptime_secs * 1_000_000_000.0) as u64;
        let unix_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let time_delta = unix_ns.saturating_sub(uptime_ns);
        let mut time_delta_map: Array<_, u64> =
            Array::try_from(bpf.map_mut("TIME_DELTA_MAP").unwrap())?;
        time_delta_map.set(0, time_delta, 0)?;
        tracing::info!(
            "TIME_DELTA_MAP initialized: delta={} ns (v1 compat)",
            time_delta
        );
    }

    // Load and attach the audit_execve Tracepoint
    let audit_prog: &mut TracePoint = bpf.program_mut("audit_execve").unwrap().try_into()?;
    audit_prog.load()?;
    audit_prog.attach("syscalls", "sys_enter_execve")?;
    tracing::info!("audit_execve tracepoint attached to sys_enter_execve");

    // Leak bpf to make it 'static — it must live for the duration of the process
    let bpf: &'static mut Ebpf = Box::leak(Box::new(bpf));
    // SAFETY: bpf is 'static; raw-ptr reborrows prevent lifetime overlap across map calls.
    let bpf_ptr: *mut Ebpf = bpf as *mut Ebpf;

    // ALLOW_LIST_MAP: IP → subject (u32). Shared between allowlist task and GC task.
    let allow_list_map = Arc::new(tokio::sync::Mutex::new(
        EbpfHashMap::<_, u32, u32>::try_from(
            unsafe { &mut *bpf_ptr }
                .map_mut("ALLOW_LIST_MAP")
                .ok_or_else(|| anyhow::anyhow!("ALLOW_LIST_MAP not found"))?,
        )?,
    ));

    // AUTH_STATE_MAP: subject (u32) → AuthState. Shared between GC task only for now.
    let auth_state_map = Arc::new(tokio::sync::Mutex::new(
        EbpfHashMap::<_, u32, AuthState>::try_from(
            unsafe { &mut *bpf_ptr }
                .take_map("AUTH_STATE_MAP")
                .ok_or_else(|| anyhow::anyhow!("AUTH_STATE_MAP not found"))?,
        )?,
    ));

    // AUTH_STATE_MAP is managed exclusively by the GC daemon (opened after bpf leak below).

    // Extract AUDIT_CGROUP_MAP before perf_array borrows bpf, so we can move it to the
    // cgroup registration task independently.
    let audit_cgroup_map: EbpfHashMap<_, u64, u8> = EbpfHashMap::try_from(
        unsafe { &mut *bpf_ptr }
            .take_map("AUDIT_CGROUP_MAP")
            .ok_or_else(|| anyhow::anyhow!("AUDIT_CGROUP_MAP not found"))?,
    )?;

    // Consume AuditEvents: spawn one async task per online CPU via AsyncPerfEventArray
    let mut perf_array: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(
        unsafe { &mut *bpf_ptr }
            .take_map("AUDIT_EVENTS")
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

                        let mut args_vec = Vec::new();
                        let max_args = (event.args_len as usize).min(5);
                        for chunk in event.args.chunks(51).take(max_args) {
                            let end = chunk.iter().position(|&b| b == 0).unwrap_or(chunk.len());
                            if end > 0 {
                                args_vec.push(bytes_to_str(&chunk[..end]));
                            }
                        }
                        let args = args_vec.join(" ");

                        tracing::info!(
                            "[AUDIT] cgroup={} uid={} pid={} tid={} exec=\"{}\" argv=\"{}\"",
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
                    tokio::spawn(async move {
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
                    });
                }
            }
        } else {
            tracing::error!("Failed to bind health probe on {}", health_addr);
        }
    });

    // ── Map Managers ────────────────────────────────────────────────────────────────────────
    // Channel for session IP registration / deregistration
    let (allowlist_tx, mut allowlist_rx) = tokio::sync::mpsc::channel::<(u32, u32, bool)>(64);

    // allowlist_rx task: manages ALLOW_LIST_MAP updates from QUIC sessions.
    // Each message is (ip, subject, add=true|false).
    let allowlist_allow_map = Arc::clone(&allow_list_map);
    tokio::spawn(async move {
        let mut ip_ref_counts: std::collections::HashMap<u32, (u32, usize)> =
            std::collections::HashMap::new();

        while let Some((ip, subject, add)) = allowlist_rx.recv().await {
            let mut allow_map = allowlist_allow_map.lock().await;
            if add {
                let entry = ip_ref_counts.entry(ip).or_insert((subject, 0));
                entry.1 += 1;
                if entry.1 == 1 {
                    let _ = allow_map.insert(ip, subject, 0);
                    tracing::info!("ALLOW_LIST: +{} (subject={})", ip, subject);
                }
            } else if let std::collections::hash_map::Entry::Occupied(mut e) =
                ip_ref_counts.entry(ip)
            {
                let count = &mut e.get_mut().1;
                if *count > 0 {
                    *count -= 1;
                }
                if *count == 0 {
                    let _ = allow_map.remove(&ip);
                    e.remove();
                    tracing::info!("ALLOW_LIST: -{} (fully evicted)", ip);
                }
            }
        }
    });

    let (cgroup_tx, mut cgroup_rx) = tokio::sync::mpsc::channel::<(u64, bool)>(64);
    tokio::spawn(async move {
        let mut cgroup_map = audit_cgroup_map;
        while let Some((cgroup_id, add)) = cgroup_rx.recv().await {
            if add {
                let _ = cgroup_map.insert(cgroup_id, 1u8, 0);
                tracing::info!(
                    "[AUDIT] Registered cgroup_id={} in AUDIT_CGROUP_MAP",
                    cgroup_id
                );
            } else {
                let _ = cgroup_map.remove(&cgroup_id);
                tracing::info!(
                    "[AUDIT] Removed cgroup_id={} from AUDIT_CGROUP_MAP",
                    cgroup_id
                );
            }
        }
    });

    // ── M1.3: eBPF Map GC Daemon ──────────────────────────────────────────────────────────
    // Scans AUTH_STATE_MAP every GC_INTERVAL seconds.
    // Purges entries that are:
    //   (a) quota-exhausted: auth.quota_bytes == 0
    //   (b) dead sessions:   bucket_tokens == 0 AND last_refill_ns is stale (>DEAD_NS ago)
    // For each purged subject, also removes the reverse IP binding from ALLOW_LIST_MAP.
    {
        const GC_INTERVAL_SECS: u64 = 10;
        const DEAD_NS: u64 = 30_000_000_000; // 30 s with no traffic = dead session

        // GC gets clones of the shared Arc handles.
        let gc_allow_map = Arc::clone(&allow_list_map);
        let gc_auth_map = Arc::clone(&auth_state_map);

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(GC_INTERVAL_SECS));
            interval.tick().await; // skip first immediate tick

            loop {
                interval.tick().await;

                // Collect current kernel monotonic ns via /proc/uptime (user-space equivalent)
                // We use /proc/uptime to derive ktime_ns equivalent without entering kernel.
                let ktime_ns: u64 = std::fs::read_to_string("/proc/uptime")
                    .ok()
                    .and_then(|s| {
                        s.split_whitespace()
                            .next()
                            .and_then(|v| v.parse::<f64>().ok())
                    })
                    .map(|secs| (secs * 1_000_000_000.0) as u64)
                    .unwrap_or(0);

                // Collect subjects to evict
                let mut to_evict: Vec<u32> = Vec::new();
                let auth_map = gc_auth_map.lock().await;
                let subjects: Vec<u32> = auth_map.keys().filter_map(|r| r.ok()).collect();

                for subject in &subjects {
                    if let Ok(state) = auth_map.get(subject, 0) {
                        let is_exhausted = state.quota_bytes == 0;
                        let elapsed = ktime_ns.saturating_sub(state.last_refill_ns);
                        let is_dead = state.bucket_tokens == 0 && elapsed > DEAD_NS;

                        if is_exhausted {
                            tracing::info!("[GC] subject={} quota exhausted — evicting", subject);
                            to_evict.push(*subject);
                        } else if is_dead {
                            tracing::info!(
                                "[GC] subject={} idle {}s — evicting dead session",
                                subject,
                                elapsed / 1_000_000_000
                            );
                            to_evict.push(*subject);
                        }
                    }
                }

                // Also collect any IP entries whose subject has been evicted
                let allow_map = gc_allow_map.lock().await;
                let ips_to_remove: Vec<u32> = allow_map
                    .iter()
                    .filter_map(|r| r.ok())
                    .filter(|(_, subj)| to_evict.contains(subj))
                    .map(|(ip, _)| ip)
                    .collect();
                drop(allow_map);

                {
                    let mut auth_map = gc_auth_map.lock().await;
                    for subject in &to_evict {
                        let _ = auth_map.remove(subject);
                    }
                }
                {
                    let mut allow_map = gc_allow_map.lock().await;
                    for ip in &ips_to_remove {
                        let _ = allow_map.remove(ip);
                        tracing::info!("[GC] removed ALLOW_LIST entry for ip={}", ip);
                    }
                }

                if !to_evict.is_empty() {
                    tracing::info!("[GC] cycle complete: evicted {} session(s)", to_evict.len());
                }
            }
        });
    }

    while let Some(conn) = endpoint.accept().await {
        let token_clone = Arc::clone(&token);
        let cgroup_tx_clone = cgroup_tx.clone();
        let allowlist_tx_clone = allowlist_tx.clone();
        let auth_map_clone = Arc::clone(&auth_state_map);
        tokio::spawn(async move {
            let remote = conn.remote_address();
            let client_ip = match remote {
                SocketAddr::V4(v4) => u32::from_be_bytes(v4.ip().octets()),
                _ => {
                    tracing::warn!("Unsupported non-IPv4 client: {}", remote);
                    return;
                }
            };

            tracing::info!("Connection initialized from {}", remote);
            let connection = match conn.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Connection failed from {}: {}", remote, e);
                    return;
                }
            };

            // Log Client Auth Info and Parse DID Subject
            let mut client_subject = 1; // Fallback
            if let Some(identity) = connection.peer_identity() {
                if let Some(certs) =
                    identity.downcast_ref::<Vec<rustls::pki_types::CertificateDer>>()
                {
                    if let Some(cert) = certs.first() {
                        tracing::info!(
                            "Client authenticated with cert size: {} bytes",
                            cert.as_ref().len()
                        );
                        // Parse X.509 CN for DID Subject
                        if let Ok((_, x509)) = x509_parser::parse_x509_certificate(cert.as_ref()) {
                            for subject in x509.subject().iter_common_name() {
                                if let Ok(cn) = subject.attr_value().as_str() {
                                    if let Ok(parsed_subject) = cn.parse::<u32>() {
                                        client_subject = parsed_subject;
                                        tracing::info!(
                                            "Resolved DID Subject from cert CN: {}",
                                            client_subject
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                tracing::warn!("Client connected without identity (should be rejected by rustls)");
            }

            // Fetch initial quota from AUTH_STATE_MAP to initialize Atomic limits
            let initial_quota = {
                let auth_map = auth_map_clone.lock().await;
                match auth_map.get(&client_subject, 0) {
                    Ok(state) => state.quota_bytes,
                    Err(_) => {
                        // If state missing somehow, default to 1GB or drop?
                        // Usually pre-populated by SPA.
                        10 * 1024 * 1024 // Fallback to 10MB just in case
                    }
                }
            };

            let consumed_bytes = Arc::new(AtomicU64::new(0));
            let synced_bytes = Arc::new(AtomicU64::new(0));

            if let Err(e) = handle_connection(
                connection,
                &token_clone,
                cgroup_tx_clone,
                allowlist_tx_clone,
                auth_map_clone,
                client_ip,
                client_subject,
                initial_quota,
                consumed_bytes,
                synced_bytes,
            )
            .await
            {
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
    cgroup_tx: tokio::sync::mpsc::Sender<(u64, bool)>,
    allowlist_tx: tokio::sync::mpsc::Sender<(u32, u32, bool)>,
    auth_state_map: Arc<tokio::sync::Mutex<EbpfHashMap<aya::maps::MapData, u32, AuthState>>>,
    client_ip: u32,
    client_subject: u32,
    initial_quota: u64,
    consumed_bytes: Arc<AtomicU64>,
    synced_bytes: Arc<AtomicU64>,
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

    // Bind IP <-> subject in ALLOW_LIST_MAP and allow QUIC traffic
    allowlist_tx
        .send((client_ip, client_subject, true))
        .await
        .ok();

    // 3. Prepare empty Session Cgroup FIRST
    static SESSION_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let session_idx = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let session_id = format!("session_{}", session_idx);
    let _session_cgroup = match cgroup::SessionCgroup::create_empty(&session_id) {
        Ok(cg) => {
            // Send cgroup_id to the main task to insert into AUDIT_CGROUP_MAP
            cgroup_tx.send((cg.id, true)).await.ok();
            tracing::info!("[AUDIT] Activated kernel probe for cgroup_id={}", cg.id);
            Some(cg)
        }
        Err(e) => {
            tracing::warn!("[AUDIT] Could not create session cgroup: {:#}", e);
            None
        }
    };

    let cgroup_procs_path = _session_cgroup
        .as_ref()
        .map(|cg| cg.path.join("cgroup.procs"));

    // 4. Execution Phase: Spawn PTY with Config and Cgroup Hook
    let session =
        session::PtySession::new(handshake.pty_size, handshake.env_vars, cgroup_procs_path)?;
    let child_pid = session.child_pid;
    let mut child_guard = session.child;

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

    let to_pty_consumed = Arc::clone(&consumed_bytes);
    let to_pty_synced = Arc::clone(&synced_bytes);
    let to_pty_auth_map = Arc::clone(&auth_state_map);

    // Task 1: QUIC Stream Recv -> to_pty_tx
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let mut local_unreported = 0u64;
        const SYNC_THRESHOLD: u64 = 65536; // 64KB

        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    let bytes_read = n as u64;
                    local_unreported += bytes_read;

                    let total_consumed =
                        to_pty_consumed.fetch_add(bytes_read, Ordering::Relaxed) + bytes_read;

                    if total_consumed > initial_quota {
                        tracing::warn!("Guillotine: Quota exhausted on Recv task");
                        break;
                    }

                    if local_unreported >= SYNC_THRESHOLD {
                        let mut auth_map = to_pty_auth_map.lock().await;
                        if let Ok(mut state) = auth_map.get(&client_subject, 0) {
                            state.quota_bytes = state.quota_bytes.saturating_sub(local_unreported);
                            let _ = auth_map.insert(client_subject, state, 0);
                        }
                        to_pty_synced.fetch_add(local_unreported, Ordering::Relaxed);
                        local_unreported = 0;
                    }

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

    let from_pty_consumed = Arc::clone(&consumed_bytes);
    let from_pty_synced = Arc::clone(&synced_bytes);
    let from_pty_auth_map = Arc::clone(&auth_state_map);

    // Task 4: from_pty_rx -> QUIC Stream Send
    tokio::spawn(async move {
        let mut local_unreported = 0u64;
        const SYNC_THRESHOLD: u64 = 65536; // 64KB

        while let Some(data) = from_pty_rx.recv().await {
            let len = data.len() as u64;

            let total_consumed = from_pty_consumed.fetch_add(len, Ordering::Relaxed) + len;

            if total_consumed > initial_quota {
                tracing::warn!("Guillotine: Quota exhausted on Send task");
                break;
            }

            if send.write_all(&data).await.is_err() {
                break;
            }

            local_unreported += len;

            if local_unreported >= SYNC_THRESHOLD {
                let mut auth_map = from_pty_auth_map.lock().await;
                if let Ok(mut state) = auth_map.get(&client_subject, 0) {
                    state.quota_bytes = state.quota_bytes.saturating_sub(local_unreported);
                    let _ = auth_map.insert(client_subject, state, 0);
                }
                from_pty_synced.fetch_add(local_unreported, Ordering::Relaxed);
                local_unreported = 0;
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
                    // Fix 1: Bound memory allocation to prevent OOM crash
                    if len > 65536 {
                        tracing::error!("Control message too large: {} bytes", len);
                        break;
                    }

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

                 // C. Quota Guillotine Check (Fall-back)
                 if consumed_bytes.load(Ordering::Acquire) > initial_quota {
                     tracing::warn!("Supervision: Quota exhausted (Guillotine cut). Terminating session.");
                     break;
                 }
            }
        }
    }

    // Flush final consumed bytes back to BPF map
    {
        let final_consumed = consumed_bytes.load(Ordering::Acquire);
        let final_synced = synced_bytes.load(Ordering::Acquire);

        let unsynced = final_consumed.saturating_sub(final_synced);

        if unsynced > 0 {
            let mut auth_map = auth_state_map.lock().await;
            if let Ok(mut state) = auth_map.get(&client_subject, 0) {
                state.quota_bytes = state.quota_bytes.saturating_sub(unsynced);
                let _ = auth_map.insert(client_subject, state, 0);
                tracing::info!(
                    "Supervision: Synced final quota for {} (Unsynced tail: {}, Total Session Consumed: {})",
                    client_subject,
                    unsynced,
                    final_consumed
                );
            }
        }
    }

    if let Some(cg) = _session_cgroup {
        tracing::info!("[AUDIT] Deactivating kernel probe for cgroup_id={}", cg.id);
        let _ = cgroup_tx.send((cg.id, false)).await;
    }

    // Remove the IP binding when the session ends
    let _ = allowlist_tx.send((client_ip, client_subject, false)).await;

    Ok(())
}
