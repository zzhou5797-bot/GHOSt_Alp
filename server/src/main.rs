use anyhow::{Context, Result};
use clap::Parser;
use quinn::{Endpoint, ServerConfig};
use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};
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

    while let Some(conn) = endpoint.accept().await {
        let token_clone = Arc::clone(&token);
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

            if let Err(e) = handle_connection(connection, &token_clone).await {
                tracing::error!("Connection error with {}: {:?}", remote, e);
            }
        });
    }

    Ok(())
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

mod protocol;
mod session;

async fn handle_connection(connection: quinn::Connection, expected_token: &str) -> Result<()> {
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
