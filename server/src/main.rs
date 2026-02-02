use anyhow::Result;
use clap::Parser;
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use quinn::{Endpoint, ServerConfig};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let addr = format!("0.0.0.0:{}", args.port).parse::<SocketAddr>()?;

    let (server_config, _cert) = configure_server()?;
    let endpoint = Endpoint::server(server_config, addr)?;
    
    println!("QUIC Server listening on {}", endpoint.local_addr()?);

    while let Some(conn) = endpoint.accept().await {
        tokio::spawn(async move {
            let remote = conn.remote_address();
            println!("Connection from {}", remote);
            let connection = match conn.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                    return;
                }
            };

            if let Err(e) = handle_connection(connection).await {
                eprintln!("Connection error with {}: {:?}", remote, e);
            }
        });
    }

    Ok(())
}

fn configure_server() -> Result<(ServerConfig, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_pem = cert.serialize_pem()?;
    let priv_key_pem = cert.serialize_private_key_pem();

    let cert_chain = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    
    let priv_key = rustls_pemfile::private_key(&mut priv_key_pem.as_bytes())?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)?;
    server_crypto.alpn_protocols = shared::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config = ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?));
    
    // Customize transport config
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    server_config.transport_config(Arc::new(transport_config));
    
    // We need DER for some reason? Implementation Plan says OK.
    // Client skips verify so it doesn't strictly need the cert DER from here, 
    // but the function signature returns `Vec<u8>`. We can return the first cert's DER.
    let cert_der = cert.serialize_der()?; // Keep this just to satisfy return type or debugging

    Ok((server_config, cert_der))
}

async fn handle_connection(connection: quinn::Connection) -> Result<()> {
    // Accept the first bi-directional stream (Main Shell Stream)
    let (mut send, mut recv) = connection.accept_bi().await?;
    println!("Stream established");

    // Spawn PTY
    let pty_system = NativePtySystem::default();
    let pair = pty_system.openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    })?;

    let cmd = CommandBuilder::new("sh"); // Or "bash" if preferred/available
    let mut child = pair.slave.spawn_command(cmd)?;
    
    // Drop slave to allow close propagation
    drop(pair.slave);

    let mut master_reader = pair.master.try_clone_reader()?;
    let mut master_writer = pair.master.take_writer()?;

    // Use channels to bridge blocking PTY IO with async QUIC streams
    let (to_pty_tx, mut to_pty_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let (from_pty_tx, mut from_pty_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

    // 1. Task: QUIC Stream Recv -> to_pty_tx
    let _remote_read_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if to_pty_tx.send(buf[..n].to_vec()).await.is_err() { break; }
                }
                Ok(None) => break, // EOF
                Err(_) => break,
            }
        }
    });

    // 2. Thread: to_pty_rx -> PTY Writer
    std::thread::spawn(move || {
        while let Some(data) = to_pty_rx.blocking_recv() {
            if master_writer.write_all(&data).is_err() { break; }
        }
    });

    // 3. Thread: PTY Reader -> from_pty_tx
    std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match master_reader.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if from_pty_tx.blocking_send(buf[..n].to_vec()).is_err() { break; }
                }
                _ => break,
            }
        }
    });

    // 4. Task: from_pty_rx -> QUIC Stream Send
    let _remote_write_task = tokio::spawn(async move {
        while let Some(data) = from_pty_rx.recv().await {
            if send.write_all(&data).await.is_err() { break; }
        }
        let _ = send.finish(); // No await needed in Quinn 0.11
    });

    // Wait for shell to exit
    // child.wait()?; // This blocks.
    
    // We can run a supervision loop
    loop {
        if let Ok(Some(_status)) = child.try_wait() {
             break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    
    Ok(())
}
