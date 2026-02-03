use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    terminal::{disable_raw_mode, enable_raw_mode},
};
use quinn::{ClientConfig, Endpoint, TransportConfig};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    host: String,
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // Enable Raw Mode immediately for TTY feel
    enable_raw_mode()?;

    if let Err(e) = run_client(args).await {
        disable_raw_mode()?;
        eprintln!("\r\nError: {:?}\r\n", e);
        return Err(e);
    }

    disable_raw_mode()?;
    Ok(())
}

async fn run_client(args: Args) -> Result<()> {
    // UNSAFE: Skip verification for V2 MVP
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    
    let mut crypto = crypto;
    crypto.alpn_protocols = shared::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut client_config = ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?));
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    let remote_addr: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .context("Invalid address")?;

    eprintln!("Connecting to {}...\r", remote_addr);
    
    let connection = endpoint
        .connect(remote_addr, "localhost")?
        .await
        .context("Failed to connect")?;

    eprintln!("Connected! Handshaking...\r");

    // 1. Open Control Stream FIRST
    let mut control_tx = connection.open_uni().await?;

    // 2. Perform Handshake
    // A. Send TERM environment variable
    let term = std::env::var("TERM").unwrap_or("xterm-256color".into());
    let msg = shared::ControlMessage::SetEnv { key: "TERM".into(), value: term };
    send_control_msg(&mut control_tx, &msg).await?;

    // B. Send Initial Window Size
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let msg = shared::ControlMessage::Resize { rows, cols };
    send_control_msg(&mut control_tx, &msg).await?;

    // C. Finish Handshake
    let msg = shared::ControlMessage::StartShell;
    send_control_msg(&mut control_tx, &msg).await?;

    eprintln!("Handshake complete. Stream established.\r");

    // 3. Open Data Stream SECOND
    let (mut send, mut recv) = connection.open_bi().await?;

    // 4. Spawn Resize Monitor (Polling)
    // We poll window size to avoid conflicting with input stream reading in Raw Mode
    tokio::spawn(async move {
        let mut last_cols = cols; // Use initial values
        let mut last_rows = rows;
        loop {
             if let Ok((cols, rows)) = crossterm::terminal::size() {
                 if cols != last_cols || rows != last_rows {
                      let msg = shared::ControlMessage::Resize { rows, cols };
                      // Ignore errors, if connection drops main loop will exit
                      if send_control_msg(&mut control_tx, &msg).await.is_err() { break; }
                      last_cols = cols;
                      last_rows = rows;
                 }
             }
             tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    });

    // 5. Spawn Input Task (Stdin -> QUIC)
    tokio::spawn(async move {
        // We need to read stdin specifically.
        // In Crossterm Raw Mode, Stdin is perfectly usable as raw bytes.
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    if send.write_all(&buf[..n]).await.is_err() { break; }
                }
                _ => break,
            }
        }
    });

    // Main Loop: QUIC -> Stdout
    let mut stdout = tokio::io::stdout();
    let mut buf = [0u8; 1024];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                stdout.write_all(&buf[..n]).await?;
                stdout.flush().await?;
            }
            Ok(None) => break, // EOF
            Err(_) => break, // Connection lost
        }
    }
    
    Ok(())
}

async fn send_control_msg(tx: &mut quinn::SendStream, msg: &shared::ControlMessage) -> Result<()> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();
    tx.write_all(&len).await?;
    tx.write_all(&json).await?;
    Ok(())
}
