use anyhow::{Context, Result};
use clap::Parser;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use quinn::{ClientConfig, Endpoint, TransportConfig};
use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    host: String,

    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    #[arg(long, default_value = "../certs/ca.crt")]
    ca: PathBuf,

    #[arg(long, default_value = "../certs/client.crt")]
    cert: PathBuf,

    #[arg(long, default_value = "../certs/client.key")]
    key: PathBuf,

    #[arg(long, env = "GATEWAY_TOKEN", default_value = "secret-token")]
    token: String,
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
    // 1. Load CA cert
    let ca_cert_pem =
        fs::read(&args.ca).with_context(|| format!("Failed to read CA cert from {:?}", args.ca))?;
    let mut ca_cert_reader = std::io::BufReader::new(ca_cert_pem.as_slice());
    let ca_certs: Vec<_> = rustls_pemfile::certs(&mut ca_cert_reader).collect::<Result<_, _>>()?;

    let mut roots = rustls::RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert)?;
    }

    // 2. Load Client cert
    let cert_pem = fs::read(&args.cert)
        .with_context(|| format!("Failed to read client cert from {:?}", args.cert))?;
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let cert_chain = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    // 3. Load Client key
    let key_pem = fs::read(&args.key)
        .with_context(|| format!("Failed to read client key from {:?}", args.key))?;
    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let priv_key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

    // 4. Configure TLS
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, priv_key)?;

    crypto.alpn_protocols = shared::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
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
    // A. Send Authenticate Token FIRST
    let msg = shared::ControlMessage::Authenticate { token: args.token };
    send_control_msg(&mut control_tx, &msg).await?;

    // B. Send TERM environment variable
    let term = std::env::var("TERM").unwrap_or("xterm-256color".into());
    let msg = shared::ControlMessage::SetEnv {
        key: "TERM".into(),
        value: term,
    };
    send_control_msg(&mut control_tx, &msg).await?;

    // C. Send Initial Window Size
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let msg = shared::ControlMessage::Resize { rows, cols };
    send_control_msg(&mut control_tx, &msg).await?;

    // D. Finish Handshake
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
                    if send_control_msg(&mut control_tx, &msg).await.is_err() {
                        break;
                    }
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
                    if send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
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
            Err(_) => break,   // Connection lost
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
