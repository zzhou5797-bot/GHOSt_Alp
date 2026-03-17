// This is a malicious QUIC client PoC for testing the eBPF Guillotine quota mechanism
use clap::Parser;
use quinn::{ClientConfig, Endpoint, TransportConfig};
use shared::{ControlMessage, GenesisCredential};
use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::io::AsyncWriteExt;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8080")]
    server: SocketAddr,

    #[arg(long, default_value = "localhost")]
    server_name: String,

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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // 1. Configure the Client
    let ca_cert_pem = fs::read(&args.ca)?;
    let mut ca_cert_reader = std::io::BufReader::new(ca_cert_pem.as_slice());
    let ca_certs: Vec<_> = rustls_pemfile::certs(&mut ca_cert_reader).collect::<Result<_, _>>()?;

    let mut roots = rustls::RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert)?;
    }

    let cert_pem = fs::read(&args.cert)?;
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let cert_chain = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let key_pem = fs::read(&args.key)?;
    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let priv_key = rustls_pemfile::private_key(&mut key_reader)?.unwrap();

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, priv_key)?;
    client_crypto.alpn_protocols = shared::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    // Insecure: skip server cert verification for PoC speed if needed, but we have the CA.

    let mut client_config = ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?));
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    // 2. Connect to Server
    println!("🔥 [Attacker] Attempting to penetrate GhostPTY node at {}...", args.server);
    let connection = endpoint.connect(args.server, &args.server_name)?.await?;
    println!("🔥 [Attacker] Connection established. Starting Handshake...");

    // 3. Send Handshake
    let mut control_tx = connection.open_uni().await?;
    let handshake = ControlMessage::Authenticate {
        token: args.token,
        genesis_vc: Some(GenesisCredential {
            subject: 1, // Must match client cert CN
            request_quota: 10 * 1024 * 1024, // 10 MB requested
            pubkey_index: 0,
            anchor_hash: [0u8; 32],
            signature_hex: "dummy_sig_for_poc".to_string(),
        }),
    };
    let hs_json = serde_json::to_vec(&handshake)?;
    let hs_len = (hs_json.len() as u32).to_be_bytes();
    control_tx.write_all(&hs_len).await?;
    control_tx.write_all(&hs_json).await?;
    println!("💣 [Attacker] Handshake sent requesting 10MB quota.");

    // Start Shell (Handshake requirement)
    let start_msg = serde_json::to_vec(&ControlMessage::StartShell)?;
    let msg_len = (start_msg.len() as u32).to_be_bytes();
    control_tx.write_all(&msg_len).await?;
    control_tx.write_all(&start_msg).await?;

    // We must accept the bidirectional stream the server tries to open with us for the shell data
    let (_data_tx, _data_rx) = connection.accept_bi().await?;

    println!("💣 [Attacker] Charging the payload cannon (1MB garbage block)...");
    let garbage_payload = vec![0x41u8; 1024 * 1024];
    let payload_ref = Arc::new(garbage_payload);

    println!("💣 [Attacker] Unleashing 1000 concurrent streams to exhaust quota...");

    let mut tasks = vec![];

    // 4. Violent Concurrency
    for i in 0..1000 {
        let conn_clone = connection.clone();
        let payload = payload_ref.clone();

        let task = tokio::spawn(async move {
            if let Ok((mut send, _recv)) = conn_clone.open_bi().await {
                let mut sends = 0;
                loop {
                    if send.write_all(&payload).await.is_err() {
                        println!("💀 [Stream {}] Physically severed by the Guillotine after {} MB!", i, sends);
                        break;
                    }
                    sends += 1;
                }
            } else {
                 println!("⚠️ [Stream {}] Failed to open stream.", i);
            }
        });
        tasks.push(task);
    }

    futures::future::join_all(tasks).await;
    println!("✅ [Attacker] Assault complete. Connection effectively neutralized by server.");

    // Prevent immediate exit
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    Ok(())
}
