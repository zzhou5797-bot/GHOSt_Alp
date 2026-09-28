use anyhow::{bail, Context, Result};
use clap::Parser;
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use shared::mcp_wire::{AgentRequest, AgentResponse};
use std::{net::SocketAddr, path::{Path, PathBuf}, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tracing_subscriber::EnvFilter;

const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

#[derive(Parser, Debug, Clone)]
#[command(name = "ghost-mcp-agent", version, about = "Minimal Ghost shell agent")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9080")]
    listen: SocketAddr,

    #[arg(long, default_value = "certs/ca.crt")]
    ca: PathBuf,

    #[arg(long, default_value = "certs/server.crt")]
    cert: PathBuf,

    #[arg(long, default_value = "certs/server.key")]
    key: PathBuf,

    #[arg(long, env = "GHOST_MCP_TOKEN")]
    token: String,

    #[arg(long, default_value_t = ghost_mcp_tools::DEFAULT_MAX_OUTPUT_BYTES)]
    max_output_bytes: usize,
}

#[derive(Clone)]
struct AgentConfig {
    token: Arc<String>,
    max_output_bytes: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let args = Args::parse();
    let endpoint = Endpoint::server(configure_server(&args.ca, &args.cert, &args.key)?, args.listen)?;
    let cfg = AgentConfig {
        token: Arc::new(args.token),
        max_output_bytes: args.max_output_bytes.max(1).min(MAX_FRAME_BYTES),
    };

    tracing::info!(listen = %endpoint.local_addr()?, "Ghost shell agent ready");

    while let Some(incoming) = endpoint.accept().await {
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let remote = incoming.remote_address();
            match incoming.await {
                Ok(connection) => {
                    if let Err(err) = handle_connection(connection, cfg).await {
                        tracing::warn!(%remote, error = %err, "Ghost shell connection closed");
                    }
                }
                Err(err) => tracing::warn!(%remote, error = %err, "QUIC handshake failed"),
            }
        });
    }

    Ok(())
}

fn configure_server(ca_path: &Path, cert_path: &Path, key_path: &Path) -> Result<ServerConfig> {
    let ca_pem = std::fs::read(ca_path)
        .with_context(|| format!("failed to read CA certificate {}", ca_path.display()))?;
    let mut ca_reader = std::io::BufReader::new(ca_pem.as_slice());
    let ca_certs: Vec<_> =
        rustls_pemfile::certs(&mut ca_reader).collect::<std::result::Result<_, _>>()?;

    let mut roots = rustls::RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert)?;
    }
    let client_auth = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("failed to read server certificate {}", cert_path.display()))?;
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let cert_chain =
        rustls_pemfile::certs(&mut cert_reader).collect::<std::result::Result<Vec<_>, _>>()?;

    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("failed to read server key {}", key_path.display()))?;
    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let private_key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found"))?;

    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(cert_chain, private_key)?;
    crypto.alpn_protocols = shared::ALPN_GHOST_MCP.iter().map(|x| x.to_vec()).collect();

    let mut config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(5 * 60).try_into()?));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

async fn handle_connection(connection: quinn::Connection, cfg: AgentConfig) -> Result<()> {
    let (mut tx, mut rx) = connection.accept_bi().await?;

    match read_frame::<AgentRequest>(&mut rx).await? {
        AgentRequest::Authenticate { token } if token_matches(&cfg.token, &token) => {
            write_frame(&mut tx, &AgentResponse::success(json!({"authenticated": true, "shell": true}))).await?;
        }
        AgentRequest::Authenticate { .. } => {
            write_frame(&mut tx, &AgentResponse::error("authentication failed")).await?;
            tx.finish()?;
            return Ok(());
        }
        _ => {
            write_frame(&mut tx, &AgentResponse::error("authenticate must be the first frame")).await?;
            tx.finish()?;
            return Ok(());
        }
    }

    loop {
        let request = match read_frame::<AgentRequest>(&mut rx).await {
            Ok(value) => value,
            Err(err) if clean_eof(&err) => break,
            Err(err) => return Err(err),
        };

        let response = match request {
            AgentRequest::Shell { command, cwd, timeout_ms } => {
                match ghost_mcp_tools::shell(
                    &command,
                    cwd.as_deref(),
                    timeout_ms,
                    cfg.max_output_bytes,
                )
                .await
                {
                    Ok(value) => AgentResponse::success(value),
                    Err(err) => AgentResponse::error(format!("{err:#}")),
                }
            }
            AgentRequest::Authenticate { .. } => AgentResponse::error("already authenticated"),
        };

        write_frame(&mut tx, &response).await?;
    }

    Ok(())
}

fn token_matches(expected: &str, supplied: &str) -> bool {
    expected.len() == supplied.len()
        && bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
}

fn clean_eof(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("closed") || msg.contains("finished") || msg.contains("early")
}

async fn read_frame<T: DeserializeOwned>(rx: &mut RecvStream) -> Result<T> {
    let mut len_buf = [0_u8; 4];
    rx.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        bail!("invalid frame length: {len}");
    }
    let mut body = vec![0_u8; len];
    rx.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

async fn write_frame<T: Serialize>(tx: &mut SendStream, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_FRAME_BYTES {
        bail!("response frame too large: {}", body.len());
    }
    tx.write_all(&(body.len() as u32).to_be_bytes()).await?;
    tx.write_all(&body).await?;
    Ok(())
}
