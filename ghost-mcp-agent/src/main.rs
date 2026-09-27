use anyhow::{bail, Context, Result};
use clap::Parser;
use ghost_mcp_tools::{execute_request, ToolPolicy, DEFAULT_MAX_FILE_BYTES};
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use shared::mcp_wire::{AgentRequest, AgentResponse};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tracing_subscriber::EnvFilter;

const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "ghost-mcp-agent",
    version,
    about = "Desktop-control agent carried over Ghost QUIC/mTLS"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9080")]
    listen: SocketAddr,

    #[arg(long, default_value = ".")]
    root: PathBuf,

    #[arg(long, default_value = "certs/ca.crt")]
    ca: PathBuf,

    #[arg(long, default_value = "certs/server.crt")]
    cert: PathBuf,

    #[arg(long, default_value = "certs/server.key")]
    key: PathBuf,

    #[arg(long, env = "GHOST_MCP_TOKEN")]
    token: String,

    #[arg(long, default_value_t = false)]
    enable_command: bool,

    #[arg(long, default_value_t = DEFAULT_MAX_FILE_BYTES)]
    max_file_bytes: usize,
}

#[derive(Clone)]
struct AgentConfig {
    token: Arc<String>,
    policy: Arc<ToolPolicy>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let args = Args::parse();
    let policy = Arc::new(
        ToolPolicy::new(
            &args.root,
            args.enable_command,
            args.max_file_bytes.min(MAX_FRAME_BYTES),
        )
        .await?,
    );

    let server_config = configure_server(&args.ca, &args.cert, &args.key)?;
    let endpoint = Endpoint::server(server_config, args.listen)?;
    let cfg = AgentConfig {
        token: Arc::new(args.token),
        policy,
    };

    tracing::info!(
        listen = %endpoint.local_addr()?,
        root = %cfg.policy.root.display(),
        command_enabled = cfg.policy.enable_command,
        "Ghost MCP agent ready"
    );

    while let Some(incoming) = endpoint.accept().await {
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let remote = incoming.remote_address();
            match incoming.await {
                Ok(connection) => {
                    if let Err(err) = handle_connection(connection, cfg).await {
                        tracing::warn!(%remote, error = %err, "Ghost MCP connection closed");
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

    let auth: AgentRequest = read_frame(&mut rx).await?;
    match auth {
        AgentRequest::Authenticate { token } if token_matches(cfg.token.as_str(), &token) => {
            write_frame(
                &mut tx,
                &AgentResponse::success(json!({
                    "authenticated": true,
                    "root": cfg.policy.root,
                    "command_enabled": cfg.policy.enable_command
                })),
            )
            .await?;
        }
        AgentRequest::Authenticate { .. } => {
            write_frame(&mut tx, &AgentResponse::error("authentication failed")).await?;
            tx.finish()?;
            tokio::time::sleep(Duration::from_millis(20)).await;
            return Ok(());
        }
        _ => {
            write_frame(
                &mut tx,
                &AgentResponse::error("authenticate must be the first frame"),
            )
            .await?;
            tx.finish()?;
            tokio::time::sleep(Duration::from_millis(20)).await;
            return Ok(());
        }
    }

    loop {
        let request: AgentRequest = match read_frame(&mut rx).await {
            Ok(value) => value,
            Err(err) if is_clean_eof(&err) => break,
            Err(err) => return Err(err),
        };
        if matches!(request, AgentRequest::Authenticate { .. }) {
            write_frame(&mut tx, &AgentResponse::error("already authenticated")).await?;
            continue;
        }

        let response = match execute_request(request, &cfg.policy).await {
            Ok(value) => AgentResponse::success(value),
            Err(err) => AgentResponse::error(format!("{err:#}")),
        };
        write_frame(&mut tx, &response).await?;
    }

    Ok(())
}

fn token_matches(expected: &str, supplied: &str) -> bool {
    expected.len() == supplied.len() && bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
}

fn is_clean_eof(err: &anyhow::Error) -> bool {
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
