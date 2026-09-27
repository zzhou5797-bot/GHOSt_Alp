use anyhow::{bail, Context, Result};
use clap::Parser;
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream};
use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    schemars, tool, tool_router,
    transport::stdio,
    ServiceExt,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use shared::mcp_wire::{AgentRequest, AgentResponse};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::net::lookup_host;

const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "ghost-mcp",
    version,
    about = "MCP stdio bridge for Ghost desktop control"
)]
struct Args {
    #[arg(long, env = "GHOST_MCP_HOST", default_value = "127.0.0.1")]
    host: String,

    #[arg(long, env = "GHOST_MCP_PORT", default_value_t = 9080)]
    port: u16,

    /// TLS server name expected in the Ghost MCP agent certificate.
    #[arg(long, env = "GHOST_MCP_SERVER_NAME", default_value = "localhost")]
    server_name: String,

    #[arg(long, env = "GHOST_MCP_CA", default_value = "certs/ca.crt")]
    ca: PathBuf,

    #[arg(long, env = "GHOST_MCP_CERT", default_value = "certs/client.crt")]
    cert: PathBuf,

    #[arg(long, env = "GHOST_MCP_KEY", default_value = "certs/client.key")]
    key: PathBuf,

    #[arg(long, env = "GHOST_MCP_TOKEN")]
    token: String,
}

#[derive(Clone)]
struct GhostMcp {
    cfg: Arc<Args>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PathParams {
    /// Path relative to the agent root, or an absolute path inside that root.
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadFileParams {
    /// Path relative to the agent root, or an absolute path inside that root.
    path: String,
    /// Zero-based line offset.
    offset: Option<usize>,
    /// Maximum number of lines to return.
    length: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WriteFileParams {
    /// Path relative to the agent root, or an absolute path inside that root.
    path: String,
    /// Complete UTF-8 file contents.
    content: String,
    /// Create missing parent directories.
    #[serde(default)]
    create_parents: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RunCommandParams {
    /// Shell command to execute on the Ghost-controlled host.
    command: String,
    /// Working directory inside the agent root. Defaults to the root.
    cwd: Option<String>,
    /// Timeout in milliseconds (100..120000).
    timeout_ms: Option<u64>,
}

#[tool_router(server_handler)]
impl GhostMcp {
    #[tool(
        description = "Return basic information about the Ghost-controlled host and agent policy."
    )]
    async fn system_info(&self) -> CallToolResult {
        self.call_agent(AgentRequest::SystemInfo).await
    }

    #[tool(description = "List files and directories inside the configured Ghost agent root.")]
    async fn list_directory(&self, Parameters(params): Parameters<PathParams>) -> CallToolResult {
        self.call_agent(AgentRequest::ListDirectory { path: params.path })
            .await
    }

    #[tool(description = "Read a UTF-8 text file inside the configured Ghost agent root.")]
    async fn read_file(&self, Parameters(params): Parameters<ReadFileParams>) -> CallToolResult {
        self.call_agent(AgentRequest::ReadFile {
            path: params.path,
            offset: params.offset,
            length: params.length,
        })
        .await
    }

    #[tool(description = "Replace a UTF-8 text file inside the configured Ghost agent root.")]
    async fn write_file(&self, Parameters(params): Parameters<WriteFileParams>) -> CallToolResult {
        self.call_agent(AgentRequest::WriteFile {
            path: params.path,
            content: params.content,
            create_parents: params.create_parents,
        })
        .await
    }

    #[tool(
        description = "Run a shell command on the Ghost-controlled host. The agent must be started with --enable-command."
    )]
    async fn run_command(
        &self,
        Parameters(params): Parameters<RunCommandParams>,
    ) -> CallToolResult {
        self.call_agent(AgentRequest::RunCommand {
            command: params.command,
            cwd: params.cwd,
            timeout_ms: params.timeout_ms,
        })
        .await
    }
}

impl GhostMcp {
    async fn call_agent(&self, request: AgentRequest) -> CallToolResult {
        match self.call_agent_inner(request).await {
            Ok(response) if response.ok => {
                CallToolResult::structured(response.result.unwrap_or(serde_json::Value::Null))
            }
            Ok(response) => CallToolResult::error(vec![ContentBlock::text(
                response
                    .error
                    .unwrap_or_else(|| "Ghost MCP agent returned an unknown error".to_string()),
            )]),
            Err(err) => CallToolResult::error(vec![ContentBlock::text(format!("{err:#}"))]),
        }
    }

    async fn call_agent_inner(&self, request: AgentRequest) -> Result<AgentResponse> {
        let client_config = configure_client(&self.cfg.ca, &self.cfg.cert, &self.cfg.key)?;
        let mut endpoint = Endpoint::client("[::]:0".parse::<SocketAddr>()?)?;
        endpoint.set_default_client_config(client_config);

        let remote = lookup_host((self.cfg.host.as_str(), self.cfg.port))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("could not resolve Ghost MCP agent address"))?;

        let connection = endpoint
            .connect(remote, &self.cfg.server_name)?
            .await
            .context("Ghost MCP QUIC connect failed")?;
        let (mut tx, mut rx) = connection.open_bi().await?;

        write_frame(
            &mut tx,
            &AgentRequest::Authenticate {
                token: self.cfg.token.clone(),
            },
        )
        .await?;
        let auth: AgentResponse = read_frame(&mut rx)
            .await
            .context("Ghost MCP authentication response failed")?;
        if !auth.ok {
            bail!(
                "Ghost MCP authentication failed: {}",
                auth.error.unwrap_or_else(|| "unknown error".to_string())
            );
        }

        write_frame(&mut tx, &request).await?;
        let response: AgentResponse = read_frame(&mut rx).await?;
        tx.finish()?;
        connection.close(0u32.into(), b"done");
        endpoint.wait_idle().await;
        Ok(response)
    }
}

fn configure_client(
    ca_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<ClientConfig> {
    let ca_pem = std::fs::read(ca_path)
        .with_context(|| format!("failed to read CA certificate {}", ca_path.display()))?;
    let mut roots = rustls::RootCertStore::empty();
    let mut ca_reader = std::io::BufReader::new(ca_pem.as_slice());
    for cert in rustls_pemfile::certs(&mut ca_reader).collect::<std::result::Result<Vec<_>, _>>()? {
        roots.add(cert)?;
    }

    let cert_pem = std::fs::read(cert_path)
        .with_context(|| format!("failed to read client certificate {}", cert_path.display()))?;
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let cert_chain =
        rustls_pemfile::certs(&mut cert_reader).collect::<std::result::Result<Vec<_>, _>>()?;

    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("failed to read client key {}", key_path.display()))?;
    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let private_key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("no client private key found"))?;

    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, private_key)?;
    crypto.alpn_protocols = shared::ALPN_GHOST_MCP.iter().map(|x| x.to_vec()).collect();

    let mut config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    config.transport_config(Arc::new(transport));
    Ok(config)
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
        bail!("request frame too large: {}", body.len());
    }
    tx.write_all(&(body.len() as u32).to_be_bytes()).await?;
    tx.write_all(&body).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Arc::new(Args::parse());
    let service = GhostMcp { cfg }.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
