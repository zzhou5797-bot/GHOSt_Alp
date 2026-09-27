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
use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::net::{lookup_host, UdpSocket};

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

    /// Send a Ghost SPA v2 hash-chain knock before each QUIC tool connection.
    /// Enable this when connecting to the full Ghost gateway/XDP path.
    #[arg(long, env = "GHOST_MCP_GATEWAY", default_value_t = false)]
    gateway: bool,

    /// DID used by the SPA knock. The mTLS client certificate CN must match.
    #[arg(long, env = "GHOST_MCP_TARGET", default_value_t = 1)]
    target: u32,

    #[arg(
        long,
        env = "SPA_KEY",
        default_value = "deadbeef01020304badce0ff0a0b0c0d"
    )]
    spa_key: String,

    #[arg(
        long,
        env = "SPA_SEED",
        default_value = "0102030405060708090a0b0c0d0e0f10"
    )]
    seed: String,

    #[arg(
        long,
        env = "GHOST_MCP_STATE_FILE",
        default_value = ".ghost_mcp_chain_state"
    )]
    state_file: PathBuf,

    #[arg(long, env = "GHOST_MCP_CHAIN_DEPTH", default_value_t = 10_000)]
    chain_depth: u64,
}

#[derive(Clone)]
struct GhostMcp {
    cfg: Arc<Args>,
    spa_lock: Arc<tokio::sync::Mutex<()>>,
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
        if self.cfg.gateway {
            let _spa_guard = self.spa_lock.lock().await;
            send_spa_knock(&self.cfg).await?;
        }

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

const STATE_MAGIC_V2: &[u8; 4] = b"GCv2";
const STATE_MAGIC_V3: &[u8; 4] = b"GCv3";

async fn send_spa_knock(args: &Args) -> Result<()> {
    let (secret_k0, secret_k1) = shared::spa::parse_key_hex(&args.spa_key)
        .unwrap_or((shared::spa::DEV_SECRET_K0, shared::spa::DEV_SECRET_K1));
    let seed = shared::spa::parse_seed_hex(&args.seed).unwrap_or(shared::spa::DEV_SEED);

    let (current_seq, chain_seed, _current_anchor) = load_or_init_spa_state(
        &args.state_file,
        seed,
        args.chain_depth,
        secret_k0,
        secret_k1,
    )?;
    if current_seq == 0 {
        bail!("Ghost SPA hash chain exhausted; register a new anchor with the gateway");
    }

    let next_seq = current_seq - 1;
    let next_hash = get_hash_at_seq(chain_seed, next_seq, secret_k0, secret_k1);
    save_spa_state(&args.state_file, chain_seed, next_seq, next_hash)?;

    let mut payload = Vec::with_capacity(60);
    payload.extend_from_slice(&(0x5453_5054u32).to_be_bytes());
    payload.extend_from_slice(&2u32.to_be_bytes());
    payload.extend_from_slice(&args.target.to_be_bytes());
    payload.extend_from_slice(&next_seq.to_be_bytes());
    payload.extend_from_slice(&next_hash);
    payload.extend_from_slice(&[0u8; 32]);

    let remote = lookup_host((args.host.as_str(), args.port))
        .await?
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("Ghost SPA currently requires an IPv4 gateway address"))?;
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind Ghost SPA UDP socket")?;
    socket
        .send_to(&payload, remote)
        .await
        .context("failed to send Ghost SPA v2 knock")?;

    tokio::time::sleep(Duration::from_millis(2)).await;
    Ok(())
}

fn load_or_init_spa_state(
    state_file: &PathBuf,
    seed: [u8; 8],
    chain_depth: u64,
    k0: u64,
    k1: u64,
) -> Result<(u64, [u8; 8], [u8; 8])> {
    if let Ok(data) = fs::read(state_file) {
        if data.len() == 28 && &data[0..4] == STATE_MAGIC_V3 {
            let stored_seed: [u8; 8] = data[4..12].try_into().unwrap();
            let current_seq = u64::from_le_bytes(data[12..20].try_into().unwrap());
            let current_hash: [u8; 8] = data[20..28].try_into().unwrap();
            if stored_seed == seed && current_seq > 0 {
                return Ok((current_seq, stored_seed, current_hash));
            }
        }

        if data.len() == 20 && &data[0..4] == STATE_MAGIC_V2 {
            let stored_seed: [u8; 8] = data[4..12].try_into().unwrap();
            let current_seq = u64::from_le_bytes(data[12..20].try_into().unwrap());
            if stored_seed == seed && current_seq > 0 {
                let current_hash = get_hash_at_seq(stored_seed, current_seq, k0, k1);
                save_spa_state(state_file, seed, current_seq, current_hash)?;
                return Ok((current_seq, stored_seed, current_hash));
            }
        }
    }

    let initial_hash = get_hash_at_seq(seed, chain_depth, k0, k1);
    save_spa_state(state_file, seed, chain_depth, initial_hash)?;
    Ok((chain_depth, seed, initial_hash))
}

fn save_spa_state(
    state_file: &PathBuf,
    seed: [u8; 8],
    current_seq: u64,
    current_hash: [u8; 8],
) -> Result<()> {
    let mut data = Vec::with_capacity(28);
    data.extend_from_slice(STATE_MAGIC_V3);
    data.extend_from_slice(&seed);
    data.extend_from_slice(&current_seq.to_le_bytes());
    data.extend_from_slice(&current_hash);
    fs::write(state_file, &data)
        .with_context(|| format!("failed to write Ghost SPA state to {:?}", state_file))
}

fn get_hash_at_seq(seed: [u8; 8], seq: u64, k0: u64, k1: u64) -> [u8; 8] {
    let mut h = seed;
    for _ in 0..seq {
        h = hash_step(h, k0, k1);
    }
    h
}

fn hash_step(h: [u8; 8], k0: u64, k1: u64) -> [u8; 8] {
    siphash24_16b(k0, k1, u64::from_le_bytes(h), 0)
}

#[inline(always)]
fn rotate_left(x: u64, b: u32) -> u64 {
    (x << b) | (x >> (64 - b))
}

#[inline(always)]
fn siphash24_compress(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = rotate_left(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotate_left(*v0, 32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = rotate_left(*v3, 16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = rotate_left(*v3, 21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = rotate_left(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotate_left(*v2, 32);
}

fn siphash24_16b(k0: u64, k1: u64, m0: u64, m1: u64) -> [u8; 8] {
    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;
    let b = (16_u64) << 56;

    for m in [m0, m1] {
        v3 ^= m;
        siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
        siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    v3 ^= b;
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    for _ in 0..4 {
        siphash24_compress(&mut v0, &mut v1, &mut v2, &mut v3);
    }

    (v0 ^ v1 ^ v2 ^ v3).to_le_bytes()
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
    let service = GhostMcp {
        cfg,
        spa_lock: Arc::new(tokio::sync::Mutex::new(())),
    }
    .serve(stdio())
    .await?;
    service.waiting().await?;
    Ok(())
}
