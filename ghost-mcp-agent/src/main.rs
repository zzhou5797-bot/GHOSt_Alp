use anyhow::{bail, Context, Result};
use clap::Parser;
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use shared::mcp_wire::{AgentRequest, AgentResponse};
use std::{
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{fs, process::Command};
use tracing_subscriber::EnvFilter;

const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "ghost-mcp-agent",
    version,
    about = "Desktop-control agent carried over Ghost QUIC/mTLS"
)]
struct Args {
    /// UDP/QUIC listen address.
    #[arg(long, default_value = "127.0.0.1:9080")]
    listen: SocketAddr,

    /// Root directory exposed by file tools.
    #[arg(long, default_value = ".")]
    root: PathBuf,

    #[arg(long, default_value = "certs/ca.crt")]
    ca: PathBuf,

    #[arg(long, default_value = "certs/server.crt")]
    cert: PathBuf,

    #[arg(long, default_value = "certs/server.key")]
    key: PathBuf,

    /// Shared bearer token used after mutual TLS.
    #[arg(long, env = "GHOST_MCP_TOKEN")]
    token: String,

    /// Enable run_command. Off by default.
    #[arg(long, default_value_t = false)]
    enable_command: bool,

    /// Maximum UTF-8 file payload accepted by read/write tools.
    #[arg(long, default_value_t = 1_048_576)]
    max_file_bytes: usize,
}

#[derive(Clone)]
struct AgentConfig {
    root: PathBuf,
    token: Arc<String>,
    enable_command: bool,
    max_file_bytes: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let args = Args::parse();
    let root = fs::canonicalize(&args.root)
        .await
        .with_context(|| format!("cannot resolve agent root {:?}", args.root))?;
    if !fs::metadata(&root).await?.is_dir() {
        bail!("agent root is not a directory: {}", root.display());
    }

    let server_config = configure_server(&args.ca, &args.cert, &args.key)?;
    let endpoint = Endpoint::server(server_config, args.listen)?;
    let cfg = AgentConfig {
        root,
        token: Arc::new(args.token),
        enable_command: args.enable_command,
        max_file_bytes: args.max_file_bytes.min(MAX_FRAME_BYTES),
    };

    tracing::info!(
        listen = %endpoint.local_addr()?,
        root = %cfg.root.display(),
        command_enabled = cfg.enable_command,
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
                    "root": cfg.root,
                    "command_enabled": cfg.enable_command
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

        let response = match execute_request(request, &cfg).await {
            Ok(value) => AgentResponse::success(value),
            Err(err) => AgentResponse::error(format!("{err:#}")),
        };
        write_frame(&mut tx, &response).await?;
    }

    Ok(())
}

fn token_matches(expected: &str, supplied: &str) -> bool {
    if expected.len() != supplied.len() {
        return false;
    }
    bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
}

fn is_clean_eof(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("closed") || msg.contains("finished") || msg.contains("early")
}

async fn execute_request(request: AgentRequest, cfg: &AgentConfig) -> Result<serde_json::Value> {
    match request {
        AgentRequest::Authenticate { .. } => unreachable!(),
        AgentRequest::SystemInfo => {
            let hostname = std::env::var("HOSTNAME")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            Ok(json!({
                "hostname": hostname,
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "root": cfg.root,
                "command_enabled": cfg.enable_command,
                "pid": std::process::id()
            }))
        }
        AgentRequest::ListDirectory { path } => {
            let dir = resolve_existing(&cfg.root, &path).await?;
            if !fs::metadata(&dir).await?.is_dir() {
                bail!("not a directory: {}", dir.display());
            }
            let mut reader = fs::read_dir(&dir).await?;
            let mut entries = Vec::new();
            while let Some(entry) = reader.next_entry().await? {
                let meta = entry.metadata().await?;
                let file_type = entry.file_type().await?;
                entries.push(json!({
                    "name": entry.file_name().to_string_lossy(),
                    "path": entry.path(),
                    "type": if file_type.is_dir() {
                        "directory"
                    } else if file_type.is_file() {
                        "file"
                    } else if file_type.is_symlink() {
                        "symlink"
                    } else {
                        "other"
                    },
                    "size": meta.len()
                }));
            }
            entries.sort_by(|a, b| {
                a.get("name")
                    .and_then(|x| x.as_str())
                    .cmp(&b.get("name").and_then(|x| x.as_str()))
            });
            Ok(json!({"path": dir, "entries": entries}))
        }
        AgentRequest::ReadFile {
            path,
            offset,
            length,
        } => {
            let file = resolve_existing(&cfg.root, &path).await?;
            let meta = fs::metadata(&file).await?;
            if !meta.is_file() {
                bail!("not a regular file: {}", file.display());
            }
            if meta.len() as usize > cfg.max_file_bytes {
                bail!(
                    "file is {} bytes; max allowed is {} bytes",
                    meta.len(),
                    cfg.max_file_bytes
                );
            }
            let content = fs::read_to_string(&file)
                .await
                .with_context(|| format!("file is not valid UTF-8: {}", file.display()))?;
            let lines: Vec<&str> = content.lines().collect();
            let start = offset.unwrap_or(0).min(lines.len());
            let take = length.unwrap_or(lines.len().saturating_sub(start));
            let end = start.saturating_add(take).min(lines.len());
            Ok(json!({
                "path": file,
                "offset": start,
                "lines_returned": end.saturating_sub(start),
                "total_lines": lines.len(),
                "content": lines[start..end].join("\n")
            }))
        }
        AgentRequest::WriteFile {
            path,
            content,
            create_parents,
        } => {
            if content.len() > cfg.max_file_bytes {
                bail!(
                    "content is {} bytes; max allowed is {} bytes",
                    content.len(),
                    cfg.max_file_bytes
                );
            }
            let target = resolve_writable(&cfg.root, &path, create_parents).await?;
            fs::write(&target, content.as_bytes()).await?;
            Ok(json!({
                "path": target,
                "bytes_written": content.len()
            }))
        }
        AgentRequest::RunCommand {
            command,
            cwd,
            timeout_ms,
        } => {
            if !cfg.enable_command {
                bail!("run_command is disabled on this agent");
            }
            reject_blocked_command(&command)?;
            let cwd = match cwd {
                Some(path) => resolve_existing(&cfg.root, &path).await?,
                None => cfg.root.clone(),
            };
            if !fs::metadata(&cwd).await?.is_dir() {
                bail!("cwd is not a directory: {}", cwd.display());
            }

            let timeout_ms = timeout_ms.unwrap_or(30_000).clamp(100, 120_000);
            let mut child = Command::new("/bin/sh");
            child
                .arg("-lc")
                .arg(&command)
                .current_dir(&cwd)
                .kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_millis(timeout_ms), child.output())
                .await
                .context("command timed out")??;

            let stdout = cap_text(&output.stdout, cfg.max_file_bytes);
            let stderr = cap_text(&output.stderr, cfg.max_file_bytes);
            Ok(json!({
                "command": command,
                "cwd": cwd,
                "exit_code": output.status.code(),
                "success": output.status.success(),
                "stdout": stdout,
                "stderr": stderr
            }))
        }
    }
}

fn cap_text(bytes: &[u8], limit: usize) -> String {
    let slice = if bytes.len() > limit {
        &bytes[..limit]
    } else {
        bytes
    };
    let mut text = String::from_utf8_lossy(slice).into_owned();
    if bytes.len() > limit {
        text.push_str("\n[output truncated]");
    }
    text
}

fn reject_blocked_command(command: &str) -> Result<()> {
    const BLOCKED: &[&str] = &[
        "sudo", "su", "mkfs", "fdisk", "parted", "dd", "mount", "umount", "reboot", "shutdown",
        "poweroff", "halt", "passwd", "useradd", "adduser", "usermod", "groupadd", "visudo",
        "iptables", "nft", "chsh",
    ];

    for token in command
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')'))
        .filter(|s| !s.is_empty())
    {
        let basename = Path::new(token)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(token);
        if BLOCKED.iter().any(|blocked| basename == *blocked) {
            bail!("blocked command token: {basename}");
        }
    }
    Ok(())
}

async fn resolve_existing(root: &Path, input: &str) -> Result<PathBuf> {
    let candidate = candidate_path(root, input);
    let canonical = fs::canonicalize(&candidate)
        .await
        .with_context(|| format!("path does not exist: {}", candidate.display()))?;
    ensure_within(root, &canonical)?;
    Ok(canonical)
}

async fn resolve_writable(root: &Path, input: &str, create_parents: bool) -> Result<PathBuf> {
    let candidate = normalize_path(&candidate_path(root, input));
    ensure_within(root, &candidate)?;

    let file_name = candidate
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("write target must name a file"))?
        .to_os_string();
    let parent = candidate
        .parent()
        .ok_or_else(|| anyhow::anyhow!("write target has no parent"))?;

    // Verify the nearest existing ancestor before creating anything. This prevents
    // create_dir_all() from following an existing symlink out of the configured root.
    let mut ancestor = parent.to_path_buf();
    loop {
        match fs::symlink_metadata(&ancestor).await {
            Ok(_) => break,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("no existing ancestor for write target"))?
                    .to_path_buf();
            }
            Err(err) => return Err(err.into()),
        }
    }
    let canonical_ancestor = fs::canonicalize(&ancestor).await?;
    ensure_within(root, &canonical_ancestor)?;

    if create_parents {
        fs::create_dir_all(parent).await?;
    }
    let canonical_parent = fs::canonicalize(parent)
        .await
        .with_context(|| format!("parent directory does not exist: {}", parent.display()))?;
    ensure_within(root, &canonical_parent)?;
    Ok(canonical_parent.join(file_name))
}

fn candidate_path(root: &Path, input: &str) -> PathBuf {
    let path = Path::new(input);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn ensure_within(root: &Path, path: &Path) -> Result<()> {
    if !path.starts_with(root) {
        bail!(
            "path escapes configured root (root={}, path={})",
            root.display(),
            path.display()
        );
    }
    Ok(())
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
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
