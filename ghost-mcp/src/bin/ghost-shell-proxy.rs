use anyhow::{bail, Context, Result};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream};
use serde::{de::DeserializeOwned, Serialize};
use shared::mcp_wire::{AgentRequest, AgentResponse};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<()> {
    let command = extract_command(std::env::args().skip(1).collect())?;
    let root = std::env::current_dir()?;
    let repo = std::env::var("GHOST_SHELL_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/home/civet/work/GHOSt_Alp"));
    let token = std::fs::read_to_string(repo.join("target/.ghost-shell-token"))
        .context("missing target/.ghost-shell-token")?;
    let token = token.trim().to_string();

    let config = configure_client(
        &repo.join("certs/ca.crt"),
        &repo.join("certs/client.crt"),
        &repo.join("certs/client.key"),
    )?;

    let mut endpoint = Endpoint::client("[::]:0".parse::<SocketAddr>()?)?;
    endpoint.set_default_client_config(config);
    let remote: SocketAddr = std::env::var("GHOST_SHELL_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:19085".into())
        .parse()?;
    let connection = endpoint.connect(remote, "localhost")?.await?;
    let (mut tx, mut rx) = connection.open_bi().await?;

    write_frame(&mut tx, &AgentRequest::Authenticate { token }).await?;
    let auth: AgentResponse = read_frame(&mut rx).await?;
    if !auth.ok {
        bail!("{}", auth.error.unwrap_or_else(|| "authentication failed".into()));
    }

    write_frame(
        &mut tx,
        &AgentRequest::Shell {
            command,
            cwd: Some(root.to_string_lossy().into_owned()),
            timeout_ms: Some(300_000),
        },
    )
    .await?;
    let response: AgentResponse = read_frame(&mut rx).await?;
    if !response.ok {
        bail!("{}", response.error.unwrap_or_else(|| "shell failed".into()));
    }

    let value = response.result.unwrap_or_default();
    if let Some(stdout) = value.get("stdout").and_then(|v| v.as_str()) {
        print!("{stdout}");
    }
    if let Some(stderr) = value.get("stderr").and_then(|v| v.as_str()) {
        eprint!("{stderr}");
    }
    std::process::exit(value.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(1) as i32);
}

fn extract_command(args: Vec<String>) -> Result<String> {
    if args.is_empty() {
        bail!("usage: ghost-shell-proxy [-lc|-c] <command>");
    }
    for (i, arg) in args.iter().enumerate() {
        if arg == "-c" || (arg.starts_with('-') && arg.contains('c')) {
            if let Some(command) = args.get(i + 1) {
                return Ok(command.clone());
            }
        }
    }
    Ok(args.join(" "))
}

fn configure_client(ca: &PathBuf, cert: &PathBuf, key: &PathBuf) -> Result<ClientConfig> {
    let ca_pem = std::fs::read(ca)?;
    let mut roots = rustls::RootCertStore::empty();
    let mut ca_reader = std::io::BufReader::new(ca_pem.as_slice());
    for cert in rustls_pemfile::certs(&mut ca_reader).collect::<std::result::Result<Vec<_>, _>>()? {
        roots.add(cert)?;
    }
    let cert_pem = std::fs::read(cert)?;
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let chain = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key_pem = std::fs::read(key)?;
    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let private_key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("no client key"))?;
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, private_key)?;
    crypto.alpn_protocols = shared::ALPN_GHOST_MCP.iter().map(|x| x.to_vec()).collect();
    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    )))
}

async fn read_frame<T: DeserializeOwned>(rx: &mut RecvStream) -> Result<T> {
    let mut len = [0u8; 4];
    rx.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME_BYTES { bail!("bad frame length"); }
    let mut body = vec![0u8; len];
    rx.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

async fn write_frame<T: Serialize>(tx: &mut SendStream, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    tx.write_all(&(body.len() as u32).to_be_bytes()).await?;
    tx.write_all(&body).await?;
    Ok(())
}
