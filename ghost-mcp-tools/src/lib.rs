use anyhow::{bail, Context, Result};
use serde_json::json;
use shared::mcp_wire::AgentRequest;
use std::{
    path::{Component, Path, PathBuf},
    time::Duration,
};
use tokio::{fs, process::Command};

pub const DEFAULT_MAX_FILE_BYTES: usize = 1_048_576;

#[derive(Debug, Clone)]
pub struct ToolPolicy {
    pub root: PathBuf,
    pub enable_command: bool,
    pub max_file_bytes: usize,
}

impl ToolPolicy {
    pub async fn new(
        root: impl AsRef<Path>,
        enable_command: bool,
        max_file_bytes: usize,
    ) -> Result<Self> {
        let root = fs::canonicalize(root.as_ref())
            .await
            .with_context(|| format!("cannot resolve tool root {}", root.as_ref().display()))?;
        if !fs::metadata(&root).await?.is_dir() {
            bail!("tool root is not a directory: {}", root.display());
        }
        Ok(Self {
            root,
            enable_command,
            max_file_bytes: max_file_bytes.max(1),
        })
    }
}

pub async fn execute_request(
    request: AgentRequest,
    policy: &ToolPolicy,
) -> Result<serde_json::Value> {
    match request {
        AgentRequest::Authenticate { .. } => bail!("authenticate is a transport-level request"),
        AgentRequest::SystemInfo => system_info(policy).await,
        AgentRequest::ListDirectory { path } => list_directory(policy, &path).await,
        AgentRequest::ReadFile {
            path,
            offset,
            length,
        } => read_file(policy, &path, offset, length).await,
        AgentRequest::WriteFile {
            path,
            content,
            create_parents,
        } => write_file(policy, &path, &content, create_parents).await,
        AgentRequest::RunCommand {
            command,
            cwd,
            timeout_ms,
        } => run_command(policy, &command, cwd.as_deref(), timeout_ms).await,
    }
}

pub async fn system_info(policy: &ToolPolicy) -> Result<serde_json::Value> {
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
        "root": policy.root,
        "command_enabled": policy.enable_command,
        "pid": std::process::id()
    }))
}

pub async fn list_directory(policy: &ToolPolicy, path: &str) -> Result<serde_json::Value> {
    let dir = resolve_existing(&policy.root, path).await?;
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

pub async fn read_file(
    policy: &ToolPolicy,
    path: &str,
    offset: Option<usize>,
    length: Option<usize>,
) -> Result<serde_json::Value> {
    let file = resolve_existing(&policy.root, path).await?;
    let meta = fs::metadata(&file).await?;
    if !meta.is_file() {
        bail!("not a regular file: {}", file.display());
    }
    if meta.len() as usize > policy.max_file_bytes {
        bail!(
            "file is {} bytes; max allowed is {} bytes",
            meta.len(),
            policy.max_file_bytes
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

pub async fn write_file(
    policy: &ToolPolicy,
    path: &str,
    content: &str,
    create_parents: bool,
) -> Result<serde_json::Value> {
    if content.len() > policy.max_file_bytes {
        bail!(
            "content is {} bytes; max allowed is {} bytes",
            content.len(),
            policy.max_file_bytes
        );
    }
    let target = resolve_writable(&policy.root, path, create_parents).await?;
    fs::write(&target, content.as_bytes()).await?;
    Ok(json!({
        "path": target,
        "bytes_written": content.len()
    }))
}

pub async fn run_command(
    policy: &ToolPolicy,
    command: &str,
    cwd: Option<&str>,
    timeout_ms: Option<u64>,
) -> Result<serde_json::Value> {
    if !policy.enable_command {
        bail!("run_command is disabled");
    }
    reject_blocked_command(command)?;
    let cwd = resolve_cwd(policy, cwd).await?;
    let timeout_ms = timeout_ms.unwrap_or(30_000).clamp(100, 120_000);

    let mut child = Command::new("/bin/sh");
    child
        .arg("-lc")
        .arg(command)
        .current_dir(&cwd)
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_millis(timeout_ms), child.output())
        .await
        .context("command timed out")??;

    command_result(command, &cwd, &output, policy.max_file_bytes)
}

pub async fn resolve_cwd(policy: &ToolPolicy, cwd: Option<&str>) -> Result<PathBuf> {
    let cwd = match cwd {
        Some(path) => resolve_existing(&policy.root, path).await?,
        None => policy.root.clone(),
    };
    if !fs::metadata(&cwd).await?.is_dir() {
        bail!("cwd is not a directory: {}", cwd.display());
    }
    Ok(cwd)
}

pub fn command_result(
    command: &str,
    cwd: &Path,
    output: &std::process::Output,
    max_bytes: usize,
) -> Result<serde_json::Value> {
    Ok(json!({
        "command": command,
        "cwd": cwd,
        "exit_code": output.status.code(),
        "success": output.status.success(),
        "stdout": cap_text(&output.stdout, max_bytes),
        "stderr": cap_text(&output.stderr, max_bytes)
    }))
}

pub fn reject_blocked_command(command: &str) -> Result<()> {
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

pub async fn resolve_existing(root: &Path, input: &str) -> Result<PathBuf> {
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
