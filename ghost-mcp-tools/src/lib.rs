use anyhow::{bail, Context, Result};
use serde_json::json;
use std::{path::{Path, PathBuf}, time::Duration};
use tokio::process::Command;

pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1_048_576;

pub async fn shell(
    command: &str,
    cwd: Option<&str>,
    timeout_ms: Option<u64>,
    max_output_bytes: usize,
) -> Result<serde_json::Value> {
    let cwd = match cwd {
        Some(path) => PathBuf::from(path),
        None => std::env::current_dir()?,
    };

    if !tokio::fs::metadata(&cwd)
        .await
        .with_context(|| format!("cwd does not exist: {}", cwd.display()))?
        .is_dir()
    {
        bail!("cwd is not a directory: {}", cwd.display());
    }

    let timeout_ms = timeout_ms.unwrap_or(30_000).clamp(100, 300_000);
    let mut child = Command::new("/bin/sh");
    child
        .arg("-lc")
        .arg(command)
        .current_dir(&cwd)
        .kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_millis(timeout_ms), child.output())
        .await
        .context("shell command timed out")??;

    Ok(command_result(command, &cwd, &output, max_output_bytes))
}

pub fn command_result(
    command: &str,
    cwd: &Path,
    output: &std::process::Output,
    max_output_bytes: usize,
) -> serde_json::Value {
    json!({
        "command": command,
        "cwd": cwd,
        "exit_code": output.status.code(),
        "success": output.status.success(),
        "stdout": cap_text(&output.stdout, max_output_bytes),
        "stderr": cap_text(&output.stderr, max_output_bytes),
    })
}

fn cap_text(bytes: &[u8], limit: usize) -> String {
    let slice = if bytes.len() > limit { &bytes[..limit] } else { bytes };
    let mut text = String::from_utf8_lossy(slice).into_owned();
    if bytes.len() > limit {
        text.push_str("\n[output truncated]");
    }
    text
}
