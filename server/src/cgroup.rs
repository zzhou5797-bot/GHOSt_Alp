//! Cgroupv2 management for PTY session isolation and kernel audit.
//!
//! Each PTY session gets its own cgroup under:
//!   /sys/fs/cgroup/ghostpty_sessions/<session_id>/
//!
//! The shell process (and all children) are placed in this cgroup,
//! and the numeric cgroup ID is returned so it can be inserted into
//! the AUDIT_CGROUP_MAP eBPF map to activate the kernel audit probe.

use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
};

const CGROUP_BASE: &str = "/sys/fs/cgroup/ghostpty_sessions";

/// Represents a live session cgroup. Removes the cgroup directory on drop.
pub struct SessionCgroup {
    pub path: PathBuf,
    /// Numeric cgroup ID read from `cgroup.id` (used for AUDIT_CGROUP_MAP)
    pub id: u64,
}

impl SessionCgroup {
    /// Create a new cgroupv2 directory for the given session ID and move the
    /// child PID into it. Returns the numeric cgroup ID.
    pub fn create(session_id: &str, child_pid: u32) -> Result<Self> {
        let path = PathBuf::from(CGROUP_BASE).join(session_id);

        // Ensure the base directory exists (server may run as root in production)
        fs::create_dir_all(&path)
            .with_context(|| format!("Failed to create cgroup dir: {}", path.display()))?;

        // Move the child process into this cgroup
        let procs_file = path.join("cgroup.procs");
        fs::write(&procs_file, format!("{}\n", child_pid)).with_context(|| {
            format!(
                "Failed to write PID {} to {}",
                child_pid,
                procs_file.display()
            )
        })?;

        // Read back the numeric cgroup ID assigned by the kernel
        let id = Self::read_cgroup_id(&path)?;

        tracing::info!(
            "[CGROUP] Session '{}' → cgroup_id={} (pid={})",
            session_id,
            id,
            child_pid
        );

        Ok(Self { path, id })
    }

    /// Read the numeric cgroup ID from `/sys/fs/cgroup/.../cgroup.id` using
    /// the `ino` of the directory (kernels < 5.7) or the `cgroup.id` file.
    fn read_cgroup_id(path: &Path) -> Result<u64> {
        // Kernels >= 5.7 expose cgroup.id as a file
        let id_file = path.join("cgroup.id");
        if id_file.exists() {
            let raw = fs::read_to_string(&id_file)
                .with_context(|| format!("Failed to read {}", id_file.display()))?;
            let id: u64 = raw
                .trim()
                .parse()
                .with_context(|| format!("Invalid cgroup.id content: '{}'", raw.trim()))?;
            return Ok(id);
        }

        // Fallback: use the inode number of the cgroup directory as the ID.
        // bpf_get_current_cgroup_id() actually returns the cgroup inode number.
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(path)
            .with_context(|| format!("Failed to stat cgroup dir: {}", path.display()))?;
        Ok(meta.ino())
    }
}

impl Drop for SessionCgroup {
    fn drop(&mut self) {
        // Best-effort cleanup: remove the cgroup directory when the session ends.
        // The cgroup must be empty (no tasks) before it can be removed.
        if self.path.exists() {
            if let Err(e) = fs::remove_dir(&self.path) {
                tracing::warn!(
                    "[CGROUP] Failed to remove cgroup {}: {}",
                    self.path.display(),
                    e
                );
            } else {
                tracing::info!("[CGROUP] Removed cgroup {}", self.path.display());
            }
        }
    }
}
