use anyhow::Result;
use portable_pty::{Child, CommandBuilder, NativePtySystem, PtyPair, PtySize, PtySystem};
use std::collections::HashMap;
use std::path::PathBuf;

/// RAII Wrapper for PTY Child Process to ensure cleanup
pub struct ShellGuard(pub Box<dyn Child + Send + Sync>);

impl Drop for ShellGuard {
    fn drop(&mut self) {
        println!("Cleaning up ShellGuard: Killing process...");
        let _ = self.0.kill();
    }
}

pub struct PtySession {
    pub pair: PtyPair,
    pub child: ShellGuard,
    /// OS PID of the spawned shell process (used for cgroup placement)
    pub child_pid: u32,
}

impl PtySession {
    pub fn new(
        size: PtySize,
        env_vars: HashMap<String, String>,
        cgroup_procs_path: Option<PathBuf>,
    ) -> Result<Self> {
        let pty_system = NativePtySystem::default();
        let pair = pty_system.openpty(size)?;

        // Execute ourselves (the server binary) to handle the INTERNAL_CGROUP_JOIN hook before exec-ing `sh`
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe"));
        let mut cmd = CommandBuilder::new(exe);

        if let Some(path) = cgroup_procs_path {
            cmd.env("INTERNAL_CGROUP_JOIN", path.to_string_lossy().as_ref());
        } else {
            cmd.env("INTERNAL_CGROUP_JOIN", "SKIP");
        }

        for (key, val) in env_vars {
            cmd.env(key, val);
        }

        let child = pair.slave.spawn_command(cmd)?;

        // Retrieve the OS PID (this is the child rust wrapper process, which eventually execs into `sh`)
        let child_pid = child.process_id().unwrap_or(0);

        Ok(Self {
            pair,
            child_pid,
            child: ShellGuard(child),
        })
    }
}
