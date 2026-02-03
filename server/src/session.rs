use portable_pty::{Child, CommandBuilder, NativePtySystem, PtyPair, PtySize, PtySystem};
use anyhow::Result;
use std::collections::HashMap;

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
}

impl PtySession {
    pub fn new(size: PtySize, env_vars: HashMap<String, String>) -> Result<Self> {
        let pty_system = NativePtySystem::default();
        let pair = pty_system.openpty(size)?;

        let mut cmd = CommandBuilder::new("sh"); // Or "bash"
        for (key, val) in env_vars {
            cmd.env(key, val);
        }

        let child = pair.slave.spawn_command(cmd)?;
        
        // Return session (child is wrapped in ShellGuard)
        Ok(Self {
            pair,
            child: ShellGuard(child),
        })
    }
}
