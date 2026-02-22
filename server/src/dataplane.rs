/// DataPlane abstraction — control plane talks to this trait, never to eBPF maps directly.
///
/// The philosophy (SDN-style):
///   - Control plane (handle_connection, GC daemon) only calls authorize/revoke/set_quota.
///   - Data plane (EbpfDataPlane) translates those intent calls into low-level map ops.
///   - Future: MockDataPlane for tests; GrpcDataPlane for remote node delegation.
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;

pub trait DataPlaneEngine: Send {
    /// Allow traffic from `ip` on behalf of DID `subject`.
    /// Inserts (ip → subject) into ALLOW_LIST_MAP and bootstraps AUTH_STATE_MAP
    /// if the subject has no existing entry.
    fn authorize(&mut self, subject: u32, ip: u32) -> Result<()>;

    /// Remove the IP binding and, if no other IPs share the subject, also
    /// delete the AUTH_STATE_MAP entry.
    fn revoke(&mut self, subject: u32, ip: u32) -> Result<()>;

    /// Set or update the remaining payload quota for a subject (bytes).
    /// Called by the control plane quota manager.
    fn set_quota(&mut self, subject: u32, bytes: u64) -> Result<()>;
}

// ── Concrete eBPF implementation ──────────────────────────────────────────────

use aya::maps::HashMap as EbpfHashMap;
use gateway_ebpf_common::AuthState;

pub struct EbpfDataPlane {
    allow_map: Arc<Mutex<EbpfHashMap<&'static mut aya::maps::MapData, u32, u32>>>,
    auth_map: Arc<Mutex<EbpfHashMap<&'static mut aya::maps::MapData, u32, AuthState>>>,
    /// Ref-count: (subject → [(ip, count)]) — tracks how many IPs share a subject.
    ip_to_subject: std::collections::HashMap<u32, u32>,
    subject_ip_count: std::collections::HashMap<u32, usize>,
}

impl EbpfDataPlane {
    pub fn new(
        allow_map: Arc<Mutex<EbpfHashMap<&'static mut aya::maps::MapData, u32, u32>>>,
        auth_map: Arc<Mutex<EbpfHashMap<&'static mut aya::maps::MapData, u32, AuthState>>>,
    ) -> Self {
        Self {
            allow_map,
            auth_map,
            ip_to_subject: std::collections::HashMap::new(),
            subject_ip_count: std::collections::HashMap::new(),
        }
    }
}

impl DataPlaneEngine for EbpfDataPlane {
    fn authorize(&mut self, subject: u32, ip: u32) -> Result<()> {
        // Track ref-count
        self.ip_to_subject.insert(ip, subject);
        let count = self.subject_ip_count.entry(subject).or_insert(0);
        *count += 1;

        // Write ALLOW_LIST_MAP synchronously (we're already behind a Mutex in the caller)
        let allow_map = self.allow_map.try_lock();
        if let Ok(mut m) = allow_map {
            m.insert(ip, subject, 0)?;
        }

        // If first IP for this subject, bootstrap AUTH_STATE_MAP with default state
        if *count == 1 {
            let auth_map = self.auth_map.try_lock();
            if let Ok(mut m) = auth_map {
                // Only insert if no existing entry (preserves in-flight hash chain state)
                if m.get(&subject, 0).is_err() {
                    let initial = AuthState {
                        expected_seq: u64::MAX,
                        anchor_hash_lo: 0,
                        bucket_tokens: AuthState::MAX_TOKENS,
                        last_refill_ns: 0,
                        quota_bytes: 10_000_000_000, // 10 GiB default
                        last_seen_quota_seq: 0,
                        revoked: 0,
                    };
                    let _ = m.insert(subject, initial, 0);
                }
            }
        }
        Ok(())
    }

    fn revoke(&mut self, subject: u32, ip: u32) -> Result<()> {
        self.ip_to_subject.remove(&ip);
        let count = self.subject_ip_count.entry(subject).or_insert(0);
        if *count > 0 {
            *count -= 1;
        }

        let allow_map = self.allow_map.try_lock();
        if let Ok(mut m) = allow_map {
            let _ = m.remove(&ip);
        }

        // Remove AUTH_STATE_MAP entry when no IPs remain for this subject
        if *count == 0 {
            self.subject_ip_count.remove(&subject);
            let auth_map = self.auth_map.try_lock();
            if let Ok(mut m) = auth_map {
                let _ = m.remove(&subject);
            }
        }
        Ok(())
    }

    fn set_quota(&mut self, subject: u32, bytes: u64) -> Result<()> {
        let auth_map = self.auth_map.try_lock();
        if let Ok(mut m) = auth_map {
            if let Ok(mut state) = m.get(&subject, 0) {
                state.quota_bytes = bytes;
                m.insert(subject, state, 0)?;
            }
        }
        Ok(())
    }
}

// ── Shared Arc wrapper for use across tasks ───────────────────────────────────

pub type SharedDataPlane = Arc<Mutex<dyn DataPlaneEngine>>;

pub fn new_shared(plane: impl DataPlaneEngine + 'static) -> SharedDataPlane {
    Arc::new(Mutex::new(plane))
}
