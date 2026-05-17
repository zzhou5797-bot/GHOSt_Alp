//! libp2p gossipsub control plane.
//!
//! Two topics are maintained:
//!
//! * `ghost_grid_quota` — propagates per-DID quota consumption deltas across nodes so
//!   every peer converges on the same remaining-bytes view without shared state.
//!
//! * `ghost_grid_slash` — carries Ed25519-signed revocation proposals.  When a node's
//!   anomaly detector fires it broadcasts a `P2pMessage::Slash`; once `bft_threshold`
//!   distinct votes for the same (subject, sequence) pair are received, the subject's
//!   `revoked` flag is set in the local `AUTH_STATE_MAP`.
//!
//! Discovery uses mDNS for LAN peers and optional bootstrap multiaddrs for WAN mesh.

use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns, noise, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, Multiaddr,
    Swarm,
};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

use std::collections::{HashMap, HashSet};

/// Quota consumption delta broadcast to peers after each `SYNC_THRESHOLD` flush.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuotaUpdate {
    pub client_subject: u32,
    /// Bytes consumed since the last sync broadcast.
    pub delta_consumed: u64,
    /// Monotonically increasing sequence number; peers ignore stale updates.
    pub sequence_number: u64,
}

/// Messages sent over the gossipsub control plane.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2pMessage {
    Quota(QuotaUpdate),
    Slash {
        /// DID of the subject being proposed for revocation.
        subject: u32,
        /// Human-readable description of the anomaly that triggered the slash.
        reason: String,
        /// DID of the node issuing this vote.
        issuer_did: u32,
        /// Ed25519 signature over `"slash:{subject}:{issuer_did}"`.
        signature_hex: String,
        /// Quota sequence number at the time of the slash event (used to detect stale votes).
        target_sequence: u64,
    },
}

/// Combined libp2p `NetworkBehaviour` for GhostPTY nodes.
#[derive(NetworkBehaviour)]
pub struct GhostP2PBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

/// Build a gossipsub + mDNS swarm with a fresh ephemeral identity.
pub fn build_swarm() -> Result<Swarm<GhostP2PBehaviour>> {
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()
                .expect("Valid gossipsub config");

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .expect("Valid gossipsub config");

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;

            Ok(GhostP2PBehaviour { gossipsub, mdns })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}

/// Run the P2P gossipsub event loop.
///
/// Subscribes to the quota and slash topics, dials bootstrap peers, and
/// processes incoming messages.  Runs until the tokio runtime shuts down.
pub async fn run_p2p(
    mut swarm: Swarm<GhostP2PBehaviour>,
    auth_state_map: Arc<
        tokio::sync::Mutex<
            aya::maps::HashMap<aya::maps::MapData, u32, gateway_ebpf_common::AuthState>,
        >,
    >,
    mut local_updates_rx: mpsc::Receiver<P2pMessage>,
    bootstrap_peers: Vec<Multiaddr>,
    validator_set: Arc<tokio::sync::RwLock<crate::genesis::ValidatorSet>>,
) {
    let topic = gossipsub::IdentTopic::new("ghost_grid_quota");
    let slash_topic = gossipsub::IdentTopic::new("ghost_grid_slash");
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&slash_topic);

    // Listen on an OS-assigned TCP port so remote peers can connect back to us.
    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().expect("valid multiaddr"))
        .ok();

    // Dial every bootstrap peer provided via --bootstrap-peers.
    // gossipsub will discover further peers through these initial connections.
    for addr in &bootstrap_peers {
        if let Err(e) = swarm.dial(addr.clone()) {
            warn!("Failed to dial bootstrap peer {}: {:?}", addr, e);
        } else {
            info!("Dialing bootstrap peer: {}", addr);
        }
    }

    let mut slash_votes: HashMap<(u32, u64), HashSet<u32>> = HashMap::new();

    loop {
        tokio::select! {
            update = local_updates_rx.recv() => {
                if let Some(msg) = update {
                    if let Ok(bytes) = bincode::serialize(&msg) {
                        let t = match msg {
                            P2pMessage::Quota(_) => topic.clone(),
                            P2pMessage::Slash { .. } => slash_topic.clone(),
                        };
                        match swarm.behaviour_mut().gossipsub.publish(t, bytes) {
                            Ok(msg_id) => info!("Gossip published (id={:?})", msg_id),
                            Err(e) => warn!("Failed to publish local P2P message: {:?}", e),
                        }
                    }
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(GhostP2PBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    message,
                    ..
                })) => {
                    if let Ok(p2p_msg) = bincode::deserialize::<P2pMessage>(&message.data) {
                        match p2p_msg {
                            P2pMessage::Quota(update) => {
                                // Reject unreasonably large deltas from potentially malicious peers.
                                const MAX_QUOTA_DELTA: u64 = 10 * 1024 * 1024 * 1024; // 10 GB
                                if update.delta_consumed > MAX_QUOTA_DELTA {
                                    warn!("Dropping quota update from DID {}: delta {} exceeds limit", update.client_subject, update.delta_consumed);
                                    continue;
                                }
                                info!("Received Gossip Quota Update for DID {}: {} bytes", update.client_subject, update.delta_consumed);
                                let mut map = auth_state_map.lock().await;
                                if let Ok(mut state) = map.get(&update.client_subject, 0) {
                                    if update.sequence_number > state.last_seen_quota_seq {
                                        state.quota_bytes = state.quota_bytes.saturating_sub(update.delta_consumed);
                                        state.last_seen_quota_seq = update.sequence_number;
                                        let _ = map.insert(update.client_subject, state, 0);
                                    }
                                }
                            }
                            P2pMessage::Slash { subject, reason, issuer_did, signature_hex, target_sequence } => {
                                info!("Received Slash Proposal from DID {} for DID {}: {} (Seq {})", issuer_did, subject, reason, target_sequence);

                                let (sig_ok, threshold) = {
                                    let vs = validator_set.read().await;
                                    (
                                        vs.verify_slash_signature(subject, issuer_did, target_sequence, &signature_hex),
                                        vs.bft_threshold,
                                    )
                                };
                                if !sig_ok {
                                    warn!("Dropped invalid BFT Slash signature from DID {}", issuer_did);
                                    continue;
                                }

                                let votes = slash_votes.entry((subject, target_sequence)).or_default();
                                votes.insert(issuer_did);

                                if votes.len() >= threshold {
                                    info!("BFT Threshold ({}) reached! Slashing DID {} at seq {}.", threshold, subject, target_sequence);
                                    let mut map = auth_state_map.lock().await;
                                    if let Ok(mut state) = map.get(&subject, 0) {
                                        if state.last_seen_quota_seq <= target_sequence || state.last_seen_quota_seq == 0 {
                                            state.revoked = 1;
                                            let _ = map.insert(subject, state, 0);
                                        } else {
                                            info!("BFT Threshold reached but ignored: target seq {} older than actual seq {}.", target_sequence, state.last_seen_quota_seq);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("P2P Node listening on {:?}", address);
                }
                _ => {}
            }
        }
    }
}
