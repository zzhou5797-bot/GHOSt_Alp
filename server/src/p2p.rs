use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns, noise, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, Multiaddr,
    Swarm,
};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

use std::collections::{HashMap, HashSet};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuotaUpdate {
    pub client_subject: u32,
    pub delta_consumed: u64,
    pub sequence_number: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2pMessage {
    Quota(QuotaUpdate),
    Slash {
        subject: u32,
        reason: String,
        issuer_did: u32,
        signature_hex: String,
        target_sequence: u64,
    },
}

#[derive(NetworkBehaviour)]
pub struct GhostP2PBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

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

pub async fn run_p2p(
    mut swarm: Swarm<GhostP2PBehaviour>,
    auth_state_map: std::sync::Arc<
        tokio::sync::Mutex<
            aya::maps::HashMap<aya::maps::MapData, u32, gateway_ebpf_common::AuthState>,
        >,
    >,
    mut local_updates_rx: mpsc::Receiver<P2pMessage>,
    bootstrap_peers: Vec<Multiaddr>,
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
                    propagation_source: peer_id,
                    message_id: _id,
                    message,
                })) => {
                    if let Ok(p2p_msg) = bincode::deserialize::<P2pMessage>(&message.data) {
                        match p2p_msg {
                            P2pMessage::Quota(update) => {
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

                                // Phase 6.2: Sybil Threshold Cryptographic Check
                                if !crate::genesis::verify_slash_signature(subject, issuer_did, &signature_hex) {
                                    warn!("🚨 Dropped invalid BFT Slash signature from DID {}", issuer_did);
                                    continue;
                                }

                                let votes = slash_votes.entry((subject, target_sequence)).or_default();
                                votes.insert(issuer_did);

                                // BFT Slash Consensus: Require at least 3 unique Authorized DIDs to prevent Sybil attacks
                                if votes.len() >= 3 {
                                    info!("BFT Threshold (3) reached! Slashing DID {} permanently at seq {}.", subject, target_sequence);
                                    let mut map = auth_state_map.lock().await;
                                    if let Ok(mut state) = map.get(&subject, 0) {
                                        // Auto-expire legacy misvotes by only honoring the slash if the state's seq matches or is closely tracking the vote
                                        if state.last_seen_quota_seq <= target_sequence || state.last_seen_quota_seq == 0 {
                                            state.revoked = 1;
                                            let _ = map.insert(subject, state, 0);
                                        } else {
                                            info!("BFT Threshold reached but ignored: Target seq {} is older than actual seq {}.", target_sequence, state.last_seen_quota_seq);
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
