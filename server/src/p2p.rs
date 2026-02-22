use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub, mdns, noise, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, Swarm,
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
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum P2pMessage {
    Quota(QuotaUpdate),
    Slash { subject: u32, reason: String },
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
) {
    let topic = gossipsub::IdentTopic::new("ghost_grid_quota");
    let slash_topic = gossipsub::IdentTopic::new("ghost_grid_slash");
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&slash_topic);

    let mut slash_votes: HashMap<u32, HashSet<libp2p::PeerId>> = HashMap::new();

    loop {
        tokio::select! {
            update = local_updates_rx.recv() => {
                if let Some(msg) = update {
                    if let Ok(bytes) = bincode::serialize(&msg) {
                        let t = match msg {
                            P2pMessage::Quota(_) => topic.clone(),
                            P2pMessage::Slash { .. } => slash_topic.clone(),
                        };
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(t, bytes) {
                            warn!("Failed to publish local P2P message: {:?}", e);
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
                                    if update.timestamp > state.last_refill_ns {
                                        state.quota_bytes = state.quota_bytes.saturating_sub(update.delta_consumed);
                                        let _ = map.insert(update.client_subject, state, 0);
                                    }
                                }
                            }
                            P2pMessage::Slash { subject, reason } => {
                                info!("Received Slash Proposal from {:?} for DID {}: {}", peer_id, subject, reason);
                                let votes = slash_votes.entry(subject).or_default();
                                votes.insert(peer_id);

                                // BFT Slash Consensus (m >= 1 for localhost dev testing)
                                if votes.len() >= 1 {
                                    info!("BFT Threshold reached! Slashing DID {} permanently.", subject);
                                    let mut map = auth_state_map.lock().await;
                                    if let Ok(mut state) = map.get(&subject, 0) {
                                        state.revoked = 1;
                                        let _ = map.insert(subject, state, 0);
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
