use std::{collections::HashMap, ops::Index};

use ipnet::IpNet;
use iroh::PublicKey;

use crate::{ip::IpPacket, sync::{GatedReceiver, GatedSender, gated_channel}};

pub mod config;
pub mod ip;
pub mod sync;
pub mod tunnel;

pub const GATED_CHANNEL_BUFFER: usize = 1024;


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(usize);

pub struct PeerState {
    pub key: PublicKey,
    pub subnets: Vec<IpNet>,
    pub sender: GatedSender<IpPacket>,
}

pub struct PubkeyToId {
    by_key: HashMap<PublicKey, PeerId>,
    configs: Vec<PeerState>,
    cached_rx: HashMap<usize, GatedReceiver<IpPacket>>,
    keys: Vec<PublicKey>,
}

impl PubkeyToId {
    pub fn new() -> Self {
        Self {
            by_key: HashMap::new(),
            configs: Vec::new(),
            cached_rx: HashMap::new(),
            keys: Vec::new(),
        }
    }

    pub fn insert(&mut self, key: PublicKey) -> (PeerId, &mut PeerState) {
        if let Some(&id) = self.by_key.get(&key) {
            return (id, self.get_mut(id));
        }

        // Does not exist yet!
        let id = PeerId(self.keys.len());
        let (tx, rx) = gated_channel(GATED_CHANNEL_BUFFER);
        self.configs.push(PeerState {
            key,
            subnets: Vec::new(),
            sender: tx,
        });
        self.cached_rx.insert(id.0, rx);
        self.keys.push(key);
        self.by_key.insert(key, id);
        (id, self.get_mut(id))
    }

    pub fn get(&self, id: PeerId) -> &PeerState {
        &self.configs[id.0]
    }

    pub fn get_mut(&mut self, id: PeerId) -> &mut PeerState {
        &mut self.configs[id.0]
    }

    pub fn states(&self) -> &[PeerState] {
        &self.configs
    }

    pub fn get_peer(&self, key: PublicKey) -> Option<PeerId> {
        self.by_key.get(&key).copied()
    }

    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }

    pub fn take_recv(&mut self, id: PeerId) -> Option<GatedReceiver<IpPacket>> {
        self.cached_rx.remove(&id.0)
    }
}

impl Default for PubkeyToId {
    fn default() -> Self {
        Self::new()
    }
}

impl Index<PeerId> for PubkeyToId {
    type Output = PublicKey;

    fn index(&self, id: PeerId) -> &Self::Output {
        &self.keys[id.0]
    }
}
