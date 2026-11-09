// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Atomic replacement of a device's peer set.
//!
//! New peers are fully constructed before any live map is changed. Existing
//! peers are retained in place so unchanged Noise sessions survive a reload.

use super::{require_key_pair, Device, DeviceHandle, Error};
use crate::device::allowed_ips::AllowedIps;
use crate::device::peer::{AllowedIP, Peer};
use crate::noise::Tunn;
use crate::x25519;
use ip_network::IpNetwork;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Complete desired configuration for one peer.
///
/// Unlike the incremental UAPI update API, every optional field is a complete
/// value: `None` clears the endpoint, PSK, or persistent keepalive.
#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<AllowedIP>,
    pub persistent_keepalive: Option<(u32, u32)>,
    pub preshared_key: Option<[u8; 32]>,
}

struct StagedPeer {
    public_key: x25519::PublicKey,
    index: u32,
    peer: Arc<Mutex<Peer>>,
}

impl DeviceHandle {
    /// Atomically replace all configured peers.
    ///
    /// New Noise tunnels are constructed before the live peer maps are
    /// modified. Peers with an unchanged public key are updated in place,
    /// preserving their established sessions and index.
    pub fn replace_peers(&self, configs: &[PeerConfig]) -> Result<(), Error> {
        self.with_device_mut(|device| device.replace_peer_set(configs))
    }
}

impl Device {
    fn replace_peer_set(&mut self, configs: &[PeerConfig]) -> Result<(), Error> {
        let mut desired = HashMap::with_capacity(configs.len());
        let mut prefixes = HashSet::new();

        // Validate the entire declarative input before allocating or changing
        // any live peer state.
        for config in configs {
            let public_key = x25519::PublicKey::from(config.public_key);
            if desired.insert(public_key, config).is_some() {
                return Err(Error::PeerSetup(
                    "peer set contains a duplicate public key".to_owned(),
                ));
            }

            for allowed_ip in &config.allowed_ips {
                let max_prefix = match allowed_ip.addr {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                if allowed_ip.cidr > max_prefix {
                    return Err(Error::PeerSetup(format!(
                        "invalid AllowedIP prefix length: {}/{}",
                        allowed_ip.addr, allowed_ip.cidr
                    )));
                }
                let network = IpNetwork::new_truncate(allowed_ip.addr, allowed_ip.cidr as u32)
                    .map_err(|_| Error::PeerSetup("invalid AllowedIP prefix".to_owned()))?;
                let normalized = AllowedIP {
                    addr: network.network_address(),
                    cidr: network.netmask(),
                };
                if normalized != *allowed_ip {
                    return Err(Error::PeerSetup(format!(
                        "AllowedIP is not a canonical network prefix: {}/{}",
                        allowed_ip.addr, allowed_ip.cidr
                    )));
                }
                if !prefixes.insert(normalized) {
                    return Err(Error::PeerSetup(format!(
                        "peer set assigns the same AllowedIP more than once: {}/{}",
                        normalized.addr, normalized.cidr
                    )));
                }
            }
        }

        // Prepare every new Tunn/Peer before touching the current maps. An
        // error here leaves the previous peer set and all its sessions intact.
        let mut staged = HashMap::new();
        if configs.iter().any(|config| {
            !self.peers.contains_key(&x25519::PublicKey::from(config.public_key))
        }) {
            let key_pair = require_key_pair(&self.key_pair)?;
            for config in configs {
                let public_key = x25519::PublicKey::from(config.public_key);
                if self.peers.contains_key(&public_key) {
                    continue;
                }

                let index = self.next_index();
                let mut tunn = Tunn::new_with_obfuscation(
                    key_pair.0.clone(),
                    public_key,
                    config.preshared_key,
                    None,
                    index,
                    None,
                    self.config.obf,
                    self.config.amnezia.clone(),
                )
                .map_err(Error::PeerSetup)?;
                tunn.set_mtu(self.mtu.load(std::sync::atomic::Ordering::Relaxed));

                let mut peer = Peer::new(
                    tunn,
                    index,
                    config.endpoint,
                    config.preshared_key,
                );
                peer.set_persistent_keepalive_range(config.persistent_keepalive);
                staged.insert(
                    public_key,
                    StagedPeer {
                        public_key,
                        index,
                        peer: Arc::new(Mutex::new(peer)),
                    },
                );
            }
        }

        // Assemble replacement indexes before commit. All allocations and
        // prefix validation happen while the current indexes remain untouched.
        let mut next_peers = HashMap::with_capacity(configs.len());
        let mut next_peers_by_idx = HashMap::with_capacity(configs.len());
        let mut next_peers_by_ip = AllowedIps::new();

        for config in configs {
            let public_key = x25519::PublicKey::from(config.public_key);
            let peer = if let Some(existing) = self.peers.get(&public_key) {
                Arc::clone(existing)
            } else {
                Arc::clone(&staged.get(&public_key).expect("new peer was staged").peer)
            };
            let index = if let Some(existing) = self.peers.get(&public_key) {
                existing.lock().index()
            } else {
                staged.get(&public_key).expect("new peer was staged").index
            };

            next_peers.insert(public_key, Arc::clone(&peer));
            next_peers_by_idx.insert(index, Arc::clone(&peer));
            for allowed_ip in &config.allowed_ips {
                next_peers_by_ip.insert(
                    allowed_ip.addr,
                    allowed_ip.cidr as u32,
                    Arc::clone(&peer),
                );
            }
        }

        // Commit starts here. No fallible setup remains. The enclosing
        // with_device_mut keeps datapath readers out until every index and
        // every retained peer's mutable configuration is consistent.
        for config in configs {
            let public_key = x25519::PublicKey::from(config.public_key);
            if let Some(peer) = self.peers.get(&public_key) {
                let mut peer = peer.lock();

                if peer.endpoint().addr != config.endpoint {
                    peer.shutdown_endpoint();
                    peer.endpoint_mut().addr = config.endpoint;
                    if let Some(endpoint) = config.endpoint {
                        peer.set_endpoint(endpoint);
                    }
                }
                if peer.preshared_key() != config.preshared_key.as_ref() {
                    peer.set_preshared_key(config.preshared_key);
                }
                if peer.persistent_keepalive_range() != config.persistent_keepalive {
                    peer.set_persistent_keepalive_range(config.persistent_keepalive);
                }
            }
        }

        // Retire removed peers only after all replacement maps are ready.
        for (public_key, peer) in &self.peers {
            if !desired.contains_key(public_key) {
                peer.lock().shutdown_endpoint();
            }
        }

        self.peers = next_peers;
        self.peers_by_idx = next_peers_by_idx;
        self.peers_by_ip = next_peers_by_ip;

        tracing::info!(peer_count = configs.len(), "Peer set replaced");
        Ok(())
    }
}
