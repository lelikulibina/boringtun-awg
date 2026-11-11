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
        validate_peer_configs(configs)?;
        let desired: HashSet<x25519::PublicKey> = configs
            .iter()
            .map(|config| x25519::PublicKey::from(config.public_key))
            .collect();

        // Prepare every new Tunn/Peer before touching the current maps. An
        // error here leaves the previous peer set and all its sessions intact.
        let mut staged = HashMap::new();
        if configs.iter().any(|config| {
            !self
                .peers
                .contains_key(&x25519::PublicKey::from(config.public_key))
        }) {
            let private_key = require_key_pair(&self.key_pair)?.0.clone();
            for config in configs {
                let public_key = x25519::PublicKey::from(config.public_key);
                if self.peers.contains_key(&public_key) {
                    continue;
                }

                let index = self.next_index();
                let mut tunn = Tunn::new_with_obfuscation(
                    private_key.clone(),
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

                let mut peer = Peer::new(tunn, index, config.endpoint, config.preshared_key);
                peer.set_persistent_keepalive_range(config.persistent_keepalive);
                staged.insert(
                    public_key,
                    StagedPeer {
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
                Arc::clone(
                    &staged
                        .get(&public_key)
                        .ok_or_else(|| Error::PeerSetup("new peer was not staged".to_owned()))?
                        .peer,
                )
            };
            let index = if let Some(existing) = self.peers.get(&public_key) {
                existing.lock().index()
            } else {
                staged
                    .get(&public_key)
                    .ok_or_else(|| Error::PeerSetup("new peer was not staged".to_owned()))?
                    .index
            };

            next_peers.insert(public_key, Arc::clone(&peer));
            next_peers_by_idx.insert(index, Arc::clone(&peer));
            for allowed_ip in &config.allowed_ips {
                next_peers_by_ip.insert(allowed_ip.addr, allowed_ip.cidr as u32, Arc::clone(&peer));
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
                    if let Some(endpoint) = config.endpoint {
                        peer.set_endpoint(endpoint);
                    } else {
                        peer.endpoint_mut().addr = None;
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
            if !desired.contains(public_key) {
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

/// Validate declarative peer input without touching the device or allocating
/// live peer resources.
fn validate_peer_configs(configs: &[PeerConfig]) -> Result<(), Error> {
    let mut public_keys = HashSet::with_capacity(configs.len());
    let mut prefixes = HashSet::new();

    for config in configs {
        let public_key = x25519::PublicKey::from(config.public_key);
        if !public_keys.insert(public_key) {
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
            let network = IpNetwork::new_truncate(allowed_ip.addr, allowed_ip.cidr)
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(public_key: [u8; 32], allowed_ips: Vec<AllowedIP>) -> PeerConfig {
        PeerConfig {
            public_key,
            endpoint: None,
            allowed_ips,
            persistent_keepalive: None,
            preshared_key: None,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root and /dev/net/tun"]
    fn replacement_updates_and_clears_peer_fields_then_removes_peer() {
        use super::super::DeviceConfig;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static NEXT_INTERFACE: AtomicUsize = AtomicUsize::new(9000);
        let name = format!("utun{}", NEXT_INTERFACE.fetch_add(1, Ordering::Relaxed));
        let mut device = DeviceHandle::new(
            &name,
            DeviceConfig {
                n_threads: 1,
                ..DeviceConfig::default()
            },
        )
        .expect("create test tunnel device");

        device.set_private_key(x25519::StaticSecret::from([1u8; 32]));
        let public_key = x25519::PublicKey::from(&x25519::StaticSecret::from([2u8; 32]));
        let psk = [3u8; 32];
        let endpoint = "127.0.0.1:51820".parse().unwrap();
        let first_prefix = AllowedIP {
            addr: "10.10.0.0".parse().unwrap(),
            cidr: 24,
        };

        device
            .replace_peers(&[PeerConfig {
                public_key: *public_key.as_bytes(),
                endpoint: Some(endpoint),
                allowed_ips: vec![first_prefix],
                persistent_keepalive: Some((25, 25)),
                preshared_key: Some(psk),
            }])
            .expect("install initial peer");
        let initial = device.snapshot().expect("initial snapshot");
        assert_eq!(initial.peers.len(), 1);
        let original_index = initial.peers[0].index;

        let invalid = [
            config(*public_key.as_bytes(), vec![]),
            config(*public_key.as_bytes(), vec![]),
        ];
        assert!(device.replace_peers(&invalid).is_err());

        let second_prefix = AllowedIP {
            addr: "10.20.0.0".parse().unwrap(),
            cidr: 24,
        };
        device
            .replace_peers(&[PeerConfig {
                public_key: *public_key.as_bytes(),
                endpoint: None,
                allowed_ips: vec![second_prefix],
                persistent_keepalive: None,
                preshared_key: None,
            }])
            .expect("replace peer and clear optional fields");

        let updated = device.snapshot().expect("updated snapshot");
        assert_eq!(updated.peers.len(), 1);
        assert_eq!(updated.peers[0].index, original_index);
        assert_eq!(updated.peers[0].endpoint, None);
        assert_eq!(updated.peers[0].persistent_keepalive, None);
        assert_eq!(updated.peers[0].allowed_ips, vec![second_prefix]);

        // Adding an unrelated peer must not reconstruct the unchanged peer:
        // its Arc owns the live Peer/Tunn state, including the Noise session.
        let retained_peer = device.with_device_mut(|inner| {
            Arc::clone(inner.peers.get(&public_key).expect("retained peer"))
        });
        let second_public_key = x25519::PublicKey::from(&x25519::StaticSecret::from([4u8; 32]));
        let third_prefix = AllowedIP {
            addr: "10.30.0.0".parse().unwrap(),
            cidr: 24,
        };
        device
            .replace_peers(&[
                PeerConfig {
                    public_key: *public_key.as_bytes(),
                    endpoint: None,
                    allowed_ips: vec![second_prefix],
                    persistent_keepalive: None,
                    preshared_key: None,
                },
                config(*second_public_key.as_bytes(), vec![third_prefix]),
            ])
            .expect("add another peer without replacing the unchanged peer");
        let retained_after_reload = device.with_device_mut(|inner| {
            Arc::clone(
                inner
                    .peers
                    .get(&public_key)
                    .expect("retained peer after reload"),
            )
        });
        assert!(
            Arc::ptr_eq(&retained_peer, &retained_after_reload),
            "unchanged peer must retain its Peer/Tunn allocation across replacement"
        );
        assert_eq!(
            retained_peer.lock().index(),
            retained_after_reload.lock().index(),
            "unchanged peer index must remain stable"
        );

        device.replace_peers(&[]).expect("remove all peers");
        assert!(device.snapshot().expect("empty snapshot").peers.is_empty());

        device.shutdown();
        device.wait();
    }

    #[test]
    fn peer_batch_validation_accepts_distinct_and_nested_prefixes() {
        let configs = [
            config(
                [1; 32],
                vec![AllowedIP {
                    addr: "10.0.0.0".parse().unwrap(),
                    cidr: 24,
                }],
            ),
            config(
                [2; 32],
                vec![AllowedIP {
                    addr: "10.0.0.1".parse().unwrap(),
                    cidr: 32,
                }],
            ),
        ];
        assert!(validate_peer_configs(&configs).is_ok());
    }

    #[test]
    fn peer_batch_validation_rejects_duplicate_public_keys() {
        let configs = [config([1; 32], vec![]), config([1; 32], vec![])];
        assert!(validate_peer_configs(&configs).is_err());
    }

    #[test]
    fn peer_batch_validation_rejects_duplicate_prefix_ownership() {
        let prefix = AllowedIP {
            addr: "10.0.0.0".parse().unwrap(),
            cidr: 24,
        };
        let configs = [config([1; 32], vec![prefix]), config([2; 32], vec![prefix])];
        assert!(validate_peer_configs(&configs).is_err());
    }

    #[test]
    fn peer_batch_validation_rejects_noncanonical_prefixes() {
        let configs = [config(
            [1; 32],
            vec![AllowedIP {
                addr: "10.0.0.1".parse().unwrap(),
                cidr: 24,
            }],
        )];
        assert!(validate_peer_configs(&configs).is_err());
    }
}
