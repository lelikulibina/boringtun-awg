//! BoringTun implementation of the generic tunnel backend contract.

use super::{
    BackendError, PreparedInterface, TunnelBackend, TunnelHandle, TunnelPeerSnapshot,
    TunnelSnapshot,
};
use crate::config::{decode_key, EndpointHost, InterfaceConfig, PeerEndpoint, TunnelType};
use boringtun::device::{AllowedIP, DeviceConfig, DeviceHandle, PeerConfig};
use boringtun::noise::amnezia::{AmneziaConfig, AmneziaWgConfig};
use boringtun::noise::handshake::ObfuscationRanges;
use boringtun::x25519;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;

#[derive(Default)]
pub(super) struct BoringTunBackend;

impl TunnelBackend for BoringTunBackend {
    fn prepare(
        &self,
        name: &str,
        interface: &InterfaceConfig,
    ) -> Result<PreparedInterface, BackendError> {
        build_awg_config(name, interface)?;

        // Resolve all endpoints before runtime mutates host networking. Keep
        // these exact results so creation does not perform a second DNS lookup.
        let peer_endpoints = interface
            .peers
            .iter()
            .enumerate()
            .map(|(index, peer)| {
                peer.endpoint
                    .as_deref()
                    .map(resolve_endpoint)
                    .transpose()
                    .map_err(|error| {
                        BackendError::new(format!(
                            "interfaces.{name}.peers[{index}].endpoint: {error}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PreparedInterface { peer_endpoints })
    }

    fn create(
        &self,
        name: &str,
        interface: &InterfaceConfig,
        socket_fwmark: u32,
        prepared: &PreparedInterface,
    ) -> Result<Box<dyn TunnelHandle>, BackendError> {
        if prepared.peer_endpoints.len() != interface.peers.len() {
            return Err(BackendError::new(
                "prepared peer endpoint count does not match interface peer count",
            ));
        }
        let (obf, amnezia) = build_awg_config(name, interface)?;
        let config = DeviceConfig {
            n_threads: 4,
            use_connected_socket: true,
            use_multi_queue: true,
            uapi_fd: -1,
            enable_uapi: false,
            listen_port: interface.listen_port,
            obf,
            amnezia,
            probe_reply_bytes_per_sec: None,
        };
        let device = DeviceHandle::new(name, config)
            .map_err(|error| BackendError::new(error.to_string()))?;
        device.set_private_key(x25519::StaticSecret::from(
            decode_key(&interface.private_key, "private_key")
                .map_err(|error| BackendError::new(error.to_string()))?,
        ));
        device
            .set_fwmark(socket_fwmark)
            .map_err(|error| BackendError::new(error.to_string()))?;

        let peers = build_peer_configs(name, interface, prepared)?;
        device
            .replace_peers(&peers)
            .map_err(|error| BackendError::new(error.to_string()))?;

        Ok(Box::new(BoringTunHandle {
            name: name.to_owned(),
            device,
        }))
    }
}

struct BoringTunHandle {
    name: String,
    device: DeviceHandle,
}

impl TunnelHandle for BoringTunHandle {
    fn replace_peers(
        &mut self,
        interface: &InterfaceConfig,
        prepared: &PreparedInterface,
    ) -> Result<(), BackendError> {
        let peers = build_peer_configs(&self.name, interface, prepared)?;
        self.device
            .replace_peers(&peers)
            .map_err(|error| BackendError::new(error.to_string()))
    }

    fn snapshot(&self) -> Result<TunnelSnapshot, BackendError> {
        let snapshot = self
            .device
            .snapshot()
            .map_err(|error| BackendError::new(error.to_string()))?;
        Ok(TunnelSnapshot {
            name: snapshot.name,
            peers: snapshot
                .peers
                .into_iter()
                .map(|peer| TunnelPeerSnapshot {
                    public_key: peer.public_key,
                    tx_bytes: peer.tx_bytes,
                    rx_bytes: peer.rx_bytes,
                    time_since_last_handshake: peer.time_since_last_handshake,
                })
                .collect(),
        })
    }

    fn shutdown(&self) {
        self.device.shutdown();
    }

    fn wait(&mut self) {
        self.device.wait();
    }
}

fn build_peer_configs(
    name: &str,
    interface: &InterfaceConfig,
    prepared: &PreparedInterface,
) -> Result<Vec<PeerConfig>, BackendError> {
    if prepared.peer_endpoints.len() != interface.peers.len() {
        return Err(BackendError::new(
            "prepared peer endpoint count does not match interface peer count",
        ));
    }
    interface
        .peers
        .iter()
        .zip(&prepared.peer_endpoints)
        .map(|(peer, endpoint)| {
            let public_key = decode_key(&peer.public_key, "peer.public_key")
                .map_err(|error| BackendError::new(error.to_string()))?;
            let preshared_key = peer
                .preshared_key
                .as_ref()
                .map(|value| {
                    decode_key(value, "peer.preshared_key")
                        .map_err(|error| BackendError::new(error.to_string()))
                })
                .transpose()?;
            let allowed_ips = peer
                .allowed_ips
                .iter()
                .map(|prefix| {
                    AllowedIP::from_str(prefix).map_err(|error| {
                        BackendError::new(format!(
                            "interfaces.{name}: invalid AllowedIP {prefix}: {error}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let persistent_keepalive = peer
                .persistent_keepalive_secs
                .map(|seconds| (u32::from(seconds), u32::from(seconds)));
            Ok(PeerConfig {
                public_key,
                endpoint: *endpoint,
                allowed_ips,
                persistent_keepalive,
                preshared_key,
            })
        })
        .collect()
}

fn build_awg_config(
    name: &str,
    interface: &InterfaceConfig,
) -> Result<(ObfuscationRanges, AmneziaConfig), BackendError> {
    if interface.tunnel_type == TunnelType::WireGuard {
        return Ok((ObfuscationRanges::default(), AmneziaConfig::default()));
    }

    let defaults = AmneziaWgConfig::default();
    let config = interface.awg.as_ref().unwrap_or(&defaults);
    config
        .build()
        .map_err(|error| BackendError::new(format!("interfaces.{name}.awg: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_preflight_resolves_peer_endpoints_before_runtime_setup() {
        let mut interface: InterfaceConfig = toml::from_str(
            r#"
                type = "wg"
                address = ["10.0.0.1/24"]
                private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                [[peers]]
                public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                endpoint = "vpn-relay-preflight.invalid:51820"
                allowed_ips = ["10.0.0.2/32"]
            "#,
        )
        .expect("valid interface shape");

        let error = BoringTunBackend
            .prepare("wg-preflight", &interface)
            .expect_err("reserved .invalid endpoint must not resolve");
        assert!(error.to_string().contains("peers[0].endpoint"));

        interface.peers[0].endpoint = Some("192.0.2.10:51820".to_owned());
        let prepared = BoringTunBackend
            .prepare("wg-preflight", &interface)
            .expect("literal endpoint should pass preflight");
        assert_eq!(
            prepared.peer_endpoints,
            vec![Some("192.0.2.10:51820".parse().unwrap())]
        );
    }
}

fn resolve_endpoint(value: &str) -> Result<SocketAddr, BackendError> {
    let parsed = PeerEndpoint::parse(value)
        .map_err(|reason| BackendError::new(format!("invalid endpoint {value}: {reason}")))?;
    match parsed.host {
        EndpointHost::Ip(ip) => Ok(SocketAddr::new(ip, parsed.port)),
        EndpointHost::Dns(host) => (host.as_str(), parsed.port)
            .to_socket_addrs()
            .map_err(|error| {
                BackendError::new(format!("failed to resolve endpoint {value}: {error}"))
            })?
            .next()
            .ok_or_else(|| {
                BackendError::new(format!("DNS returned no addresses for endpoint {value}"))
            }),
    }
}
