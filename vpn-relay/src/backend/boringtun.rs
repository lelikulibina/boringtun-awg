//! BoringTun implementation of the generic tunnel backend contract.

use super::{BackendError, TunnelBackend, TunnelHandle, TunnelPeerSnapshot, TunnelSnapshot};
use crate::config::{decode_key, EndpointHost, InterfaceConfig, PeerEndpoint, TunnelType};
use boringtun::device::{AllowedIP, DeviceConfig, DeviceHandle};
use boringtun::noise::amnezia::{AmneziaConfig, AmneziaWgConfig};
use boringtun::noise::handshake::ObfuscationRanges;
use boringtun::x25519;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;

#[derive(Default)]
pub(super) struct BoringTunBackend;

impl TunnelBackend for BoringTunBackend {
    fn validate(&self, name: &str, interface: &InterfaceConfig) -> Result<(), BackendError> {
        build_awg_config(name, interface)?;

        // Resolve every configured endpoint during preflight, before runtime
        // installs nftables or creates any tunnel interface. Creation resolves
        // again so the live socket uses a current DNS result; this early pass
        // catches invalid/unresolvable endpoints before system state changes.
        for (index, peer) in interface.peers.iter().enumerate() {
            if let Some(endpoint) = peer.endpoint.as_deref() {
                resolve_endpoint(endpoint).map_err(|error| {
                    BackendError::new(format!(
                        "interfaces.{name}.peers[{index}].endpoint: {error}"
                    ))
                })?;
            }
        }

        Ok(())
    }

    fn create(
        &self,
        name: &str,
        interface: &InterfaceConfig,
        socket_fwmark: u32,
    ) -> Result<Box<dyn TunnelHandle>, BackendError> {
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

        for peer in &interface.peers {
            let public_key = x25519::PublicKey::from(
                decode_key(&peer.public_key, "peer.public_key")
                    .map_err(|error| BackendError::new(error.to_string()))?,
            );
            let preshared_key = peer
                .preshared_key
                .as_ref()
                .map(|value| {
                    decode_key(value, "peer.preshared_key")
                        .map_err(|error| BackendError::new(error.to_string()))
                })
                .transpose()?;
            let endpoint = peer.endpoint.as_deref().map(resolve_endpoint).transpose()?;
            let allowed_ips: Result<Vec<AllowedIP>, _> = peer
                .allowed_ips
                .iter()
                .map(|prefix| {
                    AllowedIP::from_str(prefix).map_err(|error| {
                        BackendError::new(format!("invalid AllowedIP {prefix}: {error}"))
                    })
                })
                .collect();
            let keepalive = peer
                .persistent_keepalive_secs
                .map(|seconds| (u32::from(seconds), u32::from(seconds)));
            device
                .update_peer(
                    public_key,
                    false,
                    true,
                    endpoint,
                    &allowed_ips?,
                    keepalive,
                    preshared_key,
                )
                .map_err(|error| BackendError::new(error.to_string()))?;
        }

        Ok(Box::new(BoringTunHandle { device }))
    }
}

struct BoringTunHandle {
    device: DeviceHandle,
}

impl TunnelHandle for BoringTunHandle {
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
            .validate("wg-preflight", &interface)
            .expect_err("reserved .invalid endpoint must not resolve");
        assert!(error.to_string().contains("peers[0].endpoint"));

        interface.peers[0].endpoint = Some("192.0.2.10:51820".to_owned());
        BoringTunBackend
            .validate("wg-preflight", &interface)
            .expect("literal endpoint should pass preflight");
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
