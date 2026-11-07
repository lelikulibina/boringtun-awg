//! BoringTun implementation of the generic tunnel backend contract.

use super::{BackendError, TunnelBackend, TunnelHandle, TunnelPeerSnapshot, TunnelSnapshot};
use crate::config::{
    decode_key, AwgConfig, EndpointHost, InterfaceConfig, PeerEndpoint, TunnelType,
};
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
        build_awg_config(name, interface).map(|_| ())
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

    let defaults = AwgConfig::default();
    let raw = interface.awg.as_ref().unwrap_or(&defaults);
    let config = AmneziaWgConfig {
        jc: raw.jc,
        jmin: raw.jmin,
        jmax: raw.jmax,
        s1: raw.s1,
        s2: raw.s2,
        s3: raw.s3,
        s4: raw.s4,
        h1: raw.h1.clone(),
        h2: raw.h2.clone(),
        h3: raw.h3.clone(),
        h4: raw.h4.clone(),
        disable_cookies: raw.disable_cookies,
        random_trailers: raw.random_trailers,
        i1: raw.i1.clone(),
        i2: raw.i2.clone(),
        i3: raw.i3.clone(),
        i4: raw.i4.clone(),
        i5: raw.i5.clone(),
        header_protection_key: raw.header_protection_key.clone(),
        content_padding_addition: raw.content_padding_addition.clone(),
        rekey_after_time: raw.rekey_after_time.clone(),
        rekey_timeout: raw.rekey_timeout.clone(),
        reject_after_time: raw.reject_after_time.clone(),
        keepalive_timeout: raw.keepalive_timeout.clone(),
        max_handshake_attempts: raw.max_handshake_attempts.clone(),
        version: raw.version.clone(),
    };
    config
        .build()
        .map_err(|error| BackendError::new(format!("interfaces.{name}.awg: {error}")))
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
