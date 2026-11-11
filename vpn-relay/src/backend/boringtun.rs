//! BoringTun implementation of the generic tunnel backend contract.

use super::{
    BackendError, PreparedInterface, TunnelBackend, TunnelHandle, TunnelPeerSnapshot,
    TunnelSnapshot,
};
use crate::config::{decode_key, EndpointHost, InterfaceConfig, PeerEndpoint, TunnelType};
use boringtun::device::{AllowedIP, DeviceConfig, DeviceHandle, PeerConfig};
use boringtun::noise::amnezia::AmneziaConfig;
use boringtun::noise::handshake::ObfuscationRanges;
use boringtun::x25519;
use std::ffi::{CStr, CString};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ptr;
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
                    .map(|endpoint| resolve_endpoint(endpoint))
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
    #[cfg(target_os = "linux")]
    fn verify_identity(&self) -> Result<(), BackendError> {
        self.device
            .verify_interface_identity()
            .map_err(|error| BackendError::new(error.to_string()))
    }

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
            let persistent_keepalive = match &peer.persistent_keepalive_secs {
                Some(value) => Some(value.to_range().map_err(BackendError::new)?),
                None => peer.persistent_keepalive_range,
            };
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

    let mut config = interface.awg.clone().unwrap_or_default();
    if let Some(key) = config.header_protection_key.as_deref() {
        // User-facing configuration follows WireGuard: standard Base64.
        // BoringTun's AmneziaWG config builder consumes the hex UAPI form.
        let decoded = decode_key(key, &format!("interfaces.{name}.awg.header_protection_key"))
            .map_err(|error| BackendError::new(error.to_string()))?;
        config.header_protection_key =
            Some(decoded.iter().map(|byte| format!("{byte:02x}")).collect());
    }
    config
        .build()
        .map_err(|error| BackendError::new(format!("interfaces.{name}.awg: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_passes_keepalive_ranges_and_preserves_fixed_interval_compatibility() {
        for (setting, expected) in [
            ("persistent_keepalive_range = [25, 35]", Some((25, 35))),
            ("persistent_keepalive_secs = 25", Some((25, 25))),
            ("persistent_keepalive_secs = \"25-35\"", Some((25, 35))),
        ] {
            let source = format!(
                r#"
                    type = "wg"
                    address = ["10.0.0.1/24"]
                    private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    [[peers]]
                    public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    allowed_ips = ["10.0.0.2/32"]
                    {setting}
                "#
            );
            let interface: InterfaceConfig = toml::from_str(&source).unwrap();
            let prepared = PreparedInterface {
                peer_endpoints: vec![None],
            };
            let peers = build_peer_configs("wg-test", &interface, &prepared).unwrap();
            assert_eq!(peers[0].persistent_keepalive, expected);
        }
    }

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

fn resolve_ipv4_domain(host: &str, port: u16) -> Result<SocketAddr, String> {
    let host = CString::new(host).map_err(|_| "DNS name contains a NUL byte".to_owned())?;
    let service = CString::new(port.to_string()).expect("decimal port contains no NUL");
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_INET;
    hints.ai_socktype = libc::SOCK_DGRAM;
    let mut result = ptr::null_mut();
    let status = unsafe {
        libc::getaddrinfo(host.as_ptr(), service.as_ptr(), &hints, &mut result)
    };
    if status != 0 {
        let message = unsafe { CStr::from_ptr(libc::gai_strerror(status)) }
            .to_string_lossy()
            .into_owned();
        return Err(message);
    }

    struct AddrInfoGuard(*mut libc::addrinfo);
    impl Drop for AddrInfoGuard {
        fn drop(&mut self) {
            unsafe { libc::freeaddrinfo(self.0) };
        }
    }
    let _guard = AddrInfoGuard(result);
    let mut current = result;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if entry.ai_family == libc::AF_INET && !entry.ai_addr.is_null() {
            let address = unsafe { &*(entry.ai_addr as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
            return Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)));
        }
        current = entry.ai_next;
    }
    Err("DNS returned no IPv4 A records".to_owned())
}

fn resolve_endpoint(value: &str) -> Result<SocketAddr, BackendError> {
    let parsed = PeerEndpoint::parse(value)
        .map_err(|reason| BackendError::new(format!("invalid endpoint {value}: {reason}")))?;
    match parsed.host {
        EndpointHost::Ip(ip) => Ok(SocketAddr::new(ip.into(), parsed.port)),
        EndpointHost::Dns(host) => resolve_ipv4_domain(&host, parsed.port)
            .map_err(|error| BackendError::new(format!("failed to resolve IPv4 endpoint {value}: {error}"))),
    }
}
