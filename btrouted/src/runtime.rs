//! Linux runtime: create BoringTun devices, configure peers, and install routing.
use crate::config::{decode_key, Config, EndpointHost, InterfaceConfig, ProtocolVersion};
use crate::linux::{self, LinuxError};
use crate::routing::RoutingPlan;
use boringtun::device::{AllowedIP, DeviceConfig, DeviceHandle};
use boringtun::noise::amnezia::AmneziaConfig;
use boringtun::noise::handshake::ObfuscationRanges;
use boringtun::x25519;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Linux(#[from] LinuxError),
    #[error("BoringTun device error: {0}")]
    Device(#[from] boringtun::device::Error),
    #[error("invalid runtime configuration: {0}")]
    Configuration(String),
    #[error("failed to resolve endpoint {endpoint}: {reason}")]
    Endpoint { endpoint: String, reason: String },
    #[error("failed to enable IP forwarding: {0}")]
    Forwarding(String),
}

pub struct Runtime {
    devices: Vec<DeviceHandle>,
    routing: RoutingPlan,
    stats_interval: Duration,
}

impl Runtime {
    /// Start all interfaces and install routing after the complete config has
    /// been parsed and validated. UAPI is disabled on every daemon device.
    pub fn start(config: Config) -> Result<Self, RuntimeError> {
        config.validate().map_err(|e| RuntimeError::Configuration(e.to_string()))?;
        let routing = RoutingPlan::from_config(&config);
        let mut devices = Vec::with_capacity(config.interfaces.len());

        for interface in &config.interfaces {
            let mut handle = create_device(interface)?;
            linux::configure_interface(&interface.name, interface.mtu, &interface.addresses)?;
            handle.set_private_key(x25519::StaticSecret::from(decode_key(
                &interface.private_key, "private_key"
            ).map_err(|e| RuntimeError::Configuration(e.to_string()))?));
            handle.set_fwmark(interface.socket_fwmark)?;

            for peer in &interface.peers {
                let public_key = x25519::PublicKey::from(decode_key(
                    &peer.public_key, "peer.public_key"
                ).map_err(|e| RuntimeError::Configuration(e.to_string()))?);
                let preshared_key = peer.preshared_key.as_ref().map(|value| {
                    decode_key(value, "peer.preshared_key")
                        .map_err(|e| RuntimeError::Configuration(e.to_string()))
                }).transpose()?;
                let endpoint = peer.endpoint.as_deref().map(resolve_endpoint).transpose()?;
                let allowed_ips: Result<Vec<AllowedIP>, _> = peer.allowed_ips.iter()
                    .map(|prefix| AllowedIP::from_str(prefix).map_err(|e| {
                        RuntimeError::Configuration(format!("invalid AllowedIP {prefix}: {e}"))
                    })).collect();
                let keepalive = peer.persistent_keepalive_secs.map(|seconds| {
                    (u32::from(seconds), u32::from(seconds))
                });
                handle.update_peer(
                    public_key, false, true, endpoint, &allowed_ips?, keepalive, preshared_key
                )?;
            }
            devices.push(handle);
        }

        if config.daemon.manage_ip_forwarding {
            enable_forwarding()?;
        }
        linux::apply_nft(&routing)?;
        if let Err(error) = linux::apply_policy_routing(&routing) {
            linux::remove_nft(&routing);
            return Err(error.into());
        }
        tracing::info!(interfaces = devices.len(), "btrouted runtime started");
        Ok(Self { devices, routing, stats_interval: Duration::from_secs(config.daemon.stats_interval_secs) })
    }

    pub fn routing_plan(&self) -> &RoutingPlan { &self.routing }

    /// Return consistent live counters without querying UAPI.
    pub fn snapshots(&self) -> Result<Vec<boringtun::device::DeviceSnapshot>, RuntimeError> {
        self.devices.iter().map(|device| device.snapshot().map_err(RuntimeError::from)).collect()
    }

    /// Keep the daemon alive and periodically publish peer counters.
    pub fn run(self) -> ! {
        loop {
            std::thread::sleep(self.stats_interval);
            match self.snapshots() {
                Ok(snapshots) => {
                    for device in snapshots {
                        for peer in device.peers {
                            tracing::info!(
                                interface = %device.name,
                                peer = %hex_key(&peer.public_key),
                                tx_bytes = peer.tx_bytes,
                                rx_bytes = peer.rx_bytes,
                                handshake_age_secs = ?peer.time_since_last_handshake.map(|age| age.as_secs()),
                                "peer statistics"
                            );
                        }
                    }
                }
                Err(error) => tracing::error!(%error, "failed to collect device statistics"),
            }
        }
    }
}

fn hex_key(key: &[u8; 32]) -> String {
    key.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn create_device(interface: &InterfaceConfig) -> Result<DeviceHandle, RuntimeError> {
    let (obf, amnezia) = build_awg_config(interface)?;
    let config = DeviceConfig {
        n_threads: 4,
        use_connected_socket: true,
        use_multi_queue: true,
        uapi_fd: -1,
        enable_uapi: false,
        listen_port: Some(interface.listen_port),
        obf,
        amnezia,
        probe_reply_bytes_per_sec: None,
    };
    Ok(DeviceHandle::new(&interface.name, config)?)
}

fn build_awg_config(interface: &InterfaceConfig) -> Result<(ObfuscationRanges, AmneziaConfig), RuntimeError> {
    if interface.protocol == ProtocolVersion::Wg {
        return Ok((ObfuscationRanges::default(), AmneziaConfig::default()));
    }
    let awg = interface.awg.as_ref();
    let defaults = ["1", "2", "3", "4"];
    let values: Vec<(u32, u32)> = (0..4).map(|index| {
        let value = awg.and_then(|a| match index {
            0 => a.h1.as_ref(), 1 => a.h2.as_ref(), 2 => a.h3.as_ref(), _ => a.h4.as_ref()
        }).map(String::as_str).unwrap_or(defaults[index]);
        parse_tag_range(value).ok_or_else(|| RuntimeError::Configuration(
            format!("interfaces.{}.awg.h{} has invalid tag range", interface.name, index + 1)
        ))
    }).collect::<Result<_, _>>()?;
    let obf = ObfuscationRanges::from_explicit_ranges([values[0], values[1], values[2], values[3]])
        .map_err(|e| RuntimeError::Configuration(format!("invalid AWG header ranges: {e}")))?;
    let s = |pick: fn(&crate::config::AwgConfig) -> Option<u16>| -> u16 {
        awg.and_then(pick).unwrap_or(0)
    };
    let mut amnezia = AmneziaConfig::new(
        s(|a| a.s1), s(|a| a.s2), s(|a| a.s3), s(|a| a.s4)
    );
    let jc = s(|a| a.jc);
    let jmin = s(|a| a.jmin);
    let jmax = s(|a| a.jmax);
    amnezia = amnezia.try_with_pre_handshake_junk(jc, jmin, jmax, 0)
        .map_err(|e| RuntimeError::Configuration(format!("invalid AWG junk settings: {e}")))?;
    if let Some(awg) = awg {
        amnezia = amnezia
            .with_disable_cookies(awg.disable_cookies.unwrap_or(false))
            .with_random_trailers(awg.random_trailers.unwrap_or(false));
    }
    Ok((obf, amnezia))
}

fn parse_tag_range(value: &str) -> Option<(u32, u32)> {
    let (start, end) = match value.split_once('-') {
        Some((start, end)) => (start.trim().parse().ok()?, end.trim().parse().ok()?),
        None => { let value = value.parse().ok()?; (value, value) }
    };
    (start <= end).then_some((start, end))
}

fn resolve_endpoint(value: &str) -> Result<SocketAddr, RuntimeError> {
    let parsed = crate::config::PeerEndpoint::parse(value)
        .map_err(|reason| RuntimeError::Endpoint { endpoint: value.into(), reason })?;
    match parsed.host {
        EndpointHost::Ip(ip) => Ok(SocketAddr::new(ip, parsed.port)),
        EndpointHost::Dns(host) => (host.as_str(), parsed.port).to_socket_addrs()
            .map_err(|e| RuntimeError::Endpoint { endpoint: value.into(), reason: e.to_string() })?
            .next()
            .ok_or_else(|| RuntimeError::Endpoint { endpoint: value.into(), reason: "DNS returned no addresses".into() }),
    }
}

fn enable_forwarding() -> Result<(), RuntimeError> {
    for key in ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"] {
        let output = std::process::Command::new("sysctl").args(["-w", &format!("{key}=1")])
            .output().map_err(|e| RuntimeError::Forwarding(e.to_string()))?;
        if !output.status.success() {
            return Err(RuntimeError::Forwarding(
                String::from_utf8_lossy(&output.stderr).trim().to_owned()
            ));
        }
    }
    Ok(())
}
