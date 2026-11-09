//! Static tunnel backend registry and backend-neutral runtime interfaces.

mod boringtun;

use crate::config::{Config, InterfaceConfig, TunnelType};
use std::net::SocketAddr;
use std::time::Duration;

/// Error returned by a tunnel backend.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BackendError(String);

impl BackendError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Backend-neutral live counters for a tunnel interface.
#[derive(Clone, Debug)]
pub struct TunnelSnapshot {
    pub name: String,
    pub peers: Vec<TunnelPeerSnapshot>,
}

/// Backend-neutral peer counters.
#[derive(Clone, Debug)]
pub struct TunnelPeerSnapshot {
    pub public_key: [u8; 32],
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub time_since_last_handshake: Option<Duration>,
}

/// Backend data resolved and validated before host networking changes.
#[derive(Clone, Debug)]
pub(crate) struct PreparedInterface {
    pub(crate) peer_endpoints: Vec<Option<SocketAddr>>,
}

/// A running tunnel instance managed by vpn-relay.
pub trait TunnelHandle: Send {
    fn snapshot(&self) -> Result<TunnelSnapshot, BackendError>;
    fn shutdown(&self);
    fn wait(&mut self);
}

/// Creates running tunnel instances for a specific tunnel family.
pub trait TunnelBackend: Send + Sync {
    fn prepare(&self, name: &str, interface: &InterfaceConfig) -> Result<PreparedInterface, BackendError>;

    fn create(
        &self,
        name: &str,
        interface: &InterfaceConfig,
        socket_fwmark: u32,
        prepared: &PreparedInterface,
    ) -> Result<Box<dyn TunnelHandle>, BackendError>;
}

/// Static backend registry. WG and AWG currently share BoringTun; future
/// protocol families can register independent implementations here.
#[derive(Default)]
pub struct BackendRegistry {
    boringtun: boringtun::BoringTunBackend,
}

impl BackendRegistry {
    pub(crate) fn prepare_config(
        &self,
        config: &Config,
    ) -> Result<std::collections::BTreeMap<String, PreparedInterface>, BackendError> {
        config.interfaces.iter().map(|(name, interface)| {
            let prepared = match interface.tunnel_type {
                TunnelType::WireGuard | TunnelType::AmneziaWg => self.boringtun.prepare(name, interface)?,
            };
            Ok((name.clone(), prepared))
        }).collect()
    }

    pub fn validate_config(&self, config: &Config) -> Result<(), BackendError> {
        self.prepare_config(config).map(|_| ())
    }

    pub fn create(
        &self,
        tunnel_type: TunnelType,
        name: &str,
        interface: &InterfaceConfig,
        socket_fwmark: u32,
        prepared: &PreparedInterface,
    ) -> Result<Box<dyn TunnelHandle>, BackendError> {
        match tunnel_type {
            TunnelType::WireGuard | TunnelType::AmneziaWg => {
                self.boringtun.create(name, interface, socket_fwmark, prepared)
            }
        }
    }
}
