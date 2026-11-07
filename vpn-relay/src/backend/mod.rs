//! Static tunnel backend registry and backend-neutral runtime interfaces.

mod boringtun;

use crate::config::{Config, InterfaceConfig, TunnelType};
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

/// A running tunnel instance managed by vpn-relay.
pub trait TunnelHandle: Send {
    fn snapshot(&self) -> Result<TunnelSnapshot, BackendError>;
    fn shutdown(&self);
    fn wait(&mut self);
}

/// Creates running tunnel instances for a specific tunnel family.
pub trait TunnelBackend: Send + Sync {
    fn validate(&self, name: &str, interface: &InterfaceConfig) -> Result<(), BackendError>;

    fn create(
        &self,
        name: &str,
        interface: &InterfaceConfig,
        socket_fwmark: u32,
    ) -> Result<Box<dyn TunnelHandle>, BackendError>;
}

/// Static backend registry. WG and AWG currently share BoringTun; future
/// protocol families can register independent implementations here.
#[derive(Default)]
pub struct BackendRegistry {
    boringtun: boringtun::BoringTunBackend,
}

impl BackendRegistry {
    pub fn validate_config(&self, config: &Config) -> Result<(), BackendError> {
        for (name, interface) in &config.interfaces {
            match interface.tunnel_type {
                TunnelType::WireGuard | TunnelType::AmneziaWg => {
                    self.boringtun.validate(name, interface)?;
                }
            }
        }
        Ok(())
    }

    pub fn create(
        &self,
        tunnel_type: TunnelType,
        name: &str,
        interface: &InterfaceConfig,
        socket_fwmark: u32,
    ) -> Result<Box<dyn TunnelHandle>, BackendError> {
        match tunnel_type {
            TunnelType::WireGuard | TunnelType::AmneziaWg => {
                self.boringtun.create(name, interface, socket_fwmark)
            }
        }
    }
}
