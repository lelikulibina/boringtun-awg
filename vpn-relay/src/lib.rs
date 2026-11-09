//! Configuration and control-plane building blocks for the BoringTun router daemon.
//!
//! Tunnel devices created by the daemon are configured only through
//! BoringTun's typed control API. UAPI is deliberately disabled for daemon
//! devices and is not part of this crate's management path.

#[cfg(target_os = "linux")]
pub mod backend;
pub mod config;
pub mod import;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod routing;
#[cfg(target_os = "linux")]
pub mod runtime;

pub use config::{
    Config, ConfigError, EndpointHost, NatMode, PeerConfig, PeerEndpoint, TunnelType,
};
pub use routing::{EgressPlan, RoutingDecision, RoutingPlan};
#[cfg(target_os = "linux")]
pub use runtime::{Runtime, RuntimeError};
