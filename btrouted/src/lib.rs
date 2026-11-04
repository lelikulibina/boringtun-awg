//! Configuration and control-plane building blocks for the BoringTun router daemon.
//!
//! Tunnel devices created by the future daemon are configured only through
//! BoringTun's typed control API. UAPI is deliberately disabled for daemon
//! devices and is not part of this crate's management path.

pub mod config;

pub use config::{Config, ConfigError, EndpointHost, PeerEndpoint};
