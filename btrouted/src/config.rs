use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use boringtun::device::AllowedIP;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("configuration validation failed: {0}")]
    Validation(String),
}

/// Complete daemon configuration. Unknown keys are rejected so a typo cannot
/// silently disable a security or routing setting.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub daemon: DaemonConfig,
    pub interfaces: Vec<InterfaceConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_stats_interval")]
    pub stats_interval_secs: u64,
    #[serde(default = "default_nft_table")]
    pub nft_table: String,
    #[serde(default)]
    pub manage_ip_forwarding: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            stats_interval_secs: default_stats_interval(),
            nft_table: default_nft_table(),
            manage_ip_forwarding: false,
        }
    }
}

fn default_log_level() -> String {
    "info".to_owned()
}

fn default_stats_interval() -> u64 {
    10
}

fn default_nft_table() -> String {
    "btrouted".to_owned()
}

fn default_mtu() -> u16 {
    1380
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolVersion {
    Wg,
    Awg1,
    #[serde(rename = "awg1_5")]
    Awg1_5,
    Awg2,
    Awg3,
    #[serde(rename = "awg3_1")]
    Awg3_1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceRole {
    Server,
    Client,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceConfig {
    pub name: String,
    pub protocol: ProtocolVersion,
    pub role: InterfaceRole,
    pub addresses: Vec<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    pub listen_port: u16,
    pub private_key: String,
    pub socket_fwmark: u32,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub awg: Option<AwgConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub name: String,
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub persistent_keepalive_secs: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwgConfig {
    #[serde(default)]
    pub jc: Option<u16>,
    #[serde(default)]
    pub jmin: Option<u16>,
    #[serde(default)]
    pub jmax: Option<u16>,
    #[serde(default)]
    pub s1: Option<u16>,
    #[serde(default)]
    pub s2: Option<u16>,
    #[serde(default)]
    pub s3: Option<u16>,
    #[serde(default)]
    pub s4: Option<u16>,
    #[serde(default)]
    pub h1: Option<String>,
    #[serde(default)]
    pub h2: Option<String>,
    #[serde(default)]
    pub h3: Option<String>,
    #[serde(default)]
    pub h4: Option<String>,
    #[serde(default)]
    pub disable_cookies: Option<bool>,
    #[serde(default)]
    pub random_trailers: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    pub priority: u32,
    pub ingress: String,
    pub destination: String,
    pub egress: String,
}

impl Config {
    /// Parse TOML and validate the complete configuration before any system
    /// resource (TUN, UDP socket, nftables rule, or route) is created.
    pub fn parse_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let input = fs::read_to_string(path)?;
        Self::parse_toml(&input)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.interfaces.is_empty() {
            return invalid("at least one interface must be configured");
        }
        if self.daemon.stats_interval_secs == 0 {
            return invalid("[daemon].stats_interval_secs must be greater than zero");
        }
        if !valid_nft_table_name(&self.daemon.nft_table) {
            return invalid(
                "[daemon].nft_table must contain only ASCII letters, digits, or underscores",
            );
        }
        if !matches!(
            self.daemon.log_level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error"
        ) {
            return invalid("[daemon].log_level must be trace, debug, info, warn, or error");
        }

        let mut interface_names = HashSet::new();
        let mut listen_ports = HashSet::new();
        let mut fwmarks = HashSet::new();

        for interface in &self.interfaces {
            validate_interface_name(&interface.name)?;
            if !interface_names.insert(interface.name.as_str()) {
                return invalid(format!("duplicate interface name '{}'", interface.name));
            }
            if interface.listen_port == 0 {
                return invalid(format!(
                    "interfaces.{}.listen_port must be in 1..=65535",
                    interface.name
                ));
            }
            if !listen_ports.insert(interface.listen_port) {
                return invalid(format!(
                    "UDP listen port {} is used by more than one interface",
                    interface.listen_port
                ));
            }
            if interface.socket_fwmark == 0 {
                return invalid(format!(
                    "interfaces.{}.socket_fwmark must be non-zero",
                    interface.name
                ));
            }
            if !fwmarks.insert(interface.socket_fwmark) {
                return invalid(format!(
                    "socket fwmark 0x{:x} is used by more than one interface",
                    interface.socket_fwmark
                ));
            }
            if !(576..=65535).contains(&interface.mtu) {
                return invalid(format!(
                    "interfaces.{}.mtu must be in 576..=65535",
                    interface.name
                ));
            }
            decode_key(
                &interface.private_key,
                &format!("interfaces.{}.private_key", interface.name),
            )?;

            let mut has_ipv6 = false;
            for address in &interface.addresses {
                let parsed =
                    parse_prefix(address, &format!("interfaces.{}.addresses", interface.name))?;
                has_ipv6 |= parsed.addr.is_ipv6();
            }
            if has_ipv6 && interface.mtu < 1280 {
                return invalid(format!(
                    "interfaces.{}.mtu must be at least 1280 when IPv6 addresses are configured",
                    interface.name
                ));
            }

            if interface.protocol == ProtocolVersion::Wg && interface.awg.is_some() {
                return invalid(format!(
                    "interfaces.{}.awg is not valid for protocol 'wg'",
                    interface.name
                ));
            }
            if let Some(awg) = &interface.awg {
                awg.validate(&interface.name)?;
            }

            let mut peer_names = HashSet::new();
            let mut peer_keys = HashSet::new();
            let mut owned_prefixes = HashSet::new();
            for peer in &interface.peers {
                validate_peer_name(&peer.name, &interface.name)?;
                if !peer_names.insert(peer.name.as_str()) {
                    return invalid(format!(
                        "interfaces.{}.peers contains duplicate peer name '{}'",
                        interface.name, peer.name
                    ));
                }
                let public_key = decode_key(
                    &peer.public_key,
                    &format!(
                        "interfaces.{}.peers.{}.public_key",
                        interface.name, peer.name
                    ),
                )?;
                if !peer_keys.insert(public_key) {
                    return invalid(format!(
                        "interfaces.{} contains duplicate peer public keys",
                        interface.name
                    ));
                }
                if let Some(psk) = &peer.preshared_key {
                    decode_key(
                        psk,
                        &format!(
                            "interfaces.{}.peers.{}.preshared_key",
                            interface.name, peer.name
                        ),
                    )?;
                }
                if let Some(endpoint) = &peer.endpoint {
                    SocketAddr::from_str(endpoint).map_err(|error| {
                        ConfigError::Validation(format!(
                            "interfaces.{}.peers.{}.endpoint is invalid: {}",
                            interface.name, peer.name, error
                        ))
                    })?;
                }
                for prefix in &peer.allowed_ips {
                    let parsed = parse_prefix(
                        prefix,
                        &format!(
                            "interfaces.{}.peers.{}.allowed_ips",
                            interface.name, peer.name
                        ),
                    )?;
                    has_ipv6 |= parsed.addr.is_ipv6();
                    if !owned_prefixes.insert((parsed.addr, parsed.cidr)) {
                        return invalid(format!(
                            "interfaces.{} assigns AllowedIP {} to more than one peer",
                            interface.name, prefix
                        ));
                    }
                }
            }
            if has_ipv6 && interface.mtu < 1280 {
                return invalid(format!(
                    "interfaces.{}.mtu must be at least 1280 when IPv6 AllowedIPs are configured",
                    interface.name
                ));
            }
        }

        let interfaces_by_name: std::collections::HashMap<_, _> = self
            .interfaces
            .iter()
            .map(|interface| (interface.name.as_str(), interface))
            .collect();
        let mut route_priorities = HashSet::new();
        for rule in &self.routing.rules {
            if !route_priorities.insert((rule.ingress.as_str(), rule.priority)) {
                return invalid(format!(
                    "routing contains duplicate priority {} for ingress '{}'",
                    rule.priority, rule.ingress
                ));
            }
            let ingress = interfaces_by_name
                .get(rule.ingress.as_str())
                .ok_or_else(|| {
                    ConfigError::Validation(format!(
                        "routing rule references unknown ingress '{}'",
                        rule.ingress
                    ))
                })?;
            let egress = interfaces_by_name
                .get(rule.egress.as_str())
                .ok_or_else(|| {
                    ConfigError::Validation(format!(
                        "routing rule references unknown egress '{}'",
                        rule.egress
                    ))
                })?;
            if rule.ingress == rule.egress {
                return invalid(format!(
                    "routing rule cannot use '{}' as both ingress and egress",
                    rule.ingress
                ));
            }
            if ingress.role != InterfaceRole::Server {
                return invalid(format!(
                    "routing ingress '{}' must have role = 'server'",
                    rule.ingress
                ));
            }
            if egress.role != InterfaceRole::Client {
                return invalid(format!(
                    "routing egress '{}' must have role = 'client'",
                    rule.egress
                ));
            }
            parse_prefix(&rule.destination, "routing.rules.destination")?;
        }

        Ok(())
    }
}

impl AwgConfig {
    fn validate(&self, interface: &str) -> Result<(), ConfigError> {
        match (self.jmin, self.jmax) {
            (Some(min), Some(max)) if min <= max => {}
            (Some(_), Some(_)) => {
                return invalid(format!(
                    "interfaces.{}.awg.jmin must not exceed jmax",
                    interface
                ));
            }
            (Some(_), None) | (None, Some(_)) => {
                return invalid(format!(
                    "interfaces.{}.awg.jmin and jmax must be configured together",
                    interface
                ));
            }
            (None, None) => {}
        }

        let mut header_ranges = Vec::new();
        for (name, value) in [
            ("h1", &self.h1),
            ("h2", &self.h2),
            ("h3", &self.h3),
            ("h4", &self.h4),
        ] {
            if let Some(value) = value {
                let range = parse_u32_range(value).ok_or_else(|| {
                    ConfigError::Validation(format!(
                        "interfaces.{}.awg.{} must be a uint32 tag or an inclusive start-end range",
                        interface, name
                    ))
                })?;
                header_ranges.push((name, range));
            }
        }
        for (index, (left_name, (left_start, left_end))) in header_ranges.iter().enumerate() {
            for (right_name, (right_start, right_end)) in header_ranges.iter().skip(index + 1) {
                if left_start <= right_end && right_start <= left_end {
                    return invalid(format!(
                        "interfaces.{}.awg.{} and {} ranges overlap",
                        interface, left_name, right_name
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Decode a WireGuard key from standard Base64 and require exactly 32 bytes.
pub fn decode_key(value: &str, field: &str) -> Result<[u8; 32], ConfigError> {
    let decoded = STANDARD.decode(value).map_err(|error| {
        ConfigError::Validation(format!("{} is not valid standard Base64: {}", field, error))
    })?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        ConfigError::Validation(format!(
            "{} must decode to exactly 32 bytes (got {})",
            field,
            bytes.len()
        ))
    })
}

fn parse_prefix(value: &str, field: &str) -> Result<AllowedIP, ConfigError> {
    AllowedIP::from_str(value).map_err(|error| {
        ConfigError::Validation(format!(
            "{} contains invalid CIDR '{}': {}",
            field, value, error
        ))
    })
}

fn parse_u32_range(value: &str) -> Option<(u32, u32)> {
    let (start, end) = match value.split_once('-') {
        Some((start, end)) => (start.trim().parse().ok()?, end.trim().parse().ok()?),
        None => {
            let value = value.trim().parse().ok()?;
            (value, value)
        }
    };
    (start <= end).then_some((start, end))
}

fn validate_interface_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return invalid(format!(
            "interface name '{}' must be 1..=15 ASCII letters, digits, '.', '_' or '-'",
            name
        ));
    }
    Ok(())
}

fn validate_peer_name(name: &str, interface: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return invalid(format!(
            "interfaces.{}.peers contains invalid peer name '{}'",
            interface, name
        ));
    }
    Ok(())
}

fn valid_nft_table_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Validation(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn valid_config() -> String {
        format!(
            r#"
[daemon]
log_level = "info"
stats_interval_secs = 10
nft_table = "btrouted"
manage_ip_forwarding = false

[[interfaces]]
name = "wg-server"
protocol = "wg"
role = "server"
addresses = ["10.10.0.1/24"]
mtu = 1380
listen_port = 51820
private_key = "{KEY}"
socket_fwmark = 4097

[[interfaces.peers]]
name = "client-1"
public_key = "{KEY}"
allowed_ips = ["10.10.0.2/32"]

[[interfaces]]
name = "awg-uplink"
protocol = "awg3_1"
role = "client"
addresses = ["10.20.0.2/32"]
mtu = 1380
listen_port = 51821
private_key = "{KEY}"
socket_fwmark = 4098

[[interfaces.peers]]
name = "server"
public_key = "{KEY}"
endpoint = "198.51.100.10:51820"
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive_secs = 25

[interfaces.awg]
jc = 5
jmin = 50
jmax = 1000
s1 = 0
s2 = 0
s3 = 0
s4 = 0
h1 = "1-100"
h2 = "101-200"
h3 = "201-300"
h4 = "301-400"

[[routing.rules]]
priority = 100
ingress = "wg-server"
destination = "0.0.0.0/0"
egress = "awg-uplink"

[[routing.rules]]
priority = 110
ingress = "wg-server"
destination = "::/0"
egress = "awg-uplink"
"#
        )
    }

    #[test]
    fn parses_and_validates_a_complete_multi_tunnel_config() {
        let config = Config::parse_toml(&valid_config()).unwrap();
        assert_eq!(config.interfaces.len(), 2);
        assert_eq!(config.routing.rules.len(), 2);
        assert_eq!(config.interfaces[1].protocol, ProtocolVersion::Awg3_1);
    }

    #[test]
    fn rejects_invalid_key_lengths() {
        let input = valid_config().replace(KEY, "AQID");
        let error = Config::parse_toml(&input).unwrap_err();
        assert!(error.to_string().contains("exactly 32 bytes"));
    }

    #[test]
    fn rejects_duplicate_socket_fwmarks() {
        let input = valid_config().replace("socket_fwmark = 4098", "socket_fwmark = 4097");
        let error = Config::parse_toml(&input).unwrap_err();
        assert!(error.to_string().contains("socket fwmark"));
    }

    #[test]
    fn rejects_overlapping_awg_header_ranges() {
        let input = valid_config().replace("h2 = \"101-200\"", "h2 = \"50-200\"");
        let error = Config::parse_toml(&input).unwrap_err();
        assert!(error.to_string().contains("ranges overlap"));
    }

    #[test]
    fn rejects_unknown_fields_instead_of_ignoring_typos() {
        let input = valid_config().replace("mtu = 1380", "mtu = 1380\nmtuu = 1400");
        let error = Config::parse_toml(&input).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }
}
