use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use boringtun::device::AllowedIP;
use boringtun::noise::amnezia::AmneziaConfig;
use boringtun::noise::handshake::ObfuscationRanges;
use serde::{Deserialize, Deserializer};
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
    #[serde(alias = "awg3_0")]
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

/// Source NAT is a property of a selected routing rule, not of an interface.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NatMode {
    #[default]
    None,
    Masquerade,
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
    /// Permit IPv6 packets entering or leaving this tunnel. Disabled by default.
    #[serde(default)]
    pub ipv6_enabled: bool,
    pub listen_port: u16,
    pub private_key: String,
    /// Optional mark for encrypted UDP sockets; assigned automatically when omitted.
    #[serde(default)]
    pub socket_fwmark: Option<u32>,
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
    #[serde(default)]
    pub i1: Option<String>,
    #[serde(default)]
    pub i2: Option<String>,
    #[serde(default)]
    pub i3: Option<String>,
    #[serde(default)]
    pub i4: Option<String>,
    #[serde(default)]
    pub i5: Option<String>,
    /// 64 hexadecimal characters (32-byte AWG 3.1 header-protection key).
    #[serde(default)]
    pub header_protection_key: Option<String>,
    /// Inclusive uint32 range, e.g. "10-100".
    #[serde(default)]
    pub content_padding_addition: Option<String>,
    /// mtu/awg30 or udp_window/awg31.
    #[serde(default)]
    pub content_padding_mode: Option<String>,
    #[serde(default)]
    pub rekey_after_time: Option<String>,
    #[serde(default)]
    pub rekey_timeout: Option<String>,
    #[serde(default)]
    pub reject_after_time: Option<String>,
    #[serde(default)]
    pub keepalive_timeout: Option<String>,
    #[serde(default)]
    pub max_handshake_attempts: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    /// Base mark range reserved for inner packets classified by nftables.
    /// This is intentionally separate from each interface socket_fwmark,
    /// which marks the outer encrypted UDP packets.
    #[serde(default = "default_routing_mark_base")]
    pub mark_base: u32,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            mark_base: default_routing_mark_base(),
            rules: Vec::new(),
        }
    }
}

fn default_routing_mark_base() -> u32 {
    0x8000_0000
}

/// First mark considered for automatically assigned encrypted-socket marks.
const DEFAULT_SOCKET_FWMARK_BASE: u32 = 0x1000;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    pub priority: u32,
    pub ingress: String,
    #[serde(default, deserialize_with = "deserialize_optional_cidrs")]
    pub source: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_cidrs")]
    pub destination: Option<Vec<String>>,
    pub egress: String,
    #[serde(default)]
    pub nat: NatMode,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrManyStrings {
    One(String),
    Many(Vec<String>),
}

/// Accept both a single CIDR (backward compatibility) and a list of CIDRs.
fn deserialize_optional_cidrs<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<OneOrManyStrings>::deserialize(deserializer).map(|value| {
        value.map(|value| match value {
            OneOrManyStrings::One(prefix) => vec![prefix],
            OneOrManyStrings::Many(prefixes) => prefixes,
        })
    })
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

    /// Resolve the contiguous packet-mark range assigned to client interfaces.
    /// The order matches RoutingPlan's lexicographically sorted egress list.
    pub fn resolved_routing_fwmarks(&self) -> Result<Vec<u32>, ConfigError> {
        let egress_count = self
            .interfaces
            .iter()
            .filter(|interface| interface.role == InterfaceRole::Client)
            .count();
        (0..egress_count)
            .map(|index| {
                self.routing
                    .mark_base
                    .checked_add(index as u32)
                    .filter(|mark| *mark != 0)
                    .ok_or_else(|| {
                        ConfigError::Validation(
                            "[routing].mark_base leaves no room for all client routing marks"
                                .to_owned(),
                        )
                    })
            })
            .collect()
    }

    /// Resolve explicit and automatically assigned socket marks in interface order.
    /// The socket and packet mark spaces are disjoint by exact 32-bit value.
    /// Explicit marks are reserved first so automatic allocation never displaces them.
    pub fn resolved_socket_fwmarks(&self) -> Result<Vec<u32>, ConfigError> {
        let routing_marks: HashSet<_> = self.resolved_routing_fwmarks()?.into_iter().collect();

        let mut used = HashSet::new();
        for interface in &self.interfaces {
            if let Some(mark) = interface.socket_fwmark {
                if mark == 0 {
                    return invalid(format!(
                        "interfaces.{}.socket_fwmark must be non-zero",
                        interface.name
                    ));
                }
                if !used.insert(mark) {
                    return invalid(format!(
                        "socket fwmark 0x{mark:x} is used by more than one interface"
                    ));
                }
                if routing_marks.contains(&mark) {
                    return invalid(
                        "[routing].mark_base range overlaps an interface socket_fwmark; outer UDP and inner packet marks must be distinct",
                    );
                }
            }
        }

        let mut next_candidate = DEFAULT_SOCKET_FWMARK_BASE;
        let mut resolved = Vec::with_capacity(self.interfaces.len());
        for interface in &self.interfaces {
            let mark = if let Some(mark) = interface.socket_fwmark {
                mark
            } else {
                loop {
                    if next_candidate == 0 {
                        return invalid("no available non-zero socket fwmark remains");
                    }
                    let candidate = next_candidate;
                    next_candidate = next_candidate.checked_add(1).unwrap_or(0);
                    if !routing_marks.contains(&candidate) && used.insert(candidate) {
                        break candidate;
                    }
                }
            };
            resolved.push(mark);
        }
        Ok(resolved)
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
                awg.validate(&interface.name, interface.protocol)?;
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
                    PeerEndpoint::parse(endpoint).map_err(|error| {
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

        if self.routing.mark_base == 0 {
            return invalid("[routing].mark_base must be non-zero");
        }
        self.resolved_socket_fwmarks()?;

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
            let source_prefixes = rule
                .source
                .as_ref()
                .map(|prefixes| {
                    if prefixes.is_empty() {
                        return invalid("routing.rules.source must not be an empty list");
                    }
                    prefixes
                        .iter()
                        .map(|prefix| parse_prefix(prefix, "routing.rules.source"))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?;
            let destination_prefixes = rule
                .destination
                .as_ref()
                .map(|prefixes| {
                    if prefixes.is_empty() {
                        return invalid("routing.rules.destination must not be an empty list");
                    }
                    prefixes
                        .iter()
                        .map(|prefix| parse_prefix(prefix, "routing.rules.destination"))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?;

            if let (Some(sources), Some(destinations)) = (&source_prefixes, &destination_prefixes) {
                let has_common_family = sources.iter().any(|source| {
                    destinations
                        .iter()
                        .any(|destination| source.addr.is_ipv4() == destination.addr.is_ipv4())
                });
                if !has_common_family {
                    return invalid(
                        "routing.rules.source and destination must share at least one address family",
                    );
                }
            }
        }

        Ok(())
    }
}

impl AwgConfig {
    pub fn build(
        &self,
        interface: &str,
        protocol: ProtocolVersion,
    ) -> Result<(ObfuscationRanges, AmneziaConfig), ConfigError> {
        let values = [
            self.h1.as_deref().unwrap_or("1"),
            self.h2.as_deref().unwrap_or("2"),
            self.h3.as_deref().unwrap_or("3"),
            self.h4.as_deref().unwrap_or("4"),
        ];
        let mut headers = [(0, 0); 4];
        for (i, value) in values.iter().enumerate() {
            headers[i] = parse_u32_range(value).ok_or_else(|| {
                ConfigError::Validation(format!(
                    "interfaces.{}.awg.h{} must be a uint32 tag or inclusive range",
                    interface,
                    i + 1
                ))
            })?;
        }
        let obf = ObfuscationRanges::from_explicit_ranges(headers).map_err(|e| {
            ConfigError::Validation(format!(
                "interfaces.{}.awg has invalid H1-H4 ranges: {}",
                interface, e
            ))
        })?;
        match (self.jmin, self.jmax) {
            (Some(a), Some(b)) if a <= b => {}
            (Some(_), Some(_)) => {
                return invalid(format!(
                    "interfaces.{}.awg.jmin must not exceed jmax",
                    interface
                ))
            }
            (Some(_), None) | (None, Some(_)) => {
                return invalid(format!(
                    "interfaces.{}.awg.jmin and jmax must be configured together",
                    interface
                ))
            }
            _ => {}
        }
        let mut cfg = AmneziaConfig::new(
            self.s1.unwrap_or(0),
            self.s2.unwrap_or(0),
            self.s3.unwrap_or(0),
            self.s4.unwrap_or(0),
        )
        .try_with_pre_handshake_junk(
            self.jc.unwrap_or(0),
            self.jmin.unwrap_or(0),
            self.jmax.unwrap_or(0),
            0,
        )
        .map_err(|e| {
            ConfigError::Validation(format!("interfaces.{}.awg junk settings: {}", interface, e))
        })?
        .with_disable_cookies(self.disable_cookies.unwrap_or(false))
        .with_random_trailers(self.random_trailers.unwrap_or(false));
        if let Some(value) = &self.header_protection_key {
            let key = decode_hex_key(value).ok_or_else(|| {
                ConfigError::Validation(format!(
                    "interfaces.{}.awg.header_protection_key must be 64 hexadecimal characters",
                    interface
                ))
            })?;
            cfg = cfg.with_header_protection_key(key);
        }
        if let Some(value) = &self.content_padding_addition {
            let (min, max) = parse_u32_range(value).ok_or_else(|| {
                ConfigError::Validation(format!(
                    "interfaces.{}.awg.content_padding_addition must be uint32 or min-max",
                    interface
                ))
            })?;
            cfg = cfg.with_content_padding_addition_range(min, max);
        }
        let legacy = match self.content_padding_mode.as_deref() {
            Some("mtu" | "awg30") => true,
            Some("udp_window" | "awg31") => false,
            Some(other) => {
                return invalid(format!(
                    "interfaces.{}.awg.content_padding_mode '{}' is invalid",
                    interface, other
                ))
            }
            None => protocol == ProtocolVersion::Awg3,
        };
        cfg = cfg.with_legacy_content_padding(legacy);
        for (name, value, slot) in [
            ("rekey_after_time", self.rekey_after_time.as_deref(), 0u8),
            ("rekey_timeout", self.rekey_timeout.as_deref(), 1u8),
            ("reject_after_time", self.reject_after_time.as_deref(), 2u8),
            ("keepalive_timeout", self.keepalive_timeout.as_deref(), 3u8),
            (
                "max_handshake_attempts",
                self.max_handshake_attempts.as_deref(),
                4u8,
            ),
        ] {
            if let Some(value) = value {
                let (min, max) = parse_u32_range(value).ok_or_else(|| {
                    ConfigError::Validation(format!(
                        "interfaces.{}.awg.{} must be uint32 or min-max",
                        interface, name
                    ))
                })?;
                cfg = match slot {
                    0 => cfg.with_rekey_after_time(min, max),
                    1 => cfg.with_rekey_timeout(min, max),
                    2 => cfg.with_reject_after_time(min, max),
                    3 => cfg.with_keepalive_timeout(min, max),
                    _ => cfg.with_max_handshake_attempts(min, max),
                };
            }
        }
        for (index, value) in [
            self.i1.as_deref(),
            self.i2.as_deref(),
            self.i3.as_deref(),
            self.i4.as_deref(),
            self.i5.as_deref(),
        ]
        .iter()
        .enumerate()
        {
            if let Some(spec) = value {
                cfg = cfg.with_signature_packet(index, spec).map_err(|e| {
                    ConfigError::Validation(format!(
                        "interfaces.{}.awg.i{} is invalid: {}",
                        interface,
                        index + 1,
                        e
                    ))
                })?;
            }
        }
        cfg.validate().map_err(|e| {
            ConfigError::Validation(format!("interfaces.{}.awg settings: {}", interface, e))
        })?;
        cfg.validate_random_trailers(obf).map_err(|e| {
            ConfigError::Validation(format!(
                "interfaces.{}.awg RandomTrailers: {}",
                interface, e
            ))
        })?;
        Ok((obf, cfg))
    }

    fn validate(&self, interface: &str, protocol: ProtocolVersion) -> Result<(), ConfigError> {
        self.build(interface, protocol).map(|_| ())
    }
}

fn decode_hex_key(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        key[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(key)
}

/// Parsed peer endpoint. DNS names are validated but deliberately not resolved
/// while loading configuration; resolution belongs to daemon startup/reconnect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerEndpoint {
    pub host: EndpointHost,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointHost {
    Ip(std::net::IpAddr),
    Dns(String),
}

impl PeerEndpoint {
    pub fn parse(value: &str) -> Result<Self, String> {
        if let Ok(address) = SocketAddr::from_str(value) {
            return Ok(Self {
                host: EndpointHost::Ip(address.ip()),
                port: address.port(),
            });
        }

        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| "expected host:port (IPv6 literals must be bracketed)".to_owned())?;
        let port = port
            .parse::<u16>()
            .map_err(|_| "port must be an integer in 1..=65535".to_owned())?;
        if port == 0 {
            return Err("port must be in 1..=65535".to_owned());
        }
        if host.is_empty() || host.starts_with('[') || host.ends_with(']') || host.contains(':') {
            return Err("invalid host; IPv6 literals must use [address]:port syntax".to_owned());
        }

        if let Ok(address) = host.parse::<std::net::IpAddr>() {
            return Ok(Self {
                host: EndpointHost::Ip(address),
                port,
            });
        }
        if !valid_ascii_dns_name(host) {
            return Err(
                "host must be an IP address or a valid ASCII DNS name (use punycode for IDNs)"
                    .to_owned(),
            );
        }
        Ok(Self {
            host: EndpointHost::Dns(host.to_ascii_lowercase()),
            port,
        })
    }
}

fn valid_ascii_dns_name(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
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
    fn routing_rule_nat_defaults_to_none_and_supports_source_selector() {
        let input = valid_config().replace(
            "destination = \"0.0.0.0/0\"",
            "source = \"10.10.0.0/24\"\ndestination = \"0.0.0.0/0\"\nnat = \"masquerade\"",
        );
        let config = Config::parse_toml(&input).unwrap();
        assert_eq!(
            config.routing.rules[0].source.as_deref(),
            Some(&["10.10.0.0/24".to_owned()][..])
        );
        assert_eq!(config.routing.rules[0].nat, NatMode::Masquerade);
        assert_eq!(config.routing.rules[1].nat, NatMode::None);
    }

    #[test]
    fn rejects_source_and_destination_address_family_mismatch() {
        let input = valid_config().replace(
            "destination = \"0.0.0.0/0\"",
            "source = \"2001:db8::/32\"\ndestination = \"0.0.0.0/0\"",
        );
        let error = Config::parse_toml(&input).unwrap_err();
        assert!(error
            .to_string()
            .contains("share at least one address family"));
    }

    #[test]
    fn routing_rule_allows_both_ip_selectors_to_be_omitted() {
        let input = valid_config()
            .replace("destination = \"0.0.0.0/0\"\n", "")
            .replace("destination = \"::/0\"\n", "");
        let config = Config::parse_toml(&input).unwrap();
        assert!(config.routing.rules[0].source.is_none());
        assert!(config.routing.rules[0].destination.is_none());
        assert!(config.routing.rules[1].source.is_none());
        assert!(config.routing.rules[1].destination.is_none());
    }

    #[test]
    fn routing_rule_accepts_multiple_source_and_destination_cidrs() {
        let input = valid_config().replace(
            "destination = \"0.0.0.0/0\"",
            "source = [\"10.10.0.0/24\", \"2001:db8::/32\"]\ndestination = [\"0.0.0.0/0\", \"::/0\"]",
        );
        let config = Config::parse_toml(&input).unwrap();
        assert_eq!(config.routing.rules[0].source.as_ref().unwrap().len(), 2);
        assert_eq!(
            config.routing.rules[0].destination.as_ref().unwrap().len(),
            2
        );
    }

    #[test]
    fn accepts_explicit_awg30_protocol_name_without_breaking_legacy_name() {
        let legacy = Config::parse_toml(
            &valid_config().replace("protocol = \"awg3_1\"", "protocol = \"awg3\""),
        )
        .unwrap();
        let explicit = Config::parse_toml(
            &valid_config().replace("protocol = \"awg3_1\"", "protocol = \"awg3_0\""),
        )
        .unwrap();
        assert_eq!(legacy.interfaces[1].protocol, ProtocolVersion::Awg3);
        assert_eq!(explicit.interfaces[1].protocol, ProtocolVersion::Awg3);
    }

    #[test]
    fn parses_awg_30_and_31_extension_parameters() {
        let input = valid_config()
            .replace("s1 = 0", "s1 = 12")
            .replace("s2 = 0", "s2 = 12")
            .replace("s3 = 0", "s3 = 12")
            .replace("s4 = 0", "s4 = 12")
            .replace("h4 = \"301-400\"", concat!(
            "h4 = \"301-400\"\n",
            "i1 = \"<b 0x4142><r 8>\"\n",
            "i2 = \"<t>\"\n",
            "i3 = \"<rc 4>\"\n",
            "i4 = \"<rd 4>\"\n",
            "i5 = \"<dz 2>\"\n",
            "header_protection_key = \"4242424242424242424242424242424242424242424242424242424242424242\"\n",
            "content_padding_addition = \"10-100\"\n",
            "content_padding_mode = \"udp_window\"\n",
            "rekey_after_time = \"100-120\"\n",
            "rekey_timeout = \"3-8\"\n",
            "reject_after_time = \"150-180\"\n",
            "keepalive_timeout = \"7-13\"\n",
            "max_handshake_attempts = \"15-20\""
        ));
        let config = Config::parse_toml(&input).unwrap();
        config.interfaces[1]
            .awg
            .as_ref()
            .unwrap()
            .build("awg-uplink", ProtocolVersion::Awg3_1)
            .unwrap();
    }

    #[test]
    fn rejects_invalid_awg_extension_values() {
        for (field, value) in [
            ("header_protection_key", "\"abcd\""),
            ("content_padding_addition", "\"100-10\""),
            ("rekey_timeout", "\"8-3\""),
            ("i1", "\"<unknown 2>\""),
        ] {
            let input = valid_config().replace(
                "h4 = \"301-400\"",
                &format!("h4 = \"301-400\"\n{} = {}", field, value),
            );
            assert!(Config::parse_toml(&input).is_err(), "{}", field);
        }
    }

    #[test]
    fn ipv6_is_blocked_by_default_on_every_interface() {
        let config = Config::parse_toml(&valid_config()).unwrap();
        assert!(config
            .interfaces
            .iter()
            .all(|interface| !interface.ipv6_enabled));
    }

    #[test]
    fn ipv6_can_be_enabled_independently_per_interface() {
        let input = valid_config()
            .replace(
                "socket_fwmark = 4097",
                "socket_fwmark = 4097\nipv6_enabled = true",
            )
            .replace(
                "socket_fwmark = 4098",
                "socket_fwmark = 4098\nipv6_enabled = false",
            );
        let config = Config::parse_toml(&input).unwrap();
        assert!(config.interfaces[0].ipv6_enabled);
        assert!(!config.interfaces[1].ipv6_enabled);
    }

    #[test]
    fn rejects_removed_global_ipv6_setting() {
        let input = valid_config().replace(
            "manage_ip_forwarding = false",
            "manage_ip_forwarding = false\nipv6_enabled = true",
        );
        assert!(Config::parse_toml(&input)
            .unwrap_err()
            .to_string()
            .contains("unknown field"));
    }

    #[test]
    fn parses_and_validates_a_complete_multi_tunnel_config() {
        let config = Config::parse_toml(&valid_config()).unwrap();
        assert_eq!(config.interfaces.len(), 2);
        assert_eq!(config.routing.rules.len(), 2);
        assert_eq!(config.interfaces[1].protocol, ProtocolVersion::Awg3_1);
    }

    #[test]
    fn parses_dns_peer_endpoints_without_resolving_them() {
        let endpoint = PeerEndpoint::parse("VPN.Example.COM:51820").unwrap();
        assert_eq!(
            endpoint,
            PeerEndpoint {
                host: EndpointHost::Dns("vpn.example.com".to_owned()),
                port: 51820,
            }
        );
        assert_eq!(
            PeerEndpoint::parse("xn--bcher-kva.example:443")
                .unwrap()
                .port,
            443
        );
    }

    #[test]
    fn parses_ipv4_and_bracketed_ipv6_peer_endpoints() {
        assert_eq!(PeerEndpoint::parse("192.0.2.1:51820").unwrap().port, 51820);
        assert_eq!(
            PeerEndpoint::parse("[2001:db8::1]:51820").unwrap().port,
            51820
        );
    }

    #[test]
    fn rejects_malformed_dns_endpoints_and_zero_ports() {
        for value in [
            "bad..example:51820",
            "-bad.example:51820",
            "bad-.example:51820",
            "bad_name.example:51820",
            "münich.example:51820",
            "example.com:0",
            "example.com:not-a-port",
            "2001:db8::1:51820",
        ] {
            assert!(
                PeerEndpoint::parse(value).is_err(),
                "endpoint should be rejected: {value}"
            );
        }
    }

    #[test]
    fn rejects_invalid_key_lengths() {
        let input = valid_config().replace(KEY, "AQID");
        let error = Config::parse_toml(&input).unwrap_err();
        assert!(error.to_string().contains("exactly 32 bytes"));
    }

    #[test]
    fn socket_fwmarks_are_automatically_assigned_when_omitted() {
        let input = valid_config()
            .replace("socket_fwmark = 4097\n", "")
            .replace("socket_fwmark = 4098\n", "");
        let config = Config::parse_toml(&input).unwrap();
        assert_eq!(
            config.resolved_socket_fwmarks().unwrap(),
            vec![0x1000, 0x1001]
        );
    }

    #[test]
    fn automatic_socket_marks_skip_explicit_values_regardless_of_interface_order() {
        let input = valid_config()
            .replace("socket_fwmark = 4097\n", "")
            .replace("socket_fwmark = 4098", "socket_fwmark = 4096");
        let config = Config::parse_toml(&input).unwrap();
        assert_eq!(config.resolved_socket_fwmarks().unwrap(), vec![4097, 4096]);
    }

    #[test]
    fn automatic_socket_marks_skip_the_inner_routing_mark_range() {
        let input = valid_config()
            .replace("socket_fwmark = 4097\n", "")
            .replace("socket_fwmark = 4098\n", "")
            .replacen(
                "[[routing.rules]]",
                "[routing]\nmark_base = 4096\n\n[[routing.rules]]",
                1,
            );
        let config = Config::parse_toml(&input).unwrap();
        assert_eq!(config.resolved_socket_fwmarks().unwrap(), vec![4097, 4098]);
    }

    #[test]
    fn explicit_socket_fwmarks_are_preserved_when_mixed_with_automatic_marks() {
        let input = valid_config().replace("socket_fwmark = 4097\n", "");
        let config = Config::parse_toml(&input).unwrap();
        assert_eq!(config.resolved_socket_fwmarks().unwrap(), vec![4096, 4098]);
    }

    #[test]
    fn rejects_explicit_socket_mark_inside_packet_mark_range() {
        let input = valid_config().replace("socket_fwmark = 4097", "socket_fwmark = 2147483648");
        let error = Config::parse_toml(&input).unwrap_err();
        assert!(error.to_string().contains("mark_base range overlaps"));
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
        assert!(
            matches!(
                &error,
                ConfigError::Validation(message) if message.contains("H1-H4 ranges")
            ),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn rejects_unknown_fields_instead_of_ignoring_typos() {
        let input = valid_config().replace("mtu = 1380", "mtu = 1380\nmtuu = 1400");
        let error = Config::parse_toml(&input).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_duplicate_priorities_for_the_same_ingress() {
        let input = valid_config().replace("priority = 110", "priority = 100");
        let error = Config::parse_toml(&input).unwrap_err();
        assert!(error.to_string().contains("duplicate priority"));
    }

    #[test]
    fn allows_the_same_priority_on_different_ingresses() {
        let input = valid_config()
            .replace("name = \"wg-server\"", "name = \"wg-server\"")
            .replace("priority = 110", "priority = 100");
        // Duplicate priorities are scoped to an ingress. The validation
        // fixture has one ingress, so move the second rule to another valid
        // server interface before parsing.
        let input = input.replace(
            "[[interfaces]]\nname = \"awg-uplink\"",
            "[[interfaces]]\nname = \"wg-backup\"\nprotocol = \"wg\"\nrole = \"server\"\naddresses = [\"10.11.0.1/24\"]\nlisten_port = 51823\nprivate_key = \"{KEY}\"\nsocket_fwmark = 4100\n\n[[interfaces]]\nname = \"awg-uplink\"",
        ).replace("priority = 100\ningress = \"wg-server\"\ndestination = \"::/0\"", "priority = 100\ningress = \"wg-backup\"\ndestination = \"::/0\" ")
        .replace("{KEY}", KEY);
        assert!(Config::parse_toml(&input).is_ok());
    }

    #[test]
    fn rejects_unknown_routing_ingress_and_egress() {
        let unknown_ingress =
            valid_config().replace("ingress = \"wg-server\"", "ingress = \"wg-missing\"");
        assert!(Config::parse_toml(&unknown_ingress)
            .unwrap_err()
            .to_string()
            .contains("unknown ingress"));

        let unknown_egress =
            valid_config().replace("egress = \"awg-uplink\"", "egress = \"awg-missing\"");
        assert!(Config::parse_toml(&unknown_egress)
            .unwrap_err()
            .to_string()
            .contains("unknown egress"));
    }

    #[test]
    fn rejects_same_interface_as_ingress_and_egress() {
        let input = valid_config().replace("egress = \"awg-uplink\"", "egress = \"wg-server\"");
        assert!(Config::parse_toml(&input)
            .unwrap_err()
            .to_string()
            .contains("both ingress and egress"));
    }

    #[test]
    fn rejects_wrong_interface_roles_for_routing_direction() {
        let wrong_ingress = valid_config().replacen("role = \"server\"", "role = \"client\"", 1);
        assert!(Config::parse_toml(&wrong_ingress)
            .unwrap_err()
            .to_string()
            .contains("must have role = 'server'"));

        let wrong_egress = valid_config().replacen("role = \"client\"", "role = \"server\"", 1);
        assert!(Config::parse_toml(&wrong_egress)
            .unwrap_err()
            .to_string()
            .contains("must have role = 'client'"));
    }

    #[test]
    fn rejects_empty_or_invalid_routing_cidr_selectors() {
        let empty_source = valid_config().replace(
            "destination = \"0.0.0.0/0\"",
            "source = []\ndestination = \"0.0.0.0/0\"",
        );
        assert!(Config::parse_toml(&empty_source)
            .unwrap_err()
            .to_string()
            .contains("source must not be an empty list"));

        let invalid_destination = valid_config().replace(
            "destination = \"0.0.0.0/0\"",
            "destination = \"not-a-cidr\"",
        );
        assert!(Config::parse_toml(&invalid_destination)
            .unwrap_err()
            .to_string()
            .contains("invalid CIDR"));
    }

    #[test]
    fn rejects_unknown_nat_modes() {
        let input = valid_config().replace(
            "destination = \"0.0.0.0/0\"",
            "destination = \"0.0.0.0/0\"\nnat = \"snat\"",
        );
        assert!(Config::parse_toml(&input).is_err());
    }
}
