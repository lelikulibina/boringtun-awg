use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use boringtun::noise::amnezia::AmneziaWgConfig;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;

/// Number of unique routing decisions representable in vpn-relay's reserved
/// conntrack mark field (12 decision bits plus a 4-bit namespace prefix).
pub(crate) const MAX_ROUTING_DECISIONS: usize = 0x0fff;

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
    pub interfaces: BTreeMap<String, InterfaceConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
    /// Explicit exceptions to the managed-interface INPUT/OUTPUT deny policies.
    #[serde(default)]
    pub firewall: FirewallConfig,
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
    /// Retained internally only for compatibility with the routing planner.
    /// It is never configurable and IPv6 is not a supported datapath.
    #[serde(skip)]
    pub ipv6_enabled: bool,
    #[serde(default)]
    pub manage_ip_forwarding: bool,
    /// Interfaces whose link-scoped forwarding sysctls vpn-relay manages.
    /// When non-empty, namespace-wide forwarding must already be enabled by
    /// the container/runtime; only these links are changed by vpn-relay.
    #[serde(default)]
    pub forwarding_interfaces: Vec<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            stats_interval_secs: default_stats_interval(),
            nft_table: default_nft_table(),
            ipv6_enabled: false,
            manage_ip_forwarding: false,
            forwarding_interfaces: Vec::new(),
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
    "vpn_relay".to_owned()
}

fn default_mtu() -> u16 {
    1380
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelType {
    #[serde(rename = "wg")]
    WireGuard,
    #[serde(rename = "awg")]
    AmneziaWg,
}

/// Source NAT is a property of a selected routing rule, not of an interface.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NatMode {
    #[default]
    None,
    Masquerade,
    Snat,
}

/// Fully-resolved source NAT action used by the routing and firewall layers.
/// The TOML representation keeps the backward-compatible `nat` + `nat_to`
/// fields, while this type makes it impossible to represent SNAT without an IP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NatAction {
    None,
    Masquerade,
    Snat(IpAddr),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceConfig {
    #[serde(rename = "type")]
    pub tunnel_type: TunnelType,
    pub address: Vec<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Retained internally only while the datapath migration is completed.
    /// It is never configurable; IPv6 is rejected during validation.
    #[serde(skip)]
    pub ipv6_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    pub private_key: String,
    /// Optional mark for encrypted UDP sockets; assigned automatically when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_fwmark: Option<u32>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awg: Option<AmneziaWgConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum PersistentKeepaliveConfig {
    Seconds(u16),
    Range(String),
}

impl PersistentKeepaliveConfig {
    pub fn to_range(&self) -> Result<(u32, u32), String> {
        match self {
            Self::Seconds(seconds) => Ok((u32::from(*seconds), u32::from(*seconds))),
            Self::Range(value) => {
                let (min, max) = value
                    .split_once('-')
                    .ok_or_else(|| format!("invalid PersistentKeepalive range '{value}'"))?;
                if max.contains('-') {
                    return Err(format!("invalid PersistentKeepalive range '{value}'"));
                }
                let min = min
                    .parse::<u32>()
                    .map_err(|_| format!("invalid PersistentKeepalive range '{value}'"))?;
                let max = max
                    .parse::<u32>()
                    .map_err(|_| format!("invalid PersistentKeepalive range '{value}'"))?;
                if min == 0 || max == 0 || min > max {
                    return Err(format!(
                        "invalid PersistentKeepalive range '{value}': expected 1 <= min <= max"
                    ));
                }
                Ok((min, max))
            }
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive_secs: Option<PersistentKeepaliveConfig>,
    /// Inclusive AmneziaWG keepalive interval range in seconds. Mutually exclusive with the legacy field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive_range: Option<(u32, u32)>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    #[serde(default)]
    pub input: FirewallRuleSet,
    #[serde(default)]
    pub output: FirewallRuleSet,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRuleSet {
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

/// An allow exception scoped to one managed interface. INPUT rules may use
/// source CIDRs; OUTPUT rules may use destination CIDRs. Missing selectors
/// intentionally mean any address/protocol on that interface.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRule {
    pub interface: String,
    #[serde(default, deserialize_with = "deserialize_optional_cidrs")]
    pub source: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_cidrs")]
    pub destination: Option<Vec<String>>,
    #[serde(default)]
    pub protocol: Option<FirewallProtocol>,
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
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
    /// Required only for static source NAT.
    #[serde(default)]
    pub nat_to: Option<IpAddr>,
}

impl RoutingRule {
    /// Resolve the validated TOML fields into one exhaustive, typed action.
    pub fn nat_action(&self) -> NatAction {
        match self.nat {
            NatMode::None => NatAction::None,
            NatMode::Masquerade => NatAction::Masquerade,
            NatMode::Snat => NatAction::Snat(
                self.nat_to
                    .expect("validated SNAT routing rule must contain nat_to"),
            ),
        }
    }
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

    /// Ensure a candidate configuration can be applied without recreating
    /// tunnel devices or changing resources whose lifecycle is owned by start().
    ///
    /// Peer sets, routing decisions and firewall rules are intentionally
    /// mutable. Interface identity and tunnel construction parameters are not.
    pub fn validate_reload_compatibility(&self, next: &Self) -> Result<(), ConfigError> {
        if self.interfaces.keys().ne(next.interfaces.keys()) {
            return invalid(
                "reload cannot add or remove interfaces; tunnel lifecycle changes require a restart",
            );
        }

        for (name, current) in &self.interfaces {
            let candidate = &next.interfaces[name];
            if current.tunnel_type != candidate.tunnel_type
                || current.address != candidate.address
                || current.mtu != candidate.mtu
                || current.ipv6_enabled != candidate.ipv6_enabled
                || current.listen_port != candidate.listen_port
                || current.private_key != candidate.private_key
                || current.socket_fwmark != candidate.socket_fwmark
                || current.awg != candidate.awg
            {
                return invalid(format!(
                    "reload cannot change immutable tunnel parameters for interface '{name}'; restart vpn-relay to apply them",
                ));
            }
        }

        if self.resolved_socket_fwmarks()? != next.resolved_socket_fwmarks()? {
            return invalid(
                "reload cannot change resolved socket fwmarks; restart vpn-relay to apply them",
            );
        }
        let current_egresses: std::collections::BTreeSet<_> = self
            .routing
            .rules
            .iter()
            .map(|rule| rule.egress.as_str())
            .collect();
        let next_egresses: std::collections::BTreeSet<_> = next
            .routing
            .rules
            .iter()
            .map(|rule| rule.egress.as_str())
            .collect();
        let current_marks: std::collections::BTreeSet<_> =
            self.resolved_routing_fwmarks()?.into_iter().collect();
        let next_marks: std::collections::BTreeSet<_> =
            next.resolved_routing_fwmarks()?.into_iter().collect();
        let policy_resources_unchanged =
            current_egresses == next_egresses && current_marks == next_marks;
        if !policy_resources_unchanged && current_marks.intersection(&next_marks).next().is_some() {
            return invalid(
                "reload requires old and new routing mark ranges to be disjoint when policy-routing resources change",
            );
        }

        if self.daemon.nft_table != next.daemon.nft_table {
            return invalid("reload cannot change daemon.nft_table while the daemon is running");
        }
        if self.daemon.ipv6_enabled != next.daemon.ipv6_enabled {
            return invalid("reload cannot change daemon.ipv6_enabled while the daemon is running");
        }
        if self.daemon.manage_ip_forwarding != next.daemon.manage_ip_forwarding
            || self.daemon.forwarding_interfaces != next.daemon.forwarding_interfaces
        {
            return invalid(
                "reload cannot change daemon.manage_ip_forwarding or daemon.forwarding_interfaces while the daemon is running",
            );
        }
        if self.daemon.log_level != next.daemon.log_level {
            return invalid("reload cannot change daemon.log_level; restart vpn-relay to apply it");
        }

        Ok(())
    }

    /// Resolve one packet mark for each distinct egress referenced by routing rules.
    /// The order matches the lexicographically sorted egress list in RoutingPlan.
    pub fn resolved_routing_fwmarks(&self) -> Result<Vec<u32>, ConfigError> {
        let egress_count = self
            .routing
            .rules
            .iter()
            .map(|rule| rule.egress.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len();
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

    /// Resolve explicit and automatically assigned socket marks in interface-name order.
    /// The socket and packet mark spaces are disjoint by exact 32-bit value.
    /// Explicit marks are reserved first so automatic allocation never displaces them.
    pub fn resolved_socket_fwmarks(&self) -> Result<Vec<u32>, ConfigError> {
        let routing_marks: HashSet<_> = self.resolved_routing_fwmarks()?.into_iter().collect();

        let mut used = HashSet::new();
        for (interface_name, interface) in &self.interfaces {
            if let Some(mark) = interface.socket_fwmark {
                if mark == 0 {
                    return invalid(format!(
                        "interfaces.{}.socket_fwmark must be non-zero",
                        interface_name
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
        for interface in self.interfaces.values() {
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
        if self.routing.rules.len() > MAX_ROUTING_DECISIONS {
            return invalid(format!(
                "[routing].rules supports at most {MAX_ROUTING_DECISIONS} entries because conntrack decision marks have a reserved 12-bit id field"
            ));
        }
        if self.interfaces.is_empty() {
            return invalid("at least one interface must be configured");
        }
        if !self.daemon.forwarding_interfaces.is_empty() && !self.daemon.manage_ip_forwarding {
            return invalid("[daemon].forwarding_interfaces requires manage_ip_forwarding = true");
        }
        let mut forwarding_names = HashSet::new();
        for name in &self.daemon.forwarding_interfaces {
            validate_interface_name(name)?;
            if !forwarding_names.insert(name) {
                return invalid(format!(
                    "[daemon].forwarding_interfaces contains duplicate interface '{name}'"
                ));
            }
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

        for (name, interface) in &self.interfaces {
            if !self.daemon.ipv6_enabled && interface.ipv6_enabled {
                return invalid(format!(
                    "interfaces.{name}.ipv6_enabled cannot be true when daemon.ipv6_enabled = false"
                ));
            }
        }

        let mut listen_ports = HashSet::new();

        for (interface_name, interface) in &self.interfaces {
            validate_interface_name(interface_name)?;
            if let Some(port) = interface.listen_port {
                if port == 0 {
                    return invalid(format!(
                        "interfaces.{}.listen_port must be in 1..=65535 when specified",
                        interface_name
                    ));
                }
                if !listen_ports.insert(port) {
                    return invalid(format!(
                        "UDP listen port {} is used by more than one interface",
                        port
                    ));
                }
            }
            if !(576..=65535).contains(&interface.mtu) {
                return invalid(format!(
                    "interfaces.{}.mtu must be in 576..=65535",
                    interface_name
                ));
            }
            decode_key(
                &interface.private_key,
                &format!("interfaces.{}.private_key", interface_name),
            )?;

            let mut has_ipv6 = false;
            for address in &interface.address {
                let parsed =
                    parse_prefix(address, &format!("interfaces.{}.address", interface_name))?;
                has_ipv6 |= parsed.0.is_ipv6();
            }
            if has_ipv6 && !interface.ipv6_enabled {
                return invalid(format!(
                    "interfaces.{interface_name}.address contains IPv6, but IPv6 is disabled on that interface"
                ));
            }
            if has_ipv6 && interface.mtu < 1280 {
                return invalid(format!(
                    "interfaces.{}.mtu must be at least 1280 when IPv6 addresses are configured",
                    interface_name
                ));
            }

            if interface.tunnel_type == TunnelType::WireGuard && interface.awg.is_some() {
                return invalid(format!(
                    "interfaces.{}.awg is not valid for tunnel type 'wg'",
                    interface_name
                ));
            }
            let mut peer_keys = HashSet::new();
            let mut owned_prefixes = HashSet::new();
            for (peer_index, peer) in interface.peers.iter().enumerate() {
                let peer_path = format!("interfaces.{}.peers[{}]", interface_name, peer_index);
                let public_key = decode_key(&peer.public_key, &format!("{peer_path}.public_key"))?;
                if !peer_keys.insert(public_key) {
                    return invalid(format!(
                        "interfaces.{} contains duplicate peer public keys",
                        interface_name
                    ));
                }
                if let Some(psk) = &peer.preshared_key {
                    decode_key(psk, &format!("{peer_path}.preshared_key"))?;
                }
                if peer.persistent_keepalive_secs.is_some()
                    && peer.persistent_keepalive_range.is_some()
                {
                    return invalid(format!(
                        "{peer_path} must not set both persistent_keepalive_secs and persistent_keepalive_range"
                    ));
                }
                if let Some(value) = &peer.persistent_keepalive_secs {
                    value.to_range().map_err(|error| {
                        ConfigError::Validation(format!(
                            "{peer_path}.persistent_keepalive_secs: {error}"
                        ))
                    })?;
                }
                if let Some((min, max)) = peer.persistent_keepalive_range {
                    if min == 0 || max == 0 || min > max {
                        return invalid(format!(
                            "{peer_path}.persistent_keepalive_range must satisfy 1 <= min <= max"
                        ));
                    }
                }
                if let Some(endpoint) = &peer.endpoint {
                    let parsed = PeerEndpoint::parse(endpoint).map_err(|error| {
                        ConfigError::Validation(format!(
                            "{peer_path}.endpoint is invalid: {}",
                            error
                        ))
                    })?;
                    if matches!(parsed.host, EndpointHost::Ip(ip) if ip.is_ipv6())
                        && !interface.ipv6_enabled
                    {
                        return invalid(format!(
                            "{peer_path}.endpoint uses an IPv6 literal, but IPv6 is disabled on interface '{interface_name}'"
                        ));
                    }
                }
                for prefix in &peer.allowed_ips {
                    let parsed = parse_prefix(prefix, &format!("{peer_path}.allowed_ips"))?;
                    has_ipv6 |= parsed.0.is_ipv6();
                    if parsed.0.is_ipv6() && !interface.ipv6_enabled {
                        return invalid(format!(
                            "{peer_path}.allowed_ips contains IPv6 CIDR {prefix}, but interface '{interface_name}' has IPv6 disabled"
                        ));
                    }
                    if !owned_prefixes.insert(parsed) {
                        return invalid(format!(
                            "interfaces.{} assigns AllowedIP {} to more than one peer",
                            interface_name, prefix
                        ));
                    }
                }
            }
            if has_ipv6 && interface.mtu < 1280 {
                return invalid(format!(
                    "interfaces.{}.mtu must be at least 1280 when IPv6 AllowedIPs are configured",
                    interface_name
                ));
            }
        }

        if self.routing.mark_base == 0 {
            return invalid("[routing].mark_base must be non-zero");
        }
        self.resolved_socket_fwmarks()?;

        let mut route_priorities = HashSet::new();
        for rule in &self.routing.rules {
            if !route_priorities.insert((rule.ingress.as_str(), rule.priority)) {
                return invalid(format!(
                    "routing contains duplicate priority {} for ingress '{}'",
                    rule.priority, rule.ingress
                ));
            }
            if !self.interfaces.contains_key(rule.ingress.as_str()) {
                return invalid(format!(
                    "routing rule references unknown ingress '{}'",
                    rule.ingress
                ));
            }
            if !self.interfaces.contains_key(rule.egress.as_str()) {
                return invalid(format!(
                    "routing rule references unknown egress '{}'",
                    rule.egress
                ));
            }
            if rule.ingress == rule.egress {
                return invalid(format!(
                    "routing rule cannot use '{}' as both ingress and egress",
                    rule.ingress
                ));
            }
            let source_prefixes = rule
                .source
                .as_ref()
                .map(|prefixes| {
                    if prefixes.is_empty() {
                        return invalid("routing.rules.source must not be an empty list");
                    }
                    let mut unique = HashSet::new();
                    for prefix in prefixes {
                        if !unique.insert(canonical_prefix(prefix, "routing.rules.source")?) {
                            return invalid(
                                "routing.rules.source must not contain duplicate CIDR selectors (including equivalent CIDR networks)",
                            );
                        }
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
                    let mut unique = HashSet::new();
                    for prefix in prefixes {
                        if !unique.insert(canonical_prefix(prefix, "routing.rules.destination")?) {
                            return invalid(
                                "routing.rules.destination must not contain duplicate CIDR selectors (including equivalent CIDR networks)",
                            );
                        }
                    }
                    prefixes
                        .iter()
                        .map(|prefix| parse_prefix(prefix, "routing.rules.destination"))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?;

            let ingress_ipv6 = self.interfaces[&rule.ingress].ipv6_enabled;
            let egress_ipv6 = self.interfaces[&rule.egress].ipv6_enabled;
            if source_prefixes
                .iter()
                .flatten()
                .chain(destination_prefixes.iter().flatten())
                .any(|(address, _)| address.is_ipv6())
                && !(ingress_ipv6 && egress_ipv6)
            {
                return invalid(format!(
                    "routing rule {} -> {} contains IPv6 selectors but IPv6 is disabled on ingress or egress",
                    rule.ingress, rule.egress
                ));
            }

            match rule.nat {
                NatMode::Snat => {
                    let Some(address) = rule.nat_to else {
                        return invalid("routing.rules.nat_to is required when nat = \"snat\"");
                    };
                    let ingress_ipv6 = self.interfaces[&rule.ingress].ipv6_enabled;
                    let egress_ipv6 = self.interfaces[&rule.egress].ipv6_enabled;
                    if address.is_ipv6() && !(ingress_ipv6 && egress_ipv6) {
                        return invalid(format!(
                            "routing rule {} -> {} uses IPv6 SNAT but IPv6 is disabled on ingress or egress",
                            rule.ingress, rule.egress
                        ));
                    }
                    let family_matches = match (&source_prefixes, &destination_prefixes) {
                        (Some(sources), Some(destinations)) => sources.iter().any(|(source, _)| {
                            source.is_ipv4() == address.is_ipv4()
                                && destinations.iter().any(|(destination, _)| {
                                    destination.is_ipv4() == address.is_ipv4()
                                })
                        }),
                        (Some(sources), None) => sources
                            .iter()
                            .any(|(source, _)| source.is_ipv4() == address.is_ipv4()),
                        (None, Some(destinations)) => destinations
                            .iter()
                            .any(|(destination, _)| destination.is_ipv4() == address.is_ipv4()),
                        (None, None) => true,
                    };
                    if !family_matches {
                        return invalid("routing.rules.nat_to address family must match the routing rule's selected source/destination family");
                    }
                }
                NatMode::None | NatMode::Masquerade if rule.nat_to.is_some() => {
                    return invalid("routing.rules.nat_to is valid only when nat = \"snat\"");
                }
                NatMode::None | NatMode::Masquerade => {}
            }

            if let (Some(sources), Some(destinations)) = (&source_prefixes, &destination_prefixes) {
                let has_common_family = sources.iter().any(|source| {
                    destinations
                        .iter()
                        .any(|destination| source.0.is_ipv4() == destination.0.is_ipv4())
                });
                if !has_common_family {
                    return invalid(
                        "routing.rules.source and destination must share at least one address family",
                    );
                }
            }
        }

        for (direction, rules, is_input) in [
            ("firewall.input", &self.firewall.input.rules, true),
            ("firewall.output", &self.firewall.output.rules, false),
        ] {
            for (index, rule) in rules.iter().enumerate() {
                let path = format!("{direction}.rules[{index}]");
                let Some(interface) = self.interfaces.get(&rule.interface) else {
                    return invalid(format!(
                        "{path} references unknown interface '{}'",
                        rule.interface
                    ));
                };
                if is_input && rule.destination.is_some() {
                    return invalid(format!("{path}.destination is not valid for INPUT rules"));
                }
                if !is_input && rule.source.is_some() {
                    return invalid(format!("{path}.source is not valid for OUTPUT rules"));
                }
                let mut has_ipv4_selector = false;
                let mut has_ipv6_selector = false;
                for (field, prefixes) in [
                    ("source", rule.source.as_ref()),
                    ("destination", rule.destination.as_ref()),
                ] {
                    if let Some(prefixes) = prefixes {
                        if prefixes.is_empty() {
                            return invalid(format!("{path}.{field} must not be an empty list"));
                        }
                        let mut unique = HashSet::new();
                        for prefix in prefixes {
                            if !unique.insert(canonical_prefix(prefix, &format!("{path}.{field}"))?)
                            {
                                return invalid(format!(
                                    "{path}.{field} must not contain duplicate CIDR selectors (including equivalent CIDR networks)"
                                ));
                            }
                        }
                        for prefix in prefixes {
                            let (address, _) = parse_prefix(prefix, &format!("{path}.{field}"))?;
                            has_ipv6_selector |= address.is_ipv6();
                            has_ipv4_selector |= address.is_ipv4();
                            if address.is_ipv6() && !interface.ipv6_enabled {
                                return invalid(format!(
                                    "{path}.{field} contains IPv6 CIDR {prefix}, but interface '{}' has IPv6 disabled",
                                    rule.interface
                                ));
                            }
                        }
                    }
                }
                match rule.protocol {
                    Some(FirewallProtocol::Icmp) if has_ipv6_selector => {
                        return invalid(format!(
                            "{path}.protocol = \"icmp\" cannot be combined with IPv6 CIDR selectors"
                        ));
                    }
                    Some(FirewallProtocol::Icmpv6) if has_ipv4_selector => {
                        return invalid(format!(
                            "{path}.protocol = \"icmpv6\" cannot be combined with IPv4 CIDR selectors"
                        ));
                    }
                    Some(FirewallProtocol::Icmpv6) if !interface.ipv6_enabled => {
                        return invalid(format!(
                            "{path}.protocol = \"icmpv6\" requires IPv6 to be enabled on interface '{}'",
                            rule.interface
                        ));
                    }
                    _ => {}
                }
                if let Some(ports) = &rule.ports {
                    if ports.is_empty() || ports.contains(&0) {
                        return invalid(format!(
                            "{path}.ports must contain one or more ports in 1..=65535"
                        ));
                    }
                    if !matches!(
                        rule.protocol,
                        Some(FirewallProtocol::Tcp | FirewallProtocol::Udp)
                    ) {
                        return invalid(format!(
                            "{path}.ports requires protocol = \"tcp\" or \"udp\""
                        ));
                    }
                }
            }
        }

        Ok(())
    }
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

fn canonical_prefix(value: &str, field: &str) -> Result<(IpAddr, u8), ConfigError> {
    let (address, prefix) = parse_prefix(value, field)?;
    let network = match address {
        IpAddr::V4(address) => {
            let bits = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(std::net::Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(address) => {
            let bits = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(std::net::Ipv6Addr::from(bits & mask))
        }
    };
    Ok((network, prefix))
}

fn parse_prefix(value: &str, field: &str) -> Result<(IpAddr, u8), ConfigError> {
    let (address, prefix) = value.split_once('/').ok_or_else(|| {
        ConfigError::Validation(format!(
            "{} contains invalid CIDR '{}': expected address/prefix",
            field, value
        ))
    })?;
    let address = address.parse::<IpAddr>().map_err(|error| {
        ConfigError::Validation(format!(
            "{} contains invalid CIDR '{}': {}",
            field, value, error
        ))
    })?;
    let prefix = prefix.parse::<u8>().map_err(|error| {
        ConfigError::Validation(format!(
            "{} contains invalid CIDR '{}': {}",
            field, value, error
        ))
    })?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(ConfigError::Validation(format!(
            "{} contains invalid CIDR '{}': prefix exceeds {}",
            field, value, max_prefix
        )));
    }
    Ok((address, prefix))
}

fn validate_interface_name(name: &str) -> Result<(), ConfigError> {
    // BoringTun interprets a numeric Linux interface name as an inherited
    // file descriptor. vpn-relay owns its TUN descriptors and must not accept
    // this alternate constructor mode from configuration.
    if name.parse::<i32>().is_ok() {
        return invalid(format!(
            "interface name '{}' must not be a numeric file descriptor",
            name
        ));
    }
    if name.is_empty()
        || name == "."
        || name == ".."
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
nft_table = "vpn_relay"
manage_ip_forwarding = false

[interfaces.wg-server]
type = "wg"
address = ["10.10.0.1/24"]
mtu = 1380
listen_port = 51820
private_key = "{KEY}"
socket_fwmark = 4097

[[interfaces.wg-server.peers]]
public_key = "{KEY}"
allowed_ips = ["10.10.0.2/32"]

[interfaces.awg-uplink]
type = "awg"
address = ["10.20.0.2/32"]
mtu = 1380
listen_port = 51821
private_key = "{KEY}"
socket_fwmark = 4098

[[interfaces.awg-uplink.peers]]
public_key = "{KEY}"
endpoint = "198.51.100.10:51820"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive_secs = 25

[interfaces.awg-uplink.awg]
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

"#
        )
    }

    fn ipv4_config() -> String {
        valid_config()
    }

    #[test]
    fn forwarding_interface_allowlist_requires_explicit_global_management() {
        let text = valid_config().replace(
            "manage_ip_forwarding = false",
            "manage_ip_forwarding = false\nforwarding_interfaces = [\"eth0\"]",
        );
        assert!(Config::parse_toml(&text).is_err());
    }

    #[test]
    fn forwarding_interface_allowlist_accepts_unique_valid_names() {
        let text = valid_config().replace(
            "manage_ip_forwarding = false",
            "manage_ip_forwarding = true\nforwarding_interfaces = [\"eth0\", \"wg-server\"]",
        );
        let config = Config::parse_toml(&text).unwrap();
        assert_eq!(
            config.daemon.forwarding_interfaces,
            vec!["eth0".to_owned(), "wg-server".to_owned()]
        );
    }

    #[test]
    fn forwarding_interface_allowlist_rejects_duplicates_and_invalid_names() {
        let duplicate = valid_config().replace(
            "manage_ip_forwarding = false",
            "manage_ip_forwarding = true\nforwarding_interfaces = [\"eth0\", \"eth0\"]",
        );
        assert!(Config::parse_toml(&duplicate).is_err());

        let invalid = valid_config().replace(
            "manage_ip_forwarding = false",
            "manage_ip_forwarding = true\nforwarding_interfaces = [\"../eth0\"]",
        );
        assert!(Config::parse_toml(&invalid).is_err());
    }

    #[test]
    fn forwarding_interface_allowlist_is_immutable_during_reload() {
        let current = Config::parse_toml(&valid_config().replace(
            "manage_ip_forwarding = false",
            "manage_ip_forwarding = true\nforwarding_interfaces = [\"eth0\"]",
        ))
        .unwrap();
        let next = Config::parse_toml(&valid_config().replace(
            "manage_ip_forwarding = false",
            "manage_ip_forwarding = true\nforwarding_interfaces = [\"eth1\"]",
        ))
        .unwrap();
        assert!(current.validate_reload_compatibility(&next).is_err());
    }

    #[test]
    fn numeric_interface_names_are_rejected_as_inherited_file_descriptors() {
        assert!(validate_interface_name("123").is_err());
        assert!(validate_interface_name("-1").is_err());
        assert!(validate_interface_name("wg123").is_ok());
        assert!(validate_interface_name(".").is_err());
        assert!(validate_interface_name("..").is_err());
    }

    #[test]
    fn reload_compatibility_allows_peer_routing_and_firewall_changes() {
        let current = Config::parse_toml(&valid_config()).unwrap();
        let mut candidate_text = valid_config()
            .replace("10.10.0.2/32", "10.10.0.3/32")
            .replace(
                "destination = \"0.0.0.0/0\"",
                "destination = \"10.0.0.0/8\"",
            );
        candidate_text.push_str(
            "\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nsource = \"10.10.0.3/32\"\n",
        );
        let candidate = Config::parse_toml(&candidate_text).unwrap();
        current.validate_reload_compatibility(&candidate).unwrap();
    }

    #[test]
    fn reload_compatibility_allows_disjoint_policy_route_resource_changes() {
        let current = Config::parse_toml(&valid_config()).unwrap();

        let changed_mark_base = Config::parse_toml(&valid_config().replacen(
            "[[routing.rules]]",
            "[routing]\nmark_base = 0x90000000\n\n[[routing.rules]]",
            1,
        ))
        .unwrap();
        current
            .validate_reload_compatibility(&changed_mark_base)
            .unwrap();

        let mut changed_egress = current.clone();
        changed_egress.routing.rules.truncate(1);
        changed_egress.routing.rules[0].ingress = "awg-uplink".to_owned();
        changed_egress.routing.rules[0].egress = "wg-server".to_owned();
        changed_egress.routing.mark_base = 0x9000_0000;
        changed_egress.validate().unwrap();
        current
            .validate_reload_compatibility(&changed_egress)
            .unwrap();

        let mut no_egress = current.clone();
        no_egress.routing.rules.clear();
        no_egress.validate().unwrap();
        current.validate_reload_compatibility(&no_egress).unwrap();
    }

    #[test]
    fn reload_compatibility_rejects_overlapping_policy_route_mark_ranges() {
        let current = Config::parse_toml(&valid_config()).unwrap();
        let mut changed_egress = current.clone();
        changed_egress.routing.rules.truncate(1);
        changed_egress.routing.rules[0].ingress = "awg-uplink".to_owned();
        changed_egress.routing.rules[0].egress = "wg-server".to_owned();
        // Keep the old mark base: the same numeric mark would select a
        // different egress while both old and new policy rules are installed.
        changed_egress.validate().unwrap();
        assert!(current
            .validate_reload_compatibility(&changed_egress)
            .unwrap_err()
            .to_string()
            .contains("mark ranges to be disjoint"));
    }

    #[test]
    fn reload_compatibility_rejects_daemon_lifecycle_changes_but_allows_stats_interval() {
        let current = Config::parse_toml(&valid_config()).unwrap();

        let mut changed_table = current.clone();
        changed_table.daemon.nft_table = "other_table".to_owned();
        assert!(current
            .validate_reload_compatibility(&changed_table)
            .unwrap_err()
            .to_string()
            .contains("daemon.nft_table"));

        let mut changed_forwarding = current.clone();
        changed_forwarding.daemon.manage_ip_forwarding = !current.daemon.manage_ip_forwarding;
        assert!(current
            .validate_reload_compatibility(&changed_forwarding)
            .unwrap_err()
            .to_string()
            .contains("manage_ip_forwarding"));

        let mut changed_log_level = current.clone();
        changed_log_level.daemon.log_level = "debug".to_owned();
        assert!(current
            .validate_reload_compatibility(&changed_log_level)
            .unwrap_err()
            .to_string()
            .contains("daemon.log_level"));

        let ipv4_current = Config::parse_toml(&ipv4_config()).unwrap();
        let mut changed_ipv6_mode = ipv4_current.clone();
        changed_ipv6_mode.daemon.ipv6_enabled = false;
        changed_ipv6_mode.validate().unwrap();
        assert!(ipv4_current
            .validate_reload_compatibility(&changed_ipv6_mode)
            .unwrap_err()
            .to_string()
            .contains("daemon.ipv6_enabled"));

        let mut changed_stats_interval = current.clone();
        changed_stats_interval.daemon.stats_interval_secs += 1;
        changed_stats_interval.validate().unwrap();
        current
            .validate_reload_compatibility(&changed_stats_interval)
            .unwrap();
    }

    #[test]
    fn reload_compatibility_rejects_tunnel_identity_and_lifecycle_changes() {
        let current = Config::parse_toml(&valid_config()).unwrap();

        let changed_key = valid_config().replace(
            "private_key = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"",
            "private_key = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"",
        );
        let changed_key = Config::parse_toml(&changed_key).unwrap();
        assert!(current
            .validate_reload_compatibility(&changed_key)
            .unwrap_err()
            .to_string()
            .contains("immutable tunnel parameters"));

        let changed_awg = Config::parse_toml(&valid_config().replace("jc = 5", "jc = 6")).unwrap();
        assert!(current
            .validate_reload_compatibility(&changed_awg)
            .unwrap_err()
            .to_string()
            .contains("immutable tunnel parameters"));

        let changed_socket_mark = Config::parse_toml(
            &valid_config().replace("socket_fwmark = 4098", "socket_fwmark = 4099"),
        )
        .unwrap();
        assert!(current
            .validate_reload_compatibility(&changed_socket_mark)
            .unwrap_err()
            .to_string()
            .contains("immutable tunnel parameters"));

        let added_interface = Config::parse_toml(&format!(
            "{}\n[interfaces.extra]\ntype = \"wg\"\naddress = [\"10.30.0.1/24\"]\nprivate_key = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n",
            valid_config()
        )).unwrap();
        assert!(current
            .validate_reload_compatibility(&added_interface)
            .unwrap_err()
            .to_string()
            .contains("add or remove interfaces"));
    }

    #[test]
    fn reload_compatibility_rejects_interface_address_mtu_ipv6_and_listen_port_changes() {
        let current = Config::parse_toml(&valid_config()).unwrap();

        let mut changed_address = current.clone();
        changed_address
            .interfaces
            .get_mut("wg-server")
            .unwrap()
            .address = vec!["10.10.0.9/24".to_owned()];
        changed_address.validate().unwrap();
        assert!(current
            .validate_reload_compatibility(&changed_address)
            .unwrap_err()
            .to_string()
            .contains("immutable tunnel parameters"));

        let mut changed_mtu = current.clone();
        changed_mtu.interfaces.get_mut("wg-server").unwrap().mtu = 1400;
        changed_mtu.validate().unwrap();
        assert!(current
            .validate_reload_compatibility(&changed_mtu)
            .unwrap_err()
            .to_string()
            .contains("immutable tunnel parameters"));

        let mut changed_ipv6 = current.clone();
        changed_ipv6
            .interfaces
            .get_mut("wg-server")
            .unwrap()
            .ipv6_enabled = false;
        changed_ipv6.routing.rules.pop();
        changed_ipv6.validate().unwrap();
        assert!(current
            .validate_reload_compatibility(&changed_ipv6)
            .unwrap_err()
            .to_string()
            .contains("immutable tunnel parameters"));

        let mut changed_listen_port = current.clone();
        changed_listen_port
            .interfaces
            .get_mut("wg-server")
            .unwrap()
            .listen_port = Some(51822);
        changed_listen_port.validate().unwrap();
        assert!(current
            .validate_reload_compatibility(&changed_listen_port)
            .unwrap_err()
            .to_string()
            .contains("immutable tunnel parameters"));

        let mut changed_tunnel_type = current.clone();
        let awg_uplink = changed_tunnel_type
            .interfaces
            .get_mut("awg-uplink")
            .unwrap();
        awg_uplink.tunnel_type = TunnelType::WireGuard;
        awg_uplink.awg = None;
        changed_tunnel_type.validate().unwrap();
        assert!(current
            .validate_reload_compatibility(&changed_tunnel_type)
            .unwrap_err()
            .to_string()
            .contains("immutable tunnel parameters"));

        let mut removed_interface = current.clone();
        removed_interface.interfaces.remove("awg-uplink");
        removed_interface.routing.rules.clear();
        removed_interface.validate().unwrap();
        assert!(current
            .validate_reload_compatibility(&removed_interface)
            .unwrap_err()
            .to_string()
            .contains("add or remove interfaces"));
    }

    #[test]
    fn firewall_allow_rules_parse_and_validate() {
        let input = format!(
            "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nsource = [\"10.10.0.2/32\"]\nprotocol = \"tcp\"\nports = [22, 443]\n[firewall.output]\n[[firewall.output.rules]]\ninterface = \"awg-uplink\"\ndestination = \"0.0.0.0/0\"\nprotocol = \"udp\"\nports = [53]\n",
            valid_config()
        );
        let config = Config::parse_toml(&input).unwrap();
        assert_eq!(config.firewall.input.rules.len(), 1);
        assert_eq!(config.firewall.output.rules.len(), 1);
        assert_eq!(
            config.firewall.input.rules[0].protocol,
            Some(FirewallProtocol::Tcp)
        );
        assert_eq!(
            config.firewall.output.rules[0].ports.as_deref(),
            Some(&[53][..])
        );
    }

    #[test]
    fn firewall_rules_reject_unknown_interfaces_and_wrong_direction_selectors() {
        let unknown = format!(
            "{}\n[[firewall.input.rules]]\ninterface = \"missing\"\n",
            valid_config()
        );
        assert!(Config::parse_toml(&unknown).is_err());

        let wrong_direction = format!(
            "{}\n[[firewall.input.rules]]\ninterface = \"wg-server\"\ndestination = \"10.0.0.0/24\"\n",
            valid_config()
        );
        assert!(Config::parse_toml(&wrong_direction).is_err());
    }

    #[test]
    fn firewall_icmp_protocol_must_match_selector_address_family() {
        let icmp_v6_selector = format!(
            "{}\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nsource = [\"2001:db8::2/128\"]\nprotocol = \"icmp\"\n",
            ipv4_config().replace(
                "socket_fwmark = 4097",
                "socket_fwmark = 4097\nipv6_enabled = true",
            )
        );
        assert!(Config::parse_toml(&icmp_v6_selector)
            .unwrap_err()
            .to_string()
            .contains("icmp\" cannot be combined with IPv6"));

        let icmp_v4_selector = format!(
            "{}\n[[firewall.output.rules]]\ninterface = \"awg-uplink\"\ndestination = [\"10.0.0.0/24\"]\nprotocol = \"icmpv6\"\n",
            ipv4_config().replace(
                "socket_fwmark = 4098",
                "socket_fwmark = 4098\nipv6_enabled = true",
            )
        );
        assert!(Config::parse_toml(&icmp_v4_selector)
            .unwrap_err()
            .to_string()
            .contains("icmpv6\" cannot be combined with IPv4"));

        let disabled_icmpv6 = format!(
            "{}\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nprotocol = \"icmpv6\"\n",
            ipv4_config()
        );
        assert!(Config::parse_toml(&disabled_icmpv6)
            .unwrap_err()
            .to_string()
            .contains("icmpv6\" requires IPv6"));
    }

    #[test]
    fn routing_rule_resolves_nat_fields_into_a_typed_action() {
        let mut rule: RoutingRule = toml::from_str(
            r#"
                priority = 1
                ingress = "wg-server"
                egress = "awg-uplink"
            "#,
        )
        .unwrap();
        assert_eq!(rule.nat_action(), NatAction::None);

        rule.nat = NatMode::Masquerade;
        assert_eq!(rule.nat_action(), NatAction::Masquerade);

        rule.nat = NatMode::Snat;
        rule.nat_to = Some("203.0.113.9".parse().unwrap());
        assert_eq!(
            rule.nat_action(),
            NatAction::Snat("203.0.113.9".parse().unwrap())
        );
    }

    #[test]
    fn static_snat_requires_an_address_and_matching_enabled_family() {
        let missing_address = valid_config().replacen(
            "egress = \"awg-uplink\"",
            "egress = \"awg-uplink\"\nnat = \"snat\"",
            1,
        );
        assert!(Config::parse_toml(&missing_address).is_err());

        let valid_snat = valid_config().replacen(
            "egress = \"awg-uplink\"",
            "egress = \"awg-uplink\"\nnat = \"snat\"\nnat_to = \"203.0.113.9\"",
            1,
        );
        let parsed = Config::parse_toml(&valid_snat).unwrap();
        assert_eq!(parsed.routing.rules[0].nat, NatMode::Snat);
        assert_eq!(
            parsed.routing.rules[0].nat_to,
            Some("203.0.113.9".parse().unwrap())
        );

        let disabled_ipv6 = ipv4_config().replacen(
            "egress = \"awg-uplink\"",
            "egress = \"awg-uplink\"\nnat = \"snat\"\nnat_to = \"2001:db8::1\"",
            1,
        );
        assert!(Config::parse_toml(&disabled_ipv6).is_err());
    }

    #[test]
    fn static_snat_family_must_match_the_intersection_of_both_selectors() {
        let input = ipv4_config()
            .replace(
                "[interfaces.wg-server]",
                "[interfaces.wg-server]\nipv6_enabled = true",
            )
            .replace(
                "[interfaces.awg-uplink]",
                "[interfaces.awg-uplink]\nipv6_enabled = true",
            )
            .replacen(
                "destination = \"0.0.0.0/0\"",
                "source = [\"10.10.0.0/24\", \"2001:db8::/32\"]\ndestination = \"0.0.0.0/0\"\nnat = \"snat\"\nnat_to = \"2001:db8::10\"",
                1,
            );
        let error = Config::parse_toml(&input).unwrap_err();
        assert!(error
            .to_string()
            .contains("routing rule's selected source/destination family"));
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
    fn persistent_keepalive_range_is_validated_and_mutually_exclusive() {
        let ranged = valid_config().replace(
            "persistent_keepalive_secs = 25",
            "persistent_keepalive_secs = \"25-35\"",
        );
        let config = Config::parse_toml(&ranged).unwrap();
        assert_eq!(
            config.interfaces["awg-uplink"].peers[0].persistent_keepalive_secs,
            Some(PersistentKeepaliveConfig::Range("25-35".to_owned()))
        );

        for range in ["35-25", "0-25", "25-0", "1-2-3", "4294967296-4294967297"] {
            let input = valid_config().replace(
                "persistent_keepalive_secs = 25",
                &format!("persistent_keepalive_secs = \"{range}\""),
            );
            assert!(
                Config::parse_toml(&input).is_err(),
                "accepted range {range}"
            );
        }

        let fixed = Config::parse_toml(&valid_config()).unwrap();
        assert_eq!(
            fixed.interfaces["awg-uplink"].peers[0].persistent_keepalive_secs,
            Some(PersistentKeepaliveConfig::Seconds(25))
        );

        let both = valid_config().replace(
            "persistent_keepalive_secs = 25",
            "persistent_keepalive_secs = 25\npersistent_keepalive_range = [25, 35]",
        );
        assert!(Config::parse_toml(&both)
            .unwrap_err()
            .to_string()
            .contains("must not set both"));
    }

    #[test]
    fn configuration_uses_only_the_canonical_singular_address_key() {
        let input = valid_config().replace("address =", "addresses =");
        assert!(Config::parse_toml(&input).is_err());
    }

    #[test]
    fn config_selects_tunnel_family_without_exposing_awg_generation() {
        let config = Config::parse_toml(&valid_config()).unwrap();
        assert_eq!(
            config.interfaces["wg-server"].tunnel_type,
            TunnelType::WireGuard
        );
        assert_eq!(
            config.interfaces["awg-uplink"].tunnel_type,
            TunnelType::AmneziaWg
        );
    }

    #[test]
    fn parses_awg_30_and_31_extension_parameters() {
        let input = valid_config()
            .replace("s1 = 0", "s1 = 12")
            .replace("s2 = 0", "s2 = 12")
            .replace("s3 = 0", "s3 = 12")
            .replace("s4 = 0", "s4 = 12")
            .replace(
                "h4 = \"301-400\"",
                concat!(
                    "h4 = \"301-400\"\n",
                    "i1 = \"<b 0x4142><r 8>\"\n",
                    "i2 = \"<t>\"\n",
                    "i3 = \"<rc 4>\"\n",
                    "i4 = \"<rd 4>\"\n",
                    "i5 = \"<dz 2>\"\n",
                    "header_protection_key = \"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=\"\n",
                    "content_padding_addition = \"10-100\"\n",
                    "rekey_after_time = \"100-120\"\n",
                    "rekey_timeout = \"3-8\"\n",
                    "reject_after_time = \"150-180\"\n",
                    "keepalive_timeout = \"7-13\"\n",
                    "max_handshake_attempts = \"15-20\""
                ),
            );
        let config = Config::parse_toml(&input).unwrap();
        crate::backend::BackendRegistry::default()
            .validate_config(&config)
            .unwrap();
    }

    #[test]
    fn rejects_invalid_awg_extension_values() {
        for (field, value) in [
            ("header_protection_key", "\"abcd\""),
            (
                "header_protection_key",
                "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
            ),
            ("content_padding_addition", "\"100-10\""),
            ("rekey_timeout", "\"8-3\""),
            ("i1", "\"<unknown 2>\""),
        ] {
            let input = valid_config().replace(
                "h4 = \"301-400\"",
                &format!("h4 = \"301-400\"\n{} = {}", field, value),
            );
            let config = Config::parse_toml(&input).unwrap();
            assert!(
                crate::backend::BackendRegistry::default()
                    .validate_config(&config)
                    .is_err(),
                "{}",
                field
            );
        }
    }

    #[test]
    fn ipv6_is_blocked_by_default_on_every_interface() {
        let config = Config::parse_toml(&ipv4_config()).unwrap();
        assert!(config.daemon.ipv6_enabled);
        assert!(config
            .interfaces
            .values()
            .all(|interface| !interface.ipv6_enabled));
    }

    #[test]
    fn ipv6_can_be_enabled_independently_per_interface() {
        let input = ipv4_config()
            .replace(
                "socket_fwmark = 4097",
                "socket_fwmark = 4097\nipv6_enabled = true",
            )
            .replace(
                "socket_fwmark = 4098",
                "socket_fwmark = 4098\nipv6_enabled = false",
            );
        let config = Config::parse_toml(&input).unwrap();
        assert!(config.interfaces["wg-server"].ipv6_enabled);
        assert!(!config.interfaces["awg-uplink"].ipv6_enabled);
    }

    #[test]
    fn daemon_ipv4_only_mode_rejects_ipv6_configuration() {
        let input = ipv4_config().replace(
            "manage_ip_forwarding = false",
            "manage_ip_forwarding = false\nipv6_enabled = false",
        );
        let config = Config::parse_toml(&input).unwrap();
        assert!(!config.daemon.ipv6_enabled);

        let enabled_interface = input.replace(
            "socket_fwmark = 4097",
            "socket_fwmark = 4097\nipv6_enabled = true",
        );
        assert!(Config::parse_toml(&enabled_interface)
            .unwrap_err()
            .to_string()
            .contains("daemon.ipv6_enabled = false"));

        let ipv6_address = input.replace("10.10.0.1/24", "2001:db8::1/64");
        assert!(Config::parse_toml(&ipv6_address).is_err());

        let ipv6_endpoint = input.replace(
            "allowed_ips = [\"10.10.0.2/32\"]",
            "allowed_ips = [\"10.10.0.2/32\"]\nendpoint = \"[2001:db8::2]:51820\"",
        );
        assert!(Config::parse_toml(&ipv6_endpoint).is_err());

        let ipv6_allowed_ip = input.replace("10.10.0.2/32", "2001:db8::2/128");
        assert!(Config::parse_toml(&ipv6_allowed_ip).is_err());

        let ipv6_route_selector = input.replace(
            "destination = \"0.0.0.0/0\"",
            "destination = \"2001:db8::/32\"",
        );
        assert!(Config::parse_toml(&ipv6_route_selector).is_err());
    }

    #[test]
    fn parses_and_validates_a_complete_multi_tunnel_config() {
        let config = Config::parse_toml(&valid_config()).unwrap();
        assert_eq!(config.interfaces.len(), 2);
        assert_eq!(config.routing.rules.len(), 2);
        assert_eq!(
            config.interfaces["awg-uplink"].tunnel_type,
            TunnelType::AmneziaWg
        );
        assert!(config.interfaces.contains_key("wg-server"));
        assert_eq!(config.interfaces["wg-server"].peers.len(), 1);
        assert_eq!(config.interfaces["awg-uplink"].peers.len(), 1);
        assert_eq!(config.resolved_socket_fwmarks().unwrap(), vec![4098, 4097]);
    }

    #[test]
    fn shipped_example_configuration_parses_with_named_sections() {
        let config = Config::parse_toml(include_str!("../vpn-relay.example.toml")).unwrap();
        assert!(config.interfaces.contains_key("wg-server"));
        assert_eq!(config.interfaces["wg-server"].peers.len(), 1);
        assert_eq!(config.interfaces["awg-primary"].peers.len(), 1);
        assert_eq!(config.interfaces["awg-secondary"].peers.len(), 1);
    }

    #[test]
    fn named_interfaces_and_unnamed_peer_arrays_parse() {
        let config = Config::parse_toml(&valid_config()).unwrap();
        assert_eq!(
            config
                .interfaces
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["awg-uplink", "wg-server"]
        );
        assert_eq!(config.interfaces["wg-server"].peers.len(), 1);
        assert_eq!(config.interfaces["awg-uplink"].peers.len(), 1);
    }

    #[test]
    fn interfaces_without_peers_are_valid() {
        let input = valid_config()
            .replace(
                &format!(
                    "[[interfaces.wg-server.peers]]\npublic_key = \"{KEY}\"\nallowed_ips = [\"10.10.0.2/32\"]\n\n"
                ),
                "",
            )
            .replace(
                &format!(
                    "[[interfaces.awg-uplink.peers]]\npublic_key = \"{KEY}\"\nendpoint = \"198.51.100.10:51820\"\nallowed_ips = [\"0.0.0.0/0\", \"::/0\"]\npersistent_keepalive_secs = 25\n\n"
                ),
                "",
            );
        let config = Config::parse_toml(&input).unwrap();
        assert!(config
            .interfaces
            .values()
            .all(|interface| interface.peers.is_empty()));
    }

    #[test]
    fn rejects_duplicate_peer_public_keys_in_unnamed_peer_array() {
        let input = valid_config().replace(
            "[interfaces.awg-uplink]",
            &format!(
                "[[interfaces.wg-server.peers]]\npublic_key = \"{}\"\nallowed_ips = [\"10.10.0.3/32\"]\n\n[interfaces.awg-uplink]",
                KEY
            ),
        );
        let error = Config::parse_toml(&input).unwrap_err();
        assert!(error.to_string().contains("duplicate peer public keys"));
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
        assert_eq!(config.resolved_socket_fwmarks().unwrap(), vec![4096, 4097]);
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
        assert_eq!(config.resolved_socket_fwmarks().unwrap(), vec![4098, 4096]);
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
        let config = Config::parse_toml(&input).unwrap();
        let error = crate::backend::BackendRegistry::default()
            .validate_config(&config)
            .unwrap_err();
        assert!(
            error.to_string().contains("H1-H4 ranges"),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn rejects_more_routing_decisions_than_conntrack_mark_space_supports() {
        let mut config = Config::parse_toml(&valid_config()).unwrap();
        let template = config.routing.rules[0].clone();
        config
            .routing
            .rules
            .resize(MAX_ROUTING_DECISIONS + 1, template);

        let error = config.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("at most 4095 entries because conntrack decision marks"));
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
        let input = valid_config().replace("priority = 110", "priority = 100");
        // Duplicate priorities are scoped to an ingress. The validation
        // fixture has one ingress, so move the second rule to another valid
        // server interface before parsing.
        let input = input.replace(
            "[interfaces.awg-uplink]",
            "[interfaces.wg-backup]\ntype = \"wg\"\nipv6_enabled = true\naddress = [\"10.11.0.1/24\"]\nlisten_port = 51823\nprivate_key = \"{KEY}\"\nsocket_fwmark = 4100\n\n[interfaces.awg-uplink]",
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
    fn interfaces_can_be_used_in_both_routing_directions() {
        let input = valid_config().replace(
            "priority = 110\ningress = \"wg-server\"\ndestination = \"::/0\"\negress = \"awg-uplink\"",
            "priority = 110\ningress = \"wg-server\"\ndestination = \"::/0\"\negress = \"awg-uplink\"\n\n[[routing.rules]]\npriority = 120\ningress = \"awg-uplink\"\ndestination = \"10.0.0.0/24\"\negress = \"wg-server\""
        );
        let config = Config::parse_toml(&input).unwrap();
        assert_eq!(config.resolved_routing_fwmarks().unwrap().len(), 2);
    }

    #[test]
    fn routing_marks_are_allocated_only_for_distinct_configured_egresses() {
        let mut config = Config::parse_toml(&valid_config()).unwrap();
        config.routing.rules.truncate(1);
        assert_eq!(
            config.resolved_routing_fwmarks().unwrap(),
            vec![config.routing.mark_base]
        );
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

    #[test]
    fn rejects_duplicate_routing_cidr_selectors() {
        let duplicate_source = valid_config().replace(
            "destination = \"0.0.0.0/0\"",
            "source = [\"10.10.0.0/24\", \"10.10.0.0/24\"]\ndestination = \"0.0.0.0/0\"",
        );
        assert!(Config::parse_toml(&duplicate_source)
            .unwrap_err()
            .to_string()
            .contains("source must not contain duplicate CIDR selectors"));

        let duplicate_destination = valid_config().replace(
            "destination = \"0.0.0.0/0\"",
            "destination = [\"0.0.0.0/0\", \"0.0.0.0/0\"]",
        );
        assert!(Config::parse_toml(&duplicate_destination)
            .unwrap_err()
            .to_string()
            .contains("destination must not contain duplicate CIDR selectors"));
    }

    #[test]
    fn rejects_equivalent_cidr_networks_with_different_host_bits() {
        let source = valid_config().replace(
            "destination = \"0.0.0.0/0\"",
            "source = [\"10.10.0.0/24\", \"10.10.0.99/24\"]\ndestination = \"0.0.0.0/0\"",
        );
        assert!(Config::parse_toml(&source)
            .unwrap_err()
            .to_string()
            .contains("equivalent CIDR networks"));

        let destination = valid_config().replace(
            "destination = \"0.0.0.0/0\"",
            "destination = [\"2001:db8::/32\", \"2001:db8:abcd::1/32\"]",
        );
        assert!(Config::parse_toml(&destination)
            .unwrap_err()
            .to_string()
            .contains("equivalent CIDR networks"));
    }

    #[test]
    fn rejects_empty_firewall_selectors_and_unknown_interfaces() {
        let empty_input = format!(
            "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nsource = []\n",
            valid_config()
        );
        assert!(Config::parse_toml(&empty_input)
            .unwrap_err()
            .to_string()
            .contains("firewall.input.rules[0].source must not be an empty list"));

        let empty_output = format!(
            "{}\n[firewall.output]\n[[firewall.output.rules]]\ninterface = \"awg-uplink\"\ndestination = []\n",
            valid_config()
        );
        assert!(Config::parse_toml(&empty_output)
            .unwrap_err()
            .to_string()
            .contains("firewall.output.rules[0].destination must not be an empty list"));

        let unknown_interface = format!(
            "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-missing\"\n",
            valid_config()
        );
        assert!(Config::parse_toml(&unknown_interface)
            .unwrap_err()
            .to_string()
            .contains("firewall.input.rules[0] references unknown interface"));
    }

    #[test]
    fn rejects_empty_zero_and_non_transport_firewall_ports() {
        let empty_ports = format!(
            "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nprotocol = \"tcp\"\nports = []\n",
            valid_config()
        );
        assert!(Config::parse_toml(&empty_ports)
            .unwrap_err()
            .to_string()
            .contains("ports must contain one or more ports"));

        let zero_port = format!(
            "{}\n[firewall.output]\n[[firewall.output.rules]]\ninterface = \"awg-uplink\"\nprotocol = \"udp\"\nports = [0]\n",
            valid_config()
        );
        assert!(Config::parse_toml(&zero_port)
            .unwrap_err()
            .to_string()
            .contains("ports must contain one or more ports"));

        let icmp_ports = format!(
            "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nprotocol = \"icmp\"\nports = [53]\n",
            valid_config()
        );
        assert!(Config::parse_toml(&icmp_ports)
            .unwrap_err()
            .to_string()
            .contains("ports requires protocol"));
    }

    #[test]
    fn rejects_empty_routing_destination_list() {
        let input = valid_config().replace("destination = \"0.0.0.0/0\"", "destination = []");
        assert!(Config::parse_toml(&input)
            .unwrap_err()
            .to_string()
            .contains("routing.rules.destination must not be an empty list"));
    }

    #[test]
    fn rejects_duplicate_firewall_cidr_selectors() {
        let input = format!(
            "{}\n[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nsource = [\"10.10.0.0/24\", \"10.10.0.0/24\"]\n",
            valid_config()
        );
        assert!(Config::parse_toml(&input)
            .unwrap_err()
            .to_string()
            .contains("firewall.input.rules[0].source must not contain duplicate CIDR selectors"));
    }

    #[test]
    fn rejects_unknown_firewall_and_nat_rule_fields() {
        let unknown_nat = valid_config().replace(
            "destination = \"0.0.0.0/0\"",
            "destination = \"0.0.0.0/0\"\nnat = \"snat\"\nnat_to = \"203.0.113.9\"\nnat_target = \"203.0.113.10\"",
        );
        assert!(Config::parse_toml(&unknown_nat)
            .unwrap_err()
            .to_string()
            .contains("unknown field"));

        let unknown_firewall = valid_config().replacen(
            "[[routing.rules]]",
            "[firewall.input]\n[[firewall.input.rules]]\ninterface = \"wg-server\"\nprotocol = \"tcp\"\nports = [22]\nallow_all = true\n\n[[routing.rules]]",
            1,
        );
        assert!(Config::parse_toml(&unknown_firewall)
            .unwrap_err()
            .to_string()
            .contains("unknown field"));
    }
}
