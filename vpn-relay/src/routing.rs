//! Pure routing-plan generation for the Linux daemon.
//!
//! This module deliberately does not execute privileged commands. It turns a
//! validated TOML configuration into deterministic nftables and policy-routing
//! operations; the runtime layer can apply these operations transactionally.

use crate::config::{Config, FirewallProtocol, FirewallRule, NatAction, NatMode};
use std::collections::BTreeMap;

pub(crate) const FIRST_ROUTING_TABLE: u32 = 10_000;
pub(crate) const FIRST_IP_RULE_PRIORITY: u32 = 10_000;
const SOCKET_MAIN_RULE_PRIORITY: u32 = 9_000;
// vpn-relay owns the high 16 bits of ct mark for routing decision identity
// and managed host-flow authorization; the low 16 bits remain host policy/QoS.
const CONNTRACK_MARK_MASK: u32 = 0xffff_0000;
const CONNTRACK_MARK_PRESERVE_MASK: u32 = !CONNTRACK_MARK_MASK;
// A new namespace prevents pre-state-file conntrack entries from being reinterpreted after upgrade.
const FIRST_CONNTRACK_MARK: u32 = 0x5000_0000;
const LEGACY_CONNTRACK_MARK: u32 = 0x4000_0000;
const LOCAL_FLOW_CONNTRACK_MARK: u32 = 0x8000_0000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressPlan {
    pub interface: String,
    pub mark: u32,
    pub table_id: u32,
    pub ip_rule_priority: u32,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct RoutingDecision {
    pub priority: u32,
    pub ingress: String,
    pub source: Option<Vec<String>>,
    pub destination: Option<Vec<String>>,
    pub egress: String,
    pub routing_mark: u32,
    /// Unique decision id persisted in conntrack for reverse filtering and NAT.
    pub conntrack_mark: u32,
    pub nat: NatMode,
    pub nat_to: Option<std::net::Ipv4Addr>,
}

impl RoutingDecision {
    /// Resolve persisted routing-decision fields into one exhaustive NAT action.
    fn nat_action(&self) -> NatAction {
        match self.nat {
            NatMode::None => NatAction::None,
            NatMode::Masquerade => NatAction::Masquerade,
            NatMode::Snat => NatAction::Snat(
                self.nat_to
                    .expect("validated SNAT routing decision must contain nat_to"),
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NftFirewallRule {
    pub interface: String,
    pub source: Option<Vec<String>>,
    pub destination: Option<Vec<String>>,
    pub protocol: Option<FirewallProtocol>,
    pub ports: Option<Vec<u16>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingPlan {
    pub nft_family: String,
    pub nft_table: String,
    pub managed_interfaces: Vec<String>,
    pub egresses: Vec<EgressPlan>,
    pub decisions: Vec<RoutingDecision>,
    /// Explicit INPUT exceptions; all other managed ingress is denied.
    pub input_rules: Vec<NftFirewallRule>,
    /// Explicit OUTPUT exceptions; all other managed egress is denied.
    pub output_rules: Vec<NftFirewallRule>,
    /// Socket marks that force outer encrypted UDP through the main table.
    pub socket_marks: Vec<u32>,
    /// TUN interfaces on which inner IPv6 traffic is blocked.
    pub ipv6_drop_interfaces: Vec<String>,
    /// Kernel interface indices captured from the original TUN descriptors.
    pub interface_indices: Option<BTreeMap<String, u32>>,
}

impl RoutingPlan {
    /// Assign decision marks without reusing an ID that may still exist in
    /// conntrack. The history is persisted for the lifetime of the network
    /// namespace, so a daemon restart with a changed config cannot reinterpret
    /// old conntrack entries as a different routing decision.
    pub(crate) fn assign_stable_conntrack_marks(
        &mut self,
        history: &mut Vec<RoutingDecision>,
    ) -> Result<(), String> {
        Self::validate_conntrack_mark_history(history)?;

        let mut used_marks: std::collections::BTreeSet<u32> = history
            .iter()
            .map(|decision| decision.conntrack_mark)
            .collect();

        for decision in &mut self.decisions {
            let mut key = decision.clone();
            key.conntrack_mark = 0;
            // Routing marks are implementation details of the current policy
            // routing table allocation. Keep the conntrack decision identity
            // stable when mark_base changes so established flows can be
            // remapped by the new nftables prerouting rules without losing
            // their decision during an atomic policy switch.
            key.routing_mark = 0;
            let existing_mark = history.iter().find_map(|previous| {
                let mut previous_key = previous.clone();
                previous_key.conntrack_mark = 0;
                previous_key.routing_mark = 0;
                (previous_key == key).then_some(previous.conntrack_mark)
            });

            if let Some(mark) = existing_mark {
                decision.conntrack_mark = mark;
                continue;
            }

            let (_id, mark) = (1..=0x0fff)
                .map(|id| (id, FIRST_CONNTRACK_MARK | (id << 16)))
                .find(|(_, mark)| !used_marks.contains(mark))
                .ok_or_else(|| {
                    "all 4095 vpn-relay conntrack decision IDs are reserved; existing conntrack entries must expire before new routing decisions can be added"
                        .to_owned()
                })?;
            used_marks.insert(mark);
            decision.conntrack_mark = mark;
            history.push(decision.clone());
        }

        Ok(())
    }

    /// Reject corrupted or ambiguous persisted history instead of risking
    /// reuse of a mark that could still identify an older connection.
    pub(crate) fn validate_conntrack_mark_history(
        history: &[RoutingDecision],
    ) -> Result<(), String> {
        let mut used_marks = std::collections::BTreeSet::new();
        let mut keys = Vec::with_capacity(history.len());

        for decision in history {
            let mark = decision.conntrack_mark;
            let id = (mark & 0x0fff_0000) >> 16;
            let namespace = mark & 0xf000_0000;
            if (namespace != FIRST_CONNTRACK_MARK && namespace != LEGACY_CONNTRACK_MARK)
                || mark & 0x0000_ffff != 0
                || id == 0
                || id > 0x0fff
                || !used_marks.insert(mark)
            {
                return Err(format!(
                    "invalid or duplicate persisted conntrack decision mark 0x{mark:08x}"
                ));
            }

            // Older versions allocated a new conntrack ID when routing
            // mark_base changed. Preserve compatibility with those valid
            // historical aliases: only an exact decision duplicate (including
            // its routing mark) is ambiguous. The active plan still reuses the
            // first matching conntrack ID independent of routing_mark.
            let mut key = decision.clone();
            key.conntrack_mark = 0;
            if keys.contains(&key) {
                return Err("duplicate persisted conntrack decision identity".to_owned());
            }
            keys.push(key);
        }

        Ok(())
    }

    /// Build a deterministic plan from a fully validated configuration.
    pub fn from_config(config: &Config) -> Self {
        let egress_names: Vec<_> = config
            .interfaces
            .keys()
            .filter(|name| {
                config
                    .routing
                    .rules
                    .iter()
                    .any(|rule| &rule.egress == *name)
            })
            .map(String::as_str)
            .collect();
        let routing_marks = config
            .resolved_routing_fwmarks()
            .expect("RoutingPlan::from_config requires a validated configuration");
        let egresses: Vec<_> = egress_names
            .iter()
            .enumerate()
            .map(|(index, name)| EgressPlan {
                interface: (*name).to_owned(),
                mark: routing_marks[index],
                table_id: FIRST_ROUTING_TABLE + index as u32,
                ip_rule_priority: FIRST_IP_RULE_PRIORITY + index as u32,
            })
            .collect();

        let egress_marks: BTreeMap<_, _> = egresses
            .iter()
            .map(|egress| (egress.interface.as_str(), egress.mark))
            .collect();

        let mut decisions: Vec<_> = config
            .routing
            .rules
            .iter()
            .map(|rule| RoutingDecision {
                priority: rule.priority,
                ingress: rule.ingress.clone(),
                source: rule.source.clone(),
                destination: rule.destination.clone(),
                egress: rule.egress.clone(),
                routing_mark: egress_marks[rule.egress.as_str()],
                conntrack_mark: 0,
                nat: rule.nat,
                nat_to: rule.nat_to,
            })
            .collect();
        decisions.sort_by(|left, right| {
            left.ingress
                .cmp(&right.ingress)
                .then(left.priority.cmp(&right.priority))
        });
        // Persist the exact selected rule in conntrack. Decisions sharing an
        // egress still need distinct identifiers when their NAT differs.
        for (index, decision) in decisions.iter_mut().enumerate() {
            let decision_id = u32::try_from(index + 1)
                .expect("validated routing decision count must fit in a conntrack mark");
            decision.conntrack_mark = FIRST_CONNTRACK_MARK | (decision_id << 16);
        }

        let to_firewall_rule = |rule: &FirewallRule| NftFirewallRule {
            interface: rule.interface.clone(),
            source: rule.source.clone(),
            destination: rule.destination.clone(),
            protocol: rule.protocol,
            ports: rule.ports.clone(),
        };
        let input_rules = config
            .firewall
            .input
            .rules
            .iter()
            .map(to_firewall_rule)
            .collect();
        let output_rules = config
            .firewall
            .output
            .rules
            .iter()
            .map(to_firewall_rule)
            .collect();

        let mut socket_marks = config
            .resolved_socket_fwmarks()
            .expect("RoutingPlan::from_config requires a validated configuration");
        socket_marks.sort_unstable();

        let managed_interfaces: Vec<_> = config.interfaces.keys().cloned().collect();
        // IPv6 is unsupported by vpn-relay. Keep only a per-TUN drop guard;
        // do not apply IPv6 policy to BoringTun's outer UDP sockets.
        let ipv6_drop_interfaces: Vec<_> = config.interfaces.keys().cloned().collect();

        Self {
            nft_family: "inet".to_owned(),
            nft_table: config.daemon.nft_table.clone(),
            managed_interfaces,
            egresses,
            decisions,
            input_rules,
            output_rules,
            socket_marks,
            ipv6_drop_interfaces,
            interface_indices: None,
        }
    }

    /// Build a drop-only policy for the startup window before TUN descriptors
    /// and their kernel interface indices have been established.
    pub fn fail_closed_bootstrap(&self) -> Self {
        let mut bootstrap = self.clone();
        bootstrap.decisions.clear();
        bootstrap.input_rules.clear();
        bootstrap.output_rules.clear();
        bootstrap
    }

    /// Bind firewall selectors to the kernel identities of the original interfaces.
    pub fn bind_interface_indices(&mut self, indices: BTreeMap<String, u32>) -> Result<(), String> {
        if indices.len() != self.managed_interfaces.len()
            || self
                .managed_interfaces
                .iter()
                .any(|name| indices.get(name).is_none_or(|index| *index == 0))
        {
            return Err("interface index map does not cover all managed interfaces".into());
        }
        let unique: std::collections::BTreeSet<_> = indices.values().copied().collect();
        if unique.len() != indices.len() {
            return Err("two managed interfaces resolved to the same kernel index".into());
        }
        self.interface_indices = Some(indices);
        Ok(())
    }

    /// vpn-relay owns IPv4 policy routing only.
    pub fn ip_families_for_egress(&self, _egress: &EgressPlan) -> &'static [&'static str] {
        &["-4"]
    }

    pub fn ip_policy_families(&self) -> &'static [&'static str] {
        &["-4"]
    }

    pub fn ip_families(_egress: &EgressPlan) -> &'static [&'static str] {
        &["-4"]
    }

    /// Render a fail-closed transit policy. New flows require an explicit
    /// ingress/egress rule and any configured IP selectors; conntrack permits
    /// only their replies. Unmatched packets entering or leaving a managed TUN
    /// are dropped.
    pub fn nft_script(&self) -> String {
        let interfaces = self
            .managed_interfaces
            .iter()
            .map(|interface| format!("\"{}\"", interface))
            .collect::<Vec<_>>()
            .join(", ");

        let mut output = format!(
            "add table {} {} {{ comment \"managed by vpn-relay\"; }}\n\
             add set {} {} managed_interfaces {{ type ifname; elements = {{ {} }}; }}\n\
             add chain {} {} prerouting {{ type filter hook prerouting priority mangle; policy accept; }}\n\
             add chain {} {} input {{ type filter hook input priority filter; policy accept; }}\n\
             add chain {} {} forward {{ type filter hook forward priority filter; policy accept; }}\n\
             add chain {} {} output {{ type filter hook output priority filter; policy accept; }}\n\
             add chain {} {} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n",
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table, interfaces,
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table
        );

        if !self.ipv6_drop_interfaces.is_empty() {
            let (set_type, elements, input_selector, output_selector) =
                if let Some(indices) = &self.interface_indices {
                    let elements = self
                        .ipv6_drop_interfaces
                        .iter()
                        .filter_map(|name| indices.get(name))
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    ("iface_index", elements, "iif", "oif")
                } else {
                    let elements = self
                        .ipv6_drop_interfaces
                        .iter()
                        .map(|name| format!("\"{}\"", name))
                        .collect::<Vec<_>>()
                        .join(", ");
                    ("ifname", elements, "iifname", "oifname")
                };
            output.push_str(&format!(
                "add set {} {} ipv6_drop_interfaces {{ type {}; elements = {{ {} }}; }}\n",
                self.nft_family, self.nft_table, set_type, elements
            ));
            output.push_str(&format!(
                "add rule {} {} prerouting {} @ipv6_drop_interfaces meta nfproto ipv6 drop\n",
                self.nft_family, self.nft_table, input_selector
            ));
            output.push_str(&format!(
                "add rule {} {} forward {} @ipv6_drop_interfaces meta nfproto ipv6 drop\n",
                self.nft_family, self.nft_table, output_selector
            ));
            output.push_str(&format!(
                "add rule {} {} output {} @ipv6_drop_interfaces meta nfproto ipv6 counter drop\n",
                self.nft_family, self.nft_table, output_selector
            ));
        }

        // Invalid conntrack state must never reach an explicit allow rule.
        // Keep the drop scoped to managed ingress so unrelated host traffic
        // remains outside vpn-relay's firewall ownership.
        output.push_str(&format!(
            "add rule {} {} input iifname @managed_interfaces ct state invalid drop\n",
            self.nft_family, self.nft_table
        ));
        // INPUT is scoped to managed ingress. Explicit allow rules admit
        // original-direction client traffic and tag the conntrack entry. The
        // tag prevents unrelated host-initiated flows from being accepted as
        // replies merely because conntrack reports an established state.
        for rule in &self.input_rules {
            for (family, sources, _) in firewall_rule_family_variants(rule, true) {
                let mut selectors = format!("iifname \"{}\"", rule.interface);
                if let Some(family) = family {
                    if sources.is_empty() {
                        selectors.push_str(" meta nfproto ipv4");
                    }
                    append_cidr_selector(&mut selectors, family, "saddr", &sources);
                }
                append_firewall_protocol_selector(&mut selectors, rule);
                output.push_str(&format!(
                    "add rule {} {} input {} ct state new,established,related ct direction original ct mark set (ct mark & 0x{:08x}) | 0x{:08x} accept\n",
                    self.nft_family,
                    self.nft_table,
                    selectors,
                    CONNTRACK_MARK_PRESERVE_MASK,
                    LOCAL_FLOW_CONNTRACK_MARK
                ));
            }
        }
        // Only replies to explicitly admitted host-initiated flows may enter
        // through managed interfaces without a separate INPUT allow rule.
        output.push_str(&format!(
            "add rule {} {} input iifname @managed_interfaces ct state established,related ct direction reply ct mark & 0x{:08x} == 0x{:08x} accept\n",
            self.nft_family,
            self.nft_table,
            CONNTRACK_MARK_MASK,
            LOCAL_FLOW_CONNTRACK_MARK
        ));
        output.push_str(&format!(
            "add rule {} {} input iifname @managed_interfaces drop\n",
            self.nft_family, self.nft_table
        ));

        // Invalid conntrack state must not be admitted by a broad protocol
        // or address allow rule on a managed TUN egress.
        output.push_str(&format!(
            "add rule {} {} output oifname @managed_interfaces ct state invalid drop\n",
            self.nft_family, self.nft_table
        ));
        // OUTPUT is scoped to the actual managed TUN egress. Socket-marked
        // outer UDP routed through the underlay is therefore unaffected.
        for rule in &self.output_rules {
            for (family, _, destinations) in firewall_rule_family_variants(rule, false) {
                let mut selectors = format!("oifname \"{}\"", rule.interface);
                if let Some(family) = family {
                    if destinations.is_empty() {
                        selectors.push_str(" meta nfproto ipv4");
                    }
                    append_cidr_selector(&mut selectors, family, "daddr", &destinations);
                }
                append_firewall_protocol_selector(&mut selectors, rule);
                output.push_str(&format!(
                    "add rule {} {} output {} ct state new,established,related ct direction original ct mark set (ct mark & 0x{:08x}) | 0x{:08x} accept\n",
                    self.nft_family,
                    self.nft_table,
                    selectors,
                    CONNTRACK_MARK_PRESERVE_MASK,
                    LOCAL_FLOW_CONNTRACK_MARK
                ));
            }
        }
        // Permit replies to client-initiated flows only after INPUT admitted
        // their original-direction packets and tagged the conntrack entry.
        output.push_str(&format!(
            "add rule {} {} output oifname @managed_interfaces ct state established,related ct direction reply ct mark & 0x{:08x} == 0x{:08x} accept\n",
            self.nft_family,
            self.nft_table,
            CONNTRACK_MARK_MASK,
            LOCAL_FLOW_CONNTRACK_MARK
        ));
        output.push_str(&format!(
            "add rule {} {} output oifname @managed_interfaces drop\n",
            self.nft_family, self.nft_table
        ));

        // The reply direction must use the main table to reach the ingress TUN.
        // Original-direction packets restore the egress mark saved on the first
        // packet of the connection.
        output.push_str(&format!(
            "add rule {} {} prerouting iifname @managed_interfaces meta mark set 0\n\
             add rule {} {} prerouting iifname @managed_interfaces ct state established,related ct direction reply meta mark set 0 return\n",
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table
        ));
        for decision in &self.decisions {
            output.push_str(&format!(
                "add rule {} {} prerouting iifname @managed_interfaces ct state established,related ct direction original ct mark & 0x{:08x} == 0x{:08x} meta mark set 0x{:x} return\n",
                self.nft_family, self.nft_table, CONNTRACK_MARK_MASK, decision.conntrack_mark, decision.routing_mark
            ));
        }

        for rule in &self.decisions {
            for (family, sources, destinations) in rule_family_variants(rule) {
                let mut selectors = format!("iifname \"{}\" ct state new", rule.ingress);
                if let Some(family) = family {
                    if sources.is_empty() && destinations.is_empty() {
                        selectors.push_str(" meta nfproto ipv4");
                    }
                    append_cidr_selector(&mut selectors, family, "saddr", &sources);
                    append_cidr_selector(&mut selectors, family, "daddr", &destinations);
                }
                output.push_str(&format!(
                    "add rule {} {} prerouting {} meta mark set 0x{:x} ct mark set (ct mark & 0x{:08x}) | 0x{:08x} return\n",
                    self.nft_family,
                    self.nft_table,
                    selectors,
                    rule.routing_mark,
                    CONNTRACK_MARK_PRESERVE_MASK,
                    rule.conntrack_mark
                ));
            }
        }

        output.push_str(&format!(
            "add rule {} {} forward iifname @managed_interfaces ct state invalid drop\n",
            self.nft_family, self.nft_table
        ));
        for rule in &self.decisions {
            output.push_str(&format!(
                "add rule {} {} forward iifname \"{}\" oifname \"{}\" ct state new,established,related meta mark 0x{:x} accept\n",
                self.nft_family, self.nft_table, rule.ingress, rule.egress, rule.routing_mark
            ));
        }
        for rule in &self.decisions {
            output.push_str(&format!(
                "add rule {} {} forward iifname \"{}\" oifname \"{}\" ct state established,related ct mark & 0x{:08x} == 0x{:08x} accept\n",
                self.nft_family, self.nft_table, rule.egress, rule.ingress, CONNTRACK_MARK_MASK, rule.conntrack_mark
            ));
        }
        output.push_str(&format!(
            "add rule {} {} forward iifname @managed_interfaces drop\n\
             add rule {} {} forward oifname @managed_interfaces drop\n",
            self.nft_family, self.nft_table, self.nft_family, self.nft_table
        ));

        // NAT consumes the selected decision id from conntrack instead of
        // repeating selector matching and risking a different overlapping rule.
        for rule in &self.decisions {
            let family_guard = " meta nfproto ipv4";
            let selector = format!(
                "iifname \"{}\" oifname \"{}\" ct mark & 0x{:08x} == 0x{:08x}{}",
                rule.ingress, rule.egress, CONNTRACK_MARK_MASK, rule.conntrack_mark, family_guard
            );
            match rule.nat_action() {
                NatAction::None => output.push_str(&format!(
                    "add rule {} {} postrouting {} return\n",
                    self.nft_family, self.nft_table, selector
                )),
                NatAction::Masquerade => output.push_str(&format!(
                    "add rule {} {} postrouting {} masquerade\n",
                    self.nft_family, self.nft_table, selector
                )),
                NatAction::Snat(address) => {
                    output.push_str(&format!(
                        "add rule {} {} postrouting {} snat ip to {}\n",
                        self.nft_family, self.nft_table, selector, address
                    ));
                }
            }
        }

        if let Some(indices) = &self.interface_indices {
            // Translate every name-based selector and set element only after
            // the runtime has resolved indices from verified TUN descriptors.
            for (name, index) in indices {
                output = output.replace(&format!("\"{name}\""), &index.to_string());
            }
            output = output
                .replace("type ifname;", "type iface_index;")
                .replace("iifname @managed_interfaces", "iif @managed_interfaces")
                .replace("oifname @managed_interfaces", "oif @managed_interfaces")
                .replace("iifname @ipv6_drop_interfaces", "iif @ipv6_drop_interfaces")
                .replace("oifname @ipv6_drop_interfaces", "oif @ipv6_drop_interfaces")
                .replace("iifname", "iif")
                .replace("oifname", "oif");

            // A same-name replacement has a different ifindex and must be
            // explicitly dropped, not merely omitted from the numeric sets.
            // These guards run before every configured allow/drop decision.
            let mut guards = String::new();
            for (name, index) in indices {
                guards.push_str(&format!(
                    "add rule {} {} prerouting iifname \"{}\" iif != {} counter drop\n\
                     add rule {} {} input iifname \"{}\" iif != {} counter drop\n\
                     add rule {} {} forward iifname \"{}\" iif != {} counter drop\n\
                     add rule {} {} forward oifname \"{}\" oif != {} counter drop\n\
                     add rule {} {} output oifname \"{}\" oif != {} counter drop\n",
                    self.nft_family,
                    self.nft_table,
                    name,
                    index,
                    self.nft_family,
                    self.nft_table,
                    name,
                    index,
                    self.nft_family,
                    self.nft_table,
                    name,
                    index,
                    self.nft_family,
                    self.nft_table,
                    name,
                    index,
                    self.nft_family,
                    self.nft_table,
                    name,
                    index,
                ));
            }
            let first_rule = output.find("add rule ").unwrap_or(output.len());
            output.insert_str(first_rule, &guards);
        }
        output
    }

    /// Commands needed to populate egress tables and select them by packet
    /// mark. Socket marks explicitly use the main table to avoid tunnel loops.
    pub fn ip_commands(&self) -> Vec<Vec<String>> {
        let mut commands =
            Vec::with_capacity(self.egresses.len() * 4 + self.socket_marks.len() * 2);
        for mark in &self.socket_marks {
            let families: &[&str] = &["-4"];
            for &family in families {
                commands.push(vec![
                    family.into(),
                    "rule".into(),
                    "add".into(),
                    "priority".into(),
                    SOCKET_MAIN_RULE_PRIORITY.to_string(),
                    "fwmark".into(),
                    format!("0x{:x}", mark),
                    "lookup".into(),
                    "main".into(),
                ]);
            }
        }
        for egress in &self.egresses {
            for &family in self.ip_families_for_egress(egress) {
                commands.push(vec![
                    family.into(),
                    "route".into(),
                    "replace".into(),
                    "default".into(),
                    "dev".into(),
                    egress.interface.clone(),
                    "table".into(),
                    egress.table_id.to_string(),
                ]);
                commands.push(vec![
                    family.into(),
                    "rule".into(),
                    "add".into(),
                    "priority".into(),
                    egress.ip_rule_priority.to_string(),
                    "fwmark".into(),
                    format!("0x{:x}", egress.mark),
                    "lookup".into(),
                    egress.table_id.to_string(),
                ]);
            }
        }
        commands
    }
}

fn firewall_rule_family_variants(
    rule: &NftFirewallRule,
    input: bool,
) -> Vec<(Option<&'static str>, Vec<String>, Vec<String>)> {
    let prefixes = if input {
        rule.source.as_ref()
    } else {
        rule.destination.as_ref()
    };
    let Some(prefixes) = prefixes else {
        return vec![(Some("ip"), Vec::new(), Vec::new())];
    };
    prefixes
        .iter()
        .map(|prefix| nft_family_match(prefix))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|family| {
            let selected = prefixes
                .iter()
                .filter(|prefix| nft_family_match(prefix) == family)
                .cloned()
                .collect::<Vec<_>>();
            if input {
                (Some(family), selected, Vec::new())
            } else {
                (Some(family), Vec::new(), selected)
            }
        })
        .collect()
}

fn append_firewall_protocol_selector(selectors: &mut String, rule: &NftFirewallRule) {
    if let Some(protocol) = rule.protocol {
        selectors.push_str(match protocol {
            FirewallProtocol::Tcp if rule.ports.is_some() => " tcp",
            FirewallProtocol::Tcp => " meta l4proto tcp",
            FirewallProtocol::Udp if rule.ports.is_some() => " udp",
            FirewallProtocol::Udp => " meta l4proto udp",
            FirewallProtocol::Icmp => " meta l4proto icmp",
        });
    }
    if let Some(ports) = &rule.ports {
        let ports = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        selectors.push_str(&format!(" dport {{ {ports} }}"));
    }
}

fn nft_family_match(prefix: &str) -> &'static str {
    let _ = prefix;
    "ip"
}

fn rule_family_variants(
    rule: &RoutingDecision,
) -> Vec<(Option<&'static str>, Vec<String>, Vec<String>)> {
    let sources = rule.source.clone().unwrap_or_default();
    let destinations = rule.destination.clone().unwrap_or_default();
    vec![(Some("ip"), sources, destinations)]
}

fn append_cidr_selector(
    selectors: &mut String,
    family: &str,
    direction: &str,
    prefixes: &[String],
) {
    if prefixes.is_empty() {
        return;
    }
    if prefixes.len() == 1 {
        selectors.push_str(&format!(" {} {} {}", family, direction, prefixes[0]));
    } else {
        selectors.push_str(&format!(
            " {} {} {{ {} }}",
            family,
            direction,
            prefixes.join(", ")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn sample_config() -> Config {
        let toml = format!(
            r#"
[interfaces.wg-server]
type = "wg"
address = ["10.0.0.1/24"]
listen_port = 51820
private_key = "{KEY}"
socket_fwmark = 4097

[interfaces.awg-primary]
type = "awg"
address = ["10.1.0.2/32"]
listen_port = 51821
private_key = "{KEY}"
socket_fwmark = 4098

[interfaces.awg-secondary]
type = "awg"
address = ["10.2.0.2/32"]
listen_port = 51822
private_key = "{KEY}"
socket_fwmark = 4099

[[routing.rules]]
priority = 10
ingress = "wg-server"
destination = "195.142.0.0/16"
egress = "awg-secondary"

[[routing.rules]]
priority = 20
ingress = "wg-server"
destination = "79.100.22.0/24"
egress = "awg-secondary"

[[routing.rules]]
priority = 100
ingress = "wg-server"
destination = "0.0.0.0/0"
egress = "awg-primary"
"#
        );
        Config::parse_toml(&toml).unwrap()
    }

    #[test]
    fn ipv4_only_mode_blocks_ipv6_only_on_managed_tun_interfaces() {
        let mut config = sample_config();
        let plan = RoutingPlan::from_config(&config);
        let commands = plan.ip_commands();
        assert!(commands
            .iter()
            .all(|command| command.first().is_some_and(|family| family == "-4")));
        assert!(!commands
            .iter()
            .any(|command| command.first().is_some_and(|family| family == "-6")));

        let script = plan.nft_script();
        assert!(!script.contains("socket_fwmarks"));
        assert!(!script.contains("socket mark @socket_fwmarks drop"));
        assert!(!script.contains("meta mark @socket_fwmarks drop"));
        assert!(script.contains("prerouting iifname @ipv6_drop_interfaces meta nfproto ipv6 drop"));
        assert!(!script.contains("snat ip6"));
    }

    #[test]
    fn ipv4_only_selector_free_routing_firewall_and_masquerade_are_family_limited() {
        let mut config = sample_config();
        config.routing.rules[0].source = None;
        config.routing.rules[0].destination = None;
        config.routing.rules[0].nat = NatMode::Masquerade;
        config.firewall.input.rules.push(FirewallRule {
            interface: "wg-server".to_owned(),
            source: None,
            destination: None,
            protocol: Some(FirewallProtocol::Tcp),
            ports: Some(vec![22]),
        });
        config.firewall.output.rules.push(FirewallRule {
            interface: "awg-secondary".to_owned(),
            source: None,
            destination: None,
            protocol: Some(FirewallProtocol::Udp),
            ports: Some(vec![53]),
        });

        let script = RoutingPlan::from_config(&config).nft_script();
        assert!(script
            .contains("prerouting iifname \"wg-server\" ct state new meta nfproto ipv4 meta mark"));
        assert!(script.contains("input iifname \"wg-server\" meta nfproto ipv4 tcp dport { 22 }"));
        assert!(
            script.contains("output oifname \"awg-secondary\" meta nfproto ipv4 udp dport { 53 }")
        );
        assert!(script.contains("postrouting iifname \"wg-server\" oifname \"awg-secondary\""));
        assert!(script.contains("meta nfproto ipv4 masquerade"));
        assert!(!script.contains("meta nfproto ipv6 masquerade"));
        assert!(script
            .lines()
            .filter(|line| line.starts_with("add rule inet vpn_relay postrouting"))
            .all(|line| line.contains("meta nfproto ipv4")));
    }

    #[test]
    fn managed_input_and_output_default_to_deny_with_explicit_allow_exceptions() {
        let mut config = sample_config();
        config.firewall.input.rules.push(FirewallRule {
            interface: "wg-server".to_owned(),
            source: Some(vec!["10.0.0.2/32".to_owned()]),
            destination: None,
            protocol: Some(FirewallProtocol::Tcp),
            ports: Some(vec![22, 443]),
        });
        config.firewall.output.rules.push(FirewallRule {
            interface: "awg-primary".to_owned(),
            source: None,
            destination: Some(vec!["10.0.0.0/24".to_owned()]),
            protocol: Some(FirewallProtocol::Udp),
            ports: Some(vec![53]),
        });

        let script = RoutingPlan::from_config(&config).nft_script();
        assert!(script.contains("input iifname \"wg-server\" ip saddr 10.0.0.2/32 tcp dport { 22, 443 } ct state new,established,related ct direction original ct mark set (ct mark & 0x0000ffff) | 0x80000000 accept"));
        assert!(script.contains("input iifname @managed_interfaces ct state invalid drop"));
        assert!(script.contains("output oifname @managed_interfaces ct state invalid drop"));
        assert!(script.contains("input iifname @managed_interfaces ct state established,related ct direction reply ct mark & 0xffff0000 == 0x80000000 accept"));
        assert!(script.contains("input iifname @managed_interfaces drop"));
        assert!(script.contains("output oifname \"awg-primary\" ip daddr 10.0.0.0/24 udp dport { 53 } ct state new,established,related ct direction original ct mark set (ct mark & 0x0000ffff) | 0x80000000 accept"));
        assert!(script.contains("output oifname @managed_interfaces ct state established,related ct direction reply ct mark & 0xffff0000 == 0x80000000 accept"));
        assert!(script.contains("output oifname @managed_interfaces drop"));
        assert!(script.contains("forward iifname @managed_interfaces drop"));
    }

    #[test]
    fn icmp_firewall_rules_use_valid_l4_protocol_selectors() {
        let mut config = sample_config();
        config.firewall.input.rules.push(FirewallRule {
            interface: "wg-server".to_owned(),
            source: Some(vec!["10.0.0.2/32".to_owned()]),
            destination: None,
            protocol: Some(FirewallProtocol::Icmp),
            ports: None,
        });
        config.firewall.output.rules.push(FirewallRule {
            interface: "awg-primary".to_owned(),
            source: None,
            destination: Some(vec!["203.0.113.1/32".to_owned()]),
            protocol: Some(FirewallProtocol::Icmp),
            ports: None,
        });

        let script = RoutingPlan::from_config(&config).nft_script();
        assert!(script.contains(
            "input iifname \"wg-server\" ip saddr 10.0.0.2/32 meta l4proto icmp ct state"
        ));
        assert!(script.contains(
            "output oifname \"awg-primary\" ip daddr 203.0.113.1/32 meta l4proto icmp ct state"
        ));
    }

    #[test]
    fn rule_without_source_or_destination_matches_entire_ingress_interface() {
        let mut config = sample_config();
        config.routing.rules[0].source = None;
        config.routing.rules[0].destination = None;
        // Keep this test focused on the selector-free rule. Other rules on
        // the same ingress legitimately contain destination selectors.
        config.routing.rules.truncate(1);
        let script = RoutingPlan::from_config(&config).nft_script();
        assert!(script.contains(
            "prerouting iifname \"wg-server\" ct state new meta nfproto ipv4 meta mark set 0x80000000 ct mark set (ct mark & 0x0000ffff) | 0x50010000 return"
        ));
        assert!(!script.contains("prerouting iifname \"wg-server\" ct state new ip saddr"));
        assert!(!script.contains("prerouting iifname \"wg-server\" ct state new ip daddr"));
        assert!(script.contains(
            "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50010000 meta nfproto ipv4 return"
        ));
    }

    #[test]
    fn nft_rule_supports_multiple_cidrs_for_both_selectors() {
        let mut config = sample_config();
        config.routing.rules[0].source =
            Some(vec!["10.0.0.0/24".to_owned(), "10.1.0.0/24".to_owned()]);
        config.routing.rules[0].destination = Some(vec![
            "195.142.0.0/16".to_owned(),
            "79.100.22.0/24".to_owned(),
        ]);
        let script = RoutingPlan::from_config(&config).nft_script();
        assert!(script.contains("ip saddr { 10.0.0.0/24, 10.1.0.0/24 }"));
        assert!(script.contains("ip daddr { 195.142.0.0/16, 79.100.22.0/24 }"));
    }

    #[test]
    fn bootstrap_firewall_drops_all_managed_traffic_until_descriptors_are_bound() {
        let plan = RoutingPlan::from_config(&sample_config()).fail_closed_bootstrap();
        let script = plan.nft_script();
        assert!(script.contains("input iifname @managed_interfaces drop"));
        assert!(script.contains("output oifname @managed_interfaces drop"));
        assert!(script.contains("forward iifname @managed_interfaces drop"));
        assert!(script.contains("forward oifname @managed_interfaces drop"));
        assert!(!script.contains(" ct direction original ct mark set "));
        assert!(!script.contains(" meta mark set 0x"));
        assert!(!script.contains(" masquerade"));
        assert!(!script.contains(" snat "));
    }

    #[test]
    fn nft_policy_binds_managed_interfaces_to_numeric_kernel_indices() {
        let mut plan = RoutingPlan::from_config(&sample_config());
        plan.bind_interface_indices(BTreeMap::from([
            ("wg-server".to_owned(), 17),
            ("awg-primary".to_owned(), 18),
            ("awg-secondary".to_owned(), 19),
        ]))
        .unwrap();

        let script = plan.nft_script();
        assert!(script.contains("managed_interfaces { type iface_index; elements = { 18, 19, 17 }"));
        assert!(script.contains("prerouting iif 17 ct state new"));
        assert!(script.contains("forward iif 17 oif 18"));
        assert!(script.contains("postrouting iif 17 oif 18"));
        assert!(script.contains("prerouting iifname \"wg-server\" iif != 17 counter drop"));
        assert!(script.contains("input iifname \"wg-server\" iif != 17 counter drop"));
        assert!(script.contains("forward iifname \"wg-server\" iif != 17 counter drop"));
        assert!(script.contains("forward oifname \"awg-primary\" oif != 18 counter drop"));
        assert!(script.contains("output oifname \"awg-secondary\" oif != 19 counter drop"));
        assert!(!script.contains("type ifname"));
    }

    #[test]
    fn ipv6_drop_guard_covers_every_managed_tun_by_numeric_identity() {
        let mut config = sample_config();
        let mut plan = RoutingPlan::from_config(&config);
        plan.bind_interface_indices(BTreeMap::from([
            ("wg-server".to_owned(), 17),
            ("awg-primary".to_owned(), 18),
            ("awg-secondary".to_owned(), 19),
        ]))
        .unwrap();

        let script = plan.nft_script();
        assert!(
            script.contains("ipv6_drop_interfaces { type iface_index; elements = { 18, 19, 17 }")
        );
        assert!(script.contains("prerouting iif @ipv6_drop_interfaces meta nfproto ipv6 drop"));
        assert!(script.contains("forward oif @ipv6_drop_interfaces meta nfproto ipv6 drop"));
        assert!(script.contains("output oif @ipv6_drop_interfaces meta nfproto ipv6 drop"));
    }

    #[test]
    fn nft_policy_drops_unmatched_managed_interface_transit() {
        let plan = RoutingPlan::from_config(&sample_config());
        let script = plan.nft_script();
        assert!(script.contains("elements = { \"awg-primary\", \"awg-secondary\", \"wg-server\" }"));
        assert!(script.contains("forward iifname @managed_interfaces drop"));
        assert!(script.contains("ipv6_drop_interfaces { type ifname;"));
        assert!(script.contains("add chain inet vpn_relay output { type filter hook output priority filter; policy accept; }"));
        assert!(script.contains("forward oifname @managed_interfaces drop"));
        assert!(script.contains("iifname @managed_interfaces meta mark set 0"));
        assert!(script.contains("ct direction reply meta mark set 0"));
        assert!(script.contains(
            "ct direction original ct mark & 0xffff0000 == 0x50010000 meta mark set 0x80000001"
        ));
    }

    #[test]
    fn nft_static_snat_is_emitted_for_the_selected_address_family() {
        let mut config = sample_config();
        config.routing.rules[0].nat = NatMode::Snat;
        config.routing.rules[0].nat_to = Some("203.0.113.10".parse().unwrap());
        let script = RoutingPlan::from_config(&config).nft_script();
        assert!(script.contains(
            "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50010000 meta nfproto ipv4 snat ip to 203.0.113.10"
        ));
        assert!(!script.contains("snat ip6"));
    }

    #[test]
    fn nft_masquerade_is_limited_to_the_selected_rule() {
        let mut config = sample_config();
        config.routing.rules[0].source = Some(vec!["10.0.0.0/24".to_owned()]);
        config.routing.rules[0].nat = NatMode::Masquerade;
        let script = RoutingPlan::from_config(&config).nft_script();
        assert!(script.contains(
            "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50010000 meta nfproto ipv4 masquerade"
        ));
        assert!(!script.contains("masquerade return"));
    }

    #[test]
    fn nft_nat_is_rule_scoped_and_disabled_by_default() {
        let plan = RoutingPlan::from_config(&sample_config());
        let script = plan.nft_script();
        assert!(script.contains("postrouting iifname \"wg-server\" oifname \"awg-secondary\""));
        assert!(script.contains("postrouting iifname \"wg-server\" oifname \"awg-primary\""));
        assert!(!script.contains(" masquerade "));
    }

    #[test]
    fn assigns_stable_tables_and_marks_to_egresses() {
        let plan = RoutingPlan::from_config(&sample_config());
        assert_eq!(plan.egresses.len(), 2);
        assert_eq!(plan.egresses[0].interface, "awg-primary");
        assert_eq!(plan.egresses[0].table_id, FIRST_ROUTING_TABLE);
        assert_eq!(plan.egresses[1].interface, "awg-secondary");
        assert_eq!(plan.egresses[1].table_id, FIRST_ROUTING_TABLE + 1);
        assert_eq!(plan.egresses[0].mark, 0x8000_0000);
        assert_eq!(plan.egresses[1].mark, 0x8000_0001);
        assert_ne!(plan.egresses[1].mark, 4099);
    }

    #[test]
    fn routing_plan_guarantees_socket_and_packet_mark_spaces_are_disjoint() {
        let plan = RoutingPlan::from_config(&sample_config());
        let packet_marks: std::collections::HashSet<_> =
            plan.egresses.iter().map(|egress| egress.mark).collect();
        let socket_marks: std::collections::HashSet<_> =
            plan.socket_marks.iter().copied().collect();

        assert_eq!(packet_marks.len(), plan.egresses.len());
        assert_eq!(socket_marks.len(), plan.socket_marks.len());
        assert!(packet_marks.is_disjoint(&socket_marks));
    }

    #[test]
    fn automatic_socket_marks_skip_the_complete_multi_egress_packet_mark_range() {
        let mut config = sample_config();
        config.routing.mark_base = 0x1000;
        for interface in config.interfaces.values_mut() {
            interface.socket_fwmark = None;
        }

        let plan = RoutingPlan::from_config(&config);
        assert_eq!(
            plan.egresses
                .iter()
                .map(|egress| egress.mark)
                .collect::<Vec<_>>(),
            vec![0x1000, 0x1001]
        );
        assert_eq!(plan.socket_marks, vec![0x1002, 0x1003, 0x1004]);
        assert!(plan.socket_marks.iter().all(|socket_mark| plan
            .egresses
            .iter()
            .all(|egress| egress.mark != *socket_mark)));
    }

    #[test]
    fn routing_plan_uses_automatically_resolved_socket_marks() {
        let mut config = sample_config();
        for interface in config.interfaces.values_mut() {
            interface.socket_fwmark = None;
        }
        let plan = RoutingPlan::from_config(&config);
        assert_eq!(plan.socket_marks, vec![0x1000, 0x1001, 0x1002]);
    }

    #[test]
    fn routing_decisions_preserve_explicit_priority_and_mark_selection() {
        let plan = RoutingPlan::from_config(&sample_config());
        assert_eq!(
            plan.decisions[0].destination.as_deref(),
            Some(&["195.142.0.0/16".to_owned()][..])
        );
        assert_eq!(
            plan.decisions[1].destination.as_deref(),
            Some(&["79.100.22.0/24".to_owned()][..])
        );
        assert_eq!(
            plan.decisions[2].destination.as_deref(),
            Some(&["0.0.0.0/0".to_owned()][..])
        );
        assert_eq!(plan.decisions[0].routing_mark, 0x8000_0001);
        assert_eq!(plan.decisions[0].conntrack_mark, 0x5001_0000);
        assert_eq!(plan.decisions[2].routing_mark, 0x8000_0000);
        assert_eq!(plan.decisions[2].conntrack_mark, 0x5003_0000);
        let script = plan.nft_script();
        assert!(script.contains(
            "ip daddr 195.142.0.0/16 meta mark set 0x80000001 ct mark set (ct mark & 0x0000ffff) | 0x50010000 return"
        ));
        assert!(script.contains("iifname \"wg-server\""));
    }

    #[test]
    fn rejects_overlap_between_inner_packet_and_udp_socket_marks() {
        let mut config = sample_config();
        config.routing.mark_base = 4098;
        assert!(config.validate().is_err());
    }

    #[test]
    fn overlapping_rules_sharing_egress_keep_distinct_conntrack_decisions() {
        let mut config = sample_config();
        config.routing.rules[0].source = None;
        config.routing.rules[0].destination = Some(vec!["0.0.0.0/0".to_owned()]);
        config.routing.rules[0].nat = NatMode::None;
        config.routing.rules[1].source = None;
        config.routing.rules[1].destination = Some(vec!["195.142.0.0/16".to_owned()]);
        config.routing.rules[1].nat = NatMode::Masquerade;

        let plan = RoutingPlan::from_config(&config);
        assert_ne!(
            plan.decisions[0].conntrack_mark,
            plan.decisions[1].conntrack_mark
        );
        assert_eq!(
            plan.decisions[0].routing_mark,
            plan.decisions[1].routing_mark
        );
        let script = plan.nft_script();
        assert!(script.contains(
            "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50010000 meta nfproto ipv4 return"
        ));
        assert!(script.contains(
            "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50020000 meta nfproto ipv4 masquerade"
        ));
        assert!(!script.contains(
            "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark & 0xffff0000 == 0x50010000 meta nfproto ipv4 masquerade"
        ));
    }
    #[test]
    fn conntrack_decision_marks_are_stable_across_rule_reordering() {
        let original_config = sample_config();
        let original_plan = RoutingPlan::from_config(&original_config);
        let original_marks: Vec<_> = original_plan
            .decisions
            .iter()
            .map(|decision| (decision.priority, decision.conntrack_mark))
            .collect();
        let mut history = original_plan.decisions.clone();

        let mut changed_config = sample_config();
        changed_config.routing.rules[0].priority = 150;
        changed_config.validate().unwrap();
        let mut changed_plan = RoutingPlan::from_config(&changed_config);
        changed_plan
            .assign_stable_conntrack_marks(&mut history)
            .unwrap();

        assert_eq!(
            changed_plan
                .decisions
                .iter()
                .find(|decision| decision.priority == 20)
                .unwrap()
                .conntrack_mark,
            original_marks[1].1
        );
        assert_eq!(
            changed_plan
                .decisions
                .iter()
                .find(|decision| decision.priority == 100)
                .unwrap()
                .conntrack_mark,
            original_marks[2].1
        );
        let changed_mark = changed_plan
            .decisions
            .iter()
            .find(|decision| decision.priority == 150)
            .unwrap()
            .conntrack_mark;
        assert!(!original_marks.iter().any(|(_, mark)| *mark == changed_mark));
        assert_eq!(changed_mark, 0x5004_0000);

        // Restoring an exact historical decision is safe: old conntrack
        // entries still describe the same ingress/selectors/egress/NAT action.
        let mut restored_plan = RoutingPlan::from_config(&original_config);
        restored_plan
            .assign_stable_conntrack_marks(&mut history)
            .unwrap();
        for (decision, (_, mark)) in restored_plan.decisions.iter().zip(original_marks) {
            assert_eq!(decision.conntrack_mark, mark);
        }
    }

    #[test]
    fn conntrack_decision_marks_remain_stable_when_routing_mark_base_changes() {
        let original_config = sample_config();
        let original_plan = RoutingPlan::from_config(&original_config);
        let original_marks: Vec<_> = original_plan
            .decisions
            .iter()
            .map(|decision| decision.conntrack_mark)
            .collect();
        let original_routing_marks: Vec<_> = original_plan
            .decisions
            .iter()
            .map(|decision| decision.routing_mark)
            .collect();
        let mut history = original_plan.decisions.clone();

        let mut changed_config = sample_config();
        changed_config.routing.mark_base = 0x9000_0000;
        changed_config.validate().unwrap();
        let mut changed_plan = RoutingPlan::from_config(&changed_config);
        changed_plan
            .assign_stable_conntrack_marks(&mut history)
            .unwrap();

        assert_eq!(
            changed_plan
                .decisions
                .iter()
                .map(|decision| decision.conntrack_mark)
                .collect::<Vec<_>>(),
            original_marks
        );
        assert_ne!(
            changed_plan
                .decisions
                .iter()
                .map(|decision| decision.routing_mark)
                .collect::<Vec<_>>(),
            original_routing_marks
        );
        assert_eq!(history.len(), original_marks.len());
        RoutingPlan::validate_conntrack_mark_history(&history).unwrap();
    }

    #[test]
    fn legacy_conntrack_marks_remain_valid_but_new_decisions_use_new_namespace() {
        let config = sample_config();
        let mut legacy_history = RoutingPlan::from_config(&config).decisions;
        for (index, decision) in legacy_history.iter_mut().enumerate() {
            decision.conntrack_mark = 0x4000_0000 | (((index as u32) + 1) << 16);
        }
        RoutingPlan::validate_conntrack_mark_history(&legacy_history).unwrap();

        let mut unchanged = RoutingPlan::from_config(&config);
        unchanged
            .assign_stable_conntrack_marks(&mut legacy_history)
            .unwrap();
        for (decision, previous) in unchanged.decisions.iter().zip(&legacy_history) {
            assert_eq!(decision.conntrack_mark, previous.conntrack_mark);
        }

        let mut changed_config = sample_config();
        changed_config.routing.rules[0].priority = 150;
        changed_config.validate().unwrap();
        let mut changed = RoutingPlan::from_config(&changed_config);
        changed
            .assign_stable_conntrack_marks(&mut legacy_history)
            .unwrap();
        let new_decision_mark = changed
            .decisions
            .iter()
            .find(|decision| decision.priority == 150)
            .unwrap()
            .conntrack_mark;
        assert_eq!(new_decision_mark, 0x5001_0000);
    }

    #[test]
    fn conntrack_mark_history_accepts_legacy_routing_mark_aliases() {
        let config = sample_config();
        let mut history = RoutingPlan::from_config(&config).decisions;
        RoutingPlan::from_config(&config)
            .assign_stable_conntrack_marks(&mut history)
            .unwrap();

        let mut legacy_alias = history[0].clone();
        legacy_alias.conntrack_mark = 0x500f_0000;
        legacy_alias.routing_mark = legacy_alias.routing_mark.wrapping_add(0x1000);
        history.push(legacy_alias);
        assert!(RoutingPlan::validate_conntrack_mark_history(&history).is_ok());

        let mut exact_duplicate = history[0].clone();
        exact_duplicate.conntrack_mark = 0x500e_0000;
        history.push(exact_duplicate);
        assert!(RoutingPlan::validate_conntrack_mark_history(&history)
            .unwrap_err()
            .contains("duplicate persisted conntrack decision identity"));
    }

    #[test]
    fn conntrack_mark_history_rejects_duplicate_or_invalid_ids() {
        let mut history = RoutingPlan::from_config(&sample_config()).decisions;
        history[1].conntrack_mark = history[0].conntrack_mark;
        assert!(RoutingPlan::validate_conntrack_mark_history(&history)
            .unwrap_err()
            .contains("invalid or duplicate"));

        let mut history = RoutingPlan::from_config(&sample_config()).decisions;
        history[0].conntrack_mark = 0x8000_0000;
        assert!(RoutingPlan::validate_conntrack_mark_history(&history)
            .unwrap_err()
            .contains("invalid or duplicate"));
    }

    #[test]
    fn source_only_and_destination_only_rules_generate_family_specific_matches() {
        let mut config = sample_config();
        config.routing.rules.truncate(2);
        config.routing.rules[0].source = Some(vec!["10.10.0.0/24".to_owned()]);
        config.routing.rules[0].destination = None;
        config.routing.rules[1].source = None;
        config.routing.rules[1].destination = Some(vec!["203.0.113.0/24".to_owned()]);

        let script = RoutingPlan::from_config(&config).nft_script();
        assert!(script.contains("ct state new ip saddr 10.10.0.0/24 meta mark set"));
        assert!(script.contains("ct state new ip daddr 203.0.113.0/24 meta mark set"));
        assert!(script.contains("ip saddr 10.10.0.0/24 meta mark set"));
    }
}
