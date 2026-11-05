//! Pure routing-plan generation for the Linux daemon.
//!
//! This module deliberately does not execute privileged commands. It turns a
//! validated TOML configuration into deterministic nftables and policy-routing
//! operations; the runtime layer can apply these operations transactionally.

use crate::config::{Config, InterfaceRole, NatMode};
use std::collections::BTreeMap;

const FIRST_ROUTING_TABLE: u32 = 10_000;
const FIRST_IP_RULE_PRIORITY: u32 = 10_000;
const SOCKET_MAIN_RULE_PRIORITY: u32 = 9_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressPlan {
    pub interface: String,
    pub mark: u32,
    pub table_id: u32,
    pub ip_rule_priority: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NftRule {
    pub priority: u32,
    pub ingress: String,
    pub source: Option<String>,
    pub destination: String,
    pub egress: String,
    pub mark: u32,
    pub nat: NatMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingPlan {
    pub nft_family: String,
    pub nft_table: String,
    pub managed_interfaces: Vec<String>,
    pub egresses: Vec<EgressPlan>,
    pub nft_rules: Vec<NftRule>,
    /// Socket marks that force outer encrypted UDP through the main table.
    pub socket_marks: Vec<u32>,
}

impl RoutingPlan {
    /// Build a deterministic plan from a fully validated configuration.
    pub fn from_config(config: &Config) -> Self {
        let mut egress_names: Vec<_> = config
            .interfaces
            .iter()
            .filter(|interface| interface.role == InterfaceRole::Client)
            .map(|interface| interface.name.as_str())
            .collect();
        egress_names.sort_unstable();
        egress_names.dedup();

        let egresses: Vec<_> = egress_names
            .iter()
            .enumerate()
            .map(|(index, name)| EgressPlan {
                interface: (*name).to_owned(),
                mark: config.routing.mark_base + index as u32,
                table_id: FIRST_ROUTING_TABLE + index as u32,
                ip_rule_priority: FIRST_IP_RULE_PRIORITY + index as u32,
            })
            .collect();

        let egress_marks: BTreeMap<_, _> = egresses
            .iter()
            .map(|egress| (egress.interface.as_str(), egress.mark))
            .collect();

        let mut nft_rules: Vec<_> = config
            .routing
            .rules
            .iter()
            .map(|rule| NftRule {
                priority: rule.priority,
                ingress: rule.ingress.clone(),
                source: rule.source.clone(),
                destination: rule.destination.clone(),
                egress: rule.egress.clone(),
                mark: egress_marks[rule.egress.as_str()],
                nat: rule.nat,
            })
            .collect();
        nft_rules.sort_by(|left, right| {
            left.ingress
                .cmp(&right.ingress)
                .then(left.priority.cmp(&right.priority))
        });

        let mut socket_marks: Vec<_> = config
            .interfaces
            .iter()
            .map(|interface| interface.socket_fwmark)
            .collect();
        socket_marks.sort_unstable();

        let mut managed_interfaces: Vec<_> = config.interfaces.iter().map(|interface| interface.name.clone()).collect();
        managed_interfaces.sort();

        Self {
            nft_family: "inet".to_owned(),
            nft_table: config.daemon.nft_table.clone(),
            managed_interfaces,
            egresses,
            nft_rules,
            socket_marks,
        }
    }

    /// Render a fail-closed transit policy. New flows require an explicit
    /// ingress/destination/egress rule; conntrack permits only their replies.
    /// Unmatched packets entering or leaving a managed TUN are dropped.
    pub fn nft_script(&self) -> String {
        let interfaces = self.managed_interfaces.iter()
            .map(|interface| format!("\"{}\"", interface))
            .collect::<Vec<_>>()
            .join(", ");

        let mut output = format!(
            "add table {} {} {{ comment \"managed by btrouted\"; }}\n\
             add set {} {} managed_interfaces {{ type ifname; elements = {{ {} }}; }}\n\
             add chain {} {} prerouting {{ type filter hook prerouting priority mangle; policy accept; }}\n\
             add chain {} {} forward {{ type filter hook forward priority filter; policy accept; }}\n\
             add chain {} {} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n",
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table, interfaces,
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table
        );

        // The reply direction must use the main table to reach the ingress TUN.
        // Original-direction packets restore the egress mark saved on the first
        // packet of the connection.
        output.push_str(&format!(
            "add rule {} {} prerouting iifname @managed_interfaces meta mark set 0\n\
             add rule {} {} prerouting iifname @managed_interfaces ct state established,related ct direction reply meta mark set 0 return\n\
             add rule {} {} prerouting iifname @managed_interfaces ct state established,related ct direction original ct mark != 0 meta mark set ct mark return\n",
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table
        ));

        for rule in &self.nft_rules {
            let family = nft_family_match(&rule.destination);
            let mut selectors = format!("iifname \"{}\" ct state new ", rule.ingress);
            if let Some(source) = &rule.source {
                selectors.push_str(&format!("{} saddr {} ", nft_family_match(source), source));
            }
            selectors.push_str(&format!("{} daddr {}", family, rule.destination));
            output.push_str(&format!(
                "add rule {} {} prerouting {} meta mark set 0x{:x} ct mark set meta mark return\n",
                self.nft_family, self.nft_table, selectors, rule.mark
            ));
        }

        output.push_str(&format!(
            "add rule {} {} forward iifname @managed_interfaces ct state invalid drop\n",
            self.nft_family, self.nft_table
        ));
        for rule in &self.nft_rules {
            output.push_str(&format!(
                "add rule {} {} forward iifname \"{}\" oifname \"{}\" ct state new,established,related meta mark 0x{:x} accept\n",
                self.nft_family, self.nft_table, rule.ingress, rule.egress, rule.mark
            ));
        }
        for rule in &self.nft_rules {
            output.push_str(&format!(
                "add rule {} {} forward iifname \"{}\" oifname \"{}\" ct state established,related ct mark 0x{:x} accept\n",
                self.nft_family, self.nft_table, rule.egress, rule.ingress, rule.mark
            ));
        }
        output.push_str(&format!(
            "add rule {} {} forward iifname @managed_interfaces drop\n\
             add rule {} {} forward oifname @managed_interfaces drop\n",
            self.nft_family, self.nft_table,
            self.nft_family, self.nft_table
        ));

        // Evaluate NAT rules in the same priority order as routing rules. A
        // matching "none" rule returns from the NAT chain, preventing a later,
        // more-specific rule from overriding the rule selected for this flow.
        for rule in &self.nft_rules {
            let mut selectors = format!(
                "iifname \"{}\" oifname \"{}\" ct mark 0x{:x} ",
                rule.ingress, rule.egress, rule.mark
            );
            if let Some(source) = &rule.source {
                selectors.push_str(&format!("{} saddr {} ", nft_family_match(source), source));
            }
            selectors.push_str(&format!(
                "{} daddr {}",
                nft_family_match(&rule.destination),
                rule.destination
            ));
            match rule.nat {
                NatMode::None => output.push_str(&format!(
                    "add rule {} {} postrouting {} return\n",
                    self.nft_family, self.nft_table, selectors
                )),
                NatMode::Masquerade => output.push_str(&format!(
                    "add rule {} {} postrouting {} masquerade return\n",
                    self.nft_family, self.nft_table, selectors
                )),
            }
        }
        output
    }

    /// Commands needed to populate egress tables and select them by packet
    /// mark. Socket marks explicitly use the main table to avoid tunnel loops.
    pub fn ip_commands(&self) -> Vec<Vec<String>> {
        let mut commands =
            Vec::with_capacity(self.egresses.len() * 4 + self.socket_marks.len() * 2);
        for mark in &self.socket_marks {
            for family in ["-4", "-6"] {
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
            for family in ["-4", "-6"] {
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn sample_config() -> Config {
        let toml = format!(
            r#"
[[interfaces]]
name = "wg-server"
protocol = "wg"
role = "server"
addresses = ["10.0.0.1/24"]
listen_port = 51820
private_key = "{KEY}"
socket_fwmark = 4097

[[interfaces]]
name = "awg-primary"
protocol = "awg3_1"
role = "client"
addresses = ["10.1.0.2/32"]
listen_port = 51821
private_key = "{KEY}"
socket_fwmark = 4098

[[interfaces]]
name = "awg-secondary"
protocol = "awg2"
role = "client"
addresses = ["10.2.0.2/32"]
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
    fn nft_policy_drops_unmatched_managed_interface_transit() {
        let plan = RoutingPlan::from_config(&sample_config());
        let script = plan.nft_script();
        assert!(script.contains("elements = { \"awg-primary\", \"awg-secondary\", \"wg-server\" }"));
        assert!(script.contains("forward iifname @managed_interfaces drop"));
        assert!(script.contains("forward oifname @managed_interfaces drop"));
        assert!(script.contains("iifname @managed_interfaces meta mark set 0"));
        assert!(script.contains("ct direction reply meta mark set 0"));
        assert!(script.contains("ct direction original ct mark != 0 meta mark set ct mark"));
    }

    #[test]
    fn nft_masquerade_is_limited_to_the_selected_rule() {
        let mut config = sample_config();
        config.routing.rules[0].source = Some("10.0.0.0/24".to_owned());
        config.routing.rules[0].nat = NatMode::Masquerade;
        let script = RoutingPlan::from_config(&config).nft_script();
        assert!(script.contains(
            "postrouting iifname \"wg-server\" oifname \"awg-secondary\" ct mark 0x80000001 ip saddr 10.0.0.0/24 ip daddr 195.142.0.0/16 masquerade return"
        ));
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
    fn nft_rules_preserve_explicit_priority_and_mark_selection() {
        let plan = RoutingPlan::from_config(&sample_config());
        assert_eq!(plan.nft_rules[0].destination, "195.142.0.0/16");
        assert_eq!(plan.nft_rules[1].destination, "79.100.22.0/24");
        assert_eq!(plan.nft_rules[2].destination, "0.0.0.0/0");
        assert_eq!(plan.nft_rules[0].mark, 0x8000_0001);
        assert_eq!(plan.nft_rules[2].mark, 0x8000_0000);
        let script = plan.nft_script();
        assert!(script.contains("ip daddr 195.142.0.0/16 meta mark set 0x80000001 ct mark set meta mark return"));
        assert!(script.contains("iifname \"wg-server\""));
    }

    #[test]
    fn rejects_overlap_between_inner_packet_and_udp_socket_marks() {
        let mut config = sample_config();
        config.routing.mark_base = 4098;
        assert!(config.validate().is_err());
    }

    #[test]
    fn creates_ipv4_and_ipv6_policy_rules_for_each_uplink() {
        let plan = RoutingPlan::from_config(&sample_config());
        let commands = plan.ip_commands();
        assert_eq!(commands.len(), 14);
        assert!(commands
            .iter()
            .any(|args| args.first().is_some_and(|arg| arg == "-6")));
        assert!(commands
            .iter()
            .any(|args| args.iter().any(|arg| arg == "0x80000000")));
        assert!(commands
            .iter()
            .any(|args| args.iter().any(|arg| arg == "main")));
    }
}
