//! Pure routing-plan generation for the Linux daemon.
//!
//! This module deliberately does not execute privileged commands. It turns a
//! validated TOML configuration into deterministic nftables and policy-routing
//! operations; the runtime layer can apply these operations transactionally.

use crate::config::{Config, InterfaceRole};
use std::collections::BTreeMap;
use std::net::IpAddr;

const FIRST_ROUTING_TABLE: u32 = 10_000;
const FIRST_IP_RULE_PRIORITY: u32 = 10_000;

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
    pub destination: String,
    pub egress: String,
    pub mark: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingPlan {
    pub nft_family: String,
    pub nft_table: String,
    pub egresses: Vec<EgressPlan>,
    pub nft_rules: Vec<NftRule>,
}

impl RoutingPlan {
    /// Build a deterministic plan from a fully validated configuration.
    pub fn from_config(config: &Config) -> Self {
        let mut egress_names: Vec<_> = config.interfaces.iter()
            .filter(|interface| interface.role == InterfaceRole::Client)
            .map(|interface| interface.name.as_str())
            .collect();
        egress_names.sort_unstable();
        egress_names.dedup();

        let marks: BTreeMap<_, _> = config.interfaces.iter()
            .map(|interface| (interface.name.as_str(), interface.socket_fwmark))
            .collect();

        let egresses: Vec<_> = egress_names.iter().enumerate()
            .map(|(index, name)| EgressPlan {
                interface: (*name).to_owned(),
                mark: marks[name],
                table_id: FIRST_ROUTING_TABLE + index as u32,
                ip_rule_priority: FIRST_IP_RULE_PRIORITY + index as u32,
            })
            .collect();

        let egress_marks: BTreeMap<_, _> = egresses.iter()
            .map(|egress| (egress.interface.as_str(), egress.mark))
            .collect();

        let mut nft_rules: Vec<_> = config.routing.rules.iter()
            .map(|rule| NftRule {
                priority: rule.priority,
                ingress: rule.ingress.clone(),
                destination: rule.destination.clone(),
                egress: rule.egress.clone(),
                mark: egress_marks[rule.egress.as_str()],
            })
            .collect();
        nft_rules.sort_by(|left, right| left.ingress.cmp(&right.ingress)
            .then(left.priority.cmp(&right.priority)));

        Self {
            nft_family: "inet".to_owned(),
            nft_table: config.daemon.nft_table.clone(),
            egresses,
            nft_rules,
        }
    }

    /// Render the daemon-owned nftables table. Lower numeric priorities are
    /// emitted first; each rule assigns a mark consumed by an ip rule fwmark.
    pub fn nft_script(&self) -> String {
        let mut output = format!(
            "add table {} {}\nadd chain {} {} prerouting {{ type filter hook prerouting priority mangle; policy accept; }}\n",
            self.nft_family, self.nft_table, self.nft_family, self.nft_table
        );
        for rule in &self.nft_rules {
            let family_match = match rule.destination.parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => "ip",
                Ok(IpAddr::V6(_)) => "ip6",
                Err(_) if rule.destination.contains(':') => "ip6",
                Err(_) => "ip",
            };
            output.push_str(&format!(
                "add rule {} {} prerouting iifname \"{}\" {} daddr {} meta mark set 0x{:x} return\n",
                self.nft_family, self.nft_table, rule.ingress, family_match,
                rule.destination, rule.mark
            ));
        }
        output
    }

    /// Commands needed to populate each egress routing table and select it by
    /// packet mark. The caller is responsible for executing them and rollback.
    pub fn ip_commands(&self) -> Vec<Vec<String>> {
        let mut commands = Vec::with_capacity(self.egresses.len() * 4);
        for egress in &self.egresses {
            for family in ["-4", "-6"] {
                commands.push(vec![
                    family.into(), "route".into(), "replace".into(), "default".into(),
                    "dev".into(), egress.interface.clone(), "table".into(),
                    egress.table_id.to_string(),
                ]);
                commands.push(vec![
                    family.into(), "rule".into(), "add".into(), "priority".into(),
                    egress.ip_rule_priority.to_string(), "fwmark".into(),
                    format!("0x{:x}", egress.mark), "lookup".into(),
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
    fn assigns_stable_tables_and_marks_to_egresses() {
        let plan = RoutingPlan::from_config(&sample_config());
        assert_eq!(plan.egresses.len(), 2);
        assert_eq!(plan.egresses[0].interface, "awg-primary");
        assert_eq!(plan.egresses[0].table_id, FIRST_ROUTING_TABLE);
        assert_eq!(plan.egresses[1].interface, "awg-secondary");
        assert_eq!(plan.egresses[1].table_id, FIRST_ROUTING_TABLE + 1);
        assert_eq!(plan.egresses[1].mark, 4099);
    }

    #[test]
    fn nft_rules_preserve_explicit_priority_and_mark_selection() {
        let plan = RoutingPlan::from_config(&sample_config());
        assert_eq!(plan.nft_rules[0].destination, "195.142.0.0/16");
        assert_eq!(plan.nft_rules[1].destination, "79.100.22.0/24");
        assert_eq!(plan.nft_rules[2].destination, "0.0.0.0/0");
        assert_eq!(plan.nft_rules[0].mark, 4099);
        assert_eq!(plan.nft_rules[2].mark, 4098);
        let script = plan.nft_script();
        assert!(script.contains("ip daddr 195.142.0.0/16 meta mark set 0x1003 return"));
        assert!(script.contains("iifname \"wg-server\""));
    }

    #[test]
    fn creates_ipv4_and_ipv6_policy_rules_for_each_uplink() {
        let plan = RoutingPlan::from_config(&sample_config());
        let commands = plan.ip_commands();
        assert_eq!(commands.len(), 8);
        assert!(commands.iter().any(|args| args.first().is_some_and(|arg| arg == "-6")));
        assert!(commands.iter().any(|args| args.iter().any(|arg| arg == "0x1002")));
    }
}
