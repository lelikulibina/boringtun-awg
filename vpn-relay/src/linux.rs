//! Linux command execution for daemon-owned network resources.
use crate::routing::RoutingPlan;
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

// Reserved iproute2 protocol tag identifying resources owned by vpn-relay.
const ROUTING_PROTOCOL: &str = "242";

#[derive(Debug, thiserror::Error)]
pub enum LinuxError {
    #[error("failed to execute {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{program} failed ({status}): {stderr}")]
    Command {
        program: String,
        status: String,
        stderr: String,
    },
    #[error("refusing to modify non-daemon network resource {resource}: {details}")]
    Conflict { resource: String, details: String },
}

fn output(program: &str, args: &[String]) -> Result<std::process::Output, LinuxError> {
    Command::new(program)
        .args(args)
        .output()
        .map_err(|source| LinuxError::Spawn {
            program: program.to_owned(),
            source,
        })
}

fn run(program: &str, args: &[String]) -> Result<(), LinuxError> {
    let output = output(program, args)?;
    if output.status.success() {
        return Ok(());
    }
    Err(LinuxError::Command {
        program: format!("{} {}", program, args.join(" ")),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

pub fn run_ip(args: &[String]) -> Result<(), LinuxError> {
    run("ip", args)
}

/// Return true only when the nftables table object itself carries our ownership marker.
fn table_is_owned(json: &str, family: &str, name: &str) -> bool {
    let Ok(document) = serde_json::from_str::<Value>(json) else {
        return false;
    };
    document
        .get("nftables")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                let Some(table) = item.get("table") else {
                    return false;
                };
                table.get("family").and_then(Value::as_str) == Some(family)
                    && table.get("name").and_then(Value::as_str) == Some(name)
                    && table.get("comment").and_then(Value::as_str) == Some("managed by vpn-relay")
            })
        })
}

fn inspect_nft_table(plan: &RoutingPlan) -> Result<bool, LinuxError> {
    let existing = Command::new("nft")
        .args(["-j", "list", "table", &plan.nft_family, &plan.nft_table])
        .output()
        .map_err(|source| LinuxError::Spawn {
            program: "nft".into(),
            source,
        })?;
    if !existing.status.success() {
        let stderr = String::from_utf8_lossy(&existing.stderr);
        if stderr.contains("No such file or directory") || stderr.contains("does not exist") {
            return Ok(false);
        }
        return Err(LinuxError::Command {
            program: "nft -j list table".into(),
            status: existing.status.to_string(),
            stderr: stderr.trim().into(),
        });
    }
    if table_is_owned(
        &String::from_utf8_lossy(&existing.stdout),
        &plan.nft_family,
        &plan.nft_table,
    ) {
        Ok(true)
    } else {
        Err(LinuxError::Conflict {
            resource: format!("nft table {} {}", plan.nft_family, plan.nft_table),
            details: "table exists but its table-level ownership marker is absent or invalid"
                .into(),
        })
    }
}

/// Replace only a table whose table-level metadata proves ownership.
pub fn apply_nft(plan: &RoutingPlan) -> Result<(), LinuxError> {
    let mut script = String::new();
    if inspect_nft_table(plan)? {
        script.push_str(&format!(
            "delete table {} {}\n",
            plan.nft_family, plan.nft_table
        ));
    }
    script.push_str(&plan.nft_script());
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| LinuxError::Spawn {
            program: "nft".into(),
            source,
        })?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(script.as_bytes())
        .map_err(|source| LinuxError::Spawn {
            program: "nft stdin".into(),
            source,
        })?;
    let output = child
        .wait_with_output()
        .map_err(|source| LinuxError::Spawn {
            program: "nft".into(),
            source,
        })?;
    if output.status.success() {
        return Ok(());
    }
    Err(LinuxError::Command {
        program: "nft -f -".into(),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().into(),
    })
}

pub fn remove_nft(plan: &RoutingPlan) {
    if !matches!(inspect_nft_table(plan), Ok(true)) {
        return;
    }
    let _ = run(
        "nft",
        &[
            "delete".into(),
            "table".into(),
            plan.nft_family.clone(),
            plan.nft_table.clone(),
        ],
    );
}

fn rule_has_owned_identity(line: &str, mark: u32, table: &str) -> bool {
    let Some((_, selector)) = line.split_once(':') else {
        return false;
    };
    selector.trim() == format!("from all fwmark 0x{mark:x} lookup {table} proto {ROUTING_PROTOCOL}")
}

fn parse_fwmark_value(value: &str) -> Option<u32> {
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

/// Return true when an ip rule's fwmark selector matches the supplied mark,
/// including selectors that use a partial mask or a wildcard mask.
fn rule_matches_fwmark(line: &str, mark: u32) -> bool {
    let fields: Vec<_> = line.split_whitespace().collect();
    let Some(index) = fields.iter().position(|field| *field == "fwmark") else {
        return false;
    };
    let Some(specification) = fields.get(index + 1) else {
        return false;
    };
    let (value, mask) = specification
        .split_once('/')
        .unwrap_or((specification, "0xffffffff"));
    let (Some(value), Some(mask)) = (parse_fwmark_value(value), parse_fwmark_value(mask)) else {
        return false;
    };
    mark & mask == value & mask
}

fn route_has_owned_identity(line: &str, interface: &str) -> bool {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() < 5
        || fields[0] != "default"
        || fields[1] != "dev"
        || fields[2] != interface
        || fields[3] != "proto"
        || fields[4] != ROUTING_PROTOCOL
    {
        return false;
    }

    // iproute2 may display kernel-default IPv6 metric/preference attributes.
    // Accept only those metadata fields; a gateway or other route mutation is
    // not part of the daemon-owned default route identity.
    let mut index = 5;
    while index < fields.len() {
        match fields[index] {
            "scope" if fields.get(index + 1) == Some(&"link") => index += 2,
            "metric"
                if fields
                    .get(index + 1)
                    .is_some_and(|value| value.parse::<u32>().is_ok()) =>
            {
                index += 2;
            }
            "pref"
                if fields
                    .get(index + 1)
                    .is_some_and(|value| matches!(*value, "low" | "medium" | "high")) =>
            {
                index += 2;
            }
            _ => return false,
        }
    }
    true
}

fn ensure_policy_slots_available(plan: &RoutingPlan) -> Result<(), LinuxError> {
    for family in ["-4", "-6"] {
        let args = vec![family.into(), "rule".into(), "show".into()];
        let rules = output("ip", &args)?;
        if !rules.status.success() {
            return Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: rules.status.to_string(),
                stderr: String::from_utf8_lossy(&rules.stderr).trim().to_owned(),
            });
        }

        for line in String::from_utf8_lossy(&rules.stdout).lines() {
            let Some((priority, _)) = line.split_once(':') else {
                continue;
            };
            let Ok(priority) = priority.trim().parse::<u32>() else {
                continue;
            };
            for mark in &plan.socket_marks {
                if rule_matches_fwmark(line, *mark) {
                    let expected = priority == 9_000 && rule_has_owned_identity(line, *mark, "main");
                    if !expected {
                        return Err(LinuxError::Conflict {
                            resource: format!("IPv{family} rule matching socket fwmark 0x{mark:x}"),
                            details: line.trim().to_owned(),
                        });
                    }
                }
            }
            for egress in &plan.egresses {
                if rule_matches_fwmark(line, egress.mark) {
                    let expected = priority == egress.ip_rule_priority
                        && rule_has_owned_identity(line, egress.mark, &egress.table_id.to_string());
                    if !expected {
                        return Err(LinuxError::Conflict {
                            resource: format!("IPv{family} rule matching routing fwmark 0x{:x}", egress.mark),
                            details: line.trim().to_owned(),
                        });
                    }
                }
            }
            if priority == 9_000 {
                let ours = plan
                    .socket_marks
                    .iter()
                    .any(|mark| rule_has_owned_identity(line, *mark, "main"));
                if !ours {
                    return Err(LinuxError::Conflict {
                        resource: format!("IPv{family} rule priority 9000"),
                        details: line.trim().to_owned(),
                    });
                }
            }
            if let Some(egress) = plan.egresses.iter().find(|egress| egress.ip_rule_priority == priority) {
                let expected =
                    rule_has_owned_identity(line, egress.mark, &egress.table_id.to_string());
                if !expected {
                    return Err(LinuxError::Conflict {
                        resource: format!("IPv{family} rule priority {priority}"),
                        details: line.trim().to_owned(),
                    });
                }
            }
        }

        for egress in plan
            .egresses
            .iter()
            .filter(|egress| family != "-6" || egress.ipv6_enabled)
        {
            let args = vec![
                family.into(),
                "route".into(),
                "show".into(),
                "table".into(),
                egress.table_id.to_string(),
            ];
            let routes = output("ip", &args)?;
            if !routes.status.success() {
                let stderr = String::from_utf8_lossy(&routes.stderr);
                // iproute2 returns status 2 when a routing table has not been
                // created yet. That is the normal first-start state.
                if stderr.contains("FIB table does not exist") {
                    continue;
                }
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: routes.status.to_string(),
                    stderr: stderr.trim().to_owned(),
                });
            }
            for line in String::from_utf8_lossy(&routes.stdout).lines() {
                let owned_route = route_has_owned_identity(line, &egress.interface);
                if !owned_route {
                    return Err(LinuxError::Conflict {
                        resource: format!("IPv{family} route table {}", egress.table_id),
                        details: line.trim().to_owned(),
                    });
                }
            }
        }
    }
    Ok(())
}

pub fn apply_policy_routing(plan: &RoutingPlan) -> Result<(), LinuxError> {
    ensure_policy_slots_available(plan)?;
    for mark in &plan.socket_marks {
        // Keep encrypted outer IPv6 transport on the main table even when inner IPv6 is disabled.
        for family in ["-4", "-6"] {
            let args = vec![
                family.into(),
                "rule".into(),
                "del".into(),
                "priority".into(),
                "9000".into(),
                "fwmark".into(),
                format!("0x{:x}", mark),
                "lookup".into(),
                "main".into(),
                "protocol".into(),
                ROUTING_PROTOCOL.into(),
            ];
            let _ = run("ip", &args);
            let args = vec![
                family.into(),
                "rule".into(),
                "add".into(),
                "priority".into(),
                "9000".into(),
                "fwmark".into(),
                format!("0x{:x}", mark),
                "lookup".into(),
                "main".into(),
                "protocol".into(),
                ROUTING_PROTOCOL.into(),
            ];
            if let Err(error) = run("ip", &args) {
                remove_policy_routing(plan);
                return Err(error);
            }
        }
    }

    for egress in &plan.egresses {
        if !egress.ipv6_enabled {
            // Remove stale daemon-owned IPv6 policy left by an earlier enabled configuration.
            let stale_rule = [
                "-6".into(),
                "rule".into(),
                "del".into(),
                "priority".into(),
                egress.ip_rule_priority.to_string(),
                "fwmark".into(),
                format!("0x{:x}", egress.mark),
                "lookup".into(),
                egress.table_id.to_string(),
                "protocol".into(),
                ROUTING_PROTOCOL.into(),
            ];
            let stale_route = [
                "-6".into(),
                "route".into(),
                "del".into(),
                "default".into(),
                "dev".into(),
                egress.interface.clone(),
                "table".into(),
                egress.table_id.to_string(),
                "proto".into(),
                ROUTING_PROTOCOL.into(),
            ];
            let _ = run("ip", &stale_rule);
            let _ = run("ip", &stale_route);
        }
        for &family in RoutingPlan::ip_families(egress) {
            let priority = egress.ip_rule_priority.to_string();
            let mark = format!("0x{:x}", egress.mark);
            let table = egress.table_id.to_string();
            // A stale rule from a previous daemon instance is removed first.
            let _ = run(
                "ip",
                &[
                    family.into(),
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    priority.clone(),
                    "fwmark".into(),
                    mark.clone(),
                    "lookup".into(),
                    table.clone(),
                    "protocol".into(),
                    ROUTING_PROTOCOL.into(),
                ],
            );
            if let Err(error) = run(
                "ip",
                &[
                    family.into(),
                    "route".into(),
                    "replace".into(),
                    "default".into(),
                    "dev".into(),
                    egress.interface.clone(),
                    "table".into(),
                    table.clone(),
                    "proto".into(),
                    ROUTING_PROTOCOL.into(),
                ],
            )
            .and_then(|_| {
                run(
                    "ip",
                    &[
                        family.into(),
                        "rule".into(),
                        "add".into(),
                        "priority".into(),
                        priority,
                        "fwmark".into(),
                        mark,
                        "lookup".into(),
                        table,
                        "protocol".into(),
                        ROUTING_PROTOCOL.into(),
                    ],
                )
            }) {
                remove_policy_routing(plan);
                return Err(error);
            }
        }
    }
    Ok(())
}

pub fn remove_policy_routing(plan: &RoutingPlan) {
    for mark in &plan.socket_marks {
        for family in ["-4", "-6"] {
            let _ = run(
                "ip",
                &[
                    family.into(),
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    "9000".into(),
                    "fwmark".into(),
                    format!("0x{:x}", mark),
                    "lookup".into(),
                    "main".into(),
                    "protocol".into(),
                    ROUTING_PROTOCOL.into(),
                ],
            );
        }
    }
    for egress in &plan.egresses {
        for family in ["-4", "-6"] {
            let _ = run(
                "ip",
                &[
                    family.into(),
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    egress.ip_rule_priority.to_string(),
                    "fwmark".into(),
                    format!("0x{:x}", egress.mark),
                    "lookup".into(),
                    egress.table_id.to_string(),
                    "protocol".into(),
                    ROUTING_PROTOCOL.into(),
                ],
            );
            let _ = run(
                "ip",
                &[
                    family.into(),
                    "route".into(),
                    "del".into(),
                    "default".into(),
                    "dev".into(),
                    egress.interface.clone(),
                    "table".into(),
                    egress.table_id.to_string(),
                    "proto".into(),
                    ROUTING_PROTOCOL.into(),
                ],
            );
        }
    }
}

pub fn configure_interface(name: &str, mtu: u16, addresses: &[String]) -> Result<(), LinuxError> {
    run(
        "ip",
        &[
            "link".into(),
            "set".into(),
            "dev".into(),
            name.into(),
            "mtu".into(),
            mtu.to_string(),
            "up".into(),
        ],
    )?;
    for address in addresses {
        let family = if address.contains(':') { "-6" } else { "-4" };
        run(
            "ip",
            &[
                family.into(),
                "address".into(),
                "replace".into(),
                address.clone(),
                "dev".into(),
                name.into(),
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_ownership_requires_table_level_comment_and_exact_identity() {
        let owned = r#"{"nftables":[{"table":{"family":"inet","name":"vpn_relay","comment":"managed by vpn-relay"}}]}"#;
        assert!(table_is_owned(owned, "inet", "vpn_relay"));
        assert!(!table_is_owned(owned, "ip", "vpn_relay"));
        assert!(!table_is_owned(owned, "inet", "other"));
        let rule_comment = r#"{"nftables":[{"table":{"family":"inet","name":"vpn_relay"}},{"rule":{"family":"inet","table":"vpn_relay","comment":"managed by vpn-relay"}}]}"#;
        assert!(!table_is_owned(rule_comment, "inet", "vpn_relay"));
        assert!(!table_is_owned("not json", "inet", "vpn_relay"));
    }

    #[test]
    fn recognizes_only_exact_daemon_owned_ip_rules() {
        assert!(rule_has_owned_identity(
            "10000: from all fwmark 0x80000000 lookup 10000 proto 242",
            0x8000_0000,
            "10000"
        ));
        assert!(!rule_has_owned_identity(
            "10000: from all fwmark 0x80000000 lookup 10000",
            0x8000_0000,
            "10000"
        ));
        assert!(!rule_has_owned_identity(
            "10000: from all fwmark 0x80000001 lookup 10000 proto 242",
            0x8000_0000,
            "10000"
        ));
        assert!(!rule_has_owned_identity(
            "10000: from all fwmark 0x80000000 lookup 10001 proto 242",
            0x8000_0000,
            "10000"
        ));
    }

    #[test]
    fn detects_ip_rules_that_shadow_or_overlap_reserved_fwmarks() {
        assert!(rule_matches_fwmark(
            "100: from all fwmark 0x80000000 lookup 10000",
            0x8000_0000
        ));
        assert!(rule_matches_fwmark(
            "100: from all fwmark 0x80000000/0xffff0000 lookup 10000",
            0x8000_0001
        ));
        assert!(rule_matches_fwmark(
            "100: from all fwmark 0x0/0x0 lookup main",
            0x8000_0001
        ));
        assert!(!rule_matches_fwmark(
            "100: from all fwmark 0x80000001 lookup 10000",
            0x8000_0000
        ));
        assert!(!rule_matches_fwmark(
            "100: from all lookup 10000",
            0x8000_0000
        ));
    }

    #[test]
    fn recognizes_owned_default_routes_and_kernel_metadata() {
        assert!(route_has_owned_identity(
            "default dev awg-primary proto 242",
            "awg-primary"
        ));
        assert!(route_has_owned_identity(
            "default dev awg-primary proto 242 metric 1024 pref medium",
            "awg-primary"
        ));
        assert!(!route_has_owned_identity(
            "default dev awg-primary",
            "awg-primary"
        ));
        assert!(!route_has_owned_identity(
            "default via 192.0.2.1 dev awg-primary proto 242",
            "awg-primary"
        ));
        assert!(!route_has_owned_identity(
            "default dev awg-secondary proto 242",
            "awg-primary"
        ));
        assert!(!route_has_owned_identity(
            "default dev awg-primary proto 242 mtu 1400",
            "awg-primary"
        ));
    }
}
