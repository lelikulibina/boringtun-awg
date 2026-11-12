//! Linux command execution for daemon-owned network resources.
use crate::routing::{RoutingPlan, FIRST_IP_RULE_PRIORITY, FIRST_ROUTING_TABLE};
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
    #[error("policy-routing cleanup failed: {0}")]
    Cleanup(String),
    #[error("{operation}; rollback failed: {rollback}")]
    Rollback { operation: String, rollback: String },
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

/// Older nftables releases omit table comments from JSON output. Fall back to
/// the human-readable representation, but accept only the table-level comment
/// (four-space indentation), never a similarly named comment inside a chain.
fn table_is_owned_text(output: &str, family: &str, name: &str) -> bool {
    let expected_header = format!("table {family} {name} {{");
    let expected_comment = "comment \"managed by vpn-relay\"";
    let mut in_table = false;

    for line in output.lines() {
        if !in_table {
            in_table = line.trim() == expected_header;
            continue;
        }

        // The table's closing brace is the only closing brace at column zero.
        if line.starts_with('}') {
            return false;
        }

        // nftables 1.0.2 prints tabs; newer releases commonly print spaces.
        let top_level_indentation = (line.starts_with('\t') && !line.starts_with("\t\t"))
            || (line.starts_with("    ") && !line.starts_with("        "));
        if top_level_indentation && line.trim() == expected_comment {
            return true;
        }
    }

    false
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

    let json = String::from_utf8_lossy(&existing.stdout);
    if table_is_owned(&json, &plan.nft_family, &plan.nft_table) {
        return Ok(true);
    }

    // nftables 1.0.2 (Ubuntu 22.04) accepts table comments but does not expose
    // them in JSON. Require the exact table header and a top-level comment
    // before considering the table daemon-owned.
    let textual = Command::new("nft")
        .args(["list", "table", &plan.nft_family, &plan.nft_table])
        .output()
        .map_err(|source| LinuxError::Spawn {
            program: "nft".into(),
            source,
        })?;
    if !textual.status.success() {
        return Err(LinuxError::Command {
            program: "nft list table".into(),
            status: textual.status.to_string(),
            stderr: String::from_utf8_lossy(&textual.stderr).trim().into(),
        });
    }
    if table_is_owned_text(
        &String::from_utf8_lossy(&textual.stdout),
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
    apply_nft_with(plan, &mut inspect_nft_table, &mut run_nft_script)
}

fn apply_nft_with<I, R>(
    plan: &RoutingPlan,
    inspect_table: &mut I,
    run_script: &mut R,
) -> Result<(), LinuxError>
where
    I: FnMut(&RoutingPlan) -> Result<bool, LinuxError>,
    R: FnMut(&str) -> Result<(), LinuxError>,
{
    let mut script = String::new();
    if inspect_table(plan)? {
        script.push_str(&format!(
            "delete table {} {}\n",
            plan.nft_family, plan.nft_table
        ));
    }
    script.push_str(&plan.nft_script());
    run_script(&script)
}

/// Submit one complete nftables batch. nft applies a batch transactionally:
/// a rejected batch leaves the previous table intact.
fn run_nft_script(script: &str) -> Result<(), LinuxError> {
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
    let write_result = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(script.as_bytes());
    if let Err(source) = write_result {
        // Closing stdin lets nft observe EOF. Always reap the child even when
        // the pipe breaks, otherwise a failed policy update can leave an
        // unreaped subprocess behind.
        let _ = child.wait_with_output();
        return Err(LinuxError::Spawn {
            program: "nft stdin".into(),
            source,
        });
    }
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

pub fn remove_nft(plan: &RoutingPlan) -> Result<(), LinuxError> {
    remove_nft_with(plan, &mut inspect_nft_table, &mut run)
}

fn remove_nft_with<I, R>(
    plan: &RoutingPlan,
    inspect_table: &mut I,
    run_command: &mut R,
) -> Result<(), LinuxError>
where
    I: FnMut(&RoutingPlan) -> Result<bool, LinuxError>,
    R: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    if !inspect_table(plan)? {
        return Ok(());
    }
    run_command(
        "nft",
        &[
            "delete".into(),
            "table".into(),
            plan.nft_family.clone(),
            plan.nft_table.clone(),
        ],
    )
}

fn rule_has_owned_identity(line: &str, mark: u32, table: &str) -> bool {
    let Some((_, selector)) = line.split_once(':') else {
        return false;
    };
    selector.trim() == format!("from all fwmark 0x{mark:x} lookup {table} proto {ROUTING_PROTOCOL}")
}

fn rule_uses_table(line: &str, table_id: u32) -> bool {
    let fields: Vec<_> = line.split_whitespace().collect();
    let Some(index) = fields.iter().position(|field| *field == "lookup") else {
        return false;
    };
    let table = table_id.to_string();
    fields.get(index + 1).copied() == Some(table.as_str())
}

fn parse_fwmark_value(value: &str) -> Option<u32> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
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

    // iproute2 may display kernel-default metric/preference attributes.
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
    for &family in plan.ip_policy_families() {
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
                    let expected =
                        priority == 9_000 && rule_has_owned_identity(line, *mark, "main");
                    if !expected {
                        return Err(LinuxError::Conflict {
                            resource: format!("IPv{family} rule matching socket fwmark 0x{mark:x}"),
                            details: line.trim().to_owned(),
                        });
                    }
                }
            }
            for egress in &plan.egresses {
                if rule_uses_table(line, egress.table_id) {
                    let expected = priority == egress.ip_rule_priority
                        && rule_has_owned_identity(line, egress.mark, &egress.table_id.to_string());
                    if !expected {
                        return Err(LinuxError::Conflict {
                            resource: format!(
                                "IPv{family} rule referencing route table {}",
                                egress.table_id
                            ),
                            details: line.trim().to_owned(),
                        });
                    }
                }
                if rule_matches_fwmark(line, egress.mark) {
                    let expected = priority == egress.ip_rule_priority
                        && rule_has_owned_identity(line, egress.mark, &egress.table_id.to_string());
                    if !expected {
                        return Err(LinuxError::Conflict {
                            resource: format!(
                                "IPv{family} rule matching routing fwmark 0x{:x}",
                                egress.mark
                            ),
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
            if let Some(egress) = plan
                .egresses
                .iter()
                .find(|egress| egress.ip_rule_priority == priority)
            {
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

        for egress in &plan.egresses {
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

/// Allocate a second, disjoint set of table IDs and rule priorities for a
/// live routing-plan transition. Existing plans are never reused while active.
pub fn allocate_policy_routing_resources(
    plan: &mut RoutingPlan,
    occupied: &[RoutingPlan],
) -> Result<(), LinuxError> {
    if plan.egresses.is_empty() {
        return Ok(());
    }

    let last_index = u32::try_from(plan.egresses.len() - 1).map_err(|_| LinuxError::Conflict {
        resource: "policy-routing slots".to_owned(),
        details: "egress count does not fit in an iproute2 slot index".to_owned(),
    })?;
    let max_offset = 32_765u32
        .saturating_sub(FIRST_IP_RULE_PRIORITY)
        .saturating_sub(last_index);
    if max_offset < 1_000 {
        return Err(LinuxError::Conflict {
            resource: "policy-routing slots".to_owned(),
            details: "no dynamic rule-priority range remains below the main-table rule".to_owned(),
        });
    }

    for offset in 1_000..=max_offset {
        let mut candidate = plan.clone();
        for (index, egress) in candidate.egresses.iter_mut().enumerate() {
            let slot = offset + index as u32;
            egress.table_id = FIRST_ROUTING_TABLE + slot;
            egress.ip_rule_priority = FIRST_IP_RULE_PRIORITY + slot;
        }

        let overlaps_active_resources = candidate.egresses.iter().any(|candidate_egress| {
            occupied.iter().any(|active| {
                active.egresses.iter().any(|active_egress| {
                    candidate_egress.table_id == active_egress.table_id
                        || candidate_egress.ip_rule_priority == active_egress.ip_rule_priority
                })
            })
        });
        if overlaps_active_resources {
            continue;
        }

        match ensure_policy_slots_available(&candidate) {
            Ok(()) => {
                plan.egresses = candidate.egresses;
                return Ok(());
            }
            Err(LinuxError::Conflict { resource, .. })
                if candidate.egresses.iter().any(|egress| {
                    resource.ends_with(&format!("rule priority {}", egress.ip_rule_priority))
                        || resource.ends_with(&format!("route table {}", egress.table_id))
                }) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    Err(LinuxError::Conflict {
        resource: "dynamic policy-routing slots".to_owned(),
        details: "no unused route-table and rule-priority pair was found".to_owned(),
    })
}

/// Install only egress routes and fwmark rules. Socket-mark rules are deliberately
/// left untouched so they remain continuously active during a plan transition.
pub fn apply_egress_policy_routing(plan: &RoutingPlan) -> Result<(), LinuxError> {
    ensure_policy_slots_available(plan)?;
    apply_egress_policy_routing_with(plan, &mut run)
}

fn apply_egress_policy_routing_with<F>(
    plan: &RoutingPlan,
    run_command: &mut F,
) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    // Treat the complete multi-egress install as one transaction. Keep the
    // runner injectable so every partial-apply and rollback boundary is tested.
    let install_result = (|| -> Result<(), LinuxError> {
        for egress in &plan.egresses {
            for &family in plan.ip_families_for_egress(egress) {
                let priority = egress.ip_rule_priority.to_string();
                let mark = format!("0x{:x}", egress.mark);
                let table = egress.table_id.to_string();
                let stale_rule = [
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
                ];
                run_ip_cleanup_with(&stale_rule, run_command)?;
                run_command(
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
                )?;
                run_command(
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
                )?;
            }
        }
        Ok(())
    })();

    match install_result {
        Ok(()) => Ok(()),
        Err(operation) => match remove_egress_policy_routing_with(plan, run_command) {
            Ok(()) => Err(operation),
            Err(rollback) => Err(LinuxError::Rollback {
                operation: operation.to_string(),
                rollback: rollback.to_string(),
            }),
        },
    }
}

fn run_ip_cleanup_with<F>(args: &[String], run_command: &mut F) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    match run_command("ip", args) {
        Ok(()) => Ok(()),
        Err(LinuxError::Command { stderr, .. })
            if stderr.contains("No such file or directory")
                || stderr.contains("No such process")
                || stderr.contains("FIB table does not exist") =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Remove only egress rules/routes tagged with vpn-relay's protocol marker.
/// Missing resources are already clean; any other failure is reported.
fn remove_egress_policy_routing_with<F>(
    plan: &RoutingPlan,
    run_command: &mut F,
) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    let mut failures = Vec::new();
    for egress in &plan.egresses {
        for &family in plan.ip_policy_families() {
            let rule = [
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
            ];
            if let Err(error) = run_ip_cleanup_with(&rule, run_command) {
                failures.push(error.to_string());
            }

            let route = [
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
            ];
            if let Err(error) = run_ip_cleanup_with(&route, run_command) {
                failures.push(error.to_string());
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(LinuxError::Cleanup(failures.join("; ")))
    }
}

pub fn remove_egress_policy_routing(plan: &RoutingPlan) -> Result<(), LinuxError> {
    remove_egress_policy_routing_with(plan, &mut run)
}

pub fn apply_policy_routing(plan: &RoutingPlan) -> Result<(), LinuxError> {
    ensure_policy_slots_available(plan)?;
    apply_policy_routing_with(plan, &mut run)
}

fn apply_policy_routing_with<F>(plan: &RoutingPlan, run_command: &mut F) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    let install_result = (|| -> Result<(), LinuxError> {
        // Remove every stale socket rule before installing any replacement.
        // Interleaving delete/add per family could leave a partially refreshed
        // policy when a later stale-rule deletion fails.
        for mark in &plan.socket_marks {
            for &family in plan.ip_policy_families() {
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
                run_ip_cleanup_with(&args, run_command)?;
            }
        }
        // Keep marked encrypted UDP transport on the main table.
        for mark in &plan.socket_marks {
            for &family in plan.ip_policy_families() {
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
                run_command("ip", &args)?;
            }
        }
        apply_egress_policy_routing_with(plan, run_command)
    })();

    match install_result {
        Ok(()) => Ok(()),
        // Egress installation owns its rollback. Only unwind socket rules
        // here, avoiding duplicate route/rule deletions by the outer layer.
        Err(operation) => match remove_socket_mark_rules_with(plan, run_command) {
            Ok(()) => Err(operation),
            Err(rollback) => Err(LinuxError::Rollback {
                operation: operation.to_string(),
                rollback: rollback.to_string(),
            }),
        },
    }
}

fn remove_socket_mark_rules_with<F>(
    plan: &RoutingPlan,
    run_command: &mut F,
) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    let mut failures = Vec::new();
    for mark in &plan.socket_marks {
        for &family in plan.ip_policy_families() {
            let args = [
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
            if let Err(error) = run_ip_cleanup_with(&args, run_command) {
                failures.push(error.to_string());
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(LinuxError::Cleanup(failures.join("; ")))
    }
}

pub fn remove_policy_routing(plan: &RoutingPlan) -> Result<(), LinuxError> {
    remove_policy_routing_with(plan, &mut run)
}

fn remove_policy_routing_with<F>(plan: &RoutingPlan, run_command: &mut F) -> Result<(), LinuxError>
where
    F: FnMut(&str, &[String]) -> Result<(), LinuxError>,
{
    let mut failures = Vec::new();
    if let Err(error) = remove_socket_mark_rules_with(plan, run_command) {
        failures.push(error.to_string());
    }
    if let Err(error) = remove_egress_policy_routing_with(plan, run_command) {
        failures.push(error.to_string());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(LinuxError::Cleanup(failures.join("; ")))
    }
}

pub fn interface_index(name: &str) -> Result<u32, LinuxError> {
    let name_c = std::ffi::CString::new(name).map_err(|_| LinuxError::Conflict {
        resource: format!("network interface '{name}'"),
        details: "interface name contains an interior NUL byte".into(),
    })?;
    let index = unsafe { libc::if_nametoindex(name_c.as_ptr()) };
    if index == 0 {
        return Err(LinuxError::Command {
            program: "if_nametoindex".into(),
            status: "failed".into(),
            stderr: std::io::Error::last_os_error().to_string(),
        });
    }
    Ok(index)
}

/// Resolve an interface index back to its current name in this process' network namespace.
/// This reverse lookup is used by durable forwarding-state recovery to avoid
/// restoring sysctls onto a different link that later reused an interface name.
pub fn interface_name(index: u32) -> Result<String, LinuxError> {
    if index == 0 {
        return Err(LinuxError::Conflict {
            resource: "network interface index 0".into(),
            details: "zero is not a valid Linux interface index".into(),
        });
    }
    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    let result = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
    if result.is_null() {
        return Err(LinuxError::Command {
            program: "if_indextoname".into(),
            status: "failed".into(),
            stderr: std::io::Error::last_os_error().to_string(),
        });
    }
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) };
    Ok(name.to_string_lossy().into_owned())
}

/// Verify both directions of the name/index mapping. A matching name alone is
/// insufficient because Linux may recycle an ifindex after a link disappears.
pub fn verify_interface_identity(name: &str, expected_index: u32) -> Result<(), LinuxError> {
    verify_interface_identity_with(name, expected_index, interface_index, interface_name)
}

fn verify_interface_identity_with(
    name: &str,
    expected_index: u32,
    mut index_for_name: impl FnMut(&str) -> Result<u32, LinuxError>,
    mut name_for_index: impl FnMut(u32) -> Result<String, LinuxError>,
) -> Result<(), LinuxError> {
    let current_index = index_for_name(name)?;
    let current_name = name_for_index(expected_index)?;
    if current_index != expected_index || current_name != name {
        return Err(LinuxError::Conflict {
            resource: format!("network interface '{name}' (ifindex {expected_index})"),
            details: format!(
                "interface identity changed: name resolves to ifindex {current_index}, while saved ifindex resolves to '{current_name}'"
            ),
        });
    }
    Ok(())
}

const NETLINK_ROUTE: libc::c_int = 0;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLMSG_ERROR: u16 = 2;
const NLM_F_CAPPED: u16 = 0x100;
const NLM_F_ACK_TLVS: u16 = 0x200;
const NLMSGERR_ATTR_MSG: u16 = 1;
const SOL_NETLINK: libc::c_int = 270;
const NETLINK_EXT_ACK: libc::c_int = 11;
const IFLA_AF_SPEC: u16 = 26;
const IFLA_INET_CONF: u16 = 1;
const IPV4_DEVCONF_FORWARDING: u16 = 1;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);
const AF_INET_ATTR: u16 = libc::AF_INET as u16;
#[cfg(test)]
const IPV4_DEVCONF_MAX: usize = 33;

#[repr(C)]
struct NetlinkAddress {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

fn align_netlink(length: usize) -> usize {
    (length + 3) & !3
}

fn append_netlink_attribute(buffer: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let length = 4 + payload.len();
    buffer.extend_from_slice(&(length as u16).to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(align_netlink(buffer.len()), 0);
}

fn build_link_message(
    message_type: u16,
    flags: u16,
    ifindex: u32,
    sequence: u32,
    attributes: &[u8],
) -> Result<Vec<u8>, LinuxError> {
    let index = i32::try_from(ifindex).map_err(|_| LinuxError::Conflict {
        resource: format!("network interface index {ifindex}"),
        details: "ifindex does not fit the rtnetlink interface index field".into(),
    })?;
    let mut message = Vec::with_capacity(32 + attributes.len());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.push(libc::AF_UNSPEC as u8);
    message.push(0);
    message.extend_from_slice(&0u16.to_ne_bytes());
    message.extend_from_slice(&index.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    message.extend_from_slice(attributes);
    let length = u32::try_from(message.len()).map_err(|_| LinuxError::Conflict {
        resource: "rtnetlink message".into(),
        details: "message length overflow".into(),
    })?;
    message[0..4].copy_from_slice(&length.to_ne_bytes());
    Ok(message)
}

fn netlink_extended_ack(response: &[u8], offset: usize, length: usize) -> Option<String> {
    // NLMSG_ERROR contains the outer header, errno, and the original
    // nlmsghdr before any optional extended-ACK attributes.
    let end = offset.checked_add(length)?;
    if length < 36 || end > response.len() {
        return None;
    }
    let flags = u16::from_ne_bytes(response[offset + 6..offset + 8].try_into().ok()?);
    if flags & NLM_F_ACK_TLVS == 0 {
        return None;
    }
    let original_length =
        u32::from_ne_bytes(response[offset + 20..offset + 24].try_into().ok()?) as usize;
    if original_length < 16 {
        return None;
    }
    let original_payload_length = if flags & NLM_F_CAPPED != 0 {
        16
    } else {
        original_length
    };
    let attributes_offset = offset.checked_add(16 + align_netlink(4 + original_payload_length))?;
    let end = offset.checked_add(length)?;
    if attributes_offset > end {
        return None;
    }
    let mut attributes = &response[attributes_offset..end];
    while !attributes.is_empty() {
        if attributes.len() < 4 {
            return None;
        }
        let attribute_length = u16::from_ne_bytes(attributes[0..2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(attributes[2..4].try_into().ok()?) & NLA_TYPE_MASK;
        if attribute_length < 4 || attribute_length > attributes.len() {
            return None;
        }
        if kind == NLMSGERR_ATTR_MSG {
            let message = attributes[4..attribute_length]
                .split(|byte| *byte == 0)
                .next()?;
            let message = String::from_utf8_lossy(message).trim().to_owned();
            if !message.is_empty() {
                return Some(message);
            }
            return None;
        }
        let aligned = align_netlink(attribute_length);
        if aligned > attributes.len() {
            return None;
        }
        attributes = &attributes[aligned..];
    }
    None
}

fn netlink_request(
    ifindex: u32,
    message_type: u16,
    flags: u16,
    attributes: &[u8],
) -> Result<Vec<u8>, LinuxError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    static NEXT_SEQUENCE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let sequence = NEXT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let message = build_link_message(message_type, flags, ifindex, sequence, attributes)?;
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(LinuxError::Spawn {
            program: "rtnetlink socket".into(),
            source: std::io::Error::last_os_error(),
        });
    }
    let socket = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    // Extended ACKs provide kernel-side context (for example, the rejected
    // attribute) when supported. Keep the request functional on older kernels.
    let enabled: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_NETLINK,
            NETLINK_EXT_ACK,
            &enabled as *const libc::c_int as *const libc::c_void,
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        );
    }
    let local = NetlinkAddress {
        family: libc::AF_NETLINK as u16,
        pad: 0,
        pid: 0,
        groups: 0,
    };
    let bind_result = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            &local as *const NetlinkAddress as *const libc::sockaddr,
            std::mem::size_of::<NetlinkAddress>() as libc::socklen_t,
        )
    };
    if bind_result < 0 {
        return Err(LinuxError::Command {
            program: "rtnetlink bind".into(),
            status: "failed".into(),
            stderr: std::io::Error::last_os_error().to_string(),
        });
    }
    let timeout = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    let timeout_result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if timeout_result < 0 {
        return Err(LinuxError::Command {
            program: "rtnetlink receive timeout".into(),
            status: "failed".into(),
            stderr: std::io::Error::last_os_error().to_string(),
        });
    }
    let kernel = NetlinkAddress {
        family: libc::AF_NETLINK as u16,
        pad: 0,
        pid: 0,
        groups: 0,
    };
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            message.as_ptr() as *const libc::c_void,
            message.len(),
            0,
            &kernel as *const NetlinkAddress as *const libc::sockaddr,
            std::mem::size_of::<NetlinkAddress>() as libc::socklen_t,
        )
    };
    if sent < 0 || sent as usize != message.len() {
        return Err(LinuxError::Command {
            program: "rtnetlink send".into(),
            status: "failed".into(),
            stderr: std::io::Error::last_os_error().to_string(),
        });
    }
    let mut response = vec![0u8; 16 * 1024];
    loop {
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                response.as_mut_ptr() as *mut libc::c_void,
                response.len(),
                0,
            )
        };
        if received < 0 {
            return Err(LinuxError::Command {
                program: "rtnetlink receive".into(),
                status: "failed".into(),
                stderr: std::io::Error::last_os_error().to_string(),
            });
        }
        let received = received as usize;
        let mut offset = 0usize;
        while offset + 16 <= received {
            let length =
                u32::from_ne_bytes(response[offset..offset + 4].try_into().unwrap()) as usize;
            if length < 16 || offset + length > received {
                return Err(LinuxError::Conflict {
                    resource: "rtnetlink response".into(),
                    details: "kernel returned a malformed netlink message".into(),
                });
            }
            let kind = u16::from_ne_bytes(response[offset + 4..offset + 6].try_into().unwrap());
            let seq = u32::from_ne_bytes(response[offset + 8..offset + 12].try_into().unwrap());
            if seq == sequence {
                if kind == NLMSG_ERROR {
                    if length < 20 {
                        return Err(LinuxError::Conflict {
                            resource: "rtnetlink acknowledgement".into(),
                            details: "kernel returned a truncated netlink error".into(),
                        });
                    }
                    let code =
                        i32::from_ne_bytes(response[offset + 16..offset + 20].try_into().unwrap());
                    if code == 0 {
                        return Ok(response[..received].to_vec());
                    }
                    let errno = std::io::Error::from_raw_os_error(-code).to_string();
                    let extended = netlink_extended_ack(&response, offset, length);
                    return Err(LinuxError::Command {
                        program: "rtnetlink request".into(),
                        status: "kernel rejected request".into(),
                        stderr: extended
                            .map_or(errno.clone(), |message| format!("{errno}: {message}")),
                    });
                }
                if message_type == RTM_GETLINK && kind == RTM_NEWLINK {
                    return Ok(response[offset..offset + length].to_vec());
                }
            }
            offset += align_netlink(length);
        }
    }
}

fn parse_link_ipv4_forwarding(response: &[u8], expected_ifindex: u32) -> Result<bool, LinuxError> {
    fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, LinuxError> {
        let mut result = Vec::new();
        while !bytes.is_empty() {
            if bytes.len() < 4 {
                return Err(LinuxError::Conflict {
                    resource: "rtnetlink link attributes".into(),
                    details: "truncated attribute header".into(),
                });
            }
            let length = u16::from_ne_bytes(bytes[0..2].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(bytes[2..4].try_into().unwrap()) & !NLA_F_NESTED;
            if length < 4 || length > bytes.len() {
                return Err(LinuxError::Conflict {
                    resource: "rtnetlink link attributes".into(),
                    details: "invalid attribute length".into(),
                });
            }
            result.push((kind, &bytes[4..length]));
            let aligned = align_netlink(length);
            if aligned > bytes.len() {
                if length != bytes.len() {
                    return Err(LinuxError::Conflict {
                        resource: "rtnetlink link attributes".into(),
                        details: "invalid attribute alignment".into(),
                    });
                }
                break;
            }
            bytes = &bytes[aligned..];
        }
        Ok(result)
    }
    if response.len() < 32 {
        return Err(LinuxError::Conflict {
            resource: "rtnetlink link response".into(),
            details: "truncated RTM_NEWLINK response".into(),
        });
    }
    let response_ifindex = i32::from_ne_bytes(response[20..24].try_into().unwrap());
    if response_ifindex <= 0 || response_ifindex as u32 != expected_ifindex {
        return Err(LinuxError::Conflict {
            resource: format!("IPv4 forwarding interface index {expected_ifindex}"),
            details: format!("RTM_GETLINK response identifies ifindex {response_ifindex}"),
        });
    }
    let link_attributes = attributes(&response[32..])?;
    let af_spec = link_attributes
        .iter()
        .find(|(kind, _)| *kind == IFLA_AF_SPEC)
        .ok_or_else(|| LinuxError::Conflict {
            resource: "IPv4 link configuration".into(),
            details: "kernel omitted IFLA_AF_SPEC".into(),
        })?;
    let families = attributes(af_spec.1)?;
    let inet = families
        .iter()
        .find(|(kind, _)| *kind == AF_INET_ATTR)
        .ok_or_else(|| LinuxError::Conflict {
            resource: "IPv4 link configuration".into(),
            details: "kernel omitted AF_INET configuration".into(),
        })?;
    let inet_attributes = attributes(inet.1)?;
    let conf = inet_attributes
        .iter()
        .find(|(kind, _)| *kind == IFLA_INET_CONF)
        .ok_or_else(|| LinuxError::Conflict {
            resource: "IPv4 link configuration".into(),
            details: "kernel omitted IFLA_INET_CONF".into(),
        })?;
    if conf.1.len() < 4 {
        return Err(LinuxError::Conflict {
            resource: "IPv4 link configuration".into(),
            details: "kernel omitted the IPv4 forwarding devconf value".into(),
        });
    }
    match u32::from_ne_bytes(conf.1[0..4].try_into().unwrap()) {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(LinuxError::Conflict {
            resource: "IPv4 forwarding".into(),
            details: format!("kernel returned unexpected forwarding value {value}"),
        }),
    }
}

/// Read IPv4 forwarding by ifindex using RTM_GETLINK (no name-based sysctl lookup).
pub fn ipv4_interface_forwarding(ifindex: u32) -> Result<bool, LinuxError> {
    if ifindex == 0 {
        return Err(LinuxError::Conflict {
            resource: "IPv4 forwarding interface".into(),
            details: "ifindex 0 is not valid".into(),
        });
    }
    let response = netlink_request(ifindex, RTM_GETLINK, NLM_F_REQUEST, &[])?;
    parse_link_ipv4_forwarding(&response, ifindex)
}

/// Set IPv4 forwarding by ifindex using RTM_NEWLINK and verify it with RTM_GETLINK.
///
/// The name/index identity guard is deliberately performed after constructing
/// the netlink attributes and immediately before RTM_NEWLINK. It narrows the
/// userspace race window but cannot make the identity check atomic with the
/// kernel's later ifindex lookup. The post-ACK readback is followed by another
/// identity check so a replacement link is not silently accepted as the owner.
pub fn set_ipv4_interface_forwarding(
    name: &str,
    ifindex: u32,
    enabled: bool,
) -> Result<(), LinuxError> {
    set_ipv4_interface_forwarding_with(
        name,
        ifindex,
        enabled,
        verify_interface_identity,
        netlink_request,
        ipv4_interface_forwarding,
    )
}

fn set_ipv4_interface_forwarding_with(
    name: &str,
    ifindex: u32,
    enabled: bool,
    mut verify: impl FnMut(&str, u32) -> Result<(), LinuxError>,
    mut request: impl FnMut(u32, u16, u16, &[u8]) -> Result<Vec<u8>, LinuxError>,
    mut readback: impl FnMut(u32) -> Result<bool, LinuxError>,
) -> Result<(), LinuxError> {
    if ifindex == 0 {
        return Err(LinuxError::Conflict {
            resource: "IPv4 forwarding interface".into(),
            details: "ifindex 0 is not valid".into(),
        });
    }
    let value = u32::from(enabled);
    let mut conf = Vec::new();
    append_netlink_attribute(&mut conf, IPV4_DEVCONF_FORWARDING, &value.to_ne_bytes());
    let mut inet = Vec::new();
    append_netlink_attribute(&mut inet, IFLA_INET_CONF | NLA_F_NESTED, &conf);
    let mut af_spec = Vec::new();
    append_netlink_attribute(&mut af_spec, AF_INET_ATTR | NLA_F_NESTED, &inet);
    let mut attributes = Vec::new();
    append_netlink_attribute(&mut attributes, IFLA_AF_SPEC | NLA_F_NESTED, &af_spec);

    // RTM_NEWLINK is addressed by ifindex, so check the saved name/index pair
    // as late as possible before the kernel resolves that index.
    verify(name, ifindex)?;
    request(
        ifindex,
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK,
        &attributes,
    )?;
    let actual = readback(ifindex)?;
    verify(name, ifindex)?;
    if actual != enabled {
        return Err(LinuxError::Conflict {
            resource: format!("IPv4 forwarding on ifindex {ifindex}"),
            details: format!(
                "kernel acknowledged update but reports forwarding={}",
                u8::from(actual)
            ),
        });
    }
    Ok(())
}

fn validate_ipv4_interface_addresses(name: &str, addresses: &[String]) -> Result<(), LinuxError> {
    for address in addresses {
        if address.contains(':') {
            return Err(LinuxError::Conflict {
                resource: format!("IPv6 address {address} on interface {name}"),
                details: "vpn-relay supports IPv4 interface addresses only".to_owned(),
            });
        }
    }
    Ok(())
}

pub fn configure_interface(name: &str, mtu: u16, addresses: &[String]) -> Result<(), LinuxError> {
    validate_ipv4_interface_addresses(name, addresses)?;
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
        run(
            "ip",
            &[
                "-4".into(),
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

    fn cleanup_test_plan() -> RoutingPlan {
        RoutingPlan {
            nft_family: "inet".into(),
            nft_table: "vpn_relay".into(),
            managed_interfaces: vec!["wg0".into(), "awg0".into()],
            egresses: vec![crate::routing::EgressPlan {
                interface: "awg0".into(),
                mark: 0x8000_0001,
                table_id: 10001,
                ip_rule_priority: 10001,
            }],
            decisions: Vec::new(),
            input_rules: Vec::new(),
            output_rules: Vec::new(),
            socket_marks: Vec::new(),
            ipv6_drop_interfaces: Vec::new(),
            interface_indices: None,
        }
    }

    #[test]
    fn socket_fwmark_apply_failure_at_each_install_boundary_rolls_back_all_rules() {
        let plan = {
            let mut plan = cleanup_test_plan();
            plan.socket_marks = vec![0x1000_0001, 0x1000_0002];
            plan
        };

        for failure_position in 1..=2 {
            let mut calls = Vec::new();
            let mut add_count = 0;
            let mut failure_index = None;
            let result = apply_policy_routing_with(&plan, &mut |_program, args| {
                calls.push(args.to_vec());
                if args.get(2).is_some_and(|part| part == "add") {
                    add_count += 1;
                    if add_count == failure_position {
                        failure_index = Some(calls.len() - 1);
                        return Err(LinuxError::Command {
                            program: format!("ip {}", args.join(" ")),
                            status: "exit status 2".into(),
                            stderr: format!(
                                "injected socket install failure at step {failure_position}"
                            ),
                        });
                    }
                }
                Ok(())
            });

            assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
                if stderr.contains(&format!("step {failure_position}"))));
            let rollback = &calls[failure_index.expect("failure was injected")..];
            let cleanup = rollback
                .iter()
                .filter(|args| {
                    args.get(2).is_some_and(|part| part == "del")
                        && args.get(4).is_some_and(|part| part == "9000")
                })
                .count();
            assert_eq!(
                cleanup, 2,
                "failure at socket install step {failure_position} must roll back every socket mark"
            );
        }
    }

    #[test]
    fn socket_fwmark_stale_rule_cleanup_failure_aborts_install_and_rolls_back() {
        let mut plan = cleanup_test_plan();
        plan.socket_marks = vec![0x1000_0001, 0x1000_0002];

        for failure_position in 1..=2 {
            let mut calls = Vec::new();
            let mut stale_cleanup_attempts = 0;
            let mut failure_injected = false;
            let result = apply_policy_routing_with(&plan, &mut |_program, args| {
                calls.push(args.to_vec());
                let is_socket_rule = args.get(1).is_some_and(|part| part == "rule")
                    && args.get(4).is_some_and(|part| part == "9000");
                if is_socket_rule
                    && args.get(2).is_some_and(|part| part == "del")
                    && !failure_injected
                {
                    stale_cleanup_attempts += 1;
                    if stale_cleanup_attempts == failure_position {
                        failure_injected = true;
                        return Err(LinuxError::Command {
                            program: format!("ip {}", args.join(" ")),
                            status: "exit status 2".into(),
                            stderr: format!(
                                "injected stale socket rule cleanup failure at step {failure_position}"
                            ),
                        });
                    }
                }
                Ok(())
            });

            assert!(
                failure_injected,
                "failure point {failure_position} was not reached"
            );
            assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
                if stderr.contains(&format!("step {failure_position}"))));
            assert!(
                !calls.iter().any(|args| {
                    args.get(1).is_some_and(|part| part == "rule")
                        && args.get(2).is_some_and(|part| part == "add")
                        && args.get(3).is_some_and(|part| part == "priority")
                        && args.get(4).is_some_and(|part| part == "9000")
                        && args.get(5).is_some_and(|part| part == "fwmark")
                        && args.get(6).is_some_and(|value| {
                            plan.socket_marks
                                .iter()
                                .any(|mark| value == &format!("0x{mark:x}"))
                        })
                        && args.get(7).is_some_and(|part| part == "lookup")
                        && args.get(8).is_some_and(|part| part == "main")
                        && args.get(9).is_some_and(|part| part == "protocol")
                        && args.get(10).is_some_and(|part| part == ROUTING_PROTOCOL)
                }),
                "socket rules must not be installed after stale-rule cleanup fails; calls: {calls:?}"
            );

            let rollback = calls
                .iter()
                .filter(|args| {
                    args.get(1).is_some_and(|part| part == "rule")
                        && args.get(2).is_some_and(|part| part == "del")
                        && args.get(4).is_some_and(|part| part == "9000")
                })
                .count();
            assert_eq!(
                rollback,
                failure_position + 2,
                "failed pre-cleanup plus rollback must attempt every socket mark"
            );
        }
    }

    #[test]
    fn socket_fwmark_cleanup_attempts_every_rule_after_failures() {
        let mut plan = cleanup_test_plan();
        plan.socket_marks = vec![0x1000_0001, 0x1000_0002];
        let mut cleanup_attempts = 0;
        let result = remove_policy_routing_with(&plan, &mut |_program, args| {
            if args.get(2).is_some_and(|part| part == "del")
                && args.get(4).is_some_and(|part| part == "9000")
            {
                cleanup_attempts += 1;
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: "injected socket cleanup failure".into(),
                });
            }
            Ok(())
        });

        assert_eq!(cleanup_attempts, 2);
        assert!(matches!(result, Err(LinuxError::Cleanup(message))
            if message.matches("injected socket cleanup failure").count() == 2));
    }

    #[test]
    fn egress_stale_rule_cleanup_failure_aborts_install_and_rolls_back() {
        let plan = cleanup_test_plan();

        for failure_position in 1..=1 {
            let mut calls = Vec::new();
            let mut stale_cleanup_attempts = 0;
            let mut failure_injected = false;
            let result = apply_egress_policy_routing_with(&plan, &mut |_program, args| {
                calls.push(args.to_vec());
                let is_stale_delete = args.get(2).is_some_and(|part| part == "del")
                    && (args.get(1).is_some_and(|part| part == "rule")
                        || args.get(1).is_some_and(|part| part == "route"));
                if is_stale_delete && !failure_injected {
                    stale_cleanup_attempts += 1;
                    if stale_cleanup_attempts == failure_position {
                        failure_injected = true;
                        return Err(LinuxError::Command {
                            program: format!("ip {}", args.join(" ")),
                            status: "exit status 2".into(),
                            stderr: format!(
                                "injected stale egress cleanup failure at step {failure_position}"
                            ),
                        });
                    }
                }
                Ok(())
            });

            assert!(
                failure_injected,
                "failure point {failure_position} was not reached"
            );
            assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
                if stderr.contains(&format!("step {failure_position}"))));
            assert!(
                !calls.iter().any(|args| {
                    args.get(2).is_some_and(|part| part == "replace")
                        || args.get(2).is_some_and(|part| part == "add")
                }),
                "egress routes and rules must not be installed after stale cleanup fails"
            );

            let cleanup = calls
                .iter()
                .filter(|args| {
                    args.get(2).is_some_and(|part| part == "del")
                        && (args.get(1).is_some_and(|part| part == "rule")
                            || args.get(1).is_some_and(|part| part == "route"))
                })
                .count();
            assert_eq!(
                cleanup,
                failure_position + 2,
                "failed pre-cleanup plus rollback must attempt all IPv4 egress resources"
            );
        }
    }

    #[test]
    fn egress_apply_failure_at_each_ipv4_install_boundary_rolls_back_all_resources() {
        let plan = cleanup_test_plan();
        let failure_points = [("-4", "route", "replace"), ("-4", "rule", "add")];

        for (failed_family, failed_kind, failed_operation) in failure_points {
            let mut calls = Vec::new();
            let mut injected = false;
            let result = apply_egress_policy_routing_with(&plan, &mut |_program, args| {
                calls.push(args.to_vec());
                if !injected
                    && args.first().is_some_and(|family| family == failed_family)
                    && args.get(1).is_some_and(|kind| kind == failed_kind)
                    && args
                        .get(2)
                        .is_some_and(|operation| operation == failed_operation)
                {
                    injected = true;
                    return Err(LinuxError::Command {
                        program: format!("ip {}", args.join(" ")),
                        status: "exit status 2".into(),
                        stderr: format!(
                            "injected {failed_family} {failed_kind} {failed_operation} failure"
                        ),
                    });
                }
                Ok(())
            });

            assert!(
                injected,
                "failure point {failed_family} {failed_kind} {failed_operation} was not reached"
            );
            assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
                if stderr.contains(&format!("injected {failed_family} {failed_kind} {failed_operation} failure"))));

            let cleanup = &calls[calls.len() - 2..];
            assert_eq!(cleanup.len(), 2);
            assert!(cleanup
                .iter()
                .any(|args| args.first().is_some_and(|value| value == "-4")
                    && args.get(1).is_some_and(|value| value == "rule")
                    && args.get(2).is_some_and(|value| value == "del")));
            assert!(cleanup
                .iter()
                .any(|args| args.first().is_some_and(|value| value == "-4")
                    && args.get(1).is_some_and(|value| value == "route")
                    && args.get(2).is_some_and(|value| value == "del")));
        }
    }

    #[test]
    fn egress_apply_reports_rollback_failure_without_hiding_install_failure() {
        let plan = cleanup_test_plan();
        let mut calls = 0usize;
        let result = apply_egress_policy_routing_with(&plan, &mut |_program, args| {
            calls += 1;
            if args.get(2).is_some_and(|part| part == "add") {
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: "injected install failure".into(),
                });
            }
            if calls > 3 {
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: "injected rollback failure".into(),
                });
            }
            Ok(())
        });

        assert!(
            matches!(result, Err(LinuxError::Rollback { operation, rollback })
                if operation.contains("injected install failure")
                    && rollback.contains("injected rollback failure"))
        );
    }

    #[test]
    fn egress_apply_aggregates_every_rollback_cleanup_failure() {
        let plan = cleanup_test_plan();
        let mut calls = Vec::new();
        let mut failure_index = None;
        let result = apply_egress_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            if failure_index.is_none()
                && args.get(1).is_some_and(|part| part == "rule")
                && args.get(2).is_some_and(|part| part == "add")
            {
                failure_index = Some(calls.len() - 1);
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: "injected primary install failure".into(),
                });
            }
            if failure_index.is_some() {
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: format!("injected rollback cleanup failure: {}", args.join(" ")),
                });
            }
            Ok(())
        });

        let cleanup = &calls[failure_index.expect("install failure injected") + 1..];
        assert_eq!(cleanup.len(), 2, "every IPv4 resource cleanup must run");
        assert!(cleanup
            .iter()
            .all(|args| args.get(2).is_some_and(|op| op == "del")));
        assert!(
            matches!(result, Err(LinuxError::Rollback { operation, rollback })
                if operation.contains("injected primary install failure")
                    && rollback.matches("injected rollback cleanup failure").count() == 2)
        );
    }

    #[test]
    fn egress_cleanup_attempts_both_ipv4_resources_after_command_failures() {
        let plan = cleanup_test_plan();
        let mut calls = Vec::new();
        let result = remove_egress_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: "exit status 2".into(),
                stderr: "RTNETLINK answers: Operation not permitted".into(),
            })
        });

        assert_eq!(
            calls.len(),
            2,
            "IPv4 route and rule cleanup must both be attempted"
        );
        assert!(matches!(result, Err(LinuxError::Cleanup(message))
            if message.matches("Operation not permitted").count() == 2));
        assert!(calls
            .iter()
            .any(|args| args.first().is_some_and(|family| family == "-4")));
        assert!(calls
            .iter()
            .any(|args| args.get(1).is_some_and(|kind| kind == "rule")));
        assert!(calls
            .iter()
            .any(|args| args.get(1).is_some_and(|kind| kind == "route")));
    }

    #[test]
    fn egress_cleanup_treats_missing_resources_as_already_removed() {
        let plan = cleanup_test_plan();
        let mut calls = 0;
        let result = remove_egress_policy_routing_with(&plan, &mut |_program, _args| {
            calls += 1;
            Err(LinuxError::Command {
                program: "ip".into(),
                status: "exit status 2".into(),
                stderr: "RTNETLINK answers: No such process".into(),
            })
        });

        assert!(result.is_ok());
        assert_eq!(calls, 2, "cleanup must inspect both IPv4 resources");
    }

    #[test]
    fn egress_cleanup_aggregates_failures_across_multiple_interfaces() {
        let mut plan = cleanup_test_plan();
        plan.egresses.push(crate::routing::EgressPlan {
            interface: "wg1".into(),
            mark: 0x8000_0002,
            table_id: 10002,
            ip_rule_priority: 10002,
        });
        let mut calls = Vec::new();
        let result = remove_egress_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            Err(LinuxError::Command {
                program: format!("ip {}", args.join(" ")),
                status: "exit status 2".into(),
                stderr: format!("injected cleanup failure for {}", args.join(" ")),
            })
        });

        assert_eq!(
            calls.len(),
            4,
            "both IPv4 resources on both interfaces must be attempted"
        );
        assert!(matches!(result, Err(LinuxError::Cleanup(message))
            if message.matches("injected cleanup failure").count() == 4));
        for interface in ["awg0", "wg1"] {
            let expected_mark = if interface == "awg0" {
                "0x80000001"
            } else {
                "0x80000002"
            };
            assert!(calls.iter().any(|args| {
                args.get(1).is_some_and(|v| v == "rule")
                    && args.get(2).is_some_and(|v| v == "del")
                    && args.iter().any(|v| v == expected_mark)
            }));
            assert!(calls.iter().any(|args| {
                args.get(1).is_some_and(|v| v == "route")
                    && args.get(2).is_some_and(|v| v == "del")
                    && args.iter().any(|v| v == interface)
            }));
        }
    }

    #[test]
    fn policy_apply_aggregates_socket_rollback_failures_after_egress_rollback() {
        let mut plan = cleanup_test_plan();
        plan.socket_marks = vec![0x1000_0001, 0x1000_0002];
        let mut calls = Vec::new();
        let mut install_failure_index = None;
        let result = apply_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            if install_failure_index.is_none()
                && args.get(1).is_some_and(|part| part == "rule")
                && args.get(2).is_some_and(|part| part == "add")
                && args.first().is_some_and(|family| family == "-4")
                && args.get(4).is_some_and(|priority| priority == "10001")
            {
                install_failure_index = Some(calls.len() - 1);
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: "injected egress installation failure".into(),
                });
            }
            if let Some(index) = install_failure_index {
                let after_failure = &calls[index + 1..];
                let socket_cleanup_started = after_failure.iter().any(|call| {
                    call.get(1).is_some_and(|part| part == "rule")
                        && call.get(2).is_some_and(|part| part == "del")
                        && call.get(4).is_some_and(|priority| priority == "9000")
                });
                if socket_cleanup_started {
                    return Err(LinuxError::Command {
                        program: format!("ip {}", args.join(" ")),
                        status: "exit status 2".into(),
                        stderr: "injected socket rollback failure".into(),
                    });
                }
            }
            Ok(())
        });

        let failure_index = install_failure_index.expect("egress install failure injected");
        let rollback_calls = &calls[failure_index + 1..];
        let egress_cleanup = rollback_calls
            .iter()
            .filter(|args| {
                args.get(2).is_some_and(|operation| operation == "del")
                    && (args.get(1).is_some_and(|kind| kind == "route")
                        || args.get(4).is_some_and(|priority| priority == "10001"))
            })
            .count();
        let socket_cleanup = rollback_calls
            .iter()
            .filter(|args| {
                args.get(4).is_some_and(|priority| priority == "9000")
                    && args.get(2).is_some_and(|operation| operation == "del")
            })
            .count();

        assert_eq!(
            egress_cleanup, 2,
            "nested IPv4 egress rollback must complete first"
        );
        assert_eq!(
            socket_cleanup, 2,
            "outer rollback must attempt every socket mark"
        );
        assert!(
            matches!(result, Err(LinuxError::Rollback { operation, rollback })
                if operation.contains("injected egress installation failure")
                    && rollback.matches("injected socket rollback failure").count() == 2)
        );
    }

    #[test]
    fn nested_policy_rollback_does_not_repeat_egress_cleanup() {
        let mut plan = cleanup_test_plan();
        plan.socket_marks = vec![0x1000_0001];
        let mut calls = Vec::new();
        let mut install_failed = false;
        let mut failure_index = None;
        let result = apply_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            if !install_failed
                && args.get(1).is_some_and(|v| v == "rule")
                && args.get(2).is_some_and(|v| v == "add")
                && args.get(4).is_some_and(|v| v == "10001")
                && args.first().is_some_and(|v| v == "-4")
            {
                install_failed = true;
                failure_index = Some(calls.len() - 1);
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: "injected egress install failure".into(),
                });
            }
            if args.get(2).is_some_and(|v| v == "del") && args.get(1).is_some_and(|v| v == "route")
            {
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: "injected egress rollback failure".into(),
                });
            }
            Ok(())
        });

        assert!(
            matches!(result, Err(LinuxError::Rollback { operation, rollback })
                if operation.contains("injected egress install failure")
                    && rollback.contains("injected egress rollback failure"))
        );
        let egress_cleanup_calls = calls[failure_index.expect("install failure injected")..]
            .iter()
            .filter(|args| {
                args.get(2).is_some_and(|v| v == "del") && args.iter().any(|v| v == "10001")
            })
            .count();
        assert_eq!(
            egress_cleanup_calls, 2,
            "IPv4 egress rollback must run exactly once"
        );
        let socket_cleanup_calls = calls[failure_index.expect("install failure injected")..]
            .iter()
            .filter(|args| {
                args.get(2).is_some_and(|v| v == "del") && args.get(4).is_some_and(|v| v == "9000")
            })
            .count();
        assert_eq!(
            socket_cleanup_calls, 1,
            "outer rollback must still clean the socket mark"
        );
    }

    #[test]
    fn policy_cleanup_aggregates_socket_and_egress_failures() {
        let mut plan = cleanup_test_plan();
        plan.socket_marks = vec![0x1000_0001, 0x1000_0002];
        let mut calls = Vec::new();
        let result = remove_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            let socket_rule = args.get(1).is_some_and(|kind| kind == "rule")
                && args.get(4).is_some_and(|priority| priority == "9000");
            let egress_rule = args.get(1).is_some_and(|kind| kind == "rule")
                && args.get(4).is_some_and(|priority| priority == "10001");
            let egress_route = args.get(1).is_some_and(|kind| kind == "route")
                && args.iter().any(|value| value == "10001");
            if socket_rule || egress_rule || egress_route {
                let category = if socket_rule { "socket" } else { "egress" };
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: format!("injected {category} cleanup failure"),
                });
            }
            Ok(())
        });

        let socket_calls = calls
            .iter()
            .filter(|args| {
                args.get(1).is_some_and(|kind| kind == "rule")
                    && args.get(4).is_some_and(|priority| priority == "9000")
            })
            .count();
        let egress_calls = calls
            .iter()
            .filter(|args| {
                (args.get(1).is_some_and(|kind| kind == "rule")
                    && args.get(4).is_some_and(|priority| priority == "10001"))
                    || (args.get(1).is_some_and(|kind| kind == "route")
                        && args.iter().any(|value| value == "10001"))
            })
            .count();

        assert_eq!(socket_calls, 2, "all socket marks must be attempted");
        assert_eq!(
            egress_calls, 2,
            "the IPv4 egress route and rule must both be attempted"
        );
        assert!(matches!(result, Err(LinuxError::Cleanup(message))
            if message.matches("injected socket cleanup failure").count() == 2
                && message.matches("injected egress cleanup failure").count() == 2));
    }

    #[test]
    fn nft_text_ownership_accepts_only_the_exact_table_level_comment() {
        let owned = "table inet vpn_relay {\n    comment \"managed by vpn-relay\"\n    chain input {\n        type filter hook input priority filter; policy accept;\n    }\n}\n";
        assert!(table_is_owned_text(owned, "inet", "vpn_relay"));
        assert!(!table_is_owned_text(owned, "inet", "other_table"));

        let tab_indented = "table inet vpn_relay {\n\tcomment \"managed by vpn-relay\"\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n";
        assert!(table_is_owned_text(tab_indented, "inet", "vpn_relay"));

        let nested_only = "table inet vpn_relay {\n    chain input {\n        comment \"managed by vpn-relay\"\n    }\n}\n";
        assert!(!table_is_owned_text(nested_only, "inet", "vpn_relay"));

        let foreign = "table inet vpn_relay {\n    comment \"owned by someone else\"\n}\n";
        assert!(!table_is_owned_text(foreign, "inet", "vpn_relay"));
    }

    #[test]
    fn nft_apply_does_not_mutate_when_inspection_fails() {
        let plan = cleanup_test_plan();
        let mut apply_calls = 0;
        let result = apply_nft_with(
            &plan,
            &mut |_plan| {
                Err(LinuxError::Conflict {
                    resource: "nft table inet vpn_relay".into(),
                    details: "unowned table".into(),
                })
            },
            &mut |_script| {
                apply_calls += 1;
                Ok(())
            },
        );

        assert!(matches!(result, Err(LinuxError::Conflict { .. })));
        assert_eq!(apply_calls, 0, "must not mutate an unowned table");
    }

    #[test]
    fn nft_apply_creates_missing_table_without_delete_command() {
        let plan = cleanup_test_plan();
        let mut submitted = None;
        apply_nft_with(&plan, &mut |_plan| Ok(false), &mut |script| {
            submitted = Some(script.to_owned());
            Ok(())
        })
        .unwrap();

        let script = submitted.expect("nft batch must be submitted");
        assert!(!script.starts_with("delete table"));
        assert!(script.contains("table inet vpn_relay"));
    }

    #[test]
    fn nft_apply_preserves_owned_table_on_transaction_failure() {
        let plan = cleanup_test_plan();
        let mut submitted = None;
        let result = apply_nft_with(&plan, &mut |_plan| Ok(true), &mut |script| {
            submitted = Some(script.to_owned());
            Err(LinuxError::Command {
                program: "nft -f -".into(),
                status: "exit status 1".into(),
                stderr: "injected transaction failure".into(),
            })
        });

        assert!(submitted
            .as_deref()
            .is_some_and(|script| script.starts_with("delete table inet vpn_relay\n")));
        assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
            if stderr.contains("injected transaction failure")));
    }

    #[test]
    fn nft_remove_does_not_delete_when_inspection_fails() {
        let plan = cleanup_test_plan();
        let mut delete_calls = 0;
        let result = remove_nft_with(
            &plan,
            &mut |_plan| {
                Err(LinuxError::Command {
                    program: "nft -j list table".into(),
                    status: "exit status 1".into(),
                    stderr: "permission denied".into(),
                })
            },
            &mut |_program, _args| {
                delete_calls += 1;
                Ok(())
            },
        );

        assert!(matches!(
            result,
            Err(LinuxError::Command { ref stderr, .. }) if stderr == "permission denied"
        ));
        assert_eq!(
            delete_calls, 0,
            "delete must not run after failed inspection"
        );
    }

    #[test]
    fn nft_remove_skips_missing_table_and_propagates_delete_failure() {
        let plan = cleanup_test_plan();
        let mut delete_calls = 0;
        remove_nft_with(&plan, &mut |_plan| Ok(false), &mut |_program, _args| {
            delete_calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(delete_calls, 0);

        let result = remove_nft_with(&plan, &mut |_plan| Ok(true), &mut |program, args| {
            delete_calls += 1;
            assert_eq!(program, "nft");
            assert_eq!(args, ["delete", "table", "inet", "vpn_relay"]);
            Err(LinuxError::Command {
                program: "nft delete table".into(),
                status: "exit status 1".into(),
                stderr: "injected delete failure".into(),
            })
        });
        assert_eq!(delete_calls, 1);
        assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
            if stderr.contains("injected delete failure")));
    }

    fn ipv4_link_response(forwarding: u32) -> Vec<u8> {
        let mut devconf = vec![0u8; IPV4_DEVCONF_MAX * 4];
        devconf[0..4].copy_from_slice(&forwarding.to_ne_bytes());
        let mut inet = Vec::new();
        append_netlink_attribute(&mut inet, IFLA_INET_CONF, &devconf);
        let mut af_spec = Vec::new();
        append_netlink_attribute(&mut af_spec, AF_INET_ATTR | NLA_F_NESTED, &inet);
        let mut attributes = Vec::new();
        append_netlink_attribute(&mut attributes, IFLA_AF_SPEC | NLA_F_NESTED, &af_spec);
        build_link_message(RTM_NEWLINK, 0, 9, 1, &attributes).unwrap()
    }

    #[test]
    fn rtnetlink_extended_ack_extracts_kernel_message() {
        let mut response = vec![0u8; 16];
        response[0..4].copy_from_slice(&40u32.to_ne_bytes());
        response[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        response[6..8].copy_from_slice(&NLM_F_CAPPED.to_ne_bytes());
        response.extend_from_slice(&(-libc::EINVAL).to_ne_bytes());
        let mut original = [0u8; 16];
        original[0..4].copy_from_slice(&16u32.to_ne_bytes());
        response.extend_from_slice(&original);
        let message = b"invalid forwarding attribute\0";
        let attribute_length = 4 + message.len();
        response.extend_from_slice(&(attribute_length as u16).to_ne_bytes());
        response.extend_from_slice(&(NLMSGERR_ATTR_MSG | NLA_F_NET_BYTEORDER).to_ne_bytes());
        response.extend_from_slice(message);
        response.resize(align_netlink(response.len()), 0);
        let length = response.len();
        response[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
        response[6..8].copy_from_slice(&(NLM_F_CAPPED | NLM_F_ACK_TLVS).to_ne_bytes());
        assert_eq!(
            netlink_extended_ack(&response, 0, length).as_deref(),
            Some("invalid forwarding attribute")
        );
    }

    #[test]
    fn rtnetlink_extended_ack_extracts_uncapped_kernel_message() {
        let mut response = vec![0u8; 16];
        response[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        response.extend_from_slice(&(-libc::EINVAL).to_ne_bytes());
        let mut original = [0u8; 16];
        original[0..4].copy_from_slice(&20u32.to_ne_bytes());
        response.extend_from_slice(&original);
        response.extend_from_slice(&[1, 2, 3, 4]);
        let message = b"invalid uncapped attribute\0";
        let attribute_length = 4 + message.len();
        response.extend_from_slice(&(attribute_length as u16).to_ne_bytes());
        response.extend_from_slice(&NLMSGERR_ATTR_MSG.to_ne_bytes());
        response.extend_from_slice(message);
        response.resize(align_netlink(response.len()), 0);
        let length = response.len();
        response[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
        response[6..8].copy_from_slice(&NLM_F_ACK_TLVS.to_ne_bytes());
        assert_eq!(
            netlink_extended_ack(&response, 0, length).as_deref(),
            Some("invalid uncapped attribute")
        );
    }

    #[test]
    fn rtnetlink_extended_ack_ignores_truncated_error_header() {
        let response = vec![0u8; 35];
        assert_eq!(netlink_extended_ack(&response, 0, response.len()), None);
    }

    #[test]
    fn rtnetlink_extended_ack_ignores_malformed_attributes() {
        let mut response = vec![0u8; 36];
        response[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        response[6..8].copy_from_slice(&(NLM_F_CAPPED | NLM_F_ACK_TLVS).to_ne_bytes());
        response[16..20].copy_from_slice(&(-libc::EINVAL).to_ne_bytes());
        response[20..24].copy_from_slice(&16u32.to_ne_bytes());
        response.extend_from_slice(&3u16.to_ne_bytes());
        response.extend_from_slice(&NLMSGERR_ATTR_MSG.to_ne_bytes());
        let length = response.len();
        response[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
        assert_eq!(netlink_extended_ack(&response, 0, length), None);
    }

    #[test]
    fn rtnetlink_ipv4_forwarding_readback_parses_kernel_devconf() {
        assert!(parse_link_ipv4_forwarding(&ipv4_link_response(1), 9).unwrap());
        assert!(!parse_link_ipv4_forwarding(&ipv4_link_response(0), 9).unwrap());
        assert!(matches!(
            parse_link_ipv4_forwarding(&ipv4_link_response(2), 9),
            Err(LinuxError::Conflict { .. })
        ));
    }

    #[test]
    fn rtnetlink_ipv4_forwarding_rejects_response_for_different_ifindex() {
        let response = ipv4_link_response(1);
        assert!(matches!(
            parse_link_ipv4_forwarding(&response, 10),
            Err(LinuxError::Conflict { details, .. })
                if details.contains("ifindex 9")
        ));
    }

    #[test]
    fn rtnetlink_ipv4_forwarding_rejects_truncated_devconf() {
        let mut inet = Vec::new();
        append_netlink_attribute(&mut inet, IFLA_INET_CONF, &[]);
        let mut af_spec = Vec::new();
        append_netlink_attribute(&mut af_spec, AF_INET_ATTR | NLA_F_NESTED, &inet);
        let mut attributes = Vec::new();
        append_netlink_attribute(&mut attributes, IFLA_AF_SPEC | NLA_F_NESTED, &af_spec);
        let response = build_link_message(RTM_NEWLINK, 0, 9, 1, &attributes).unwrap();
        assert!(matches!(
            parse_link_ipv4_forwarding(&response, 9),
            Err(LinuxError::Conflict { details, .. }) if details.contains("omitted")
        ));
    }

    #[test]
    fn rtnetlink_forwarding_set_failure_matrix_stops_at_each_boundary() {
        for stage in ["identity_before_send", "send_or_ack", "readback", "identity_after_readback"] {
            let mut verify_calls = 0usize;
            let mut request_calls = 0usize;
            let mut readback_calls = 0usize;
            let result = set_ipv4_interface_forwarding_with(
                "eth0",
                7,
                true,
                |_, _| {
                    verify_calls += 1;
                    if (stage == "identity_before_send" && verify_calls == 1)
                        || (stage == "identity_after_readback" && verify_calls == 2)
                    {
                        Err(LinuxError::Conflict {
                            resource: "injected interface identity".into(),
                            details: format!("injected {stage} failure"),
                        })
                    } else {
                        Ok(())
                    }
                },
                |ifindex, message_type, flags, _| {
                    request_calls += 1;
                    assert_eq!(ifindex, 7);
                    assert_eq!(message_type, RTM_NEWLINK);
                    assert_eq!(flags, NLM_F_REQUEST | NLM_F_ACK);
                    if stage == "send_or_ack" {
                        Err(LinuxError::Command {
                            program: "injected rtnetlink send/ACK".into(),
                            status: "failed".into(),
                            stderr: format!("injected {stage} failure"),
                        })
                    } else {
                        Ok(Vec::new())
                    }
                },
                |_| {
                    readback_calls += 1;
                    if stage == "readback" {
                        Err(LinuxError::Command {
                            program: "injected RTM_GETLINK readback".into(),
                            status: "failed".into(),
                            stderr: format!("injected {stage} failure"),
                        })
                    } else {
                        Ok(true)
                    }
                },
            );
            assert!(result.is_err(), "{stage} failure was not propagated");
            assert_eq!(
                verify_calls,
                if stage == "identity_after_readback" { 2 } else { 1 },
                "unexpected identity check count for {stage}"
            );
            assert_eq!(
                request_calls,
                if stage == "identity_before_send" { 0 } else { 1 },
                "unsafe or missing RTM_NEWLINK request for {stage}"
            );
            assert_eq!(
                readback_calls,
                if matches!(stage, "readback" | "identity_after_readback") { 1 } else { 0 },
                "unexpected RTM_GETLINK readback count for {stage}"
            );
        }
    }

    #[test]
    fn rtnetlink_forwarding_set_rejects_acknowledged_value_mismatch() {
        let mut verify_calls = 0usize;
        let result = set_ipv4_interface_forwarding_with(
            "eth0",
            7,
            true,
            |_, _| {
                verify_calls += 1;
                Ok(())
            },
            |_, _, _, _| Ok(Vec::new()),
            |_| Ok(false),
        );
        assert!(matches!(
            result,
            Err(LinuxError::Conflict { details, .. })
                if details.contains("reports forwarding=0")
        ));
        assert_eq!(verify_calls, 2);
    }

    #[test]
    fn rtnetlink_reads_loopback_ipv4_forwarding_by_ifindex() {
        let index = interface_index("lo").expect("loopback interface exists");
        let netlink_value = ipv4_interface_forwarding(index).unwrap();
        let sysctl_value = std::fs::read_to_string("/proc/sys/net/ipv4/conf/lo/forwarding")
            .unwrap()
            .trim()
            == "1";
        assert_eq!(netlink_value, sysctl_value);
    }

    #[test]
    fn interface_name_round_trips_current_network_namespace_identity() {
        let index = interface_index("lo").expect("loopback interface exists");
        assert_eq!(interface_name(index).unwrap(), "lo");
        verify_interface_identity("lo", index).unwrap();
    }

    #[test]
    fn interface_identity_rejects_zero_and_mismatched_links() {
        assert!(matches!(
            interface_name(0),
            Err(LinuxError::Conflict { .. })
        ));
        let index = interface_index("lo").unwrap();
        assert!(matches!(
            verify_interface_identity("lo", index.saturating_add(1)),
            Err(LinuxError::Conflict { .. }) | Err(LinuxError::Command { .. })
        ));
    }

    #[test]
    fn interface_identity_rejects_reused_names_and_indices() {
        let name_reused =
            verify_interface_identity_with("eth0", 7, |_| Ok(9), |_| Ok("eth0".to_owned()));
        assert!(matches!(name_reused, Err(LinuxError::Conflict { .. })));

        let index_reused =
            verify_interface_identity_with("eth0", 7, |_| Ok(7), |_| Ok("eth1".to_owned()));
        assert!(matches!(index_reused, Err(LinuxError::Conflict { .. })));

        verify_interface_identity_with("eth0", 7, |_| Ok(7), |_| Ok("eth0".to_owned())).unwrap();
    }

    #[test]
    fn interface_identity_propagates_missing_link_lookup_errors() {
        let missing_name = verify_interface_identity_with(
            "eth0",
            7,
            |_| {
                Err(LinuxError::Conflict {
                    resource: "network interface 'eth0'".into(),
                    details: "interface disappeared".into(),
                })
            },
            |_| Ok("eth0".to_owned()),
        );
        assert!(matches!(
            missing_name,
            Err(LinuxError::Conflict { details, .. }) if details == "interface disappeared"
        ));

        let missing_index = verify_interface_identity_with(
            "eth0",
            7,
            |_| Ok(7),
            |_| {
                Err(LinuxError::Conflict {
                    resource: "network interface index 7".into(),
                    details: "interface index disappeared".into(),
                })
            },
        );
        assert!(matches!(
            missing_index,
            Err(LinuxError::Conflict { details, .. }) if details == "interface index disappeared"
        ));
    }

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
