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

#[cfg(test)]
fn apply_nft_script_with<F>(script: &str, run_script: &mut F) -> Result<(), LinuxError>
where
    F: FnMut(&str) -> Result<(), LinuxError>,
{
    run_script(script)
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
            if !egress.ipv6_enabled {
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
                run_ip_cleanup_with(&stale_rule, run_command)?;
                run_ip_cleanup_with(&stale_route, run_command)?;
            }

            for &family in RoutingPlan::ip_families(egress) {
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

fn run_ip_cleanup(args: &[String]) -> Result<(), LinuxError> {
    run_ip_cleanup_with(args, &mut run)
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
        for family in ["-4", "-6"] {
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
                run_ip_cleanup_with(&args, run_command)?;
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
        Err(operation) => match remove_policy_routing_with(plan, run_command) {
            Ok(()) => Err(operation),
            Err(rollback) => Err(LinuxError::Rollback {
                operation: operation.to_string(),
                rollback: rollback.to_string(),
            }),
        },
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
    for mark in &plan.socket_marks {
        for family in ["-4", "-6"] {
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
                ipv6_enabled: true,
            }],
            decisions: Vec::new(),
            input_rules: Vec::new(),
            output_rules: Vec::new(),
            socket_marks: Vec::new(),
            ipv6_blocked_interfaces: Vec::new(),
            interface_indices: None,
        }
    }

    #[test]
    fn socket_fwmark_apply_failure_rolls_back_all_families_and_egress() {
        let mut plan = cleanup_test_plan();
        plan.socket_marks = vec![0x1000_0001, 0x1000_0002];
        let mut calls = Vec::new();
        let mut add_count = 0;
        let mut failure_index = None;
        let result = apply_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            if args.get(2).is_some_and(|part| part == "add") {
                add_count += 1;
                if add_count == 2 {
                    failure_index = Some(calls.len() - 1);
                    return Err(LinuxError::Command {
                        program: format!("ip {}", args.join(" ")),
                        status: "exit status 2".into(),
                        stderr: "injected IPv6 socket rule failure".into(),
                    });
                }
            }
            Ok(())
        });

        assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
            if stderr.contains("injected IPv6 socket rule failure")));
        let cleanup = calls[failure_index.expect("failure was injected")..]
            .iter()
            .filter(|args| {
                args.get(2).is_some_and(|part| part == "del")
                    && args.get(4).is_some_and(|part| part == "9000")
            })
            .count();
        assert_eq!(
            cleanup, 4,
            "all socket rules must be attempted during rollback"
        );
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

        assert_eq!(cleanup_attempts, 4);
        assert!(matches!(result, Err(LinuxError::Cleanup(message))
            if message.matches("injected socket cleanup failure").count() == 4));
    }

    #[test]
    fn egress_apply_failure_at_each_install_boundary_rolls_back_all_resources() {
        let plan = cleanup_test_plan();
        let failure_points = [
            ("-4", "route", "replace"),
            ("-4", "rule", "add"),
            ("-6", "route", "replace"),
            ("-6", "rule", "add"),
        ];

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

            let cleanup = &calls[calls.len() - 4..];
            assert_eq!(cleanup.len(), 4);
            for family in ["-4", "-6"] {
                assert!(cleanup.iter().any(|args| args
                    .first()
                    .is_some_and(|value| value == family)
                    && args.get(1).is_some_and(|value| value == "rule")
                    && args.get(2).is_some_and(|value| value == "del")));
                assert!(cleanup.iter().any(|args| args
                    .first()
                    .is_some_and(|value| value == family)
                    && args.get(1).is_some_and(|value| value == "route")
                    && args.get(2).is_some_and(|value| value == "del")));
            }
        }
    }

    #[test]
    fn egress_apply_failure_rolls_back_every_family_and_resource() {
        let plan = cleanup_test_plan();
        let mut calls = Vec::new();
        let mut failed = false;
        let result = apply_egress_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            // The first add operation fails, after the IPv4 route was installed.
            if !failed
                && args.get(1).is_some_and(|part| part == "rule")
                && args.get(2).is_some_and(|part| part == "add")
            {
                failed = true;
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: "injected rule installation failure".into(),
                });
            }
            Ok(())
        });

        assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
            if stderr.contains("injected rule installation failure")));
        // Cleanup is attempted for both families and both resource types,
        // including the family whose installation had not yet started.
        let cleanup = &calls[calls.len() - 4..];
        assert_eq!(cleanup.len(), 4);
        assert!(cleanup
            .iter()
            .any(|args| args.first().is_some_and(|v| v == "-4")
                && args.get(1).is_some_and(|v| v == "rule")));
        assert!(cleanup
            .iter()
            .any(|args| args.first().is_some_and(|v| v == "-6")
                && args.get(1).is_some_and(|v| v == "route")));
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
    fn egress_cleanup_attempts_every_resource_after_command_failures() {
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
            4,
            "both families and resource types must be attempted"
        );
        assert!(matches!(result, Err(LinuxError::Cleanup(message))
            if message.matches("Operation not permitted").count() == 4));
        assert!(calls
            .iter()
            .any(|args| args.first().is_some_and(|family| family == "-4")));
        assert!(calls
            .iter()
            .any(|args| args.first().is_some_and(|family| family == "-6")));
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
        assert_eq!(calls, 4, "cleanup must inspect every owned resource");
    }

    #[test]
    fn egress_cleanup_aggregates_failures_across_multiple_interfaces() {
        let mut plan = cleanup_test_plan();
        plan.egresses.push(crate::routing::EgressPlan {
            interface: "wg1".into(),
            mark: 0x8000_0002,
            table_id: 10002,
            ip_rule_priority: 10002,
            ipv6_enabled: true,
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

        assert_eq!(calls.len(), 8, "all resources on both interfaces must be attempted");
        assert!(matches!(result, Err(LinuxError::Cleanup(message))
            if message.matches("injected cleanup failure").count() == 8));
        for interface in ["awg0", "wg1"] {
            assert!(calls.iter().any(|args| args.get(1).is_some_and(|v| v == "rule")
                && args.get(5).is_some_and(|v| v == "0x80000001" || v == "0x80000002")
                && args.get(2).is_some_and(|v| v == "del")));
            assert!(calls.iter().any(|args| args.get(1).is_some_and(|v| v == "route")
                && args.iter().any(|v| v == interface)));
        }
    }

    #[test]
    fn nested_policy_rollback_does_not_repeat_egress_cleanup() {
        let mut plan = cleanup_test_plan();
        plan.socket_marks = vec![0x1000_0001];
        let mut calls = Vec::new();
        let mut install_failed = false;
        let result = apply_policy_routing_with(&plan, &mut |_program, args| {
            calls.push(args.to_vec());
            if !install_failed
                && args.get(1).is_some_and(|v| v == "rule")
                && args.get(2).is_some_and(|v| v == "add")
                && args.first().is_some_and(|v| v == "-4")
            {
                install_failed = true;
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: "injected egress install failure".into(),
                });
            }
            if args.get(2).is_some_and(|v| v == "del")
                && args.get(1).is_some_and(|v| v == "route")
            {
                return Err(LinuxError::Command {
                    program: format!("ip {}", args.join(" ")),
                    status: "exit status 2".into(),
                    stderr: "injected egress rollback failure".into(),
                });
            }
            Ok(())
        });

        assert!(matches!(result, Err(LinuxError::Rollback { operation, rollback })
            if operation.contains("injected egress install failure")
                && rollback.contains("injected egress rollback failure")));
        let egress_cleanup_calls = calls.iter().filter(|args| {
            args.get(2).is_some_and(|v| v == "del")
                && args.get(4).is_some_and(|v| v == "10001")
        }).count();
        assert_eq!(egress_cleanup_calls, 4, "egress rollback must run exactly once");
        let socket_cleanup_calls = calls.iter().filter(|args| {
            args.get(2).is_some_and(|v| v == "del")
                && args.get(4).is_some_and(|v| v == "9000")
        }).count();
        assert_eq!(socket_cleanup_calls, 2, "outer rollback must still clean both socket families");
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

    #[test]
    fn nft_batch_failure_is_reported_without_mutating_the_committed_policy() {
        let script = "delete table inet vpn_relay\ntable inet vpn_relay { }\n";
        let mut submitted = None;
        let result = apply_nft_script_with(script, &mut |batch| {
            submitted = Some(batch.to_owned());
            Err(LinuxError::Command {
                program: "nft -f -".into(),
                status: "exit status 1".into(),
                stderr: "injected transaction validation failure".into(),
            })
        });

        assert_eq!(submitted.as_deref(), Some(script));
        assert!(matches!(result, Err(LinuxError::Command { ref stderr, .. })
            if stderr.contains("injected transaction validation failure")));
    }

    #[test]
    fn nft_replacement_is_submitted_as_one_atomic_batch() {
        let plan = cleanup_test_plan();
        let mut batch = String::new();
        batch.push_str(&format!(
            "delete table {} {}\n",
            plan.nft_family, plan.nft_table
        ));
        batch.push_str(&plan.nft_script());

        let mut calls = 0;
        apply_nft_script_with(&batch, &mut |script| {
            calls += 1;
            assert!(script.starts_with("delete table inet vpn_relay\n"));
            assert!(script.contains("table inet vpn_relay"));
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 1, "replacement must be a single nft transaction");
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
