//! Linux command execution for daemon-owned network resources.
use crate::routing::RoutingPlan;
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug, thiserror::Error)]
pub enum LinuxError {
    #[error("failed to execute {program}: {source}")]
    Spawn { program: String, #[source] source: std::io::Error },
    #[error("{program} failed ({status}): {stderr}")]
    Command { program: String, status: String, stderr: String },
}

fn run(program: &str, args: &[String]) -> Result<(), LinuxError> {
    let output = Command::new(program).args(args).output().map_err(|source| LinuxError::Spawn {
        program: program.to_owned(), source
    })?;
    if output.status.success() { return Ok(()); }
    Err(LinuxError::Command {
        program: format!("{} {}", program, args.join(" ")),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

pub fn run_ip(args: &[String]) -> Result<(), LinuxError> { run("ip", args) }

/// Replace only the table named by this daemon's configuration, then apply
/// its complete nft batch. nft processes the batch transactionally.
pub fn apply_nft(plan: &RoutingPlan) -> Result<(), LinuxError> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| LinuxError::Spawn { program: "nft".into(), source })?;
    child.stdin.take().expect("piped stdin").write_all(plan.nft_script().as_bytes())
        .map_err(|source| LinuxError::Spawn { program: "nft stdin".into(), source })?;
    let output = child.wait_with_output().map_err(|source| LinuxError::Spawn {
        program: "nft".into(), source
    })?;
    if output.status.success() { return Ok(()); }
    Err(LinuxError::Command {
        program: "nft -f -".into(),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

pub fn remove_nft(plan: &RoutingPlan) {
    let _ = run("nft", &["delete".into(), "table".into(), plan.nft_family.clone(), plan.nft_table.clone()]);
}

pub fn apply_policy_routing(plan: &RoutingPlan) -> Result<(), LinuxError> {
    for egress in &plan.egresses {
        for family in ["-4", "-6"] {
            let priority = egress.ip_rule_priority.to_string();
            let mark = format!("0x{:x}", egress.mark);
            let table = egress.table_id.to_string();
            // A stale rule from a previous daemon instance is removed first.
            let _ = run("ip", &[family.into(), "rule".into(), "del".into(), "priority".into(),
                priority.clone(), "fwmark".into(), mark.clone(), "lookup".into(), table.clone()]);
            if let Err(error) = run("ip", &[family.into(), "route".into(), "replace".into(), "default".into(),
                "dev".into(), egress.interface.clone(), "table".into(), table.clone()])
                .and_then(|_| run("ip", &[family.into(), "rule".into(), "add".into(), "priority".into(),
                    priority, "fwmark".into(), mark, "lookup".into(), table]))
            {
                remove_policy_routing(plan);
                return Err(error);
            }
        }
    }
    Ok(())
}

pub fn configure_interface(name: &str, mtu: u16, addresses: &[String]) -> Result<(), LinuxError> {
    run("ip", &["link".into(), "set".into(), "dev".into(), name.into(), "mtu".into(),
        mtu.to_string(), "up".into()])?;
    for address in addresses {
        let family = if address.contains(':') { "-6" } else { "-4" };
        run("ip", &[family.into(), "address".into(), "replace".into(), address.clone(),
            "dev".into(), name.into()])?;
    }
    Ok(())
}
