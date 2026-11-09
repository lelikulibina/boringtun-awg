//! Linux runtime: dispatch tunnel backends and install shared routing.
use crate::backend::{BackendError, BackendRegistry, TunnelHandle, TunnelSnapshot};
use crate::config::Config;
use crate::linux::{self, LinuxError};
use crate::routing::RoutingPlan;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_shutdown(_: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Linux(#[from] LinuxError),
    #[error("tunnel backend error: {0}")]
    Backend(#[from] BackendError),
    #[error("invalid runtime configuration: {0}")]
    Configuration(String),
    #[error("failed to enable IP forwarding: {0}")]
    Forwarding(String),
    #[error("another vpn-relay instance is already running (lock: {0})")]
    AlreadyRunning(String),
    #[error("failed to acquire daemon instance lock: {0}")]
    InstanceLock(String),
    #[error("failed to install signal handler: {0}")]
    Signal(String),
}

pub struct Runtime {
    devices: Vec<Box<dyn TunnelHandle>>,
    routing: RoutingPlan,
    stats_interval: Duration,
    forwarding_state: Option<ForwardingState>,
    _instance_lock: InstanceLock,
}

struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// Key the lock by the current network namespace inode. This allows
    /// independent daemons in separate namespaces while preventing duplicate
    /// instances inside the same namespace.
    fn path_for_netns_inode(inode: u64) -> PathBuf {
        PathBuf::from(format!("/run/vpn-relay-netns-{inode}.lock"))
    }

    fn current_netns_path() -> Result<PathBuf, RuntimeError> {
        let metadata = std::fs::metadata("/proc/self/ns/net")
            .map_err(|error| RuntimeError::InstanceLock(error.to_string()))?;
        Ok(Self::path_for_netns_inode(metadata.ino()))
    }

    fn acquire(path: &Path) -> Result<Self, RuntimeError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| RuntimeError::InstanceLock(error.to_string()))?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(RuntimeError::AlreadyRunning(path.display().to_string()));
            }
            return Err(RuntimeError::InstanceLock(error.to_string()));
        }
        Ok(Self { _file: file })
    }
}

struct ForwardingState {
    ipv4: String,
    ipv6: String,
}

impl Runtime {
    /// Start all interfaces through their registered backend, then install
    /// shared routing only after every tunnel has been configured.
    pub fn start(config: Config) -> Result<Self, RuntimeError> {
        config
            .validate()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let lock_path = InstanceLock::current_netns_path()?;
        let instance_lock = InstanceLock::acquire(&lock_path)?;
        let socket_fwmarks = config
            .resolved_socket_fwmarks()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let routing = RoutingPlan::from_config(&config);
        let backends = BackendRegistry::default();
        backends.validate_config(&config)?;

        // Install the fail-closed policy before creating or bringing up any
        // TUN interface. The nftables rules refer to interface names and do
        // not require the links to exist yet. This closes the window even
        // when forwarding was already enabled before vpn-relay started.
        linux::apply_nft(&routing)?;

        let mut devices = Vec::with_capacity(config.interfaces.len());
        let setup_result = (|| -> Result<(), RuntimeError> {
            for ((interface_name, interface), socket_fwmark) in
                config.interfaces.iter().zip(socket_fwmarks)
            {
                let handle = backends.create(
                    interface.tunnel_type,
                    interface_name,
                    interface,
                    socket_fwmark,
                )?;
                devices.push(handle);
                linux::configure_interface(interface_name, interface.mtu, &interface.address)?;
            }
            Ok(())
        })();
        if let Err(error) = setup_result {
            // Dropping the handles stops and joins any workers created before
            // the failing interface; the firewall is removed only afterwards.
            drop(devices);
            linux::remove_nft(&routing);
            return Err(error);
        }

        if let Err(error) = linux::apply_policy_routing(&routing) {
            drop(devices);
            linux::remove_nft(&routing);
            return Err(error.into());
        }

        let forwarding_state = if config.daemon.manage_ip_forwarding {
            match enable_forwarding() {
                Ok(state) => Some(state),
                Err(error) => {
                    linux::remove_policy_routing(&routing);
                    drop(devices);
                    linux::remove_nft(&routing);
                    return Err(error);
                }
            }
        } else {
            None
        };

        tracing::info!(interfaces = devices.len(), "vpn-relay runtime started");
        Ok(Self {
            devices,
            routing,
            stats_interval: Duration::from_secs(config.daemon.stats_interval_secs),
            forwarding_state,
            _instance_lock: instance_lock,
        })
    }

    pub fn routing_plan(&self) -> &RoutingPlan {
        &self.routing
    }

    /// Return consistent live counters without depending on a backend UAPI.
    pub fn snapshots(&self) -> Result<Vec<TunnelSnapshot>, RuntimeError> {
        self.devices
            .iter()
            .map(|device| device.snapshot().map_err(RuntimeError::from))
            .collect()
    }

    /// Keep the daemon alive, publish peer counters, and stop cleanly on SIGINT/SIGTERM.
    pub fn run(mut self) -> Result<(), RuntimeError> {
        install_signal_handlers()?;
        while !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            let mut elapsed = 0;
            while elapsed < self.stats_interval.as_secs()
                && !SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
            {
                std::thread::sleep(Duration::from_secs(1));
                elapsed += 1;
            }
            if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
                break;
            }
            match self.snapshots() {
                Ok(snapshots) => {
                    for device in snapshots {
                        for peer in device.peers {
                            tracing::info!(
                                interface = %device.name,
                                peer = %hex_key(&peer.public_key),
                                tx_bytes = peer.tx_bytes,
                                rx_bytes = peer.rx_bytes,
                                handshake_age_secs = ?peer
                                    .time_since_last_handshake
                                    .map(|age| age.as_secs()),
                                "peer statistics"
                            );
                        }
                    }
                }
                Err(error) => {
                    tracing::error!(%error, "failed to collect tunnel statistics")
                }
            }
        }

        for device in &self.devices {
            device.shutdown();
        }
        for device in &mut self.devices {
            device.wait();
        }
        Ok(())
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        linux::remove_policy_routing(&self.routing);
        linux::remove_nft(&self.routing);
        if let Some(state) = &self.forwarding_state {
            restore_forwarding(state);
        }
    }
}

fn install_signal_handlers() -> Result<(), RuntimeError> {
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    unsafe {
        if libc::signal(libc::SIGINT, request_shutdown as libc::sighandler_t) == libc::SIG_ERR {
            return Err(RuntimeError::Signal("SIGINT".into()));
        }
        if libc::signal(libc::SIGTERM, request_shutdown as libc::sighandler_t) == libc::SIG_ERR {
            return Err(RuntimeError::Signal("SIGTERM".into()));
        }
    }
    Ok(())
}

fn hex_key(key: &[u8; 32]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_sysctl(key: &str) -> Result<String, RuntimeError> {
    let output = std::process::Command::new("sysctl")
        .args(["-n", key])
        .output()
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    if !output.status.success() {
        return Err(RuntimeError::Forwarding(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn write_sysctl(key: &str, value: &str) -> Result<(), RuntimeError> {
    let output = std::process::Command::new("sysctl")
        .args(["-w", &format!("{key}={value}")])
        .output()
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    if !output.status.success() {
        return Err(RuntimeError::Forwarding(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(())
}

fn enable_forwarding() -> Result<ForwardingState, RuntimeError> {
    let state = ForwardingState {
        ipv4: read_sysctl("net.ipv4.ip_forward")?,
        ipv6: read_sysctl("net.ipv6.conf.all.forwarding")?,
    };
    write_sysctl("net.ipv4.ip_forward", "1")?;
    if let Err(error) = write_sysctl("net.ipv6.conf.all.forwarding", "1") {
        let _ = write_sysctl("net.ipv4.ip_forward", &state.ipv4);
        return Err(error);
    }
    Ok(state)
}

fn restore_forwarding(state: &ForwardingState) {
    let _ = write_sysctl("net.ipv4.ip_forward", &state.ipv4);
    let _ = write_sysctl("net.ipv6.conf.all.forwarding", &state.ipv6);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_lock_rejects_a_second_process_and_releases_on_drop() {
        let path =
            std::env::temp_dir().join(format!("vpn-relay-lock-test-{}.lock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let first = InstanceLock::acquire(&path).unwrap();
        assert!(matches!(
            InstanceLock::acquire(&path),
            Err(RuntimeError::AlreadyRunning(_))
        ));
        drop(first);
        assert!(InstanceLock::acquire(&path).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn network_namespace_lock_paths_are_keyed_by_namespace_inode() {
        assert_ne!(
            InstanceLock::path_for_netns_inode(100),
            InstanceLock::path_for_netns_inode(200)
        );
        assert_eq!(
            InstanceLock::current_netns_path().unwrap(),
            InstanceLock::current_netns_path().unwrap()
        );
    }
}
