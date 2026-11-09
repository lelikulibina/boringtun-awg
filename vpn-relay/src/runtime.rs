//! Linux runtime: dispatch tunnel backends and install shared routing.
use crate::backend::{BackendError, BackendRegistry, PreparedInterface, TunnelHandle, TunnelSnapshot};
use crate::config::{Config, PeerConfig};
use crate::linux::{self, LinuxError};
use crate::routing::RoutingPlan;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
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
    #[error("control socket error: {0}")]
    Control(String),
    #[error("peer rollback failed; daemon must stop: {0}")]
    FatalRollback(String),
}

pub struct Runtime {
    devices: Vec<Box<dyn TunnelHandle>>,
    config: Config,
    prepared_interfaces: std::collections::BTreeMap<String, PreparedInterface>,
    backends: BackendRegistry,
    routing: RoutingPlan,
    stats_interval: Duration,
    forwarding_state: Option<ForwardingState>,
    control_socket: ControlSocket,
    fatal_error: Option<String>,
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

    fn current_control_path() -> Result<PathBuf, RuntimeError> {
        let lock_path = Self::current_netns_path()?;
        Ok(lock_path.with_extension("sock"))
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

#[derive(serde::Serialize, serde::Deserialize)]
struct PeerReplacementRequest {
    interface: String,
    peers: Vec<PeerConfig>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ControlResponse {
    ok: bool,
    error: Option<String>,
}

struct ControlSocket {
    listener: UnixListener,
    path: PathBuf,
}

impl ControlSocket {
    fn bind(path: PathBuf) -> Result<Self, RuntimeError> {
        if path.exists() {
            match UnixStream::connect(&path) {
                Ok(_) => {
                    return Err(RuntimeError::Control(format!(
                        "control socket is already accepting connections: {}",
                        path.display()
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    let metadata = fs::symlink_metadata(&path)
                        .map_err(|error| RuntimeError::Control(error.to_string()))?;
                    if !metadata.file_type().is_socket() {
                        return Err(RuntimeError::Control(format!(
                            "refusing to replace non-socket path {}",
                            path.display()
                        )));
                    }
                    fs::remove_file(&path)
                        .map_err(|error| RuntimeError::Control(error.to_string()))?;
                }
                Err(error) => {
                    return Err(RuntimeError::Control(format!(
                        "cannot inspect existing control socket {}: {error}",
                        path.display()
                    )));
                }
            }
        }
        let listener =
            UnixListener::bind(&path).map_err(|error| RuntimeError::Control(error.to_string()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|error| RuntimeError::Control(error.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| RuntimeError::Control(error.to_string()))?;
        Ok(Self { listener, path })
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %self.path.display(), %error, "failed to remove control socket");
            }
        }
    }
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
        let control_socket = ControlSocket::bind(InstanceLock::current_control_path()?)?;
        let socket_fwmarks = config
            .resolved_socket_fwmarks()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let routing = RoutingPlan::from_config(&config);
        let backends = BackendRegistry::default();
        let prepared_interfaces = backends.prepare_config(&config)?;

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
                    prepared_interfaces.get(interface_name).ok_or_else(|| {
                        BackendError::new(format!(
                            "interface '{interface_name}' is missing its prepared backend configuration"
                        ))
                    })?,
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

        let stats_interval = Duration::from_secs(config.daemon.stats_interval_secs);
        tracing::info!(interfaces = devices.len(), "vpn-relay runtime started");
        Ok(Self {
            devices,
            config,
            prepared_interfaces,
            backends,
            routing,
            stats_interval,
            forwarding_state,
            control_socket,
            fatal_error: None,
            _instance_lock: instance_lock,
        })
    }

    pub fn routing_plan(&self) -> &RoutingPlan {
        &self.routing
    }

    /// Replace only the peer set of an existing interface. Endpoint DNS,
    /// keys and AllowedIPs are prepared before the live backend is changed;
    /// routing, firewall, interface identity and socket marks remain fixed.
    pub fn replace_peers(
        &mut self,
        interface_name: &str,
        peers: Vec<PeerConfig>,
    ) -> Result<(), RuntimeError> {
        let mut candidate = self.config.clone();
        let interface = candidate.interfaces.get_mut(interface_name).ok_or_else(|| {
            RuntimeError::Configuration(format!("unknown interface '{interface_name}'"))
        })?;
        interface.peers = peers;
        self.reload_config(candidate)
    }

    /// Apply mutable peer, routing-decision and firewall configuration.
    ///
    /// The compatibility check guarantees that policy-routing tables, marks,
    /// tunnel devices and forwarding ownership remain stable. Peer sets are
    /// committed first; the nftables table is then replaced in one kernel
    /// transaction. Any later failure restores already committed peer sets.
    pub fn reload_config(&mut self, candidate: Config) -> Result<(), RuntimeError> {
        candidate
            .validate()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        self.config
            .validate_reload_compatibility(&candidate)
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;

        let next_routing = RoutingPlan::from_config(&candidate);
        if self.routing.egresses != next_routing.egresses
            || self.routing.socket_marks != next_routing.socket_marks
        {
            return Err(RuntimeError::Configuration(
                "candidate changes live policy-routing resources; restart vpn-relay".to_owned(),
            ));
        }

        // Resolve and validate every changed peer set before the first live
        // device is touched. Keep the exact old endpoint resolutions for
        // unchanged peers so a later rollback never depends on fresh DNS.
        let mut prepared = self.prepared_interfaces.clone();
        let mut changed_interfaces = Vec::new();
        for (index, (name, next_interface)) in candidate.interfaces.iter().enumerate() {
            let current_interface = &self.config.interfaces[name];
            if current_interface.peers == next_interface.peers {
                continue;
            }
            let next_prepared = self.backends.prepare_interface(name, next_interface)?;
            prepared.insert(name.clone(), next_prepared);
            changed_interfaces.push((index, name.clone()));
        }

        let mut committed = Vec::new();
        for (index, name) in changed_interfaces {
            let next_interface = candidate.interfaces.get(&name).ok_or_else(|| {
                RuntimeError::Configuration(format!(
                    "candidate is missing interface '{name}' during peer commit"
                ))
            })?;
            let next_prepared = prepared.get(&name).ok_or_else(|| {
                RuntimeError::Configuration(format!(
                    "candidate is missing prepared backend configuration for '{name}'"
                ))
            })?;
            if let Err(error) = self.devices[index].replace_peers(next_interface, next_prepared) {
                self.rollback_peer_replacements(&committed)?;
                return Err(error.into());
            }
            committed.push(index);
        }

        if self.routing != next_routing {
            if let Err(error) = linux::apply_nft(&next_routing) {
                self.rollback_peer_replacements(&committed)?;
                return Err(error.into());
            }
        }

        self.config = candidate;
        self.prepared_interfaces = prepared;
        self.routing = next_routing;
        self.stats_interval = Duration::from_secs(self.config.daemon.stats_interval_secs);
        tracing::info!("runtime configuration reloaded");
        Ok(())
    }

    fn rollback_peer_replacements(&mut self, committed: &[usize]) -> Result<(), RuntimeError> {
        let mut failures = Vec::new();
        for index in committed.iter().rev().copied() {
            let Some((name, interface)) = self.config.interfaces.iter().nth(index) else {
                failures.push(format!("missing previous interface at device index {index}"));
                continue;
            };
            let Some(prepared) = self.prepared_interfaces.get(name) else {
                failures.push(format!("missing previous prepared configuration for '{name}'"));
                continue;
            };
            if let Err(error) = self.devices[index].replace_peers(interface, prepared) {
                failures.push(format!("{name}: {error}"));
            }
        }
        if failures.is_empty() {
            return Ok(());
        }

        let details = failures.join("; ");
        self.fatal_error = Some(details.clone());
        Err(RuntimeError::FatalRollback(details))
    }

    fn accept_control_connections(&mut self) {
        loop {
            match self.control_socket.listener.accept() {
                Ok((stream, _)) => self.handle_control_connection(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    tracing::warn!(%error, "failed to accept control connection");
                    break;
                }
            }
        }
    }

    fn handle_control_connection(&mut self, mut stream: UnixStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut payload = Vec::new();
        let read_result = (&mut stream)
            .take(1024 * 1024 + 1)
            .read_to_end(&mut payload);
        let response = match read_result {
            Ok(_) if payload.len() > 1024 * 1024 => ControlResponse {
                ok: false,
                error: Some("request exceeds 1 MiB limit".to_owned()),
            },
            Ok(_) => match serde_json::from_slice::<PeerReplacementRequest>(&payload) {
                Ok(request) => match self.replace_peers(&request.interface, request.peers) {
                    Ok(()) => ControlResponse {
                        ok: true,
                        error: None,
                    },
                    Err(error) => ControlResponse {
                        ok: false,
                        error: Some(error.to_string()),
                    },
                },
                Err(error) => ControlResponse {
                    ok: false,
                    error: Some(format!("invalid control request: {error}")),
                },
            },
            Err(error) => ControlResponse {
                ok: false,
                error: Some(format!("failed to read control request: {error}")),
            },
        };
        let write_result = serde_json::to_vec(&response)
            .map_err(|error| error.to_string())
            .and_then(|payload| {
                stream
                    .write_all(&payload)
                    .map_err(|error| error.to_string())
            });
        if let Err(error) = write_result {
            tracing::warn!(%error, "failed to send control response");
        }
    }

    /// Send a peer replacement request to the daemon in this network namespace.
    pub fn request_peer_replacement(
        interface: String,
        peers: Vec<PeerConfig>,
    ) -> Result<(), RuntimeError> {
        let path = InstanceLock::current_control_path()?;
        let mut stream =
            UnixStream::connect(&path).map_err(|error| RuntimeError::Control(error.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| RuntimeError::Control(error.to_string()))?;
        let request = PeerReplacementRequest { interface, peers };
        serde_json::to_writer(&mut stream, &request)
            .map_err(|error| RuntimeError::Control(error.to_string()))?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|error| RuntimeError::Control(error.to_string()))?;
        let mut response = Vec::new();
        (&mut stream)
            .take(64 * 1024)
            .read_to_end(&mut response)
            .map_err(|error| RuntimeError::Control(error.to_string()))?;
        let response: ControlResponse = serde_json::from_slice(&response)
            .map_err(|error| RuntimeError::Control(error.to_string()))?;
        if response.ok {
            Ok(())
        } else {
            Err(RuntimeError::Control(
                response
                    .error
                    .unwrap_or_else(|| "daemon rejected request".to_owned()),
            ))
        }
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
            self.accept_control_connections();
            if let Some(error) = &self.fatal_error {
                return Err(RuntimeError::FatalRollback(error.clone()));
            }
            let mut elapsed = 0;
            while elapsed < self.stats_interval.as_secs()
                && !SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
            {
                std::thread::sleep(Duration::from_secs(1));
                elapsed += 1;
                self.accept_control_connections();
                if let Some(error) = &self.fatal_error {
                    return Err(RuntimeError::FatalRollback(error.clone()));
                }
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

        // Runtime::drop performs the single ordered shutdown sequence.
        Ok(())
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // Stop datapath workers first, but keep the firewall active until all
        // managed TUN links have been destroyed. This matters when the host's
        // original forwarding state was already enabled.
        for device in &self.devices {
            device.shutdown();
        }
        for device in &mut self.devices {
            device.wait();
        }

        linux::remove_policy_routing(&self.routing);
        self.devices.clear();
        linux::remove_nft(&self.routing);

        if let Some(state) = &self.forwarding_state {
            restore_forwarding(state);
        }
    }
}

fn install_signal_handlers() -> Result<(), RuntimeError> {
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    unsafe {
        if libc::signal(
            libc::SIGINT,
            request_shutdown as *const () as libc::sighandler_t,
        ) == libc::SIG_ERR
        {
            return Err(RuntimeError::Signal("SIGINT".into()));
        }
        if libc::signal(
            libc::SIGTERM,
            request_shutdown as *const () as libc::sighandler_t,
        ) == libc::SIG_ERR
        {
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
    if let Err(error) = write_sysctl("net.ipv4.ip_forward", &state.ipv4) {
        tracing::warn!(%error, "failed to restore IPv4 forwarding state");
    }
    if let Err(error) = write_sysctl("net.ipv6.conf.all.forwarding", &state.ipv6) {
        tracing::warn!(%error, "failed to restore IPv6 forwarding state");
    }
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
    fn control_socket_is_private_and_removed_on_drop() {
        let path = std::env::temp_dir().join(format!(
            "vpn-relay-control-{}-{}.sock",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_file(&path);
        let socket = ControlSocket::bind(path.clone()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(UnixStream::connect(&path).is_ok());
        drop(socket);
        assert!(!path.exists());
    }

    #[test]
    fn control_socket_refuses_to_replace_regular_files() {
        let path = std::env::temp_dir().join(format!(
            "vpn-relay-control-file-{}.sock",
            std::process::id()
        ));
        std::fs::write(&path, b"do not replace").unwrap();
        assert!(matches!(
            ControlSocket::bind(path.clone()),
            Err(RuntimeError::Control(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"do not replace");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn control_socket_recovers_stale_socket_files() {
        let path = std::env::temp_dir().join(format!(
            "vpn-relay-control-stale-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let stale = UnixListener::bind(&path).unwrap();
        drop(stale);
        let socket = ControlSocket::bind(path.clone()).unwrap();
        assert!(path.exists());
        drop(socket);
        assert!(!path.exists());
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
