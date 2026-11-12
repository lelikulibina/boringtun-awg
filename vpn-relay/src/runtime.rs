//! Linux runtime: dispatch tunnel backends and install shared routing.
use crate::backend::{
    BackendError, BackendRegistry, PreparedInterface, TunnelHandle, TunnelSnapshot,
};
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
    #[error("conntrack decision-mark state error: {0}")]
    ConntrackMarkState(String),
    #[error("runtime transaction rollback or cleanup failed; daemon must stop: {0}")]
    FatalTransition(String),
}

pub struct Runtime {
    devices: Vec<Box<dyn TunnelHandle>>,
    config: Config,
    prepared_interfaces: std::collections::BTreeMap<String, PreparedInterface>,
    backends: BackendRegistry,
    routing: RoutingPlan,
    retired_routing: Vec<RoutingPlan>,
    conntrack_mark_state_path: PathBuf,
    conntrack_mark_history: Vec<crate::routing::RoutingDecision>,
    stats_interval: Duration,
    forwarding_state: Option<ForwardingState>,
    forwarding_state_path: PathBuf,
    control_socket: ControlSocket,
    fatal_error: Option<String>,
    /// Preserve the name-mismatch guards if the original TUN descriptor is lost.
    retain_firewall: bool,
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

    fn current_conntrack_mark_state_path() -> Result<PathBuf, RuntimeError> {
        let lock_path = Self::current_netns_path()?;
        Ok(lock_path.with_extension("marks"))
    }

    fn current_forwarding_state_path() -> Result<PathBuf, RuntimeError> {
        let lock_path = Self::current_netns_path()?;
        Ok(lock_path.with_extension("forwarding"))
    }

    fn current_netns_inode() -> Result<u64, RuntimeError> {
        std::fs::metadata("/proc/self/ns/net")
            .map(|metadata| metadata.ino())
            .map_err(|error| RuntimeError::InstanceLock(error.to_string()))
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

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConntrackMarkStateFile {
    version: u32,
    decisions: Vec<crate::routing::RoutingDecision>,
}

fn validate_private_state_file(path: &Path) -> Result<(), RuntimeError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(RuntimeError::ConntrackMarkState(format!(
            "refusing to use non-private state file {}",
            path.display()
        )));
    }
    Ok(())
}

fn load_conntrack_mark_history(
    path: &Path,
) -> Result<Vec<crate::routing::RoutingDecision>, RuntimeError> {
    // Open the inode we validate and read. A separate symlink_metadata()+read()
    // sequence permits a path swap between the security check and the read.
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(RuntimeError::ConntrackMarkState(error.to_string())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(RuntimeError::ConntrackMarkState(format!(
            "refusing to use non-private state file {}",
            path.display()
        )));
    }
    const MAX_STATE_FILE_SIZE: u64 = 4 * 1024 * 1024;
    if metadata.len() > MAX_STATE_FILE_SIZE {
        return Err(RuntimeError::ConntrackMarkState(
            "state file exceeds 4 MiB".to_owned(),
        ));
    }

    // Bound the read as well: the file may grow after fstat().
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_STATE_FILE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    if bytes.len() as u64 > MAX_STATE_FILE_SIZE {
        return Err(RuntimeError::ConntrackMarkState(
            "state file exceeds 4 MiB".to_owned(),
        ));
    }
    let state: ConntrackMarkStateFile = serde_json::from_slice(&bytes)
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    if state.version != 1 {
        return Err(RuntimeError::ConntrackMarkState(format!(
            "unsupported state file version {}",
            state.version
        )));
    }
    RoutingPlan::validate_conntrack_mark_history(&state.decisions)
        .map_err(RuntimeError::ConntrackMarkState)?;
    Ok(state.decisions)
}

fn persist_conntrack_mark_history(
    path: &Path,
    decisions: &[crate::routing::RoutingDecision],
) -> Result<(), RuntimeError> {
    RoutingPlan::validate_conntrack_mark_history(decisions)
        .map_err(RuntimeError::ConntrackMarkState)?;

    if path.exists() {
        validate_private_state_file(path)?;
    }

    let temporary_path = path.with_extension(format!("marks.tmp-{}", std::process::id()));
    if let Ok(metadata) = fs::symlink_metadata(&temporary_path) {
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(RuntimeError::ConntrackMarkState(format!(
                "refusing to replace unsafe temporary state file {}",
                temporary_path.display()
            )));
        }
        fs::remove_file(&temporary_path)
            .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary_path)
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    let state = ConntrackMarkStateFile {
        version: 1,
        decisions: decisions.to_vec(),
    };
    let write_result = serde_json::to_writer(&mut file, &state)
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))
        .and_then(|()| {
            file.sync_all()
                .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))
        });
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }

    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(RuntimeError::ConntrackMarkState(error.to_string()));
    }
    let parent = path.parent().ok_or_else(|| {
        RuntimeError::ConntrackMarkState("state file path has no parent directory".to_owned())
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    Ok(())
}

fn commit_peer_replacements(
    devices: &mut [Box<dyn TunnelHandle>],
    changed_interfaces: &[(usize, String)],
    candidate: &Config,
    prepared: &std::collections::BTreeMap<String, PreparedInterface>,
) -> Result<Vec<usize>, (Vec<usize>, RuntimeError)> {
    let mut committed = Vec::with_capacity(changed_interfaces.len());
    for (index, name) in changed_interfaces {
        let Some(interface) = candidate.interfaces.get(name) else {
            return Err((
                committed,
                RuntimeError::Configuration(format!(
                    "candidate is missing interface '{name}' during peer commit"
                )),
            ));
        };
        let Some(prepared_interface) = prepared.get(name) else {
            return Err((
                committed,
                RuntimeError::Configuration(format!(
                    "candidate is missing prepared backend configuration for '{name}'"
                )),
            ));
        };
        let Some(device) = devices.get_mut(*index) else {
            return Err((
                committed,
                RuntimeError::Configuration(format!(
                    "candidate interface '{name}' has no matching tunnel device"
                )),
            ));
        };
        if let Err(error) = device.replace_peers(interface, prepared_interface) {
            return Err((committed, RuntimeError::Backend(error)));
        }
        committed.push(*index);
    }
    Ok(committed)
}

fn rollback_peer_replacements(
    devices: &mut [Box<dyn TunnelHandle>],
    committed: &[usize],
    previous_config: &Config,
    previous_prepared: &std::collections::BTreeMap<String, PreparedInterface>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for index in committed.iter().rev().copied() {
        let Some((name, interface)) = previous_config.interfaces.iter().nth(index) else {
            failures.push(format!(
                "missing previous interface at device index {index}"
            ));
            continue;
        };
        let Some(prepared) = previous_prepared.get(name) else {
            failures.push(format!(
                "missing previous prepared configuration for '{name}'"
            ));
            continue;
        };
        let Some(device) = devices.get_mut(index) else {
            failures.push(format!(
                "missing tunnel device for '{name}' at index {index}"
            ));
            continue;
        };
        if let Err(error) = device.replace_peers(interface, prepared) {
            failures.push(format!("{name}: {error}"));
        }
    }
    failures
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
struct ForwardingState {
    ipv4: String,
    ipv4_changed: bool,
    /// Per-link state is optional so version-1 namespace-only journals remain readable.
    #[serde(default)]
    interfaces: Vec<InterfaceForwardingState>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
struct InterfaceForwardingState {
    name: String,
    ifindex: u32,
    /// True when this link is created and destroyed by vpn-relay's TUN backend.
    #[serde(default)]
    daemon_owned: bool,
    ipv4: String,
    ipv4_changed: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardingStateFile {
    version: u32,
    namespace_inode: u64,
    state: ForwardingState,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum ControlRequest {
    ReplacePeers {
        interface: String,
        peers: Vec<PeerConfig>,
    },
    ReloadConfig {
        toml: String,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ControlResponse {
    ok: bool,
    error: Option<String>,
}

struct ControlSocket {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
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
        Self::bind_with(path, |path, listener| {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            listener.set_nonblocking(true)
        })
    }

    fn bind_with(
        path: PathBuf,
        configure: impl FnOnce(&Path, &UnixListener) -> std::io::Result<()>,
    ) -> Result<Self, RuntimeError> {
        let listener =
            UnixListener::bind(&path).map_err(|error| RuntimeError::Control(error.to_string()))?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| RuntimeError::Control(error.to_string()))?;
        if !metadata.file_type().is_socket() {
            return Err(RuntimeError::Control(format!(
                "control socket path was replaced during bind: {}",
                path.display()
            )));
        }
        let device = metadata.dev();
        let inode = metadata.ino();
        if let Err(error) = configure(&path, &listener) {
            drop(listener);
            remove_owned_socket_path(&path, device, inode);
            return Err(RuntimeError::Control(error.to_string()));
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                drop(listener);
                remove_owned_socket_path(&path, device, inode);
                return Err(RuntimeError::Control(error.to_string()));
            }
        };
        if !metadata.file_type().is_socket() || metadata.dev() != device || metadata.ino() != inode
        {
            return Err(RuntimeError::Control(format!(
                "control socket path changed while being configured: {}",
                path.display()
            )));
        }
        Ok(Self {
            listener,
            path,
            device,
            inode,
        })
    }
}

fn remove_owned_socket_path(path: &Path, device: u64, inode: u64) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "failed to inspect control socket before unlink");
            return;
        }
    };
    if !metadata.file_type().is_socket() || metadata.dev() != device || metadata.ino() != inode {
        tracing::warn!(path = %path.display(), "control socket path no longer refers to the daemon-owned socket; refusing to unlink it");
        return;
    }
    if let Err(error) = fs::remove_file(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(path = %path.display(), %error, "failed to remove control socket");
        }
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        remove_owned_socket_path(&self.path, self.device, self.inode);
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
        let forwarding_state_path = InstanceLock::current_forwarding_state_path()?;
        let namespace_inode = InstanceLock::current_netns_inode()?;
        recover_forwarding_state(&forwarding_state_path, namespace_inode)?;
        let control_socket = ControlSocket::bind(InstanceLock::current_control_path()?)?;
        let conntrack_mark_state_path = InstanceLock::current_conntrack_mark_state_path()?;
        let mut conntrack_mark_history = load_conntrack_mark_history(&conntrack_mark_state_path)?;
        let socket_fwmarks = config
            .resolved_socket_fwmarks()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let mut routing = RoutingPlan::from_config(&config);
        routing
            .assign_stable_conntrack_marks(&mut conntrack_mark_history)
            .map_err(RuntimeError::ConntrackMarkState)?;
        persist_conntrack_mark_history(&conntrack_mark_state_path, &conntrack_mark_history)?;
        let backends = BackendRegistry::default();
        let prepared_interfaces = backends.prepare_config(&config)?;

        // Install a drop-only bootstrap policy before creating any TUN.
        // It scopes drops by the configured names but contains no allow rules;
        // after descriptor verification it is atomically replaced by the
        // numeric-ifindex policy. This prevents traffic from slipping through
        // during link creation/configuration even if forwarding is pre-enabled.
        let bootstrap_routing = routing.fail_closed_bootstrap();
        linux::apply_nft(&bootstrap_routing)?;

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
                devices
                    .last()
                    .expect("just-pushed tunnel handle")
                    .verify_identity()
                    .map_err(|error| {
                        RuntimeError::FatalTransition(format!(
                            "new tunnel interface '{interface_name}' failed its identity check: {error}"
                        ))
                    })?;
                linux::configure_interface(interface_name, interface.mtu, &interface.address)?;
            }
            // Recheck the complete set after address/MTU configuration and
            // before installing any policy routes that refer to interface names.
            for (index, device) in devices.iter().enumerate() {
                device.verify_identity().map_err(|error| {
                    RuntimeError::FatalTransition(format!(
                        "tunnel device at runtime index {index} lost its identity during startup: {error}"
                    ))
                })?;
            }
            Ok(())
        })();
        if let Err(error) = setup_result {
            // Dropping the handles stops and joins any workers created before
            // the failing interface; the firewall is removed only afterwards.
            drop(devices);
            if let Err(cleanup) = linux::remove_nft(&routing) {
                return Err(RuntimeError::FatalTransition(format!(
                    "interface setup failed ({error}); nftables cleanup failed ({cleanup})"
                )));
            }
            return Err(error);
        }

        // Replace bootstrap name selectors with indices resolved only after
        // checking each original TUN descriptor. This switch is atomic in nft.
        let interface_indices_result = (|| -> Result<_, RuntimeError> {
            let mut indices = std::collections::BTreeMap::new();
            for (index, (name, _)) in config.interfaces.iter().enumerate() {
                devices[index].verify_identity()?;
                indices.insert(name.clone(), linux::interface_index(name)?);
                devices[index].verify_identity()?;
            }
            Ok(indices)
        })();
        let interface_indices = match interface_indices_result {
            Ok(indices) => indices,
            Err(error) => {
                drop(devices);
                if let Err(cleanup) = linux::remove_nft(&routing) {
                    return Err(RuntimeError::FatalTransition(format!(
                        "interface identity resolution failed ({error}); bootstrap firewall cleanup failed ({cleanup})"
                    )));
                }
                return Err(error);
            }
        };
        if let Err(error) = routing.bind_interface_indices(interface_indices) {
            drop(devices);
            if let Err(cleanup) = linux::remove_nft(&routing) {
                return Err(RuntimeError::FatalTransition(format!(
                    "interface index binding failed ({error}); bootstrap firewall cleanup failed ({cleanup})"
                )));
            }
            return Err(RuntimeError::Configuration(error));
        }
        if let Err(error) = linux::apply_nft(&routing) {
            drop(devices);
            if let Err(cleanup) = linux::remove_nft(&routing) {
                return Err(RuntimeError::FatalTransition(format!(
                    "numeric firewall install failed ({error}); cleanup failed ({cleanup})"
                )));
            }
            return Err(error.into());
        }

        // Close the lookup-to-activation race as far as userspace can:
        // every descriptor must still identify its original link after the
        // numeric nftables policy has been installed.
        let identity_error = devices
            .iter()
            .enumerate()
            .find_map(|(index, device)| device.verify_identity().err().map(|error| (index, error)));
        if let Some((index, error)) = identity_error {
            drop(devices);
            return Err(RuntimeError::FatalTransition(format!(
                "tunnel identity changed while activating numeric firewall (device {index}): {error}; retaining fail-closed nftables policy"
            )));
        }

        if let Err(error) = linux::apply_policy_routing(&routing) {
            drop(devices);
            if matches!(&error, LinuxError::Rollback { .. } | LinuxError::Cleanup(_)) {
                tracing::error!(%error, "startup policy-routing rollback failed; retaining nftables policy");
                return Err(RuntimeError::FatalTransition(error.to_string()));
            }
            if let Err(cleanup) = linux::remove_nft(&routing) {
                return Err(RuntimeError::FatalTransition(format!(
                    "policy-routing setup failed ({error}); nftables cleanup failed ({cleanup})"
                )));
            }
            return Err(error.into());
        }

        let forwarding_state = if config.daemon.manage_ip_forwarding {
            match enable_forwarding_durable(
                &forwarding_state_path,
                namespace_inode,
                &config.daemon.forwarding_interfaces,
                &config.interfaces.keys().cloned().collect(),
            ) {
                Ok(state) => Some(state),
                Err(error) => {
                    let route_cleanup = linux::remove_policy_routing(&routing);
                    drop(devices);
                    if let Err(cleanup) = route_cleanup {
                        tracing::error!(
                            %cleanup,
                            "startup policy-routing cleanup failed; retaining nftables policy"
                        );
                        return Err(RuntimeError::FatalTransition(format!(
                            "forwarding setup failed ({error}); policy-routing cleanup failed ({cleanup})"
                        )));
                    }
                    // If restoring the original forwarding value failed, the
                    // firewall is the remaining fail-closed protection.
                    if matches!(&error, RuntimeError::FatalTransition(_)) {
                        tracing::error!(
                            %error,
                            "startup aborted with forwarding state uncertain; retaining nftables policy"
                        );
                        return Err(error);
                    }
                    if let Err(cleanup) = linux::remove_nft(&routing) {
                        return Err(RuntimeError::FatalTransition(format!(
                            "forwarding setup failed ({error}); nftables cleanup failed ({cleanup})"
                        )));
                    }
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
            retired_routing: Vec::new(),
            conntrack_mark_state_path,
            conntrack_mark_history,
            stats_interval,
            forwarding_state,
            forwarding_state_path,
            control_socket,
            fatal_error: None,
            retain_firewall: false,
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
        let interface = candidate
            .interfaces
            .get_mut(interface_name)
            .ok_or_else(|| {
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
        self.verify_tunnel_identities()?;
        if let Some(error) = &self.fatal_error {
            return Err(RuntimeError::FatalTransition(error.clone()));
        }
        candidate
            .validate()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        self.config
            .validate_reload_compatibility(&candidate)
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;

        let mut next_routing = RoutingPlan::from_config(&candidate);
        let mut next_conntrack_mark_history = self.conntrack_mark_history.clone();
        next_routing
            .assign_stable_conntrack_marks(&mut next_conntrack_mark_history)
            .map_err(RuntimeError::ConntrackMarkState)?;
        if let Some(indices) = self.routing.interface_indices.clone() {
            next_routing
                .bind_interface_indices(indices)
                .map_err(RuntimeError::Configuration)?;
        }
        if self.routing.socket_marks != next_routing.socket_marks {
            return Err(RuntimeError::Configuration(
                "candidate changes live socket fwmarks; restart vpn-relay".to_owned(),
            ));
        }

        // RoutingPlan::from_config starts with the default table/priority
        // numbers. Preserve the dynamically allocated live slots when the
        // actual egress identity and fwmark are unchanged; otherwise every
        // peer-only or firewall-only reload would look like a route migration.
        let same_egress_resources = self.routing.egresses.len() == next_routing.egresses.len()
            && next_routing.egresses.iter().all(|next| {
                self.routing
                    .egresses
                    .iter()
                    .any(|current| current.interface == next.interface && current.mark == next.mark)
            });
        if same_egress_resources {
            for next in &mut next_routing.egresses {
                if let Some(current) = self
                    .routing
                    .egresses
                    .iter()
                    .find(|current| current.interface == next.interface)
                {
                    next.table_id = current.table_id;
                    next.ip_rule_priority = current.ip_rule_priority;
                }
            }
        }
        let route_resources_changed = !same_egress_resources;
        if route_resources_changed {
            let mut occupied = self.retired_routing.clone();
            occupied.push(self.routing.clone());
            linux::allocate_policy_routing_resources(&mut next_routing, &occupied)?;
        }

        // Resolve and validate every changed peer set before the first live
        // device or routing resource is touched. Keep exact old endpoint
        // resolutions for unchanged peers so rollback never depends on DNS.
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

        if next_conntrack_mark_history != self.conntrack_mark_history {
            // Reserve new decision IDs before they can be written into conntrack.
            // Failed reloads may leave unused IDs reserved; that is safe, while
            // reusing an ID still present in conntrack would not be.
            if let Err(error) = persist_conntrack_mark_history(
                &self.conntrack_mark_state_path,
                &next_conntrack_mark_history,
            ) {
                let details = format!("failed to persist conntrack decision marks: {error}");
                self.fatal_error = Some(details.clone());
                return Err(RuntimeError::FatalTransition(details));
            }
            self.conntrack_mark_history = next_conntrack_mark_history.clone();
        }

        // New policy routes use disjoint marks, tables and priorities. They are
        // installed while the old nft classifier still emits only old marks.
        if route_resources_changed {
            if let Err(error) = linux::apply_egress_policy_routing(&next_routing) {
                self.rollback_reload(&[], Some(&next_routing))?;
                return Err(error.into());
            }
        }

        let committed = match commit_peer_replacements(
            &mut self.devices,
            &changed_interfaces,
            &candidate,
            &prepared,
        ) {
            Ok(committed) => committed,
            Err((committed, error)) => {
                self.rollback_reload(&committed, route_resources_changed.then_some(&next_routing))?;
                return Err(error);
            }
        };

        if self.routing != next_routing {
            if let Err(error) = linux::apply_nft(&next_routing) {
                self.rollback_reload(&committed, route_resources_changed.then_some(&next_routing))?;
                return Err(error.into());
            }
        }

        let previous_routing = self.routing.clone();
        self.config = candidate;
        self.prepared_interfaces = prepared;
        self.routing = next_routing;
        self.stats_interval = Duration::from_secs(self.config.daemon.stats_interval_secs);

        // Only after nftables selects the new marks can old policy routes be
        // removed. Retain the old plan until cleanup succeeds so Drop can retry.
        if route_resources_changed {
            self.retired_routing.push(previous_routing.clone());
            if let Err(error) = linux::remove_egress_policy_routing(&previous_routing) {
                let details = format!(
                    "new routing plan is active but old policy routes could not be removed: {error}"
                );
                self.fatal_error = Some(details.clone());
                return Err(RuntimeError::FatalTransition(details));
            }
            self.retired_routing.pop();
        }

        tracing::info!("runtime configuration reloaded");
        Ok(())
    }

    fn rollback_reload(
        &mut self,
        committed: &[usize],
        staged_routing: Option<&RoutingPlan>,
    ) -> Result<(), RuntimeError> {
        let mut failures = self.rollback_peer_replacements(committed);
        if let Some(plan) = staged_routing {
            self.retired_routing.push(plan.clone());
            if let Err(error) = linux::remove_egress_policy_routing(plan) {
                failures.push(format!("staged policy routes: {error}"));
            } else {
                self.retired_routing.pop();
            }
        }

        if failures.is_empty() {
            return Ok(());
        }

        let details = failures.join("; ");
        self.fatal_error = Some(details.clone());
        Err(RuntimeError::FatalTransition(details))
    }

    fn verify_tunnel_identities(&mut self) -> Result<(), RuntimeError> {
        for (index, device) in self.devices.iter().enumerate() {
            if let Err(error) = device.verify_identity() {
                let details = format!(
                    "tunnel device at runtime index {index} lost its original interface identity: {error}"
                );
                self.fatal_error = Some(details.clone());
                self.retain_firewall = true;
                return Err(RuntimeError::FatalTransition(details));
            }
        }
        if !self.config.daemon.forwarding_interfaces.is_empty() {
            let state = self.forwarding_state.as_ref().ok_or_else(|| {
                RuntimeError::FatalTransition(
                    "per-interface forwarding state is missing while forwarding management is enabled".to_owned(),
                )
            })?;
            if let Err(error) =
                verify_managed_forwarding_runtime(&self.config.daemon.forwarding_interfaces, state)
            {
                let details =
                    format!("per-interface forwarding invariants changed at runtime: {error}");
                self.fatal_error = Some(details.clone());
                self.retain_firewall = true;
                return Err(RuntimeError::FatalTransition(details));
            }
        }
        Ok(())
    }

    fn rollback_peer_replacements(&mut self, committed: &[usize]) -> Vec<String> {
        rollback_peer_replacements(
            &mut self.devices,
            committed,
            &self.config,
            &self.prepared_interfaces,
        )
    }

    fn accept_control_connections(&mut self) {
        // A failed rollback or post-commit cleanup makes the datapath state
        // unsuitable for further management operations. Do not drain queued
        // requests after the transition to fatal state: run() will return and
        // Runtime::drop will perform the ordered shutdown.
        if self.fatal_error.is_some() {
            return;
        }

        loop {
            match self.control_socket.listener.accept() {
                Ok((stream, _)) => {
                    self.handle_control_connection(stream);
                    // A request may itself trigger a fatal transition. Stop
                    // immediately rather than accepting another queued reload
                    // or peer replacement in the partially committed state.
                    if self.fatal_error.is_some() {
                        break;
                    }
                }
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
            Ok(_) => match serde_json::from_slice::<ControlRequest>(&payload) {
                Ok(request) => {
                    let result = match request {
                        ControlRequest::ReplacePeers { interface, peers } => {
                            self.replace_peers(&interface, peers)
                        }
                        ControlRequest::ReloadConfig { toml } => Config::parse_toml(&toml)
                            .map_err(|error| RuntimeError::Configuration(error.to_string()))
                            .and_then(|candidate| self.reload_config(candidate)),
                    };
                    match result {
                        Ok(()) => ControlResponse {
                            ok: true,
                            error: None,
                        },
                        Err(error) => ControlResponse {
                            ok: false,
                            error: Some(error.to_string()),
                        },
                    }
                }
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
        Self::send_control_request(ControlRequest::ReplacePeers { interface, peers })
    }

    /// Send a complete TOML configuration to the running daemon for validation
    /// and transactional application.
    pub fn request_config_reload(toml: String) -> Result<(), RuntimeError> {
        Self::send_control_request(ControlRequest::ReloadConfig { toml })
    }

    fn send_control_request(request: ControlRequest) -> Result<(), RuntimeError> {
        let path = InstanceLock::current_control_path()?;
        let mut stream =
            UnixStream::connect(&path).map_err(|error| RuntimeError::Control(error.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(300)))
            .map_err(|error| RuntimeError::Control(error.to_string()))?;
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
            self.verify_tunnel_identities()?;
            self.accept_control_connections();
            if let Some(error) = &self.fatal_error {
                return Err(RuntimeError::FatalTransition(error.clone()));
            }
            let mut elapsed = 0;
            while elapsed < self.stats_interval.as_secs()
                && !SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
            {
                std::thread::sleep(Duration::from_secs(1));
                elapsed += 1;
                self.verify_tunnel_identities()?;
                self.accept_control_connections();
                if let Some(error) = &self.fatal_error {
                    return Err(RuntimeError::FatalTransition(error.clone()));
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
        // Stop datapath workers first. Keep firewall installed while policy
        // routing and forwarding state are restored, then destroy managed
        // TUN links and finally remove the firewall.
        for device in &self.devices {
            device.shutdown();
        }
        for device in &mut self.devices {
            device.wait();
        }

        let mut cleanup_failures = Vec::new();
        for retired in &self.retired_routing {
            if let Err(error) = linux::remove_egress_policy_routing(retired) {
                cleanup_failures.push(format!("retired policy routing: {error}"));
            }
        }
        if let Err(error) = linux::remove_policy_routing(&self.routing) {
            cleanup_failures.push(format!("active policy routing: {error}"));
        }
        // Restore persistent external-link sysctls before tearing down TUNs.
        // Daemon-owned TUN entries are skipped because their sysctls disappear
        // with the non-persistent link; keep the firewall until teardown ends.
        if let Some(state) = &self.forwarding_state {
            match restore_forwarding(state) {
                Ok(()) => {
                    if let Err(error) = remove_forwarding_state_file(&self.forwarding_state_path) {
                        cleanup_failures.push(error.to_string());
                    }
                }
                Err(error) => cleanup_failures.push(error.to_string()),
            }
        }
        self.devices.clear();

        if !cleanup_failures.is_empty() {
            tracing::error!(
                failures = %cleanup_failures.join("; "),
                "shutdown cleanup incomplete; retaining fail-closed nftables policy"
            );
        } else if self.retain_firewall {
            tracing::error!(
                fatal_error = ?self.fatal_error,
                "original TUN identity was lost; retaining fail-closed nftables policy"
            );
        } else if let Err(error) = linux::remove_nft(&self.routing) {
            tracing::error!(%error, "failed to remove vpn-relay nftables policy");
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

fn enable_forwarding_state_with(
    mut state: ForwardingState,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
) -> Result<ForwardingState, RuntimeError> {
    if state.ipv4 != "1" {
        state.ipv4_changed = true;
        if let Err(enable_error) = write("net.ipv4.ip_forward", "1") {
            if let Err(restore_error) = restore_forwarding_with(&state, &mut write) {
                return Err(RuntimeError::FatalTransition(format!(
                    "IPv4 forwarding enable failed ({enable_error}); restoring original forwarding state also failed ({restore_error}); fail-closed nftables policy must remain installed"
                )));
            }
            return Err(enable_error);
        }
    }
    Ok(state)
}

fn validate_forwarding_state(state: &ForwardingState) -> Result<(), RuntimeError> {
    if !matches!(state.ipv4.as_str(), "0" | "1") {
        return Err(RuntimeError::Forwarding(
            "forwarding state contains an invalid IPv4 sysctl value".to_owned(),
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    let mut indices = std::collections::BTreeSet::new();
    for entry in &state.interfaces {
        if entry.name.is_empty()
            || entry.name.len() > 15
            || !entry.name.is_ascii()
            || !entry
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || entry.ifindex == 0
        {
            return Err(RuntimeError::Forwarding(
                "forwarding journal contains an invalid interface identity".to_owned(),
            ));
        }
        if !matches!(entry.ipv4.as_str(), "0" | "1") {
            return Err(RuntimeError::Forwarding(format!(
                "forwarding journal contains an invalid IPv4 sysctl value for interface '{}'",
                entry.name
            )));
        }
        if !names.insert(entry.name.as_str()) || !indices.insert(entry.ifindex) {
            return Err(RuntimeError::Forwarding(format!(
                "forwarding journal contains a duplicate interface name or ifindex for '{}'/{}",
                entry.name, entry.ifindex
            )));
        }
    }
    Ok(())
}

fn load_forwarding_state(
    path: &Path,
    namespace_inode: u64,
) -> Result<Option<ForwardingState>, RuntimeError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(RuntimeError::Forwarding(error.to_string())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(RuntimeError::Forwarding(format!(
            "refusing to use non-private forwarding state file {}",
            path.display()
        )));
    }
    const MAX_FORWARDING_STATE_SIZE: u64 = 64 * 1024;
    if metadata.len() > MAX_FORWARDING_STATE_SIZE {
        return Err(RuntimeError::Forwarding(
            "forwarding state file exceeds 64 KiB".to_owned(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FORWARDING_STATE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    if bytes.len() as u64 > MAX_FORWARDING_STATE_SIZE {
        return Err(RuntimeError::Forwarding(
            "forwarding state file exceeds 4 KiB".to_owned(),
        ));
    }
    let document: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    let state = document.get("state").unwrap_or(&document);
    let global_ipv6_pending = state
        .get("ipv6_changed")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let interface_ipv6_pending = state
        .get("interfaces")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry
                    .get("ipv6_changed")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
            })
        });
    if global_ipv6_pending || interface_ipv6_pending {
        return Err(RuntimeError::Forwarding(format!(
            "legacy forwarding journal '{}' contains pending IPv6 sysctl recovery; vpn-relay no longer manages IPv6, restore the recorded IPv6 values manually before removing this journal",
            path.display()
        )));
    }
    let saved: ForwardingStateFile = serde_json::from_value(document)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    if saved.version != 1 {
        return Err(RuntimeError::Forwarding(format!(
            "unsupported forwarding state version {}",
            saved.version
        )));
    }
    if saved.namespace_inode != namespace_inode {
        return Err(RuntimeError::Forwarding(format!(
            "forwarding state belongs to network namespace {}, current namespace is {}",
            saved.namespace_inode, namespace_inode
        )));
    }
    validate_forwarding_state(&saved.state)?;
    Ok(Some(saved.state))
}

fn persist_forwarding_state(
    path: &Path,
    namespace_inode: u64,
    state: &ForwardingState,
) -> Result<(), RuntimeError> {
    validate_forwarding_state(state)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let _ = load_forwarding_state(path, namespace_inode)?.ok_or_else(|| {
                RuntimeError::Forwarding(
                    "forwarding state disappeared during validation".to_owned(),
                )
            })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(RuntimeError::Forwarding(error.to_string())),
    }
    let temporary_path = path.with_extension(format!("forwarding.tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary_path)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    let saved = ForwardingStateFile {
        version: 1,
        namespace_inode,
        state: state.clone(),
    };
    let result = serde_json::to_writer(&mut file, &saved)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))
        .and_then(|()| {
            file.sync_all()
                .map_err(|error| RuntimeError::Forwarding(error.to_string()))
        });
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(RuntimeError::Forwarding(error.to_string()));
    }
    let parent = path.parent().ok_or_else(|| {
        RuntimeError::Forwarding("forwarding state path has no parent directory".to_owned())
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))
}

fn remove_forwarding_state_file(path: &Path) -> Result<(), RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o777 == 0o600
                && metadata.nlink() == 1 =>
        {
            fs::remove_file(path).map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
            let parent = path.parent().ok_or_else(|| {
                RuntimeError::Forwarding("forwarding state path has no parent directory".to_owned())
            })?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| RuntimeError::Forwarding(error.to_string()))
        }
        Ok(_) => Err(RuntimeError::Forwarding(format!(
            "refusing to remove non-private forwarding state file {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RuntimeError::Forwarding(error.to_string())),
    }
}

fn interface_forwarding_sysctl_key(name: &str) -> Result<String, RuntimeError> {
    if name.is_empty()
        || name.len() > 15
        || !name.is_ascii()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || name == "."
        || name == ".."
    {
        return Err(RuntimeError::Forwarding(
            "refusing to construct a sysctl path from an invalid interface name".to_owned(),
        ));
    }
    Ok(format!("net.ipv4.conf.{name}.forwarding"))
}

fn read_forwarding_state_value(state: &ForwardingState, key: &str) -> Result<String, RuntimeError> {
    for entry in &state.interfaces {
        if key == interface_forwarding_sysctl_key(&entry.name)? {
            let enabled = linux::ipv4_interface_forwarding(entry.ifindex)
                .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
            return Ok(if enabled { "1" } else { "0" }.to_owned());
        }
    }
    read_sysctl(key)
}

fn write_forwarding_state_value(
    state: &ForwardingState,
    key: &str,
    value: &str,
) -> Result<(), RuntimeError> {
    for entry in &state.interfaces {
        if key == interface_forwarding_sysctl_key(&entry.name)? {
            let enabled = match value {
                "0" => false,
                "1" => true,
                _ => {
                    return Err(RuntimeError::Forwarding(
                        "IPv4 forwarding must be 0 or 1".to_owned(),
                    ))
                }
            };
            verify_forwarding_interface(&entry.name, entry.ifindex)?;
            linux::set_ipv4_interface_forwarding(entry.ifindex, enabled)
                .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
            verify_forwarding_interface(&entry.name, entry.ifindex)?;
            return Ok(());
        }
    }
    write_sysctl(key, value)
}

fn restore_interface_forwarding_entry_with(
    entry: &InterfaceForwardingState,
    original: &str,
    changed: bool,
    mut read: impl FnMut(&str) -> Result<String, RuntimeError>,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
    mut verify: impl FnMut(&str, u32) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    if !changed {
        return Ok(());
    }
    let key = interface_forwarding_sysctl_key(&entry.name)?;
    if let Err(error) = verify(&entry.name, entry.ifindex) {
        if entry.daemon_owned {
            return Ok(());
        }
        return Err(error);
    }
    let current = read(&key)?;
    if current == original || current != "1" {
        return Ok(());
    }
    verify(&entry.name, entry.ifindex)?;
    write(&key, original)
}

fn verify_forwarding_interface(name: &str, index: u32) -> Result<(), RuntimeError> {
    linux::verify_interface_identity(name, index)
        .map_err(|error| RuntimeError::Forwarding(error.to_string()))
}

fn restore_interface_forwarding_entries_with(
    state: &ForwardingState,
    mut read: impl FnMut(&str) -> Result<String, RuntimeError>,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
    mut verify: impl FnMut(&str, u32) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let mut failures = Vec::new();
    for entry in &state.interfaces {
        if entry.daemon_owned {
            continue;
        }
        if let Err(error) = restore_interface_forwarding_entry_with(
            entry,
            &entry.ipv4,
            entry.ipv4_changed,
            &mut read,
            &mut write,
            &mut verify,
        ) {
            failures.push(format!("{} IPv4: {error}", entry.name));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::FatalTransition(format!(
            "failed to recover per-interface forwarding state: {}",
            failures.join("; ")
        )))
    }
}

fn verify_managed_forwarding_runtime(
    allowed_names: &[String],
    state: &ForwardingState,
) -> Result<(), RuntimeError> {
    if read_sysctl("net.ipv4.ip_forward")? != "1" {
        return Err(RuntimeError::Forwarding(
            "namespace-wide IPv4 forwarding prerequisite changed".to_owned(),
        ));
    }
    let allowed = allowed_names
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    validate_unmanaged_forwarding_with(
        &allowed,
        &interface_sysctl_names("/proc/sys/net/ipv4/conf")?,
        read_unmanaged_forwarding_sysctl,
    )?;
    for entry in &state.interfaces {
        verify_forwarding_interface(&entry.name, entry.ifindex)?;
        if !linux::ipv4_interface_forwarding(entry.ifindex)
            .map_err(|error| RuntimeError::Forwarding(error.to_string()))?
        {
            return Err(RuntimeError::Forwarding(format!(
                "managed interface '{}' lost its IPv4 forwarding enable value",
                entry.name
            )));
        }
    }
    Ok(())
}

fn validate_unmanaged_forwarding_with(
    allowed: &std::collections::BTreeSet<String>,
    ipv4_interfaces: &[String],
    mut read: impl FnMut(&str) -> Result<Option<String>, RuntimeError>,
) -> Result<(), RuntimeError> {
    for name in ipv4_interfaces {
        if allowed.contains(name) {
            continue;
        }
        let key = format!("net.ipv4.conf.{name}.forwarding");
        let Some(value) = read(&key)? else {
            return Err(RuntimeError::Forwarding(format!(
                "IPv4 forwarding sysctl is unavailable for unmanaged interface '{name}'"
            )));
        };
        if value.trim() != "0" {
            return Err(RuntimeError::Forwarding(format!(
                "unmanaged interface '{name}' has IPv4 forwarding enabled; disable it or add the interface to daemon.forwarding_interfaces"
            )));
        }
    }
    Ok(())
}

fn read_unmanaged_forwarding_sysctl(key: &str) -> Result<Option<String>, RuntimeError> {
    read_sysctl(key).map(Some)
}

fn interface_sysctl_names(directory: &str) -> Result<Vec<String>, RuntimeError> {
    let entries =
        fs::read_dir(directory).map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
        let name = entry.file_name().into_string().map_err(|_| {
            RuntimeError::Forwarding(format!("non-UTF-8 interface sysctl entry in {directory}"))
        })?;
        if name != "all" && name != "default" {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

fn enable_interface_forwarding_durable(
    path: &Path,
    namespace_inode: u64,
    names: &[String],
    daemon_owned_names: &std::collections::BTreeSet<String>,
) -> Result<ForwardingState, RuntimeError> {
    if read_sysctl("net.ipv4.ip_forward")? != "1" {
        return Err(RuntimeError::Forwarding(
            "per-interface forwarding requires net.ipv4.ip_forward=1; configure this namespace-wide prerequisite externally".to_owned(),
        ));
    }
    let allowed = names
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    validate_unmanaged_forwarding_with(
        &allowed,
        &interface_sysctl_names("/proc/sys/net/ipv4/conf")?,
        read_unmanaged_forwarding_sysctl,
    )?;
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let ifindex = linux::interface_index(name)
            .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
        verify_forwarding_interface(name, ifindex)?;
        let ipv4 = linux::ipv4_interface_forwarding(ifindex)
            .map_err(|error| RuntimeError::Forwarding(error.to_string()))?;
        verify_forwarding_interface(name, ifindex)?;
        entries.push(InterfaceForwardingState {
            name: name.clone(),
            ifindex,
            daemon_owned: daemon_owned_names.contains(name),
            ipv4: if ipv4 { "1" } else { "0" }.to_owned(),
            ipv4_changed: false,
        });
    }
    let mut state = ForwardingState {
        ipv4: "1".to_owned(),
        ipv4_changed: false,
        interfaces: entries,
    };
    for entry in &mut state.interfaces {
        entry.ipv4_changed = entry.ipv4 != "1";
    }
    validate_forwarding_state(&state)?;
    if state.interfaces.iter().any(|entry| entry.ipv4_changed) {
        persist_forwarding_state(path, namespace_inode, &state)?;
    }
    if let Err(error) = enable_interface_forwarding_entries_with(
        &state,
        |key| read_forwarding_state_value(&state, key),
        |key, value| write_forwarding_state_value(&state, key, value),
        verify_forwarding_interface,
    ) {
        if matches!(error, RuntimeError::FatalTransition(_)) {
            return Err(error);
        }
        remove_forwarding_state_file(path)?;
        return Err(error);
    }
    Ok(state)
}

fn enable_interface_forwarding_entries_with(
    state: &ForwardingState,
    mut read: impl FnMut(&str) -> Result<String, RuntimeError>,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
    mut verify: impl FnMut(&str, u32) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let mut failures = Vec::new();
    for entry in &state.interfaces {
        if !entry.ipv4_changed {
            continue;
        }
        let key = interface_forwarding_sysctl_key(&entry.name)?;
        if let Err(error) = verify(&entry.name, entry.ifindex).and_then(|()| write(&key, "1")) {
            failures.push(format!("{} IPv4: {error}", entry.name));
        }
    }
    if failures.is_empty() {
        return Ok(());
    }
    if let Err(rollback_error) =
        restore_interface_forwarding_entries_with(state, &mut read, &mut write, &mut verify)
    {
        return Err(RuntimeError::FatalTransition(format!(
            "per-interface forwarding setup failed ({}); rollback failed ({rollback_error}); fail-closed nftables policy must remain installed",
            failures.join("; ")
        )));
    }
    Err(RuntimeError::Forwarding(format!(
        "per-interface forwarding setup failed: {}",
        failures.join("; ")
    )))
}

fn restore_forwarding_state_with(
    state: &ForwardingState,
    read: impl FnMut(&str) -> Result<String, RuntimeError>,
    write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    restore_forwarding_state_with_mode(state, read, write)
}

fn restore_forwarding_state_with_mode(
    state: &ForwardingState,
    mut read: impl FnMut(&str) -> Result<String, RuntimeError>,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let mut failures = Vec::new();
    if state.ipv4_changed {
        match read("net.ipv4.ip_forward") {
            Ok(current) if current == state.ipv4 => {}
            Ok(_) => {
                if let Err(error) = write("net.ipv4.ip_forward", &state.ipv4) {
                    failures.push(format!("IPv4: {error}"));
                }
            }
            Err(error) => failures.push(format!("IPv4 read: {error}")),
        }
    }
    if let Err(error) = restore_interface_forwarding_entries_with(
        state,
        &mut read,
        &mut write,
        verify_forwarding_interface,
    ) {
        failures.push(error.to_string());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::FatalTransition(format!(
            "failed to recover IPv4 forwarding state: {}",
            failures.join("; ")
        )))
    }
}

fn recover_forwarding_state(path: &Path, namespace_inode: u64) -> Result<(), RuntimeError> {
    let Some(state) = load_forwarding_state(path, namespace_inode)? else {
        return Ok(());
    };
    restore_forwarding_state_with_mode(
        &state,
        |key| read_forwarding_state_value(&state, key),
        |key, value| write_forwarding_state_value(&state, key, value),
    )?;
    remove_forwarding_state_file(path)
}

fn enable_forwarding_durable(
    path: &Path,
    namespace_inode: u64,
    forwarding_interfaces: &[String],
    daemon_owned_names: &std::collections::BTreeSet<String>,
) -> Result<ForwardingState, RuntimeError> {
    if !forwarding_interfaces.is_empty() {
        return enable_interface_forwarding_durable(
            path,
            namespace_inode,
            forwarding_interfaces,
            daemon_owned_names,
        );
    }
    let mut state = ForwardingState {
        ipv4: read_sysctl("net.ipv4.ip_forward")?,
        ipv4_changed: false,
        interfaces: Vec::new(),
    };
    state.ipv4_changed = state.ipv4 != "1";
    validate_forwarding_state(&state)?;
    if state.ipv4_changed {
        persist_forwarding_state(path, namespace_inode, &state)?;
    }
    match enable_forwarding_state_with(state, write_sysctl) {
        Ok(state) => Ok(state),
        Err(error) => {
            if !matches!(error, RuntimeError::FatalTransition(_)) {
                remove_forwarding_state_file(path)?;
            }
            Err(error)
        }
    }
}

fn restore_forwarding_with(
    state: &ForwardingState,
    mut write: impl FnMut(&str, &str) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    if state.ipv4_changed {
        write("net.ipv4.ip_forward", &state.ipv4).map_err(|error| {
            RuntimeError::FatalTransition(format!(
                "failed to restore IPv4 forwarding state: {error}"
            ))
        })?;
    }
    Ok(())
}

fn restore_forwarding(state: &ForwardingState) -> Result<(), RuntimeError> {
    restore_forwarding_state_with(
        state,
        |key| read_forwarding_state_value(state, key),
        |key, value| write_forwarding_state_value(state, key, value),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmanaged_forwarding_treats_any_nonzero_value_as_enabled() {
        let allowed = std::collections::BTreeSet::new();
        validate_unmanaged_forwarding_with(&allowed, &["eth0".to_owned()], |_| {
            Ok(Some("2".to_owned()))
        })
        .unwrap_err();
    }

    #[test]
    fn recovery_rejects_legacy_ipv6_journal_without_accessing_sysctls() {
        let path = std::env::temp_dir().join(format!(
            "vpn-relay-legacy-ipv6-pending-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let document = serde_json::json!({
            "version": 2,
            "namespace_inode": 4242,
            "state": {
                "ipv4": "0",
                "ipv4_changed": false,
                "ipv6": "1",
                "ipv6_changed": true,
                "interfaces": [{
                    "name": "wg0",
                    "ifindex": 7,
                    "daemon_owned": false,
                    "ipv4": "0",
                    "ipv4_changed": false,
                    "ipv6": "1",
                    "ipv6_changed": true,
                    "ipv6_enabled": true
                }]
            }
        });
        let bytes = serde_json::to_vec(&document).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();

        let error = recover_forwarding_state(&path, 4242).unwrap_err();
        assert!(error.to_string().contains("pending IPv6 sysctl recovery"));
        assert!(path.exists(), "legacy recovery journal must be retained");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unmanaged_forwarding_validation_ignores_allowlisted_links() {
        let allowed = std::collections::BTreeSet::from(["wg0".to_owned()]);
        validate_unmanaged_forwarding_with(&allowed, &["wg0".to_owned()], |_| {
            Ok(Some("1".to_owned()))
        })
        .unwrap();
    }

    #[test]
    fn forwarding_state_file_round_trips_with_private_permissions() {
        let path = forwarding_state_test_path("round-trip");
        persist_forwarding_state(&path, 1234, &sample_forwarding_state()).unwrap();

        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            load_forwarding_state(&path, 1234).unwrap(),
            Some(sample_forwarding_state())
        );

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn forwarding_state_file_rejects_a_different_network_namespace() {
        let path = forwarding_state_test_path("namespace");
        persist_forwarding_state(&path, 1234, &sample_forwarding_state()).unwrap();

        assert!(matches!(
            load_forwarding_state(&path, 5678),
            Err(RuntimeError::Forwarding(message))
                if message.contains("belongs to network namespace 1234")
        ));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn forwarding_state_file_rejects_corrupt_json() {
        let path = forwarding_state_test_path("corrupt");
        std::fs::write(&path, b"{").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            load_forwarding_state(&path, 1234),
            Err(RuntimeError::Forwarding(_))
        ));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn forwarding_state_persistence_does_not_follow_a_dangling_symlink() {
        use std::os::unix::fs::symlink;

        let path = forwarding_state_test_path("symlink");
        let target = forwarding_state_test_path("missing-target");
        symlink(&target, &path).unwrap();

        assert!(matches!(
            persist_forwarding_state(&path, 1234, &sample_forwarding_state()),
            Err(RuntimeError::Forwarding(_))
        ));
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!target.exists());

        std::fs::remove_file(path).unwrap();
    }

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
    fn control_request_protocol_supports_peer_replacement_and_full_reload() {
        let peer_request = ControlRequest::ReplacePeers {
            interface: "wg0".to_owned(),
            peers: Vec::new(),
        };
        let peer_json = serde_json::to_vec(&peer_request).unwrap();
        assert!(String::from_utf8_lossy(&peer_json).contains("\"operation\":\"replace_peers\""));
        assert_eq!(
            serde_json::from_slice::<ControlRequest>(&peer_json).unwrap(),
            peer_request
        );

        let reload_request = ControlRequest::ReloadConfig {
            toml: "[interfaces.wg0]".to_owned(),
        };
        let reload_json = serde_json::to_vec(&reload_request).unwrap();
        assert!(String::from_utf8_lossy(&reload_json).contains("\"operation\":\"reload_config\""));
        assert_eq!(
            serde_json::from_slice::<ControlRequest>(&reload_json).unwrap(),
            reload_request
        );
        assert!(serde_json::from_slice::<ControlRequest>(br#"{"operation":"unknown"}"#).is_err());
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
    fn control_socket_bind_failure_removes_incompletely_configured_path() {
        let path = std::env::temp_dir().join(format!(
            "vpn-relay-control-bind-failure-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let result = ControlSocket::bind_with(path.clone(), |_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected socket configuration failure",
            ))
        });
        assert!(
            matches!(result, Err(RuntimeError::Control(message)) if message.contains("injected socket configuration failure"))
        );
        assert!(!path.exists());
    }

    #[test]
    fn control_socket_bind_rejects_replaced_path_without_unlinking_it() {
        let path = std::env::temp_dir().join(format!(
            "vpn-relay-control-bind-replaced-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let result = ControlSocket::bind_with(path.clone(), |path, _| {
            std::fs::remove_file(path)?;
            std::fs::write(path, b"external replacement")?;
            Ok(())
        });
        assert!(matches!(
            result,
            Err(RuntimeError::Control(message)) if message.contains("path changed while being configured")
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"external replacement");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn control_socket_drop_does_not_remove_replaced_path() {
        let path = std::env::temp_dir().join(format!(
            "vpn-relay-control-replaced-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let socket = ControlSocket::bind(path.clone()).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"administrator-owned replacement").unwrap();
        drop(socket);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"administrator-owned replacement"
        );
        std::fs::remove_file(path).unwrap();
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
    fn multi_device_peer_commit_failure_rolls_back_previously_committed_device() {
        let previous = peer_test_config("old-a", "old-b");
        let candidate = peer_test_config("new-a", "new-b");
        let prepared = peer_test_prepared();
        let mut devices: Vec<Box<dyn TunnelHandle>> = vec![
            Box::new(FaultInjectingTunnel {
                name: "wg0".to_owned(),
                peers: vec!["old-a".to_owned()],
                calls: 0,
                fail_calls: std::collections::HashSet::new(),
            }),
            Box::new(FaultInjectingTunnel {
                name: "wg1".to_owned(),
                peers: vec!["old-b".to_owned()],
                calls: 0,
                fail_calls: [1].into_iter().collect(),
            }),
        ];
        let changed = vec![(0, "wg0".to_owned()), (1, "wg1".to_owned())];

        let (committed, error) =
            commit_peer_replacements(&mut devices, &changed, &candidate, &prepared)
                .expect_err("second device must fail");
        assert_eq!(committed, vec![0]);
        assert!(error
            .to_string()
            .contains("injected peer replacement failure"));

        let failures = rollback_peer_replacements(&mut devices, &committed, &previous, &prepared);
        assert!(failures.is_empty(), "rollback failed: {failures:?}");

        let restored_first = devices[0].snapshot().unwrap();
        assert_eq!(restored_first.peers.len(), 1);
        assert_eq!(restored_first.peers[0].public_key[0], b'o');
        let unchanged_second = devices[1].snapshot().unwrap();
        assert_eq!(unchanged_second.peers.len(), 1);
        assert_eq!(unchanged_second.peers[0].public_key[0], b'o');
    }

    #[test]
    fn multi_device_peer_rollback_continues_after_one_device_fails() {
        let previous = peer_test_config("old-a", "old-b");
        let candidate = peer_test_config("new-a", "new-b");
        let prepared = peer_test_prepared();
        let mut devices: Vec<Box<dyn TunnelHandle>> = vec![
            Box::new(FaultInjectingTunnel {
                name: "wg0".to_owned(),
                peers: vec!["old-a".to_owned()],
                calls: 0,
                fail_calls: std::collections::HashSet::new(),
            }),
            Box::new(FaultInjectingTunnel {
                name: "wg1".to_owned(),
                peers: vec!["old-b".to_owned()],
                calls: 0,
                fail_calls: [2].into_iter().collect(),
            }),
        ];
        let changed = vec![(0, "wg0".to_owned()), (1, "wg1".to_owned())];

        let committed = commit_peer_replacements(&mut devices, &changed, &candidate, &prepared)
            .expect("both peer sets must commit before rollback is exercised");
        assert_eq!(committed, vec![0, 1]);

        // Rollback runs in reverse order. wg1 fails on its restore call, but
        // wg0 must still be restored instead of being skipped by early return.
        let failures = rollback_peer_replacements(&mut devices, &committed, &previous, &prepared);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("wg1"));

        let restored_first = devices[0].snapshot().unwrap();
        assert_eq!(restored_first.peers[0].public_key[0], b'o');
        let failed_restore_second = devices[1].snapshot().unwrap();
        assert_eq!(failed_restore_second.peers[0].public_key[0], b'n');
    }

    #[test]
    fn conntrack_mark_state_is_persisted_with_private_permissions() {
        let directory = std::env::temp_dir().join(format!(
            "vpn-relay-marks-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("namespace.marks");
        let history = vec![sample_conntrack_decision()];

        persist_conntrack_mark_history(&path, &history).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(load_conntrack_mark_history(&path).unwrap(), history);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn conntrack_mark_state_rejects_symlinks_and_non_private_files() {
        let directory = std::env::temp_dir().join(format!(
            "vpn-relay-marks-safety-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let target = directory.join("target");
        let path = directory.join("namespace.marks");

        fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(matches!(
            load_conntrack_mark_history(&path),
            Err(RuntimeError::ConntrackMarkState(_))
        ));
        fs::remove_file(&path).unwrap();

        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_conntrack_mark_history(&path),
            Err(RuntimeError::ConntrackMarkState(_))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn conntrack_mark_state_rejects_oversized_files_before_deserializing() {
        const MAX_STATE_FILE_SIZE: usize = 4 * 1024 * 1024;
        let directory = std::env::temp_dir().join(format!(
            "vpn-relay-marks-oversized-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("namespace.marks");
        fs::write(&path, vec![b'x'; MAX_STATE_FILE_SIZE + 1]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            load_conntrack_mark_history(&path),
            Err(RuntimeError::ConntrackMarkState(message))
                if message.contains("exceeds 4 MiB")
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn conntrack_mark_state_rejects_malformed_json_and_unsupported_versions() {
        let directory = std::env::temp_dir().join(format!(
            "vpn-relay-marks-format-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("namespace.marks");

        fs::write(&path, b"{not-json").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            load_conntrack_mark_history(&path),
            Err(RuntimeError::ConntrackMarkState(_))
        ));

        fs::write(&path, br#"{"version":2,"decisions":[]}"#).unwrap();
        assert!(matches!(
            load_conntrack_mark_history(&path),
            Err(RuntimeError::ConntrackMarkState(message))
                if message.contains("unsupported state file version 2")
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn conntrack_mark_state_rejects_hard_links() {
        let directory = std::env::temp_dir().join(format!(
            "vpn-relay-marks-hardlink-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("namespace.marks");
        let linked_path = directory.join("linked.marks");
        persist_conntrack_mark_history(&path, &[sample_conntrack_decision()]).unwrap();
        fs::hard_link(&path, &linked_path).unwrap();

        assert!(matches!(
            load_conntrack_mark_history(&path),
            Err(RuntimeError::ConntrackMarkState(_))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn conntrack_mark_state_persistence_refuses_unsafe_existing_files() {
        let directory = std::env::temp_dir().join(format!(
            "vpn-relay-marks-persist-safety-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("namespace.marks");
        let linked_path = directory.join("linked.marks");
        fs::write(&path, b"untrusted").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, &linked_path).unwrap();

        assert!(matches!(
            persist_conntrack_mark_history(&path, &[sample_conntrack_decision()]),
            Err(RuntimeError::ConntrackMarkState(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"untrusted");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn conntrack_mark_state_persistence_refuses_unsafe_temporary_symlinks() {
        let directory = std::env::temp_dir().join(format!(
            "vpn-relay-marks-temp-symlink-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("namespace.marks");
        let target = directory.join("target");
        let temporary_path = path.with_extension(format!("marks.tmp-{}", std::process::id()));
        fs::write(&target, b"do not modify").unwrap();
        std::os::unix::fs::symlink(&target, &temporary_path).unwrap();

        assert!(matches!(
            persist_conntrack_mark_history(&path, &[sample_conntrack_decision()]),
            Err(RuntimeError::ConntrackMarkState(_))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"do not modify");
        assert!(fs::symlink_metadata(&temporary_path)
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_dir_all(directory).unwrap();
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

    #[test]
    fn unmanaged_forwarding_interfaces_must_remain_disabled() {
        let allowed = std::collections::BTreeSet::from(["wg0".to_owned()]);
        let interfaces = vec!["eth0".to_owned(), "wg0".to_owned()];
        validate_unmanaged_forwarding_with(&allowed, &interfaces, |key| {
            if key == "net.ipv4.conf.eth0.forwarding" {
                Ok(Some("1".to_owned()))
            } else {
                Ok(Some("0".to_owned()))
            }
        })
        .unwrap_err();
    }

    fn test_forwarding_entry(name: &str, ifindex: u32) -> InterfaceForwardingState {
        InterfaceForwardingState {
            name: name.to_owned(),
            ifindex,
            daemon_owned: false,
            ipv4: "0".to_owned(),
            ipv4_changed: true,
        }
    }

    #[test]
    fn interface_forwarding_enable_rolls_back_partial_writes() {
        let state = ForwardingState {
            ipv4: "1".to_owned(),
            ipv4_changed: false,
            interfaces: vec![
                test_forwarding_entry("eth0", 7),
                test_forwarding_entry("eth1", 8),
            ],
        };
        let values = std::cell::RefCell::new(std::collections::BTreeMap::from([
            ("net.ipv4.conf.eth0.forwarding".to_owned(), "0".to_owned()),
            ("net.ipv4.conf.eth1.forwarding".to_owned(), "0".to_owned()),
        ]));
        let result = enable_interface_forwarding_entries_with(
            &state,
            |key| Ok(values.borrow().get(key).cloned().unwrap()),
            |key, value| {
                if key == "net.ipv4.conf.eth1.forwarding" && value == "1" {
                    return Err(RuntimeError::Forwarding("injected setup failure".to_owned()));
                }
                values.borrow_mut().insert(key.to_owned(), value.to_owned());
                Ok(())
            },
            |_, _| Ok(()),
        );
        assert!(matches!(result, Err(RuntimeError::Forwarding(_))));
        assert_eq!(values.borrow()["net.ipv4.conf.eth0.forwarding"], "0");
        assert_eq!(values.borrow()["net.ipv4.conf.eth1.forwarding"], "0");
    }

    #[test]
    fn interface_forwarding_enable_reports_fatal_when_rollback_fails() {
        let state = ForwardingState {
            ipv4: "1".to_owned(),
            ipv4_changed: false,
            interfaces: vec![test_forwarding_entry("eth0", 7)],
        };
        let current = std::cell::RefCell::new("0".to_owned());
        let result = enable_interface_forwarding_entries_with(
            &state,
            |_| Ok(current.borrow().clone()),
            |_, value| {
                if value == "1" {
                    *current.borrow_mut() = "1".to_owned();
                    return Err(RuntimeError::Forwarding("injected setup failure".to_owned()));
                }
                Err(RuntimeError::Forwarding("injected rollback failure".to_owned()))
            },
            |_, _| Ok(()),
        );
        assert!(matches!(result, Err(RuntimeError::FatalTransition(message))
            if message.contains("injected setup failure")
                && message.contains("injected rollback failure")));
    }

    #[test]
    fn interface_forwarding_enable_fails_closed_if_identity_is_lost() {
        let state = ForwardingState {
            ipv4: "1".to_owned(),
            ipv4_changed: false,
            interfaces: vec![test_forwarding_entry("eth0", 7)],
        };
        let mut writes = 0;
        let result = enable_interface_forwarding_entries_with(
            &state,
            |_| Ok("0".to_owned()),
            |_, _| {
                writes += 1;
                Ok(())
            },
            |_, _| Err(RuntimeError::Forwarding("identity changed".to_owned())),
        );
        assert!(matches!(result, Err(RuntimeError::FatalTransition(_))));
        assert_eq!(writes, 0);
    }

    #[test]
    fn daemon_owned_tun_sysctls_are_never_restored_by_saved_identity() {
        let mut entry = test_forwarding_entry("wg0", 17);
        entry.daemon_owned = true;
        let state = ForwardingState {
            ipv4: "1".to_owned(),
            ipv4_changed: false,
            interfaces: vec![entry],
        };
        let mut reads = 0;
        let mut writes = 0;
        restore_interface_forwarding_entries_with(
            &state,
            |_| {
                reads += 1;
                Ok("1".to_owned())
            },
            |_, _| {
                writes += 1;
                Ok(())
            },
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(reads, 0);
        assert_eq!(writes, 0);
    }

    #[test]
    fn interface_forwarding_restore_checks_identity_and_daemon_value() {
        let entry = test_forwarding_entry("eth0", 7);
        let calls = std::cell::RefCell::new(Vec::new());
        restore_interface_forwarding_entry_with(
            &entry,
            "0",
            true,
            |key| {
                calls.borrow_mut().push(format!("read:{key}"));
                Ok("1".to_owned())
            },
            |key, value| {
                calls.borrow_mut().push(format!("write:{key}={value}"));
                Ok(())
            },
            |name, index| {
                calls.borrow_mut().push(format!("verify:{name}:{index}"));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            calls.into_inner(),
            vec![
                "verify:eth0:7",
                "read:net.ipv4.conf.eth0.forwarding",
                "verify:eth0:7",
                "write:net.ipv4.conf.eth0.forwarding=0",
            ]
        );
    }

    #[test]
    fn interface_forwarding_restore_never_writes_after_identity_mismatch() {
        let entry = test_forwarding_entry("eth0", 7);
        let mut reads = 0;
        let mut writes = 0;
        let result = restore_interface_forwarding_entry_with(
            &entry,
            "0",
            true,
            |_| {
                reads += 1;
                Ok("1".to_owned())
            },
            |_, _| {
                writes += 1;
                Ok(())
            },
            |_, _| Err(RuntimeError::Forwarding("identity changed".to_owned())),
        );
        assert!(result.is_err());
        assert_eq!(reads, 0);
        assert_eq!(writes, 0);
    }

    #[test]
    fn interface_forwarding_restore_preserves_operator_value() {
        let entry = test_forwarding_entry("eth0", 7);
        let mut writes = 0;
        restore_interface_forwarding_entry_with(
            &entry,
            "0",
            true,
            |_| Ok("2".to_owned()),
            |_, _| {
                writes += 1;
                Ok(())
            },
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(writes, 0);
    }

    #[test]
    fn forwarding_journal_accepts_legacy_namespace_only_state() {
        let legacy = r#"{"ipv4":"0","ipv4_changed":true,"interfaces":[]}"#;
        let state: ForwardingState = serde_json::from_str(legacy).unwrap();
        assert!(state.interfaces.is_empty());
        validate_forwarding_state(&state).unwrap();
    }

    #[test]
    fn forwarding_journal_validates_link_identity_and_values() {
        let mut state = sample_forwarding_state();
        state.interfaces.push(test_forwarding_entry("awg0", 17));
        validate_forwarding_state(&state).unwrap();

        state.interfaces[0].ifindex = 0;
        assert!(validate_forwarding_state(&state).is_err());
        state.interfaces[0].ifindex = 17;
        state.interfaces[0].name = "../net/eth0".to_owned();
        assert!(validate_forwarding_state(&state).is_err());
        state.interfaces[0].name = "awg0".to_owned();
        state.interfaces[0].ipv4 = "2".to_owned();
        assert!(validate_forwarding_state(&state).is_err());
    }

    #[test]
    fn forwarding_journal_rejects_duplicate_link_identity() {
        let mut state = sample_forwarding_state();
        let entry = test_forwarding_entry("awg0", 17);
        state.interfaces = vec![entry.clone(), entry];
        assert!(validate_forwarding_state(&state).is_err());
    }

    #[test]
    fn forwarding_enable_does_not_rewrite_already_enabled_ipv4() {
        let state = ForwardingState {
            ipv4: "1".to_owned(),
            ipv4_changed: false,
            interfaces: Vec::new(),
        };
        let enabled = enable_forwarding_state_with(state.clone(), |_, _| {
            panic!("already-enabled IPv4 forwarding must not be rewritten")
        })
        .unwrap();
        assert_eq!(enabled, state);
    }

    #[test]
    fn forwarding_enable_changes_and_restores_ipv4_state() {
        let state = ForwardingState {
            ipv4: "0".to_owned(),
            ipv4_changed: false,
            interfaces: Vec::new(),
        };
        let mut writes = Vec::new();
        let enabled = enable_forwarding_state_with(state, |key, value| {
            writes.push((key.to_owned(), value.to_owned()));
            Ok(())
        })
        .unwrap();
        assert!(enabled.ipv4_changed);
        assert_eq!(
            writes,
            vec![("net.ipv4.ip_forward".to_owned(), "1".to_owned())]
        );

        restore_forwarding_with(&enabled, |key, value| {
            writes.push((key.to_owned(), value.to_owned()));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            writes.last(),
            Some(&("net.ipv4.ip_forward".to_owned(), "0".to_owned()))
        );
    }

    #[test]
    fn forwarding_enable_keeps_fail_closed_policy_when_restore_fails() {
        let state = ForwardingState {
            ipv4: "0".to_owned(),
            ipv4_changed: false,
            interfaces: Vec::new(),
        };
        let result = enable_forwarding_state_with(state, |_, value| {
            if value == "1" {
                Err(RuntimeError::Forwarding("injected enable failure".to_owned()))
            } else {
                Err(RuntimeError::Forwarding("injected restore failure".to_owned()))
            }
        });
        assert!(matches!(result, Err(RuntimeError::FatalTransition(message))
            if message.contains("injected enable failure")
                && message.contains("injected restore failure")));
    }

    #[test]
    fn per_interface_restore_attempts_every_entry_after_failures() {
        let state = ForwardingState {
            ipv4: "1".to_owned(),
            ipv4_changed: false,
            interfaces: vec![
                test_forwarding_entry("eth0", 7),
                test_forwarding_entry("eth1", 8),
            ],
        };
        let mut writes = Vec::new();
        let result = restore_interface_forwarding_entries_with(
            &state,
            |_| Ok("1".to_owned()),
            |key, value| {
                writes.push((key.to_owned(), value.to_owned()));
                Ok(())
            },
            |name, _| {
                if name == "eth0" {
                    Err(RuntimeError::Forwarding("identity changed".to_owned()))
                } else {
                    Ok(())
                }
            },
        );
        assert!(matches!(result, Err(RuntimeError::FatalTransition(_))));
        assert_eq!(
            writes,
            vec![("net.ipv4.conf.eth1.forwarding".to_owned(), "0".to_owned())]
        );
    }

    #[test]
    fn forwarding_state_recovery_restores_and_is_idempotent() {
        let state = ForwardingState {
            ipv4: "0".to_owned(),
            ipv4_changed: true,
            interfaces: Vec::new(),
        };
        let mut writes = Vec::new();
        restore_forwarding_state_with_mode(
            &state,
            |_| Ok("1".to_owned()),
            |key, value| {
                writes.push((key.to_owned(), value.to_owned()));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            writes,
            vec![("net.ipv4.ip_forward".to_owned(), "0".to_owned())]
        );

        writes.clear();
        restore_forwarding_state_with_mode(
            &state,
            |_| Ok("0".to_owned()),
            |key, value| {
                writes.push((key.to_owned(), value.to_owned()));
                Ok(())
            },
        )
        .unwrap();
        assert!(writes.is_empty());
    }

    #[test]
    fn multi_device_peer_rollback_failure_is_reported_for_fatal_shutdown() {
        let previous = peer_test_config("old-a", "old-b");
        let candidate = peer_test_config("new-a", "new-b");
        let prepared = peer_test_prepared();
        let mut devices: Vec<Box<dyn TunnelHandle>> = vec![
            Box::new(FaultInjectingTunnel {
                name: "wg0".to_owned(),
                peers: vec!["old-a".to_owned()],
                calls: 0,
                fail_calls: [2].into_iter().collect(),
            }),
            Box::new(FaultInjectingTunnel {
                name: "wg1".to_owned(),
                peers: vec!["old-b".to_owned()],
                calls: 0,
                fail_calls: [1].into_iter().collect(),
            }),
        ];
        let changed = vec![(0, "wg0".to_owned()), (1, "wg1".to_owned())];

        let (committed, _) =
            commit_peer_replacements(&mut devices, &changed, &candidate, &prepared)
                .expect_err("second device must fail");
        assert_eq!(committed, vec![0]);
        let failures = rollback_peer_replacements(&mut devices, &committed, &previous, &prepared);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("wg0"));
        assert!(failures[0].contains("injected peer replacement failure"));

        let partially_committed = devices[0].snapshot().unwrap();
        assert_eq!(partially_committed.peers[0].public_key[0], b'n');
        let never_committed = devices[1].snapshot().unwrap();
        assert_eq!(never_committed.peers[0].public_key[0], b'o');
    }

    fn forwarding_state_test_path(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vpn-relay-forwarding-{label}-{}-{nonce}.json",
            std::process::id()
        ))
    }

    fn sample_forwarding_state() -> ForwardingState {
        ForwardingState {
            ipv4: "0".to_owned(),
            ipv4_changed: true,
            interfaces: Vec::new(),
        }
    }

    struct FaultInjectingTunnel {
        name: String,
        peers: Vec<String>,
        calls: usize,
        fail_calls: std::collections::HashSet<usize>,
    }

    impl TunnelHandle for FaultInjectingTunnel {
        fn snapshot(&self) -> Result<TunnelSnapshot, BackendError> {
            Ok(TunnelSnapshot {
                name: self.name.clone(),
                peers: self
                    .peers
                    .iter()
                    .map(|key| {
                        let mut public_key = [0u8; 32];
                        public_key[0] = key.as_bytes().first().copied().unwrap_or_default();
                        crate::backend::TunnelPeerSnapshot {
                            public_key,
                            tx_bytes: 0,
                            rx_bytes: 0,
                            time_since_last_handshake: None,
                        }
                    })
                    .collect(),
            })
        }

        fn replace_peers(
            &mut self,
            interface: &crate::config::InterfaceConfig,
            _prepared: &PreparedInterface,
        ) -> Result<(), BackendError> {
            self.calls += 1;
            if self.fail_calls.contains(&self.calls) {
                return Err(BackendError::new(format!(
                    "injected peer replacement failure on {} call {}",
                    self.name, self.calls
                )));
            }
            self.peers = interface
                .peers
                .iter()
                .map(|peer| peer.public_key.clone())
                .collect();
            Ok(())
        }

        fn shutdown(&self) {}
        fn wait(&mut self) {}
    }

    fn peer_interface(peer_key: &str) -> crate::config::InterfaceConfig {
        crate::config::InterfaceConfig {
            tunnel_type: crate::config::TunnelType::WireGuard,
            address: vec!["10.0.0.1/24".to_owned()],
            mtu: 1380,
            listen_port: None,
            private_key: "private".to_owned(),
            socket_fwmark: None,
            peers: vec![PeerConfig {
                public_key: peer_key.to_owned(),
                preshared_key: None,
                endpoint: None,
                allowed_ips: vec!["10.0.0.2/32".to_owned()],
                persistent_keepalive_secs: None,
                persistent_keepalive_range: None,
            }],
            awg: None,
        }
    }

    fn peer_test_config(wg0: &str, wg1: &str) -> Config {
        Config {
            daemon: crate::config::DaemonConfig::default(),
            interfaces: [
                ("wg0".to_owned(), peer_interface(wg0)),
                ("wg1".to_owned(), peer_interface(wg1)),
            ]
            .into_iter()
            .collect(),
            routing: crate::config::RoutingConfig::default(),
            firewall: crate::config::FirewallConfig::default(),
        }
    }

    fn peer_test_prepared() -> std::collections::BTreeMap<String, PreparedInterface> {
        [
            (
                "wg0".to_owned(),
                PreparedInterface {
                    peer_endpoints: vec![None],
                },
            ),
            (
                "wg1".to_owned(),
                PreparedInterface {
                    peer_endpoints: vec![None],
                },
            ),
        ]
        .into_iter()
        .collect()
    }

    fn sample_conntrack_decision() -> crate::routing::RoutingDecision {
        crate::routing::RoutingDecision {
            priority: 10,
            ingress: "wg-ingress".to_owned(),
            source: Some(vec!["10.0.0.2/32".to_owned()]),
            destination: Some(vec!["0.0.0.0/0".to_owned()]),
            egress: "awg-uplink".to_owned(),
            routing_mark: 0x8000_0001,
            conntrack_mark: 0x5001_0000,
            nat: crate::config::NatMode::None,
            nat_to: None,
        }
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
}
