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

    fn current_conntrack_mark_state_path() -> Result<PathBuf, RuntimeError> {
        let lock_path = Self::current_netns_path()?;
        Ok(lock_path.with_extension("marks"))
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
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(RuntimeError::ConntrackMarkState(error.to_string())),
    };
    if metadata.len() > 4 * 1024 * 1024 {
        return Err(RuntimeError::ConntrackMarkState(
            "state file exceeds 4 MiB".to_owned(),
        ));
    }
    validate_private_state_file(path)?;

    let bytes =
        fs::read(path).map_err(|error| RuntimeError::ConntrackMarkState(error.to_string()))?;
    if bytes.len() > 4 * 1024 * 1024 {
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

struct ForwardingState {
    ipv4: String,
    ipv6: String,
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
            retired_routing: Vec::new(),
            conntrack_mark_state_path,
            conntrack_mark_history,
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
                self.routing.egresses.iter().any(|current| {
                    current.interface == next.interface
                        && current.mark == next.mark
                        && current.ipv6_enabled == next.ipv6_enabled
                })
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

    fn rollback_peer_replacements(&mut self, committed: &[usize]) -> Vec<String> {
        rollback_peer_replacements(
            &mut self.devices,
            committed,
            &self.config,
            &self.prepared_interfaces,
        )
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
        // Stop datapath workers first, but keep the firewall active until all
        // managed TUN links have been destroyed. This matters when the host's
        // original forwarding state was already enabled.
        for device in &self.devices {
            device.shutdown();
        }
        for device in &mut self.devices {
            device.wait();
        }

        for retired in &self.retired_routing {
            if let Err(error) = linux::remove_egress_policy_routing(retired) {
                tracing::warn!(%error, "failed to remove retired policy-routing resources");
            }
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
            ipv6_enabled: false,
            listen_port: None,
            private_key: "private".to_owned(),
            socket_fwmark: None,
            peers: vec![PeerConfig {
                public_key: peer_key.to_owned(),
                preshared_key: None,
                endpoint: None,
                allowed_ips: vec!["10.0.0.2/32".to_owned()],
                persistent_keepalive_secs: None,
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

        // A failed rollback leaves a mixed live state. Runtime must therefore
        // treat this as fatal rather than publish the candidate or keep serving.
        let partially_committed = devices[0].snapshot().unwrap();
        assert_eq!(partially_committed.peers.len(), 1);
        assert_eq!(partially_committed.peers[0].public_key[0], b'n');
        let never_committed = devices[1].snapshot().unwrap();
        assert_eq!(never_committed.peers.len(), 1);
        assert_eq!(never_committed.peers[0].public_key[0], b'o');
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
            ipv6_enabled: false,
        }
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
