// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod allowed_ips;
pub mod api;
mod dev_lock;
pub mod drop_privileges;
#[cfg(test)]
mod integration_tests;
pub mod peer;
mod probe_budget;
mod probe_reply;
mod reply_policy;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "kqueue.rs"]
pub mod poll;

#[cfg(target_os = "linux")]
#[path = "epoll.rs"]
pub mod poll;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
pub mod tun;

use std::collections::HashMap;
use std::io::{self, Write as _};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use crate::noise::amnezia::AmneziaConfig;
use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::handshake::ObfuscationRanges;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{Packet, Tunn, TunnResult};
use crate::x25519;
use allowed_ips::AllowedIps;
use parking_lot::Mutex;
pub use peer::AllowedIP;
use peer::Peer;
use poll::{EventPoll, EventRef, WaitResult};
use probe_reply::ProbeResponder;
use rand_chacha::ChaCha8Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use socket2::{Domain, Protocol, Type};
use tun::TunSocket;

use dev_lock::{Lock, LockReadGuard};

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const MAX_ITR: usize = 100; // Number of packets to handle per handler call

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    IoError(#[from] io::Error),
    #[error("{0}")]
    Socket(io::Error),
    #[error("{0}")]
    Bind(String),
    #[error("{0}")]
    FCntl(io::Error),
    #[error("{0}")]
    EventQueue(io::Error),
    #[error("{0}")]
    IOCtl(io::Error),
    #[error("{0}")]
    Connect(String),
    #[error("{0}")]
    SetSockOpt(String),
    #[error("Invalid tunnel name")]
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    #[error("{0}")]
    GetSockOpt(io::Error),
    #[error("{0}")]
    GetSockName(String),
    #[cfg(target_os = "linux")]
    #[error("{0}")]
    Timer(io::Error),
    #[error("iface read: {0}")]
    IfaceRead(io::Error),
    #[error("{0}")]
    DropPrivileges(String),
    #[error("API socket error: {0}")]
    ApiSocket(io::Error),
    #[error("failed to set up peer: {0}")]
    PeerSetup(String),
}

// What the event loop should do after a handler returns
enum Action {
    Continue, // Continue the loop
    Yield,    // Yield the read lock and acquire it again
    Exit,     // Stop the loop
}

// Event handler function
type Handler = Box<dyn Fn(&mut LockReadGuard<Device>, &mut ThreadData) -> Action + Send + Sync>;

pub struct DeviceHandle {
    device: Arc<Lock<Device>>, // The interface this handle owns
    threads: Vec<JoinHandle<()>>,
}

/// Read-only interface state returned by the typed control API.
#[derive(Clone, Debug)]
pub struct DeviceSnapshot {
    pub name: String,
    pub listen_port: u16,
    pub mtu: usize,
    pub fwmark: Option<u32>,
    pub peers: Vec<PeerSnapshot>,
}

/// Read-only peer state. Byte counters and handshake age are taken directly
/// from the live Noise tunnel; no UAPI serialization or socket is involved.
#[derive(Clone, Debug)]
pub struct PeerSnapshot {
    pub public_key: [u8; 32],
    pub index: u32,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<AllowedIP>,
    pub persistent_keepalive: Option<(u32, u32)>,
    pub time_since_last_handshake: Option<std::time::Duration>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

// Not `Copy`: `amnezia` owns an optional imitation domain.
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub n_threads: usize,
    pub use_connected_socket: bool,
    #[cfg(target_os = "linux")]
    pub use_multi_queue: bool,
    #[cfg(target_os = "linux")]
    pub uapi_fd: i32,
    /// Whether UAPI is enabled for this device. Defaults to true for
    /// compatibility with wg/awg tooling. When false, no UAPI handler is
    /// registered and any configured UAPI file descriptor is ignored.
    /// Embedding applications such as btrouted must set this to false and
    /// manage the device exclusively through the typed control API instead.
    pub enable_uapi: bool,
    /// Optional UDP listen port. None preserves the historical ephemeral port.
    pub listen_port: Option<u16>,
    /// Interface-wide AmneziaWG H1-H4 message-type tag ranges.
    ///
    /// These are device-scoped rather than per-peer because ingress must
    /// classify a datagram *before* it knows which peer sent it: the tag is
    /// what the parse keys on, and the parse result is what finds the peer.
    /// The default is the vanilla WireGuard message types.
    pub obf: ObfuscationRanges,
    /// Interface-wide AmneziaWG S1-S4 junk sizes, Jc pre-handshake junk, and
    /// imitation settings. Applied to every peer verbatim, matching the kernel
    /// module: junk is emitted by whichever side initiates a handshake.
    pub amnezia: AmneziaConfig,
    /// Bytes per second of replies to *unauthenticated* probe traffic, or
    /// `None` to answer nothing.
    ///
    /// **Defaults to `None`.** Answering an unverified source is the one thing
    /// this daemon otherwise never does — `verify_packet` computes mac1 from the
    /// server's static public key before a single byte is written — so it is
    /// opt-in rather than something an embedder acquires by upgrading. A reply
    /// also requires `amnezia.imitation` to name a protocol, but that is a
    /// second condition, not a substitute for this one: `Ip = dns` is what
    /// AmneziaWG installers write on *clients*, and a client that answers scans
    /// is more identifiable than one that stays silent, not less.
    ///
    /// `boringtun-cli` turns it on when `--imitate-protocol` is given, which is
    /// where the operator has actually asked for a service to be imitated.
    ///
    /// Read **once**, at [`Device::new`]. There is no UAPI key and nothing
    /// re-reads the copy retained in the device's config, so changing it after
    /// construction has no effect; a future key would need to rebuild the
    /// responder rather than assign this.
    ///
    /// The ceiling is aggregate and byte-based rather than per-source: a
    /// per-source limiter is defeated by spoofing, since every forged address
    /// gets a fresh allowance, and amplification is a byte ratio rather than a
    /// packet count. The reasoning is in full in `device::probe_budget`, named
    /// rather than linked because it is a private module.
    pub probe_reply_bytes_per_sec: Option<u32>,
}

/// The rate `boringtun-cli` uses when `--imitate-protocol` names a service.
///
/// Far more than any legitimate probing draws, and low enough that the port is
/// worthless as an amplifier: a reflector contributing 16 KiB/s is not worth an
/// attacker's spoofed packets. No reply-per-second figure is quoted here — it
/// depends on which protocol is configured and on the request, and a number in
/// a comment is the kind of thing that goes stale without anything failing.
///
/// One number rather than a knob per protocol. The replies are small and, more
/// to the point, *bounded*: a DNS SERVFAIL is never larger than its query, a
/// STUN Binding Success is capped by `MAX_SOFTWARE_LEN`, and a QUIC Version
/// Negotiation by `version_negotiation::MAX_LEN`. Each of those bounds is
/// asserted by a test in the module that owns it, rather than restated here as
/// a number that would go stale.
pub const DEFAULT_PROBE_REPLY_BYTES_PER_SEC: u32 = 16 * 1024;

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            n_threads: 4,
            use_connected_socket: true,
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            #[cfg(target_os = "linux")]
            uapi_fd: -1,
            enable_uapi: true,
            listen_port: None,
            // Vanilla WireGuard: no obfuscation, no junk. Exactly the behaviour
            // before AmneziaWG support existed.
            obf: ObfuscationRanges::default(),
            amnezia: AmneziaConfig::default(),
            // Silent to unauthenticated sources, which is what the sentence
            // above promises and what the daemon did before this existed.
            probe_reply_bytes_per_sec: None,
        }
    }
}

pub struct Device {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    queue: Arc<EventPoll<Handler>>,

    listen_port: u16,
    fwmark: Option<u32>,

    iface: Arc<TunSocket>,
    udp4: Option<socket2::Socket>,
    udp6: Option<socket2::Socket>,

    yield_notice: Option<EventRef>,
    exit_notice: Option<EventRef>,

    peers: HashMap<x25519::PublicKey, Arc<Mutex<Peer>>>,
    peers_by_ip: AllowedIps<Arc<Mutex<Peer>>>,
    peers_by_idx: HashMap<u32, Arc<Mutex<Peer>>>,
    next_index: IndexLfsr,

    config: DeviceConfig,

    cleanup_paths: Vec<String>,

    mtu: AtomicUsize,

    rate_limiter: Option<Arc<RateLimiter>>,

    /// State for answering unauthenticated probes, or `None` when that is off
    /// — which is the default.
    ///
    /// One per device, not one per worker thread. Its byte ceiling is aggregate,
    /// so a per-thread copy would multiply the allowance the operator configured
    /// by `n_threads`; sharing it is also what made the clock handling in
    /// `ProbeBudget::try_consume` load-bearing (see the comment there). Its
    /// STUN SOFTWARE value goes the other way and is wider still — one draw per
    /// *process*, via `stun::host_software`, because a single ICE agent
    /// announces one stack and the outbound Binding Requests read the same
    /// value; it must not vary per worker, per reply, or per device.
    probe_responder: Option<ProbeResponder>,

    #[cfg(target_os = "linux")]
    uapi_fd: i32,
}

struct ThreadData {
    iface: Arc<TunSocket>,
    src_buf: [u8; MAX_UDP_SIZE],
    dst_buf: [u8; MAX_UDP_SIZE],
    /// Per-thread CSPRNG for AmneziaWG junk bytes.
    ///
    /// The junk fillers write byte-by-byte from `next_u32`, so handing them
    /// `OsRng` costs a syscall per few bytes. That is on the cookie-reply path,
    /// which runs *before* any peer is authenticated, so an unauthenticated
    /// flood would turn into a syscall storm. `Tunn` already uses a seeded
    /// ChaCha8 for exactly these bytes (`noise/handshake.rs`), so this matches
    /// the per-peer path rather than weakening it.
    junk_rng: ChaCha8Rng,
    /// Per-thread CSPRNG for probe replies, deliberately **not** `junk_rng`.
    ///
    /// A QUIC Version Negotiation puts six bits of its draw straight on the wire
    /// (RFC 9000 §17.2.1 has a server randomise the Unused bits), and an
    /// unauthenticated prober chooses when and how often that happens. Sharing
    /// one stream would let a stranger both step and partially observe the
    /// generator that fills AmneziaWG cover junk on the cookie-reply path —
    /// which is the one thing about that junk that has to be unguessable.
    ///
    /// ChaCha8 makes neither of those exploitable today. The point is that the
    /// obfuscation's unpredictability should not rest on the responder's choice
    /// of RNG, because nothing would flag it if that choice later changed.
    probe_rng: ChaCha8Rng,
}

/// Does `addr` route to `owner` in this index?
///
/// Free and generic so the rule can be tested without a `Device`, which needs
/// a TUN device and root to construct. An untestable ownership check is how
/// the divergence this replaces went unnoticed.
fn index_owns<D>(index: &AllowedIps<Arc<D>>, owner: &Arc<D>, addr: IpAddr) -> bool {
    index
        .find(addr)
        .is_some_and(|found| Arc::ptr_eq(found, owner))
}

/// Every prefix in `index` that routes to `owner`.
fn index_prefixes<D>(index: &AllowedIps<Arc<D>>, owner: &Arc<D>) -> Vec<(IpAddr, u8)> {
    index
        .iter()
        .filter(|(found, _, _)| Arc::ptr_eq(found, owner))
        .map(|(_, addr, cidr)| (addr, cidr))
        .collect()
}

/// Read and discard up to `MAX_ITR` queued datagrams.
///
/// Required for correctness, not tidiness. `EventPoll::new_event` documents
/// that the event "will keep triggering until a Read operation is no longer
/// possible on the trigger", and it registers socket events with
/// `needs_read: false`, so `EventGuard::Drop` re-arms the fd without reading
/// it. A handler that returns without consuming the datagram therefore leaves
/// the socket readable and is re-dispatched immediately -- on the *same*
/// queued datagram. No further traffic is needed: one datagram spins a worker
/// at 100% CPU indefinitely, and a daemon that is started but never given a
/// private key never leaves that state on its own.
///
/// Bounded by `MAX_ITR` so a flood yields between batches instead of being
/// drained inside one dispatch -- the same budget the keyed path uses.
fn drain_datagrams(udp: &socket2::Socket, buf: &mut [u8]) {
    // Safety: as in the keyed path below -- `recv_from` promises not to write
    // uninitialised bytes to the buffer.
    let uninit = unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
    for _ in 0..MAX_ITR {
        if udp.recv_from(uninit).is_err() {
            break;
        }
    }
}

/// The device's key pair, or an error naming what is missing.
///
/// Extracted from `update_peer` so the guard sits behind a name that a test can
/// call. A free function rather than a method because constructing a `Device`
/// needs a TUN device and root, which would put this out of reach of ordinary
/// tests -- and an untestable guard is how it silently regresses to a panic.
fn require_key_pair(
    key_pair: &Option<(x25519::StaticSecret, x25519::PublicKey)>,
) -> Result<&(x25519::StaticSecret, x25519::PublicKey), Error> {
    key_pair
        .as_ref()
        .ok_or_else(|| Error::PeerSetup("private key must be set first".to_owned()))
}

impl DeviceHandle {
    pub fn new(name: &str, config: DeviceConfig) -> Result<DeviceHandle, Error> {
        let n_threads = config.n_threads;
        let listen_port = config.listen_port.unwrap_or(0);
        let mut wg_interface = Device::new(name, config)?;
        // Port 0 retains the historical behaviour: let the OS choose one.
        wg_interface.open_listen_socket(listen_port)?;

        let interface_lock = Arc::new(Lock::new(wg_interface));

        let mut threads = vec![];

        for i in 0..n_threads {
            threads.push({
                let dev = Arc::clone(&interface_lock);
                thread::spawn(move || DeviceHandle::event_loop(i, &dev))
            });
        }

        Ok(DeviceHandle {
            device: interface_lock,
            threads,
        })
    }

    /// Run a control-plane operation while the datapath cooperatively yields
    /// its read locks. This is the same synchronization used by UAPI set=1.
    fn with_device_mut<R>(&self, operation: impl FnOnce(&mut Device) -> R) -> R {
        let mut device = self.device.read();
        device
            .try_writeable(
                |device| device.trigger_yield(),
                |device| {
                    device.cancel_yield();
                    operation(device)
                },
            )
            .expect("device write operation always returns a result")
    }

    /// Configure the interface private key without going through UAPI.
    pub fn set_private_key(&self, private_key: x25519::StaticSecret) {
        self.with_device_mut(|device| device.set_key(private_key));
    }

    /// Add, update, or remove a peer through the typed device API.
    ///
    /// When `remove` is false, `allowed_ips` are either appended or replace
    /// the existing set according to `replace_allowed_ips`. Optional fields
    /// preserve their current values when omitted.
    #[allow(clippy::too_many_arguments)]
    pub fn update_peer(
        &self,
        public_key: x25519::PublicKey,
        remove: bool,
        replace_allowed_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        persistent_keepalive: Option<(u32, u32)>,
        preshared_key: Option<[u8; 32]>,
    ) -> Result<(), Error> {
        self.with_device_mut(|device| {
            device.update_peer(
                public_key,
                remove,
                replace_allowed_ips,
                endpoint,
                allowed_ips,
                persistent_keepalive,
                preshared_key,
            )
        })
    }

    /// Apply interface-wide AmneziaWG framing and obfuscation settings.
    pub fn set_obfuscation(&self, obfuscation: ObfuscationRanges, amnezia: AmneziaConfig) -> bool {
        self.with_device_mut(|device| device.set_obfuscation(obfuscation, amnezia))
    }

    /// Change the UDP listen port without going through UAPI.
    pub fn set_listen_port(&self, port: u16) -> Result<(), Error> {
        self.with_device_mut(|device| device.open_listen_socket(port))
    }

    /// Current UDP listen port selected for this interface.
    pub fn listen_port(&self) -> u16 {
        self.device.read().listen_port
    }

    /// Return a consistent read-only snapshot of the interface and its peers.
    ///
    /// This reads the live Device/Noise state directly. It deliberately does
    /// not query or serialize UAPI, so it is available in daemon mode where
    /// UAPI is completely disabled.
    pub fn snapshot(&self) -> Result<DeviceSnapshot, Error> {
        let device = self.device.read();
        let mut peers = Vec::with_capacity(device.peers.len());

        for (public_key, peer_ref) in &device.peers {
            let allowed_ips = device
                .peer_allowed_ips(peer_ref)
                .into_iter()
                .map(|(addr, cidr)| AllowedIP { addr, cidr })
                .collect();
            let peer = peer_ref.lock();
            let endpoint = peer.endpoint().addr;
            let keepalive = peer.persistent_keepalive_range();
            let (last_handshake, tx_bytes, rx_bytes, _, _) = peer.tunnel.stats();

            peers.push(PeerSnapshot {
                public_key: *public_key.as_bytes(),
                index: peer.index(),
                endpoint,
                allowed_ips,
                persistent_keepalive: keepalive,
                time_since_last_handshake: last_handshake,
                tx_bytes: tx_bytes as u64,
                rx_bytes: rx_bytes as u64,
            });
        }

        // HashMap iteration order is intentionally unspecified. Stable order
        // makes snapshots suitable for monitoring, tests, and config diffs.
        peers.sort_by_key(|peer| peer.public_key);

        Ok(DeviceSnapshot {
            name: device.iface.name()?,
            listen_port: device.listen_port,
            mtu: device.mtu.load(Ordering::Relaxed),
            fwmark: device.fwmark,
            peers,
        })
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Set the socket fwmark used by this interface and its connected peers.
    pub fn set_fwmark(&self, mark: u32) -> Result<(), Error> {
        self.with_device_mut(|device| device.set_fwmark(mark))
    }

    /// Request a graceful stop of all datapath worker threads.
    pub fn shutdown(&self) {
        self.device.read().trigger_exit();
    }

    pub fn wait(&mut self) {
        while let Some(thread) = self.threads.pop() {
            thread.join().unwrap();
        }
    }

    pub fn clean(&mut self) {
        for path in &self.device.read().cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = std::fs::remove_file(path);
        }
    }

    fn event_loop(_i: usize, device: &Lock<Device>) {
        #[cfg(target_os = "linux")]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            junk_rng: ChaCha8Rng::from_rng(OsRng).expect("OsRng must seed ChaCha8"),
            probe_rng: ChaCha8Rng::from_rng(OsRng).expect("OsRng must seed ChaCha8"),
            iface: if _i == 0 || !device.read().config.use_multi_queue {
                // For the first thread use the original iface
                Arc::clone(&device.read().iface)
            } else {
                // For for the rest create a new iface queue
                let iface_local = Arc::new(
                    TunSocket::new(&device.read().iface.name().unwrap())
                        .unwrap()
                        .set_non_blocking()
                        .unwrap(),
                );

                device
                    .read()
                    .register_iface_handler(Arc::clone(&iface_local))
                    .ok();

                iface_local
            },
        };

        #[cfg(not(target_os = "linux"))]
        let mut thread_local = ThreadData {
            src_buf: [0u8; MAX_UDP_SIZE],
            dst_buf: [0u8; MAX_UDP_SIZE],
            junk_rng: ChaCha8Rng::from_rng(OsRng).expect("OsRng must seed ChaCha8"),
            probe_rng: ChaCha8Rng::from_rng(OsRng).expect("OsRng must seed ChaCha8"),
            iface: Arc::clone(&device.read().iface),
        };

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = device.read().uapi_fd;

        loop {
            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let mut device_lock = device.read();
            let queue = Arc::clone(&device_lock.queue);

            loop {
                match queue.wait() {
                    WaitResult::Ok(handler) => {
                        let action = (*handler)(&mut device_lock, &mut thread_local);
                        match action {
                            Action::Continue => {}
                            Action::Yield => break,
                            Action::Exit => {
                                device_lock.trigger_exit();
                                return;
                            }
                        }
                    }
                    WaitResult::EoF(handler) => {
                        if uapi_fd >= 0 && uapi_fd == handler.fd() {
                            device_lock.trigger_exit();
                            return;
                        }
                        handler.cancel();
                    }
                    WaitResult::Error(e) => tracing::error!(message = "Poll error", error = ?e),
                }
            }
        }
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

impl Device {
    fn next_index(&mut self) -> u32 {
        self.next_index.next()
    }

    fn remove_peer(&mut self, pub_key: &x25519::PublicKey) {
        if let Some(peer) = self.peers.remove(pub_key) {
            // Found a peer to remove, now purge all references to it:
            {
                let p = peer.lock();
                p.shutdown_endpoint(); // close open udp socket and free the closure
                self.peers_by_idx.remove(&p.index());
            }
            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(&peer, p));

            tracing::info!("Peer removed");
        }
    }

    /// Apply an update to a peer that already exists, in place.
    ///
    /// Each field is only touched when the caller supplied it, so a reload that
    /// re-sends unchanged values is inert. That matters because the underlying
    /// setters are not all free: changing the pre-shared key discards live
    /// sessions.
    /// Does `addr` route to this peer?
    ///
    /// `peers_by_ip` is the single authority for which peer owns a prefix.
    /// `Peer` used to keep its own copy for this check, which meant moving a
    /// prefix between peers updated the global index but left the old owner's
    /// copy intact -- so the previous owner could still source-spoof an address
    /// it no longer held. One index cannot disagree with itself.
    fn peer_owns(&self, peer: &Arc<Mutex<Peer>>, addr: IpAddr) -> bool {
        index_owns(&self.peers_by_ip, peer, addr)
    }

    /// The prefixes currently routed to this peer, for reporting and for the
    /// additive form of a peer update.
    ///
    /// Derived rather than stored: a cached copy is what allowed the two to
    /// drift. This walks the whole trie, which is fine for `get=1` and for a
    /// peer update, neither of which is on the data path.
    fn peer_allowed_ips(&self, peer: &Arc<Mutex<Peer>>) -> Vec<(IpAddr, u8)> {
        index_prefixes(&self.peers_by_ip, peer)
    }

    fn remove_peer_allowed_ips(&mut self, peer: &Arc<Mutex<Peer>>) {
        self.peers_by_ip
            .remove(&|owner: &Arc<Mutex<Peer>>| Arc::ptr_eq(owner, peer));
    }

    fn add_peer_allowed_ip(&mut self, peer: &Arc<Mutex<Peer>>, allowed_ip: AllowedIP) {
        self.peers_by_ip
            .insert(allowed_ip.addr, allowed_ip.cidr as u32, Arc::clone(peer));
    }

    fn remove_peer_allowed_ip(&mut self, peer: &Arc<Mutex<Peer>>, allowed_ip: AllowedIP) {
        self.peers_by_ip
            .remove_exact(allowed_ip.addr, allowed_ip.cidr as u32, &|owner: &Arc<
                Mutex<Peer>,
            >| {
                Arc::ptr_eq(owner, peer)
            });
    }

    fn merge_peer(
        &mut self,
        peer: &Arc<Mutex<Peer>>,
        replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        keepalive: Option<(u32, u32)>,
        preshared_key: Option<[u8; 32]>,
    ) {
        {
            let mut p = peer.lock();

            if let Some(addr) = endpoint {
                p.set_endpoint(addr);
            }
            if keepalive.is_some() {
                p.set_persistent_keepalive_range(keepalive);
            }
            if preshared_key.is_some() {
                p.set_preshared_key(preshared_key);
            }
        }

        // `replace_allowed_ips=true` means "these prefixes are now the whole
        // set"; without it the new prefixes are additive. Either way the stale
        // global index entries have to go first, or a prefix that was just
        // dropped keeps routing here.
        if replace_ips || !allowed_ips.is_empty() {
            // Additive updates keep what the trie already routes here; a
            // replace starts from nothing. Either way the peer's existing
            // entries come out first, or a dropped prefix keeps routing here.
            let mut prefixes: Vec<(IpAddr, u8)> = if replace_ips {
                Vec::new()
            } else {
                self.peer_allowed_ips(peer)
            };
            prefixes.extend(allowed_ips.iter().map(|ip| (ip.addr, ip.cidr)));

            self.peers_by_ip
                .remove(&|p: &Arc<Mutex<Peer>>| Arc::ptr_eq(peer, p));
            for (addr, cidr) in prefixes {
                self.peers_by_ip.insert(addr, cidr as _, Arc::clone(peer));
            }
        }

        tracing::info!("Peer updated");
    }

    #[allow(clippy::too_many_arguments)]
    fn update_peer(
        &mut self,
        pub_key: x25519::PublicKey,
        remove: bool,
        replace_ips: bool,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        keepalive: Option<(u32, u32)>,
        preshared_key: Option<[u8; 32]>,
    ) -> Result<(), Error> {
        if remove {
            // Completely remove a peer
            self.remove_peer(&pub_key);
            return Ok(());
        }

        // Merge into an existing peer rather than rejecting the update.
        //
        // This path is not exotic: `awg syncconf` re-sends every peer's full
        // block on each configuration reload, so the installer hits it on every
        // client add and revoke. Aborting here would take the daemon down during
        // routine peer management.
        if let Some(peer) = self.peers.get(&pub_key).cloned() {
            self.merge_peer(
                &peer,
                replace_ips,
                endpoint,
                allowed_ips,
                keepalive,
                preshared_key,
            );
            return Ok(());
        }

        let next_index = self.next_index();
        // Reachable from the control plane, not an invariant: a `set=1`
        // transaction that names a peer before `private_key=` arrives here with
        // no key pair. `awg setconf` always sends the key first, so this is
        // malformed input rather than normal use -- which is exactly why it
        // should be an error the caller sees rather than a dead daemon.
        let device_key_pair = require_key_pair(&self.key_pair)?;

        // Read the obfuscation settings from the device rather than taking them
        // as parameters: that is what guarantees every peer's copy stays
        // byte-identical to the device's, which matters because the connected-
        // socket path strips with the *per-peer* config while the anonymous
        // path strips with the device's.
        // Pass the validated ranges straight through rather than decomposing
        // them into eight integers for `new_with_amnezia` to re-validate. That
        // round trip could only fail on values this device has already
        // accepted, so its error was unreachable -- and asserting an
        // unreachable error with `expect` turns any future gap in that
        // reasoning into a dead daemon.
        let mut tunn = Tunn::new_with_obfuscation(
            device_key_pair.0.clone(),
            pub_key,
            preshared_key,
            None,
            next_index,
            None,
            self.config.obf,
            // Not `as_responder()`: the kernel module emits Jc junk from
            // `wg_packet_send_handshake_initiation` (src/send.c:58-75), i.e.
            // from whichever side initiates, with no role distinction. Since
            // this device layer is also what backs boringtun-cli as
            // `wg-quick`'s userspace implementation -- a client -- suppressing
            // it here would silently drop configured junk for the common case.
            // Embedders that genuinely want responder-only suppression can
            // still opt in via `AmneziaConfig::as_responder`.
            self.config.amnezia.clone(),
        )
        .map_err(Error::PeerSetup)?;
        tunn.set_mtu(self.mtu.load(Ordering::Relaxed));

        let mut peer = Peer::new(tunn, next_index, endpoint, preshared_key);
        if let Some(range) = keepalive {
            peer.set_persistent_keepalive_range(Some(range));
        }

        let peer = Arc::new(Mutex::new(peer));
        self.peers.insert(pub_key, Arc::clone(&peer));
        self.peers_by_idx.insert(next_index, Arc::clone(&peer));

        for AllowedIP { addr, cidr } in allowed_ips {
            self.peers_by_ip
                .insert(*addr, *cidr as _, Arc::clone(&peer));
        }

        tracing::info!("Peer added");
        Ok(())
    }

    pub fn new(name: &str, config: DeviceConfig) -> Result<Device, Error> {
        let poll = EventPoll::<Handler>::new()?;

        // Create a tunnel device
        let iface = Arc::new(TunSocket::new(name)?.set_non_blocking()?);
        let mtu = iface.mtu()?;

        let enable_uapi = config.enable_uapi;
        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        // Disabling UAPI is an absolute opt-out: do not register, poll, or
        // otherwise attach even a caller-supplied UAPI descriptor.
        let uapi_fd = if enable_uapi { config.uapi_fd } else { -1 };

        // Before `config` is moved into the device.
        // `filter(> 0)` so `Some(0)` and `None` cannot mean different things:
        // a zero-byte allowance already refuses every reply, so leaving both
        // spellings live would be two encodings of one state.
        let probe_responder = config
            .probe_reply_bytes_per_sec
            .filter(|&rate| rate > 0)
            .map(ProbeResponder::new);

        let mut device = Device {
            queue: Arc::new(poll),
            iface,
            config,
            exit_notice: Default::default(),
            yield_notice: Default::default(),
            fwmark: Default::default(),
            key_pair: Default::default(),
            listen_port: Default::default(),
            next_index: Default::default(),
            peers: Default::default(),
            peers_by_idx: Default::default(),
            peers_by_ip: AllowedIps::new(),
            udp4: Default::default(),
            udp6: Default::default(),
            cleanup_paths: Default::default(),
            mtu: AtomicUsize::new(mtu),
            rate_limiter: None,
            probe_responder,
            #[cfg(target_os = "linux")]
            uapi_fd,
        };

        if uapi_fd >= 0 {
            device.register_api_fd(uapi_fd)?;
        } else if enable_uapi {
            device.register_api_handler()?;
        }
        device.register_iface_handler(Arc::clone(&device.iface))?;
        device.register_notifiers()?;
        device.register_timers()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE") {
                if name == "utun" {
                    std::fs::write(&name_file, device.iface.name().unwrap().as_bytes()).unwrap();
                    device.cleanup_paths.push(name_file);
                }
            }
        }

        Ok(device)
    }

    fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        // Binds the network facing interfaces
        // First close any existing open socket, and remove them from the event loop
        if let Some(s) = self.udp4.take() {
            unsafe {
                // This is safe because the event loop is not running yet
                self.queue.clear_event_by_fd(s.as_raw_fd())
            }
        };

        if let Some(s) = self.udp6.take() {
            unsafe { self.queue.clear_event_by_fd(s.as_raw_fd()) };
        }

        for peer in self.peers.values() {
            peer.lock().shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock4.set_reuse_address(true)?;
        udp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        udp_sock4.set_nonblocking(true)?;

        if port == 0 {
            // Random port was assigned
            port = udp_sock4.local_addr()?.as_socket().unwrap().port();
        }

        let udp_sock6 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock6.set_reuse_address(true)?;
        udp_sock6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        udp_sock6.set_nonblocking(true)?;

        self.register_udp_handler(udp_sock4.try_clone().unwrap())?;
        self.register_udp_handler(udp_sock6.try_clone().unwrap())?;
        self.udp4 = Some(udp_sock4);
        self.udp6 = Some(udp_sock6);

        self.listen_port = port;

        Ok(())
    }

    fn set_key(&mut self, private_key: x25519::StaticSecret) {
        let public_key = x25519::PublicKey::from(&private_key);
        let key_pair = Some((private_key.clone(), public_key));

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.values_mut() {
            peer.lock().tunnel.set_static_private(
                private_key.clone(),
                public_key,
                Some(Arc::clone(&rate_limiter)),
            )
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);
    }

    /// Set the interface-wide AmneziaWG parameters.
    ///
    /// Returns `false` and changes nothing when the values already match.
    ///
    /// The short-circuit is an optimisation, not a correctness requirement:
    /// `awg syncconf` re-sends the whole `[Interface]` block on every peer add
    /// or revoke, so without it each of those would walk every peer, take every
    /// peer lock and log a spurious "parameters updated". Applying redundantly
    /// would still be *safe* — `Tunn::set_obfuscation` keeps established
    /// sessions, because obfuscation is framing rather than key material.
    /// (`set_key` above short-circuits for a stronger reason: rekeying really
    /// does drop sessions.)
    fn set_obfuscation(&mut self, obf: ObfuscationRanges, amnezia: AmneziaConfig) -> bool {
        if self.config.obf == obf && self.config.amnezia == amnezia {
            return false;
        }

        self.config.obf = obf;
        self.config.amnezia = amnezia;

        // Push to every existing peer, exactly as `set_key` does above. Peers
        // snapshot these values when their `Tunn` is built, so without this a
        // live change leaves each peer framing packets differently from the
        // interface that has to parse them: every tunnel dies silently and
        // stays dead until the daemon restarts. `awg syncconf` reaches here on
        // any `[Interface]` edit, so this is a routine path, not a corner case.
        let obf = self.config.obf;
        let amnezia = self.config.amnezia.clone();
        for peer in self.peers.values_mut() {
            peer.lock().tunnel.set_obfuscation(obf, amnezia.clone());
        }

        true
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        if let Some(ref sock) = self.udp4 {
            sock.set_mark(mark)?;
        }

        if let Some(ref sock) = self.udp6 {
            sock.set_mark(mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.values() {
            if let Some(ref sock) = peer.lock().endpoint().conn {
                sock.set_mark(mark)?
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
        self.peers_by_idx.clear();
        self.peers_by_ip.clear();
    }

    fn register_notifiers(&mut self) -> Result<(), Error> {
        let yield_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_, _| Action::Yield))?;
        self.yield_notice = Some(yield_ev);

        let exit_ev = self
            .queue
            // The exit event handler simply returns Action::Exit
            .new_notifier(Box::new(|_, _| Action::Exit))?;
        self.exit_notice = Some(exit_ev);
        Ok(())
    }

    fn register_timers(&self) -> Result<(), Error> {
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count()
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;

        self.queue.new_periodic_event(
            // Execute the timed function of every peer in the list
            Box::new(|d, t| {
                // The TUN MTU can change after peers are created. Refresh the
                // device value and every peer-owned Tunn independently of the
                // presence of a UAPI control socket.
                if let Ok(mtu) = d.iface.mtu() {
                    let previous = d.mtu.swap(mtu, Ordering::Relaxed);
                    if previous != mtu {
                        for peer in d.peers.values() {
                            peer.lock().tunnel.set_mtu(mtu);
                        }
                    }
                }

                let peer_map = &d.peers;

                let (udp4, udp6) = match (d.udp4.as_ref(), d.udp6.as_ref()) {
                    (Some(udp4), Some(udp6)) => (udp4, udp6),
                    _ => return Action::Continue,
                };

                // Go over each peer and invoke the timer function
                for peer in peer_map.values() {
                    let mut p = peer.lock();
                    let endpoint_addr = match p.endpoint().addr {
                        Some(addr) => addr,
                        None => continue,
                    };

                    match p.update_timers(&mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            p.shutdown_endpoint(); // close open udp socket
                        }
                        TunnResult::Err(e) => tracing::error!(message = "Timer error", error = ?e),
                        TunnResult::WriteToNetwork(packet) => {
                            match endpoint_addr {
                                SocketAddr::V4(_) => {
                                    udp4.send_to(packet, &endpoint_addr.into()).ok()
                                }
                                SocketAddr::V6(_) => {
                                    udp6.send_to(packet, &endpoint_addr.into()).ok()
                                }
                            };
                        }
                        // update_timers only yields Done/Err/WriteToNetwork, but
                        // this runs on a 250 ms tick for every peer: an
                        // unexpected variant must not take the daemon down.
                        other => tracing::error!(
                            message = "Unexpected result from update_timers",
                            result = ?other
                        ),
                    };
                }
                Action::Continue
            }),
            std::time::Duration::from_millis(250),
        )?;
        Ok(())
    }

    pub(crate) fn trigger_yield(&self) {
        self.queue
            .trigger_notification(self.yield_notice.as_ref().unwrap())
    }

    pub(crate) fn trigger_exit(&self) {
        self.queue
            .trigger_notification(self.exit_notice.as_ref().unwrap())
    }

    pub(crate) fn cancel_yield(&self) {
        self.queue
            .stop_notification(self.yield_notice.as_ref().unwrap())
    }

    fn register_udp_handler(&self, udp: socket2::Socket) -> Result<(), Error> {
        // Logged at most once per socket. The keyless path is re-dispatched
        // for every batch of arriving datagrams, and a daemon that is never
        // given a key stays on it indefinitely, so logging per dispatch would
        // turn one misconfiguration into unbounded log volume. Once carries
        // the whole signal: the operator needs to know traffic arrived before
        // the key, not how much of it did.
        let warned_keyless = AtomicBool::new(false);
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // Handler that handles anonymous packets over UDP
                let mut iter = MAX_ITR;
                // `DeviceHandle::new` binds this socket, via its
                // `open_listen_socket(0)` call, before any `private_key=` can
                // arrive over the UAPI -- so a datagram in that window reaches
                // a device that has no key yet.
                //
                // Panicking here did not merely lose a worker:
                // `DeviceHandle::wait` joins the workers with
                // `thread.join().unwrap()`, so a panicked worker panics the
                // main thread and the whole daemon exits. One unauthenticated datagram, no key required, and
                // the interface is gone -- measured, not inferred: with the
                // panic restored the interop harness reports "Unable to modify
                // interface: No such device" at the next `awg setconf`.
                //
                // `set_key` establishes `key_pair` and `rate_limiter`
                // together, so neither can be observed without the other; both
                // are checked anyway rather than unwrapping the second on the
                // strength of the first.
                let (private_key, public_key) = match d.key_pair.as_ref() {
                    Some(pair) => pair,
                    None => {
                        if !warned_keyless.swap(true, Ordering::Relaxed) {
                            tracing::debug!("dropping datagrams: no private key set yet");
                        }
                        drain_datagrams(&udp, &mut t.src_buf);
                        return Action::Continue;
                    }
                };
                let rate_limiter = match d.rate_limiter.as_ref() {
                    Some(limiter) => limiter,
                    None => {
                        if !warned_keyless.swap(true, Ordering::Relaxed) {
                            tracing::debug!("dropping datagrams: no rate limiter yet");
                        }
                        drain_datagrams(&udp, &mut t.src_buf);
                        return Action::Continue;
                    }
                };
                // Interface-wide AmneziaWG tag ranges. `ObfuscationRanges` is
                // `Copy`, so this is a cheap snapshot for the whole batch.
                let obf = d.config.obf;

                // Loop while we have packets on the anonymous connection

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                let src_buf =
                    unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };
                // Bound the batch on datagrams *received*, not on datagrams
                // fully processed. Every `continue` below -- unrecognised
                // framing, a probe reply, a cookie reply, an unknown peer --
                // skips the bottom of the loop, so with the decrement down
                // there a flood of anything that is not a valid peer packet
                // kept this worker inside a single dispatch indefinitely. It
                // holds the device read lock while it spins, so `awg set`
                // blocks for the duration of the flood, and this worker's
                // timers never run. `MAX_ITR` is what `drain_datagrams`
                // already bounds itself by; this makes the main path agree.
                //
                // The budget is spent *before* the receive, not after it: with
                // the test inside the loop body the last iteration called
                // `recv_from` first and broke afterwards, so one datagram per
                // saturated dispatch was taken off the socket and dropped
                // unprocessed -- a legitimate handshake as readily as junk.
                while iter > 0 {
                    let Ok((packet_len, addr)) = udp.recv_from(src_buf) else {
                        break;
                    };
                    iter -= 1;

                    // Resolved once, here, rather than twice further down behind
                    // `unwrap()`. A `SockAddr` whose family is neither AF_INET
                    // nor AF_INET6 cannot be replied to *or* attributed to a
                    // peer, and a panic in this worker takes the whole daemon
                    // down (see the keyless comment above), so it is dropped.
                    let Some(from) = addr.as_socket() else {
                        continue;
                    };

                    // AmneziaWG framing first, probe detection only if that
                    // fails. The order lives inside `classify` rather than here
                    // so it can be tested; see its doc for why getting it
                    // backwards makes the server answer its own clients.
                    // Reverse Header Protection before the shared S/H
                    // classifier and peer demultiplexer inspect the packet.
                    // Keep the S-prefix intact so classify can preserve the
                    // established probe-vs-WireGuard ordering and strip it
                    // only after the recovered H tag has matched.
                    let raw_datagram = &t.src_buf[..packet_len];
                    let decoded_datagram = d
                        .config
                        .amnezia
                        .decrypt_inbound_with_prefix(obf, raw_datagram);
                    let datagram = match decoded_datagram.as_deref() {
                        Some(decoded) => decoded,
                        None if !d.config.amnezia.header_protection_enabled() => raw_datagram,
                        // Do not fall back to plaintext classification when a
                        // Header Protection key is configured. Otherwise a
                        // correctly tagged but unprotected packet could bypass
                        // the configured wire policy (especially with broad H
                        // ranges).
                        None => continue,
                    };
                    let packet = match probe_reply::classify(
                        datagram,
                        &d.config.amnezia,
                        obf,
                        from,
                        d.probe_responder.as_ref(),
                        &mut t.probe_rng,
                    ) {
                        probe_reply::Ingress::Wireguard(packet) => packet,
                        probe_reply::Ingress::Reply(reply) => {
                            let _: Result<_, _> = udp.send_to(&reply, &addr);
                            continue;
                        }
                        probe_reply::Ingress::Drop => continue,
                    };
                    // The rate limiter checks mac1 and mac2 over the slice
                    // `classify` handed back -- the S-prefix already stripped.
                    // That order is mandatory: the MACs are computed over the
                    // unpadded packet, so verifying the padded datagram fails
                    // the check. It mirrors the kernel module, which strips at
                    // device level before peer lookup.
                    let parsed_packet = match rate_limiter.verify_packet_with_cookie_policy(
                        obf,
                        &mut OsRng,
                        Some(from.ip()),
                        packet,
                        &mut t.dst_buf,
                        d.config.amnezia.disable_cookies,
                    ) {
                        Ok(packet) => packet,
                        Err(TunnResult::WriteToNetwork(cookie)) => {
                            // Nothing here has been authenticated. `verify_packet`
                            // returns a cookie on a valid mac1, and mac1 is keyed
                            // on this server's *public* key -- which is in every
                            // client configuration. Upstream AWG sends the
                            // configured S3 prefix verbatim; only source-address
                            // hygiene is applied before sending.
                            let cookie_len = cookie.len();
                            match reply_policy::cookie_verdict(from) {
                                reply_policy::CookieVerdict::Send => {
                                    // The limiter writes a bare cookie reply; it
                                    // does not know about S3. Re-prefix it in
                                    // place before sending, or the peer will
                                    // reject it.
                                    if let Ok(out) = d.config.amnezia.prepend_outbound_with_limits(
                                        obf,
                                        &mut t.dst_buf,
                                        cookie_len,
                                        crate::noise::amnezia::DEFAULT_UDP_WINDOW,
                                        usize::MAX,
                                        &mut t.junk_rng,
                                    ) {
                                        let _: Result<_, _> = udp.send_to(out, &addr);
                                    }
                                }
                                reply_policy::CookieVerdict::RefusedSource => {}
                            }
                            continue;
                        }
                        Err(_) => continue,
                    };

                    let peer = match &parsed_packet {
                        Packet::HandshakeInit(p) => {
                            parse_handshake_anon(private_key, public_key, p)
                                .ok()
                                .and_then(|hh| {
                                    d.peers.get(&x25519::PublicKey::from(hh.peer_static_public))
                                })
                        }
                        Packet::HandshakeResponse(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketCookieReply(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                        Packet::PacketData(p) => d.peers_by_idx.get(&(p.receiver_idx >> 8)),
                    };

                    let peer = match peer {
                        None => continue,
                        Some(peer) => peer,
                    };

                    let mut p = peer.lock();

                    // We found a peer, use it to decapsulate the message+
                    let mut flush = false; // Are there packets to send from the queue?
                    match p
                        .tunnel
                        .handle_verified_packet(parsed_packet, &mut t.dst_buf[..])
                    {
                        TunnResult::Done => {}
                        TunnResult::Err(_) => continue,
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            let _: Result<_, _> = udp.send_to(packet, &addr);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if d.peer_owns(peer, addr.into()) {
                                t.iface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if d.peer_owns(peer, addr.into()) {
                                t.iface.write6(packet);
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        while let TunnResult::WriteToNetwork(packet) =
                            p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            let _: Result<_, _> = udp.send_to(packet, &addr);
                        }
                    }

                    // This packet was OK, that means we want to create a connected socket for this peer
                    let ip_addr = from.ip();
                    p.set_endpoint(from);
                    if d.config.use_connected_socket {
                        if let Ok(sock) = p.connect_endpoint(d.listen_port, d.fwmark) {
                            d.register_conn_handler(Arc::clone(peer), sock, ip_addr)
                                .unwrap();
                        }
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_conn_handler(
        &self,
        peer: Arc<Mutex<Peer>>,
        udp: socket2::Socket,
        peer_addr: IpAddr,
    ) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let iface = &t.iface;
                let mut iter = MAX_ITR;

                // Safety: the `recv_from` implementation promises not to write uninitialised
                // bytes to the buffer, so this casting is safe.
                let src_buf =
                    unsafe { &mut *(&mut t.src_buf[..] as *mut [u8] as *mut [MaybeUninit<u8>]) };

                while let Ok(read_bytes) = udp.recv(src_buf) {
                    let mut flush = false;
                    let mut p = peer.lock();
                    match p.tunnel.decapsulate(
                        Some(peer_addr),
                        &t.src_buf[..read_bytes],
                        &mut t.dst_buf[..],
                    ) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => eprintln!("Decapsulate error {:?}", e),
                        TunnResult::WriteToNetwork(packet) => {
                            flush = true;
                            let _: Result<_, _> = udp.send(packet);
                        }
                        TunnResult::WriteToTunnelV4(packet, addr) => {
                            if d.peer_owns(&peer, addr.into()) {
                                iface.write4(packet);
                            }
                        }
                        TunnResult::WriteToTunnelV6(packet, addr) => {
                            if d.peer_owns(&peer, addr.into()) {
                                iface.write6(packet);
                            }
                        }
                    };

                    if flush {
                        // Flush pending queue
                        while let TunnResult::WriteToNetwork(packet) =
                            p.tunnel.decapsulate(None, &[], &mut t.dst_buf[..])
                        {
                            let _: Result<_, _> = udp.send(packet);
                        }
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_iface_handler(&self, iface: Arc<TunSocket>) -> Result<(), Error> {
        self.queue.new_event(
            iface.as_raw_fd(),
            Box::new(move |d, t| {
                // The iface_handler handles packets received from the WireGuard virtual network
                // interface. The flow is as follows:
                // * Read a packet
                // * Determine peer based on packet destination ip
                // * Encapsulate the packet for the given peer
                // * Send encapsulated packet to the peer's endpoint
                let mtu = d.mtu.load(Ordering::Relaxed);

                let udp4 = d.udp4.as_ref().expect("Not connected");
                let udp6 = d.udp6.as_ref().expect("Not connected");

                let peers = &d.peers_by_ip;
                for _ in 0..MAX_ITR {
                    let src = match iface.read(&mut t.src_buf[..mtu]) {
                        Ok(src) => src,
                        Err(Error::IfaceRead(e)) => {
                            let ek = e.kind();
                            if ek == io::ErrorKind::Interrupted || ek == io::ErrorKind::WouldBlock {
                                break;
                            }
                            eprintln!("Fatal read error on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                        Err(e) => {
                            eprintln!("Unexpected error on tun interface: {:?}", e);
                            return Action::Exit;
                        }
                    };

                    let dst_addr = match Tunn::dst_address(src) {
                        Some(addr) => addr,
                        None => continue,
                    };

                    let mut peer = match peers.find(dst_addr) {
                        Some(peer) => peer.lock(),
                        None => continue,
                    };

                    match peer.tunnel.encapsulate(src, &mut t.dst_buf[..]) {
                        TunnResult::Done => {}
                        TunnResult::Err(e) => {
                            tracing::error!(message = "Encapsulate error", error = ?e)
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            let mut endpoint = peer.endpoint_mut();
                            if let Some(conn) = endpoint.conn.as_mut() {
                                // Prefer to send using the connected socket
                                let _: Result<_, _> = conn.write(packet);
                            } else if let Some(addr @ SocketAddr::V4(_)) = endpoint.addr {
                                let _: Result<_, _> = udp4.send_to(packet, &addr.into());
                            } else if let Some(addr @ SocketAddr::V6(_)) = endpoint.addr {
                                let _: Result<_, _> = udp6.send_to(packet, &addr.into());
                            } else {
                                tracing::error!("No endpoint");
                            }
                        }
                        // Per-packet path: drop the packet rather than aborting
                        // the whole daemon on an unexpected variant.
                        other => tracing::error!(
                            message = "Unexpected result from encapsulate",
                            result = ?other
                        ),
                    };
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }
}

/// A basic linear-feedback shift register implemented as xorshift, used to
/// distribute peer indexes across the 24-bit address space reserved for peer
/// identification.
/// The purpose is to obscure the total number of peers using the system and to
/// ensure it requires a non-trivial amount of processing power and/or samples
/// to guess other peers' indices. Anything more ambitious than this is wasted
/// with only 24 bits of space.
struct IndexLfsr {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

impl IndexLfsr {
    /// Generate a random 24-bit nonzero integer
    fn random_index() -> u32 {
        const LFSR_MAX: u32 = 0xffffff; // 24-bit seed
        loop {
            let i = OsRng.next_u32() & LFSR_MAX;
            if i > 0 {
                // LFSR seed must be non-zero
                return i;
            }
        }
    }

    /// Generate the next value in the pseudorandom sequence
    fn next(&mut self) -> u32 {
        // 24-bit polynomial for randomness. This is arbitrarily chosen to
        // inject bitflips into the value.
        const LFSR_POLY: u32 = 0xd80000; // 24-bit polynomial
        let value = self.lfsr - 1; // lfsr will never have value of 0
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1u32)) & LFSR_POLY);
        assert!(self.lfsr != self.initial, "Too many peers created");
        value ^ self.mask
    }
}

impl Default for IndexLfsr {
    fn default() -> Self {
        let seed = Self::random_index();
        IndexLfsr {
            initial: seed,
            lfsr: seed,
            mask: Self::random_index(),
        }
    }
}

#[cfg(test)]
mod ingress_tests {
    //! Device-level ingress demux, exercised without a TUN device or root.
    //!
    //! `integration_tests` covers the daemon end-to-end but needs `CAP_NET_ADMIN`
    //! to create interfaces, so it cannot run in CI or under an unprivileged
    //! shell. The demux is the part of the server that AmneziaWG actually
    //! changes, and it is reachable with nothing but a keypair and a byte
    //! buffer: reproduce the exact sequence `register_udp_handler` performs on
    //! an anonymous datagram.

    use super::*;

    #[test]
    fn device_config_keeps_uapi_compatibility_and_allows_daemon_mode() {
        let legacy = DeviceConfig::default();
        assert!(legacy.enable_uapi);
        assert_eq!(legacy.listen_port, None);

        let daemon = DeviceConfig {
            enable_uapi: false,
            listen_port: Some(51820),
            ..DeviceConfig::default()
        };
        assert!(!daemon.enable_uapi);
        assert_eq!(daemon.listen_port, Some(51820));
    }

    /// Moving a prefix from one peer to another must transfer ownership
    /// completely. The old owner keeping its own copy is what let it carry on
    /// source-spoofing an address the trie had already reassigned.
    #[test]
    fn moving_a_prefix_transfers_ownership_completely() {
        let a = Arc::new("peer-a");
        let b = Arc::new("peer-b");
        let addr: IpAddr = "10.66.66.2".parse().unwrap();

        let mut index: AllowedIps<Arc<&str>> = AllowedIps::new();
        index.insert(addr, 32, Arc::clone(&a));
        assert!(index_owns(&index, &a, addr), "a owns it to begin with");

        // The move: b claims the same prefix.
        index.insert(addr, 32, Arc::clone(&b));

        assert!(index_owns(&index, &b, addr), "b owns it now");
        assert!(
            !index_owns(&index, &a, addr),
            "a must not still own a prefix it lost -- this is the spoofing gap"
        );
        assert!(index_prefixes(&index, &a).is_empty(), "a has no prefixes");
        assert_eq!(index_prefixes(&index, &b), vec![(addr, 32)]);
    }

    /// Overlapping prefixes stay independent: a /32 inside another peer's /24
    /// does not displace it, matching the kernel's separate-node behaviour.
    #[test]
    fn overlapping_prefixes_belong_to_their_own_owners() {
        let wide = Arc::new("peer-wide");
        let narrow = Arc::new("peer-narrow");
        let inside: IpAddr = "10.66.66.7".parse().unwrap();
        let elsewhere: IpAddr = "10.66.66.9".parse().unwrap();

        let mut index: AllowedIps<Arc<&str>> = AllowedIps::new();
        index.insert("10.66.66.0".parse().unwrap(), 24, Arc::clone(&wide));
        index.insert(inside, 32, Arc::clone(&narrow));

        // Longest prefix wins for the specific address...
        assert!(index_owns(&index, &narrow, inside));
        assert!(!index_owns(&index, &wide, inside));
        // ...while the rest of the /24 still belongs to its owner.
        assert!(index_owns(&index, &wide, elsewhere));
        assert!(!index_owns(&index, &narrow, elsewhere));
        // And neither displaced the other from the index.
        assert_eq!(index_prefixes(&index, &narrow), vec![(inside, 32)]);
        assert_eq!(index_prefixes(&index, &wide).len(), 1);
    }
    use crate::noise::handshake::parse_handshake_anon;
    use crate::noise::packet_sizes::{COOKIE_REPLY_SZ, HANDSHAKE_INIT_SZ};
    use crate::x25519;
    use rand_core::OsRng;

    /// Run the device's anonymous-ingress sequence over `datagram`, returning
    /// the initiator's static public key when it demuxes to a handshake.
    ///
    /// Mirrors `register_udp_handler`: strip the S-prefix, verify with the
    /// device-scoped ranges, then identify the peer from the parse result.
    ///
    /// The source address is supplied for the same reason the real path
    /// supplies it (`Some(addr.as_socket().unwrap().ip())`): once the limiter
    /// is under load, `verify_packet` rejects a `None` address outright with
    /// `UnderLoad`, because mac2 cannot be validated without one. Passing
    /// `None` here would pass today only because two packets never trip the
    /// 100/s limit -- the helper would quietly stop mirroring production the
    /// moment the limit dropped or this was reused for cookie-path tests.
    fn demux_handshake(
        server_secret: &x25519::StaticSecret,
        obf: ObfuscationRanges,
        amnezia: &AmneziaConfig,
        datagram: &[u8],
    ) -> Option<[u8; 32]> {
        let server_public = x25519::PublicKey::from(server_secret);
        let limiter = RateLimiter::new(&server_public, HANDSHAKE_RATE_LIMIT);
        let mut scratch = vec![0u8; MAX_UDP_SIZE];

        // RFC 5737 TEST-NET-3, so the value is obviously a fixture.
        let src_addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        // A datagram matching no configured shape is dropped, exactly as the
        // real ingress path does.
        let decoded = amnezia.decrypt_inbound_with_prefix(obf, datagram);
        let datagram = match decoded.as_deref() {
            Some(decoded) => decoded,
            None if !amnezia.header_protection_enabled() => datagram,
            None => return None,
        };
        let stripped = amnezia.strip_inbound(obf, datagram)?;
        let parsed = limiter
            .verify_packet(obf, &mut OsRng, Some(src_addr), stripped, &mut scratch)
            .ok()?;

        match parsed {
            Packet::HandshakeInit(p) => parse_handshake_anon(server_secret, &server_public, &p)
                .ok()
                .map(|hh| hh.peer_static_public),
            _ => None,
        }
    }

    /// An AmneziaWG client's obfuscated initiation is demuxed to the right peer.
    ///
    /// This is the crux of server support: ingress has to classify a datagram
    /// *before* any peer is known, so the S-prefix must be stripped and the
    /// H1 tag understood using the device's settings alone.
    #[test]
    fn obfuscated_initiation_demuxes_to_the_initiating_peer() {
        let server_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let server_public = x25519::PublicKey::from(&server_secret);
        let client_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let client_public = x25519::PublicKey::from(&client_secret);

        // Non-default tags and a junk prefix on every packet kind, so a device
        // still on the vanilla defaults could not parse this.
        let obf = ObfuscationRanges::new(
            342871004, 442871003, 542871004, 642871003, 742871004, 842871003, 942871004, 1042871003,
        )
        .unwrap();
        let amnezia = AmneziaConfig::new(37, 121, 88, 64).with_header_protection_key([0x37; 32]);

        let mut client = Tunn::new_with_amnezia(
            client_secret,
            server_public,
            None,
            None,
            1,
            None,
            342871004,
            442871003,
            542871004,
            642871003,
            742871004,
            842871003,
            942871004,
            1042871003,
            amnezia.clone(),
        )
        .unwrap();

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let datagram = match client.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("expected an initiation, got {:?}", other),
        };

        // S1 = 37 bytes of junk ahead of the 148-byte initiation.
        assert_eq!(datagram.len(), 37 + 148, "S1 prefix present on the wire");
        let decoded = amnezia
            .decrypt_inbound_with_prefix(obf, &datagram)
            .expect("device ingress must recover the protected H1 tag");
        let mut tag_bytes = [0u8; 4];
        tag_bytes.copy_from_slice(&decoded[37..41]);
        let tag = u32::from_le_bytes(tag_bytes);
        assert!(
            (342871004..=442871003).contains(&tag),
            "H1 tag in the configured range, got {}",
            tag
        );

        let demuxed = demux_handshake(&server_secret, obf, &amnezia, &datagram)
            .expect("device ingress must demux an obfuscated initiation");
        assert_eq!(
            demuxed,
            *client_public.as_bytes(),
            "must identify the initiating peer"
        );
    }

    #[test]
    fn device_ingress_rejects_plaintext_when_header_protection_is_required() {
        let server_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let server_public = x25519::PublicKey::from(&server_secret);
        let client_secret = x25519::StaticSecret::random_from_rng(OsRng);

        // The sender deliberately has no HP key, but uses the same S-prefix
        // sizes and H values. A receiver configured with HP must not silently
        // accept this otherwise-valid, plaintext initiation.
        let sender_amnezia = AmneziaConfig::new(12, 12, 12, 12);
        let receiver_amnezia =
            AmneziaConfig::new(12, 12, 12, 12).with_header_protection_key([0x42; 32]);
        let mut client = Tunn::new_with_amnezia(
            client_secret,
            server_public,
            None,
            None,
            1,
            None,
            1,
            1,
            2,
            2,
            3,
            3,
            4,
            4,
            sender_amnezia,
        )
        .unwrap();

        let mut buffer = vec![0u8; MAX_UDP_SIZE];
        let mut plaintext_initiation = match client.format_handshake_initiation(&mut buffer, false)
        {
            TunnResult::WriteToNetwork(datagram) => datagram.to_vec(),
            other => panic!("expected an initiation, got {:?}", other),
        };
        // Fix the S1 nonce so this negative case is deterministic: for key
        // 0x42 and nonce 00..0b, the decrypted type cannot match H1 = 1.
        for (i, byte) in plaintext_initiation[..12].iter_mut().enumerate() {
            *byte = i as u8;
        }

        assert!(
            demux_handshake(
                &server_secret,
                ObfuscationRanges::default(),
                &receiver_amnezia,
                &plaintext_initiation,
            )
            .is_none(),
            "configured Header Protection must not fall back to plaintext"
        );
    }

    /// Drive the ingress cookie path far enough to measure the request and
    /// the upstream-compatible Cookie Reply wire sizes for an S1/S3 profile.
    ///
    /// The initiation carries a valid MAC1 and no MAC2. The limiter is pushed
    /// under load because that is the only state in which `verify_packet`
    /// produces a cookie. The helper is test-only and uses fresh local keys.
    fn cookie_exchange_sizes(amnezia: &AmneziaConfig) -> (usize, usize) {
        let server_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let server_public = x25519::PublicKey::from(&server_secret);
        // Vanilla tags, matching `ObfuscationRanges::default()`: the H-ranges
        // are orthogonal to everything under test here, and the interop config
        // exercises non-default ones in
        // `obfuscated_initiation_demuxes_to_the_initiating_peer`.
        let obf = ObfuscationRanges::default();

        let mut client = Tunn::new(
            x25519::StaticSecret::random_from_rng(OsRng),
            server_public,
            None,
            None,
            1,
            None,
            1,
            1,
            2,
            2,
            3,
            3,
            4,
            4,
        )
        .unwrap();

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let raw_datagram = match client.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("expected an initiation, got {:?}", other),
        };
        // Apply the configured S1 prefix and Header Protection exactly as
        // the outbound path does, then decode it as the anonymous UDP ingress
        // path does before MAC1 validation.
        let mut wire_buffer = vec![0u8; MAX_UDP_SIZE];
        wire_buffer[..raw_datagram.len()].copy_from_slice(&raw_datagram);
        let datagram = amnezia
            .prepend_outbound(obf, &mut wire_buffer, raw_datagram.len(), &mut OsRng)
            .expect("reference S1 and Header Protection must fit")
            .to_vec();

        let limiter = RateLimiter::new(&server_public, HANDSHAKE_RATE_LIMIT);
        let stripped = if amnezia.header_protection_enabled() {
            amnezia
                .decrypt_inbound(obf, &datagram)
                .expect("our own protected initiation must match its S1/H1 shape")
        } else {
            amnezia
                .strip_inbound(obf, &datagram)
                .expect("our own initiation must match its S1/H1 shape")
                .to_vec()
        };
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let mut scratch = vec![0u8; MAX_UDP_SIZE];

        // `is_under_load` returns the counter value from *before* its own
        // increment, so the limit-th call still reads as unloaded and the one
        // after it is the first to demand a cookie. Asserting `Ok` here is not
        // decoration: if the threshold ever moves, this loop stops leaving the
        // limiter in the state the test is about, and it says so.
        for _ in 0..HANDSHAKE_RATE_LIMIT {
            limiter
                .verify_packet(obf, &mut OsRng, Some(src), &stripped, &mut scratch)
                .expect("below the handshake rate limit, no cookie is demanded");
        }
        let cookie_len =
            match limiter.verify_packet(obf, &mut OsRng, Some(src), &stripped, &mut scratch) {
                Err(TunnResult::WriteToNetwork(cookie)) => cookie.len(),
                Ok(_) => panic!("over the rate limit the limiter must demand a cookie"),
                Err(other) => panic!("expected a cookie reply, got {:?}", other),
            };

        (datagram.len(), amnezia.cookie_reply_len(cookie_len))
    }

    /// The reference S3 value is intentionally allowed to produce a Cookie Reply
    /// larger than the triggering handshake, matching upstream amneziawg-go.
    /// This pins the source-address policy to that compatibility decision.
    #[test]
    fn large_s3_cookie_replies_follow_upstream_semantics() {
        let config = AmneziaConfig::new(284, 659, 1045, 12).with_header_protection_key([0x42; 32]);
        config
            .validate()
            .expect("the reference AWG 3.1 S values must be accepted");
        let (request_len, reply_len) = cookie_exchange_sizes(&config);
        assert_eq!(request_len, 284 + HANDSHAKE_INIT_SZ);
        assert_eq!(reply_len, 1045 + COOKIE_REPLY_SZ);
        assert_eq!(
            reply_policy::cookie_verdict("203.0.113.5:40000".parse().unwrap()),
            reply_policy::CookieVerdict::Send,
            "upstream sends the S3-prefixed cookie reply even when it exceeds the request"
        );
    }

    /// A commonly used S1-S4 configuration remains eligible for Cookie Replies.
    #[test]
    fn the_interop_configuration_still_gets_its_cookie_reply() {
        let amnezia = AmneziaConfig::new(120, 130, 110, 80);
        let (request_len, reply_len) = cookie_exchange_sizes(&amnezia);

        assert_eq!(request_len, 120 + HANDSHAKE_INIT_SZ);
        assert_eq!(reply_len, 110 + COOKIE_REPLY_SZ);
        assert_eq!(
            reply_policy::cookie_verdict("203.0.113.5:40000".parse().unwrap()),
            reply_policy::CookieVerdict::Send,
            "upstream cookie replies remain WireGuard's DoS defence"
        );
    }

    /// A peer named before `private_key=` is an error the control plane can
    /// report, not a reason to abort the daemon.
    ///
    /// `awg setconf` always sends the key first, so this is malformed input --
    /// but it arrives over a socket, and a UAPI client should not be able to
    /// kill the server by reordering two lines.
    #[test]
    fn peer_before_private_key_is_an_error_not_a_panic() {
        // Calls the same `require_key_pair` that `update_peer` calls, so a
        // regression to `expect`/panic there fails here. An earlier version of
        // this test inlined the `ok_or_else` instead, which only asserted that
        // `Option::ok_or_else` works and would have passed either way.
        // `expect_err` is unavailable here: the Ok type contains `StaticSecret`,
        // which deliberately does not implement `Debug` so secrets cannot leak
        // into a panic message or a log line.
        let err = match require_key_pair(&None) {
            Err(e) => e,
            Ok(_) => panic!("no key pair must be an error"),
        };
        assert!(
            matches!(err, Error::PeerSetup(ref m) if m.contains("private key")),
            "error should name the missing private key, got {:?}",
            err
        );

        // And the configured case still yields the pair.
        let secret = x25519::StaticSecret::random_from_rng(OsRng);
        let public = x25519::PublicKey::from(&secret);
        let configured = Some((secret, public));
        match require_key_pair(&configured) {
            Ok((_, got_public)) => assert_eq!(got_public.as_bytes(), public.as_bytes()),
            Err(e) => panic!("a configured key pair must be returned, got {:?}", e),
        }
    }

    /// A device left on the vanilla defaults cannot read that datagram. This is
    /// what was silently happening before device-scoped settings existed: the
    /// daemon dropped every AmneziaWG client without a diagnostic.
    #[test]
    fn vanilla_device_cannot_demux_an_obfuscated_initiation() {
        let server_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let server_public = x25519::PublicKey::from(&server_secret);
        let client_secret = x25519::StaticSecret::random_from_rng(OsRng);

        let amnezia = AmneziaConfig::new(37, 121, 88, 64);
        let mut client = Tunn::new_with_amnezia(
            client_secret,
            server_public,
            None,
            None,
            1,
            None,
            342871004,
            442871003,
            542871004,
            642871003,
            742871004,
            842871003,
            942871004,
            1042871003,
            amnezia,
        )
        .unwrap();

        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let datagram = match client.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("expected an initiation, got {:?}", other),
        };

        let demuxed = demux_handshake(
            &server_secret,
            ObfuscationRanges::default(),
            &AmneziaConfig::default(),
            &datagram,
        );
        assert!(
            demuxed.is_none(),
            "a vanilla device must not be able to read an obfuscated initiation"
        );
    }

    /// A handshake response must demux back to the peer that initiated it.
    ///
    /// This is the contract between `Tunn` and `Device`, and nothing in the
    /// type system holds the two ends together: `Device::update_peer` keys
    /// `peers_by_idx` by the 24-bit index from `IndexLfsr`, while ingress
    /// recovers it with `peers_by_idx.get(&(receiver_idx >> 8))`. The low byte
    /// belongs to `Handshake::inc_index`, which cycles it per session, so
    /// `Tunn` has to seed the handshake with `index << 8`. Seeding it with a
    /// bare `index` shifts the peer index out from under the lookup: every
    /// response is dropped as "no peer", and an initiator can never complete a
    /// handshake at all.
    ///
    /// A `Tunn`-to-`Tunn` test cannot see this. `handle_handshake_response`
    /// matches the response against its own `local_index` directly and never
    /// consults the device index, so a full handshake between two bare `Tunn`s
    /// succeeds under either seeding -- which is how a suite of 100+ passing
    /// tests coexisted with an initiator that could not connect to anything.
    #[test]
    fn handshake_response_demuxes_back_to_the_initiating_peer() {
        // A realistic `IndexLfsr` output: 24 bits wide with a non-zero low
        // byte, so an unshifted seed cannot coincidentally survive the `>> 8`.
        const INITIATOR_IDX: u32 = 0x00B0_1B85;
        const RESPONDER_IDX: u32 = 0x00C4_2A17;

        let obf = ObfuscationRanges::default();
        let amnezia = AmneziaConfig::default();

        let initiator_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let responder_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let initiator_public = x25519::PublicKey::from(&initiator_secret);
        let responder_public = x25519::PublicKey::from(&responder_secret);

        let mut initiator = Tunn::new_with_obfuscation(
            initiator_secret,
            responder_public,
            None,
            None,
            INITIATOR_IDX,
            None,
            obf,
            amnezia.clone(),
        )
        .unwrap();
        let mut responder = Tunn::new_with_obfuscation(
            responder_secret,
            initiator_public,
            None,
            None,
            RESPONDER_IDX,
            None,
            obf,
            amnezia,
        )
        .unwrap();

        let mut init_buf = vec![0u8; MAX_UDP_SIZE];
        let initiation = match initiator.format_handshake_initiation(&mut init_buf, false) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("expected an initiation, got {:?}", other),
        };

        let mut resp_buf = vec![0u8; MAX_UDP_SIZE];
        let parsed_init = Tunn::parse_incoming_packet(obf, &initiation)
            .expect("the responder must parse the initiation");
        let response = match responder.handle_verified_packet(parsed_init, &mut resp_buf) {
            TunnResult::WriteToNetwork(d) => d.to_vec(),
            other => panic!("expected a handshake response, got {:?}", other),
        };

        let receiver_idx = match Tunn::parse_incoming_packet(obf, &response)
            .expect("the initiator must parse the response")
        {
            Packet::HandshakeResponse(p) => p.receiver_idx,
            other => panic!("expected a handshake response, got {:?}", other),
        };

        // Exactly what `register_udp_handler` does, against an index keyed
        // exactly the way `Device::update_peer` keys it.
        let peer = Arc::new(());
        let mut peers_by_idx: HashMap<u32, Arc<()>> = HashMap::new();
        peers_by_idx.insert(INITIATOR_IDX, Arc::clone(&peer));

        assert!(
            peers_by_idx.contains_key(&(receiver_idx >> 8)),
            "response echoed sender index {:#x}, which reduces to {:#x}, but the \
             device registered this peer under {:#x} -- the initiator will drop \
             every response it receives",
            receiver_idx,
            receiver_idx >> 8,
            INITIATOR_IDX,
        );
    }

    /// The same invariant stated directly, across the width of the index space.
    ///
    /// Covers the initiation as well as the response, so it also pins the
    /// responder's `peers_by_idx` lookup for cookie replies and transport data,
    /// which key off the initiator's sender index the same way.
    ///
    /// Several indices rather than one: the low byte is what a missing shift
    /// destroys, so an index whose low byte happens to be convenient could hide
    /// it. `0xFF` wraps the session counter to zero, and `0xFF_FFFF` is the
    /// widest value `IndexLfsr` can produce.
    #[test]
    fn a_tunns_wire_index_reduces_to_its_device_index() {
        for peer_idx in [1u32, 0xFF, 0x0100, 0x00B0_1B85, 0x00FF_FFFF] {
            let obf = ObfuscationRanges::default();
            let peer_public =
                x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));

            let mut tunn = Tunn::new_with_obfuscation(
                x25519::StaticSecret::random_from_rng(OsRng),
                peer_public,
                None,
                None,
                peer_idx,
                None,
                obf,
                AmneziaConfig::default(),
            )
            .unwrap();

            let mut buf = vec![0u8; MAX_UDP_SIZE];
            let initiation = match tunn.format_handshake_initiation(&mut buf, false) {
                TunnResult::WriteToNetwork(d) => d.to_vec(),
                other => panic!("expected an initiation, got {:?}", other),
            };

            match Tunn::parse_incoming_packet(obf, &initiation)
                .expect("a freshly formatted initiation must parse")
            {
                Packet::HandshakeInit(_) => {}
                other => panic!("expected an initiation, got {:?}", other),
            }

            // Bytes 4..8 are `sender_index`, little-endian, per the WireGuard
            // message layout -- the same field `parse_incoming_packet` reads.
            // Taken off the wire because `HandshakeInit::sender_idx` is private
            // to `noise`, and built byte-wise because this crate is edition
            // 2018, where `TryInto` is not in the prelude.
            let sender_idx =
                u32::from_le_bytes([initiation[4], initiation[5], initiation[6], initiation[7]]);

            assert_eq!(
                sender_idx >> 8,
                peer_idx,
                "peer index {:#x} went onto the wire as {:#x}, which reduces to \
                 {:#x} under the device's demux",
                peer_idx,
                sender_idx,
                sender_idx >> 8,
            );
        }
    }
}
