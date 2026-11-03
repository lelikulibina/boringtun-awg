// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::dev_lock::LockReadGuard;
use super::drop_privileges::get_saved_ids;
use super::{AllowedIP, Device, Error, SocketAddr};
use crate::device::Action;
use crate::noise::amnezia::AmneziaConfig;
use crate::noise::handshake::ObfuscationRanges;
use crate::noise::signature::SignatureChain;
use crate::serialization::KeyBytes;
use crate::x25519;
use hex::{decode as decode_hex, encode as encode_hex};
use libc::*;
use std::collections::HashMap;
use std::fs::{create_dir, remove_file};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::IpAddr;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const SOCK_DIR: &str = "/var/run/wireguard/";
/// Where `amneziawg-tools` looks for a userspace implementation's UAPI socket.
///
/// `wg` uses `/var/run/wireguard/`, but `awg` is a fork and searches
/// `/var/run/amneziawg/%s.sock` instead, so a socket published only under
/// `SOCK_DIR` is invisible to it -- `awg setconf` fails with "Operation not
/// supported" because it falls back to netlink and finds a TUN device that is
/// not an amneziawg interface. Since AmneziaWG support is the point of this
/// fork, publish in both places rather than choosing.
const AWG_SOCK_DIR: &str = "/var/run/amneziawg/";

/// Parse an AmneziaWG magic-header value: either a bare tag (`"1"`) or an
/// inclusive range (`"342871004-442871003"`). A bare value is a degenerate
/// range, which is exactly how the kernel module's `mh_genspec` treats it, so
/// existing single-value configs map across unchanged.
fn parse_u16_range(val: &str) -> Option<(u16, u16)> {
    let (start, end) = match val.split_once('-') {
        Some((start, end)) => (start.trim().parse().ok()?, end.trim().parse().ok()?),
        None => {
            let value: u16 = val.trim().parse().ok()?;
            (value, value)
        }
    };
    (start <= end).then_some((start, end))
}

fn parse_u32_range(val: &str) -> Option<(u32, u32)> {
    // Upstream AmneziaWG exposes all 3.x timer ranges as UintRange values
    // backed by uint16. Keep the internal timer representation u32 (Duration
    // arithmetic uses it), but reject values the reference UAPI cannot accept.
    let (start, end): (u16, u16) = match val.split_once('-') {
        Some((start, end)) => (start.trim().parse().ok()?, end.trim().parse().ok()?),
        None => {
            let value: u16 = val.trim().parse().ok()?;
            (value, value)
        }
    };
    (start <= end).then_some((u32::from(start), u32::from(end)))
}

fn parse_uapi_bool(val: &str) -> Option<bool> {
    match val {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn parse_tag_range(val: &str) -> Option<(u32, u32)> {
    let (start, end) = match val.split_once('-') {
        Some((start, end)) => (start.trim().parse().ok()?, end.trim().parse().ok()?),
        None => {
            let v: u32 = val.trim().parse().ok()?;
            (v, v)
        }
    };
    if start > end {
        return None;
    }
    // Reject 0 rather than accepting it silently. `ObfuscationRanges::new`
    // treats an all-zero range as "unset" and substitutes the vanilla WireGuard
    // message type for that packet kind, so `h1=0` would quietly disable
    // obfuscation instead of using tag 0 -- the opposite of what the operator
    // wrote. Failing the transaction with EINVAL makes that visible.
    if start == 0 {
        return None;
    }
    Some((start, end))
}

/// AmneziaWG values accumulated over one `set=1` transaction.
///
/// They cannot be applied one at a time: `ObfuscationRanges::new` validates all
/// four header ranges together and rejects overlaps, so a partially-applied set
/// could transiently fail validation on a configuration that is valid as a
/// whole. Anything left `None` keeps the device's current value.
#[derive(Default)]
struct AwgParams {
    jc: Option<u16>,
    jmin: Option<u16>,
    jmax: Option<u16>,
    s1: Option<u16>,
    s2: Option<u16>,
    s3: Option<u16>,
    s4: Option<u16>,
    h1: Option<(u32, u32)>,
    h2: Option<(u32, u32)>,
    h3: Option<(u32, u32)>,
    h4: Option<(u32, u32)>,
    disable_cookies: Option<bool>,
    random_trailers: Option<bool>,
    signature_packets: [Option<Option<SignatureChain>>; 5],
    header_protection_key: Option<[u8; 32]>,
    content_padding_addition: Option<(u16, u16)>,
    rekey_after_time: Option<(u32, u32)>,
    rekey_timeout: Option<(u32, u32)>,
    reject_after_time: Option<(u32, u32)>,
    keepalive_timeout: Option<(u32, u32)>,
    max_handshake_attempts: Option<(u32, u32)>,
    seen: bool,
}

impl AwgParams {
    fn set_size(&mut self, key: &str, val: u16) {
        match key {
            "jc" => self.jc = Some(val),
            "jmin" => self.jmin = Some(val),
            "jmax" => self.jmax = Some(val),
            "s1" => self.s1 = Some(val),
            "s2" => self.s2 = Some(val),
            "s3" => self.s3 = Some(val),
            "s4" => self.s4 = Some(val),
            _ => unreachable!("caller matched the key"),
        }
        self.seen = true;
    }

    fn set_signature_packet(&mut self, index: usize, chain: Option<SignatureChain>) {
        self.signature_packets[index] = Some(chain);
        self.seen = true;
    }

    fn set_header(&mut self, key: &str, range: (u32, u32)) {
        match key {
            "h1" => self.h1 = Some(range),
            "h2" => self.h2 = Some(range),
            "h3" => self.h3 = Some(range),
            "h4" => self.h4 = Some(range),
            _ => unreachable!("caller matched the key"),
        }
        self.seen = true;
    }

    /// Apply the accumulated values, merging with whatever the device already
    /// has. A no-op when the transaction carried no AmneziaWG keys, so plain
    /// WireGuard configurations are untouched.
    fn apply(&self, device: &mut Device) -> Result<(), i32> {
        if !self.seen {
            return Ok(());
        }
        let (obf, amnezia) = self.merged(device.config.obf, &device.config.amnezia)?;
        if device.set_obfuscation(obf, amnezia) {
            tracing::info!(message = "AmneziaWG parameters updated");
        }
        Ok(())
    }

    /// Merge this transaction over the device's current settings.
    ///
    /// Split out of [`Self::apply`] so the merge can be tested without a
    /// `Device`, which needs a TUN interface and root. The property worth
    /// testing is that protocol imitation *survives* — it has no UAPI key, so it
    /// can only arrive via `DeviceConfig` at startup, and rebuilding rather than
    /// merging here would make any `awg setconf` silently switch camouflage off.
    fn merged(
        &self,
        cur_obf: ObfuscationRanges,
        cur_amnezia: &AmneziaConfig,
    ) -> Result<(ObfuscationRanges, AmneziaConfig), i32> {
        let cur_junk = cur_amnezia.pre_handshake_junk;
        let (h1, h2, h3, h4) = (
            self.h1
                .unwrap_or((cur_obf.h1_init.start, cur_obf.h1_init.end)),
            self.h2
                .unwrap_or((cur_obf.h2_resp.start, cur_obf.h2_resp.end)),
            self.h3
                .unwrap_or((cur_obf.h3_cookie.start, cur_obf.h3_cookie.end)),
            self.h4
                .unwrap_or((cur_obf.h4_data.start, cur_obf.h4_data.end)),
        );

        let obf = ObfuscationRanges::new(h1.0, h1.1, h2.0, h2.1, h3.0, h3.1, h4.0, h4.1)
            .map_err(|_| EINVAL)?;

        // Start from the current value and overwrite only what this transaction
        // carried. Rebuilding with `AmneziaConfig::new` would discard the
        // protocol-imitation settings, which have no UAPI key of their own and
        // therefore can only arrive via `DeviceConfig` at startup -- so any
        // `set=1` mentioning an AmneziaWG key would silently turn imitation off.
        let mut amnezia = cur_amnezia.clone();
        amnezia.init_packet_junk_size = self.s1.unwrap_or(amnezia.init_packet_junk_size);
        amnezia.response_packet_junk_size = self.s2.unwrap_or(amnezia.response_packet_junk_size);
        amnezia.cookie_packet_junk_size = self.s3.unwrap_or(amnezia.cookie_packet_junk_size);
        amnezia.transport_packet_junk_size = self.s4.unwrap_or(amnezia.transport_packet_junk_size);
        amnezia.disable_cookies = self.disable_cookies.unwrap_or(amnezia.disable_cookies);
        amnezia.random_trailers = self.random_trailers.unwrap_or(amnezia.random_trailers);
        for (index, chain) in self.signature_packets.iter().enumerate() {
            if let Some(chain) = chain {
                amnezia.signature_packets[index] = chain.clone();
            }
        }
        amnezia.header_protection_key = self
            .header_protection_key
            .unwrap_or(amnezia.header_protection_key);
        amnezia.content_padding_addition = self
            .content_padding_addition
            .unwrap_or(amnezia.content_padding_addition);
        amnezia.rekey_after_time = self.rekey_after_time.unwrap_or(amnezia.rekey_after_time);
        amnezia.rekey_timeout = self.rekey_timeout.unwrap_or(amnezia.rekey_timeout);
        amnezia.reject_after_time = self.reject_after_time.unwrap_or(amnezia.reject_after_time);
        amnezia.keepalive_timeout = self.keepalive_timeout.unwrap_or(amnezia.keepalive_timeout);
        amnezia.max_handshake_attempts = self
            .max_handshake_attempts
            .unwrap_or(amnezia.max_handshake_attempts);
        let amnezia = amnezia.with_pre_handshake_junk(
            self.jc.unwrap_or(cur_junk.packet_count),
            self.jmin.unwrap_or(cur_junk.packet_size_min),
            self.jmax.unwrap_or(cur_junk.packet_size_max),
            cur_junk.packet_delay_ms,
        );

        // Reject sizes that could never emit a valid datagram, before anything
        // is committed. Without this, an oversized S value is accepted here and
        // only shows up later as a tunnel that never completes a handshake.
        if let Err(e) = amnezia.validate() {
            tracing::error!(message = "rejecting AmneziaWG parameters", error = %e);
            return Err(EINVAL);
        }

        if let Err(e) = amnezia.validate_random_trailers(obf) {
            tracing::error!(message = "rejecting AmneziaWG RandomTrailers parameters", error = %e);
            return Err(EINVAL);
        }

        Ok((obf, amnezia))
    }
}

/// The attributes of a single `[Peer]` section of a `set=1` transaction.
///
/// Grouped into one struct with a `Default` so that starting a new section is a
/// single assignment. They were previously six separate locals declared outside
/// the parse loop, of which only `allowed_ips` was reset between sections — so
/// every other attribute leaked into the next peer.
#[derive(Default)]
struct PeerSection {
    remove: bool,
    replace_ips: bool,
    endpoint: Option<SocketAddr>,
    keepalive: Option<u16>,
    preshared_key: Option<[u8; 32]>,
    allowed_ips: Vec<AllowedIP>,
    removed_allowed_ips: Vec<AllowedIP>,
    update_only: bool,
}

fn create_sock_dir(dir: &str) {
    let _ = create_dir(dir); // Create the directory if it does not exist

    if let Ok((saved_uid, saved_gid)) = get_saved_ids() {
        unsafe {
            let c_path = std::ffi::CString::new(dir).unwrap();
            // The directory is under the root user, but we want to be able to
            // delete the files there when we exit, so we need to change the owner
            chown(
                c_path.as_bytes_with_nul().as_ptr() as _,
                saved_uid,
                saved_gid,
            );
        }
    }
}

impl Device {
    /// Register the api handler for this Device. The api handler receives stream connections on a Unix socket
    /// with a known path: /var/run/wireguard/{tun_name}.sock.
    ///
    /// The same socket is also published at /var/run/amneziawg/{tun_name}.sock
    /// as a symlink, because `amneziawg-tools` searches that directory rather
    /// than the WireGuard one; without it `awg` cannot see this interface at
    /// all. There is still exactly one socket and one accept loop. If the
    /// symlink cannot be created the handler is registered anyway and a warning
    /// is logged, leaving the device reachable by `wg` but not `awg`.
    pub fn register_api_handler(&mut self) -> Result<(), Error> {
        let name = self.iface.name()?;
        let path = format!("{}/{}.sock", SOCK_DIR, name);

        create_sock_dir(SOCK_DIR);

        let _ = remove_file(&path); // Attempt to remove the socket if already exists

        let api_listener = UnixListener::bind(&path).map_err(Error::ApiSocket)?; // Bind a new socket to the path

        self.cleanup_paths.push(path.clone());

        // Also publish where `awg` looks. A symlink rather than a second
        // listener, so there is exactly one socket and one accept loop; both
        // toolchains then reach the same device. Failure is not fatal -- the
        // daemon still works, just only under `wg`.
        let awg_path = format!("{}/{}.sock", AWG_SOCK_DIR, name);
        create_sock_dir(AWG_SOCK_DIR);
        let _ = remove_file(&awg_path);
        match std::os::unix::fs::symlink(&path, &awg_path) {
            Ok(()) => self.cleanup_paths.push(awg_path),
            Err(e) => tracing::warn!(
                message = "could not publish the UAPI socket for amneziawg-tools; awg will not find this interface",
                path = awg_path.as_str(),
                error = %e
            ),
        }

        self.queue.new_event(
            api_listener.as_raw_fd(),
            Box::new(move |d, _| {
                // This is the closure that listens on the api unix socket
                let (api_conn, _) = match api_listener.accept() {
                    Ok(conn) => conn,
                    _ => return Action::Continue,
                };

                let mut reader = BufReader::new(&api_conn);
                let mut writer = BufWriter::new(&api_conn);
                loop {
                    let mut cmd = String::new();
                    match reader.read_line(&mut cmd) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    if cmd.ends_with('\n') { cmd.pop(); }
                    if cmd.ends_with('\r') { cmd.pop(); }
                    let status = match cmd.as_str() {
                        "get=1" => {
                            let mut terminator = String::new();
                            match reader.read_line(&mut terminator) {
                                Ok(n) if n > 0 && terminator == "\n" => api_get(&mut writer, d),
                                _ => EINVAL,
                            }
                        }
                        "set=1" => api_set(&mut reader, d),
                        _ => {
                            let _ = writeln!(writer, "errno={}\n", EIO);
                            let _ = writer.flush();
                            break;
                        }
                    };
                    if writeln!(writer, "errno={}\n", status).is_err() || writer.flush().is_err() {
                        break;
                    }
                }
                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        self.register_monitor(path)?;
        self.register_api_signal_handlers()
    }

    pub fn register_api_fd(&mut self, fd: i32) -> Result<(), Error> {
        let io_file = unsafe { UnixStream::from_raw_fd(fd) };

        self.queue.new_event(
            io_file.as_raw_fd(),
            Box::new(move |d, _| {
                // This is the closure that listens on the api file descriptor

                let mut reader = BufReader::new(&io_file);
                let mut writer = BufWriter::new(&io_file);
                loop {
                    let mut cmd = String::new();
                    match reader.read_line(&mut cmd) {
                        Ok(0) | Err(_) => {
                            d.trigger_exit();
                            return Action::Exit;
                        }
                        Ok(_) => {}
                    }
                    if cmd.ends_with('\n') { cmd.pop(); }
                    if cmd.ends_with('\r') { cmd.pop(); }
                    let status = match cmd.as_str() {
                        "get=1" => {
                            let mut terminator = String::new();
                            match reader.read_line(&mut terminator) {
                                Ok(n) if n > 0 && terminator == "\n" => api_get(&mut writer, d),
                                _ => EINVAL,
                            }
                        }
                        "set=1" => api_set(&mut reader, d),
                        _ => {
                            let _ = writeln!(writer, "errno={}\n", EIO);
                            let _ = writer.flush();
                            break;
                        }
                    };
                    if writeln!(writer, "errno={}\n", status).is_err() || writer.flush().is_err() {
                        break;
                    }
                }

                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        Ok(())
    }

    fn register_monitor(&self, path: String) -> Result<(), Error> {
        self.queue.new_periodic_event(
            Box::new(move |d, _| {
                // This is not a very nice hack to detect if the control socket was removed
                // and exiting nicely as a result. We check every 3 seconds in a loop if the
                // file was deleted by stating it.
                // The problem is that on linux inotify can be used quite beautifully to detect
                // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
                // will require introducing new events, for no measurable benefit.
                // TODO: Could this be an issue if we restart the service too quickly?
                let path = std::path::Path::new(&path);
                if !path.exists() {
                    d.trigger_exit();
                    return Action::Exit;
                }

                // Periodically read the mtu of the interface in case it changes
                if let Ok(mtu) = d.iface.mtu() {
                    d.mtu.store(mtu, Ordering::Relaxed);
                }

                Action::Continue
            }),
            std::time::Duration::from_millis(1000),
        )?;

        Ok(())
    }

    fn register_api_signal_handlers(&self) -> Result<(), Error> {
        self.queue
            .new_signal_event(SIGINT, Box::new(move |_, _| Action::Exit))?;

        self.queue
            .new_signal_event(SIGTERM, Box::new(move |_, _| Action::Exit))?;

        Ok(())
    }
}

#[allow(unused_must_use)]
fn api_get(writer: &mut BufWriter<&UnixStream>, d: &Device) -> i32 {
    // get command requires an empty line, but there is no reason to be religious about it
    if let Some(ref k) = d.key_pair {
        // The UAPI get operation must return the private key so showconf/setconf
        // can round-trip the interface configuration.
        writeln!(writer, "private_key={}", encode_hex(k.0.to_bytes()));
    }

    if d.listen_port != 0 {
        writeln!(writer, "listen_port={}", d.listen_port);
    }

    if let Some(fwmark) = d.fwmark {
        writeln!(writer, "fwmark={}", fwmark);
    }

    // AmneziaWG interface parameters, emitted only when they differ from plain
    // WireGuard so a vanilla device's output is byte-identical to before.
    // Sizes are `%u`; magic headers use the kernel's `mh_genspec` convention --
    // a bare value when the range is degenerate, `start-end` otherwise.
    {
        let a = &d.config.amnezia;
        if a.header_protection_enabled() {
            writeln!(
                writer,
                "header_protection_key={}",
                encode_hex(&a.header_protection_key)
            );
        }
        writeln!(writer, "disable_cookies={}", if a.disable_cookies { 1 } else { 0 });
        writeln!(writer, "random_trailers={}", if a.random_trailers { 1 } else { 0 });
        for (index, chain) in a.signature_packets.iter().enumerate() {
            if let Some(chain) = chain {
                writeln!(writer, "i{}={}", index + 1, chain.spec());
            }
        }
        let (padding_min, padding_max) = a.content_padding_addition;
        if padding_min != 0 || padding_max != 0 {
            if padding_min == padding_max {
                writeln!(writer, "content_padding_addition={}", padding_min);
            } else {
                writeln!(
                    writer,
                    "content_padding_addition={}-{}",
                    padding_min, padding_max
                );
            }
        }
        for (key, range) in [
            ("rekey_after_time", a.rekey_after_time),
            ("rekey_timeout", a.rekey_timeout),
            ("reject_after_time", a.reject_after_time),
            ("keepalive_timeout", a.keepalive_timeout),
            ("max_handshake_attempts", a.max_handshake_attempts),
        ] {
            if range != (0, 0) {
                if range.0 == range.1 {
                    writeln!(writer, "{}={}", key, range.0);
                } else {
                    writeln!(writer, "{}={}-{}", key, range.0, range.1);
                }
            }
        }

        for (key, val) in [
            ("jc", a.pre_handshake_junk.packet_count),
            ("jmin", a.pre_handshake_junk.packet_size_min),
            ("jmax", a.pre_handshake_junk.packet_size_max),
            ("s1", a.init_packet_junk_size),
            ("s2", a.response_packet_junk_size),
            ("s3", a.cookie_packet_junk_size),
            ("s4", a.transport_packet_junk_size),
        ] {
            if val != 0 {
                writeln!(writer, "{}={}", key, val);
            }
        }

        let obf = d.config.obf;
        let default = ObfuscationRanges::default();
        for (key, range, def) in [
            ("h1", obf.h1_init, default.h1_init),
            ("h2", obf.h2_resp, default.h2_resp),
            ("h3", obf.h3_cookie, default.h3_cookie),
            ("h4", obf.h4_data, default.h4_data),
        ] {
            if range != def {
                if range.start == range.end {
                    writeln!(writer, "{}={}", key, range.start);
                } else {
                    writeln!(writer, "{}={}-{}", key, range.start, range.end);
                }
            }
        }
    }

    // Walk the trie once and group by owner. `peers_by_ip` remains the only
    // place prefixes live, but `AllowedIps::iter` materialises the whole
    // index into a VecDeque, so asking it per peer would be O(peers x
    // prefixes) with a fresh allocation each time -- visible on `awg show`
    // for a server with many peers.
    let mut prefixes_by_peer: HashMap<usize, Vec<(IpAddr, u8)>> = HashMap::new();
    for (owner, addr, cidr) in d.peers_by_ip.iter() {
        prefixes_by_peer
            .entry(Arc::as_ptr(owner) as usize)
            .or_default()
            .push((addr, cidr));
    }

    for (k, peer) in d.peers.iter() {
        let p = peer.lock();
        writeln!(writer, "public_key={}", encode_hex(k.as_bytes()));

        let zero_psk = [0u8; 32];
        writeln!(
            writer,
            "preshared_key={}",
            encode_hex(p.preshared_key().unwrap_or(&zero_psk))
        );
        writeln!(writer, "protocol_version=1");

        if let Some(keepalive) = p.persistent_keepalive() {
            writeln!(writer, "persistent_keepalive_interval={}", keepalive);
        }

        if let Some(ref addr) = p.endpoint().addr {
            writeln!(writer, "endpoint={}", addr);
        }

        for (ip, cidr) in prefixes_by_peer
            .get(&(Arc::as_ptr(peer) as usize))
            .map_or(&[][..], Vec::as_slice)
        {
            writeln!(writer, "allowed_ip={}/{}", ip, cidr);
        }

        // `last_handshake_time_*` is an absolute wall-clock timestamp in the
        // UAPI, not an age -- `wg`/`awg` subtract it from the current time to
        // render "N seconds ago". Reporting the elapsed duration instead made
        // every peer read as roughly 56 years stale, so any health check or
        // management UI treating a stale handshake as "peer down" saw every
        // peer as permanently dead. Verified against the kernel module, which
        // reports the epoch timestamp here.
        if let Some(elapsed) = p.time_since_last_handshake() {
            if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let handshake_at = now.saturating_sub(elapsed);
                writeln!(writer, "last_handshake_time_sec={}", handshake_at.as_secs());
                writeln!(
                    writer,
                    "last_handshake_time_nsec={}",
                    handshake_at.subsec_nanos()
                );
            }
        } else {
            writeln!(writer, "last_handshake_time_sec=0");
            writeln!(writer, "last_handshake_time_nsec=0");
        }

        let (_, tx_bytes, rx_bytes, ..) = p.tunnel.stats();

        writeln!(writer, "rx_bytes={}", rx_bytes);
        writeln!(writer, "tx_bytes={}", tx_bytes);
    }
    0
}

fn api_set(reader: &mut BufReader<&UnixStream>, d: &mut LockReadGuard<Device>) -> i32 {
    d.try_writeable(
        |device| device.trigger_yield(),
        |device| {
            device.cancel_yield();

            let mut cmd = String::new();
            // AmneziaWG keys are validated as a set (`ObfuscationRanges::new`
            // rejects overlapping H ranges), so they are accumulated across the
            // transaction and applied at whichever exit point comes first --
            // including before delegating to a peer section, since peers
            // snapshot the device's settings when they are created.
            let mut awg = AwgParams::default();

            loop {
                cmd.clear();
                let bytes_read = match reader.read_line(&mut cmd) {
                    Ok(n) => n,
                    Err(_) => return EIO,
                };
                if bytes_read == 0 {
                    break;
                }
                if cmd.ends_with('\n') { cmd.pop(); }
                if cmd.ends_with('\r') { cmd.pop(); }
                if cmd.is_empty() {
                    match awg.apply(device) {
                        Ok(()) => return 0, // Done
                        Err(code) => return code,
                    }
                }
                {
                    // Split on the *first* `=` only. Values may legitimately
                    // contain one: `KeyBytes` accepts base64 as well as hex, and
                    // a base64-encoded 32-byte key is 44 characters ending in
                    // `=` padding, which `split('=')` would turn into three
                    // fields and reject as EPROTO.
                    let parsed_cmd: Vec<&str> = cmd.splitn(2, '=').collect();
                    if parsed_cmd.len() != 2 {
                        return EPROTO;
                    }

                    let (key, val) = (parsed_cmd[0], parsed_cmd[1]);

                    match key {
                        "private_key" => match val.parse::<KeyBytes>() {
                            Ok(key_bytes) => {
                                device.set_key(x25519::StaticSecret::from(key_bytes.0))
                            }
                            Err(_) => return EINVAL,
                        },
                        "listen_port" => match val.parse::<u16>() {
                            Ok(port) => match device.open_listen_socket(port) {
                                Ok(()) => {}
                                Err(_) => return EADDRINUSE,
                            },
                            Err(_) => return EINVAL,
                        },
                        #[cfg(any(
                            target_os = "android",
                            target_os = "fuchsia",
                            target_os = "linux"
                        ))]
                        "fwmark" => match val.parse::<u32>() {
                            Ok(mark) => match device.set_fwmark(mark) {
                                Ok(()) => {}
                                Err(_) => return EADDRINUSE,
                            },
                            Err(_) => return EINVAL,
                        },
                        "replace_peers" => {
                            if val != "true" {
                                return EINVAL;
                            }
                            device.clear_peers();
                        },
                        "public_key" => match val.parse::<KeyBytes>() {
                            // Indicates a new peer section
                            Ok(key_bytes) => {
                                // Apply before the first peer is built: peers
                                // snapshot the device's AmneziaWG settings.
                                if let Err(code) = awg.apply(device) {
                                    return code;
                                }
                                return api_set_peer(
                                    reader,
                                    device,
                                    x25519::PublicKey::from(key_bytes.0),
                                );
                            }
                            Err(_) => return EINVAL,
                        },
                        // AmneziaWG device keys. Sizes are `%u`; magic headers
                        // are `%s` and may be a bare value or a `start-end`
                        // range, matching amneziawg-tools' wire format.
                        "jc" | "jmin" | "jmax" | "s1" | "s2" | "s3" | "s4" => {
                            match val.parse::<u16>() {
                                Ok(v) => awg.set_size(key, v),
                                Err(_) => return EINVAL,
                            }
                        }
                        "h1" | "h2" | "h3" | "h4" => match parse_tag_range(val) {
                            Some(range) => awg.set_header(key, range),
                            None => return EINVAL,
                        },
                        "header_protection_key" => match decode_hex(val) {
                            Ok(bytes) if bytes.len() == 32 => {
                                let mut key = [0u8; 32];
                                key.copy_from_slice(&bytes);
                                awg.header_protection_key = Some(key);
                                awg.seen = true;
                            }
                            _ => return EINVAL,
                        },
                        "content_padding_addition" => match parse_u16_range(val) {
                            Some(range) => {
                                awg.content_padding_addition = Some(range);
                                awg.seen = true;
                            }
                            None => return EINVAL,
                        },
                        "rekey_after_time" => match parse_u32_range(val) {
                            Some(range) => {
                                awg.rekey_after_time = Some(range);
                                awg.seen = true;
                            }
                            None => return EINVAL,
                        },
                        "rekey_timeout" => match parse_u32_range(val) {
                            Some(range) => {
                                awg.rekey_timeout = Some(range);
                                awg.seen = true;
                            }
                            None => return EINVAL,
                        },
                        "reject_after_time" => match parse_u32_range(val) {
                            Some(range) => {
                                awg.reject_after_time = Some(range);
                                awg.seen = true;
                            }
                            None => return EINVAL,
                        },
                        "keepalive_timeout" => match parse_u32_range(val) {
                            Some(range) => {
                                awg.keepalive_timeout = Some(range);
                                awg.seen = true;
                            }
                            None => return EINVAL,
                        },
                        "max_handshake_attempts" => match parse_u32_range(val) {
                            Some(range) => {
                                awg.max_handshake_attempts = Some(range);
                                awg.seen = true;
                            }
                            None => return EINVAL,
                        },
                        "i1" | "i2" | "i3" | "i4" | "i5" => {
                            let index = (key.as_bytes()[1] - b'1') as usize;
                            match SignatureChain::parse(val) {
                                Ok(chain) => awg.set_signature_packet(index, chain),
                                Err(_) => return EINVAL,
                            }
                        }
                        "random_trailers" => match parse_uapi_bool(val) {
                            Some(value) => {
                                awg.random_trailers = Some(value);
                                awg.seen = true;
                            }
                            None => return EINVAL,
                        },
                        "disable_cookies" => match parse_uapi_bool(val) {
                            Some(value) => {
                                awg.disable_cookies = Some(value);
                                awg.seen = true;
                            }
                            None => return EINVAL,
                        },
                        _ => return EINVAL,
                    }
                }
                cmd.clear();
            }

            match awg.apply(device) {
                Ok(()) => 0,
                Err(code) => code,
            }
        },
    )
    .unwrap_or(EIO)
}

fn api_set_peer(
    reader: &mut BufReader<&UnixStream>,
    d: &mut Device,
    pub_key: x25519::PublicKey,
) -> i32 {
    let mut cmd = String::new();

    let mut public_key = pub_key;
    let mut sec = PeerSection::default();
    loop {
        cmd.clear();
        let bytes_read = match reader.read_line(&mut cmd) {
            Ok(n) => n,
            Err(_) => return EIO,
        };
        if bytes_read == 0 {
            break;
        }
        if cmd.ends_with('\n') { cmd.pop(); }
        if cmd.ends_with('\r') { cmd.pop(); }
        if cmd.is_empty() {
            if !(sec.update_only && !d.peers.contains_key(&public_key)) {
                if let Err(e) = d.update_peer(
                    public_key.clone(),
                    sec.remove,
                    sec.replace_ips,
                    sec.endpoint,
                    sec.allowed_ips.as_slice(),
                    sec.keepalive,
                    sec.preshared_key,
                ) {
                    tracing::error!(
                        message = "failed to apply peer",
                        peer = encode_hex(public_key.as_bytes()).as_str(),
                        error = ?e
                    );
                    return EIO;
                }
                if !sec.remove {
                    for ip in &sec.removed_allowed_ips {
                        d.remove_allowed_ip(&public_key, *ip);
                    }
                }
            }
            return 0; // Done
        }
        {
            let parsed_cmd: Vec<&str> = cmd.splitn(2, '=').collect();
            if parsed_cmd.len() != 2 {
                return EPROTO;
            }
            let (key, val) = (parsed_cmd[0], parsed_cmd[1]);
            match key {
                "remove" => {
                    if val != "true" {
                        return EINVAL;
                    }
                    sec.remove = true;
                },
                "preshared_key" => match val.parse::<KeyBytes>() {
                    Ok(key_bytes) => sec.preshared_key = Some(key_bytes.0),
                    Err(_) => return EINVAL,
                },
                "endpoint" => match val.parse::<SocketAddr>() {
                    Ok(addr) => sec.endpoint = Some(addr),
                    Err(_) => return EINVAL,
                },
                "persistent_keepalive_interval" => match val.parse::<u16>() {
                    Ok(interval) => sec.keepalive = Some(interval),
                    Err(_) => return EINVAL,
                },
                "replace_allowed_ips" => {
                    if val != "true" {
                        return EINVAL;
                    }
                    sec.replace_ips = true;
                },
                "allowed_ip" => {
                    let (remove, value) = match val.strip_prefix('-') {
                        Some(value) => (true, value),
                        None => (false, val),
                    };
                    match value.parse::<AllowedIP>() {
                        Ok(ip) if remove => sec.removed_allowed_ips.push(ip),
                        Ok(ip) => sec.allowed_ips.push(ip),
                        Err(_) => return EINVAL,
                    }
                }
                "update_only" => {
                    if val != "true" {
                        return EINVAL;
                    }
                    sec.update_only = true;
                },
                "public_key" => {
                    // Indicates a new peer section. Commit changes for current peer, and continue to next peer
                    if !(sec.update_only && !d.peers.contains_key(&public_key)) {
                        if let Err(e) = d.update_peer(
                            public_key.clone(),
                            sec.remove,
                            sec.replace_ips,
                            sec.endpoint,
                            sec.allowed_ips.as_slice(),
                            sec.keepalive,
                            sec.preshared_key,
                        ) {
                            tracing::error!(
                                message = "failed to apply peer",
                                peer = encode_hex(public_key.as_bytes()).as_str(),
                                error = ?e
                            );
                            return EIO;
                        }
                        if !sec.remove {
                            for ip in &sec.removed_allowed_ips {
                                d.remove_allowed_ip(&public_key, *ip);
                            }
                        }
                    }
                    // Each `[Peer]` block is independent, matching the kernel's
                    // nested-attribute model. Reset every attribute, not just
                    // allowed_ips: carrying `remove` would delete the next peer,
                    // and carrying `preshared_key` would overwrite its key.
                    sec = PeerSection::default();
                    match val.parse::<KeyBytes>() {
                        Ok(key_bytes) => public_key = key_bytes.0.into(),
                        Err(_) => return EINVAL,
                    }
                }
                "protocol_version" => match val.parse::<u32>() {
                    Ok(1) => {} // Only version 1 is legal
                    _ => return EINVAL,
                },
                _ => return EINVAL,
            }
        }
        cmd.clear();
    }

    // EOF terminates a set operation too, matching IpcSetOperation's Scanner
    // semantics. Do not silently drop the final peer when the client closes
    // after its last configuration line instead of sending a blank line.
    if !(sec.update_only && !d.peers.contains_key(&public_key)) {
        if let Err(e) = d.update_peer(
            public_key.clone(),
            sec.remove,
            sec.replace_ips,
            sec.endpoint,
            sec.allowed_ips.as_slice(),
            sec.keepalive,
            sec.preshared_key,
        ) {
            tracing::error!(
                message = "failed to apply peer",
                peer = encode_hex(public_key.as_bytes()).as_str(),
                error = ?e
            );
            return EIO;
        }
        if !sec.remove {
            for ip in &sec.removed_allowed_ips {
                d.remove_allowed_ip(&public_key, *ip);
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Protocol imitation survives a `set=1` that carries AmneziaWG keys.
    ///
    /// It has no UAPI key of its own — `awg showconf` drops keys it does not
    /// know, so a value set that way would not round-trip — which makes startup
    /// configuration the only way in. If `merged` rebuilt the config instead of
    /// merging over it, every `awg setconf` would silently switch camouflage off
    /// and nothing would say so.
    ///
    /// The comment at the merge site asserted this; nothing tested it. A
    /// cross-module claim in prose is exactly the thing that drifts.
    #[test]
    fn a_set_transaction_preserves_protocol_imitation() {
        use crate::noise::amnezia::{
            AmneziaImitation, AmneziaImitationBrowser, AmneziaImitationProtocol,
        };

        let current = AmneziaConfig::new(1, 1, 1, 1).with_protocol_imitation_browser(
            AmneziaImitationProtocol::Quic,
            Some("example.com".to_owned()),
            AmneziaImitationBrowser::Firefox,
        );
        let expected_imitation = AmneziaImitation::new(
            AmneziaImitationProtocol::Quic,
            Some("example.com".to_owned()),
            AmneziaImitationBrowser::Firefox,
        );

        // A transaction that touches only the S sizes, as `awg setconf` does.
        let mut params = AwgParams::default();
        params.set_size("s1", 120);
        params.set_size("s2", 130);

        let (_, merged) = params
            .merged(ObfuscationRanges::default(), &current)
            .expect("valid parameters");

        assert_eq!(
            merged.imitation, expected_imitation,
            "the S sizes were updated but imitation must be carried over intact"
        );
        assert_eq!(merged.init_packet_junk_size, 120, "s1 applied");
        assert_eq!(merged.response_packet_junk_size, 130, "s2 applied");
        // And the keys the transaction did not mention keep their old values.
        assert_eq!(merged.cookie_packet_junk_size, 1, "s3 untouched");
        assert_eq!(merged.transport_packet_junk_size, 1, "s4 untouched");
    }

    #[test]
    fn i1_i5_signature_chains_merge_roundtrip_and_clear_individually() {
        let current = AmneziaConfig::new(0, 0, 0, 0);
        let chain = SignatureChain::parse("<b 4142><r 4>").unwrap();
        let mut params = AwgParams::default();
        params.set_signature_packet(0, chain.clone());
        params.set_signature_packet(4, SignatureChain::parse("<b 4935>").unwrap());

        let (_, merged) = params
            .merged(ObfuscationRanges::default(), &current)
            .expect("valid I1/I5 chains");
        assert_eq!(merged.signature_packets[0], chain);
        assert_eq!(
            merged.signature_packets[4]
                .as_ref()
                .map(SignatureChain::spec),
            Some("<b 4935>")
        );

        // A partial update keeps the untouched chain, while an empty I1 clears
        // only that slot (the same semantics as upstream's nil obfChain).
        let mut clear = AwgParams::default();
        clear.set_signature_packet(0, SignatureChain::parse("").unwrap());
        let (_, cleared) = clear
            .merged(ObfuscationRanges::default(), &merged)
            .expect("clearing a signature chain is valid");
        assert!(cleared.signature_packets[0].is_none());
        assert!(cleared.signature_packets[4].is_some());
    }

    #[test]
    fn disable_cookies_is_merged_without_changing_the_default() {
        let current = AmneziaConfig::new(0, 0, 0, 0);
        let params = AwgParams::default();
        let (_, unchanged) = params
            .merged(ObfuscationRanges::default(), &current)
            .expect("default config remains valid");
        assert!(!unchanged.disable_cookies);

        let mut params = AwgParams::default();
        params.disable_cookies = Some(true);
        params.seen = true;
        let (_, enabled) = params
            .merged(ObfuscationRanges::default(), &current)
            .expect("valid DisableCookies setting");
        assert!(enabled.disable_cookies);

        let mut params = AwgParams::default();
        params.disable_cookies = Some(false);
        params.seen = true;
        let (_, disabled) = params
            .merged(ObfuscationRanges::default(), &enabled)
            .expect("DisableCookies can be switched off");
        assert!(!disabled.disable_cookies);
    }

    #[test]
    fn header_protection_key_is_merged_and_validated_atomically() {
        let current = AmneziaConfig::new(12, 12, 12, 12);
        let key = [0x5a; 32];
        let mut params = AwgParams::default();
        params.header_protection_key = Some(key);
        params.seen = true;

        let (_, merged) = params
            .merged(ObfuscationRanges::default(), &current)
            .expect("valid 32-byte key and four 12-byte prefixes");
        assert_eq!(merged.header_protection_key, key);
        assert!(merged.header_protection_enabled());

        // A partial update that does not mention the key preserves it.
        let params = AwgParams::default();
        let (_, unchanged) = params
            .merged(ObfuscationRanges::default(), &merged)
            .expect("existing valid HP configuration remains valid");
        assert_eq!(unchanged.header_protection_key, key);

        // An S update that makes any prefix shorter than the nonce is rejected
        // before the merged configuration can be committed.
        let mut params = AwgParams::default();
        params.set_size("s4", 11);
        assert!(
            params
                .merged(ObfuscationRanges::default(), &merged)
                .is_err(),
            "S4 shorter than 12 must be rejected while HP is enabled"
        );
    }

    #[test]
    fn parse_tag_range_accepts_bare_values_and_ranges() {
        // A bare value is a degenerate range, matching the kernel module's
        // mh_genspec, so single-value AmneziaWG configs map across unchanged.
        assert_eq!(parse_tag_range("1"), Some((1, 1)));
        assert_eq!(parse_tag_range("342871004"), Some((342871004, 342871004)));
        assert_eq!(
            parse_tag_range("342871004-442871003"),
            Some((342871004, 442871003))
        );
        assert_eq!(parse_tag_range(" 7 - 9 "), Some((7, 9)));
        assert_eq!(
            parse_tag_range(&u32::MAX.to_string()),
            Some((u32::MAX, u32::MAX))
        );
    }

    #[test]
    fn uapi_line_split_keeps_padding_in_base64_values() {
        // A base64-encoded 32-byte key is 44 chars ending in `=` padding.
        // Splitting on every `=` yields three fields and is rejected as EPROTO,
        // even though KeyBytes documents base64 as an accepted form.
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let line = format!("private_key={}", key);

        let parts: Vec<&str> = line.splitn(2, '=').collect();
        assert_eq!(parts.len(), 2, "must split into exactly key and value");
        assert_eq!(parts[0], "private_key");
        assert_eq!(parts[1], key, "padding must survive intact");
        assert!(
            parts[1].parse::<KeyBytes>().is_ok(),
            "value must still parse"
        );

        // A line with no separator is still rejected.
        assert_eq!("no_separator".splitn(2, '=').count(), 1);
    }

    #[test]
    fn parse_tag_range_rejects_malformed_input() {
        assert_eq!(parse_tag_range(""), None);
        assert_eq!(parse_tag_range("abc"), None);
        assert_eq!(parse_tag_range("9-7"), None, "inverted range");
        assert_eq!(parse_tag_range("1-"), None);
        assert_eq!(parse_tag_range("-1"), None);
        assert_eq!(parse_tag_range("4294967296"), None, "overflows u32");
        assert_eq!(parse_tag_range("1-2-3"), None);
    }

    #[test]
    fn parse_tag_range_rejects_zero_rather_than_silently_disabling() {
        // ObfuscationRanges::new treats an all-zero range as "unset" and
        // substitutes the vanilla WireGuard message type. Accepting h1=0 would
        // therefore turn obfuscation *off* for that packet kind while reporting
        // success -- the opposite of what the operator asked for.
        assert_eq!(parse_tag_range("0"), None);
        assert_eq!(parse_tag_range("0-0"), None);
        assert_eq!(parse_tag_range("0-5"), None);
        // Non-zero starts are unaffected.
        assert_eq!(parse_tag_range("1"), Some((1, 1)));
        assert_eq!(parse_tag_range("1-5"), Some((1, 5)));
    }
    #[test]
    fn randomized_timer_ranges_are_parsed_merged_and_validated() {
        assert_eq!(parse_u32_range("12"), Some((12, 12)));
        assert_eq!(parse_u32_range("5-9"), Some((5, 9)));
        assert_eq!(parse_u32_range("9-5"), None);
        assert_eq!(parse_u32_range("65535"), Some((65535, 65535)));
        assert_eq!(parse_u32_range("65535-65535"), Some((65535, 65535)));
        assert_eq!(
            parse_u32_range("65536"),
            None,
            "upstream timer ranges are uint16"
        );
        assert_eq!(parse_u32_range("4294967296"), None);

        let current = AmneziaConfig::new(0, 0, 0, 0);
        let mut params = AwgParams::default();
        params.rekey_after_time = parse_u32_range("100-140");
        params.rekey_timeout = parse_u32_range("3-7");
        params.reject_after_time = parse_u32_range("150-190");
        params.keepalive_timeout = parse_u32_range("8-12");
        params.max_handshake_attempts = parse_u32_range("10-20");
        params.random_trailers = Some(true);
        params.seen = true;
        let (_, merged) = params
            .merged(ObfuscationRanges::default(), &current)
            .expect("valid timer ranges");
        assert_eq!(merged.rekey_after_time, (100, 140));
        assert_eq!(merged.rekey_timeout, (3, 7));
        assert_eq!(merged.reject_after_time, (150, 190));
        assert_eq!(merged.keepalive_timeout, (8, 12));
        assert_eq!(merged.max_handshake_attempts, (10, 20));
        assert!(merged.random_trailers);

        let mut invalid = AwgParams::default();
        invalid.rekey_timeout = Some((9, 3));
        invalid.seen = true;
        assert!(invalid
            .merged(ObfuscationRanges::default(), &current)
            .is_err());
    }

    #[test]
    fn combined_awg31_uapi_update_merges_all_extensions_atomically() {
        let current = AmneziaConfig::new(12, 12, 12, 12);
        let mut params = AwgParams::default();
        params.set_header("h1", (100_000, 100_010));
        params.set_header("h2", (200_000, 200_000));
        params.set_header("h3", (300_000, 300_000));
        params.set_header("h4", (400_000, 400_000));
        params.disable_cookies = Some(true);
        params.random_trailers = Some(true);
        params.header_protection_key = Some([0x5a; 32]);
        params.content_padding_addition = Some((8, 32));
        params.rekey_after_time = Some((100, 140));
        params.rekey_timeout = Some((3, 7));
        params.reject_after_time = Some((150, 190));
        params.keepalive_timeout = Some((8, 12));
        params.max_handshake_attempts = Some((5, 9));
        params.seen = true;

        let (obf, merged) = params
            .merged(ObfuscationRanges::default(), &current)
            .expect("all AWG 3.1 values should validate as one transaction");

        assert!(obf.matches_h1(100_010));
        assert!(obf.matches_h2(200_000));
        assert!(obf.matches_h3(300_000));
        assert!(obf.matches_h4(400_000));
        assert!(merged.disable_cookies);
        assert!(merged.random_trailers);
        assert_eq!(merged.header_protection_key, [0x5a; 32]);
        assert_eq!(merged.content_padding_addition, (8, 32));
        assert_eq!(merged.rekey_after_time, (100, 140));
        assert_eq!(merged.rekey_timeout, (3, 7));
        assert_eq!(merged.reject_after_time, (150, 190));
        assert_eq!(merged.keepalive_timeout, (8, 12));
        assert_eq!(merged.max_handshake_attempts, (5, 9));

        // A later partial update changes only its named field.
        let mut partial = AwgParams::default();
        partial.keepalive_timeout = Some((20, 20));
        partial.seen = true;
        let (unchanged_obf, partial_merged) = partial
            .merged(obf, &merged)
            .expect("partial UAPI updates preserve the valid AWG 3.1 state");
        assert_eq!(unchanged_obf, obf);
        assert_eq!(partial_merged.keepalive_timeout, (20, 20));
        assert!(partial_merged.disable_cookies);
        assert!(partial_merged.random_trailers);
        assert_eq!(partial_merged.header_protection_key, [0x5a; 32]);
        assert_eq!(partial_merged.content_padding_addition, (8, 32));
        assert_eq!(partial_merged.rekey_after_time, (100, 140));
        assert_eq!(partial_merged.rekey_timeout, (3, 7));
        assert_eq!(partial_merged.reject_after_time, (150, 190));
    }

    #[test]
    fn content_padding_addition_range_is_parsed_and_merged() {
        assert_eq!(parse_u16_range("24"), Some((24, 24)));
        assert_eq!(parse_u16_range("0-64"), Some((0, 64)));
        assert_eq!(parse_u16_range("65-64"), None);
        assert_eq!(parse_u16_range("-1"), None);

        let current = AmneziaConfig::new(0, 0, 0, 0);
        let mut params = AwgParams::default();
        params.content_padding_addition = parse_u16_range("8-32");
        params.seen = true;
        let (_, merged) = params
            .merged(ObfuscationRanges::default(), &current)
            .expect("valid ContentPaddingAddition range");
        assert_eq!(merged.content_padding_addition, (8, 32));

        let mut invalid = AwgParams::default();
        invalid.content_padding_addition = Some((32, 8));
        invalid.seen = true;
        assert!(invalid
            .merged(ObfuscationRanges::default(), &current)
            .is_err());
    }
}
