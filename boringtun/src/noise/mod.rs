// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod amnezia;
pub mod errors;
pub mod handshake;
// `pub(crate)` rather than private: `device::probe_reply` builds the replies
// from the same modules that generate the outbound cover traffic, which is the
// whole point -- a classifier and a responder that share a parser cannot drift
// apart. Still crate-private, so none of it is public API.
pub(crate) mod imitation;
pub mod rate_limiter;
pub(crate) mod signature;

// QUIC Initial imitation generator (always compiled; pulls in `aes`).
pub(crate) mod quic;
mod session;
mod timers;

use amnezia::AmneziaConfig;
use handshake::ObfuscationRanges;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};
use crate::x25519;

use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;
#[cfg(feature = "mock-instant")]
use mock_instant::Instant;

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT
const N_SESSIONS: usize = 8;

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    /// The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    sessions: [Option<session::Session>; N_SESSIONS],
    /// Index of most recently used session
    current: usize,
    /// Queue to store blocked packets
    packet_queue: VecDeque<Vec<u8>>,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    amnezia: AmneziaConfig,
    /// Largest authenticated transport datagram observed for this peer.
    udp_window: usize,
    pending_amnezia_junk: Option<PendingAmneziaJunk>,
    rate_limiter: Arc<RateLimiter>,
}

struct PendingAmneziaJunk {
    /// Pre-generated standalone imitation datagrams (DNS/SIP/STUN sequence or
    /// browser QUIC Initials), each with the delay to wait before emitting it.
    /// Emitted one per call before any random/protocol junk and the handshake
    /// initiation; these use protocol-natural timing, not the Jd delay.
    signature_datagrams: VecDeque<Vec<u8>>,
    imitation_datagrams: VecDeque<(Duration, Vec<u8>)>,
    remaining: u16,
    last_packet_at: Option<Instant>,
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

/// The wire sizes above, re-exported for the ingress tests in `device`.
///
/// `device::reply_policy` decides whether a cookie reply is larger than the
/// packet that provoked it. The decision itself takes both lengths as
/// arguments, so production needs none of these constants — but its tests do,
/// and asserting against remembered numbers instead would leave a change to
/// either packet size to be discovered in the field.
///
/// Gated rather than three `pub(crate)` constants, for the reason
/// [`amnezia::conforming_initiation`] gives for living in `noise` at all:
/// widening a protocol constant crate-wide and permanently, to serve a test,
/// is a larger change than the test is worth. The `device` half of the gate
/// matters too — without it these are dead code in every build of the crate
/// that leaves the feature off.
#[cfg(all(test, feature = "device"))]
pub(crate) mod packet_sizes {
    pub(crate) const HANDSHAKE_INIT_SZ: usize = super::HANDSHAKE_INIT_SZ;
    pub(crate) const HANDSHAKE_RESP_SZ: usize = super::HANDSHAKE_RESP_SZ;
    pub(crate) const COOKIE_REPLY_SZ: usize = super::COOKIE_REPLY_SZ;
}

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
}

impl Tunn {
    #[inline(always)]
    pub fn parse_incoming_packet(
        obf: ObfuscationRanges,
        src: &[u8],
    ) -> Result<Packet<'_>, WireGuardError> {
        if src.len() < 4 {
            return Err(WireGuardError::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

        Ok(match (packet_type, src.len()) {
            (v, HANDSHAKE_INIT_SZ) if obf.matches_h1(v) => Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                    .expect("length already checked above"),
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
            }),
            (v, HANDSHAKE_RESP_SZ) if obf.matches_h2(v) => {
                Packet::HandshakeResponse(HandshakeResponse {
                    sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                    receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                    unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                        .expect("length already checked above"),
                    encrypted_nothing: &src[44..60],
                })
            }
            (v, COOKIE_REPLY_SZ) if obf.matches_h3(v) => {
                Packet::PacketCookieReply(PacketCookieReply {
                    receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                    nonce: &src[8..32],
                    encrypted_cookie: &src[32..64],
                })
            }
            (v, DATA_OVERHEAD_SZ..=std::usize::MAX) if obf.matches_h4(v) => {
                Packet::PacketData(PacketData {
                    receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                    counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                    encrypted_encapsulated_packet: &src[16..],
                })
            }
            _ => return Err(WireGuardError::InvalidPacket),
        })
    }

    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            _ => None,
        }
    }

    /// Create a new tunnel using own private key and the peer public key
    // The eight trailing `u32`s are the H1-H4 tag ranges, spelled out rather
    // than passed as the `ObfuscationRanges` they build. In-tree this is only
    // reached from tests -- `device` and the C bindings both go to
    // `new_with_amnezia` -- but it is a `pub` constructor of a library crate,
    // so narrowing it breaks consumers outside this repository. That belongs in
    // an API change, not a lint fix.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
        h1_init_start: u32,
        h1_init_end: u32,
        h2_resp_start: u32,
        h2_resp_end: u32,
        h3_cookie_start: u32,
        h3_cookie_end: u32,
        h4_data_start: u32,
        h4_data_end: u32,
    ) -> Result<Self, String> {
        Self::new_with_amnezia(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index,
            rate_limiter,
            h1_init_start,
            h1_init_end,
            h2_resp_start,
            h2_resp_end,
            h3_cookie_start,
            h3_cookie_end,
            h4_data_start,
            h4_data_end,
            AmneziaConfig::default(),
        )
    }

    /// Create a new tunnel with Amnezia S1-S4 junk prefix handling.
    // As `new` above, plus the `AmneziaConfig`. This is the one the C bindings
    // actually reach (`ffi::new_tunnel_with_amnezia_config`), and a C caller
    // cannot hand over an `ObfuscationRanges`, so the eight scalars have to
    // survive at least as far as this frame.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_amnezia(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
        h1_init_start: u32,
        h1_init_end: u32,
        h2_resp_start: u32,
        h2_resp_end: u32,
        h3_cookie_start: u32,
        h3_cookie_end: u32,
        h4_data_start: u32,
        h4_data_end: u32,
        amnezia: AmneziaConfig,
    ) -> Result<Self, String> {
        let obf = ObfuscationRanges::new(
            h1_init_start,
            h1_init_end,
            h2_resp_start,
            h2_resp_end,
            h3_cookie_start,
            h3_cookie_end,
            h4_data_start,
            h4_data_end,
        )?;

        Self::new_with_obfuscation(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index,
            rate_limiter,
            obf,
            amnezia,
        )
    }

    /// As [`Self::new_with_amnezia`], but taking obfuscation ranges that have
    /// already been validated.
    ///
    /// Callers holding an [`ObfuscationRanges`] should prefer this: the raw
    /// eight-integer form has to re-run `ObfuscationRanges::new`, which can
    /// only fail on input the caller has by definition already rejected, so the
    /// error it returns is unreachable and tempts callers into `expect`.
    ///
    /// The remaining failure is real but rare: seeding the per-tunnel RNG from
    /// OS entropy.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_obfuscation(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
        obf: ObfuscationRanges,
        amnezia: AmneziaConfig,
    ) -> Result<Self, String> {
        amnezia.validate()?;
        amnezia.validate_random_trailers(obf)?;
        let static_public = x25519::PublicKey::from(&static_private);
        let timers = Timers::new(persistent_keepalive, rate_limiter.is_none(), &amnezia);

        Ok(Tunn {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                // `index << 8`, not `index`: the low byte is the cyclic session
                // counter `Handshake::inc_index` advances, so the device's peer
                // index has to sit in the top 24 bits. `Device` demuxes every
                // inbound response, cookie and data packet with
                // `peers_by_idx.get(&(receiver_idx >> 8))`, and that only finds
                // the peer if the index on the wire was seeded shifted.
                index << 8,
                preshared_key,
                obf,
            )?,
            sessions: Default::default(),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),
            amnezia,
            udp_window: amnezia::DEFAULT_UDP_WINDOW,
            pending_amnezia_junk: None,

            packet_queue: VecDeque::new(),
            timers,

            rate_limiter: rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
            }),
        })
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) {
        self.timers.should_reset_rr = rate_limiter.is_none();
        self.rate_limiter = rate_limiter.unwrap_or_else(|| {
            Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
        });
        self.handshake
            .set_static_private(static_private, static_public);
        for s in &mut self.sessions {
            *s = None;
        }
        self.pending_amnezia_junk = None;
    }

    /// Replace this tunnel's AmneziaWG obfuscation settings.
    ///
    /// H1-H4 and S1-S4 are interface-wide in AmneziaWG, so when the device's
    /// settings change every peer must follow: a peer left on the old values
    /// tags and pads its packets differently from the interface that has to
    /// parse them, and the tunnel dies silently and permanently.
    ///
    /// Live sessions are kept. Obfuscation is a framing concern, not a
    /// cryptographic one — the keys and the Noise state are untouched, so
    /// forcing a re-handshake would drop traffic for no benefit. Any queued
    /// pre-handshake junk is dropped, since it was generated under the previous
    /// configuration.
    pub fn set_obfuscation(&mut self, obf: ObfuscationRanges, amnezia: AmneziaConfig) {
        if let Err(error) = self.try_set_obfuscation(obf, amnezia) {
            tracing::error!(message = "rejecting invalid AmneziaWG tunnel configuration", error = %error);
        }
    }

    /// Fallible variant of the runtime obfuscation update.
    ///
    /// Validate all framing and timer constraints before changing the live
    /// tunnel. On failure the previous configuration remains active.
    pub fn try_set_obfuscation(
        &mut self,
        obf: ObfuscationRanges,
        amnezia: AmneziaConfig,
    ) -> Result<(), String> {
        amnezia.validate()?;
        amnezia.validate_random_trailers(obf)?;

        self.handshake.set_obfuscation(obf);
        self.timers.set_timer_ranges(&amnezia);
        self.amnezia = amnezia;
        self.pending_amnezia_junk = None;
        Ok(())
    }

    /// Update the persistent-keepalive interval.
    ///
    /// Purely a timer change, so live sessions are kept: the peer's keys are
    /// unaffected and re-handshaking would be gratuitous.
    pub fn set_persistent_keepalive(&mut self, keepalive: Option<u16>) {
        self.timers.set_persistent_keepalive(keepalive);
    }

    /// Set an inclusive persistent-keepalive interval range in seconds.
    /// None or (0, 0) disables persistent keepalive.
    pub fn set_persistent_keepalive_range(&mut self, range: Option<(u32, u32)>) {
        self.timers
            .set_persistent_keepalive_range(range.unwrap_or((0, 0)));
    }

    /// Reset the peer's learned UDP datagram window after endpoint roaming.
    pub(crate) fn reset_udp_window(&mut self) {
        self.udp_window = amnezia::DEFAULT_UDP_WINDOW;
    }

    /// The peer's optional pre-shared key.
    pub fn preshared_key(&self) -> Option<[u8; 32]> {
        self.handshake.preshared_key()
    }

    /// Replace the peer's optional pre-shared key.
    ///
    /// Unlike the keepalive, this **discards every established session**. The
    /// pre-shared key is mixed into the handshake, so sessions derived under the
    /// old value are cryptographically stale; keeping them would leave the peer
    /// authenticated by a key the operator has just revoked. This mirrors what
    /// [`Self::set_static_private`] does for the static key.
    ///
    /// No-op when the key is unchanged, so a configuration reload that re-sends
    /// the same value does not tear down live tunnels.
    pub fn set_preshared_key(&mut self, preshared_key: Option<[u8; 32]>) {
        // Compare the *effective* key, not the `Option`. The handshake mixes
        // `preshared_key.unwrap_or([0u8; 32])`, so `None` and `Some([0; 32])`
        // are the same key cryptographically -- and wg's tooling clears a PSK
        // by sending 32 zero bytes rather than omitting the field, so a plain
        // `Option` comparison would treat a routine reload as a key change and
        // tear down every session for a peer that never had a PSK.
        let effective = |key: Option<[u8; 32]>| key.unwrap_or([0u8; 32]);
        let unchanged = effective(self.handshake.preshared_key()) == effective(preshared_key);

        // Always store the caller's value, even when it is cryptographically
        // equivalent. `Peer` keeps its own copy for `get=1`, and skipping the
        // write here would let the two disagree -- the handshake holding
        // `Some([0; 32])` while the peer reports `None`, or the reverse.
        self.handshake.set_preshared_key(preshared_key);

        // Only the teardown is conditional: sessions derived from an equivalent
        // key are still valid, so discarding them would drop live traffic for
        // no gain.
        if unchanged {
            return;
        }
        for s in &mut self.sessions {
            *s = None;
        }
        self.pending_amnezia_junk = None;
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// # Panics
    /// Panics if dst is too small for the base WireGuard packet formatter.
    /// Without Amnezia padding, dst should be at least src.len() + 32, and no
    /// less than 148 bytes. With Amnezia enabled, callers must also allow for
    /// the configured S-prefix on the emitted packet type; when no session is
    /// established, the first output can instead be a standalone pre-handshake
    /// junk packet up to 1280 bytes. If dst fits the base WireGuard packet but
    /// not the configured Amnezia output, this returns
    /// TunnResult::Err(WireGuardError::DestinationBufferTooSmall).
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let current = self.current;
        if let Some(ref session) = self.sessions[current % N_SESSIONS] {
            // ContentPaddingAddition and RandomTrailers are applied to the
            // plaintext IP packet before AEAD encryption. Their combined size
            // is bounded by the peer's learned UDP window; empty keepalives
            // remain empty and retain their ordinary wire size.
            let wire_packet_size =
                src.len() + DATA_OVERHEAD_SZ + self.amnezia.transport_packet_junk_size as usize;
            let content_padding = self.amnezia.transport_padding_size(
                src.len(),
                wire_packet_size,
                self.udp_window,
                &mut self.handshake.rng,
            );
            if dst.len() < src.len() + content_padding + DATA_OVERHEAD_SZ {
                return TunnResult::Err(WireGuardError::DestinationBufferTooSmall);
            }
            // Send the packet using an established session
            let packet = session.format_packet_data(
                self.handshake.obf,
                &mut self.handshake.rng,
                src,
                content_padding,
                dst,
            );
            let packet_size = packet.len();
            self.timer_tick(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if !src.is_empty() {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes += src.len();
            return self.write_to_network(dst, packet_size);
        }

        // If there is no session, queue the packet for future retry
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.format_handshake_initiation(dst, false)
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            // Indicates a repeated call
            return self.send_queued_packet(dst);
        }

        let request_datagram_size = datagram.len();

        // Header-protected datagrams must be decrypted far enough to recover
        // their type and receiver index before the regular WireGuard parser
        // and rate limiter can inspect them. Without a key, retain the
        // allocation-free legacy S/H parsing path byte-for-byte.
        let decoded_datagram = self.amnezia.decrypt_inbound(self.handshake.obf, datagram);
        let datagram = match decoded_datagram.as_deref() {
            Some(decoded) => decoded,
            None if !self.amnezia.header_protection_enabled() => {
                match self.amnezia.strip_inbound(self.handshake.obf, datagram) {
                    Some(d) => d,
                    None => return TunnResult::Err(WireGuardError::InvalidPacket),
                }
            }
            None => return TunnResult::Err(WireGuardError::InvalidPacket),
        };
        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self.rate_limiter.verify_packet_with_cookie_policy(
            self.handshake.obf,
            &mut self.handshake.rng,
            src_addr,
            datagram,
            &mut cookie,
            self.amnezia.disable_cookies,
        ) {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                let packet_size = cookie.len();
                dst[..packet_size].copy_from_slice(cookie);
                return self.write_to_network_bounded(dst, packet_size, request_datagram_size);
            }
            Err(TunnResult::Err(e)) => return TunnResult::Err(e),
            _ => unreachable!(),
        };

        self.handle_verified_packet_with_datagram_size(packet, dst, request_datagram_size)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        self.handle_verified_packet_with_datagram_size(packet, dst, 0)
    }

    pub(crate) fn handle_verified_packet_with_datagram_size<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
        datagram_size: usize,
    ) -> TunnResult<'a> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, dst),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p),
            Packet::PacketData(p) => self.handle_data(p, dst, datagram_size),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn handle_handshake_init<'a>(
        &mut self,
        p: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_initiation",
            remote_idx = p.sender_idx
        );

        let (packet, session) = self.handshake.receive_handshake_initialization(p, dst)?;
        let packet_size = packet.len();

        // Store new session in ring buffer
        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index); // New session established, we are not the initiator

        tracing::debug!(message = "Sending handshake_response", local_idx = index);

        Ok(self.write_to_network(dst, packet_size))
    }

    fn handle_handshake_response<'a>(
        &mut self,
        p: HandshakeResponse,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        let session = self.handshake.receive_handshake_response(p)?;

        let keepalive_packet =
            session.format_packet_data(self.handshake.obf, &mut self.handshake.rng, &[], 0, dst);
        let keepalive_packet_size = keepalive_packet.len();
        // Store new session in ring buffer
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index); // New session established, we are the initiator
        self.set_current_session(l_idx);

        tracing::debug!("Sending keepalive");

        Ok(self.write_to_network(dst, keepalive_packet_size)) // Send a keepalive as a response
    }

    fn handle_cookie_reply<'a>(
        &mut self,
        p: PacketCookieReply,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received cookie_reply",
            local_idx = p.receiver_idx
        );

        self.handshake.receive_cookie_reply(p)?;
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeCookieReceived);

        tracing::debug!("Did set cookie");

        Ok(TunnResult::Done)
    }

    /// Update the index of the currently used session, if needed
    fn set_current_session(&mut self, new_idx: usize) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[cur_idx % N_SESSIONS].is_none()
            || self.timers.session_timers[new_idx % N_SESSIONS]
                >= self.timers.session_timers[cur_idx % N_SESSIONS]
        {
            self.current = new_idx;
            tracing::debug!(message = "New session", session = new_idx);
        }
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(
        &mut self,
        packet: PacketData,
        dst: &'a mut [u8],
        datagram_size: usize,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let r_idx = packet.receiver_idx as usize;
        let idx = r_idx % N_SESSIONS;

        // Get the (probably) right session
        let decapsulated_packet = {
            let session = self.sessions[idx].as_ref();
            let session = session.ok_or_else(|| {
                tracing::trace!(message = "No current session available", remote_idx = r_idx);
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        // Match upstream's per-peer UDP window: learn only from authenticated
        // transport datagrams, including their S4 prefix and any outer trailer.
        if datagram_size > 0 {
            self.udp_window = self.udp_window.max(datagram_size);
        }

        self.set_current_session(r_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        // Upstream checks receive-side key freshness for every authenticated
        // transport packet, including an empty keepalive.
        self.timer_check_key_fresh_receiving();

        Ok(self.validate_decapsulated_packet(decapsulated_packet))
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        if self.pending_amnezia_junk.is_some() {
            return self.advance_amnezia_junk(dst);
        }

        if self.handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        if self.handshake.is_expired() {
            self.timers.clear();
        }

        if self.amnezia.emits_pre_handshake() {
            let signature_datagrams = self
                .amnezia
                .pre_handshake_signature_datagrams(&mut self.handshake.rng);
            let imitation_datagrams = self
                .amnezia
                .pre_handshake_imitation_datagrams(&mut self.handshake.rng);
            // Like wgbooster (execute_imitation_obfuscation then
            // send_random_packets then the handshake), the imitation sequence and
            // the Jc random/protocol-shaped junk are both emitted: the sequence
            // first, then `packet_count` junk packets, then the initiation.
            self.pending_amnezia_junk = Some(PendingAmneziaJunk {
                signature_datagrams,
                imitation_datagrams,
                remaining: self.amnezia.pre_handshake_junk.packet_count,
                last_packet_at: None,
            });
            return self.advance_amnezia_junk(dst);
        }

        self.format_handshake_initiation_now(dst, force_resend)
    }

    fn format_handshake_initiation_now<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        if self.handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        let starting_new_handshake = !self.handshake.is_in_progress();

        match self.handshake.format_handshake_initiation(dst) {
            Ok(packet) => {
                let packet_size = packet.len();
                tracing::debug!("Sending handshake_initiation");

                if starting_new_handshake {
                    self.timer_tick(TimerName::TimeLastHandshakeStarted);
                }
                self.timer_tick(TimerName::TimeLastPacketSent);
                self.write_to_network(dst, packet_size)
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    fn advance_amnezia_junk<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let Some(pending) = self.pending_amnezia_junk.as_ref() else {
            return TunnResult::Done;
        };

        // The next imitation datagram carries its own protocol-natural delay;
        // random/protocol junk uses the configured Jd delay.
        let has_signature_datagram = !pending.signature_datagrams.is_empty();
        let next_datagram_delay = pending.imitation_datagrams.front().map(|(d, _)| *d);
        let delay = if has_signature_datagram {
            Duration::ZERO
        } else {
            next_datagram_delay.unwrap_or_else(|| self.amnezia.pre_handshake_junk.delay())
        };
        let delay_elapsed = pending
            .last_packet_at
            .map(|last| last.elapsed() >= delay)
            .unwrap_or(true);
        let has_queued_datagram = next_datagram_delay.is_some();
        let remaining = pending.remaining;
        // `pending` (immutable borrow) ends here; the rest reborrows as needed.

        if !delay_elapsed {
            return TunnResult::Done;
        }

        // I1-I5 signature chains are sent first, in slot order, without
        // pacing. Upstream batches them before imitation/Jc cover traffic.
        if has_signature_datagram {
            let pending = self
                .pending_amnezia_junk
                .as_mut()
                .expect("pending checked above");
            let size = pending
                .signature_datagrams
                .front()
                .expect("queue checked non-empty above")
                .len();
            if dst.len() < size {
                return TunnResult::Err(WireGuardError::DestinationBufferTooSmall);
            }
            let datagram = pending.signature_datagrams.pop_front().unwrap();
            dst[..size].copy_from_slice(&datagram);
            return TunnResult::WriteToNetwork(&mut dst[..size]);
        }

        // Emit any pre-generated standalone imitation datagrams (DNS/SIP/STUN or
        // browser QUIC Initials) first, one per call.
        if has_queued_datagram {
            let pending = self
                .pending_amnezia_junk
                .as_mut()
                .expect("pending checked above");
            // Check capacity before dequeuing so a too-small buffer can be
            // retried without losing the datagram.
            let size = pending
                .imitation_datagrams
                .front()
                .expect("queue checked non-empty above")
                .1
                .len();
            if dst.len() < size {
                return TunnResult::Err(WireGuardError::DestinationBufferTooSmall);
            }
            let (_, datagram) = pending.imitation_datagrams.pop_front().unwrap();
            // wgbooster uses a delay-AFTER model: the imitation sequence has no
            // trailing sleep, and send_random_packets() emits its first packet
            // immediately. So once the imitation queue is drained, clear
            // last_packet_at to make the first Jc junk packet (or the handshake,
            // when Jc=0) due immediately rather than waiting one extra Jd. While
            // datagrams remain, time the next one's delay from now.
            pending.last_packet_at = if pending.imitation_datagrams.is_empty() {
                None
            } else {
                Some(Instant::now())
            };
            dst[..size].copy_from_slice(&datagram);
            return TunnResult::WriteToNetwork(&mut dst[..size]);
        }

        if remaining == 0 {
            // The initiation was deliberately deferred behind the junk packets, so
            // it must be emitted now: force the (re)format. A previous attempt may
            // have already moved the handshake into `InitSent` before
            // `write_to_network` failed on an oversized prefix, and a non-forced
            // retry would otherwise hit the `is_in_progress()` guard, return `Done`,
            // and silently drop the initiation. Clear the pending state only once
            // the initiation packet is actually written to the network, so a retry
            // with a larger buffer resends only the initiation, never the junk.
            let result = self.format_handshake_initiation_now(dst, true);
            if matches!(result, TunnResult::WriteToNetwork(_)) {
                self.pending_amnezia_junk = None;
            }
            return result;
        }

        let packet = match self
            .amnezia
            .fill_pre_handshake_junk(dst, &mut self.handshake.rng)
        {
            Ok(packet) => packet,
            Err(e) => return TunnResult::Err(e),
        };

        if let Some(pending) = &mut self.pending_amnezia_junk {
            pending.remaining -= 1;
            pending.last_packet_at = Some(Instant::now());
        }

        TunnResult::WriteToNetwork(packet)
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> TunnResult<'a> {
        let (computed_len, src_ip_address) = match packet.len() {
            0 => return TunnResult::Done, // This is keepalive, and not an error
            _ if packet[0] == 0 => {
                // AWG ContentPaddingAddition and RandomTrailers can turn an
                // empty keepalive into an authenticated all-zero plaintext.
                // Upstream treats zero-prefixed transport plaintext as a
                // keepalive rather than attempting to parse it as an IP packet.
                return TunnResult::Done;
            }
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize,
                    IpAddr::from(addr_bytes),
                )
            }
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(addr_bytes),
                )
            }
            _ => return TunnResult::Err(WireGuardError::InvalidPacket),
        };

        if computed_len > packet.len() {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived);
        self.rx_bytes += computed_len;

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToTunnelV4(&mut packet[..computed_len], addr),
            IpAddr::V6(addr) => TunnResult::WriteToTunnelV6(&mut packet[..computed_len], addr),
        }
    }

    /// Get a packet from the queue, and try to encapsulate it
    fn send_queued_packet<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.encapsulate(&packet, dst) {
                TunnResult::Err(_) => {
                    // On error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r => return r,
            }
        }
        TunnResult::Done
    }

    /// Push packet to the back of the queue
    fn queue_packet(&mut self, packet: &[u8]) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet.to_vec());
        }
    }

    /// Push packet to the front of the queue
    fn requeue_packet(&mut self, packet: Vec<u8>) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_front(packet);
        }
    }

    fn dequeue_packet(&mut self) -> Option<Vec<u8>> {
        self.packet_queue.pop_front()
    }

    fn write_to_network<'a>(&mut self, dst: &'a mut [u8], packet_size: usize) -> TunnResult<'a> {
        self.write_to_network_bounded(dst, packet_size, usize::MAX)
    }

    fn write_to_network_bounded<'a>(
        &mut self,
        dst: &'a mut [u8],
        packet_size: usize,
        max_datagram_size: usize,
    ) -> TunnResult<'a> {
        match self.amnezia.prepend_outbound_with_limits(
            self.handshake.obf,
            dst,
            packet_size,
            self.udp_window,
            max_datagram_size,
            &mut self.handshake.rng,
        ) {
            Ok(packet) => TunnResult::WriteToNetwork(packet),
            Err(e) => TunnResult::Err(e),
        }
    }

    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[(session_idx.wrapping_sub(i)) % N_SESSIONS] {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake();
        let tx_bytes = self.tx_bytes;
        let rx_bytes = self.rx_bytes;
        let loss = self.estimate_loss();
        let rtt = self.handshake.last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock-instant")]
    use crate::noise::timers::{REKEY_AFTER_TIME, REKEY_TIMEOUT};

    use super::*;
    use rand_core::{OsRng, RngCore};
    use std::convert::TryInto;

    fn create_two_tuns() -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_tun = Tunn::new(
            my_secret_key,
            their_public_key,
            None,
            None,
            my_idx,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        .unwrap();

        let their_tun = Tunn::new(
            their_secret_key,
            my_public_key,
            None,
            None,
            their_idx,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        .unwrap();

        (my_tun, their_tun)
    }

    fn create_two_tuns_with_amnezia(amnezia: AmneziaConfig) -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_tun = Tunn::new_with_amnezia(
            my_secret_key,
            their_public_key,
            None,
            None,
            my_idx,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            amnezia.clone(),
        )
        .unwrap();

        let their_tun = Tunn::new_with_amnezia(
            their_secret_key,
            my_public_key,
            None,
            None,
            their_idx,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            amnezia,
        )
        .unwrap();

        (my_tun, their_tun)
    }

    fn create_handshake_init(tun: &mut Tunn) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_init = tun.format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            sent
        } else {
            unreachable!();
        };

        handshake_init.into()
    }

    fn create_handshake_response(tun: &mut Tunn, handshake_init: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_resp = tun.decapsulate(None, handshake_init, &mut dst);
        assert!(matches!(handshake_resp, TunnResult::WriteToNetwork(_)));

        let handshake_resp = if let TunnResult::WriteToNetwork(sent) = handshake_resp {
            sent
        } else {
            unreachable!();
        };

        handshake_resp.into()
    }

    fn parse_handshake_resp(tun: &mut Tunn, handshake_resp: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, handshake_resp, &mut dst);
        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

        let keepalive = if let TunnResult::WriteToNetwork(sent) = keepalive {
            sent
        } else {
            unreachable!();
        };

        keepalive.into()
    }

    fn parse_keepalive(tun: &mut Tunn, keepalive: &[u8]) {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, keepalive, &mut dst);
        assert!(matches!(keepalive, TunnResult::Done));
    }

    fn unwrap_network_packet(result: TunnResult) -> Vec<u8> {
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
        if let TunnResult::WriteToNetwork(sent) = result {
            sent.to_vec()
        } else {
            unreachable!();
        }
    }

    fn create_two_tuns_and_handshake() -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        (my_tun, their_tun)
    }

    fn create_two_tuns_and_handshake_with_amnezia(amnezia: AmneziaConfig) -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = create_two_tuns_with_amnezia(amnezia);
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        (my_tun, their_tun)
    }

    fn create_ipv4_udp_packet() -> Vec<u8> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        packet
    }

    fn create_ipv6_udp_packet() -> Vec<u8> {
        let header = etherparse::PacketBuilder::ipv6(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
            64,
        )
        .udp(5678, 23);
        let payload = [4, 3, 2, 1, 0];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        packet
    }

    /// Move time forward past a pacing gate, whichever clock is compiled in.
    ///
    /// The imitation and Jc sequences are paced by `Instant::now()`, so a test
    /// that waits for the next datagram has to advance the clock the production
    /// code is actually reading. `std::thread::sleep` only advances the real
    /// one: under `mock-instant` the mocked clock stays put, `update_timers`
    /// finds nothing due, and the test sees `Done` where it expected a
    /// datagram. That is what `cargo hack test --each-feature` hit — these
    /// tests passed under every other feature and failed under this one.
    ///
    /// Advancing the mock is also strictly better where it applies: no real
    /// sleeping, and no dependence on the scheduler waking us late enough.
    fn advance_past_pacing_gate(d: Duration) {
        #[cfg(feature = "mock-instant")]
        mock_instant::MockClock::advance(d);
        #[cfg(not(feature = "mock-instant"))]
        std::thread::sleep(d);
    }

    #[cfg(feature = "mock-instant")]
    fn update_timer_results_in_handshake(tun: &mut Tunn) {
        let mut dst = vec![0u8; 2048];
        let result = tun.update_timers(&mut dst);
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
        let packet_data = if let TunnResult::WriteToNetwork(data) = result {
            data
        } else {
            unreachable!();
        };
        let packet = Tunn::parse_incoming_packet(tun.handshake.obf, packet_data).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn create_two_tunnels_linked_to_eachother() {
        let (_my_tun, _their_tun) = create_two_tuns();
    }

    #[test]
    fn handshake_init() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(my_tun.handshake.obf, &init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn handshake_init_and_response() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let packet = Tunn::parse_incoming_packet(my_tun.handshake.obf, &resp).unwrap();
        assert!(matches!(packet, Packet::HandshakeResponse(_)));
    }

    #[test]
    fn full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        let packet = Tunn::parse_incoming_packet(my_tun.handshake.obf, &keepalive).unwrap();
        assert!(matches!(packet, Packet::PacketData(_)));
    }

    #[test]
    fn full_handshake_plus_timers() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        // Time has not yet advanced so their is nothing to do
        assert!(matches!(my_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn session_and_handshake_key_material_expire_at_distinct_reject_deadlines() {
        let (mut tun, _peer) = create_two_tuns_and_handshake();
        assert!(tun.sessions.iter().any(Option::is_some));

        // Receiving keys stop being usable after RejectAfterTime, while the
        // handshake's key material is retained for the additional 2x window.
        mock_instant::MockClock::advance(Duration::from_secs(181));
        assert!(matches!(tun.update_timers(&mut []), TunnResult::Done));
        assert!(
            tun.sessions.iter().all(Option::is_none),
            "session keys must be retired after RejectAfterTime"
        );

        mock_instant::MockClock::advance(Duration::from_secs(358));
        assert!(matches!(tun.update_timers(&mut []), TunnResult::Done));

        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(
            tun.update_timers(&mut []),
            TunnResult::Err(WireGuardError::ConnectionExpired)
        ));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn send_side_rekey_fires_at_selected_rekey_after_time() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_after_time(2, 2)
            .with_rekey_timeout(2, 2)
            .with_reject_after_time(180, 180)
            .with_keepalive_timeout(10, 10);
        let (mut initiator, mut responder) = create_two_tuns_with_amnezia(config);

        let init = create_handshake_init(&mut initiator);
        let response = create_handshake_response(&mut responder, &init);
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);

        // Upstream checks keyRefreshTimeoutSending() on each outbound data
        // packet, using the selected RekeyAfterTime value for this keypair.
        mock_instant::MockClock::advance(Duration::from_millis(1));
        let packet = create_ipv4_udp_packet();
        let mut network = [0u8; 2048];
        assert!(matches!(
            initiator.encapsulate(&packet, &mut network),
            TunnResult::WriteToNetwork(_)
        ));

        mock_instant::MockClock::advance(Duration::from_millis(1998));
        assert!(matches!(
            initiator.update_timers(&mut network),
            TunnResult::Done
        ));

        mock_instant::MockClock::advance(Duration::from_millis(1));
        match initiator.update_timers(&mut network) {
            TunnResult::WriteToNetwork(packet) => assert_eq!(
                packet.len(),
                HANDSHAKE_INIT_SZ,
                "RekeyAfterTime must trigger a fresh handshake at its configured boundary"
            ),
            other => panic!(
                "expected send-side RekeyAfterTime handshake at two seconds, got {:?}",
                other
            ),
        }
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn send_side_rekey_completes_and_new_session_carries_data() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_after_time(2, 2)
            .with_rekey_timeout(2, 2)
            .with_reject_after_time(180, 180)
            .with_keepalive_timeout(10, 10);
        let (mut initiator, mut responder) = create_two_tuns_with_amnezia(config);

        let init = create_handshake_init(&mut initiator);
        let response = create_handshake_response(&mut responder, &init);
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);

        mock_instant::MockClock::advance(Duration::from_millis(1));
        let packet = create_ipv4_udp_packet();
        let mut network = [0u8; 2048];
        let mut tunnel = [0u8; 2048];
        assert!(matches!(
            initiator.encapsulate(&packet, &mut network),
            TunnResult::WriteToNetwork(_)
        ));

        mock_instant::MockClock::advance(Duration::from_millis(1999));
        let rekey_init = unwrap_network_packet(initiator.update_timers(&mut network));
        assert!(matches!(
            Tunn::parse_incoming_packet(initiator.handshake.obf, &rekey_init),
            Ok(Packet::HandshakeInit(_))
        ));

        let rekey_response = create_handshake_response(&mut responder, &rekey_init);
        let rekey_keepalive = parse_handshake_resp(&mut initiator, &rekey_response);
        parse_keepalive(&mut responder, &rekey_keepalive);

        assert_eq!(
            initiator.time_since_last_handshake(),
            Some(Duration::ZERO),
            "successful rekey must refresh the initiator handshake timestamp"
        );

        let outbound = match initiator.encapsulate(&packet, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected data under rekeyed session, got {:?}", other),
        };
        assert!(matches!(
            responder.decapsulate(None, &outbound, &mut tunnel),
            TunnResult::WriteToTunnelV4(_, _)
        ));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn rekeyed_session_survives_old_key_reject_after_time_expiry() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_after_time(120, 120)
            .with_rekey_timeout(2, 2)
            .with_reject_after_time(180, 180)
            .with_keepalive_timeout(120, 120);
        let (mut initiator, mut responder) = create_two_tuns_with_amnezia(config);

        // Establish the original session and carry authenticated traffic.
        let init = create_handshake_init(&mut initiator);
        let response = create_handshake_response(&mut responder, &init);
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);

        mock_instant::MockClock::advance(Duration::from_secs(1));
        let packet = create_ipv4_udp_packet();
        let mut network = [0u8; 2048];
        let mut tunnel = [0u8; 2048];
        let outbound = unwrap_network_packet(initiator.encapsulate(&packet, &mut network));
        assert!(matches!(
            responder.decapsulate(None, &outbound, &mut tunnel),
            TunnResult::WriteToTunnelV4(restored, _) if restored == packet
        ));

        // The first data send is at t=1s; RekeyAfterTime is measured from
        // session establishment, so rekey is due at t=120s.
        // Both peers temporarily retain old and new receive keys.
        mock_instant::MockClock::advance(Duration::from_secs(119));
        let rekey_init = unwrap_network_packet(initiator.update_timers(&mut network));
        assert!(matches!(
            Tunn::parse_incoming_packet(initiator.handshake.obf, &rekey_init),
            Ok(Packet::HandshakeInit(_))
        ));
        let rekey_response = create_handshake_response(&mut responder, &rekey_init);
        let rekey_keepalive = parse_handshake_resp(&mut initiator, &rekey_response);
        parse_keepalive(&mut responder, &rekey_keepalive);

        let outbound = unwrap_network_packet(initiator.encapsulate(&packet, &mut network));
        assert!(matches!(
            responder.decapsulate(None, &outbound, &mut tunnel),
            TunnResult::WriteToTunnelV4(restored, _) if restored == packet
        ));
        let reply = unwrap_network_packet(responder.encapsulate(&packet, &mut network));
        assert!(matches!(
            initiator.decapsulate(None, &reply, &mut tunnel),
            TunnResult::WriteToTunnelV4(restored, _) if restored == packet
        ));

        let initiator_sessions = initiator.sessions.iter().filter(|s| s.is_some()).count();
        let responder_sessions = responder.sessions.iter().filter(|s| s.is_some()).count();
        assert!(
            initiator_sessions >= 2 && responder_sessions >= 2,
            "old and rekeyed sessions should coexist before RejectAfterTime: initiator={initiator_sessions}, responder={responder_sessions}"
        );

        // At t=181s the original key is 181s old and must be retired, while
        // the replacement key is only 61s old and must remain usable.
        mock_instant::MockClock::advance(Duration::from_secs(61));
        assert!(matches!(
            initiator.update_timers(&mut network),
            TunnResult::Done
        ));
        assert!(matches!(
            responder.update_timers(&mut network),
            TunnResult::Done
        ));

        assert_eq!(
            initiator.sessions.iter().filter(|s| s.is_some()).count(),
            1,
            "initiator must retire only the expired old session"
        );
        assert_eq!(
            responder.sessions.iter().filter(|s| s.is_some()).count(),
            1,
            "responder must retire only the expired old session"
        );

        // Traffic must continue in both directions using the surviving keys.
        let outbound = unwrap_network_packet(initiator.encapsulate(&packet, &mut network));
        assert!(matches!(
            responder.decapsulate(None, &outbound, &mut tunnel),
            TunnResult::WriteToTunnelV4(restored, _) if restored == packet
        ));
        let reply = unwrap_network_packet(responder.encapsulate(&packet, &mut network));
        assert!(matches!(
            initiator.decapsulate(None, &reply, &mut tunnel),
            TunnResult::WriteToTunnelV4(restored, _) if restored == packet
        ));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn responder_does_not_initiate_send_side_rekey_after_rekey_after_time() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_after_time(2, 2)
            .with_rekey_timeout(2, 2)
            .with_reject_after_time(180, 180)
            .with_keepalive_timeout(10, 10);
        let (mut initiator, mut responder) = create_two_tuns_with_amnezia(config);

        let init = create_handshake_init(&mut initiator);
        let response = create_handshake_response(&mut responder, &init);
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);

        mock_instant::MockClock::advance(Duration::from_millis(1));
        let packet = create_ipv4_udp_packet();
        let mut network = [0u8; 2048];
        assert!(matches!(
            responder.encapsulate(&packet, &mut network),
            TunnResult::WriteToNetwork(_)
        ));

        mock_instant::MockClock::advance(Duration::from_secs(2));
        assert!(
            matches!(responder.update_timers(&mut network), TunnResult::Done),
            "the original handshake responder must not start send-side rekey solely at RekeyAfterTime"
        );
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn authenticated_inbound_data_cancels_and_restarts_inactivity_deadline() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_after_time(120, 120)
            .with_rekey_timeout(2, 2)
            .with_reject_after_time(180, 180)
            .with_keepalive_timeout(6, 6);
        let (mut sender, mut receiver) = create_two_tuns_with_amnezia(config);

        let init = create_handshake_init(&mut sender);
        let response = create_handshake_response(&mut receiver, &init);
        let keepalive = parse_handshake_resp(&mut sender, &response);
        parse_keepalive(&mut receiver, &keepalive);

        let packet = create_ipv4_udp_packet();
        let mut network = [0u8; 2048];
        let mut tunnel = [0u8; 2048];

        assert!(matches!(
            sender.encapsulate(&packet, &mut network),
            TunnResult::WriteToNetwork(_)
        ));
        let first_deadline = sender
            .timers
            .new_handshake_deadline
            .expect("first outbound data starts inactivity deadline");

        mock_instant::MockClock::advance(Duration::from_secs(1));
        let reply = match receiver.encapsulate(&packet, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected authenticated peer data, got {:?}", other),
        };
        assert!(matches!(
            sender.decapsulate(None, &reply, &mut tunnel),
            TunnResult::WriteToTunnelV4(_, _)
        ));
        assert_eq!(
            sender.timers.new_handshake_deadline, None,
            "authenticated inbound data must cancel the pending inactivity deadline"
        );

        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(
            sender.encapsulate(&packet, &mut network),
            TunnResult::WriteToNetwork(_)
        ));
        let restarted_deadline = sender
            .timers
            .new_handshake_deadline
            .expect("the next outbound data starts a fresh inactivity deadline");
        assert!(
            restarted_deadline > first_deadline,
            "the restarted deadline must be based on the authenticated inbound activity"
        );
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn receive_side_rekey_uses_reject_minus_min_keepalive_and_rekey_timeout() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_after_time(120, 120)
            .with_rekey_timeout(2, 4)
            .with_reject_after_time(10, 10)
            .with_keepalive_timeout(6, 8);
        let (mut initiator, mut responder) = create_two_tuns_with_amnezia(config);

        let init = create_handshake_init(&mut initiator);
        let response = create_handshake_response(&mut responder, &init);
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);

        // The initiator must have authenticated receive activity after the
        // session was established for the receive-side key refresh rule.
        mock_instant::MockClock::advance(Duration::from_millis(1));
        let packet = create_ipv4_udp_packet();
        let mut network = [0u8; 2048];
        let mut tunnel = [0u8; 2048];
        let outbound = match responder.encapsulate(&packet, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected responder data packet, got {:?}", other),
        };
        assert!(matches!(
            initiator.decapsulate(None, &outbound, &mut tunnel),
            TunnResult::WriteToTunnelV4(_, _)
        ));

        // Upstream keyRefreshTimeoutReceiving() samples RejectAfterTime for
        // each authenticated transport packet and subtracts the lower bounds
        // of KeepaliveTimeout and RekeyTimeout.
        let threshold = initiator
            .timers
            .reject_after_time
            .saturating_sub(Duration::from_secs(6 + 2));
        assert_eq!(threshold, Duration::from_secs(2));

        // Without a new authenticated packet, the receive-side rule does not
        // fire merely because wall-clock time passes.
        mock_instant::MockClock::advance(threshold - Duration::from_millis(2));
        assert!(matches!(
            initiator.update_timers(&mut network),
            TunnResult::Done
        ));

        // A subsequent authenticated packet crosses the threshold and causes
        // exactly one new handshake, as keepKeyFreshReceiving does upstream.
        mock_instant::MockClock::advance(Duration::from_millis(2));
        let outbound = match responder.encapsulate(&packet, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected second responder data packet, got {:?}", other),
        };
        assert!(matches!(
            initiator.decapsulate(None, &outbound, &mut tunnel),
            TunnResult::WriteToTunnelV4(_, _)
        ));
        match initiator.update_timers(&mut network) {
            TunnResult::WriteToNetwork(packet) => {
                assert_eq!(
                    packet.len(),
                    HANDSHAKE_INIT_SZ,
                    "the receive-side refresh threshold must emit a new handshake"
                );
            }
            other => panic!(
                "expected rekey exactly at RejectAfterTime - KeepaliveTimeout.Lo - RekeyTimeout.Lo, got {:?}",
                other
            ),
        }
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn reject_expiry_uses_configured_upper_bound_and_inclusive_key_lifetime() {
        let config = AmneziaConfig::new(0, 0, 0, 0).with_reject_after_time(180, 200);
        let (mut tun, _peer) = create_two_tuns_and_handshake_with_amnezia(config);
        assert!(tun.sessions.iter().any(Option::is_some));

        // Session expiration is strictly after the configured upper bound.
        mock_instant::MockClock::advance(Duration::from_secs(200));
        assert!(matches!(tun.update_timers(&mut []), TunnResult::Done));
        assert!(tun.sessions.iter().any(Option::is_some));

        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(tun.update_timers(&mut []), TunnResult::Done));
        assert!(tun.sessions.iter().all(Option::is_none));

        // The handshake key material lifetime is three times the upper bound.
        mock_instant::MockClock::advance(Duration::from_secs(398));
        assert!(matches!(tun.update_timers(&mut []), TunnResult::Done));
        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(
            tun.update_timers(&mut []),
            TunnResult::Err(WireGuardError::ConnectionExpired)
        ));
    }

    #[test]
    fn disable_cookies_accepts_authenticated_peer_handshake_under_forced_load() {
        let initiator_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let initiator_public = x25519::PublicKey::from(&initiator_secret);
        let responder_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let responder_public = x25519::PublicKey::from(&responder_secret);
        let rate_limiter = Arc::new(RateLimiter::new(&responder_public, 0));
        let config = AmneziaConfig::new(0, 0, 0, 0).with_disable_cookies(true);

        let mut initiator = Tunn::new_with_amnezia(
            initiator_secret,
            responder_public,
            None,
            None,
            1,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            config.clone(),
        )
        .unwrap();
        let mut responder = Tunn::new_with_amnezia(
            responder_secret,
            initiator_public,
            None,
            None,
            2,
            Some(rate_limiter.clone()),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            config,
        )
        .unwrap();

        let init = create_handshake_init(&mut initiator);
        let mut invalid_mac1 = init.clone();
        let mac1_offset = invalid_mac1.len() - 32;
        invalid_mac1[mac1_offset] ^= 0x80;
        let mut network = [0u8; 2048];

        assert!(matches!(
            responder.decapsulate(None, &invalid_mac1, &mut network),
            TunnResult::Err(WireGuardError::InvalidMac)
        ));

        let response = match responder.decapsulate(None, &init, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!(
                "DisableCookies should allow a valid MAC1 under load, got {:?}",
                other
            ),
        };
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);
        assert!(
            initiator.sessions.iter().any(Option::is_some)
                && responder.sessions.iter().any(Option::is_some),
            "both peers should establish a session without a cookie exchange"
        );
    }

    #[test]
    fn disable_cookies_accepts_handshake_response_under_forced_load_but_checks_mac1() {
        let initiator_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let initiator_public = x25519::PublicKey::from(&initiator_secret);
        let responder_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let responder_public = x25519::PublicKey::from(&responder_secret);
        let initiator_limiter = Arc::new(RateLimiter::new(&initiator_public, 0));
        let responder_limiter = Arc::new(RateLimiter::new(&responder_public, 0));
        let config = AmneziaConfig::new(0, 0, 0, 0).with_disable_cookies(true);

        let mut initiator = Tunn::new_with_amnezia(
            initiator_secret,
            responder_public,
            None,
            None,
            1,
            Some(initiator_limiter),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            config.clone(),
        )
        .unwrap();
        let mut responder = Tunn::new_with_amnezia(
            responder_secret,
            initiator_public,
            None,
            None,
            2,
            Some(responder_limiter),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            config,
        )
        .unwrap();

        let init = create_handshake_init(&mut initiator);
        let mut network = [0u8; 2048];
        let response = match responder.decapsulate(None, &init, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected responder handshake response, got {:?}", other),
        };

        let mut invalid_mac1 = response.clone();
        let mac1_offset = invalid_mac1.len() - 32;
        invalid_mac1[mac1_offset] ^= 0x80;
        assert!(matches!(
            initiator.decapsulate(None, &invalid_mac1, &mut network),
            TunnResult::Err(WireGuardError::InvalidMac)
        ));

        let keepalive = match initiator.decapsulate(None, &response, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!(
                "DisableCookies must bypass the response-side forced-load cookie challenge while still accepting only valid MAC1, got {:?}",
                other
            ),
        };
        parse_keepalive(&mut responder, &keepalive);
        assert!(
            initiator.sessions.iter().any(Option::is_some)
                && responder.sessions.iter().any(Option::is_some),
            "both peers must establish a session without Cookie Reply in the response-side rate-limit path"
        );
    }

    #[test]
    fn disable_cookies_still_accepts_incoming_cookie_replies() {
        let initiator_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let initiator_public = x25519::PublicKey::from(&initiator_secret);
        let responder_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let responder_public = x25519::PublicKey::from(&responder_secret);
        let rate_limiter = Arc::new(RateLimiter::new(&responder_public, 0));
        let initiator_config = AmneziaConfig::new(0, 0, 0, 0).with_disable_cookies(true);
        let responder_config = AmneziaConfig::new(0, 0, 0, 0);

        let mut initiator = Tunn::new_with_amnezia(
            initiator_secret,
            responder_public,
            None,
            None,
            1,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            initiator_config,
        )
        .unwrap();
        let mut responder = Tunn::new_with_amnezia(
            responder_secret,
            initiator_public,
            None,
            None,
            2,
            Some(rate_limiter),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            responder_config,
        )
        .unwrap();

        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut network = [0u8; 2048];
        let init = create_handshake_init(&mut initiator);
        let cookie = match responder.decapsulate(Some(source), &init, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!(
                "the cookie-enabled responder must challenge under forced load, got {:?}",
                other
            ),
        };

        assert!(matches!(
            initiator.decapsulate(None, &cookie, &mut network),
            TunnResult::Done
        ));

        let authenticated_init = match initiator.format_handshake_initiation(&mut network, true) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!(
                "DisableCookies must not disable receiving Cookie Reply or formatting MAC2, got {:?}",
                other
            ),
        };
        let response = match responder.decapsulate(Some(source), &authenticated_init, &mut network)
        {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!(
                "expected MAC2-authenticated handshake response, got {:?}",
                other
            ),
        };
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);

        assert!(
            initiator.sessions.iter().any(Option::is_some)
                && responder.sessions.iter().any(Option::is_some),
            "an AWG peer with DisableCookies enabled must remain interoperable with a cookie-requiring peer"
        );
    }

    #[test]
    fn disable_cookies_composes_with_header_protection_padding_and_random_trailers() {
        let initiator_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let initiator_public = x25519::PublicKey::from(&initiator_secret);
        let responder_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let responder_public = x25519::PublicKey::from(&responder_secret);
        // A zero limit forces the responder into the under-load path from the
        // first authenticated initiation.
        let rate_limiter = Arc::new(RateLimiter::new(&responder_public, 0));
        let config = AmneziaConfig::new(12, 12, 12, 12)
            .with_disable_cookies(true)
            .with_header_protection_key([0x31; 32])
            .with_content_padding_addition(3, 3)
            .with_random_trailers(true);

        let mut initiator = Tunn::new_with_amnezia(
            initiator_secret,
            responder_public,
            None,
            None,
            1,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            config.clone(),
        )
        .unwrap();
        let mut responder = Tunn::new_with_amnezia(
            responder_secret,
            initiator_public,
            None,
            None,
            2,
            Some(rate_limiter),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            config,
        )
        .unwrap();

        let mut network = [0u8; 4096];
        let init = match initiator.format_handshake_initiation(&mut network, false) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!(
                "combined AWG 3.1 initiator could not format handshake: {:?}",
                other
            ),
        };
        let response = match responder.decapsulate(None, &init, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!(
                "DisableCookies must bypass the forced-load cookie challenge with all AWG 3.1 transforms enabled, got {:?}",
                other
            ),
        };
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);

        assert!(
            initiator.sessions.iter().any(Option::is_some)
                && responder.sessions.iter().any(Option::is_some),
            "header protection, content padding, random trailers and DisableCookies must establish a session"
        );
    }

    #[test]
    fn header_protection_and_random_trailers_preserve_cookie_challenge_mac_flow() {
        let initiator_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let initiator_public = x25519::PublicKey::from(&initiator_secret);
        let responder_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let responder_public = x25519::PublicKey::from(&responder_secret);
        let rate_limiter = Arc::new(RateLimiter::new(&responder_public, 0));
        let config = AmneziaConfig::new(12, 12, 12, 12)
            .with_header_protection_key([0x5a; 32])
            .with_random_trailers(true);

        let mut initiator = Tunn::new_with_amnezia(
            initiator_secret,
            responder_public,
            None,
            None,
            1,
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            config.clone(),
        )
        .unwrap();
        let mut responder = Tunn::new_with_amnezia(
            responder_secret,
            initiator_public,
            None,
            None,
            2,
            Some(rate_limiter),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            config,
        )
        .unwrap();

        let mut network = [0u8; 4096];
        let first_init = create_handshake_init(&mut initiator);
        let cookie = match responder.decapsulate(
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            &first_init,
            &mut network,
        ) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!(
                "expected protected cookie reply under load, got {:?}",
                other
            ),
        };
        assert!(cookie.len() > 12 + COOKIE_REPLY_SZ - 1);

        // Corrupt the encrypted-cookie authentication tag inside the fixed
        // 64-byte message (12-byte S3 prefix + 48-byte tag offset). The
        // random outer trailer must not affect parsing, and a forged reply
        // must never install cookie state.
        let mut corrupted_cookie = cookie.clone();
        corrupted_cookie[12 + 48] ^= 0x80;
        assert!(matches!(
            initiator.decapsulate(None, &corrupted_cookie, &mut network),
            TunnResult::Err(WireGuardError::InvalidAeadTag)
        ));

        assert!(matches!(
            initiator.decapsulate(None, &cookie, &mut network),
            TunnResult::Done
        ));

        let authenticated_init = match initiator.format_handshake_initiation(&mut network, true) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected cookie-authenticated initiation, got {:?}", other),
        };
        let response = match responder.decapsulate(
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            &authenticated_init,
            &mut network,
        ) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected MAC2-authenticated response, got {:?}", other),
        };
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);

        assert!(
            initiator.sessions.iter().any(Option::is_some)
                && responder.sessions.iter().any(Option::is_some),
            "header protection, random trailers and cookie MAC flow should establish a session"
        );
    }

    #[test]
    fn completed_handshake_resets_attempt_count_and_reselects_configured_budget() {
        let initial = AmneziaConfig::new(0, 0, 0, 0).with_max_handshake_attempts(2, 2);
        let replacement = AmneziaConfig::new(0, 0, 0, 0).with_max_handshake_attempts(7, 7);
        let (mut initiator, mut responder) = create_two_tuns_with_amnezia(initial);
        assert_eq!(initiator.timers.max_handshake_attempts, 2);
        assert_eq!(responder.timers.max_handshake_attempts, 2);

        // The selected budget is stable throughout the attempt cycle. A live
        // configuration update is sampled only when the handshake completes,
        // matching upstream timersStart/timersHandshakeComplete.
        initiator.timers.set_timer_ranges(&replacement);
        responder.timers.set_timer_ranges(&replacement);
        initiator.timers.handshake_attempts = 5;
        responder.timers.handshake_attempts = 3;
        let init = create_handshake_init(&mut initiator);
        assert_eq!(initiator.timers.max_handshake_attempts, 2);
        let response = create_handshake_response(&mut responder, &init);
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        assert_eq!(initiator.timers.max_handshake_attempts, 7);
        parse_keepalive(&mut responder, &keepalive);

        assert_eq!(initiator.timers.handshake_attempts, 0);
        assert_eq!(responder.timers.handshake_attempts, 0);
        assert_eq!(initiator.timers.max_handshake_attempts, 7);
        assert_eq!(responder.timers.max_handshake_attempts, 7);
    }

    #[test]
    fn content_padding_addition_preserves_padded_keepalive_semantics() {
        let config = AmneziaConfig::new(0, 0, 0, 0).with_content_padding_addition(10, 100);
        let (mut sender, mut receiver) = create_two_tuns_and_handshake_with_amnezia(config);
        let mut network = [0u8; 2048];
        let mut tunnel = [0u8; 2048];

        let keepalive = match sender.encapsulate(&[], &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected padded keepalive, got {:?}", other),
        };
        assert!(
            (DATA_OVERHEAD_SZ + 10..=DATA_OVERHEAD_SZ + 100).contains(&keepalive.len()),
            "ContentPaddingAddition must also pad an empty transport keepalive"
        );
        assert!(
            matches!(
                receiver.decapsulate(None, &keepalive, &mut tunnel),
                TunnResult::Done
            ),
            "an authenticated zero-prefixed keepalive must not be rejected as an invalid IP packet"
        );
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn new_handshake_after_two_mins() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];

        // Advance time 1 second and "send" 1 packet so that we send a handshake
        // after the timeout
        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(
            my_tun.update_timers(&mut my_dst),
            TunnResult::Done
        ));
        let sent_packet_buf = create_ipv4_udp_packet();
        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));

        //Advance to timeout
        mock_instant::MockClock::advance(REKEY_AFTER_TIME + Duration::from_millis(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn handshake_no_resp_rekey_timeout() {
        let (mut my_tun, _their_tun) = create_two_tuns();

        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(my_tun.handshake.obf, &init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));

        mock_instant::MockClock::advance(REKEY_TIMEOUT + Duration::from_millis(334));
        update_timer_results_in_handshake(&mut my_tun)
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn lost_handshake_response_is_retried_and_session_recovers() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_timeout(2, 2)
            .with_max_handshake_attempts(3, 3);
        let (mut initiator, mut responder) = create_two_tuns_with_amnezia(config);

        // The responder processes the first initiation and emits a valid
        // response, but the network drops that response.
        let first_init = create_handshake_init(&mut initiator);
        let dropped_response = create_handshake_response(&mut responder, &first_init);
        assert!(matches!(
            Tunn::parse_incoming_packet(initiator.handshake.obf, &dropped_response),
            Ok(Packet::HandshakeResponse(_))
        ));
        assert_eq!(initiator.timers.handshake_attempts, 0);

        // Retry timeout is two seconds plus the upstream 0..333 ms jitter.
        // Advancing by three seconds guarantees the retransmit is due.
        mock_instant::MockClock::advance(Duration::from_secs(3));
        let mut network = [0u8; 2048];
        let retry_init = unwrap_network_packet(initiator.update_timers(&mut network));
        assert!(matches!(
            Tunn::parse_incoming_packet(initiator.handshake.obf, &retry_init),
            Ok(Packet::HandshakeInit(_))
        ));
        assert_eq!(initiator.timers.handshake_attempts, 1);

        // A fresh initiation must recover even though the responder already
        // processed the first one whose response was lost.
        let retry_response = create_handshake_response(&mut responder, &retry_init);
        let keepalive = parse_handshake_resp(&mut initiator, &retry_response);
        parse_keepalive(&mut responder, &keepalive);

        assert_eq!(
            initiator.timers.handshake_attempts, 0,
            "successful retry handshake resets the retry budget"
        );
        assert!(
            initiator.sessions.iter().any(Option::is_some)
                && responder.sessions.iter().any(Option::is_some),
            "both peers must install sessions after the retransmitted handshake"
        );

        let packet = create_ipv4_udp_packet();
        let mut tunnel = [0u8; 2048];
        let outbound = unwrap_network_packet(initiator.encapsulate(&packet, &mut network));
        assert!(matches!(
            responder.decapsulate(None, &outbound, &mut tunnel),
            TunnResult::WriteToTunnelV4(restored, _) if restored == packet
        ));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn receive_side_rekey_is_latched_once_until_handshake_completion() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_timeout(1, 1)
            .with_reject_after_time(1, 1)
            .with_keepalive_timeout(100, 100);
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake_with_amnezia(config);

        mock_instant::MockClock::advance(Duration::from_secs(2));
        my_tun.timer_tick(TimerName::TimeLastPacketReceived);
        my_tun.timer_check_key_fresh_receiving();
        assert!(my_tun.timers.sent_last_minute_handshake);
        assert!(my_tun.timers.rekey_due_on_receive);

        let mut dst = [0u8; 2048];
        assert!(matches!(
            my_tun.update_timers(&mut dst),
            TunnResult::WriteToNetwork(_)
        ));
        assert!(my_tun.handshake.timer().is_some());
        assert!(!my_tun.timers.rekey_due_on_receive);

        // Simulate an unsuccessful attempt. Upstream keeps the one-shot guard
        // set until a new handshake completes, rather than initiating again
        // on every timer poll or every subsequent received data packet.
        my_tun.handshake.abort_initiation();
        assert!(matches!(my_tun.update_timers(&mut dst), TunnResult::Done));
        my_tun.timer_tick(TimerName::TimeLastDataPacketReceived);
        assert!(matches!(my_tun.update_timers(&mut dst), TunnResult::Done));
        assert!(my_tun.handshake.timer().is_none());
        assert!(my_tun.timers.sent_last_minute_handshake);
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn handshake_attempt_budget_is_checked_on_retry_expiry() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let _init = create_handshake_init(&mut my_tun);
        my_tun.timers.max_handshake_attempts = 0;
        assert_eq!(my_tun.timers.handshake_attempts, 0);

        mock_instant::MockClock::advance(REKEY_TIMEOUT + Duration::from_millis(334));
        let mut dst = [0u8; 2048];
        assert!(matches!(
            my_tun.update_timers(&mut dst),
            TunnResult::WriteToNetwork(_)
        ));
        assert_eq!(my_tun.timers.handshake_attempts, 1);

        // The retry budget is not exhausted until the retransmit timer for
        // the just-sent retry expires; polling immediately must not kill it
        // or consume another attempt.
        assert!(matches!(my_tun.update_timers(&mut dst), TunnResult::Done));
        assert_eq!(my_tun.timers.handshake_attempts, 1);

        mock_instant::MockClock::advance(REKEY_TIMEOUT + Duration::from_millis(334));
        assert!(matches!(my_tun.update_timers(&mut dst), TunnResult::Done));
        assert!(
            !my_tun.is_expired(),
            "exhausting the retry budget must stop this handshake, not expire the peer"
        );
        assert!(
            my_tun.handshake.timer().is_none(),
            "the timed-out initiation must no longer be scheduled for retransmission"
        );
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn exhausted_rekey_keeps_an_established_session_usable() {
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        let sessions_before = my_tun
            .sessions
            .iter()
            .filter(|session| session.is_some())
            .count();
        assert!(sessions_before > 0);

        let mut dst = [0u8; 2048];
        let _ = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, true));
        my_tun.timers.max_handshake_attempts = 0;
        my_tun.packet_queue.push_back(vec![0x45, 0x00]);

        // First expiry sends the one retry allowed when max_attempts is zero.
        mock_instant::MockClock::advance(REKEY_TIMEOUT + Duration::from_millis(334));
        assert!(matches!(
            my_tun.update_timers(&mut dst),
            TunnResult::WriteToNetwork(_)
        ));

        // The next expiry ends only the retry cycle. The established keypair
        // remains available for traffic, while staged packets are discarded.
        mock_instant::MockClock::advance(REKEY_TIMEOUT + Duration::from_millis(334));
        assert!(matches!(my_tun.update_timers(&mut dst), TunnResult::Done));
        assert!(!my_tun.is_expired());
        assert_eq!(
            my_tun
                .sessions
                .iter()
                .filter(|session| session.is_some())
                .count(),
            sessions_before,
            "retry exhaustion must not destroy an otherwise valid session"
        );
        assert!(my_tun.packet_queue.is_empty());

        let packet = create_ipv4_udp_packet();
        assert!(matches!(
            my_tun.encapsulate(&packet, &mut dst),
            TunnResult::WriteToNetwork(_)
        ));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn inactivity_handshake_deadline_starts_at_first_data_send() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_after_time(120, 120)
            .with_rekey_timeout(1, 2)
            .with_keepalive_timeout(3, 8);
        let (mut initiator, mut responder) = create_two_tuns_with_amnezia(config);

        let init = create_handshake_init(&mut initiator);
        let response = create_handshake_response(&mut responder, &init);
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);

        // A long idle period before the first outbound data packet must not
        // consume the inactivity timer: upstream starts it on that first send.
        mock_instant::MockClock::advance(Duration::from_secs(20));
        let packet = create_ipv4_udp_packet();
        let mut network = [0u8; 2048];
        assert!(matches!(
            initiator.encapsulate(&packet, &mut network),
            TunnResult::WriteToNetwork(_)
        ));
        assert!(matches!(
            initiator.update_timers(&mut network),
            TunnResult::Done
        ));
        let first_deadline = initiator.timers.new_handshake_deadline;
        let first_deadline = first_deadline.expect("first data send starts the deadline");
        let selected_delay = first_deadline - initiator.timers[TimerName::TimeCurrent];
        assert!(
            (Duration::from_secs(9)..=Duration::from_millis(10_333)).contains(&selected_delay),
            "upstream uses KeepaliveTimeout.Hi + random RekeyTimeout + 0..333ms jitter; got {selected_delay:?}"
        );

        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(
            initiator.encapsulate(&packet, &mut network),
            TunnResult::WriteToNetwork(_)
        ));
        assert_eq!(
            initiator.timers.new_handshake_deadline,
            Some(first_deadline),
            "subsequent data sends must not postpone the active inactivity timer"
        );

        // The latest possible deadline is 8s + 2s + 333ms after the first
        // send. Ten more seconds after the second send clears every possible draw.
        mock_instant::MockClock::advance(Duration::from_secs(10));
        assert!(matches!(
            initiator.update_timers(&mut network),
            TunnResult::WriteToNetwork(_)
        ));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn repeated_data_receives_do_not_postpone_keepalive_and_request_one_more() {
        let config = AmneziaConfig::new(0, 0, 0, 0).with_keepalive_timeout(3, 3);
        let (mut sender, mut receiver) = create_two_tuns_with_amnezia(config);

        let init = create_handshake_init(&mut sender);
        let response = create_handshake_response(&mut receiver, &init);
        let keepalive = parse_handshake_resp(&mut sender, &response);
        parse_keepalive(&mut receiver, &keepalive);

        let packet = create_ipv4_udp_packet();
        let mut network = [0u8; 2048];
        let mut tunnel = [0u8; 2048];
        let outbound = match sender.encapsulate(&packet, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected first data packet, got {:?}", other),
        };
        assert!(matches!(
            receiver.decapsulate(None, &outbound, &mut tunnel),
            TunnResult::WriteToTunnelV4(_, _)
        ));

        // The first receive starts a three-second timer. A second receive while
        // it is pending requests one additional keepalive but does not reset it.
        let first_deadline = receiver.timers.send_keepalive_deadline;
        mock_instant::MockClock::advance(Duration::from_secs(1));
        let outbound = match sender.encapsulate(&packet, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected second data packet, got {:?}", other),
        };
        assert!(matches!(
            receiver.decapsulate(None, &outbound, &mut tunnel),
            TunnResult::WriteToTunnelV4(_, _)
        ));
        assert_eq!(
            receiver.timers.send_keepalive_deadline, first_deadline,
            "subsequent data receives must not postpone the active keepalive timer"
        );

        mock_instant::MockClock::advance(Duration::from_secs(2));
        assert!(matches!(
            receiver.update_timers(&mut network),
            TunnResult::WriteToNetwork(_)
        ));
        mock_instant::MockClock::advance(Duration::from_secs(2));
        assert!(matches!(
            receiver.update_timers(&mut network),
            TunnResult::Done
        ));
        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(
            receiver.update_timers(&mut network),
            TunnResult::WriteToNetwork(_)
        ));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn authenticated_inbound_data_cancels_pending_inactivity_handshake_deadline() {
        let config = AmneziaConfig::new(0, 0, 0, 0)
            .with_rekey_after_time(120, 120)
            .with_rekey_timeout(1, 1)
            .with_keepalive_timeout(60, 60);
        let (mut initiator, mut responder) = create_two_tuns_with_amnezia(config);
        let init = create_handshake_init(&mut initiator);
        let response = create_handshake_response(&mut responder, &init);
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);

        let packet = create_ipv4_udp_packet();
        let mut network = [0u8; 2048];
        let mut tunnel = [0u8; 2048];
        let outbound = match initiator.encapsulate(&packet, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected outbound data packet, got {:?}", other),
        };
        let deadline = initiator.timers.new_handshake_deadline;
        assert!(deadline.is_some());
        assert!(matches!(
            responder.decapsulate(None, &outbound, &mut tunnel),
            TunnResult::WriteToTunnelV4(_, _)
        ));

        let reply = match responder.encapsulate(&packet, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected authenticated reply packet, got {:?}", other),
        };
        let mut corrupted_reply = reply.clone();
        let last = corrupted_reply.len() - 1;
        corrupted_reply[last] ^= 0x01;
        assert!(matches!(
            initiator.decapsulate(None, &corrupted_reply, &mut tunnel),
            TunnResult::Err(_)
        ));
        assert_eq!(
            initiator.timers.new_handshake_deadline, deadline,
            "unauthenticated inbound traffic must not cancel the pending inactivity handshake"
        );

        assert!(matches!(
            initiator.decapsulate(None, &reply, &mut tunnel),
            TunnResult::WriteToTunnelV4(_, _)
        ));
        assert_eq!(
            initiator.timers.new_handshake_deadline, None,
            "authenticated inbound traffic must cancel the pending inactivity handshake"
        );

        mock_instant::MockClock::advance(Duration::from_secs(10));
        assert!(matches!(
            initiator.update_timers(&mut network),
            TunnResult::Done
        ));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn authenticated_outbound_data_cancels_pending_keepalive_deadline() {
        let config = AmneziaConfig::new(0, 0, 0, 0).with_keepalive_timeout(60, 60);
        let (mut sender, mut receiver) = create_two_tuns_with_amnezia(config);
        let init = create_handshake_init(&mut sender);
        let response = create_handshake_response(&mut receiver, &init);
        let keepalive = parse_handshake_resp(&mut sender, &response);
        parse_keepalive(&mut receiver, &keepalive);

        let packet = create_ipv4_udp_packet();
        let mut network = [0u8; 2048];
        let mut tunnel = [0u8; 2048];
        let outbound = match sender.encapsulate(&packet, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected outbound data packet, got {:?}", other),
        };
        assert!(matches!(
            receiver.decapsulate(None, &outbound, &mut tunnel),
            TunnResult::WriteToTunnelV4(_, _)
        ));
        assert!(receiver.timers.send_keepalive_deadline.is_some());

        let reply = match receiver.encapsulate(&packet, &mut network) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected outbound reply packet, got {:?}", other),
        };
        assert!(matches!(
            sender.decapsulate(None, &reply, &mut tunnel),
            TunnResult::WriteToTunnelV4(_, _)
        ));
        assert_eq!(
            receiver.timers.send_keepalive_deadline, None,
            "authenticated outbound traffic must cancel the pending keepalive"
        );

        mock_instant::MockClock::advance(Duration::from_secs(10));
        assert!(matches!(
            receiver.update_timers(&mut network),
            TunnResult::Done
        ));
    }

    #[test]
    fn one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];

        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    #[test]
    fn amnezia_s1_to_s4_full_handshake_and_data() {
        let amnezia = AmneziaConfig::new(5, 7, 11, 13);
        let (mut my_tun, mut their_tun) = create_two_tuns_with_amnezia(amnezia);
        let init = create_handshake_init(&mut my_tun);
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ + 5);
        assert_eq!(
            u32::from_le_bytes(init[5..9].try_into().unwrap()),
            HANDSHAKE_INIT
        );

        let resp = create_handshake_response(&mut their_tun, &init);
        assert_eq!(resp.len(), HANDSHAKE_RESP_SZ + 7);
        assert_eq!(
            u32::from_le_bytes(resp[7..11].try_into().unwrap()),
            HANDSHAKE_RESP
        );

        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        assert_eq!(keepalive.len(), DATA_OVERHEAD_SZ + 13);
        assert_eq!(
            u32::from_le_bytes(keepalive[13..17].try_into().unwrap()),
            DATA
        );
        parse_keepalive(&mut their_tun, &keepalive);

        let sent_packet_buf = create_ipv4_udp_packet();
        let mut my_dst = [0u8; 2048];
        let mut their_dst = [0u8; 2048];
        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };
        assert_eq!(u32::from_le_bytes(data[13..17].try_into().unwrap()), DATA);

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    #[test]
    fn amnezia_full_handshake_and_data_for_each_imitation_protocol() {
        use amnezia::AmneziaImitationProtocol as P;

        for protocol in [P::None, P::Dns, P::Quic, P::Sip, P::Stun] {
            let amnezia = AmneziaConfig::new(5, 7, 11, 13)
                .with_protocol_imitation(protocol, Some("example.com".to_owned()));
            let (mut my_tun, mut their_tun) = create_two_tuns_with_amnezia(amnezia);

            // Each non-None protocol emits a standalone pre-handshake sequence
            // before the initiation (QUIC's omitted browser defaults to curl = 1
            // Initial). Sleep past the protocol-natural inter-datagram delays
            // (max 20 ms) so the queued datagrams become due.
            let pre_handshake_count = match protocol {
                P::Dns => 3,
                P::Sip | P::Stun => 2,
                P::Quic => 1,
                P::None => 0,
            };
            let mut dst = vec![0u8; 2048];
            let mut result = my_tun.format_handshake_initiation(&mut dst, false);
            for _ in 0..pre_handshake_count {
                assert!(
                    matches!(result, TunnResult::WriteToNetwork(_)),
                    "expected pre-handshake datagram for protocol={:?}",
                    protocol
                );
                advance_past_pacing_gate(Duration::from_millis(25));
                result = my_tun.update_timers(&mut dst);
            }
            let init = unwrap_network_packet(result);

            // Full handshake: every packet type carries a protocol-shaped S-prefix
            // and must still be stripped and parsed by the peer.
            assert_eq!(init.len(), HANDSHAKE_INIT_SZ + 5, "protocol={protocol:?}");
            let resp = create_handshake_response(&mut their_tun, &init);
            assert_eq!(resp.len(), HANDSHAKE_RESP_SZ + 7, "protocol={protocol:?}");
            let keepalive = parse_handshake_resp(&mut my_tun, &resp);
            assert_eq!(
                keepalive.len(),
                DATA_OVERHEAD_SZ + 13,
                "protocol={protocol:?}"
            );
            parse_keepalive(&mut their_tun, &keepalive);

            // Data packet round-trips through the real decapsulate path.
            let sent_packet_buf = create_ipv4_udp_packet();
            let mut my_dst = [0u8; 2048];
            let mut their_dst = [0u8; 2048];
            let data = unwrap_network_packet(my_tun.encapsulate(&sent_packet_buf, &mut my_dst));
            let recv = their_tun.decapsulate(None, &data, &mut their_dst);
            let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = recv {
                recv
            } else {
                panic!(
                    "expected WriteToTunnelV4 for protocol={:?}, got {:?}",
                    protocol, recv
                );
            };
            assert_eq!(sent_packet_buf, recv_packet_buf, "protocol={protocol:?}");
        }
    }

    #[test]
    fn amnezia_encapsulate_errors_when_dst_cannot_hold_s4_prefix() {
        // Establish a session, then try to send into a buffer that comfortably
        // fits the base transport packet but not the configured 600-byte S4
        // prefix.
        let (mut my_tun, _their_tun) =
            create_two_tuns_and_handshake_with_amnezia(AmneziaConfig::new(0, 0, 0, 600));

        let sent_packet_buf = create_ipv4_udp_packet();
        let mut dst = vec![0u8; 256];
        assert!(matches!(
            my_tun.encapsulate(&sent_packet_buf, &mut dst),
            TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
        ));
    }

    #[test]
    fn amnezia_pre_handshake_junk_precedes_handshake_initiation() {
        let amnezia = AmneziaConfig::new(5, 0, 0, 0).with_pre_handshake_junk(2, 10, 20, 0);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        let junk1 = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
        assert!((10..=20).contains(&junk1.len()));
        assert!(matches!(
            Tunn::parse_incoming_packet(my_tun.handshake.obf, &junk1),
            Err(WireGuardError::InvalidPacket)
        ));

        let junk2 = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert!((10..=20).contains(&junk2.len()));

        let init = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ + 5);
        assert_eq!(
            u32::from_le_bytes(init[5..9].try_into().unwrap()),
            HANDSHAKE_INIT
        );
    }

    #[test]
    fn set_preshared_key_treats_all_zero_as_absent() {
        // The handshake mixes `preshared_key.unwrap_or([0u8; 32])`, so an
        // all-zero key and `None` are the same key. wg clears a PSK by sending
        // 32 zero bytes, so this transition happens on ordinary reloads and
        // must not be mistaken for a key change.
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        assert!(my_tun.sessions.iter().any(|s| s.is_some()));

        my_tun.set_preshared_key(Some([0u8; 32]));
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "None -> all-zero is not a key change and must keep sessions"
        );
        assert_eq!(
            my_tun.preshared_key(),
            Some([0u8; 32]),
            "the stored value must follow the caller, so `Peer`'s copy cannot disagree"
        );

        my_tun.set_preshared_key(None);
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "all-zero -> None must keep sessions too"
        );
        assert_eq!(my_tun.preshared_key(), None, "stored value follows back");

        // A genuine key still resets, since sessions derived under the old key
        // are cryptographically stale.
        my_tun.set_preshared_key(Some([7u8; 32]));
        assert!(
            my_tun.sessions.iter().all(|s| s.is_none()),
            "a real key change must discard sessions"
        );
    }

    #[test]
    fn set_obfuscation_reframes_without_dropping_sessions() {
        // H/S are interface-wide, so a live change has to reach every peer or
        // the peer frames packets the interface can no longer parse. It is a
        // framing change, not a cryptographic one, so sessions must survive.
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "session exists"
        );

        let new_obf = ObfuscationRanges::new(10, 20, 30, 40, 50, 60, 70, 80).unwrap();
        let new_amnezia = AmneziaConfig::new(3, 5, 7, 9);
        my_tun.set_obfuscation(new_obf, new_amnezia.clone());

        assert_eq!(my_tun.handshake.obf, new_obf, "tag ranges updated");
        assert_eq!(my_tun.amnezia, new_amnezia, "junk sizes updated");
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "reframing must not tear down established sessions"
        );

        // A handshake initiation now carries the new H1 tag and S1 prefix.
        let mut dst = vec![0u8; 2048];
        let init = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, true));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ + 3, "S1 = 3 applied");
        let tag = u32::from_le_bytes(init[3..7].try_into().unwrap());
        assert!((10..=20).contains(&tag), "H1 in new range, got {}", tag);
    }

    #[test]
    fn set_persistent_keepalive_updates_interval_without_dropping_sessions() {
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "session exists"
        );

        my_tun.set_persistent_keepalive(Some(25));
        assert_eq!(my_tun.persistent_keepalive(), Some(25));
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "a keepalive change is a timer change; sessions must survive"
        );

        // None disables it, matching how Timers::new reads the same argument.
        my_tun.set_persistent_keepalive(None);
        assert_eq!(my_tun.persistent_keepalive(), None);
    }

    #[test]
    fn last_handshake_timestamp_survives_session_key_expiry() {
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        assert!(my_tun.time_since_last_handshake().is_some());

        // Key material can expire while the UAPI's last-handshake timestamp
        // remains available, as it does in amneziawg-go.
        for session in &mut my_tun.sessions {
            *session = None;
        }
        assert!(my_tun.time_since_last_handshake().is_some());
    }

    #[test]
    fn set_preshared_key_discards_sessions_only_when_it_actually_changes() {
        let (mut my_tun, _their_tun) = create_two_tuns_and_handshake();
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "session exists"
        );

        // Re-applying the same value must not disturb live tunnels -- a config
        // reload re-sends every peer's block unchanged.
        let current = my_tun.preshared_key();
        my_tun.set_preshared_key(current);
        assert!(
            my_tun.sessions.iter().any(|s| s.is_some()),
            "unchanged key must not tear down sessions"
        );

        // A real change invalidates them: sessions derived under the old key are
        // cryptographically stale.
        my_tun.set_preshared_key(Some([7u8; 32]));
        assert_eq!(my_tun.preshared_key(), Some([7u8; 32]));
        assert!(
            my_tun.sessions.iter().all(|s| s.is_none()),
            "changed key must discard every session"
        );
    }

    #[test]
    fn amnezia_responder_skips_pre_handshake_but_keeps_padding() {
        // Same configuration as the test above, but adapted for a responder:
        // the initiation must come out immediately, with no junk datagrams
        // ahead of it, while S1 padding is still applied.
        let amnezia = AmneziaConfig::new(5, 0, 0, 0)
            .with_pre_handshake_junk(2, 10, 20, 0)
            .with_protocol_imitation(crate::noise::amnezia::AmneziaImitationProtocol::Quic, None)
            .as_responder();
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        let init = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));

        assert_eq!(
            init.len(),
            HANDSHAKE_INIT_SZ + 5,
            "a responder emits the initiation directly, still S1-padded"
        );
        assert_eq!(
            u32::from_le_bytes(init[5..9].try_into().unwrap()),
            HANDSHAKE_INIT
        );
        // The imitation protocol is retained, so the padding is still
        // protocol-shaped rather than random: QUIC uses a 1-RTT short header.
        assert_eq!(init[0] & 0xc0, 0x40, "S1 padding keeps its QUIC shape");
    }

    #[test]
    fn amnezia_pending_junk_completes_after_expired_handshake_state() {
        let amnezia = AmneziaConfig::new(0, 0, 0, 0).with_pre_handshake_junk(1, 10, 20, 0);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        my_tun.handshake.set_expired();

        let junk = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
        assert!((10..=20).contains(&junk.len()));

        let init = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ);
        assert_eq!(
            u32::from_le_bytes(init[..4].try_into().unwrap()),
            HANDSHAKE_INIT
        );
    }

    #[test]
    fn amnezia_init_buffer_too_small_preserves_pending_without_junk_replay() {
        // S1 = 64 so the handshake initiation needs HANDSHAKE_INIT_SZ + 64 bytes,
        // while a single pre-handshake junk packet is only 10..=20 bytes.
        let amnezia = AmneziaConfig::new(64, 0, 0, 0).with_pre_handshake_junk(1, 10, 20, 0);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut big = vec![0u8; 2048];

        // First call drains the single junk packet. Use the non-forced path
        // (the one `encapsulate` uses): the failed initiation below moves the
        // handshake into `InitSent`, and a non-forced retry must still re-emit
        // the initiation rather than returning `Done` and dropping it.
        let junk = unwrap_network_packet(my_tun.format_handshake_initiation(&mut big, false));
        assert!((10..=20).contains(&junk.len()));

        // Retry the (now due) initiation into a buffer that fits the base
        // WireGuard packet but not the S1 prefix: prepend_outbound must reject it
        // and the pending junk state must survive so we don't replay junk.
        let mut small = vec![0u8; HANDSHAKE_INIT_SZ + 16];
        assert!(matches!(
            my_tun.update_timers(&mut small),
            TunnResult::Err(WireGuardError::DestinationBufferTooSmall)
        ));
        assert!(my_tun.pending_amnezia_junk.is_some());

        // Retrying with a large enough buffer emits the initiation directly,
        // without re-emitting any junk packets.
        let init = unwrap_network_packet(my_tun.update_timers(&mut big));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ + 64);
        assert_eq!(
            u32::from_le_bytes(init[64..68].try_into().unwrap()),
            HANDSHAKE_INIT
        );
        assert!(my_tun.pending_amnezia_junk.is_none());
    }

    #[test]
    fn amnezia_quic_browser_imitation_emits_chrome_initials_before_handshake() {
        let amnezia = AmneziaConfig::new(0, 0, 0, 0).with_protocol_imitation_browser(
            amnezia::AmneziaImitationProtocol::Quic,
            None,
            amnezia::AmneziaImitationBrowser::Chrome,
        );
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        // Chrome opens with two QUIC Initials carrying the split ClientHello.
        let p1 = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
        assert_eq!(p1.len(), 1250);
        let p2 = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(p2.len(), 1250);

        // Then the real handshake initiation follows.
        let init = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ);
        assert_eq!(
            u32::from_le_bytes(init[..4].try_into().unwrap()),
            HANDSHAKE_INIT
        );

        // The two emitted datagrams reassemble to a real Chrome ClientHello.
        let fp = quic::fingerprint::fingerprint_of_packets(&[p1, p2]);
        assert_eq!(fp.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
        assert_eq!(fp.supported_groups, vec![0x11ec, 0x001d, 0x0017, 0x0018]);
        assert_eq!(fp.alpn, vec!["h3".to_string()]);
        assert!(fp.sni.is_some(), "imitation carries a generated SNI");
    }

    #[test]
    fn amnezia_dns_sip_stun_imitation_emit_sequence_before_handshake() {
        use amnezia::AmneziaImitationProtocol as P;

        for (protocol, count) in [(P::Dns, 3usize), (P::Sip, 2), (P::Stun, 2)] {
            let amnezia = AmneziaConfig::new(0, 0, 0, 0)
                .with_protocol_imitation(protocol, Some("example.com".to_owned()));
            let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
            let mut dst = vec![0u8; 2048];

            let mut datagrams = vec![unwrap_network_packet(
                my_tun.format_handshake_initiation(&mut dst, false),
            )];
            // Sleep past the protocol-natural inter-datagram delays (max 20 ms).
            for _ in 1..count {
                advance_past_pacing_gate(Duration::from_millis(25));
                datagrams.push(unwrap_network_packet(my_tun.update_timers(&mut dst)));
            }
            assert_eq!(datagrams.len(), count, "protocol={protocol:?}");

            // The handshake initiation follows the imitation sequence.
            let init = unwrap_network_packet(my_tun.update_timers(&mut dst));
            assert_eq!(init.len(), HANDSHAKE_INIT_SZ, "protocol={protocol:?}");
            assert_eq!(
                u32::from_le_bytes(init[..4].try_into().unwrap()),
                HANDSHAKE_INIT
            );

            // Spot-check the protocol shape of the first emitted datagram.
            match protocol {
                P::Dns => assert_eq!(&datagrams[0][2..4], &[0x01, 0x00], "DNS RD flag"),
                P::Stun => {
                    assert_eq!(&datagrams[0][0..2], &[0x00, 0x01], "STUN Binding Request");
                    assert_eq!(
                        &datagrams[0][4..8],
                        &[0x21, 0x12, 0xa4, 0x42],
                        "magic cookie"
                    );
                }
                P::Sip => assert!(datagrams[0].starts_with(b"INVITE sip:"), "SIP INVITE"),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn amnezia_i1_i5_signature_packets_precede_imitation_and_junk() {
        let amnezia = AmneziaConfig::new(0, 0, 0, 0)
            .with_signature_packet(0, "<b 4931><r 3>")
            .unwrap()
            .with_signature_packet(4, "<b 4935>")
            .unwrap()
            .with_pre_handshake_junk(1, 28, 100, 0)
            .with_protocol_imitation(amnezia::AmneziaImitationProtocol::Stun, None);
        let (mut tun, _peer) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        let i1 = unwrap_network_packet(tun.format_handshake_initiation(&mut dst, false));
        assert_eq!(&i1[..2], b"I1");
        assert_eq!(i1.len(), 5);

        let i5 = unwrap_network_packet(tun.update_timers(&mut dst));
        assert_eq!(i5, b"I5");

        // I1-I5 are followed by the configured imitation sequence, then Jc.
        let stun1 = unwrap_network_packet(tun.update_timers(&mut dst));
        assert_eq!(&stun1[..2], &[0x00, 0x01]);
        advance_past_pacing_gate(Duration::from_millis(20));
        let stun2 = unwrap_network_packet(tun.update_timers(&mut dst));
        assert_eq!(&stun2[..2], &[0x00, 0x01]);

        let junk = unwrap_network_packet(tun.update_timers(&mut dst));
        assert!((28..=100).contains(&junk.len()));
        let init = unwrap_network_packet(tun.update_timers(&mut dst));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ);
    }

    #[test]
    fn amnezia_imitation_and_jc_junk_both_precede_handshake() {
        // wgbooster emits the imitation sequence AND the Jc random/protocol-shaped
        // junk before the handshake; Jc is not dropped when imitation is set.
        let amnezia = AmneziaConfig::new(0, 0, 0, 0)
            .with_pre_handshake_junk(2, 28, 100, 0)
            .with_protocol_imitation(amnezia::AmneziaImitationProtocol::Stun, None);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        let mut datagrams = 0;
        let mut result = my_tun.format_handshake_initiation(&mut dst, false);
        loop {
            let pkt = unwrap_network_packet(result);
            if pkt.len() == HANDSHAKE_INIT_SZ
                && u32::from_le_bytes(pkt[..4].try_into().unwrap()) == HANDSHAKE_INIT
            {
                break;
            }
            datagrams += 1;
            assert!(datagrams <= 8, "imitation sequence did not terminate");
            advance_past_pacing_gate(Duration::from_millis(25));
            result = my_tun.update_timers(&mut dst);
        }
        // 2 STUN imitation packets + 2 Jc junk packets, then the initiation.
        assert_eq!(datagrams, 4);
    }

    #[test]
    fn amnezia_first_jc_packet_is_immediate_after_imitation_with_jd() {
        // wgbooster's delay-after model: the first send_random_packets() packet
        // is emitted immediately after the imitation sequence (no leading Jd),
        // and Jd only spaces the subsequent Jc packets.
        let amnezia = AmneziaConfig::new(0, 0, 0, 0)
            .with_pre_handshake_junk(2, 28, 100, 150) // Jc=2, Jd=150ms
            .with_protocol_imitation(amnezia::AmneziaImitationProtocol::Stun, None);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        // Drain the two STUN imitation packets (second after its 15 ms delay).
        let s1 = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
        assert_eq!(&s1[0..2], &[0x00, 0x01], "STUN Binding Request");
        advance_past_pacing_gate(Duration::from_millis(20));
        let s2 = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(&s2[0..2], &[0x00, 0x01]);

        // The first Jc packet must be due *immediately* — no extra Jd wait.
        let j1 = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert!((28..=100).contains(&j1.len()), "STUN-shaped Jc junk");

        // The second Jc packet, however, must wait Jd: an immediate poll is Done.
        assert!(matches!(my_tun.update_timers(&mut dst), TunnResult::Done));
    }

    #[test]
    fn amnezia_pre_handshake_junk_uses_protocol_imitation() {
        // QUIC imitation (omitted browser -> curl) emits one full Initial, then
        // the Jc QUIC-shaped junk packet, then the handshake.
        let amnezia = AmneziaConfig::new(0, 0, 0, 0)
            .with_pre_handshake_junk(1, 10, 20, 0)
            .with_protocol_imitation(amnezia::AmneziaImitationProtocol::Quic, None);
        let (mut my_tun, _their_tun) = create_two_tuns_with_amnezia(amnezia);
        let mut dst = vec![0u8; 2048];

        // curl QUIC Initial.
        let initial = unwrap_network_packet(my_tun.format_handshake_initiation(&mut dst, false));
        assert_eq!(initial.len(), 1250);
        assert_eq!(initial[0] & 0xc0, 0xc0);

        // Jc QUIC-shaped junk packet.
        let junk = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert!((1200..=1252).contains(&junk.len()));
        assert_eq!(junk[0] & 0xc0, 0xc0);

        let init = unwrap_network_packet(my_tun.update_timers(&mut dst));
        assert_eq!(init.len(), HANDSHAKE_INIT_SZ);
        assert_eq!(
            u32::from_le_bytes(init[..4].try_into().unwrap()),
            HANDSHAKE_INIT
        );
    }

    // ---- ObfuscationRanges unit tests ----

    use crate::noise::handshake::{ObfuscationRanges, TagRange};

    #[test]
    fn obf_default_mapping() {
        // (0,0) for all ranges yields default WG constants
        let obf = ObfuscationRanges::new(0, 0, 0, 0, 0, 0, 0, 0).unwrap();
        assert_eq!(obf.h1_init, TagRange { start: 1, end: 1 });
        assert_eq!(obf.h2_resp, TagRange { start: 2, end: 2 });
        assert_eq!(obf.h3_cookie, TagRange { start: 3, end: 3 });
        assert_eq!(obf.h4_data, TagRange { start: 4, end: 4 });
    }

    #[test]
    fn obf_fixed_mapping() {
        // start=end yields a single-element range
        let obf = ObfuscationRanges::new(10, 10, 20, 20, 30, 30, 40, 40).unwrap();
        assert_eq!(obf.h1_init, TagRange { start: 10, end: 10 });
        assert_eq!(obf.h2_resp, TagRange { start: 20, end: 20 });
        assert_eq!(obf.h3_cookie, TagRange { start: 30, end: 30 });
        assert_eq!(obf.h4_data, TagRange { start: 40, end: 40 });
    }

    #[test]
    fn obf_back_compat_single_value() {
        // (start, 0) where start != 0 => [start..=start]
        let obf = ObfuscationRanges::new(10, 0, 20, 0, 30, 0, 40, 0).unwrap();
        assert_eq!(obf.h1_init, TagRange { start: 10, end: 10 });
        assert_eq!(obf.h2_resp, TagRange { start: 20, end: 20 });
        assert_eq!(obf.h3_cookie, TagRange { start: 30, end: 30 });
        assert_eq!(obf.h4_data, TagRange { start: 40, end: 40 });
    }

    #[test]
    fn obf_overlap_detection() {
        // H1 [10..20] and H4 [20..30] overlap at boundary 20
        let result = ObfuscationRanges::new(10, 20, 100, 110, 200, 210, 20, 30);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("H1"), "Error should mention H1: {}", msg);
        assert!(msg.contains("H4"), "Error should mention H4: {}", msg);
        assert!(
            msg.contains("overlaps"),
            "Error should mention overlaps: {}",
            msg
        );
    }

    #[test]
    fn obf_overlap_detection_h2_h3() {
        let result = ObfuscationRanges::new(10, 20, 50, 60, 55, 65, 100, 110);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("H2"), "Error should mention H2: {}", msg);
        assert!(msg.contains("H3"), "Error should mention H3: {}", msg);
    }

    #[test]
    fn obf_start_greater_than_end() {
        let result = ObfuscationRanges::new(20, 10, 100, 110, 200, 210, 300, 310);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("H1"),
            "Error should identify range H1: {}",
            msg
        );
        assert!(msg.contains("start"), "Error should mention start: {}", msg);
    }

    #[test]
    fn obf_incoming_accept_reject() {
        let obf = ObfuscationRanges::new(10, 20, 30, 40, 50, 60, 70, 80).unwrap();

        // H1: packet with correct range and size should be accepted
        let mut init_packet = vec![0u8; HANDSHAKE_INIT_SZ];
        init_packet[0..4].copy_from_slice(&15u32.to_le_bytes()); // within [10..20]
        let result = Tunn::parse_incoming_packet(obf, &init_packet);
        assert!(matches!(result, Ok(Packet::HandshakeInit(_))));

        // H1: tag outside range but correct size should be rejected
        init_packet[0..4].copy_from_slice(&25u32.to_le_bytes()); // outside [10..20]
        let result = Tunn::parse_incoming_packet(obf, &init_packet);
        assert!(matches!(result, Err(WireGuardError::InvalidPacket)));

        // H2: packet with correct range and size
        let mut resp_packet = vec![0u8; HANDSHAKE_RESP_SZ];
        resp_packet[0..4].copy_from_slice(&35u32.to_le_bytes()); // within [30..40]
        let result = Tunn::parse_incoming_packet(obf, &resp_packet);
        assert!(matches!(result, Ok(Packet::HandshakeResponse(_))));

        // H2: tag outside range
        resp_packet[0..4].copy_from_slice(&45u32.to_le_bytes()); // outside [30..40]
        let result = Tunn::parse_incoming_packet(obf, &resp_packet);
        assert!(matches!(result, Err(WireGuardError::InvalidPacket)));

        // H3: cookie reply
        let mut cookie_packet = vec![0u8; COOKIE_REPLY_SZ];
        cookie_packet[0..4].copy_from_slice(&55u32.to_le_bytes()); // within [50..60]
        let result = Tunn::parse_incoming_packet(obf, &cookie_packet);
        assert!(matches!(result, Ok(Packet::PacketCookieReply(_))));

        cookie_packet[0..4].copy_from_slice(&65u32.to_le_bytes()); // outside [50..60]
        let result = Tunn::parse_incoming_packet(obf, &cookie_packet);
        assert!(matches!(result, Err(WireGuardError::InvalidPacket)));

        // H4: data packet (minimum size)
        let mut data_packet = vec![0u8; DATA_OVERHEAD_SZ];
        data_packet[0..4].copy_from_slice(&75u32.to_le_bytes()); // within [70..80]
        let result = Tunn::parse_incoming_packet(obf, &data_packet);
        assert!(matches!(result, Ok(Packet::PacketData(_))));

        data_packet[0..4].copy_from_slice(&85u32.to_le_bytes()); // outside [70..80]
        let result = Tunn::parse_incoming_packet(obf, &data_packet);
        assert!(matches!(result, Err(WireGuardError::InvalidPacket)));
    }

    #[test]
    fn obf_outgoing_random_within_bounds() {
        let obf = ObfuscationRanges::new(100, 200, 300, 400, 500, 600, 700, 800).unwrap();
        let mut rng = OsRng;
        for _ in 0..1000 {
            let v = obf.random_h1(&mut rng);
            assert!(
                (100..=200).contains(&v),
                "H1 random {} out of range [100..200]",
                v
            );
            let v = obf.random_h2(&mut rng);
            assert!(
                (300..=400).contains(&v),
                "H2 random {} out of range [300..400]",
                v
            );
            let v = obf.random_h3(&mut rng);
            assert!(
                (500..=600).contains(&v),
                "H3 random {} out of range [500..600]",
                v
            );
            let v = obf.random_h4(&mut rng);
            assert!(
                (700..=800).contains(&v),
                "H4 random {} out of range [700..800]",
                v
            );
        }
    }

    #[test]
    fn obf_fixed_range_random_is_constant() {
        let obf = ObfuscationRanges::new(42, 42, 99, 99, 7, 7, 13, 13).unwrap();
        let mut rng = OsRng;
        for _ in 0..100 {
            assert_eq!(obf.random_h1(&mut rng), 42);
            assert_eq!(obf.random_h2(&mut rng), 99);
            assert_eq!(obf.random_h3(&mut rng), 7);
            assert_eq!(obf.random_h4(&mut rng), 13);
        }
    }

    #[test]
    fn obf_ranges_handshake_roundtrip() {
        // Verify that tunnels with matching range config can handshake
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let mut my_tun = Tunn::new(
            my_secret_key,
            their_public_key,
            None,
            None,
            my_idx,
            None,
            100,
            200,
            300,
            400,
            500,
            600,
            700,
            800,
        )
        .unwrap();
        let mut their_tun = Tunn::new(
            their_secret_key,
            my_public_key,
            None,
            None,
            their_idx,
            None,
            100,
            200,
            300,
            400,
            500,
            600,
            700,
            800,
        )
        .unwrap();

        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);
    }

    #[test]
    fn header_protection_completes_a_full_wireguard_handshake_and_keepalive() {
        let config = AmneziaConfig::new(12, 12, 12, 12).with_header_protection_key([0x6b; 32]);
        let (mut initiator, mut responder) = create_two_tuns_with_amnezia(config);

        let initiation = create_handshake_init(&mut initiator);
        let response = create_handshake_response(&mut responder, &initiation);
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);
    }

    #[test]
    fn header_protection_and_random_trailers_interoperate_end_to_end() {
        let config = AmneziaConfig::new(12, 12, 12, 12)
            .with_header_protection_key([0x6b; 32])
            .with_random_trailers(true);
        let (mut initiator, mut responder) = create_two_tuns_with_amnezia(config);

        let initiation = create_handshake_init(&mut initiator);
        let response = create_handshake_response(&mut responder, &initiation);
        let keepalive = parse_handshake_resp(&mut initiator, &response);
        parse_keepalive(&mut responder, &keepalive);

        let packet = create_ipv4_udp_packet();
        let mut network_buffer = vec![0u8; 4096];
        let outbound = match initiator.encapsulate(&packet, &mut network_buffer) {
            TunnResult::WriteToNetwork(datagram) => datagram.to_vec(),
            other => panic!("expected protected transport datagram, got {:?}", other),
        };

        let mut tunnel_buffer = vec![0u8; 4096];
        match responder.decapsulate(None, &outbound, &mut tunnel_buffer) {
            TunnResult::WriteToTunnelV4(restored, _) => assert_eq!(restored, packet),
            other => panic!("expected restored IPv4 packet, got {:?}", other),
        }
    }

    #[test]
    fn obf_ranges_near_u32_max_random_within_bounds() {
        let h1_min = u32::MAX - 10;
        let h1_max = u32::MAX;
        let h2_min = u32::MAX - 30;
        let h2_max = u32::MAX - 21;
        let h3_min = u32::MAX - 50;
        let h3_max = u32::MAX - 41;
        let h4_min = u32::MAX - 70;
        let h4_max = u32::MAX - 61;
        let obf = ObfuscationRanges::new(
            h1_min, h1_max, h2_min, h2_max, h3_min, h3_max, h4_min, h4_max,
        )
        .unwrap();
        let mut rng = OsRng;
        for _ in 0..10_000 {
            let t1 = obf.random_h1(&mut rng);
            assert!(t1 >= h1_min && t1 <= h1_max);
            let t2 = obf.random_h2(&mut rng);
            assert!(t2 >= h2_min && t2 <= h2_max);
            let t3 = obf.random_h3(&mut rng);
            assert!(t3 >= h3_min && t3 <= h3_max);
            let t4 = obf.random_h4(&mut rng);
            assert!(t4 >= h4_min && t4 <= h4_max);
        }
    }

    #[test]
    fn obf_ranges_near_u32_max_overlap_rejected() {
        let h1_min = u32::MAX - 10;
        let h1_max = u32::MAX;
        let h2_min = u32::MAX - 5;
        let h2_max = u32::MAX - 1;
        let h3_min = u32::MAX - 30;
        let h3_max = u32::MAX - 21;
        let h4_min = u32::MAX - 50;
        let h4_max = u32::MAX - 41;
        let res = ObfuscationRanges::new(
            h1_min, h1_max, h2_min, h2_max, h3_min, h3_max, h4_min, h4_max,
        );
        assert!(res.is_err());
    }
    #[test]
    fn content_padding_addition_is_udp_window_bounded_and_removed_after_decryption_ipv6() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_content_padding_addition(12, 12);
        let (mut sender, mut receiver) = create_two_tuns_with_amnezia(cfg);
        let mut packet = create_ipv6_udp_packet();
        let target_size = 500 - DATA_OVERHEAD_SZ - 5;
        packet.resize(target_size, 0);
        let payload_len = (target_size - 40) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[44..46].copy_from_slice(&payload_len.to_be_bytes());

        let init = create_handshake_init(&mut sender);
        let response = create_handshake_response(&mut receiver, &init);
        let keepalive = parse_handshake_resp(&mut sender, &response);
        parse_keepalive(&mut receiver, &keepalive);

        let mut network_buffer = vec![0u8; 4096];
        let outbound = match sender.encapsulate(&packet, &mut network_buffer) {
            TunnResult::WriteToNetwork(datagram) => datagram.to_vec(),
            other => panic!("expected transport datagram, got {:?}", other),
        };
        assert_eq!(
            outbound.len(),
            DATA_OVERHEAD_SZ + packet.len() + 5,
            "IPv6 content addition must be clamped to the five bytes left in the UDP window"
        );

        let mut tunnel_buffer = vec![0u8; 4096];
        match receiver.decapsulate(None, &outbound, &mut tunnel_buffer) {
            TunnResult::WriteToTunnelV6(restored, _) => {
                assert_eq!(restored, packet.as_slice())
            }
            other => panic!("expected restored IPv6 packet, got {:?}", other),
        }
    }

    #[test]
    fn random_trailers_learn_udp_window_from_authenticated_inbound_data() {
        let cfg = AmneziaConfig::new(600, 600, 600, 600).with_random_trailers(true);
        let (mut sender, mut receiver) = create_two_tuns_with_amnezia(cfg);

        let init = create_handshake_init(&mut sender);
        let response = create_handshake_response(&mut receiver, &init);
        let keepalive = parse_handshake_resp(&mut sender, &response);
        parse_keepalive(&mut receiver, &keepalive);

        let mut large_packet = create_ipv4_udp_packet();
        large_packet.resize(200, 0);
        let large_packet_len = large_packet.len();
        large_packet[2..4].copy_from_slice(&(large_packet_len as u16).to_be_bytes());
        let large_udp_len = large_packet_len - 20;
        large_packet[24..26].copy_from_slice(&(large_udp_len as u16).to_be_bytes());

        let mut network_buffer = vec![0u8; 4096];
        let outbound = match sender.encapsulate(&large_packet, &mut network_buffer) {
            TunnResult::WriteToNetwork(datagram) => datagram.to_vec(),
            other => panic!("expected transport datagram, got {:?}", other),
        };
        let observed_size = outbound.len();
        let mut tunnel_buffer = vec![0u8; 4096];
        match receiver.decapsulate(None, &outbound, &mut tunnel_buffer) {
            TunnResult::WriteToTunnelV4(restored, _) => assert_eq!(restored, large_packet),
            other => panic!("expected restored IPv4 packet, got {:?}", other),
        }
        assert_eq!(
            receiver.udp_window, observed_size,
            "the authenticated receive path must learn the complete UDP datagram size"
        );

        let small_packet = create_ipv4_udp_packet();
        let mut saw_padding = false;
        for _ in 0..64 {
            let mut reverse_buffer = vec![0u8; 4096];
            let reverse = match receiver.encapsulate(&small_packet, &mut reverse_buffer) {
                TunnResult::WriteToNetwork(datagram) => datagram.to_vec(),
                other => panic!("expected reverse transport datagram, got {:?}", other),
            };
            assert!(
                reverse.len() <= observed_size,
                "random trailers must stay within the learned UDP window"
            );
            saw_padding |= reverse.len() > DATA_OVERHEAD_SZ + 600 + small_packet.len();
        }
        assert!(
            saw_padding,
            "learned UDP window should permit reverse padding"
        );
    }

    #[test]
    fn runtime_obfuscation_update_validates_before_mutating_tunnel() {
        let (mut tun, _peer) = create_two_tuns_with_amnezia(AmneziaConfig::new(0, 0, 0, 0));
        let invalid = AmneziaConfig::new(0, 0, 0, 0).with_header_protection_key([0x42; 32]);
        assert!(tun
            .try_set_obfuscation(ObfuscationRanges::default(), invalid)
            .is_err());
        assert!(!tun.amnezia.header_protection_enabled());

        let valid = AmneziaConfig::new(12, 12, 12, 12).with_header_protection_key([0x42; 32]);
        assert!(tun
            .try_set_obfuscation(ObfuscationRanges::default(), valid)
            .is_ok());
        assert!(tun.amnezia.header_protection_enabled());
    }

    #[test]
    fn random_trailers_do_not_grow_the_udp_window_for_oversized_outbound_packets() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_random_trailers(true);
        let (mut sender, mut receiver) = create_two_tuns_with_amnezia(cfg);
        let mut packet = create_ipv4_udp_packet();
        packet.resize(600, 0);
        let packet_len = packet.len();
        packet[2..4].copy_from_slice(&(packet_len as u16).to_be_bytes());
        packet[24..26].copy_from_slice(&((packet_len - 20) as u16).to_be_bytes());

        let init = create_handshake_init(&mut sender);
        let response = create_handshake_response(&mut receiver, &init);
        let keepalive = parse_handshake_resp(&mut sender, &response);
        parse_keepalive(&mut receiver, &keepalive);

        let mut network_buffer = vec![0u8; 4096];
        let outbound = match sender.encapsulate(&packet, &mut network_buffer) {
            TunnResult::WriteToNetwork(datagram) => datagram.to_vec(),
            other => panic!("expected transport datagram, got {:?}", other),
        };
        assert_eq!(
            outbound.len(),
            DATA_OVERHEAD_SZ + packet.len(),
            "a packet larger than the default 500-byte UDP window must not expand that window or receive random padding"
        );

        let mut tunnel_buffer = vec![0u8; 4096];
        match receiver.decapsulate(None, &outbound, &mut tunnel_buffer) {
            TunnResult::WriteToTunnelV4(restored, _) => assert_eq!(restored, packet),
            other => panic!("expected restored IPv4 packet, got {:?}", other),
        }
    }

    #[test]
    fn random_trailers_pad_transport_inside_aead_and_restore_ip_packet() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_random_trailers(true);
        let (mut sender, mut receiver) = create_two_tuns_with_amnezia(cfg);
        let packet = create_ipv4_udp_packet();

        let init = create_handshake_init(&mut sender);
        let response = create_handshake_response(&mut receiver, &init);
        let keepalive = parse_handshake_resp(&mut sender, &response);
        parse_keepalive(&mut receiver, &keepalive);

        let mut saw_padding = false;
        for _ in 0..64 {
            let mut network_buffer = vec![0u8; 4096];
            let outbound = match sender.encapsulate(&packet, &mut network_buffer) {
                TunnResult::WriteToNetwork(datagram) => datagram.to_vec(),
                other => panic!("expected transport datagram, got {:?}", other),
            };
            assert!(
                outbound.len() <= 500,
                "random padding must respect the learned UDP window"
            );
            assert!(outbound.len() >= DATA_OVERHEAD_SZ + packet.len());
            saw_padding |= outbound.len() > DATA_OVERHEAD_SZ + packet.len();

            let mut tunnel_buffer = vec![0u8; 4096];
            match receiver.decapsulate(None, &outbound, &mut tunnel_buffer) {
                TunnResult::WriteToTunnelV4(restored, _) => assert_eq!(restored, packet),
                other => panic!("expected restored IPv4 packet, got {:?}", other),
            }
        }
        assert!(
            saw_padding,
            "RandomTrailers should add padding to at least one packet"
        );
    }

    #[test]
    fn content_padding_addition_is_udp_window_bounded_and_removed_after_decryption() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_content_padding_addition(8, 32);
        let (mut sender, mut receiver) = create_two_tuns_with_amnezia(cfg);
        let mut packet = create_ipv4_udp_packet();
        let target_size = 500 - DATA_OVERHEAD_SZ - 5;
        packet.resize(target_size, 0);
        packet[2..4].copy_from_slice(&(target_size as u16).to_be_bytes());
        let udp_len = (target_size - 20) as u16;
        packet[24..26].copy_from_slice(&udp_len.to_be_bytes());

        let init = create_handshake_init(&mut sender);
        let response = create_handshake_response(&mut receiver, &init);
        let keepalive = parse_handshake_resp(&mut sender, &response);
        assert_eq!(
            keepalive.len(),
            DATA_OVERHEAD_SZ,
            "keepalive must not be padded"
        );
        parse_keepalive(&mut receiver, &keepalive);

        let mut network_buffer = vec![0u8; 4096];
        let outbound = match sender.encapsulate(&packet, &mut network_buffer) {
            TunnResult::WriteToNetwork(datagram) => datagram.to_vec(),
            other => panic!("expected transport datagram, got {:?}", other),
        };
        assert_eq!(
            outbound.len(),
            DATA_OVERHEAD_SZ + packet.len() + 5,
            "random addition must be clamped to the five bytes left in the UDP window"
        );

        let mut tunnel_buffer = vec![0u8; 4096];
        match receiver.decapsulate(None, &outbound, &mut tunnel_buffer) {
            TunnResult::WriteToTunnelV4(restored, _) => assert_eq!(restored, packet),
            other => panic!("expected restored IPv4 packet, got {:?}", other),
        }
    }
}
