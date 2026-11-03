// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// For `conforming_initiation` only, and gated exactly as it is: its caller is
// `device::probe_reply`, which does not exist without the `device` feature.
#[cfg(all(test, feature = "device"))]
use super::HANDSHAKE_INIT;
use super::{
    handshake::ObfuscationRanges, COOKIE_REPLY_SZ, DATA_OVERHEAD_SZ, HANDSHAKE_INIT_SZ,
    HANDSHAKE_RESP_SZ,
};
use crate::noise::errors::WireGuardError;
use crate::noise::signature::SignatureChain;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand_core::RngCore;
use std::convert::{TryFrom, TryInto};
use std::time::Duration;

const DNS_OPT_FIXED_LEN: usize = 11;
const DNS_OPT_MIN_WIRE_SIZE: usize = DNS_OPT_FIXED_LEN + 4;
const DEFAULT_JUNK_PACKET_SIZE_MIN: u16 = 50;
const DEFAULT_JUNK_PACKET_SIZE_MAX: u16 = 1000;
const MAX_JUNK_PACKET_COUNT: u16 = 128;
pub(crate) const DEFAULT_UDP_WINDOW: usize = 500;
const MAX_JUNK_PACKET_SIZE: u16 = 1280;
const MAX_JUNK_PACKET_DELAY_MS: u16 = 200;
/// Largest datagram that can actually be sent: the IPv4 UDP payload limit,
/// `65535 - 20 (IP header) - 8 (UDP header)`. IPv6 allows 27 bytes more, but the
/// stricter bound is used so a configuration validated once is sendable over
/// either family — a device may be listening on both.
///
/// The kernel module bounds the same sizes by `MESSAGE_MAX_SIZE = 65535`
/// (`amneziawg-linux-kernel-module/src/messages.h:132`), which is the protocol
/// ceiling rather than the transport one. The 28-byte difference is deliberate:
/// a configuration in that window passes the kernel's check and then fails at
/// send time with `EMSGSIZE`, so it does not work there either. Rejecting it up
/// front is not a parity break: nothing that *functions* on the kernel module
/// is refused on size grounds here.
///
/// That is a claim about size only. [`AmneziaConfig::validate`] refuses a
/// configuration whose enabled under-load cookie replies would amplify; this
/// guard is skipped when DisableCookies prevents those replies. The kernel
/// accepts amplifying configurations, so the guard is a deliberate parity
/// break when cookie replies are enabled. The argument for it is at the check.
const MAX_SENDABLE_DATAGRAM: usize = 65535 - 20 - 8;
const DNS_JUNK_SIZE_MIN: usize = 50;
const DNS_JUNK_SIZE_MAX: usize = 200;
const QUIC_JUNK_SIZE_MIN: usize = 1200;
const QUIC_JUNK_SIZE_MAX: usize = 1252;
const SIP_JUNK_SIZE_MIN: usize = 200;
const SIP_JUNK_SIZE_MAX: usize = 1200;
const STUN_JUNK_SIZE_MIN: usize = 28;
const STUN_JUNK_SIZE_MAX: usize = 100;
// RFC 5389 STUN magic cookie, present at bytes 4..8 of every STUN message.
// Imported rather than restated: `crate::noise::imitation::stun::MAGIC_COOKIE`
// is the crate's single definition. A private alias, not a re-export -- that
// would be `pub use` and would put the constant in this module's public API.
//
// A line comment, not a doc comment: rustdoc does not process docs on a
// private `use`, so a `///` here documents nothing and cannot be checked.
use crate::noise::imitation::stun::MAGIC_COOKIE as STUN_MAGIC_COOKIE;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum AmneziaImitationProtocol {
    #[default]
    None = 0,
    Dns = 1,
    Quic = 2,
    Sip = 3,
    Stun = 4,
}

impl TryFrom<u8> for AmneziaImitationProtocol {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Dns),
            2 => Ok(Self::Quic),
            3 => Ok(Self::Sip),
            4 => Ok(Self::Stun),
            _ => Err(()),
        }
    }
}

impl AmneziaImitationProtocol {
    /// Every variant, so a caller offering these as choices cannot fall behind
    /// the enum. `boringtun-cli` builds its `--imitate-protocol` value list from
    /// this rather than restating it.
    pub const ALL: [Self; 5] = [Self::None, Self::Dns, Self::Quic, Self::Sip, Self::Stun];

    /// The name used on the command line and in `Ip =` config values.
    ///
    /// A `match` over `self` rather than a lookup table: adding a variant fails
    /// to compile here, which is the whole point. The previous arrangement had
    /// the CLI map these strings with a `_ =>` catch-all, so a new variant that
    /// nobody wired up silently meant "no imitation".
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Dns => "dns",
            Self::Quic => "quic",
            Self::Sip => "sip",
            Self::Stun => "stun",
        }
    }

    /// Does this protocol's cover traffic carry a hostname?
    ///
    /// `None` and `Stun` do not, and [`AmneziaImitation::new`] silently drops a
    /// domain supplied with them. A caller that took one from an operator should
    /// use this to say so rather than let it vanish.
    pub fn uses_domain(self) -> bool {
        matches!(self, Self::Dns | Self::Sip | Self::Quic)
    }
}

impl std::str::FromStr for AmneziaImitationProtocol {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `.iter().copied()`, not `.into_iter()`: in edition 2018 the latter on
        // an array yields references, so this would be a `Result<&Self, _>`.
        Self::ALL
            .iter()
            .copied()
            .find(|p| p.as_str() == s)
            .ok_or(())
    }
}

/// Browser fingerprint for QUIC protocol imitation. All variants emit a full
/// browser-fingerprinted QUIC Initial; `Default` resolves to curl, matching
/// wgbooster's default browser when a domain is set but `Ib` is omitted.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum AmneziaImitationBrowser {
    #[default]
    Default = 0,
    Chrome = 1,
    Firefox = 2,
    Curl = 3,
    Random = 4,
}

impl TryFrom<u8> for AmneziaImitationBrowser {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Default),
            1 => Ok(Self::Chrome),
            2 => Ok(Self::Firefox),
            3 => Ok(Self::Curl),
            4 => Ok(Self::Random),
            _ => Err(()),
        }
    }
}

impl AmneziaImitationBrowser {
    /// Map to a QUIC generator profile. `Default` resolves to curl, matching
    /// wgbooster's default browser when a domain is set but no `Ib` is given —
    /// so an omitted browser still produces a full QUIC Initial rather than the
    /// lightweight QUIC-shaped junk.
    fn to_quic(self) -> crate::noise::quic::profiles::BrowserProfile {
        use crate::noise::quic::profiles::BrowserProfile;
        match self {
            AmneziaImitationBrowser::Default | AmneziaImitationBrowser::Curl => {
                BrowserProfile::Curl
            }
            AmneziaImitationBrowser::Chrome => BrowserProfile::Chrome,
            AmneziaImitationBrowser::Firefox => BrowserProfile::Firefox,
            AmneziaImitationBrowser::Random => BrowserProfile::Random,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AmneziaImitation {
    pub(crate) protocol: AmneziaImitationProtocol,
    domain: Option<String>,
    pub(crate) browser: AmneziaImitationBrowser,
}

impl AmneziaImitation {
    pub fn new(
        protocol: AmneziaImitationProtocol,
        domain: Option<String>,
        browser: AmneziaImitationBrowser,
    ) -> Self {
        // DNS QNAMEs and SIP URIs need a strict LDH host (the latter is spliced
        // into text headers, so this also prevents injection). The QUIC SNI is a
        // length-prefixed TLS extension, so it accepts UTF-8/IDN like wgbooster.
        // Invalid hosts are dropped (a random one is generated at emit time).
        let domain = match protocol {
            AmneziaImitationProtocol::Dns | AmneziaImitationProtocol::Sip => {
                domain.filter(|domain| is_valid_imitation_host(domain))
            }
            AmneziaImitationProtocol::Quic => domain.filter(|domain| is_valid_quic_sni(domain)),
            _ => None,
        };
        // Browser only applies to QUIC.
        let browser = if protocol == AmneziaImitationProtocol::Quic {
            browser
        } else {
            AmneziaImitationBrowser::Default
        };

        Self {
            protocol,
            domain,
            browser,
        }
    }

    /// The domain that survived validation, if any.
    ///
    /// `pub` so a caller can tell whether the hostname it supplied was actually
    /// kept: [`Self::new`] drops an invalid host and falls back to a randomly
    /// generated one at emit time, which is a silent substitution an operator
    /// would otherwise only discover in a packet capture.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
}

/// A conforming AmneziaWG handshake initiation, before and after
/// [`AmneziaConfig::prepend_outbound`].
///
/// Lives here, next to the padding rules, because `device::probe_reply`'s
/// ordering test needs a datagram that is *simultaneously* valid AmneziaWG and a
/// valid DNS query — which is exactly what this module produces under `ip=dns`.
/// Building it there instead meant exporting `HANDSHAKE_INIT` and
/// `HANDSHAKE_INIT_SZ` crate-wide for a test, permanently widening two
/// protocol constants that nothing in production needs outside `noise`.
///
/// Gated on `device` as well as `test`, for the reason [`super::packet_sizes`]
/// gives: the only caller is behind that feature, so a test build without it
/// carries a `dead_code` warning for this function -- and `cargo hack test
/// --each-feature`, which CI runs, compiles exactly that configuration.
#[cfg(all(test, feature = "device"))]
pub(crate) fn conforming_initiation(
    cfg: &AmneziaConfig,
    obf: ObfuscationRanges,
    rng: &mut impl RngCore,
) -> (Vec<u8>, Vec<u8>) {
    let mut original = vec![0u8; HANDSHAKE_INIT_SZ];
    original[..4].copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());
    for (i, byte) in original[4..].iter_mut().enumerate() {
        *byte = (i as u8) ^ 0x5a;
    }

    let mut buffer = vec![0u8; HANDSHAKE_INIT_SZ + 1280];
    buffer[..HANDSHAKE_INIT_SZ].copy_from_slice(&original);
    let padded = cfg
        .prepend_outbound(obf, &mut buffer, HANDSHAKE_INIT_SZ, rng)
        .expect("S1 must leave room for the initiation")
        .to_vec();

    (original, padded)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AmneziaConfig {
    pub(crate) init_packet_junk_size: u16,
    pub(crate) response_packet_junk_size: u16,
    pub(crate) cookie_packet_junk_size: u16,
    pub(crate) transport_packet_junk_size: u16,
    pub(crate) pre_handshake_junk: AmneziaPreHandshakeJunk,
    pub(crate) imitation: AmneziaImitation,
    /// Disable the under-load MAC2/cookie challenge (upstream AWG semantics).
    /// MAC1 validation and incoming Cookie Reply handling remain enabled.
    pub(crate) disable_cookies: bool,
    /// 32-byte raw ChaCha20 key for AmneziaWG 3.1 header protection.
    /// An all-zero key disables header protection, matching upstream.
    pub(crate) header_protection_key: [u8; 32],
    /// Inclusive range of extra zero bytes appended to the encrypted IP payload.
    /// `(0, 0)` disables ContentPaddingAddition.
    pub(crate) content_padding_addition: (u32, u32),
    /// Inclusive timer ranges in seconds; (0, 0) preserves WireGuard defaults.
    pub(crate) rekey_after_time: (u32, u32),
    pub(crate) rekey_timeout: (u32, u32),
    pub(crate) reject_after_time: (u32, u32),
    pub(crate) keepalive_timeout: (u32, u32),
    pub(crate) max_handshake_attempts: (u32, u32),
    /// Add random trailing bytes to handshake/cookie datagrams and encrypted transport payloads.
    pub(crate) random_trailers: bool,
    /// Optional I1-I5 standalone signature packet templates.
    pub(crate) signature_packets: [Option<SignatureChain>; 5],
    /// Suppress the client-only pre-handshake burst (Jc junk packets and the
    /// protocol imitation sequence) while keeping every other AmneziaWG
    /// behaviour. See [`AmneziaConfig::as_responder`].
    pub(crate) suppress_pre_handshake: bool,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct AmneziaPreHandshakeJunk {
    pub(crate) packet_count: u16,
    pub(crate) packet_size_min: u16,
    pub(crate) packet_size_max: u16,
    pub(crate) packet_delay_ms: u16,
}

impl AmneziaPreHandshakeJunk {
    pub fn new(
        packet_count: u16,
        packet_size_min: u16,
        packet_size_max: u16,
        delay_ms: u16,
    ) -> Self {
        let packet_count = if packet_count <= MAX_JUNK_PACKET_COUNT {
            packet_count
        } else {
            0
        };

        let (packet_size_min, packet_size_max) = if packet_count == 0 {
            (packet_size_min, packet_size_max)
        } else if packet_size_min == 0 && packet_size_max == 0 {
            (DEFAULT_JUNK_PACKET_SIZE_MIN, DEFAULT_JUNK_PACKET_SIZE_MAX)
        } else if packet_size_min > 0
            && packet_size_min <= packet_size_max
            && packet_size_max <= MAX_JUNK_PACKET_SIZE
        {
            (packet_size_min, packet_size_max)
        } else {
            (DEFAULT_JUNK_PACKET_SIZE_MIN, DEFAULT_JUNK_PACKET_SIZE_MAX)
        };

        let packet_delay_ms = if delay_ms <= MAX_JUNK_PACKET_DELAY_MS {
            delay_ms
        } else {
            0
        };

        Self {
            packet_count,
            packet_size_min,
            packet_size_max,
            packet_delay_ms,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.packet_count > 0
    }

    pub fn delay(&self) -> Duration {
        Duration::from_millis(self.packet_delay_ms as u64)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum PacketKind {
    HandshakeInit,
    HandshakeResponse,
    CookieReply,
    TransportData,
}

impl AmneziaConfig {
    /// Create a config with the AmneziaWG S1-S4 junk prefix sizes.
    ///
    /// `s1`/`s2`/`s3`/`s4` are the number of junk bytes prepended to handshake
    /// initiation, handshake response, cookie reply, and transport-data packets
    /// respectively. They are used verbatim and are not clamped: callers must
    /// size their output buffers to fit the base WireGuard packet plus the
    /// configured prefix, otherwise `prepend_outbound` (and therefore
    /// `Tunn::encapsulate`) returns [`WireGuardError::DestinationBufferTooSmall`].
    pub fn new(s1: u16, s2: u16, s3: u16, s4: u16) -> Self {
        Self {
            init_packet_junk_size: s1,
            response_packet_junk_size: s2,
            cookie_packet_junk_size: s3,
            transport_packet_junk_size: s4,
            pre_handshake_junk: AmneziaPreHandshakeJunk::default(),
            imitation: AmneziaImitation::default(),
            disable_cookies: false,
            header_protection_key: [0u8; 32],
            content_padding_addition: (0, 0),
            rekey_after_time: (0, 0),
            rekey_timeout: (0, 0),
            reject_after_time: (0, 0),
            keepalive_timeout: (0, 0),
            max_handshake_attempts: (0, 0),
            random_trailers: false,
            signature_packets: Default::default(),
            suppress_pre_handshake: false,
        }
    }

    /// Disable the under-load cookie challenge, matching AmneziaWG 3.1.
    /// When enabled, MAC1 is still verified, but the under-load MAC2/rate-limit
    /// challenge is bypassed and no Cookie Reply is sent. Incoming Cookie Reply
    /// packets remain supported.
    pub fn with_disable_cookies(mut self, disabled: bool) -> Self {
        self.disable_cookies = disabled;
        self
    }

    /// Enable AmneziaWG 3.1 header protection with a 32-byte ChaCha20 key.
    /// Passing an all-zero key disables protection, as in amneziawg-go.
    pub fn with_header_protection_key(mut self, key: [u8; 32]) -> Self {
        self.header_protection_key = key;
        self
    }

    pub(crate) fn header_protection_enabled(&self) -> bool {
        self.header_protection_key != [0u8; 32]
    }

    /// Set the inclusive ContentPaddingAddition range in bytes.
    /// Use `(0, 0)` to disable additional content padding.
    pub fn with_content_padding_addition(mut self, min: u16, max: u16) -> Self {
        self.content_padding_addition = (u32::from(min), u32::from(max));
        self
    }

    /// Set the full UAPI uint32 ContentPaddingAddition range.
    pub(crate) fn with_content_padding_addition_u32(mut self, min: u32, max: u32) -> Self {
        self.content_padding_addition = (min, max);
        self
    }

    /// Configure one AmneziaWG I1-I5 signature chain (index 0..=4).
    /// An empty/no-tag specification clears that slot.
    pub fn with_signature_packet(mut self, index: usize, spec: &str) -> Result<Self, String> {
        let slot = self
            .signature_packets
            .get_mut(index)
            .ok_or_else(|| "signature packet index must be in 0..=4".to_owned())?;
        *slot = SignatureChain::parse(spec)?;
        Ok(self)
    }

    /// Generate configured I1-I5 datagrams in slot order.
    pub(crate) fn pre_handshake_signature_datagrams(
        &self,
        rng: &mut impl RngCore,
    ) -> std::collections::VecDeque<Vec<u8>> {
        self.signature_packets
            .iter()
            .filter_map(|chain| chain.as_ref().map(|chain| chain.emit(rng)))
            .collect()
    }

    pub(crate) fn has_signature_packets(&self) -> bool {
        self.signature_packets.iter().any(Option::is_some)
    }

    /// Enable AmneziaWG RandomTrailers. Transport padding is encrypted; handshake
    /// and cookie trailers are appended after the fixed-size WireGuard message.
    pub fn with_random_trailers(mut self, enabled: bool) -> Self {
        self.random_trailers = enabled;
        self
    }

    /// Configure inclusive AmneziaWG timer ranges (seconds). `(0, 0)` keeps the WireGuard default.
    pub fn with_rekey_after_time(mut self, min: u32, max: u32) -> Self {
        self.rekey_after_time = (min, max);
        self
    }

    pub fn with_rekey_timeout(mut self, min: u32, max: u32) -> Self {
        self.rekey_timeout = (min, max);
        self
    }

    pub fn with_reject_after_time(mut self, min: u32, max: u32) -> Self {
        self.reject_after_time = (min, max);
        self
    }

    pub fn with_keepalive_timeout(mut self, min: u32, max: u32) -> Self {
        self.keepalive_timeout = (min, max);
        self
    }

    pub fn with_max_handshake_attempts(mut self, min: u32, max: u32) -> Self {
        self.max_handshake_attempts = (min, max);
        self
    }

    /// Select a random ContentPaddingAddition value and clamp it to the
    /// remaining peer UDP window, matching upstream's randomPaddingAddition.
    /// Empty keepalives and packets that already fill the window are not padded.
    pub(crate) fn content_padding_size(
        &self,
        packet_size: usize,
        wire_packet_size: usize,
        udp_window: usize,
        rng: &mut impl RngCore,
    ) -> usize {
        let (min, max) = self.content_padding_addition;
        let available = udp_window.saturating_sub(wire_packet_size);
        if (min == 0 && max == 0) || min > max || packet_size == 0 || available == 0 {
            return 0;
        }
        let selected = loop {
            if let Some(value) = Self::map_content_padding_sample(min, max, rng.next_u32()) {
                break value;
            }
        };
        selected.min(available)
    }

    /// Map one u32 draw to the inclusive CPA range without modulo bias.
    /// None denotes a draw in the rejection tail.
    fn map_content_padding_sample(min: u32, max: u32, sample: u32) -> Option<usize> {
        if min > max {
            return None;
        }
        let width = u64::from(max) - u64::from(min) + 1;
        let zone = (1u64 << 32) / width * width;
        let value = u64::from(sample);
        if value >= zone {
            return None;
        }
        Some((u64::from(min) + value % width) as usize)
    }

    pub fn with_pre_handshake_junk(
        mut self,
        packet_count: u16,
        packet_size_min: u16,
        packet_size_max: u16,
        delay_ms: u16,
    ) -> Self {
        self.pre_handshake_junk =
            AmneziaPreHandshakeJunk::new(packet_count, packet_size_min, packet_size_max, delay_ms);
        self
    }

    pub fn with_protocol_imitation(
        mut self,
        protocol: AmneziaImitationProtocol,
        domain: Option<String>,
    ) -> Self {
        self.imitation = AmneziaImitation::new(protocol, domain, AmneziaImitationBrowser::Default);
        self
    }

    /// As [`Self::with_protocol_imitation`], plus a browser fingerprint for QUIC.
    pub fn with_protocol_imitation_browser(
        mut self,
        protocol: AmneziaImitationProtocol,
        domain: Option<String>,
        browser: AmneziaImitationBrowser,
    ) -> Self {
        self.imitation = AmneziaImitation::new(protocol, domain, browser);
        self
    }

    /// Check that every S-prefix can coexist with the packet it precedes.
    ///
    /// [`Self::new`] deliberately does not clamp, because the sizes are part of
    /// the wire contract and a peer configured differently must still be
    /// describable. But a configuration whose prefix cannot fit alongside its
    /// base packet can never emit a valid datagram: `prepend_outbound` returns
    /// [`WireGuardError::DestinationBufferTooSmall`] forever, which surfaces as
    /// a tunnel that simply never completes a handshake, with nothing pointing
    /// at the configuration. Callers accepting operator input should reject it
    /// at the point of entry instead.
    ///
    /// The bounds correspond to the kernel module's own validation
    /// (`amneziawg-linux-kernel-module/src/device.c:584-601`), but are 28 bytes
    /// stricter: the kernel bounds by the protocol ceiling
    /// (`MESSAGE_MAX_SIZE = 65535`) while this uses `MAX_SENDABLE_DATAGRAM`,
    /// what a UDP socket can actually carry.
    ///
    /// The relationship is therefore one-way, not symmetric: on **size**, a
    /// configuration landing in the 28-byte gap is accepted by the kernel and
    /// rejected here, and nothing is lost — it fails on the kernel too, at send
    /// time with `EMSGSIZE`, so it never worked there either. See
    /// `MAX_SENDABLE_DATAGRAM` for the arithmetic.
    ///
    /// The amplification check below is a different matter and the one place
    /// this genuinely refuses a configuration the kernel module runs. It is
    /// intentional, and argued at the check rather than here, so that "every
    /// working kernel configuration is accepted" is not read as covering it.
    pub(crate) fn validate_timer_ranges(&self) -> Result<(), String> {
        for (name, (min, max)) in [
            ("rekey_after_time", self.rekey_after_time),
            ("rekey_timeout", self.rekey_timeout),
            ("reject_after_time", self.reject_after_time),
            ("keepalive_timeout", self.keepalive_timeout),
            ("max_handshake_attempts", self.max_handshake_attempts),
        ] {
            if min > max {
                return Err(format!("{} minimum {} exceeds maximum {}", name, min, max));
            }
        }
        Ok(())
    }

    /// RandomTrailers makes handshake lengths variable. With different
    /// S-prefix lengths, a transport packet can be examined at the wrong
    /// offset by an earlier handshake classifier and be silently discarded
    /// before its transport AEAD is tried (upstream amneziawg-go#186).
    ///
    /// Requiring one common S offset makes every classifier inspect the same
    /// four-byte type field. Since ObfuscationRanges rejects overlapping H1-H4
    /// ranges, a transport tag selected from H4 cannot match H1-H3. This is a
    /// deterministic framing constraint, not a probabilistic width heuristic.
    pub(crate) fn validate_random_trailers(&self, _obf: ObfuscationRanges) -> Result<(), String> {
        if self.random_trailers {
            let s = self.init_packet_junk_size;
            if self.response_packet_junk_size != s
                || self.cookie_packet_junk_size != s
                || self.transport_packet_junk_size != s
            {
                return Err(format!(
                    "RandomTrailers requires S1 = S2 = S3 = S4 (all currently must equal {}); different offsets can misclassify and silently drop transport packets",
                    s
                ));
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        let (padding_min, padding_max) = self.content_padding_addition;
        if padding_min > padding_max {
            return Err(format!(
                "ContentPaddingAddition minimum {} exceeds maximum {}",
                padding_min, padding_max
            ));
        }

        self.validate_timer_ranges()?;

        for (label, junk, base) in [
            ("S1", self.init_packet_junk_size, HANDSHAKE_INIT_SZ),
            ("S2", self.response_packet_junk_size, HANDSHAKE_RESP_SZ),
            ("S3", self.cookie_packet_junk_size, COOKIE_REPLY_SZ),
            ("S4", self.transport_packet_junk_size, DATA_OVERHEAD_SZ),
        ] {
            if junk as usize + base > MAX_SENDABLE_DATAGRAM {
                return Err(format!(
                    "{} is too large: {} junk bytes + {} packet bytes exceed the {}-byte maximum datagram",
                    label, junk, base, MAX_SENDABLE_DATAGRAM
                ));
            }
        }

        // Header Protection uses the first 12 bytes of each S-prefix as its
        // ChaCha20 nonce. Upstream requires every packet class to carry one.
        if self.header_protection_enabled() {
            for (label, junk) in [
                ("S1", self.init_packet_junk_size),
                ("S2", self.response_packet_junk_size),
                ("S3", self.cookie_packet_junk_size),
                ("S4", self.transport_packet_junk_size),
            ] {
                if junk < 12 {
                    return Err(format!(
                        "{} must be at least 12 bytes when Header Protection is enabled",
                        label
                    ));
                }
            }
        }

        // A cookie reply that is larger than the packet provoking it makes this
        // port a reflector, and the ratio is fixed by S1/S2/S3 alone -- an
        // attacker cannot influence it. `device::reply_policy` refuses to send
        // such a reply, which costs the peer every handshake for as long as the
        // device is over its handshake rate limit, because a peer that never
        // receives a cookie can never produce a valid mac2.
        //
        // Refusing the configuration outright is the louder failure and the one
        // the operator can act on: it happens at `awg set`, naming the values,
        // rather than silently during a flood. The AmneziaWG kernel module
        // accepts these combinations, so this is deliberately stricter than the
        // reference implementation -- a config rejected here would have run
        // there, weakly reflecting.
        // Both alternatives the message offers have to work in one pass. The
        // "raise" side therefore names every violated bound, not just the
        // binding one: at S1=100, S2=0, S3=185 both are violated, and raising
        // S2 alone still leaves the initiation a byte short.
        // DisableCookies bypasses the only path that emits an under-load
        // Cookie Reply. In that mode the reply-size amplification constraint
        // is irrelevant; incoming Cookie Replies remain supported.
        if !self.disable_cookies {
            let bounds = self.cookie_amplification_bounds();
            if let Some(&(which, request, _)) = bounds.first() {
                let reply = COOKIE_REPLY_SZ + self.cookie_packet_junk_size as usize;
                let raise = bounds
                    .iter()
                    .map(|&(label, _, min_junk)| format!("{} to at least {}", label, min_junk))
                    .collect::<Vec<_>>()
                    .join(" and ");
                return Err(format!(
                    "S3 = {} makes a cookie reply {} bytes, larger than the {}-byte packet that provokes it ({} = {}); the reply would be suppressed and handshakes would fail under load. Lower S3 to at most {}, or raise {}.",
                    self.cookie_packet_junk_size,
                    reply,
                    request,
                    which,
                    request
                        - if which == "S1" {
                            HANDSHAKE_INIT_SZ
                        } else {
                            HANDSHAKE_RESP_SZ
                        },
                    request - COOKIE_REPLY_SZ,
                    raise
                ));
            }
        }

        Ok(())
    }

    /// Adapt this configuration for the responder (server) side of a tunnel.
    ///
    /// A server must *tolerate* a client's pre-handshake camouflage but must
    /// never emit it: the Jc junk burst and the protocol imitation sequence are
    /// things a client sends to open a conversation. Emitting them from a
    /// responder is both directionally wrong — it looks like the server is
    /// opening a QUIC/DNS/SIP/STUN exchange with its own peer — and slow, since
    /// the queue drains one datagram per `update_timers` tick, delaying any
    /// server-initiated handshake by the length of the sequence.
    ///
    /// Everything else is preserved, including the imitation protocol itself:
    /// S1-S4 padding is still filled with protocol-shaped bytes
    /// (`fill_outbound_junk`), so the server's own traffic keeps the
    /// same byte distribution as the client's. Only the *standalone* datagrams
    /// are suppressed.
    pub fn as_responder(mut self) -> Self {
        self.suppress_pre_handshake = true;
        self
    }

    /// True when a full protocol-natural imitation sequence should be emitted
    /// for the pre-handshake phase. DNS/SIP/STUN/QUIC all qualify (QUIC's omitted
    /// browser defaults to curl, matching wgbooster); only `None` does not.
    pub(crate) fn has_imitation_sequence(&self) -> bool {
        self.imitation.protocol != AmneziaImitationProtocol::None
    }

    /// True when this endpoint should emit a pre-handshake burst at all —
    /// false for a responder, and for a client with neither Jc nor imitation.
    pub(crate) fn emits_pre_handshake(&self) -> bool {
        !self.suppress_pre_handshake
            && (self.pre_handshake_junk.is_enabled()
                || self.has_imitation_sequence()
                || self.has_signature_packets())
    }

    /// The configured imitation host, or a generated random one (DNS query name
    /// / SIP URI host / QUIC SNI).
    fn imitation_host(&self, rng: &mut impl RngCore) -> String {
        self.imitation
            .domain()
            .map(str::to_owned)
            .unwrap_or_else(|| random_imitation_domain(rng))
    }

    /// Generate the standalone imitation datagram sequence for the pre-handshake
    /// phase, each paired with the delay to wait *before* emitting it. Imitation
    /// ignores the generic Jd delay and uses protocol-natural timing (the first
    /// datagram always has zero delay): DNS sends A+AAAA in parallel then HTTPS
    /// after 15 ms; SIP waits 20 ms before the CANCEL; STUN waits 15 ms before
    /// the nomination check; QUIC Initials go back-to-back.
    pub(crate) fn pre_handshake_imitation_datagrams(
        &self,
        rng: &mut impl RngCore,
    ) -> std::collections::VecDeque<(Duration, Vec<u8>)> {
        use crate::noise::imitation::{dns, sip, stun};

        let (datagrams, delays_ms): (Vec<Vec<u8>>, &[u16]) = match self.imitation.protocol {
            AmneziaImitationProtocol::Dns => {
                (dns::generate(&self.imitation_host(rng), rng), &[0, 0, 15])
            }
            AmneziaImitationProtocol::Sip => {
                (sip::generate(&self.imitation_host(rng), rng), &[0, 20])
            }
            AmneziaImitationProtocol::Stun => (stun::generate(rng), &[0, 15]),
            AmneziaImitationProtocol::Quic => {
                let browser = self.imitation.browser.to_quic();
                let datagrams = crate::noise::quic::generator::generate_client_initials(
                    browser,
                    &self.imitation_host(rng),
                    rng,
                );
                (datagrams, &[])
            }
            AmneziaImitationProtocol::None => (Vec::new(), &[]),
        };

        datagrams
            .into_iter()
            .enumerate()
            .map(|(i, datagram)| {
                let ms = delays_ms.get(i).copied().unwrap_or(0);
                (Duration::from_millis(ms as u64), datagram)
            })
            .collect()
    }

    fn inbound_junk_size(&self, kind: PacketKind) -> usize {
        (match kind {
            PacketKind::HandshakeInit => self.init_packet_junk_size,
            PacketKind::HandshakeResponse => self.response_packet_junk_size,
            PacketKind::CookieReply => self.cookie_packet_junk_size,
            PacketKind::TransportData => self.transport_packet_junk_size,
        }) as usize
    }

    fn outbound_junk_size(&self, kind: PacketKind) -> usize {
        self.inbound_junk_size(kind)
    }

    fn read_tag(packet: &[u8], offset: usize) -> Option<u32> {
        let tag = packet.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(tag.try_into().ok()?))
    }

    fn tag_matches(obf: ObfuscationRanges, kind: PacketKind, tag: u32) -> bool {
        match kind {
            PacketKind::HandshakeInit => obf.matches_h1(tag),
            PacketKind::HandshakeResponse => obf.matches_h2(tag),
            PacketKind::CookieReply => obf.matches_h3(tag),
            PacketKind::TransportData => obf.matches_h4(tag),
        }
    }

    fn inbound_kind_at_offset(
        &self,
        obf: ObfuscationRanges,
        packet: &[u8],
        kind: PacketKind,
        base_size: usize,
    ) -> bool {
        let junk_size = self.inbound_junk_size(kind);
        let minimum_size = junk_size.saturating_add(base_size);
        if packet.len() < minimum_size || (!self.random_trailers && packet.len() != minimum_size) {
            return false;
        }
        Self::read_tag(packet, junk_size)
            .map(|tag| Self::tag_matches(obf, kind, tag))
            .unwrap_or(false)
    }

    /// Strip the AmneziaWG junk prefix from an inbound datagram, or reject it.
    ///
    /// Returns `None` when the datagram matches no configured packet shape.
    ///
    /// The padding rule is *per packet kind*, not global: a kind whose S is
    /// non-zero must arrive padded, while a kind whose S is zero must arrive
    /// unpadded. A configuration with `S1 = 15, S4 = 0` therefore rejects a
    /// bare initiation and accepts a bare transport packet, and both are
    /// correct. Rejecting everything unpadded would break the second case.
    ///
    /// Handing a non-matching datagram back unmodified -- as this used to --
    /// let the caller re-read the tag at offset 0 and accept it, which made
    /// the S-prefix an obfuscation rather than an input filter. The kernel
    /// module drops such a datagram outright (`prepare_awg_message`,
    /// `src/receive.c`).
    ///
    /// A datagram cannot match two kinds: `ObfuscationRanges::new` validates
    /// the H ranges as non-overlapping, and the three handshake kinds have
    /// distinct fixed sizes. With every S at zero these tests reduce to the
    /// same (tag, length) pairs `Tunn::parse_incoming_packet` applies, so
    /// plain WireGuard is unaffected.
    pub(crate) fn strip_inbound<'a>(
        &self,
        obf: ObfuscationRanges,
        packet: &'a [u8],
    ) -> Option<&'a [u8]> {
        for (kind, base) in [
            (PacketKind::HandshakeInit, HANDSHAKE_INIT_SZ),
            (PacketKind::HandshakeResponse, HANDSHAKE_RESP_SZ),
            (PacketKind::CookieReply, COOKIE_REPLY_SZ),
        ] {
            if self.inbound_kind_at_offset(obf, packet, kind, base) {
                let junk = self.inbound_junk_size(kind);
                return Some(&packet[junk..junk + base]);
            }
        }

        // Transport data is variable length, so this is a minimum rather than
        // an exact size. With S4 = 0 the offset is 0 and this is exactly the
        // vanilla check.
        let junk = self.inbound_junk_size(PacketKind::TransportData);
        if packet.len() >= junk + DATA_OVERHEAD_SZ
            && Self::read_tag(packet, junk)
                .map(|tag| Self::tag_matches(obf, PacketKind::TransportData, tag))
                .unwrap_or(false)
        {
            return Some(&packet[junk..]);
        }

        None
    }

    /// Decode an inbound packet protected by the AWG 3.1 ChaCha20 header
    /// cipher. The first 12 bytes of the packet are the nonce and remain clear.
    /// The first four encrypted bytes are recovered first so the matching H
    /// range can identify the packet kind; the same cipher stream then
    /// continues at byte four, exactly as in amneziawg-go.
    pub(crate) fn decrypt_inbound(&self, obf: ObfuscationRanges, packet: &[u8]) -> Option<Vec<u8>> {
        let decoded = self.decrypt_inbound_with_prefix(obf, packet)?;
        self.strip_inbound(obf, &decoded).map(<[u8]>::to_vec)
    }

    /// Decrypt a Header Protection packet while retaining its S-prefix.
    ///
    /// The device-level anonymous UDP path must classify the S/H framing
    /// before it knows which peer owns the packet. Returning the prefix here
    /// lets that path run the same S/H classifier on the recovered type,
    /// while the connected-peer path uses decrypt_inbound above.
    pub(crate) fn decrypt_inbound_with_prefix(
        &self,
        obf: ObfuscationRanges,
        packet: &[u8],
    ) -> Option<Vec<u8>> {
        if !self.header_protection_enabled() {
            return None;
        }

        for (kind, base_size) in [
            (PacketKind::HandshakeInit, HANDSHAKE_INIT_SZ),
            (PacketKind::HandshakeResponse, HANDSHAKE_RESP_SZ),
            (PacketKind::CookieReply, COOKIE_REPLY_SZ),
            (PacketKind::TransportData, DATA_OVERHEAD_SZ),
        ] {
            let prefix_size = self.inbound_junk_size(kind);
            if prefix_size < 12 {
                continue;
            }

            let minimum_size = prefix_size.checked_add(base_size)?;
            let is_transport = kind == PacketKind::TransportData;
            if packet.len() < minimum_size
                || (!is_transport && !self.random_trailers && packet.len() != minimum_size)
            {
                continue;
            }

            let nonce: &[u8] = packet.get(..12)?;
            let mut cipher =
                chacha20::ChaCha20::new_from_slices(&self.header_protection_key, nonce).ok()?;

            let encrypted_type = packet.get(prefix_size..prefix_size + 4)?;
            let mut message_type = [0u8; 4];
            cipher.apply_keystream(&mut message_type);
            for (byte, encrypted) in message_type.iter_mut().zip(encrypted_type) {
                *byte ^= encrypted;
            }

            let tag = u32::from_le_bytes(message_type);
            if !Self::tag_matches(obf, kind, tag) {
                continue;
            }

            let mut decoded = packet.to_vec();
            decoded[prefix_size..prefix_size + 4].copy_from_slice(&message_type);
            // Handshake and cookie messages are fixed-size and fully protected.
            // For transport, only type + receiver index + counter (16 bytes)
            // are header-protected; the payload remains AEAD ciphertext.
            let protected_header_len = if is_transport { 16 } else { base_size };
            cipher
                .apply_keystream(&mut decoded[prefix_size + 4..prefix_size + protected_header_len]);
            return Some(decoded);
        }

        None
    }

    fn classify_outbound(&self, obf: ObfuscationRanges, packet: &[u8]) -> Option<PacketKind> {
        let tag = Self::read_tag(packet, 0)?;
        match packet.len() {
            HANDSHAKE_INIT_SZ if obf.matches_h1(tag) => Some(PacketKind::HandshakeInit),
            HANDSHAKE_RESP_SZ if obf.matches_h2(tag) => Some(PacketKind::HandshakeResponse),
            COOKIE_REPLY_SZ if obf.matches_h3(tag) => Some(PacketKind::CookieReply),
            len if len >= DATA_OVERHEAD_SZ && obf.matches_h4(tag) => {
                Some(PacketKind::TransportData)
            }
            _ => None,
        }
    }

    /// How many bytes a `cookie_len`-byte cookie reply will occupy on the wire,
    /// S3 prefix included.
    ///
    /// Exists so the ingress path can decide whether the reply is an amplifier
    /// *before* [`Self::prepend_outbound`] generates junk for it. With S3 near
    /// its 65443-byte maximum, filling a prefix for a reply that policy then
    /// refuses would itself be the flood — one forged 148-byte initiation per
    /// 65 KB of keystream, which is a cheaper attack than the amplification it
    /// was meant to prevent.
    ///
    /// Reads the prefix size through [`Self::outbound_junk_size`], the same
    /// accessor `prepend_outbound` uses, so the prediction cannot drift from
    /// the production by way of two spellings of one lookup. What it still has
    /// to assume is the packet *kind*, which `prepend_outbound` derives from
    /// the tag on the wire, so
    /// [`tests::the_predicted_cookie_reply_length_is_the_one_actually_produced`]
    /// pins the two together.
    ///
    /// Gated because the ingress path is the only caller: without `device` this
    /// is dead code, and a crate built without the feature would carry a
    /// `dead_code` warning for it. `test` is in the list so the test above still
    /// runs on a default-feature `cargo test`.
    #[cfg(any(test, feature = "device"))]
    pub(crate) fn cookie_reply_len(&self, cookie_len: usize) -> usize {
        cookie_len.saturating_add(self.outbound_junk_size(PacketKind::CookieReply))
    }

    /// The S sizes at which a cookie reply would be larger than the packet that
    /// provokes it, if there are any.
    ///
    /// Every request kind the reply would exceed, tightest bound first, as
    /// `(kind, request_len, smallest_junk_that_clears_it)`, where `kind` is
    /// `"S1"` (an initiation) or `"S2"` (a response). Empty when the
    /// configuration does not amplify.
    ///
    /// `device::reply_policy::cookie_verdict` suppresses such a reply, because a
    /// cookie reply aimed at a forged source is a reflector and the ratio is
    /// fixed entirely by this configuration — an attacker cannot influence it.
    /// The cost is real: the peer never learns the cookie, so it can never
    /// produce a valid mac2, and every one of its handshakes fails for as long
    /// as the device stays over `HANDSHAKE_RATE_LIMIT`.
    ///
    /// This exists so the operator hears about that when they set the sizes,
    /// rather than during the flood. The condition is decidable from S1/S2/S3
    /// alone — `64 + S3 > 148 + S1` for an initiation, `64 + S3 > 92 + S2` for a
    /// response — so there is no reason to discover it at send time.
    ///
    /// Both kinds can be violated at once, and they are independent: S3 has to
    /// clear *both*. That is why this reports all of them rather than the first
    /// or the tightest. At S1=100, S2=0, S3=185 the reply is 249 bytes against a
    /// 248-byte initiation and a 92-byte response — advice naming either alone
    /// leaves the other failing, and the operator is sent round twice.
    ///
    /// The `min_junk` values are always reachable: `min_junk + base` is exactly
    /// `COOKIE_REPLY_SZ + S3`, and [`Self::validate`] has already bounded that
    /// by `MAX_SENDABLE_DATAGRAM` before it gets here, so following this advice
    /// can never trip the size check instead.
    ///
    /// This function only *reports*. [`Self::validate`] is what rejects, and it
    /// does so deliberately: see the argument there for why refusing a
    /// configuration the AmneziaWG kernel module would accept is the right trade
    /// rather than an interoperability break worth avoiding.
    ///
    /// Not gated: [`Self::validate`] calls it on every build, because a
    /// configuration this shape is refused rather than merely warned about.
    fn cookie_amplification_bounds(&self) -> Vec<(&'static str, usize, usize)> {
        let reply = COOKIE_REPLY_SZ + self.cookie_packet_junk_size as usize;
        let mut bounds: Vec<(&'static str, usize, usize)> = [
            ("S1", self.init_packet_junk_size, HANDSHAKE_INIT_SZ),
            ("S2", self.response_packet_junk_size, HANDSHAKE_RESP_SZ),
        ]
        .iter()
        // Filter before the subtraction, not after: `reply - base` underflows
        // on a configuration that does not amplify, which is most of them.
        // `reply > base + junk` implies `reply > base`, so the map is safe only
        // in this order.
        .filter(|&&(_, junk, base)| reply > base + junk as usize)
        .map(|&(label, junk, base)| (label, base + junk as usize, reply - base))
        .collect();
        // Stable, so an equal pair still reports S1 first and the message stays
        // the same for the common symmetric configuration.
        bounds.sort_by_key(|&(_, request, _)| request);
        bounds
    }

    /// The **binding** bound as `(kind, request_len, reply_len)` — the shortest
    /// provoking packet, the one S3 actually has to clear — or `None` when the
    /// configuration does not amplify.
    ///
    /// A view over [`Self::cookie_amplification_bounds`], not a second
    /// derivation. `validate` needs every violated bound, so it calls that
    /// directly; this narrower shape is only convenient for asserting *which*
    /// bound binds, and `#[cfg(test)]` accordingly — left ungated it is dead
    /// code, and the crate carries a `dead_code` warning for it with or without
    /// the `device` feature.
    #[cfg(test)]
    fn cookie_reply_amplifies(&self) -> Option<(&'static str, usize, usize)> {
        let reply = COOKIE_REPLY_SZ + self.cookie_packet_junk_size as usize;
        // Sorted tightest-first, so the first entry is the binding one.
        let (label, request, _) = self.cookie_amplification_bounds().into_iter().next()?;
        Some((label, request, reply))
    }

    pub(crate) fn prepend_outbound<'a>(
        &self,
        obf: ObfuscationRanges,
        buffer: &'a mut [u8],
        packet_size: usize,
        rng: &mut impl RngCore,
    ) -> Result<&'a mut [u8], WireGuardError> {
        self.prepend_outbound_with_limits(
            obf,
            buffer,
            packet_size,
            DEFAULT_UDP_WINDOW,
            usize::MAX,
            rng,
        )
    }

    /// Apply S-prefix, Header Protection and optional RandomTrailers.
    ///
    /// udp_window is the peer's learned maximum datagram size. max_datagram_size
    /// is normally unbounded, but cookie replies pass the triggering request's
    /// size so random trailers can never turn a cookie into an amplifier.
    pub(crate) fn prepend_outbound_with_limits<'a>(
        &self,
        obf: ObfuscationRanges,
        buffer: &'a mut [u8],
        packet_size: usize,
        udp_window: usize,
        max_datagram_size: usize,
        rng: &mut impl RngCore,
    ) -> Result<&'a mut [u8], WireGuardError> {
        let packet = buffer
            .get(..packet_size)
            .ok_or(WireGuardError::DestinationBufferTooSmall)?;
        let Some(kind) = self.classify_outbound(obf, packet) else {
            return Ok(&mut buffer[..packet_size]);
        };

        let junk_size = self.outbound_junk_size(kind);
        if self.header_protection_enabled() && junk_size < 12 {
            return Err(WireGuardError::InvalidPacket);
        }

        let prefixed_size = packet_size
            .checked_add(junk_size)
            .ok_or(WireGuardError::DestinationBufferTooSmall)?;
        // Never let optional trailers turn an otherwise sendable packet into
        // DestinationBufferTooSmall. The caller's actual output slice is the
        // final bound, alongside UDP's protocol maximum and any cookie request
        // bound supplied by the caller.
        let trailer_limit = max_datagram_size
            .min(buffer.len())
            .min(MAX_SENDABLE_DATAGRAM);
        let trailer_len = if self.random_trailers && kind != PacketKind::TransportData {
            self.random_trailer_len(prefixed_size, udp_window, trailer_limit, rng)
        } else {
            0
        };
        let new_size = prefixed_size
            .checked_add(trailer_len)
            .ok_or(WireGuardError::DestinationBufferTooSmall)?;
        if buffer.len() < new_size {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        if junk_size > 0 {
            buffer.copy_within(0..packet_size, junk_size);
            self.fill_outbound_junk(&mut buffer[..junk_size], packet_size, rng);
        }

        if self.header_protection_enabled() {
            let nonce: [u8; 12] = buffer[..12]
                .try_into()
                .map_err(|_| WireGuardError::InvalidPacket)?;
            let mut cipher =
                chacha20::ChaCha20::new_from_slices(&self.header_protection_key, &nonce)
                    .map_err(|_| WireGuardError::InvalidPacket)?;
            // Handshake messages protect the complete fixed-size message.
            // Transport packets protect only type + receiver index + counter;
            // the AEAD ciphertext and authentication tag must remain untouched.
            let protected_len = if kind == PacketKind::TransportData {
                16
            } else {
                packet_size
            };
            cipher.apply_keystream(&mut buffer[junk_size..junk_size + protected_len]);
        }

        if trailer_len > 0 {
            rng.fill_bytes(&mut buffer[prefixed_size..new_size]);
        }

        Ok(&mut buffer[..new_size])
    }

    /// Random trailer length follows upstream's exclusive UDP-window upper bound:
    /// fastrandn(udp_window - packet_size).
    pub(crate) fn random_trailer_len(
        &self,
        packet_size: usize,
        udp_window: usize,
        max_datagram_size: usize,
        rng: &mut impl RngCore,
    ) -> usize {
        if !self.random_trailers {
            return 0;
        }
        let available = udp_window
            .saturating_sub(packet_size)
            .min(max_datagram_size.saturating_sub(packet_size));
        if available == 0 {
            return 0;
        }
        random_usize_inclusive(0, available - 1, rng)
    }

    /// Transport RandomTrailers are zero padding inside the AEAD plaintext.
    /// Explicit ContentPaddingAddition takes precedence, matching upstream.
    pub(crate) fn transport_padding_size(
        &self,
        ip_packet_size: usize,
        wire_packet_size: usize,
        udp_window: usize,
        rng: &mut impl RngCore,
    ) -> usize {
        if self.content_padding_addition != (0, 0) {
            return self.content_padding_size(ip_packet_size, wire_packet_size, udp_window, rng);
        }
        self.random_trailer_len(wire_packet_size, udp_window, MAX_SENDABLE_DATAGRAM, rng)
    }

    pub fn fill_pre_handshake_junk<'a>(
        &self,
        buffer: &'a mut [u8],
        rng: &mut impl RngCore,
    ) -> Result<&'a mut [u8], WireGuardError> {
        if !self.pre_handshake_junk.is_enabled() {
            return Ok(&mut buffer[..0]);
        }

        let size = self.pre_handshake_junk_size(rng);
        if buffer.len() < size {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let packet = &mut buffer[..size];
        match self.imitation.protocol {
            AmneziaImitationProtocol::None => fill_random(packet, rng),
            AmneziaImitationProtocol::Dns => fill_dns(packet, 0, self.imitation.domain(), rng),
            AmneziaImitationProtocol::Quic => fill_quic_initial(packet, rng),
            AmneziaImitationProtocol::Sip => fill_sip(packet, self.imitation.domain(), rng),
            AmneziaImitationProtocol::Stun => fill_stun(packet, rng),
        }

        Ok(packet)
    }

    fn pre_handshake_junk_size(&self, rng: &mut impl RngCore) -> usize {
        match self.imitation.protocol {
            AmneziaImitationProtocol::None => random_usize_inclusive(
                self.pre_handshake_junk.packet_size_min as usize,
                self.pre_handshake_junk.packet_size_max as usize,
                rng,
            ),
            AmneziaImitationProtocol::Dns => {
                random_usize_inclusive(DNS_JUNK_SIZE_MIN, DNS_JUNK_SIZE_MAX, rng)
            }
            AmneziaImitationProtocol::Quic => {
                random_usize_inclusive(QUIC_JUNK_SIZE_MIN, QUIC_JUNK_SIZE_MAX, rng)
            }
            AmneziaImitationProtocol::Sip => {
                random_usize_inclusive(SIP_JUNK_SIZE_MIN, SIP_JUNK_SIZE_MAX, rng)
            }
            AmneziaImitationProtocol::Stun => {
                random_usize_inclusive(STUN_JUNK_SIZE_MIN, STUN_JUNK_SIZE_MAX, rng)
            }
        }
    }

    fn fill_outbound_junk(&self, dst: &mut [u8], trailing_size: usize, rng: &mut impl RngCore) {
        match self.imitation.protocol {
            AmneziaImitationProtocol::None => fill_random(dst, rng),
            protocol => {
                fill_protocol_like(protocol, self.imitation.domain(), dst, trailing_size, rng)
            }
        }
    }
}

/// Generate a plausible random host name when no domain is configured for an
/// imitation that needs one (DNS query name, SIP URI host, QUIC SNI).
fn random_imitation_domain(rng: &mut impl RngCore) -> String {
    const TLDS: [&str; 4] = ["com", "net", "org", "io"];
    let label_len = 7 + (rng.next_u32() % 10) as usize; // 7..=16 chars
    let mut host = String::with_capacity(label_len + 4);
    for _ in 0..label_len {
        host.push((b'a' + (rng.next_u32() % 26) as u8) as char);
    }
    host.push('.');
    host.push_str(TLDS[(rng.next_u32() as usize) % TLDS.len()]);
    host
}

fn random_usize_inclusive(min: usize, max: usize, rng: &mut impl RngCore) -> usize {
    if min >= max {
        return min;
    }

    let range_size = (max - min) as u64 + 1;
    let threshold = u64::MAX - (u64::MAX % range_size);
    loop {
        let val = rng.next_u64();
        if val < threshold {
            return min + (val % range_size) as usize;
        }
    }
}

fn fill_protocol_like(
    protocol: AmneziaImitationProtocol,
    domain: Option<&str>,
    dst: &mut [u8],
    trailing_size: usize,
    rng: &mut impl RngCore,
) {
    match protocol {
        AmneziaImitationProtocol::None => fill_random(dst, rng),
        AmneziaImitationProtocol::Dns => fill_dns(dst, trailing_size, domain, rng),
        // Always a 1-RTT short header, for every packet kind. A long header
        // carries a length field that would have to frame the bytes that
        // follow -- but those are the immutable WireGuard packet, which this
        // prefix cannot describe, so any long-header form parses as malformed.
        // A short header has no version or length field, so the remaining
        // bytes are indistinguishable from encrypted 1-RTT payload.
        //
        // The S-region is also far too small for a valid Initial: S2 + 92 and
        // S3 + 64 are nowhere near the 1200-byte minimum of RFC 9000 §14.1
        // (contrast `pre_handshake_junk_size`, where the QUIC branch picks
        // QUIC_JUNK_SIZE_MIN..=MAX = 1200..=1252 precisely so that a
        // long-header Initial is legal). And S2/S3 travel responder -> peer,
        // so emitting an Initial there inverts the direction of a real QUIC
        // handshake, where the Initial is the client's first packet.
        AmneziaImitationProtocol::Quic => fill_quic_short(dst, rng),
        AmneziaImitationProtocol::Sip => fill_sip(dst, domain, rng),
        AmneziaImitationProtocol::Stun => fill_stun(dst, rng),
    }
}

fn fill_random(dst: &mut [u8], rng: &mut impl RngCore) {
    let mut chunks = dst.chunks_exact_mut(4);
    for chunk in &mut chunks {
        chunk.copy_from_slice(&rng.next_u32().to_le_bytes());
    }
    let rem = chunks.into_remainder();
    if !rem.is_empty() {
        let bytes = rng.next_u32().to_le_bytes();
        rem.copy_from_slice(&bytes[..rem.len()]);
    }
}

fn random_byte(rng: &mut impl RngCore) -> u8 {
    (rng.next_u32() & 0xff) as u8
}

fn fill_quic_short(dst: &mut [u8], rng: &mut impl RngCore) {
    if dst.is_empty() {
        return;
    }

    let spin = ((rng.next_u32() >> 8) & 0x01) as u8;
    let key_phase = ((rng.next_u32() >> 8) & 0x01) as u8;
    let pn_len = (rng.next_u32() & 0x03) as u8;
    dst[0] = 0x40 | (spin << 5) | (key_phase << 2) | pn_len;
    for byte in &mut dst[1..] {
        *byte = random_byte(rng);
    }
}

fn fill_quic_initial(dst: &mut [u8], rng: &mut impl RngCore) {
    fill_random(dst, rng);
    if !dst.is_empty() {
        dst[0] = 0xc0 | (rng.next_u32() & 0x03) as u8;
    }
    if dst.len() >= 5 {
        dst[1] = 0x00;
        dst[2] = 0x00;
        dst[3] = 0x00;
        dst[4] = 0x01;
    }
    if dst.len() >= 6 {
        dst[5] = ((rng.next_u32() % 17) + 4) as u8;
    }
}

fn fill_stun(dst: &mut [u8], rng: &mut impl RngCore) {
    fill_random(dst, rng);
    let size = dst.len();

    if size >= 2 {
        dst[0] = 0x00;
        dst[1] = 0x01;
    }

    let body = if size > 20 { (size - 20) & !0x03 } else { 0 };
    let value_len = if body >= 4 { (body - 4).min(124) } else { 0 };
    let attr_len = if body >= 4 { 4 + value_len } else { 0 };

    if size >= 4 {
        let len = attr_len as u16;
        dst[2] = (len >> 8) as u8;
        dst[3] = len as u8;
    }
    if size >= 8 {
        dst[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
    }
    if size > 8 {
        for byte in &mut dst[8..size.min(20)] {
            *byte = random_byte(rng);
        }
    }
    if attr_len >= 4 {
        let value_len = value_len as u16;
        dst[20] = 0x80;
        dst[21] = 0x22;
        dst[22] = (value_len >> 8) as u8;
        dst[23] = value_len as u8;
        for byte in &mut dst[24..24 + value_len as usize] {
            *byte = 0x20 + (random_byte(rng) % 0x5f);
        }
    }
    if size >= 20 + attr_len {
        for byte in &mut dst[20 + attr_len..] {
            *byte = random_byte(rng);
        }
    }
}

fn fill_sip(dst: &mut [u8], domain: Option<&str>, rng: &mut impl RngCore) {
    fill_random(dst, rng);
    if dst.len() < 31 {
        return;
    }

    static SEEDS: [(&str, &str, &str); 6] = [
        ("OPTIONS", "u", "x"),
        ("OPTIONS", "100", "pbx"),
        ("REGISTER", "101", "gw"),
        ("MESSAGE", "noc", "lan"),
        ("OPTIONS", "m", "voip"),
        ("REGISTER", "sip", "edge"),
    ];

    let seed = SEEDS[(rng.next_u32() as usize) % SEEDS.len()];
    if run_sip_candidate_chain(dst, seed, domain, true, rng) {
        return;
    }
    let _ = run_sip_candidate_chain(dst, seed, domain, false, rng);
}

fn run_sip_candidate_chain(
    dst: &mut [u8],
    seed: (&str, &str, &str),
    domain: Option<&str>,
    require_via: bool,
    rng: &mut impl RngCore,
) -> bool {
    if let Some(domain) = domain {
        if emit_sip(
            dst,
            seed.0,
            seed.1,
            &format!("{}.{}", seed.2, domain),
            require_via,
            rng,
        ) {
            return true;
        }
        if emit_sip(dst, seed.0, seed.1, domain, require_via, rng) {
            return true;
        }
        if emit_sip(
            dst,
            "OPTIONS",
            "u",
            &format!("x.{}", domain),
            require_via,
            rng,
        ) {
            return true;
        }
        if emit_sip(dst, "OPTIONS", "u", domain, require_via, rng) {
            return true;
        }
    }

    emit_sip(dst, seed.0, seed.1, seed.2, require_via, rng)
        || emit_sip(dst, "OPTIONS", "u", "x", require_via, rng)
}

fn emit_sip(
    dst: &mut [u8],
    method: &str,
    user: &str,
    host: &str,
    require_via: bool,
    rng: &mut impl RngCore,
) -> bool {
    let token = rng.next_u32();
    let mut pos = 0usize;

    if !put_sip_line(
        dst,
        &mut pos,
        &format!("{method} sip:{user}@{host} SIP/2.0\r\n"),
    ) {
        return false;
    }

    let via_ok = put_sip_line(
        dst,
        &mut pos,
        &format!("Via: SIP/2.0/UDP {host};branch=z9hG4bK{token:08x}\r\n"),
    );
    if require_via && !via_ok {
        return false;
    }

    if via_ok {
        let _ = put_sip_line(dst, &mut pos, "Max-Forwards: 70\r\n")
            && put_sip_line(
                dst,
                &mut pos,
                &format!("From: <sip:{user}@{host}>;tag={:04x}\r\n", token & 0xffff),
            )
            && put_sip_line(dst, &mut pos, &format!("To: <sip:{user}@{host}>\r\n"))
            && put_sip_line(dst, &mut pos, &format!("Call-ID: {token:08x}@{host}\r\n"))
            && put_sip_line(dst, &mut pos, &format!("CSeq: 1 {method}\r\n"));
    }

    dst[pos] = b'\r';
    dst[pos + 1] = b'\n';
    pos += 2;
    for byte in &mut dst[pos..] {
        *byte = b' ';
    }
    true
}

fn put_sip_line(dst: &mut [u8], pos: &mut usize, line: &str) -> bool {
    let add = line.len();
    if *pos + add + 2 > dst.len() {
        return false;
    }
    dst[*pos..*pos + add].copy_from_slice(line.as_bytes());
    *pos += add;
    true
}

fn fill_dns(dst: &mut [u8], trailing_size: usize, domain: Option<&str>, rng: &mut impl RngCore) {
    let size = dst.len();
    if size == 0 {
        return;
    }
    let total_len = size.saturating_add(trailing_size);

    if let Some(domain) = domain {
        let max_qname = size.saturating_sub(16);
        if let Some(name) = choose_dns_domain_qname(domain, max_qname, DNS_OPT_MIN_WIRE_SIZE, rng) {
            if emit_dns_domain(dst, total_len, &name, rng) {
                return;
            }
        }
    }

    if trailing_size > 0 && size >= 12 + 1 + 4 + DNS_OPT_MIN_WIRE_SIZE {
        let mut pos = write_dns_header(dst, rng);
        dst[pos] = 0x00;
        pos += 1;
        write_dns_question_tail(dst, &mut pos);
        if write_dns_opt_padding(dst, size, total_len, &mut pos, 10) {
            return;
        }
    }

    fill_dns_minimal_root_query(dst, rng);
}

fn emit_dns_domain(dst: &mut [u8], total_len: usize, name: &str, rng: &mut impl RngCore) -> bool {
    let qname_size = dns_qname_wire_size(name);
    if qname_size == 0 || dst.len() < 12 + qname_size + 4 + DNS_OPT_MIN_WIRE_SIZE {
        return false;
    }

    let mut pos = write_dns_header(dst, rng);
    if !write_dns_qname(dst, &mut pos, name) {
        return false;
    }
    write_dns_question_tail(dst, &mut pos);
    write_dns_opt_padding(dst, dst.len(), total_len, &mut pos, 10)
}

fn fill_dns_minimal_root_query(dst: &mut [u8], rng: &mut impl RngCore) {
    if dst.len() >= 2 {
        dst[0] = random_byte(rng);
        dst[1] = random_byte(rng);
    }
    if dst.len() >= 4 {
        // Flags 0x0120 (RD+AD): S-prefix DNS shaping matching wgbooster's
        // protocol-aware padding (Windows DNS Client); see write_dns_header.
        dst[2] = 0x01;
        dst[3] = 0x20;
    }
    if dst.len() >= 6 {
        dst[4] = 0x00;
        dst[5] = 0x01;
    }
    let header_tail_end = dst.len().min(12);
    if header_tail_end > 6 {
        for byte in &mut dst[6..header_tail_end] {
            *byte = 0x00;
        }
    }
    if dst.len() > 12 {
        dst[12] = 0x00;
    }
    if dst.len() > 13 {
        dst[13] = 0x00;
    }
    if dst.len() > 14 {
        dst[14] = 0x01;
    }
    if dst.len() > 15 {
        dst[15] = 0x00;
    }
    if dst.len() > 16 {
        dst[16] = 0x01;
    }
    if dst.len() > 17 {
        for byte in &mut dst[17..] {
            *byte = 0x00;
        }
    }
}

fn write_dns_header(dst: &mut [u8], rng: &mut impl RngCore) -> usize {
    dst[0] = random_byte(rng);
    dst[1] = random_byte(rng);
    // Flags 0x0120 (RD=1, AD=1): this is the S1-S4 prefix DNS shaping, which
    // faithfully matches wgbooster's `protocol_aware_padding_generator` (it sets
    // AD to mimic the Windows DNS Client). The standalone pre-handshake DNS
    // queries in `imitation::dns` deliberately use 0x0100 (RD only) instead, to
    // match wgbooster's live-query path (`simulate_browser_dns_resolution`).
    dst[2] = 0x01;
    dst[3] = 0x20;
    dst[4] = 0x00;
    dst[5] = 0x01;
    for byte in &mut dst[6..12] {
        *byte = 0x00;
    }
    12
}

fn write_dns_question_tail(dst: &mut [u8], pos: &mut usize) {
    dst[*pos] = 0x00;
    dst[*pos + 1] = 0x01;
    dst[*pos + 2] = 0x00;
    dst[*pos + 3] = 0x01;
    *pos += 4;
}

fn dns_qname_wire_size(name: &str) -> usize {
    if is_valid_imitation_host(name) {
        name.len() + 2
    } else {
        0
    }
}

fn write_dns_qname(dst: &mut [u8], pos: &mut usize, name: &str) -> bool {
    let wire_size = dns_qname_wire_size(name);
    if wire_size == 0 || *pos > dst.len() || wire_size > dst.len() - *pos {
        return false;
    }

    for label in name.split('.') {
        let label_len = label.len();
        if label_len == 0 || label_len > 63 || *pos + 1 + label_len > dst.len() {
            return false;
        }
        dst[*pos] = label_len as u8;
        *pos += 1;
        dst[*pos..*pos + label_len].copy_from_slice(label.as_bytes());
        *pos += label_len;
    }
    if *pos >= dst.len() {
        return false;
    }
    dst[*pos] = 0x00;
    *pos += 1;
    true
}

fn choose_dns_domain_qname(
    domain: &str,
    max_wire_size: usize,
    opt_reserve: usize,
    rng: &mut impl RngCore,
) -> Option<String> {
    if !is_valid_imitation_host(domain) {
        return None;
    }

    const PREFIXES: [&str; 5] = ["www", "api", "cdn", "dns", ""];
    let start = (rng.next_u32() as usize) % PREFIXES.len();
    let budgets = [
        if opt_reserve > 0 && opt_reserve <= max_wire_size {
            max_wire_size - opt_reserve
        } else {
            0
        },
        max_wire_size,
    ];

    for budget in budgets {
        if budget == 0 {
            continue;
        }
        for i in 0..PREFIXES.len() {
            let prefix = PREFIXES[(start + i) % PREFIXES.len()];
            let candidate = if prefix.is_empty() {
                domain.to_owned()
            } else {
                format!("{prefix}.{domain}")
            };
            let wire_size = dns_qname_wire_size(&candidate);
            if wire_size > 0 && wire_size <= budget {
                return Some(candidate);
            }
        }
    }

    None
}

fn write_dns_opt_padding(
    dst: &mut [u8],
    write_limit: usize,
    total_len: usize,
    pos: &mut usize,
    arcount_pos: usize,
) -> bool {
    if total_len < write_limit {
        return false;
    }
    if *pos > write_limit || write_limit - *pos < DNS_OPT_MIN_WIRE_SIZE {
        return false;
    }
    if arcount_pos >= write_limit.saturating_sub(1) {
        return false;
    }
    if total_len - *pos - DNS_OPT_FIXED_LEN > 0xffff {
        return false;
    }

    let option_code = if total_len > write_limit {
        0xfde9u16
    } else {
        0x000cu16
    };

    // EDNS(0) OPT pseudo-record: root NAME (0x00), TYPE=OPT (0x0029),
    // CLASS=requestor UDP payload size (0x1000), TTL=0 (extended RCODE/flags).
    dst[*pos] = 0x00;
    dst[*pos + 1] = 0x00;
    dst[*pos + 2] = 0x29;
    dst[*pos + 3] = 0x10;
    dst[*pos + 4] = 0x00;
    dst[*pos + 5] = 0x00;
    dst[*pos + 6] = 0x00;
    dst[*pos + 7] = 0x00;
    dst[*pos + 8] = 0x00;
    *pos += 9;

    let rdata_len = total_len - *pos - 2;
    dst[*pos] = ((rdata_len >> 8) & 0xff) as u8;
    dst[*pos + 1] = (rdata_len & 0xff) as u8;
    *pos += 2;

    let pad_value_len = rdata_len - 4;
    dst[*pos] = (option_code >> 8) as u8;
    dst[*pos + 1] = option_code as u8;
    dst[*pos + 2] = ((pad_value_len >> 8) & 0xff) as u8;
    dst[*pos + 3] = (pad_value_len & 0xff) as u8;
    *pos += 4;

    while *pos < write_limit {
        dst[*pos] = 0x00;
        *pos += 1;
    }

    dst[arcount_pos] = 0x00;
    dst[arcount_pos + 1] = 0x01;
    true
}

/// Permissive validation for a QUIC ClientHello SNI: unlike DNS QNAMEs and SIP
/// URIs, the SNI is a length-prefixed TLS extension, so UTF-8/IDN host names are
/// accepted (matching wgbooster). Only emptiness, the 253-byte RFC 1035 bound,
/// and control bytes (which never appear in a real SNI) are rejected.
fn is_valid_quic_sni(host: &str) -> bool {
    !host.is_empty() && host.len() <= 253 && !host.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn is_valid_imitation_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.starts_with('-')
        || host.ends_with('.')
        || host.ends_with('-')
    {
        return false;
    }

    let mut label_len = 0usize;
    let mut label_start = true;
    let mut previous_hyphen = false;

    for byte in host.bytes() {
        if byte == b'.' {
            if label_len == 0 || previous_hyphen {
                return false;
            }
            label_len = 0;
            label_start = true;
            previous_hyphen = false;
            continue;
        }

        if !(byte.is_ascii_alphanumeric() || byte == b'-') {
            return false;
        }
        if label_start && byte == b'-' {
            return false;
        }

        label_len += 1;
        if label_len > 63 {
            return false;
        }
        label_start = false;
        previous_hyphen = byte == b'-';
    }

    label_len > 0 && !previous_hyphen
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{COOKIE_REPLY, DATA, HANDSHAKE_INIT, HANDSHAKE_RESP};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

    fn write_tag(packet: &mut [u8], tag: u32) {
        packet[..4].copy_from_slice(&tag.to_le_bytes());
    }

    fn packet_after_prepend(
        cfg: &AmneziaConfig,
        packet_size: usize,
        tag: u32,
        capacity: usize,
    ) -> Vec<u8> {
        let obf = ObfuscationRanges::default();
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut buffer = vec![0u8; capacity];
        write_tag(&mut buffer, tag);
        buffer[4] = 0x42;

        cfg.prepend_outbound(obf, &mut buffer, packet_size, &mut rng)
            .unwrap()
            .to_vec()
    }

    #[test]
    fn random_trailers_require_equal_s_prefixes_with_disjoint_h_ranges() {
        // This profile reproduces the structural ambiguity in upstream issue
        // #186: the transport type at S4 can be re-read as a control tag at S2.
        let obf = ObfuscationRanges::new(
            405_138_553,
            456_138_212,
            680_931_238,
            1_038_459_501,
            1_114_423_399,
            1_432_068_193,
            1_500_000_000,
            1_500_000_000,
        )
        .expect("all H ranges are disjoint");

        let unequal = AmneziaConfig::new(97, 41, 133, 24).with_random_trailers(true);
        let error = unequal
            .validate_random_trailers(obf)
            .expect_err("different offsets can misclassify valid transport packets");
        assert!(error.contains("S1 = S2 = S3 = S4"));
        assert!(error.contains("RandomTrailers"));

        let equal = AmneziaConfig::new(24, 24, 24, 24).with_random_trailers(true);
        equal
            .validate_random_trailers(obf)
            .expect("equal offsets plus disjoint H ranges make classification unambiguous");
    }

    #[test]
    fn equal_s_prefixes_keep_transport_tags_out_of_handshake_classifiers() {
        let obf = ObfuscationRanges::new(
            405_138_553,
            456_138_212,
            680_931_238,
            1_038_459_501,
            1_114_423_399,
            1_432_068_193,
            1_500_000_000,
            1_500_000_000,
        )
        .expect("all H ranges are disjoint");
        let cfg = AmneziaConfig::new(24, 24, 24, 24).with_random_trailers(true);
        let transport_tag = 1_500_000_000u32;
        let response_tag = 700_000_000u32;
        let mut packet = vec![0u8; 376];
        packet[24..28].copy_from_slice(&transport_tag.to_le_bytes());
        // This is where an unequal S2=41 classifier would look and falsely
        // see a valid H2 response tag. Equal S values never inspect this offset.
        packet[41..45].copy_from_slice(&response_tag.to_le_bytes());

        let stripped = cfg
            .strip_inbound(obf, &packet)
            .expect("transport must be classified using the common S offset");
        assert_eq!(&stripped[..4], &transport_tag.to_le_bytes());
    }

    #[test]
    fn random_trailers_are_clamped_to_destination_capacity() {
        let cfg = AmneziaConfig::new(12, 12, 12, 12).with_random_trailers(true);
        let mut rng = ChaCha8Rng::seed_from_u64(0xCAFE);
        let mut buffer = vec![0u8; HANDSHAKE_INIT_SZ + 12 + 10];
        write_tag(&mut buffer, HANDSHAKE_INIT);
        let wire = cfg
            .prepend_outbound(
                ObfuscationRanges::default(),
                &mut buffer,
                HANDSHAKE_INIT_SZ,
                &mut rng,
            )
            .expect("optional trailer must be shortened to fit the caller's buffer");
        assert!(wire.len() <= HANDSHAKE_INIT_SZ + 12 + 10);
        assert!(wire.len() >= HANDSHAKE_INIT_SZ + 12);
    }

    #[test]
    fn random_trailers_roundtrip_handshake_and_cookie_packets() {
        let obf = ObfuscationRanges::default();
        for (tag, base_size) in [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
        ] {
            let cfg = AmneziaConfig::new(12, 12, 12, 12).with_random_trailers(true);
            let mut rng = ChaCha8Rng::seed_from_u64(0xA11CE);
            let mut buffer = vec![0u8; DEFAULT_UDP_WINDOW];
            write_tag(&mut buffer, tag);
            buffer[4] = 0x42;

            let wire = cfg
                .prepend_outbound(obf, &mut buffer, base_size, &mut rng)
                .expect("packet fits")
                .to_vec();
            assert!(wire.len() > base_size + expected_junk(&cfg, tag));
            assert!(wire.len() < DEFAULT_UDP_WINDOW);

            let recovered = cfg.strip_inbound(obf, &wire).expect("trailer is accepted");
            assert_eq!(recovered.len(), base_size);
            assert_eq!(recovered[4], 0x42);
        }
    }

    #[test]
    fn cookie_random_trailer_is_bounded_by_triggering_request() {
        let cfg = AmneziaConfig::new(12, 12, 12, 12).with_random_trailers(true);
        let mut rng = ChaCha8Rng::seed_from_u64(0xC001);
        let mut buffer = vec![0u8; 512];
        write_tag(&mut buffer, COOKIE_REPLY);
        let wire = cfg
            .prepend_outbound_with_limits(
                ObfuscationRanges::default(),
                &mut buffer,
                COOKIE_REPLY_SZ,
                DEFAULT_UDP_WINDOW,
                92,
                &mut rng,
            )
            .expect("bounded cookie reply fits")
            .to_vec();
        assert!(wire.len() <= 92);
        assert_eq!(
            cfg.strip_inbound(ObfuscationRanges::default(), &wire)
                .expect("cookie with trailer is accepted")
                .len(),
            COOKIE_REPLY_SZ
        );
    }

    #[test]
    fn random_trailer_matches_upstream_exclusive_window_and_all_limits() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_random_trailers(true);
        let mut rng = ChaCha8Rng::seed_from_u64(0x7A11);

        // Upstream fastrandn(udpWindow - packetSize) selects [0, space),
        // not an inclusive endpoint. Exercise the exact upper bound and
        // intersecting request, UDP-window and output-buffer limits.
        for _ in 0..4096 {
            let trailer = cfg.random_trailer_len(80, 500, 120, &mut rng);
            assert!(trailer < 40, "request limit must cap the exclusive range");
            assert!(80 + trailer <= 120);
            assert!(80 + trailer <= 500);

            let trailer = cfg.random_trailer_len(80, 100, 500, &mut rng);
            assert!(trailer < 20, "peer UDP window must cap the exclusive range");

            let trailer = cfg.random_trailer_len(80, 500, 500, &mut rng);
            assert!(trailer < 420, "default peer window is exclusive");
        }

        assert_eq!(
            cfg.random_trailer_len(80, 80, 500, &mut rng),
            0,
            "no room in peer window means no trailer"
        );
        assert_eq!(
            cfg.random_trailer_len(80, 500, 80, &mut rng),
            0,
            "no room in caller datagram limit means no trailer"
        );
        assert_eq!(
            AmneziaConfig::new(0, 0, 0, 0).random_trailer_len(80, 500, 120, &mut rng),
            0,
            "disabled RandomTrailers must not consume space"
        );
    }

    #[test]
    fn random_transport_padding_respects_content_padding_precedence_and_mtu() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xBEEF);
        let random = AmneziaConfig::new(0, 0, 0, 0).with_random_trailers(true);
        let packet_size = 80;
        let padding = random.transport_padding_size(
            packet_size - DATA_OVERHEAD_SZ,
            packet_size,
            500,
            &mut rng,
        );
        assert!(padding < 500 - packet_size);
        assert!(packet_size + padding <= 500);

        let explicit = AmneziaConfig::new(0, 0, 0, 0)
            .with_random_trailers(true)
            .with_content_padding_addition(7, 7);
        assert_eq!(
            explicit.transport_padding_size(
                packet_size - DATA_OVERHEAD_SZ,
                packet_size,
                500,
                &mut rng,
            ),
            7,
            "ContentPaddingAddition takes precedence over RandomTrailers"
        );
    }

    #[test]
    fn content_padding_range_mapper_is_inclusive_and_rejects_modulo_bias_tail() {
        let min = 7u32;
        let max = 16u32;
        let width = u64::from(max) - u64::from(min) + 1;
        let zone = (1u64 << 32) / width * width;

        assert_eq!(
            AmneziaConfig::map_content_padding_sample(min, max, 0),
            Some(7)
        );
        assert_eq!(
            AmneziaConfig::map_content_padding_sample(min, max, (zone - 1) as u32),
            Some(16),
            "the last accepted sample must map to the inclusive maximum"
        );
        assert_eq!(
            AmneziaConfig::map_content_padding_sample(min, max, zone as u32),
            None,
            "the first value in the modulo-bias tail must be rejected"
        );
        assert_eq!(
            AmneziaConfig::map_content_padding_sample(0, u32::MAX, 0),
            Some(0),
            "the full u32 CPA range must not overflow"
        );
        let full_zone = 1u64 << 32;
        assert_eq!(
            AmneziaConfig::map_content_padding_sample(0, u32::MAX, (full_zone - 1) as u32),
            Some(u32::MAX as usize),
            "the final full-range sample must reach the maximum"
        );
        assert_eq!(
            AmneziaConfig::map_content_padding_sample(9, 9, 0),
            Some(9),
            "singleton ranges must remain deterministic"
        );
        assert_eq!(AmneziaConfig::map_content_padding_sample(10, 9, 0), None);
    }

    #[test]
    fn content_padding_addition_is_inclusive_and_clamped_to_udp_window() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xC0FFEE);
        let ranged = AmneziaConfig::new(0, 0, 0, 0).with_content_padding_addition(4, 12);

        for _ in 0..256 {
            let padding = ranged.content_padding_size(100, 132, 500, &mut rng);
            assert!(
                (4..=12).contains(&padding),
                "selected ContentPaddingAddition {padding} outside inclusive range 4..=12"
            );
        }

        let fixed_max = AmneziaConfig::new(0, 0, 0, 0).with_content_padding_addition(12, 12);
        assert_eq!(
            fixed_max.content_padding_size(100, 132, 500, &mut rng),
            12,
            "the configured maximum is inclusive"
        );
        assert_eq!(
            ranged.content_padding_size(100, 495, 500, &mut rng),
            5,
            "padding is clamped to the remaining UDP window"
        );
        assert_eq!(
            ranged.content_padding_size(100, 500, 500, &mut rng),
            0,
            "a full UDP window leaves no room for padding"
        );
        assert_eq!(
            ranged.content_padding_size(0, 32, 500, &mut rng),
            0,
            "empty keepalives must not receive content padding"
        );
    }

    fn expected_junk(cfg: &AmneziaConfig, tag: u32) -> usize {
        let size = match tag {
            HANDSHAKE_INIT => cfg.init_packet_junk_size,
            HANDSHAKE_RESP => cfg.response_packet_junk_size,
            COOKIE_REPLY => cfg.cookie_packet_junk_size,
            DATA => cfg.transport_packet_junk_size,
            _ => unreachable!(),
        };
        size as usize
    }

    /// For every packet kind, S-size combination, and imitation protocol, a
    /// packet that is prefixed by `prepend_outbound` must be recovered exactly
    /// by `strip_inbound`. This is the core invariant the wire protocol relies
    /// on, and it exercises every protocol-shaped filler against the stripper.
    #[test]
    fn prepend_then_strip_roundtrips_across_configs_and_protocols() {
        use AmneziaImitationProtocol::*;

        let obf = ObfuscationRanges::default();
        let kinds: [(u32, usize); 4] = [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 48),
        ];
        let bases = [
            AmneziaConfig::new(7, 11, 13, 17),
            AmneziaConfig::new(1, 1, 1, 1),
            AmneziaConfig::new(64, 0, 0, 200),
        ];

        for base in bases {
            for protocol in [None, Dns, Quic, Sip, Stun] {
                let cfg = base
                    .clone()
                    .with_protocol_imitation(protocol, Some("example.com".to_owned()));
                let mut rng = ChaCha8Rng::seed_from_u64(0xA53);

                for &(tag, base_size) in &kinds {
                    let mut original = vec![0u8; base_size];
                    write_tag(&mut original, tag);
                    for (i, byte) in original[4..].iter_mut().enumerate() {
                        *byte = (i as u8) ^ 0x5a;
                    }

                    let mut buffer = vec![0u8; base_size + 1280];
                    buffer[..base_size].copy_from_slice(&original);
                    let padded = cfg
                        .prepend_outbound(obf, &mut buffer, base_size, &mut rng)
                        .unwrap()
                        .to_vec();

                    let junk = expected_junk(&cfg, tag);
                    assert_eq!(
                        padded.len(),
                        base_size + junk,
                        "unexpected padded size: protocol={protocol:?} tag={tag} junk={junk}"
                    );

                    // Every shape produced by prepend_outbound must be accepted:
                    // this is the property that makes the stricter filter safe.
                    let stripped = cfg.strip_inbound(obf, &padded);
                    assert_eq!(
                        stripped,
                        Some(original.as_slice()),
                        "roundtrip mismatch: protocol={protocol:?} tag={tag} junk={junk}"
                    );
                }
            }
        }
    }

    /// What our own outbound cover traffic looks like to the probe detector.
    ///
    /// This table is the reason a server must classify AmneziaWG *before* it
    /// considers answering a probe. Three properties, all observed rather than
    /// assumed -- the verdicts were printed first and locked in afterwards:
    ///
    /// 1. **No cross-protocol confusion.** Across every protocol x packet kind
    ///    x S-size combination, the verdict is either `None` or the protocol we
    ///    configured. Our DNS cover traffic is never mistaken for STUN, and so
    ///    on. This is the safety property and it holds unconditionally.
    ///
    /// 2. **DNS and SIP cover traffic is detected as a probe.** At realistic S
    ///    sizes -- the installer rolls S1-S4 in 15..150 -- a datagram we emit
    ///    under `ip=dns` is a well-formed DNS query, because `fill_dns` frames
    ///    the WireGuard ciphertext inside an EDNS OPT padding option. A server
    ///    that asked "is this a probe?" first would answer its own clients
    ///    instead of handshaking with them, and would do so *more* often the
    ///    better the imitation became.
    ///
    /// 3. **QUIC and STUN are never self-detected**, and both are structural
    ///    rather than incidental:
    ///    - `fill_quic_short` writes a 1-RTT short header, so the leading two
    ///      bits are `0b01` and the long-header test cannot fire.
    ///    - `fill_stun` frames `msg_len` over the junk region only, while the
    ///      datagram continues with the WireGuard packet, so the detector's
    ///      `len == 20 + msg_len` check fails.
    ///
    ///    Both are worth pinning: this test fails the day someone extends
    ///    `fill_stun` to frame the whole datagram, or reverts S2/S3 to a QUIC
    ///    long header -- changes that would look like fidelity improvements
    ///    while silently making the server answer its own peers.
    #[test]
    fn our_cover_traffic_is_detected_as_the_protocol_we_imitate() {
        use crate::noise::imitation::detect::{detect, Probe};
        use AmneziaImitationProtocol::*;

        let obf = ObfuscationRanges::default();
        let kinds: [(u32, usize); 4] = [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 48),
        ];
        // The last entry mirrors what `amneziawg-install` actually generates.
        let bases = [
            AmneziaConfig::new(7, 11, 13, 17),
            AmneziaConfig::new(1, 1, 1, 1),
            AmneziaConfig::new(64, 0, 0, 200),
            AmneziaConfig::new(120, 130, 110, 80),
        ];

        let mut self_detected = 0usize;

        for base in &bases {
            for protocol in [None, Dns, Quic, Sip, Stun] {
                let cfg = base
                    .clone()
                    .with_protocol_imitation(protocol, Some("example.com".to_owned()));
                let mut rng = ChaCha8Rng::seed_from_u64(0xA53);

                for &(tag, base_size) in &kinds {
                    let mut buffer = vec![0u8; base_size + 1280];
                    write_tag(&mut buffer, tag);
                    let padded = cfg
                        .prepend_outbound(obf, &mut buffer, base_size, &mut rng)
                        .unwrap()
                        .to_vec();
                    let junk = expected_junk(&cfg, tag);
                    let verdict = detect(&padded);

                    // Checked before the generic cross-protocol assertion
                    // below, which would otherwise fire first here and report
                    // "cover traffic for None detected as Dns" -- true, but a
                    // worse description of the failure than this one. Random
                    // junk resembling any probe means the detector is too
                    // loose, and that is what a reader needs told.
                    if protocol == None {
                        assert!(
                            verdict.is_none(),
                            "random junk was detected as {:?} (junk={}, tag={})",
                            verdict,
                            junk,
                            tag
                        );
                    }

                    // (1) never a *different* protocol.
                    if let Some(p) = verdict {
                        assert!(
                            p.is(protocol),
                            "cover traffic for {:?} detected as {:?} (junk={}, tag={})",
                            protocol,
                            p,
                            junk,
                            tag
                        );
                        self_detected += 1;
                    }

                    // (3) QUIC and STUN never frame the whole datagram.
                    if matches!(protocol, Quic | Stun) {
                        assert!(
                            verdict.is_none(),
                            "{:?} imitation became self-detecting (junk={}, tag={}); see this test's doc comment before changing it",
                            protocol,
                            junk,
                            tag
                        );
                    }
                }
            }
        }

        // (2) the hazard is real, not hypothetical: at installer-realistic S
        // sizes every DNS and SIP datagram we emit is a valid probe. Asserted
        // as a count so the test fails if imitation quietly stops working, not
        // only if it starts misfiring.
        let realistic = AmneziaConfig::new(120, 130, 110, 80);
        for protocol in [Dns, Sip] {
            let cfg = realistic
                .clone()
                .with_protocol_imitation(protocol, Some("example.com".to_owned()));
            let mut rng = ChaCha8Rng::seed_from_u64(0xA53);
            for &(tag, base_size) in &kinds {
                let mut buffer = vec![0u8; base_size + 1280];
                write_tag(&mut buffer, tag);
                let padded = cfg
                    .prepend_outbound(obf, &mut buffer, base_size, &mut rng)
                    .unwrap()
                    .to_vec();
                let verdict = detect(&padded);
                assert!(
                    verdict.is_some_and(|p| p.is(protocol)),
                    "{:?} cover traffic at realistic S sizes must be self-detecting, got {:?} (tag={})",
                    protocol,
                    verdict,
                    tag
                );
            }
        }

        // Actual is 13 across the four S configurations. The bound guards
        // against imitation regressing toward zero, so it sits well below that
        // rather than one step under it -- a threshold of 12 would fail on any
        // legitimate change that drops a single combination.
        assert!(
            self_detected >= 8,
            "expected our cover traffic to be probe-shaped in many cases, saw only {}; if imitation regressed this is where it shows",
            self_detected
        );
        let _: fn(&[u8]) -> Option<Probe> = detect;
    }

    /// The full input matrix for `strip_inbound`, written before the change
    /// that made it fallible rather than after. The risk of that change is
    /// dropping *valid* traffic, so every configuration shape is enumerated:
    /// all-zero (plain WireGuard), fully padded, and mixed.
    #[test]
    fn strip_inbound_accepts_every_conforming_shape_and_rejects_the_rest() {
        let obf = ObfuscationRanges::default();

        // --- all S zero: must behave exactly like plain WireGuard ---------
        let vanilla = AmneziaConfig::new(0, 0, 0, 0);
        for (tag, size) in [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 48),
        ] {
            let mut p = vec![0xaa; size];
            write_tag(&mut p, tag);
            assert_eq!(
                vanilla.strip_inbound(obf, &p).map(|d| d.len()),
                Some(size),
                "vanilla must accept tag {:#x} unchanged",
                tag
            );
        }
        // Too short to be anything, and a tag that matches no range.
        assert_eq!(vanilla.strip_inbound(obf, &[0u8; 10]), None);
        let mut bogus = vec![0xaa; HANDSHAKE_INIT_SZ];
        write_tag(&mut bogus, 0x5555_5555);
        assert_eq!(vanilla.strip_inbound(obf, &bogus), None, "unknown tag");

        // --- every S configured -------------------------------------------
        let padded = AmneziaConfig::new(120, 130, 110, 80);
        for (tag, size, junk) in [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ, 120usize),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ, 130),
            (COOKIE_REPLY, COOKIE_REPLY_SZ, 110),
            (DATA, DATA_OVERHEAD_SZ + 48, 80),
        ] {
            let mut p = vec![0xaa; junk + size];
            write_tag(&mut p[junk..], tag);
            assert_eq!(
                padded.strip_inbound(obf, &p).map(|d| d.len()),
                Some(size),
                "padded tag {:#x} must strip to its base size",
                tag
            );

            // The same packet *unpadded* is not ours and must be rejected.
            let mut bare = vec![0xaa; size];
            write_tag(&mut bare, tag);
            assert_eq!(
                padded.strip_inbound(obf, &bare),
                None,
                "unpadded tag {:#x} must be dropped when its S is configured",
                tag
            );
        }

        // --- mixed: S1 set, S4 zero ----------------------------------------
        let mixed = AmneziaConfig::new(15, 0, 0, 0);
        let mut init = vec![0xaa; 15 + HANDSHAKE_INIT_SZ];
        write_tag(&mut init[15..], HANDSHAKE_INIT);
        assert_eq!(
            mixed.strip_inbound(obf, &init).map(|d| d.len()),
            Some(HANDSHAKE_INIT_SZ)
        );
        // S4 = 0, so unpadded transport is still the conforming shape and must
        // keep working. This is the case a naive 'reject anything unpadded'
        // would break.
        let mut data = vec![0xaa; DATA_OVERHEAD_SZ + 16];
        write_tag(&mut data, DATA);
        assert_eq!(
            mixed.strip_inbound(obf, &data).map(|d| d.len()),
            Some(DATA_OVERHEAD_SZ + 16),
            "S4 = 0 means unpadded transport is conforming"
        );
        // But an unpadded init is not, because S1 is set.
        let mut bare_init = vec![0xaa; HANDSHAKE_INIT_SZ];
        write_tag(&mut bare_init, HANDSHAKE_INIT);
        assert_eq!(mixed.strip_inbound(obf, &bare_init), None);
    }

    #[test]
    fn strips_inbound_s1_to_s4_when_magic_matches() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(7, 11, 13, 17);

        let mut init = vec![0xaa; cfg.init_packet_junk_size as usize + HANDSHAKE_INIT_SZ];
        write_tag(
            &mut init[cfg.init_packet_junk_size as usize..],
            HANDSHAKE_INIT,
        );
        assert_eq!(
            cfg.strip_inbound(obf, &init).map(|d| d.len()),
            Some(HANDSHAKE_INIT_SZ)
        );

        let mut resp = vec![0xaa; cfg.response_packet_junk_size as usize + HANDSHAKE_RESP_SZ];
        write_tag(
            &mut resp[cfg.response_packet_junk_size as usize..],
            HANDSHAKE_RESP,
        );
        assert_eq!(
            cfg.strip_inbound(obf, &resp).map(|d| d.len()),
            Some(HANDSHAKE_RESP_SZ)
        );

        let mut cookie = vec![0xaa; cfg.cookie_packet_junk_size as usize + COOKIE_REPLY_SZ];
        write_tag(
            &mut cookie[cfg.cookie_packet_junk_size as usize..],
            COOKIE_REPLY,
        );
        assert_eq!(
            cfg.strip_inbound(obf, &cookie).map(|d| d.len()),
            Some(COOKIE_REPLY_SZ)
        );

        let mut data = vec![0xaa; cfg.transport_packet_junk_size as usize + DATA_OVERHEAD_SZ + 8];
        write_tag(&mut data[cfg.transport_packet_junk_size as usize..], DATA);
        assert_eq!(
            cfg.strip_inbound(obf, &data).map(|d| d.len()),
            Some(DATA_OVERHEAD_SZ + 8)
        );
    }

    #[test]
    fn rejects_inbound_packet_whose_magic_does_not_match_its_shape() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(7, 11, 13, 17);
        let mut resp = vec![0xaa; cfg.response_packet_junk_size as usize + HANDSHAKE_RESP_SZ];
        write_tag(&mut resp[cfg.response_packet_junk_size as usize..], DATA);

        // The size says handshake response, the tag says transport data: it
        // matches no configured shape. Previously this was handed back for
        // the caller to reject; rejecting it here is the same outcome reached
        // one layer earlier, and without a second chance to be misread.
        assert_eq!(cfg.strip_inbound(obf, &resp), None);
    }

    #[test]
    fn rejects_unpadded_transport_when_s4_is_configured() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(0, 0, 0, 17);
        let mut data = vec![0xaa; DATA_OVERHEAD_SZ + 32];
        write_tag(&mut data, DATA);

        // S4 is configured, so a conforming peer always pads. Handing this
        // back would let the caller re-read the tag at offset 0 and accept
        // it, which is the filtering gap this rejection closes.
        assert_eq!(cfg.strip_inbound(obf, &data), None);
    }

    #[test]
    fn strips_padded_transport_when_junk_prefix_also_looks_like_h4() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(0, 0, 0, 17);
        let junk_size = cfg.transport_packet_junk_size as usize;
        let mut data = vec![0xaa; junk_size + DATA_OVERHEAD_SZ + 32];

        write_tag(&mut data, DATA);
        write_tag(&mut data[junk_size..], DATA);
        data[junk_size + 4] = 0x42;

        let stripped = cfg.strip_inbound(obf, &data);

        assert_eq!(stripped, Some(&data[junk_size..]));
    }

    #[test]
    fn prepends_outbound_junk_for_matching_packet_type() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(7, 11, 13, 17);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut buffer = vec![0u8; HANDSHAKE_INIT_SZ + 64];
        write_tag(&mut buffer, HANDSHAKE_INIT);
        buffer[4] = 0x42;

        let packet = cfg
            .prepend_outbound(obf, &mut buffer, HANDSHAKE_INIT_SZ, &mut rng)
            .unwrap();

        assert_eq!(packet.len(), HANDSHAKE_INIT_SZ + 7);
        assert_eq!(&packet[7..11], &HANDSHAKE_INIT.to_le_bytes());
        assert_eq!(packet[11], 0x42);
    }

    #[test]
    fn validate_accepts_sizes_that_fit_and_rejects_those_that_cannot() {
        // Junk + base packet must fit in one sendable UDP datagram
        // (MAX_SENDABLE_DATAGRAM = 65507, the IPv4 payload limit) -- not the
        // 65535 protocol ceiling the kernel module bounds by.
        assert!(AmneziaConfig::new(0, 0, 0, 0).validate().is_ok());
        assert!(AmneziaConfig::new(1000, 1000, 1000, 1000)
            .validate()
            .is_ok());

        // Exactly at the limit for each packet type.
        let max_s1 = (MAX_SENDABLE_DATAGRAM - HANDSHAKE_INIT_SZ) as u16;
        let max_s2 = (MAX_SENDABLE_DATAGRAM - HANDSHAKE_RESP_SZ) as u16;
        let max_s3 = (MAX_SENDABLE_DATAGRAM - COOKIE_REPLY_SZ) as u16;
        let max_s4 = (MAX_SENDABLE_DATAGRAM - DATA_OVERHEAD_SZ) as u16;
        assert!(AmneziaConfig::new(max_s1, max_s2, max_s3, max_s4)
            .validate()
            .is_ok());

        // One byte over, each in turn.
        for (cfg, want) in [
            (AmneziaConfig::new(max_s1 + 1, 0, 0, 0), "S1"),
            (AmneziaConfig::new(0, max_s2 + 1, 0, 0), "S2"),
            (AmneziaConfig::new(0, 0, max_s3 + 1, 0), "S3"),
            (AmneziaConfig::new(0, 0, 0, max_s4 + 1), "S4"),
        ] {
            let err = cfg.validate().expect_err("must be rejected");
            assert!(err.contains(want), "error should name {}: {}", want, err);
        }
    }

    #[test]
    fn validate_rejects_sizes_that_fit_the_protocol_but_not_a_udp_datagram() {
        // The protocol ceiling is 65535, but an IPv4 UDP payload tops out at
        // 65535 - 20 - 8 = 65507. Sizes in between pass the kernel module's
        // check and then fail at send time with EMSGSIZE, so they must be
        // rejected here rather than accepted into a tunnel that never works.
        const PROTOCOL_MAX: usize = 65535;
        assert_eq!(MAX_SENDABLE_DATAGRAM, 65507);

        // For each field: the size the protocol ceiling alone would allow.
        let cases = [
            ("S1", HANDSHAKE_INIT_SZ, 0usize),
            ("S2", HANDSHAKE_RESP_SZ, 1),
            ("S3", COOKIE_REPLY_SZ, 2),
            ("S4", DATA_OVERHEAD_SZ, 3),
        ];

        for (label, base, slot) in cases {
            let over = (PROTOCOL_MAX - base) as u16;
            let mut s = [0u16; 4];
            s[slot] = over;
            let cfg = AmneziaConfig::new(s[0], s[1], s[2], s[3]);

            let err = cfg.validate().expect_err(&format!(
                "{}={} yields a {}-byte datagram, unsendable over IPv4",
                label,
                over,
                over as usize + base
            ));
            assert!(err.contains(label), "error should name {}: {}", label, err);
        }
    }

    #[test]
    fn validated_max_size_actually_round_trips_through_prepend_outbound() {
        // The bound is only meaningful if the largest accepted configuration can
        // still emit a packet -- otherwise validate() would be off by one.
        let obf = ObfuscationRanges::default();
        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let max_s1 = (MAX_SENDABLE_DATAGRAM - HANDSHAKE_INIT_SZ) as u16;
        let cfg = AmneziaConfig::new(max_s1, 0, 0, 0);
        cfg.validate().unwrap();

        let mut buffer = vec![0u8; MAX_SENDABLE_DATAGRAM];
        write_tag(&mut buffer, HANDSHAKE_INIT);

        let packet = cfg
            .prepend_outbound(obf, &mut buffer, HANDSHAKE_INIT_SZ, &mut rng)
            .expect("largest validated S1 must still fit");
        assert_eq!(packet.len(), MAX_SENDABLE_DATAGRAM);
    }

    /// [`AmneziaConfig::cookie_reply_len`] must agree with the length
    /// `prepend_outbound` actually produces, for every S3 from zero to the
    /// largest `validate` admits.
    ///
    /// The ingress path predicts the length so it can refuse an amplifying
    /// cookie reply *without* paying to generate its junk. A prediction that
    /// ran low would let the amplifier through; one that ran high would silence
    /// cookie replies for a configuration that is not an amplifier at all. Both
    /// are silent, so the two are pinned to each other here rather than left to
    /// agree by inspection.
    #[test]
    fn the_predicted_cookie_reply_length_is_the_one_actually_produced() {
        let max_s3 = (MAX_SENDABLE_DATAGRAM - COOKIE_REPLY_SZ) as u16;
        for s3 in [0u16, 1, 110, 1280, max_s3] {
            // S1 and S2 are derived rather than zeroed: `validate` now refuses a
            // cookie reply larger than the packet provoking it, so a bare
            // `new(0, 0, max_s3, 0)` is no longer a configuration an operator
            // could set, and asserting against it would be testing the
            // prediction on a config that cannot exist. These are the smallest
            // values that keep each S3 legal.
            let cfg = AmneziaConfig::new(s3.saturating_sub(84), s3.saturating_sub(28), s3, 0);
            cfg.validate().expect("S3 within the validated range");

            let produced = packet_after_prepend(
                &cfg,
                COOKIE_REPLY_SZ,
                COOKIE_REPLY,
                COOKIE_REPLY_SZ + s3 as usize,
            )
            .len();

            assert_eq!(
                cfg.cookie_reply_len(COOKIE_REPLY_SZ),
                produced,
                "S3 = {}: predicted length must match the datagram prepend_outbound emits",
                s3
            );
        }
    }

    #[test]
    fn quic_imitation_uses_short_header_for_every_packet_kind() {
        let cfg = AmneziaConfig::new(8, 9, 10, 11)
            .with_protocol_imitation(AmneziaImitationProtocol::Quic, None);

        // Every S-region is a 1-RTT short header: form bit clear, fixed bit
        // set. A long header would carry a length field that cannot frame the
        // WireGuard packet that follows, and S2/S3 are far below the 1200-byte
        // minimum a valid Initial requires (RFC 9000 §14.1).
        let cases = [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 4),
        ];

        for (tag, packet_size) in cases {
            let junk_size = expected_junk(&cfg, tag);
            let packet = packet_after_prepend(&cfg, packet_size, tag, packet_size + 64);

            assert_eq!(
                packet[0] & 0xc0,
                0x40,
                "tag={:#x} must use a 1-RTT short header, got first byte {:#04x}",
                tag,
                packet[0]
            );
            assert_eq!(
                &packet[junk_size..junk_size + 4],
                &tag.to_le_bytes(),
                "tag={:#x} payload must start right after the junk prefix",
                tag
            );
        }
    }

    #[test]
    fn quic_pre_handshake_junk_keeps_long_header_initial_at_rfc_minimum_size() {
        // The Jc path is the one place a long-header Initial is legal: it is a
        // standalone client->server datagram and its size is drawn from
        // QUIC_JUNK_SIZE_MIN..=MAX, which starts at the RFC 9000 §14.1 minimum.
        // Deliberately an independent literal rather than QUIC_JUNK_SIZE_MIN:
        // this is an external requirement imposed by the RFC, and the point of
        // the test is that our constant satisfies it. Asserting against
        // QUIC_JUNK_SIZE_MIN would be tautological, since the junk length is
        // drawn from that very constant.
        const RFC9000_MIN_INITIAL_DATAGRAM: usize = 1200;
        // A `const` block, so this is a compile error rather than a test
        // failure: both sides are constants, so there is nothing to wait until
        // runtime for. That also costs the formatted message -- `assert!` in a
        // const context takes a literal only -- so the two values are named in
        // the text instead.
        const {
            assert!(
                QUIC_JUNK_SIZE_MIN >= RFC9000_MIN_INITIAL_DATAGRAM,
                "QUIC_JUNK_SIZE_MIN must not drop below 1200, the RFC 9000 \
                 §14.1 minimum, or the Jc path emits invalid Initials"
            )
        };

        let cfg = AmneziaConfig::new(0, 0, 0, 0)
            .with_pre_handshake_junk(1, 0, 0, 0)
            .with_protocol_imitation(AmneziaImitationProtocol::Quic, None);
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut buffer = vec![0u8; QUIC_JUNK_SIZE_MAX];

        let junk = cfg.fill_pre_handshake_junk(&mut buffer, &mut rng).unwrap();

        assert!(
            junk.len() >= RFC9000_MIN_INITIAL_DATAGRAM,
            "a long-header Initial needs a >={} byte datagram, got {}",
            RFC9000_MIN_INITIAL_DATAGRAM,
            junk.len()
        );
        assert_eq!(junk[0] & 0xc0, 0xc0, "long header form + fixed bit");
        assert_eq!(&junk[1..5], &[0x00, 0x00, 0x00, 0x01], "QUIC v1");
    }

    #[test]
    fn dns_imitation_wraps_trailing_wireguard_payload_in_opt_record() {
        let cfg = AmneziaConfig::new(0, 0, 0, 64).with_protocol_imitation(
            AmneziaImitationProtocol::Dns,
            Some("example.com".to_owned()),
        );

        let packet = packet_after_prepend(&cfg, DATA_OVERHEAD_SZ + 8, DATA, DATA_OVERHEAD_SZ + 128);
        let prefix = &packet[..64];
        assert_eq!(&prefix[10..12], &[0x00, 0x01]);

        let mut pos = 12usize;
        while prefix[pos] != 0 {
            pos += 1 + prefix[pos] as usize;
        }
        pos += 1 + 4;
        assert_eq!(prefix[pos], 0x00);
        assert_eq!(&prefix[pos + 1..pos + 3], &[0x00, 0x29]);

        let rdlen = u16::from_be_bytes([prefix[pos + 9], prefix[pos + 10]]) as usize;
        assert_eq!(rdlen, packet.len() - pos - DNS_OPT_FIXED_LEN);
    }

    #[test]
    fn sip_imitation_reuses_valid_configured_domain_when_it_fits() {
        let cfg = AmneziaConfig::new(96, 0, 0, 0).with_protocol_imitation(
            AmneziaImitationProtocol::Sip,
            Some("example.com".to_owned()),
        );

        let packet = packet_after_prepend(
            &cfg,
            HANDSHAKE_INIT_SZ,
            HANDSHAKE_INIT,
            HANDSHAKE_INIT_SZ + 128,
        );
        let prefix = std::str::from_utf8(&packet[..96]).unwrap();
        assert!(
            prefix.starts_with("OPTIONS")
                || prefix.starts_with("REGISTER")
                || prefix.starts_with("MESSAGE")
        );
        assert!(prefix.contains("sip:"));
        assert!(prefix.contains("example.com"));
    }

    #[test]
    fn stun_imitation_emits_binding_request_prefix() {
        let cfg = AmneziaConfig::new(0, 0, 0, 40)
            .with_protocol_imitation(AmneziaImitationProtocol::Stun, None);

        let packet = packet_after_prepend(&cfg, DATA_OVERHEAD_SZ + 4, DATA, DATA_OVERHEAD_SZ + 64);
        let prefix = &packet[..40];
        assert_eq!(&prefix[..2], &[0x00, 0x01]);
        assert_eq!(&prefix[4..8], &[0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(u16::from_be_bytes([prefix[2], prefix[3]]) % 4, 0);
    }

    #[test]
    fn pre_handshake_junk_allows_fixed_packet_size() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_pre_handshake_junk(1, 42, 42, 0);
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut buffer = vec![0u8; 128];

        let packet = cfg.fill_pre_handshake_junk(&mut buffer, &mut rng).unwrap();

        assert_eq!(packet.len(), 42);
    }

    #[test]
    fn quic_sni_accepts_utf8_idn_while_dns_sip_require_ldh() {
        // QUIC SNI is a length-prefixed TLS extension: UTF-8/IDN accepted.
        assert!(is_valid_quic_sni("xn--nxasmq6b.com"));
        assert!(is_valid_quic_sni("пример.рф"));
        assert!(!is_valid_quic_sni(""));
        assert!(!is_valid_quic_sni("bad\r\nhost"));
        assert!(!is_valid_quic_sni(&"a".repeat(254)));

        // A non-ASCII domain is kept for QUIC but dropped for DNS/SIP (strict).
        let quic = AmneziaImitation::new(
            AmneziaImitationProtocol::Quic,
            Some("пример.рф".to_owned()),
            AmneziaImitationBrowser::Default,
        );
        assert_eq!(quic.domain(), Some("пример.рф"));
        let dns = AmneziaImitation::new(
            AmneziaImitationProtocol::Dns,
            Some("пример.рф".to_owned()),
            AmneziaImitationBrowser::Default,
        );
        assert_eq!(dns.domain(), None);
    }

    #[test]
    fn quic_default_browser_emits_single_curl_initial() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_protocol_imitation(
            AmneziaImitationProtocol::Quic,
            Some("example.com".to_owned()),
        );
        assert!(cfg.has_imitation_sequence());

        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let seq = cfg.pre_handshake_imitation_datagrams(&mut rng);
        // Omitted browser -> curl -> one Initial, back-to-back (zero delay).
        assert_eq!(seq.len(), 1);
        assert_eq!(seq[0].0, Duration::from_millis(0));
        assert_eq!(seq[0].1.len(), 1250);
    }

    #[test]
    fn pre_handshake_junk_rejects_zero_min_packet_size() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_pre_handshake_junk(1, 0, 10, 0);

        assert_eq!(
            cfg.pre_handshake_junk.packet_size_min,
            DEFAULT_JUNK_PACKET_SIZE_MIN
        );
        assert_eq!(
            cfg.pre_handshake_junk.packet_size_max,
            DEFAULT_JUNK_PACKET_SIZE_MAX
        );
    }

    #[test]
    fn protocol_imitation_fillers_tolerate_tiny_buffers() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);

        for size in 0..32 {
            let mut stun = vec![0u8; size];
            fill_stun(&mut stun, &mut rng);

            let mut dns = vec![0u8; size];
            fill_dns_minimal_root_query(&mut dns, &mut rng);
        }
    }

    /// `cookie_reply_amplifies` agrees with the rule `reply_policy` enforces,
    /// on both packet kinds and at the boundary.
    ///
    /// The two live in different modules and neither can see the other, so the
    /// only thing keeping them in step is this test. The response bound
    /// (`S3 > S2 + 28`) is the tighter of the two and had no coverage at all.
    #[test]
    fn cookie_reply_amplifies_agrees_with_the_rule_that_suppresses() {
        // Parity exactly: 64 + S3 == 148 + S1 and == 92 + S2. Not an amplifier.
        let ok = AmneziaConfig::new(100, 156, 184, 0);
        assert_eq!(
            ok.cookie_reply_amplifies(),
            None,
            "parity is not amplifying"
        );

        // One byte over on the initiation side.
        let over_s1 = AmneziaConfig::new(100, 156, 185, 0);
        assert_eq!(
            over_s1.cookie_reply_amplifies(),
            Some(("S1", 248, 249)),
            "one byte past the initiation bound must be reported"
        );

        // The response bound is tighter, so a config can clear S1 and fail S2.
        let over_s2 = AmneziaConfig::new(200, 100, 250, 0);
        assert_eq!(
            over_s2.cookie_reply_amplifies(),
            Some(("S2", 192, 314)),
            "the response bound is the tighter one and must be checked too"
        );

        // The shape a real installer rolls: S1 small, S3 large.
        let installer = AmneziaConfig::new(15, 15, 150, 0);
        assert!(
            installer.cookie_reply_amplifies().is_some(),
            "S1=15 S3=150 is a shape independent rolls produce, and it amplifies"
        );

        // And the interop harness's own sizes must not trip it.
        let harness = AmneziaConfig::new(120, 130, 110, 80);
        assert_eq!(
            harness.cookie_reply_amplifies(),
            None,
            "the sizes scripts/awg-interop-poc.sh runs must keep their cookies"
        );
    }

    /// `validate` refuses an amplifying configuration when under-load cookie
    /// replies are enabled, on both packet kinds and at the boundary.
    ///
    /// This is deliberately stricter than the AmneziaWG kernel module, which
    /// accepts these combinations. The trade is stated in `validate`: a config
    /// refused here would have run there, weakly reflecting, and would have lost
    /// every handshake under load once `device::reply_policy` suppressed its
    /// cookie replies. Failing at `awg set` is the one place the operator can
    /// still act on it.
    #[test]
    fn validate_refuses_a_configuration_whose_cookie_replies_would_amplify() {
        // Parity exactly: 64 + S3 == 148 + S1 and == 92 + S2. Legal.
        AmneziaConfig::new(100, 156, 184, 0)
            .validate()
            .expect("parity is not amplification");

        // One byte past the initiation bound.
        let err = AmneziaConfig::new(100, 156, 185, 0)
            .validate()
            .expect_err("one byte over must be refused");
        assert!(
            err.contains("S1"),
            "the error must name the binding value: {}",
            err
        );
        assert!(
            err.contains("249") && err.contains("248"),
            "and both sizes, so the operator can see the margin: {}",
            err
        );

        // The response bound is the tighter of the two, so a config can clear
        // S1 and still fail on S2.
        let err = AmneziaConfig::new(200, 100, 250, 0)
            .validate()
            .expect_err("the response bound must be checked too");
        assert!(
            err.contains("S2"),
            "the error must name S2 here, not S1: {}",
            err
        );

        // The shape an installer rolling S values independently produces.
        assert!(
            AmneziaConfig::new(15, 15, 150, 0).validate().is_err(),
            "S1=15 S3=150 amplifies and must not load"
        );

        // And the sizes the interop harness runs must remain loadable, or this
        // rule has broken the project's own reference configuration.
        AmneziaConfig::new(120, 130, 110, 80)
            .validate()
            .expect("scripts/awg-interop-poc.sh must still be a legal config");

        // DisableCookies emits no under-load Cookie Reply, so the otherwise
        // amplifying S3 combination is safe and must remain configurable.
        AmneziaConfig::new(100, 156, 185, 0)
            .with_disable_cookies(true)
            .validate()
            .expect("DisableCookies must not be blocked by an unused reply-size constraint");

        // As must the default: vanilla WireGuard has no S values at all.
        AmneziaConfig::default()
            .validate()
            .expect("the default configuration must load");
    }

    /// Following the error message's advice must actually produce a loadable
    /// configuration.
    ///
    /// The message names a maximum S3. If the helper reports whichever bound it
    /// checks first rather than the binding one, that maximum can still be too
    /// high -- at S1=100, S2=0, S3=185 the initiation bound advises 184, and 184
    /// still fails the response bound of 28. This asserts the property the
    /// operator actually cares about rather than the mechanism: take the number
    /// the message gives, apply it, and the config must validate.
    #[test]
    fn the_maximum_s3_the_error_recommends_actually_validates() {
        for (s1, s2, s3) in [
            (100u16, 0u16, 185u16), // both bounds violated, response the tighter
            (0, 100, 185),          // both violated, initiation the tighter
            (15, 15, 150),          // the installer shape
            (0, 0, 100),            // no S padding at all
            (100, 156, 185),        // one byte past a symmetric parity
        ] {
            let cfg = AmneziaConfig::new(s1, s2, s3, 0);
            let (_, request, _) = cfg
                .cookie_reply_amplifies()
                .unwrap_or_else(|| panic!("S1={} S2={} S3={} should amplify", s1, s2, s3));

            let advised = (request - COOKIE_REPLY_SZ) as u16;
            AmneziaConfig::new(s1, s2, advised, 0)
                .validate()
                .unwrap_or_else(|e| {
                    panic!(
                        "S1={} S2={}: advised S3={} still rejected: {}",
                        s1, s2, advised, e
                    )
                });

            // And it is the *largest* such value, or the advice is needlessly
            // strict and the operator loses padding they could have kept.
            assert!(
                AmneziaConfig::new(s1, s2, advised + 1, 0)
                    .validate()
                    .is_err(),
                "S1={} S2={}: S3={} should have been advised instead",
                s1,
                s2,
                advised + 1
            );
        }
    }

    /// The message's *other* alternative has to work in one pass too.
    ///
    /// "Lower S3, or raise S1/S2" offers two routes and an operator may take
    /// either. When both bounds are violated they are independent, so naming
    /// only the binding one leaves the other failing: at S1=100, S2=0, S3=185,
    /// raising S2 to parity still leaves the initiation a byte short.
    ///
    /// Parses the minima back out of the rendered string rather than calling
    /// the helper, because the string is what the operator acts on. A helper
    /// that is right while the message is wrong still sends them round twice.
    #[test]
    fn every_raise_the_error_recommends_applied_together_actually_validates() {
        /// -> [("S1", 101), ("S2", 157)] from "... or raise S1 to at least 101
        /// and S2 to at least 157."
        fn parse_raises(msg: &str) -> Vec<(String, u16)> {
            let tail = msg
                .split_once(", or raise ")
                .unwrap_or_else(|| panic!("no raise advice in: {}", msg))
                .1
                .trim_end_matches('.');
            tail.split(" and ")
                .map(|clause| {
                    let (label, value) = clause
                        .split_once(" to at least ")
                        .unwrap_or_else(|| panic!("malformed raise clause: {}", clause));
                    (
                        label.to_string(),
                        value
                            .parse()
                            .unwrap_or_else(|e| panic!("bad number in {}: {}", clause, e)),
                    )
                })
                .collect()
        }

        for (s1, s2, s3, expected_count) in [
            (100u16, 0u16, 185u16, 2), // both bounds violated
            (0, 100, 185, 2),          // both violated, the other way round
            (200, 100, 250, 1),        // clears S1, fails S2
            (15, 15, 150, 2),          // the installer shape
            (100, 156, 185, 2),        // one byte past a symmetric parity
        ] {
            let err = AmneziaConfig::new(s1, s2, s3, 0)
                .validate()
                .expect_err("this configuration must be refused");
            let raises = parse_raises(&err);
            assert_eq!(
                raises.len(),
                expected_count,
                "S1={} S2={} S3={}: wrong number of bounds named in {}",
                s1,
                s2,
                s3,
                err
            );

            // Apply every raise the message names, all at once, and the
            // configuration must load.
            let mut raised_s1 = s1;
            let mut raised_s2 = s2;
            for (label, min) in &raises {
                match label.as_str() {
                    "S1" => raised_s1 = *min,
                    "S2" => raised_s2 = *min,
                    other => panic!("unexpected label {} in {}", other, err),
                }
            }
            AmneziaConfig::new(raised_s1, raised_s2, s3, 0)
                .validate()
                .unwrap_or_else(|e| {
                    panic!(
                        "S1={}->{} S2={}->{} S3={}: following the advice still fails: {}",
                        s1, raised_s1, s2, raised_s2, s3, e
                    )
                });

            // And each is the *smallest* value that works, or the advice costs
            // the operator padding they could have kept.
            for (label, min) in &raises {
                let (probe_s1, probe_s2) = match label.as_str() {
                    "S1" => (min - 1, raised_s2),
                    _ => (raised_s1, min - 1),
                };
                assert!(
                    AmneziaConfig::new(probe_s1, probe_s2, s3, 0)
                        .validate()
                        .is_err(),
                    "S1={} S2={} S3={}: {} = {} would have done, so {} is too strict",
                    s1,
                    s2,
                    s3,
                    label,
                    min - 1,
                    min
                );
            }
        }
    }
    #[test]
    fn header_protection_round_trips_all_packet_kinds() {
        use rand_core::OsRng;

        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(12, 12, 12, 12).with_header_protection_key([0x42; 32]);
        cfg.validate()
            .expect("12-byte prefixes satisfy HP requirements");

        for (tag, size) in [
            (1u32, HANDSHAKE_INIT_SZ),
            (2u32, HANDSHAKE_RESP_SZ),
            (3u32, COOKIE_REPLY_SZ),
            (4u32, DATA_OVERHEAD_SZ),
        ] {
            let mut original = vec![0u8; size];
            original[..4].copy_from_slice(&tag.to_le_bytes());
            // Receiver index and counter are part of the protected transport
            // header; give them non-zero values so the test covers those bytes.
            if tag == 4 {
                original[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
                original[8..16].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
            }

            let mut buffer = vec![0u8; size + 12];
            buffer[..size].copy_from_slice(&original);
            let protected = cfg
                .prepend_outbound(obf, &mut buffer, size, &mut OsRng)
                .expect("outbound protection succeeds")
                .to_vec();

            assert_eq!(protected.len(), size + 12);
            assert_ne!(&protected[12..16], &original[..4]);

            let decoded = cfg
                .decrypt_inbound(obf, &protected)
                .expect("inbound protection recognizes the packet");
            assert_eq!(decoded, original, "packet type {} round-trips", tag);
        }
    }

    #[test]
    fn header_protection_roundtrips_handshake_with_random_trailer() {
        let obf = ObfuscationRanges::default();
        let cfg = AmneziaConfig::new(12, 12, 12, 12)
            .with_header_protection_key([0x42; 32])
            .with_random_trailers(true);
        let mut original = vec![0u8; HANDSHAKE_INIT_SZ];
        original[..4].copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());
        for (i, byte) in original[4..].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(3).wrapping_add(1);
        }

        let mut buffer = vec![0u8; DEFAULT_UDP_WINDOW];
        buffer[..HANDSHAKE_INIT_SZ].copy_from_slice(&original);
        let mut rng = ChaCha8Rng::seed_from_u64(0xA31);
        let wire = cfg
            .prepend_outbound(obf, &mut buffer, HANDSHAKE_INIT_SZ, &mut rng)
            .expect("header protection and trailer fit")
            .to_vec();
        assert!(wire.len() > HANDSHAKE_INIT_SZ + 12);

        assert_eq!(
            cfg.decrypt_inbound(obf, &wire).as_deref(),
            Some(original.as_slice()),
            "header protection must ignore the random trailer after decoding"
        );
    }

    /// Fixed vector matching the upstream AWG construction:
    /// ChaCha20(key, S-prefix[0..12]) XORs the full handshake message,
    /// while transport protects only its 16-byte header.
    #[test]
    fn header_protection_matches_awg_chacha20_wire_vector() {
        let obf = ObfuscationRanges::default();
        let key = [0x42; 32];
        let cfg = AmneziaConfig::new(12, 12, 12, 12).with_header_protection_key(key);
        let nonce: [u8; 12] = core::array::from_fn(|i| i as u8);

        let mut initiation = vec![0u8; HANDSHAKE_INIT_SZ];
        initiation[..4].copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());
        for (i, byte) in initiation[4..].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(3);
        }

        let mut reference_ciphertext = initiation.clone();
        let mut cipher = chacha20::ChaCha20::new_from_slices(&key, &nonce).unwrap();
        cipher.apply_keystream(&mut reference_ciphertext);
        assert_eq!(
            &reference_ciphertext[..16],
            &[
                0x37, 0x3e, 0xe1, 0x64, 0x3b, 0x55, 0x38, 0xdf, 0xc8, 0xed, 0x8e, 0xe4, 0xc6, 0x72,
                0xbd, 0x58,
            ],
            "ChaCha20 stream must match the IETF/upstream AWG vector"
        );

        let mut datagram = nonce.to_vec();
        datagram.extend_from_slice(&reference_ciphertext);
        assert_eq!(
            cfg.decrypt_inbound(obf, &datagram).as_deref(),
            Some(initiation.as_slice()),
            "a datagram encrypted by the reference AWG construction must decode"
        );

        for (tag, size, expected_prefix) in [
            (
                2u32,
                HANDSHAKE_RESP_SZ,
                [
                    0x34, 0x3e, 0xe1, 0x64, 0x3b, 0x55, 0x38, 0xdf, 0xc8, 0xed, 0x8e, 0xe4, 0xc6,
                    0x72, 0xbd, 0x58,
                ],
            ),
            (
                3u32,
                COOKIE_REPLY_SZ,
                [
                    0x35, 0x3e, 0xe1, 0x64, 0x3b, 0x55, 0x38, 0xdf, 0xc8, 0xed, 0x8e, 0xe4, 0xc6,
                    0x72, 0xbd, 0x58,
                ],
            ),
        ] {
            let mut message = vec![0u8; size];
            message[..4].copy_from_slice(&tag.to_le_bytes());
            for (i, byte) in message[4..].iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(7).wrapping_add(3);
            }

            let mut ciphertext = message.clone();
            let mut cipher = chacha20::ChaCha20::new_from_slices(&key, &nonce).unwrap();
            cipher.apply_keystream(&mut ciphertext);
            assert_eq!(
                &ciphertext[..16],
                &expected_prefix,
                "upstream ChaCha20 header-protection vector for message type {tag}"
            );

            let mut datagram = nonce.to_vec();
            datagram.extend_from_slice(&ciphertext);
            assert_eq!(
                cfg.decrypt_inbound(obf, &datagram).as_deref(),
                Some(message.as_slice()),
                "upstream-protected message type {tag} must decode"
            );
        }

        let mut transport = vec![0u8; DATA_OVERHEAD_SZ + 32];
        transport[..4].copy_from_slice(&DATA.to_le_bytes());
        transport[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        transport[8..16].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        for (i, byte) in transport[16..].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(11).wrapping_add(9);
        }
        let payload = transport[16..].to_vec();
        let mut transport_ciphertext = transport.clone();
        let mut cipher = chacha20::ChaCha20::new_from_slices(&key, &nonce).unwrap();
        cipher.apply_keystream(&mut transport_ciphertext[..16]);
        assert_eq!(
            &transport_ciphertext[..16],
            &[
                0x32, 0x3e, 0xe1, 0x64, 0x40, 0x09, 0x1d, 0xd5, 0xdf, 0xcc, 0xa5, 0xd5, 0xf9, 0x33,
                0xf6, 0x09,
            ],
            "upstream transport vector protects type, receiver index, and counter"
        );
        assert_eq!(
            &transport_ciphertext[16..],
            payload.as_slice(),
            "transport AEAD ciphertext must remain byte-for-byte untouched"
        );

        let mut datagram = nonce.to_vec();
        datagram.extend_from_slice(&transport_ciphertext);
        assert_eq!(
            cfg.decrypt_inbound(obf, &datagram).as_deref(),
            Some(transport.as_slice()),
            "transport decoding must recover its 16-byte header and preserve payload"
        );
    }

    #[test]
    fn outbound_header_protection_matches_reference_for_every_packet_kind() {
        let obf = ObfuscationRanges::default();
        let key = [0x42; 32];
        let cfg = AmneziaConfig::new(12, 12, 12, 12).with_header_protection_key(key);

        for (tag, size) in [
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ),
            (COOKIE_REPLY, COOKIE_REPLY_SZ),
            (DATA, DATA_OVERHEAD_SZ + 48),
        ] {
            let mut original = vec![0u8; size];
            write_tag(&mut original, tag);
            for (i, byte) in original[4..].iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(13).wrapping_add(tag as u8);
            }

            let mut buffer = vec![0u8; 12 + size + 64];
            buffer[..size].copy_from_slice(&original);
            let mut rng = ChaCha8Rng::seed_from_u64(u64::from(tag) + 0xA31);
            let wire = cfg
                .prepend_outbound(obf, &mut buffer, size, &mut rng)
                .expect("outbound header protection must succeed")
                .to_vec();

            assert_eq!(wire.len(), 12 + size);
            let nonce = &wire[..12];
            let protected_len = if tag == DATA { 16 } else { size };
            let mut reference = original;
            let mut cipher = chacha20::ChaCha20::new_from_slices(&key, nonce).unwrap();
            cipher.apply_keystream(&mut reference[..protected_len]);

            assert_eq!(
                &wire[12..],
                reference.as_slice(),
                "outbound type {tag} must match upstream ChaCha20 protection byte-for-byte"
            );
            if tag == DATA {
                assert_eq!(
                    &wire[12 + 16..],
                    &reference[16..],
                    "transport AEAD ciphertext and tag must remain untouched"
                );
            }
        }
    }

    #[test]
    fn header_protection_classifies_custom_h1_through_h4_tags() {
        let obf = ObfuscationRanges::new(11, 11, 22, 22, 33, 33, 44, 44).unwrap();
        let cfg = AmneziaConfig::new(12, 12, 12, 12).with_header_protection_key([0x24; 32]);

        for (tag, size) in [
            (11u32, HANDSHAKE_INIT_SZ),
            (22u32, HANDSHAKE_RESP_SZ),
            (33u32, COOKIE_REPLY_SZ),
            (44u32, DATA_OVERHEAD_SZ + 8),
        ] {
            let mut original = vec![0u8; size];
            write_tag(&mut original, tag);
            original[4..].fill(tag as u8);

            let mut buffer = vec![0u8; 12 + size];
            buffer[..size].copy_from_slice(&original);
            let mut rng = ChaCha8Rng::seed_from_u64(u64::from(tag));
            let wire = cfg
                .prepend_outbound(obf, &mut buffer, size, &mut rng)
                .expect("custom H1-H4 packet must be classified")
                .to_vec();

            assert_eq!(
                cfg.decrypt_inbound(obf, &wire).as_deref(),
                Some(original.as_slice()),
                "custom H tag {tag} must survive header protection"
            );
        }
    }

    #[test]
    fn header_protection_requires_all_s_prefixes_to_be_at_least_12() {
        let cfg = AmneziaConfig::new(12, 12, 12, 11).with_header_protection_key([0x24; 32]);
        let error = cfg.validate().expect_err("S4 is too short for the nonce");
        assert!(error.contains("S4"));
        assert!(error.contains("12"));
    }

    #[test]
    fn header_protection_is_disabled_by_an_all_zero_key() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0);
        assert!(!cfg.header_protection_enabled());
    }
}
