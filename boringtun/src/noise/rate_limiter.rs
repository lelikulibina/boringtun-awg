//! Проверка MAC1/MAC2 и защита handshake от перегрузки.
//!
//! RateLimiter решает, когда требовать cookie reply от отправителя handshake.
//! Политика `DisableCookies` отключает именно challenge под нагрузкой, но не
//! аутентификацию: MAC1 всё равно должен быть корректным. Не превращайте этот
//! флаг в обход `verify_packet` или проверок MAC1 — иначе можно принимать
//! неподлинные initiation/response. Cookie reply остаётся включённым по
//! умолчанию для обычной конфигурации.

use super::handshake::{
    b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, b2s_mac_24, ObfuscationRanges,
};
use crate::noise::handshake::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::{HandshakeInit, HandshakeResponse, Packet, Tunn, TunnResult, WireGuardError};

#[cfg(feature = "mock-instant")]
use mock_instant::Instant;
use portable_atomic::{AtomicU64, Ordering};
use std::net::IpAddr;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

use super::handshake::constant_time_eq;
use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};

const COOKIE_REFRESH: u64 = 128; // Use 128 and not 120 so the compiler can optimize out the division
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How often should reset count in seconds
const RESET_PERIOD: u64 = 1;

type Cookie = [u8; COOKIE_SIZE];

/// There are two places where WireGuard requires "randomness" for cookies
/// * The 24 byte nonce in the cookie massage - here the only goal is to avoid nonce reuse
/// * A secret value that changes every two minutes
/// Because the main goal of the cookie is simply for a party to prove ownership of an IP address
/// we can relax the randomness definition a bit, in order to avoid locking, because using less
/// resources is the main goal of any DoS prevention mechanism.
/// In order to avoid locking and calls to rand we derive pseudo random values using the AEAD and
/// some counters.
pub struct RateLimiter {
    /// The key we use to derive the nonce
    nonce_key: [u8; 32],
    /// The key we use to derive the cookie
    secret_key: [u8; 16],
    start_time: Instant,
    /// A single 64 bit counter (should suffice for many years)
    nonce_ctr: AtomicU64,
    mac1_key: [u8; 32],
    cookie_key: Key,
    limit: u64,
    /// The counter since last reset
    count: AtomicU64,
    /// The time last reset was performed on this rate limiter
    last_reset: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(public_key: &crate::x25519::PublicKey, limit: u64) -> Self {
        let mut secret_key = [0u8; 16];
        OsRng.fill_bytes(&mut secret_key);
        RateLimiter {
            nonce_key: Self::rand_bytes(),
            secret_key,
            start_time: Instant::now(),
            nonce_ctr: AtomicU64::new(0),
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, public_key.as_bytes()).into(),
            limit,
            count: AtomicU64::new(0),
            last_reset: Mutex::new(Instant::now()),
        }
    }

    fn rand_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Reset packet count (ideally should be called with a period of 1 second)
    pub fn reset_count(&self) {
        // The rate limiter is not very accurate, but at the scale we care about it doesn't matter much
        let current_time = Instant::now();
        let mut last_reset_time = self.last_reset.lock();
        if current_time.duration_since(*last_reset_time).as_secs() >= RESET_PERIOD {
            self.count.store(0, Ordering::SeqCst);
            *last_reset_time = current_time;
        }
    }

    /// Compute the correct cookie value based on the current secret value and the source IP
    fn current_cookie(&self, addr: IpAddr) -> Cookie {
        let mut addr_bytes = [0u8; 16];

        match addr {
            IpAddr::V4(a) => addr_bytes[..4].copy_from_slice(&a.octets()[..]),
            IpAddr::V6(a) => addr_bytes[..].copy_from_slice(&a.octets()[..]),
        }

        // The current cookie for a given IP is the MAC(responder.changing_secret_every_two_minutes, initiator.ip_address)
        // First we derive the secret from the current time, the value of cur_counter would change with time.
        let cur_counter = Instant::now().duration_since(self.start_time).as_secs() / COOKIE_REFRESH;

        // Next we derive the cookie
        b2s_keyed_mac_16_2(&self.secret_key, &cur_counter.to_le_bytes(), &addr_bytes)
    }

    fn nonce(&self) -> [u8; COOKIE_NONCE_SIZE] {
        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed);

        b2s_mac_24(&self.nonce_key, &ctr.to_le_bytes())
    }

    fn is_under_load(&self) -> bool {
        self.count.fetch_add(1, Ordering::SeqCst) >= self.limit
    }

    pub(crate) fn format_cookie_reply<'a>(
        &self,
        obf: ObfuscationRanges,
        rng: &mut impl RngCore,
        idx: u32,
        cookie: Cookie,
        mac1: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if dst.len() < super::COOKIE_REPLY_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (nonce, rest) = rest.split_at_mut(24);
        let (encrypted_cookie, _) = rest.split_at_mut(16 + 16);

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&obf.random_h3(rng).to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&idx.to_le_bytes());
        nonce.copy_from_slice(&self.nonce()[..]);

        let cipher = XChaCha20Poly1305::new(&self.cookie_key);

        let iv = GenericArray::from_slice(nonce);

        encrypted_cookie[..16].copy_from_slice(&cookie);
        let tag = cipher
            .encrypt_in_place_detached(iv, mac1, &mut encrypted_cookie[..16])
            .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;

        encrypted_cookie[16..].copy_from_slice(&tag);

        Ok(&mut dst[..super::COOKIE_REPLY_SZ])
    }

    /// Verify MAC fields and apply standard WireGuard cookie rate limiting.
    /// This compatibility entry point preserves the original public API.
    pub fn verify_packet<'a, 'b>(
        &self,
        obf: ObfuscationRanges,
        rng: &mut impl RngCore,
        src_addr: Option<IpAddr>,
        src: &'a [u8],
        dst: &'b mut [u8],
    ) -> Result<Packet<'a>, TunnResult<'b>> {
        self.verify_packet_with_cookie_policy(obf, rng, src_addr, src, dst, false)
    }

    /// Verify a packet with AmneziaWG 3.1 DisableCookies semantics.
    // DisableCookies отключает только cookie challenge при высокой нагрузке.
    // MAC1 остаётся обязательным для initiation и response; не превращайте
    // политику cookie в обход проверки подлинности входящего handshake.
    pub(crate) fn verify_packet_with_cookie_policy<'a, 'b>(
        &self,
        obf: ObfuscationRanges,
        rng: &mut impl RngCore,
        src_addr: Option<IpAddr>,
        src: &'a [u8],
        dst: &'b mut [u8],
        disable_cookies: bool,
    ) -> Result<Packet<'a>, TunnResult<'b>> {
        let packet = Tunn::parse_incoming_packet(obf, src)?;

        // Verify and rate limit handshake messages only
        if let Packet::HandshakeInit(HandshakeInit { sender_idx, .. })
        | Packet::HandshakeResponse(HandshakeResponse { sender_idx, .. }) = packet
        {
            let (msg, macs) = src.split_at(src.len() - 32);
            let (mac1, mac2) = macs.split_at(16);

            let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, msg);
            if !constant_time_eq(&computed_mac1[..16], mac1) {
                return Err(TunnResult::Err(WireGuardError::InvalidMac));
            }

            // Upstream AmneziaWG semantics: DisableCookies disables the whole
            // under-load cookie challenge, not just transmission of Cookie Reply.
            // MAC1 is still mandatory; when disabled, MAC2/rate-limit checks are
            // skipped so a peer can complete the handshake without a cookie.
            if !disable_cookies && self.is_under_load() {
                let addr = match src_addr {
                    None => return Err(TunnResult::Err(WireGuardError::UnderLoad)),
                    Some(addr) => addr,
                };

                // Only given an address can we validate mac2
                let cookie = self.current_cookie(addr);
                let computed_mac2 = b2s_keyed_mac_16_2(&cookie, msg, mac1);

                if !constant_time_eq(&computed_mac2[..16], mac2) {
                    let cookie_packet = self
                        .format_cookie_reply(obf, rng, sender_idx, cookie, mac1, dst)
                        .map_err(TunnResult::Err)?;
                    return Err(TunnResult::WriteToNetwork(cookie_packet));
                }
            }
        }

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    const HANDSHAKE_INIT_SZ: usize = 148;

    fn initiation_with_valid_mac1(limiter: &RateLimiter) -> [u8; HANDSHAKE_INIT_SZ] {
        let mut packet = [0u8; HANDSHAKE_INIT_SZ];
        packet[..4].copy_from_slice(&1u32.to_le_bytes());
        packet[4..8].copy_from_slice(&7u32.to_le_bytes());

        let mac_offset = HANDSHAKE_INIT_SZ - 32;
        let mac1 = b2s_keyed_mac_16(&limiter.mac1_key, &packet[..mac_offset]);
        packet[mac_offset..mac_offset + 16].copy_from_slice(&mac1);
        // Leave MAC2 zeroed: it is invalid for the selected source address.
        packet
    }

    const HANDSHAKE_RESPONSE_SZ: usize = 92;

    fn response_with_valid_mac1(limiter: &RateLimiter) -> [u8; HANDSHAKE_RESPONSE_SZ] {
        let mut packet = [0u8; HANDSHAKE_RESPONSE_SZ];
        packet[..4].copy_from_slice(&2u32.to_le_bytes());
        packet[4..8].copy_from_slice(&9u32.to_le_bytes());
        packet[8..12].copy_from_slice(&7u32.to_le_bytes());

        let mac_offset = HANDSHAKE_RESPONSE_SZ - 32;
        let mac1 = b2s_keyed_mac_16(&limiter.mac1_key, &packet[..mac_offset]);
        packet[mac_offset..mac_offset + 16].copy_from_slice(&mac1);
        packet
    }

    #[test]
    fn disable_cookies_bypasses_under_load_for_handshake_responses_too() {
        let public_key = crate::x25519::PublicKey::from([7u8; 32]);
        let limiter = RateLimiter::new(&public_key, 0);
        let packet = response_with_valid_mac1(&limiter);
        let mut dst = [0u8; 128];

        let result = limiter.verify_packet_with_cookie_policy(
            ObfuscationRanges::default(),
            &mut OsRng,
            None,
            &packet,
            &mut dst,
            true,
        );

        assert!(matches!(result, Ok(Packet::HandshakeResponse(_))));
        assert_eq!(
            limiter.count.load(Ordering::SeqCst),
            0,
            "DisableCookies applies to response MAC1 validation without rate-limit accounting"
        );
    }

    #[test]
    fn disable_cookies_still_rejects_invalid_response_mac1() {
        let public_key = crate::x25519::PublicKey::from([7u8; 32]);
        let limiter = RateLimiter::new(&public_key, 0);
        let mut packet = response_with_valid_mac1(&limiter);
        let mac_offset = HANDSHAKE_RESPONSE_SZ - 32;
        packet[mac_offset] ^= 0x80;
        let mut dst = [0u8; 128];

        let result = limiter.verify_packet_with_cookie_policy(
            ObfuscationRanges::default(),
            &mut OsRng,
            None,
            &packet,
            &mut dst,
            true,
        );

        assert!(matches!(
            result,
            Err(TunnResult::Err(WireGuardError::InvalidMac))
        ));
    }

    #[test]
    fn disable_cookies_bypasses_under_load_cookie_challenge() {
        let public_key = crate::x25519::PublicKey::from([7u8; 32]);
        let limiter = RateLimiter::new(&public_key, 0);
        let packet = initiation_with_valid_mac1(&limiter);
        let mut dst = [0u8; 128];

        // With cookies disabled, an authenticated MAC1 is sufficient even
        // when the caller has no source address from which a cookie could be
        // derived. This is the behavior the UAPI switch promises.
        let result = limiter.verify_packet_with_cookie_policy(
            ObfuscationRanges::default(),
            &mut OsRng,
            None,
            &packet,
            &mut dst,
            true,
        );

        assert!(matches!(result, Ok(Packet::HandshakeInit(_))));
        assert_eq!(
            limiter.count.load(Ordering::SeqCst),
            0,
            "DisableCookies skips the under-load counter as well as the cookie challenge"
        );
    }

    #[test]
    fn disable_cookies_accepts_invalid_mac2_under_load_with_source_address() {
        let public_key = crate::x25519::PublicKey::from([7u8; 32]);
        let limiter = RateLimiter::new(&public_key, 0);
        let packet = initiation_with_valid_mac1(&limiter);
        let mut dst = [0u8; 128];

        let result = limiter.verify_packet_with_cookie_policy(
            ObfuscationRanges::default(),
            &mut OsRng,
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            &packet,
            &mut dst,
            true,
        );

        assert!(matches!(result, Ok(Packet::HandshakeInit(_))));
        assert_eq!(
            limiter.count.load(Ordering::SeqCst),
            0,
            "DisableCookies must bypass MAC2 validation and under-load accounting"
        );
    }

    #[test]
    fn disable_cookies_does_not_disable_mac1_authentication() {
        let public_key = crate::x25519::PublicKey::from([7u8; 32]);
        let limiter = RateLimiter::new(&public_key, 0);
        let mut packet = initiation_with_valid_mac1(&limiter);
        let mac_offset = HANDSHAKE_INIT_SZ - 32;
        packet[mac_offset] ^= 0x80;
        let mut dst = [0u8; 128];

        let result = limiter.verify_packet_with_cookie_policy(
            ObfuscationRanges::default(),
            &mut OsRng,
            None,
            &packet,
            &mut dst,
            true,
        );

        assert!(matches!(
            result,
            Err(TunnResult::Err(WireGuardError::InvalidMac))
        ));
    }

    #[test]
    fn default_cookie_policy_still_rejects_under_load_without_source_address() {
        let public_key = crate::x25519::PublicKey::from([7u8; 32]);
        let limiter = RateLimiter::new(&public_key, 0);
        let packet = initiation_with_valid_mac1(&limiter);
        let mut dst = [0u8; 128];

        let result = limiter.verify_packet(
            ObfuscationRanges::default(),
            &mut OsRng,
            None,
            &packet,
            &mut dst,
        );

        assert!(matches!(
            result,
            Err(TunnResult::Err(WireGuardError::UnderLoad))
        ));
    }

    #[test]
    fn valid_mac2_is_accepted_under_load() {
        let public_key = crate::x25519::PublicKey::from([7u8; 32]);
        let limiter = RateLimiter::new(&public_key, 0);
        let mut packet = initiation_with_valid_mac1(&limiter);
        let source = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mac_offset = HANDSHAKE_INIT_SZ - 32;
        let (message, macs) = packet.split_at_mut(mac_offset);
        let (mac1, mac2) = macs.split_at_mut(16);
        let cookie = limiter.current_cookie(source);
        let expected_mac2 = b2s_keyed_mac_16_2(&cookie, message, mac1);
        mac2.copy_from_slice(&expected_mac2);

        let mut dst = [0u8; 128];
        let result = limiter.verify_packet(
            ObfuscationRanges::default(),
            &mut OsRng,
            Some(source),
            &packet,
            &mut dst,
        );

        assert!(matches!(result, Ok(Packet::HandshakeInit(_))));
        assert_eq!(limiter.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cookie_reply_matches_xchacha20_poly1305_known_answer_vector() {
        // Independent fixture: keyed BLAKE2s-192 nonce derivation and
        // XChaCha20-Poly1305 (RFC 8439 AEAD construction with HChaCha20).
        let now = Instant::now();
        let limiter = RateLimiter {
            nonce_key: [0x11; 32],
            secret_key: [0x22; 16],
            start_time: now,
            nonce_ctr: AtomicU64::new(0),
            mac1_key: [0x55; 32],
            cookie_key: [0x22; 32].into(),
            limit: 0,
            count: AtomicU64::new(0),
            last_reset: Mutex::new(now),
        };
        let obf = ObfuscationRanges::new(10, 10, 20, 20, 30, 30, 40, 40).unwrap();
        let cookie = [0x44; 16];
        let mac1 = [0x33; 16];
        let mut dst = [0u8; super::super::COOKIE_REPLY_SZ];

        let packet = limiter
            .format_cookie_reply(obf, &mut OsRng, 0x1122_3344, cookie, &mac1, &mut dst)
            .unwrap();

        let expected: [u8; super::super::COOKIE_REPLY_SZ] = [
            0x1e, 0x00, 0x00, 0x00, 0x44, 0x33, 0x22, 0x11, 0x6d, 0x2f, 0xe2, 0x5e, 0x44, 0x44,
            0xa1, 0xed, 0x82, 0x29, 0xd5, 0x43, 0xad, 0xaa, 0x51, 0xe0, 0x6e, 0x02, 0x3b, 0x34,
            0x85, 0x2b, 0x2d, 0xeb, 0x7c, 0xbc, 0xcb, 0xc8, 0x1d, 0xa7, 0xaf, 0x11, 0xdb, 0x34,
            0x51, 0xa5, 0xaf, 0x1a, 0x8e, 0xf6, 0xc2, 0xb4, 0x26, 0xa0, 0x88, 0x6b, 0x6a, 0x1b,
            0xbd, 0xd4, 0x15, 0x8c, 0x1d, 0x72, 0x79, 0xd2,
        ];
        assert_eq!(packet, expected);
    }

    #[test]
    fn cookie_replies_remain_enabled_by_default() {
        let public_key = crate::x25519::PublicKey::from([7u8; 32]);
        let limiter = RateLimiter::new(&public_key, 0);
        let packet = initiation_with_valid_mac1(&limiter);
        let mut dst = [0u8; 128];

        let result = limiter.verify_packet(
            ObfuscationRanges::default(),
            &mut OsRng,
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            &packet,
            &mut dst,
        );

        assert!(matches!(result, Err(TunnResult::WriteToNetwork(_))));
    }
}
