// Copyright (c) 2024 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Source-address policy shared by unauthenticated probe replies and
//! WireGuard cookie replies.
//!
//! Cookie replies preserve upstream AmneziaWG semantics: S3 is emitted exactly
//! as configured, without a request-size amplification cap. This module only
//! prevents replies to invalid or unsafe destination addresses. Probe replies
//! have their own protocol-specific size limits and aggregate byte budget.

use std::net::{IpAddr, SocketAddr};

/// Rewrite an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) as the IPv4 address
/// it denotes.
///
/// The v6 listening socket is dual-stack, so every IPv4 peer reaching it is
/// reported in this form, and it matters twice:
///
/// - The v6 arm of [`may_reply_to`] would let `::ffff:255.255.255.255` and
///   `::ffff:224.0.0.1` through, because neither `is_multicast` nor
///   `is_broadcast` looks inside the mapping. The hygiene rules have to see the
///   address family the datagram actually came from.
/// - A STUN XOR-MAPPED-ADDRESS would otherwise report family `0x02` with a
///   16-byte address to a client that reached us over IPv4. Real servers report
///   the family they saw, so the mapped form is its own fingerprint.
///
/// `Ipv6Addr::to_ipv4_mapped`, not `to_ipv4`: the latter also unwraps the
/// deprecated IPv4-*compatible* form (`::a.b.c.d`), which a dual-stack socket
/// never produces and which should keep failing the v6 rules below.
///
/// Private, and reachable only through [`reply_target`]. Exported on its own it
/// would be one half of a pair a caller has to remember to use in the right
/// order — which is exactly the bug it exists to prevent.
fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

/// Which caller is asking, because the two can afford different answers about
/// one address: `127.0.0.1`.
///
/// **A loopback source cannot be forged from off-host.** Linux drops a datagram
/// whose source is in `127/8` on any non-loopback interface, as a martian
/// source, and that drop is unconditional — measured across a veth with a raw
/// socket, it still happens with `rp_filter=0` *and* `route_localnet=1` on every
/// relevant interface. So a reply aimed at `127.0.0.1` can never leave this
/// host, and there is no off-host reflection or amplification to bound. Refusing
/// it buys nothing against the threat this module exists for.
///
/// It is not free, though, and the two doors pay differently:
///
/// - [`Door::Cookie`] **allows** loopback. A cookie is stock WireGuard's flood
///   defence: suppress it and the peer can never produce a valid mac2, so every
///   handshake from that peer fails for as long as the device stays over
///   `HANDSHAKE_RATE_LIMIT`. A peer behind a local relay (udp2raw, phantun,
///   wstunnel — the ordinary way this fork gets deployed past a filter) is
///   exactly the peer that address belongs to, and refusing costs it every
///   handshake at the moment cookies matter most.
/// - [`Door::Probe`] **refuses** it. There is no such cost: a probe from
///   loopback comes from this host, and the camouflage is aimed at an observer
///   who is not on it. Refusing also denies a local process the ability to drain
///   [`super::probe_budget::ProbeBudget`] and silence genuine probe replies.
///
/// Link-local is refused at both doors, and that one is a real trade rather than
/// a free win: an on-link peer can legitimately hold `fe80::/10`, but unlike
/// loopback a spoofed link-local source is deliverable, so refusing closes an
/// on-segment reflection that nothing else closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Door {
    /// The probe responder. Refuses loopback.
    Probe,
    /// The WireGuard cookie reply. Allows loopback.
    Cookie,
}

/// Should we reply to this source address at all?
///
/// Independent of what the datagram contains. A source address is
/// attacker-chosen on a UDP socket, so these are the addresses a reply must
/// never be aimed at:
///
/// - **unspecified** — not a real source;
/// - **multicast / broadcast** — one forged datagram becomes a reply hitting
///   every host on the segment, a multiplier no byte-based ceiling models;
/// - **link-local** — reachable only by an on-segment host, and a spoofed
///   link-local source *is* deliverable (measured: it passes with
///   `rp_filter=0`), so refusing it does close an on-segment reflection;
/// - **`0.0.0.0/8` and `240.0.0.0/4`** — "this network" and reserved space; a
///   reply to either dies at the first hop, so it is budget spent on nothing;
/// - **port 0** — not a real source;
/// - **loopback**, for the probe door only — see [`Door`].
///
/// An earlier version of this doc claimed "none of these is an address a real
/// peer can hold". That was false, and it was the premise for applying the whole
/// list to the cookie path. A WireGuard peer reached through a local UDP relay
/// holds `127.0.0.1`, and this repository's own integration tests configure
/// exactly that — "a peer whose endpoint is on this machine"
/// (`integration_tests/mod.rs`). A peer on a point-to-point link holds an IPv6
/// link-local address and nothing else. Both are real; see [`Door`] for which
/// of them each caller can afford to refuse.
///
/// What it does **not** catch is a directed broadcast (`192.168.1.255`), which
/// needs the local prefix to recognise. Linux refuses `sendto` to a
/// locally-recognised broadcast address without `SO_BROADCAST`, which this
/// socket does not set, and RFC 2644 has routers drop remote ones — so the
/// defence there is the kernel's, not this function's. Said plainly because the
/// list above otherwise reads as exhaustive.
///
/// There is deliberately **no check on the source port matching our own listen
/// port**. It was here to stop two imitating servers trading replies, but that
/// loop cannot form: no reply this crate generates is classifiable as a probe,
/// so a reply arriving at a second server is simply dropped. That is asserted
/// by `probe_reply`'s `no_generated_reply_can_itself_be_detected_as_a_probe`,
/// which holds for servers on *different* ports too — a source-port test never
/// did. A cookie reply cannot loop either, for a duller reason: it carries a
/// receiver index no second server has issued, so peer lookup drops it.
///
/// What the check did buy was a fingerprint. A prober knows our listen port; it
/// is the port it is dialling. Sending one probe from source port 51820 and one
/// from 40000 got silence and a SERVFAIL — a one-packet discriminator that no
/// real DNS, STUN or QUIC server exhibits, in a module whose entire purpose is
/// not to be discriminable.
fn may_reply_to(from: SocketAddr, door: Door) -> bool {
    if from.port() == 0 {
        return false;
    }
    if from.ip().is_loopback() {
        return door == Door::Cookie;
    }
    match from.ip() {
        IpAddr::V4(v4) => {
            // `is_unspecified` is only 0.0.0.0 exactly, and `is_broadcast` only
            // 255.255.255.255, so 0.0.0.0/8 ("this network") and 240.0.0.0/4
            // (reserved) are spelled out. Neither can be a real source; a reply
            // to one is budget spent on a datagram that dies at the first hop.
            let this_network = v4.octets()[0] == 0;
            let reserved = v4.octets()[0] >= 240;
            !(v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local()
                || this_network
                || reserved)
        }
        IpAddr::V6(v6) => {
            // `is_unicast_link_local` is unstable, so the fe80::/10 test is
            // written out rather than waiting for it.
            let is_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            !(v6.is_unspecified() || v6.is_multicast() || is_link_local)
        }
    }
}

/// The address to aim a reply at, or `None` if this source must not be replied
/// to at all.
///
/// One function rather than an exported `unmap` beside an exported
/// `may_reply_to`, because the order between them is load-bearing and a caller
/// that gets it backwards gets a *silent* hole: the v6 rules do not see through
/// an IPv4 mapping, so checking first and unmapping second admits
/// `::ffff:255.255.255.255` — the form every IPv4 datagram arrives in on a
/// dual-stack socket. Returning the normalised address makes it impossible to
/// hold the check without also holding the normalisation.
pub(crate) fn reply_target(from: SocketAddr, door: Door) -> Option<SocketAddr> {
    let from = unmap(from);
    if may_reply_to(from, door) {
        Some(from)
    } else {
        None
    }
}

/// What to do with a cookie reply produced by the rate limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CookieVerdict {
    /// Send it using the configured S3 prefix.
    Send,
    /// The source address must never be replied to.
    RefusedSource,
}

/// Match amneziawg-go: the configured S3 prefix is emitted verbatim, without
/// limiting the cookie reply to the size of the packet that triggered it.
/// MAC1 uses the server's public key, so source-address hygiene still applies.
pub(crate) fn cookie_verdict(from: SocketAddr) -> CookieVerdict {
    if reply_target(from, Door::Cookie).is_none() {
        CookieVerdict::RefusedSource
    } else {
        CookieVerdict::Send
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(addr: &str) -> SocketAddr {
        addr.parse().unwrap()
    }

    #[test]
    fn loopback_cookie_replies_are_allowed_but_probe_replies_are_not() {
        for addr in ["127.0.0.1:51820", "[::1]:51820", "[::ffff:127.0.0.1]:51820"] {
            assert!(reply_target(peer(addr), Door::Cookie).is_some());
            assert_eq!(reply_target(peer(addr), Door::Probe), None);
        }
    }

    #[test]
    fn unsafe_cookie_destinations_are_refused() {
        for addr in [
            "0.0.0.0:40000",
            "224.0.0.1:40000",
            "255.255.255.255:40000",
            "169.254.1.1:40000",
            "[::]:40000",
            "[ff02::1]:40000",
            "[fe80::1]:40000",
            "203.0.113.5:0",
        ] {
            assert_eq!(cookie_verdict(peer(addr)), CookieVerdict::RefusedSource, "{addr}");
        }
    }

    #[test]
    fn cookie_reply_is_sent_even_when_s3_makes_it_larger_than_the_request() {
        // The exact S1/S2/S3 values are validated by AmneziaConfig tests. This
        // policy deliberately has no request/reply length arguments.
        assert_eq!(
            cookie_verdict(peer("203.0.113.5:40000")),
            CookieVerdict::Send
        );
    }
}
