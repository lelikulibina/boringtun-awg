#!/usr/bin/env bash
set -euo pipefail

ROUTER="vpn-relay-fwd-r-$$"
CLIENT_A="vpn-relay-fwd-a-$$"
CLIENT_B="vpn-relay-fwd-b-$$"
CLIENT_BAD="vpn-relay-fwd-x-$$"

cleanup() {
    ip netns del "$CLIENT_A" 2>/dev/null || true
    ip netns del "$CLIENT_B" 2>/dev/null || true
    ip netns del "$CLIENT_BAD" 2>/dev/null || true
    ip netns del "$ROUTER" 2>/dev/null || true
}
trap cleanup EXIT

fail() {
    echo "vpn-relay per-interface forwarding packet test: $*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || fail "must run as root"
command -v ip >/dev/null || fail "iproute2 is required"
command -v ping >/dev/null || fail "iputils-ping is required"

ip netns add "$ROUTER"
ip netns add "$CLIENT_A"
ip netns add "$CLIENT_B"
ip netns add "$CLIENT_BAD"

ip link add a0 type veth peer name r-in0
ip link set a0 netns "$CLIENT_A"
ip link set r-in0 netns "$ROUTER"
ip link add b0 type veth peer name r-out0
ip link set b0 netns "$CLIENT_B"
ip link set r-out0 netns "$ROUTER"
ip link add bad0 type veth peer name r-bad0
ip link set bad0 netns "$CLIENT_BAD"
ip link set r-bad0 netns "$ROUTER"

for ns in "$ROUTER" "$CLIENT_A" "$CLIENT_B" "$CLIENT_BAD"; do
    ip -n "$ns" link set lo up
done
for pair in "$CLIENT_A:a0" "$CLIENT_B:b0" "$CLIENT_BAD:bad0"; do
    ns="${pair%%:*}"
    iface="${pair##*:}"
    ip -n "$ns" link set "$iface" up
done
for iface in r-in0 r-out0 r-bad0; do
    ip -n "$ROUTER" link set "$iface" up
done

ip -n "$ROUTER" address add 10.10.1.1/24 dev r-in0
ip -n "$CLIENT_A" address add 10.10.1.2/24 dev a0
ip -n "$ROUTER" address add 10.10.2.1/24 dev r-out0
ip -n "$CLIENT_B" address add 10.10.2.2/24 dev b0
ip -n "$ROUTER" address add 10.10.3.1/24 dev r-bad0
ip -n "$CLIENT_BAD" address add 10.10.3.2/24 dev bad0

ip -n "$ROUTER" -6 address add fd10:1::1/64 dev r-in0
ip -n "$CLIENT_A" -6 address add fd10:1::2/64 dev a0
ip -n "$ROUTER" -6 address add fd10:2::1/64 dev r-out0
ip -n "$CLIENT_B" -6 address add fd10:2::2/64 dev b0
ip -n "$ROUTER" -6 address add fd10:3::1/64 dev r-bad0
ip -n "$CLIENT_BAD" -6 address add fd10:3::2/64 dev bad0

ip -n "$CLIENT_A" route add 10.10.2.0/24 via 10.10.1.1
ip -n "$CLIENT_B" route add 10.10.1.0/24 via 10.10.2.1
ip -n "$CLIENT_BAD" route add 10.10.1.0/24 via 10.10.3.1
ip -n "$CLIENT_A" -6 route add fd10:2::/64 via fd10:1::1
ip -n "$CLIENT_B" -6 route add fd10:1::/64 via fd10:2::1
ip -n "$CLIENT_BAD" -6 route add fd10:1::/64 via fd10:3::1

# IPv4 needs the global switch plus an ingress-interface gate. IPv6 keeps
# global forwarding off and opts in only the selected ingress links.
ip netns exec "$ROUTER" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$ROUTER" sysctl -qw net.ipv6.conf.all.forwarding=0
ip netns exec "$ROUTER" sysctl -qw net.ipv4.conf.all.rp_filter=0
for iface in r-in0 r-out0 r-bad0; do
    ip netns exec "$ROUTER" sysctl -qw "net.ipv4.conf.$iface.rp_filter=0"
    ip netns exec "$ROUTER" sysctl -qw "net.ipv4.conf.$iface.forwarding=0"
    ip netns exec "$ROUTER" sysctl -qw "net.ipv6.conf.$iface.force_forwarding=0"
done
for iface in r-in0 r-out0; do
    ip netns exec "$ROUTER" sysctl -qw "net.ipv4.conf.$iface.forwarding=1"
    ip netns exec "$ROUTER" sysctl -qw "net.ipv6.conf.$iface.force_forwarding=1"
done

ip netns exec "$CLIENT_A" ping -n -c 2 -W 2 10.10.2.2 >/dev/null || fail "IPv4 packet was not forwarded from allowlisted ingress"
ip netns exec "$CLIENT_B" ping -n -c 2 -W 2 10.10.1.2 >/dev/null || fail "IPv4 reply path was not forwarded"
if ip netns exec "$CLIENT_BAD" ping -n -c 1 -W 1 10.10.1.2 >/dev/null 2>&1; then
    fail "IPv4 packet was forwarded from an interface outside the allowlist"
fi

ip netns exec "$CLIENT_A" ping -6 -n -c 2 -W 2 fd10:2::2 >/dev/null || fail "IPv6 force_forwarding did not forward allowlisted ingress"
ip netns exec "$CLIENT_B" ping -6 -n -c 2 -W 2 fd10:1::2 >/dev/null || fail "IPv6 reply path was not forwarded"
if ip netns exec "$CLIENT_BAD" ping -6 -n -c 1 -W 1 fd10:1::2 >/dev/null 2>&1; then
    fail "IPv6 packet was forwarded from an interface outside the allowlist"
fi

echo "vpn-relay per-interface forwarding packet test passed"
