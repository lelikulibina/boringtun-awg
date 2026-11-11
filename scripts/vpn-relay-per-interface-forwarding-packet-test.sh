#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${VPN_RELAY_BIN:-$ROOT/target/debug/vpn-relay}"
ROUTER="vpn-relay-fwd-r-$"
CLIENT_A="vpn-relay-fwd-a-$"
CLIENT_B="vpn-relay-fwd-b-$"
CLIENT_BAD="vpn-relay-fwd-x-$"
TABLE="vpn_relay_fwd_packet_$"
TMP="$(mktemp -d)"
PID=""
INODE=""

cleanup() {
    if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        kill -TERM "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    ip netns del "$CLIENT_A" 2>/dev/null || true
    ip netns del "$CLIENT_B" 2>/dev/null || true
    ip netns del "$CLIENT_BAD" 2>/dev/null || true
    ip netns del "$ROUTER" 2>/dev/null || true
    if [[ -n "$INODE" ]]; then
        rm -f "/run/vpn-relay-netns-$INODE.forwarding"
        rm -f "/run/vpn-relay-netns-$INODE.lock"
        rm -f "/run/vpn-relay-netns-$INODE.control"
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
    echo "vpn-relay per-interface forwarding packet test: $*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || fail "must run as root"
[[ -x "$BIN" ]] || fail "vpn-relay binary not found at $BIN"
[[ -c /dev/net/tun ]] || fail "/dev/net/tun is unavailable"
command -v ip >/dev/null || fail "iproute2 is required"
command -v nft >/dev/null || fail "nftables is required"
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

# Let vpn-relay own the per-interface switches. IPv4's namespace-wide
# prerequisite remains externally managed; IPv6 global forwarding stays off.
INODE="$(ip netns exec "$ROUTER" stat -Lc '%i' /proc/self/ns/net)"
ip netns exec "$ROUTER" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$ROUTER" sysctl -qw net.ipv6.conf.all.forwarding=0
ip netns exec "$ROUTER" sysctl -qw net.ipv4.conf.all.rp_filter=0
for iface in lo r-in0 r-out0 r-bad0; do
    ip netns exec "$ROUTER" sysctl -qw "net.ipv4.conf.$iface.rp_filter=0"
    ip netns exec "$ROUTER" sysctl -qw "net.ipv4.conf.$iface.forwarding=0"
    ip netns exec "$ROUTER" sysctl -qw "net.ipv6.conf.$iface.force_forwarding=0"
done
ip netns exec "$ROUTER" sysctl -qw net.ipv6.conf.r-in0.accept_ra=2

cat >"$TMP/router.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "$TABLE"
manage_ip_forwarding = true
forwarding_interfaces = ["r-in0", "r-out0", "wg0"]

[interfaces.wg0]
type = "wg"
address = ["10.200.0.1/24"]
mtu = 1380
listen_port = 52000
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
TOML

ip netns exec "$ROUTER" "$BIN" --config "$TMP/router.toml" >"$TMP/daemon.log" 2>&1 &
PID=$!
ready=false
for _ in $(seq 1 40); do
    if ! kill -0 "$PID" 2>/dev/null; then
        wait "$PID" || true
        PID=""
        fail "vpn-relay exited before forwarding became ready"
    fi
    if ip netns exec "$ROUTER" nft list table inet "$TABLE" >/dev/null 2>&1 \\
        && [[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv4.conf.r-in0.forwarding)" == "1" ]] \\
        && [[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv4.conf.r-out0.forwarding)" == "1" ]] \\
        && [[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv6.conf.r-in0.force_forwarding)" == "1" ]] \\
        && [[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv6.conf.r-out0.force_forwarding)" == "1" ]]; then
        ready=true
        break
    fi
    sleep 0.25
done
[[ "$ready" == true ]] || fail "vpn-relay did not enable selected per-interface forwarding"

[[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv4.conf.r-bad0.forwarding)" == "0" ]] || fail "daemon enabled untrusted IPv4 ingress"
[[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv6.conf.r-bad0.force_forwarding)" == "0" ]] || fail "daemon enabled untrusted IPv6 ingress"
[[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]] || fail "daemon enabled namespace-wide IPv6 forwarding"
[[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv6.conf.r-in0.forwarding)" == "0" ]] || fail "daemon changed IPv6 Host/Router forwarding mode"
[[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv6.conf.r-in0.accept_ra)" == "2" ]] || fail "daemon changed ingress Router Advertisement policy"

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

# Graceful shutdown must restore only the values owned by vpn-relay.
kill -TERM "$PID"
wait "$PID" || fail "vpn-relay failed during graceful shutdown"
PID=""
for iface in r-in0 r-out0; do
    [[ "$(ip netns exec "$ROUTER" sysctl -n "net.ipv4.conf.$iface.forwarding")" == "0" ]] || fail "IPv4 forwarding was not restored on $iface"
    [[ "$(ip netns exec "$ROUTER" sysctl -n "net.ipv6.conf.$iface.force_forwarding")" == "0" ]] || fail "IPv6 force_forwarding was not restored on $iface"
done
[[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv4.ip_forward)" == "1" ]] || fail "daemon changed externally-owned IPv4 global forwarding"
[[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]] || fail "daemon changed externally-owned IPv6 global forwarding"
[[ "$(ip netns exec "$ROUTER" sysctl -n net.ipv6.conf.r-in0.accept_ra)" == "2" ]] || fail "daemon changed ingress Router Advertisement policy"
ip netns exec "$ROUTER" nft list table inet "$TABLE" >/dev/null 2>&1 && fail "firewall table survived graceful shutdown"

echo "vpn-relay per-interface forwarding packet test passed"
