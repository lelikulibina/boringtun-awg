#!/usr/bin/env bash
set -euo pipefail

BIN="/usr/local/bin/vpn-relay"
TABLE="vpn_relay_podman"
TMP="$(mktemp -d)"
PID=""
HOST_NETNS_INODE="${HOST_NETNS_INODE:-}"

cleanup() {
    if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        kill -TERM "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
    echo "vpn-relay rootful Podman test: $*" >&2
    [[ ! -f "$TMP/daemon.log" ]] || cat "$TMP/daemon.log" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || fail "container process must run as root"
[[ -x "$BIN" ]] || fail "vpn-relay binary is missing"
[[ -c /dev/net/tun ]] || fail "/dev/net/tun is not available in the container"
command -v ip >/dev/null || fail "iproute2 is unavailable"
command -v nft >/dev/null || fail "nftables is unavailable"
[[ -n "$HOST_NETNS_INODE" ]] || fail "host network namespace inode was not provided"

CONTAINER_NETNS_INODE="$(stat -Lc '%i' /proc/self/ns/net)"
[[ "$CONTAINER_NETNS_INODE" != "$HOST_NETNS_INODE" ]] \
    || fail "container shares the host network namespace; private bridge namespace is required"
[[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]] \
    || fail "Podman did not configure the private namespace IPv4 forwarding prerequisite"

ip link show dev eth0 >/dev/null 2>&1 || fail "expected bridge interface eth0 is missing"
# Podman mounts /proc/sys read-only by default. Baseline values are supplied
# through its namespace-scoped --sysctl options, not written from the container.
[[ "$(cat /proc/sys/net/ipv4/conf/lo/forwarding)" == "0" ]] || fail "Podman did not set loopback forwarding baseline"
[[ "$(cat /proc/sys/net/ipv4/conf/eth0/forwarding)" == "0" ]] || fail "Podman did not set eth0 forwarding baseline"

# Prove nftables administration is available inside the container before
# vpn-relay starts; the daemon itself separately proves TUN and rtnetlink access.
nft add table inet vpn_relay_podman_capability_probe \
    || fail "CAP_NET_ADMIN does not permit nftables table creation"
nft delete table inet vpn_relay_podman_capability_probe \
    || fail "could not remove the nftables capability probe table"

cat >"$TMP/config.toml" <<'TOML'
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_podman"
manage_ip_forwarding = true
forwarding_interfaces = ["eth0", "wg0"]

[interfaces.wg0]
type = "wg"
address = ["10.200.0.1/24"]
mtu = 1380
listen_port = 52000
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
TOML

"$BIN" --config "$TMP/config.toml" >"$TMP/daemon.log" 2>&1 &
PID=$!
ready=false
for _ in $(seq 1 40); do
    if ! kill -0 "$PID" 2>/dev/null; then
        wait "$PID" || true
        PID=""
        fail "vpn-relay exited before the private-namespace datapath became ready"
    fi
    if nft list table inet "$TABLE" >/dev/null 2>&1 \
        && [[ "$(cat /proc/sys/net/ipv4/conf/eth0/forwarding)" == "1" ]] \
        && [[ "$(cat /proc/sys/net/ipv4/conf/wg0/forwarding 2>/dev/null || true)" == "1" ]]; then
        ready=true
        break
    fi
    sleep 0.25
done
[[ "$ready" == true ]] || fail "daemon did not configure TUN, nftables and per-interface IPv4 forwarding"

ip link show dev wg0 >/dev/null 2>&1 || fail "daemon-managed TUN wg0 is missing"
ip -4 address show dev wg0 | grep -Fq "10.200.0.1/24" || fail "TUN IPv4 address was not configured"
nft list chain inet "$TABLE" output | grep -Fq 'meta nfproto ipv6 drop' \
    || fail "managed-TUN IPv6 drop rule is missing"
kill -0 "$PID" 2>/dev/null || fail "daemon exited after successful startup"

kill -TERM "$PID" || fail "could not request graceful daemon shutdown"
if ! wait "$PID"; then
    PID=""
    fail "daemon failed during graceful shutdown inside Podman"
fi
PID=""

[[ "$(cat /proc/sys/net/ipv4/conf/eth0/forwarding)" == "0" ]] \
    || fail "daemon did not restore the original eth0 forwarding value"
[[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]] \
    || fail "daemon changed the externally managed namespace-wide IPv4 prerequisite"
ip link show dev wg0 >/dev/null 2>&1 && fail "daemon-managed TUN survived graceful shutdown"
nft list table inet "$TABLE" >/dev/null 2>&1 && fail "daemon firewall table survived graceful shutdown"

NETNS_INODE="$(stat -Lc '%i' /proc/self/ns/net)"
[[ ! -e "/run/vpn-relay-netns-$NETNS_INODE.forwarding" ]] \
    || fail "forwarding recovery journal remained after clean shutdown"

echo "vpn-relay rootful Podman test passed: private network namespace, NET_ADMIN, /dev/net/tun, nftables, rtnetlink and IPv4 sysctl"
