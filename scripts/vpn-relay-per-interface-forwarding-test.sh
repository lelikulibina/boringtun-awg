#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${VPN_RELAY_BIN:-$ROOT/target/debug/vpn-relay}"
NS="vpn-relay-per-if-$$"
TMP="$(mktemp -d)"
PID=""
INODE=""

cleanup() {
    if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
        kill -TERM "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    ip netns del "$NS" 2>/dev/null || true
    if [[ -n "$INODE" ]]; then
        rm -f "/run/vpn-relay-netns-$INODE.forwarding"
        rm -f "/run/vpn-relay-netns-$INODE.lock"
        rm -f "/run/vpn-relay-netns-$INODE.control"
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

dump_forwarding_state() {
    echo "vpn-relay per-interface forwarding test: forwarding snapshot ($1)"
    ip netns exec "$NS" sh -c '
        for iface in all default lo uplink0 untrusted0 wg0; do
            path="/proc/sys/net/ipv4/conf/$iface/forwarding"
            if [ -r "$path" ]; then
                printf "%s=%s\n" "$iface" "$(cat "$path")"
            else
                printf "%s=<absent>\n" "$iface"
            fi
        done
        printf "ip_forward=%s\n" "$(cat /proc/sys/net/ipv4/ip_forward)"
    '
}

fail() {
    echo "vpn-relay per-interface forwarding test: $*" >&2
    [[ ! -f "$TMP/daemon.log" ]] || cat "$TMP/daemon.log" >&2
    [[ ! -f "$TMP/reject.log" ]] || cat "$TMP/reject.log" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || fail "must run as root"
[[ -x "$BIN" ]] || fail "vpn-relay binary not found at $BIN"
[[ -c /dev/net/tun ]] || fail "/dev/net/tun is unavailable"
command -v ip >/dev/null || fail "iproute2 is required"
command -v nft >/dev/null || fail "nftables is required"

cat >"$TMP/config.toml" <<'TOML'
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_per_if_test"
manage_ip_forwarding = true
forwarding_interfaces = ["uplink0", "wg0"]

[interfaces.wg0]
type = "wg"
address = ["10.200.0.1/24"]
mtu = 1380
listen_port = 52000
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
TOML

ip netns add "$NS"
INODE="$(ip netns exec "$NS" stat -Lc '%i' /proc/self/ns/net)"
ip -n "$NS" link set lo up
ip -n "$NS" link add uplink0 type dummy
ip -n "$NS" link set uplink0 up
ip -n "$NS" link add untrusted0 type dummy
ip -n "$NS" link set untrusted0 up

# IPv4's namespace switch is a prerequisite, not owned by vpn-relay.
ip netns exec "$NS" sysctl -qw net.ipv4.ip_forward=1
for iface in lo uplink0 untrusted0; do
    ip netns exec "$NS" sysctl -qw "net.ipv4.conf.$iface.forwarding=0"
done
# An unmanaged interface with forwarding enabled must make startup fail
# before the daemon changes any interface sysctl or installs its firewall.
ip netns exec "$NS" sysctl -qw net.ipv4.conf.untrusted0.forwarding=1
if ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" >"$TMP/reject.log" 2>&1; then
    fail "daemon accepted an unmanaged IPv4 forwarding interface"
fi
grep -Fq "unmanaged interface 'untrusted0' has IPv4 forwarding enabled" "$TMP/reject.log" || fail "startup rejection did not identify the unmanaged forwarding interface"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.conf.untrusted0.forwarding)" == "1" ]] || fail "rejected startup modified the administrator-owned sysctl"
ip netns exec "$NS" nft list table inet vpn_relay_per_if_test >/dev/null 2>&1 && fail "firewall leaked after unmanaged-forwarding rejection"
ip netns exec "$NS" sysctl -qw net.ipv4.conf.untrusted0.forwarding=0

start_daemon() {
    ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" >"$TMP/daemon.log" 2>&1 &
    PID=$!
    for _ in $(seq 1 30); do
        if ip netns exec "$NS" nft list table inet vpn_relay_per_if_test >/dev/null 2>&1 \
            && [[ "$(ip netns exec "$NS" sysctl -n net.ipv4.conf.uplink0.forwarding)" == "1" ]] \
; then
            return 0
        fi
        if ! kill -0 "$PID" 2>/dev/null; then
            wait "$PID" || true
            PID=""
            return 1
        fi
        sleep 1
    done
    return 1
}

start_daemon || fail "daemon did not enable selected per-interface forwarding"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.conf.untrusted0.forwarding)" == "0" ]] || fail "unmanaged IPv4 interface was enabled"

# Changes made by another administrator while the daemon is running must be
# detected; the daemon stops and retains its fail-closed firewall.
ip netns exec "$NS" sysctl -qw net.ipv4.conf.untrusted0.forwarding=1
for _ in $(seq 1 10); do
    state="$(ps -o stat= -p "$PID" 2>/dev/null | tr -d ' ' || true)"
    [[ -z "$state" || "$state" == Z* ]] && break
    sleep 1
done
state="$(ps -o stat= -p "$PID" 2>/dev/null | tr -d ' ' || true)"
if [[ -n "$state" && "$state" != Z* ]]; then
    fail "daemon did not detect runtime forwarding isolation drift"
fi
set +e
wait "$PID"
tamper_status=$?
set -e
PID=""
[[ $tamper_status -ne 0 ]] || fail "daemon exited successfully after forwarding isolation drift"
ip netns exec "$NS" nft list table inet vpn_relay_per_if_test >/dev/null 2>&1 || fail "fail-closed firewall was removed after forwarding isolation drift"
grep -Fq "per-interface forwarding invariants changed at runtime" "$TMP/daemon.log" || fail "daemon did not report runtime forwarding isolation drift"
ip netns exec "$NS" sysctl -qw net.ipv4.conf.untrusted0.forwarding=0
dump_forwarding_state "after drift reset"
ip netns exec "$NS" nft delete table inet vpn_relay_per_if_test

start_daemon || fail "daemon did not restart after forwarding drift recovery"
kill -TERM "$PID"
wait "$PID" || fail "daemon failed during graceful per-interface restore"
PID=""
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.conf.uplink0.forwarding)" == "0" ]] || fail "IPv4 interface forwarding was not restored"
dump_forwarding_state "after graceful shutdown before SIGKILL test"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || fail "daemon changed externally-owned IPv4 global forwarding"
ip netns exec "$NS" nft list table inet vpn_relay_per_if_test >/dev/null 2>&1 && fail "firewall survived graceful shutdown"

# SIGKILL leaves the durable journal but closes the TUN descriptor. Recovery
# restores persistent links and never applies a daemon-owned TUN entry to a
# replacement, even if the kernel recycles the old name and ifindex.
dump_forwarding_state "immediately before SIGKILL recovery startup"
start_daemon || fail "daemon did not restart for SIGKILL recovery test"
kill -KILL "$PID"
wait "$PID" 2>/dev/null || true
PID=""
[[ -f "/run/vpn-relay-netns-$INODE.forwarding" ]] || fail "SIGKILL did not leave the forwarding journal"
grep -Fq '"daemon_owned":true' "/run/vpn-relay-netns-$INODE.forwarding" || fail "journal did not mark the daemon-owned TUN entry"
ip netns exec "$NS" ip link show dev wg0 >/dev/null 2>&1 && fail "TUN survived SIGKILL unexpectedly"

start_daemon || fail "daemon could not recover journal after its TUN disappeared"
kill -TERM "$PID"
wait "$PID" || fail "daemon failed after per-interface journal recovery"
PID=""
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.conf.uplink0.forwarding)" == "0" ]] || fail "uplink IPv4 sysctl was not restored after SIGKILL recovery"
[[ ! -e "/run/vpn-relay-netns-$INODE.forwarding" ]] || fail "forwarding journal remained after successful recovery and shutdown"

echo "vpn-relay per-interface forwarding test passed"
