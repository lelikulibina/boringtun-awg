#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BTRouted_BIN:-$ROOT/target/debug/btrouted}"
NS="btrouted-it-$$"
TMP="$(mktemp -d)"
DAEMON_PID=""

cleanup() {
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    ip netns del "$NS" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
    echo "btrouted namespace test: $*" >&2
    for log in "$TMP/daemon.log" "$TMP/conflict.log" "$TMP/policy-conflict.log" "$TMP/route-conflict.log"; do
        if [[ -f "$log" ]]; then
            cat "$log" >&2
        fi
    done
    exit 1
}

expect_startup_failure() {
    local log="$1"
    local description="$2"
    ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" >"$TMP/$log" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 30); do
        state="$(ps -o stat= -p "$DAEMON_PID" 2>/dev/null | tr -d ' ' || true)"
        if [[ -z "$state" || "$state" == Z* ]]; then
            break
        fi
        sleep 1
    done
    state="$(ps -o stat= -p "$DAEMON_PID" 2>/dev/null | tr -d ' ' || true)"
    if [[ -n "$state" && "$state" != Z* ]]; then
        fail "daemon did not reject $description"
    fi
    set +e
    wait "$DAEMON_PID"
    status=$?
    set -e
    DAEMON_PID=""
    [[ $status -ne 0 ]] || fail "daemon accepted $description"
    for iface in wg-server awg-primary awg-secondary; do
        if ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1; then
            fail "TUN interface $iface leaked after rejecting $description"
        fi
    done
}

[[ $EUID -eq 0 ]] || fail "must run as root"
[[ -x "$BIN" ]] || fail "btrouted binary not found at $BIN"
[[ -c /dev/net/tun ]] || fail "/dev/net/tun is unavailable"
command -v ip >/dev/null || fail "iproute2 is required"
command -v nft >/dev/null || fail "nftables is required"

cat >"$TMP/config.toml" <<'TOML'
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "btrouted_it"
manage_ip_forwarding = false

[[interfaces]]
name = "wg-server"
protocol = "wg"
role = "server"
addresses = ["10.10.0.1/24"]
listen_port = 51820
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
socket_fwmark = 4097

[[interfaces]]
name = "awg-primary"
protocol = "awg3_1"
role = "client"
addresses = ["10.20.0.2/32"]
listen_port = 51821
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
socket_fwmark = 4098

[interfaces.awg]
h1 = "1"
h2 = "2"
h3 = "3"
h4 = "4"

[[interfaces]]
name = "awg-secondary"
protocol = "awg2"
role = "client"
addresses = ["10.30.0.2/32"]
listen_port = 51822
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
socket_fwmark = 4099

[interfaces.awg]
h1 = "1"
h2 = "2"
h3 = "3"
h4 = "4"

[[routing.rules]]
priority = 10
ingress = "wg-server"
destination = "195.142.0.0/16"
egress = "awg-secondary"

[[routing.rules]]
priority = 20
ingress = "wg-server"
destination = "79.100.22.0/24"
egress = "awg-secondary"

[[routing.rules]]
priority = 100
ingress = "wg-server"
destination = "0.0.0.0/0"
egress = "awg-primary"
TOML

"$BIN" --config "$TMP/config.toml" --check >/dev/null

ip netns add "$NS"
ip -n "$NS" link set lo up
ip -n "$NS" link add main0 type dummy
ip -n "$NS" link set main0 up
ip -n "$NS" route replace default dev main0
ip -n "$NS" -6 route replace default dev main0

# A foreign table with the configured name must be preserved. Startup must
# fail and roll back policy rules and TUN devices instead of deleting it.
ip netns exec "$NS" nft add table inet btrouted_it
ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" >"$TMP/conflict.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 30); do
    state="$(ps -o stat= -p "$DAEMON_PID" 2>/dev/null | tr -d ' ' || true)"
    if [[ -z "$state" || "$state" == Z* ]]; then
        break
    fi
    sleep 1
done
state="$(ps -o stat= -p "$DAEMON_PID" 2>/dev/null | tr -d ' ' || true)"
if [[ -n "$state" && "$state" != Z* ]]; then
    fail "daemon did not reject a pre-existing foreign nftables table"
fi
set +e
wait "$DAEMON_PID"
conflict_status=$?
set -e
DAEMON_PID=""
[[ $conflict_status -ne 0 ]] || fail "daemon accepted a foreign nftables table"
ip netns exec "$NS" nft list table inet btrouted_it >/dev/null 2>&1 || fail "foreign nftables table was deleted"
if ip netns exec "$NS" ip -4 rule show | grep -Eq 'fwmark 0x(80000000|80000001|1001)'; then
    fail "policy rules leaked after nftables ownership conflict"
fi
for iface in wg-server awg-primary awg-secondary; do
    if ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1; then
        fail "TUN interface $iface leaked after startup failure"
    fi
done
ip netns exec "$NS" nft delete table inet btrouted_it

# A foreign rule that happens to use the daemon's priority, mark and table
# must not be adopted or removed merely because its selectors look identical.
ip -n "$NS" -4 rule add priority 9000 fwmark 0x1001 lookup main
ip -n "$NS" -6 rule add priority 9000 fwmark 0x1001 lookup main
expect_startup_failure policy-conflict.log "foreign policy rules"
ip -n "$NS" -4 rule show | grep -Fq 'fwmark 0x1001 lookup main' || fail "foreign IPv4 policy rule was removed"
ip -n "$NS" -6 rule show | grep -Fq 'fwmark 0x1001 lookup main' || fail "foreign IPv6 policy rule was removed"
ip -n "$NS" -4 rule del priority 9000 fwmark 0x1001 lookup main
ip -n "$NS" -6 rule del priority 9000 fwmark 0x1001 lookup main

# A pre-existing route in a reserved table must also be preserved.
ip -n "$NS" -4 route replace default dev main0 table 10000 proto static
expect_startup_failure route-conflict.log "foreign routing-table route"
ip -n "$NS" -4 route show table 10000 | grep -Fq 'default dev main0 proto static' || fail "foreign route in table 10000 was overwritten"
ip -n "$NS" -4 route del default dev main0 table 10000 proto static

ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" >"$TMP/daemon.log" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 30); do
    if ip netns exec "$NS" nft list table inet btrouted_it >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        fail "daemon exited during startup"
    fi
    sleep 1
done
ip netns exec "$NS" nft list table inet btrouted_it >/dev/null 2>&1 || fail "nftables table was not installed"

for family in -4 -6; do
    rules="$(ip -n "$NS" "$family" rule show)"
    grep -Fq 'fwmark 0x1001 lookup main proto 242' <<<"$rules" || fail "socket rule lacks btrouted ownership tag for $family"
    grep -Fq 'fwmark 0x80000000 lookup 10000 proto 242' <<<"$rules" || fail "primary rule lacks btrouted ownership tag for $family"
    grep -Fq 'fwmark 0x80000001 lookup 10001 proto 242' <<<"$rules" || fail "secondary rule lacks btrouted ownership tag for $family"
    routes="$(ip -n "$NS" "$family" route show table 10000)"
    grep -Fq 'default dev awg-primary proto 242' <<<"$routes" || fail "primary route lacks btrouted ownership tag for $family"
    routes="$(ip -n "$NS" "$family" route show table 10001)"
    grep -Fq 'default dev awg-secondary proto 242' <<<"$routes" || fail "secondary route lacks btrouted ownership tag for $family"
done

for spec in \
    "0x80000000 awg-primary" \
    "0x80000001 awg-secondary" \
    "0x1001 main0"; do
    read -r mark expected <<<"$spec"
    result="$(ip netns exec "$NS" ip -4 route get 203.0.113.9 mark "$mark")"
    grep -q "dev $expected" <<<"$result" || fail "IPv4 mark $mark expected $expected, got: $result"
done

for spec in \
    "0x80000000 awg-primary" \
    "0x80000001 awg-secondary" \
    "0x1001 main0"; do
    read -r mark expected <<<"$spec"
    result="$(ip netns exec "$NS" ip -6 route get 2001:db8::9 mark "$mark")"
    grep -q "dev $expected" <<<"$result" || fail "IPv6 mark $mark expected $expected, got: $result"
done

chain="$(ip netns exec "$NS" nft list chain inet btrouted_it prerouting)"
forward_chain="$(ip netns exec "$NS" nft list chain inet btrouted_it forward)"
grep -Fq 'iifname @managed_interfaces drop' <<<"$forward_chain" || fail "managed ingress isolation drop is missing"
grep -Fq 'oifname @managed_interfaces drop' <<<"$forward_chain" || fail "managed egress isolation drop is missing"
grep -Fq 'ct direction reply meta mark set 0' <<<"$chain" || fail "reply packet mark reset is missing"

grep -Fq 'iifname "wg-server" ip daddr 195.142.0.0/16 meta mark set 0x80000001 ct mark set meta mark return' <<<"$chain" || fail "secondary exception rule missing"
grep -Fq 'iifname "wg-server" ip daddr 0.0.0.0/0 meta mark set 0x80000000 ct mark set meta mark return' <<<"$chain" || fail "primary default rule missing"

kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" || fail "daemon returned an error during graceful shutdown"
DAEMON_PID=""

if ip netns exec "$NS" nft list table inet btrouted_it >/dev/null 2>&1; then
    fail "daemon-owned nftables table survived shutdown"
fi
if ip netns exec "$NS" ip -4 rule show | grep -Eq 'fwmark 0x8000000[01]'; then
    fail "inner packet policy rule survived shutdown"
fi
if ip netns exec "$NS" ip -4 rule show | grep -q 'fwmark 0x1001'; then
    fail "outer socket policy rule survived shutdown"
fi
for family in -4 -6; do
    if ip -n "$NS" "$family" rule show | grep -q 'proto 242'; then
        fail "btrouted policy rule survived shutdown for $family"
    fi
    if ip -n "$NS" "$family" route show table 10000 | grep -q .; then
        fail "primary policy route survived shutdown for $family"
    fi
    if ip -n "$NS" "$family" route show table 10001 | grep -q .; then
        fail "secondary policy route survived shutdown for $family"
    fi
done
for iface in wg-server awg-primary awg-secondary; do
    if ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1; then
        fail "TUN interface $iface survived shutdown"
    fi
done

echo "btrouted namespace integration test passed"
