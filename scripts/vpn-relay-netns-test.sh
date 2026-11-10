#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${VPN_RELAY_BIN:-$ROOT/target/debug/vpn-relay}"
NS="vpn-relay-it-$$"
TMP="$(mktemp -d)"
DAEMON_PID=""
NETNS_INODE=""

cleanup() {
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    ip netns del "$NS" 2>/dev/null || true
    if [[ -n "$NETNS_INODE" ]]; then
        rm -f "/run/vpn-relay-netns-$NETNS_INODE.marks"
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
    echo "vpn-relay namespace test: $*" >&2
    for log in "$TMP/daemon.log" "$TMP/conflict.log" "$TMP/policy-conflict.log" "$TMP/route-conflict.log" "$TMP/policy-shadow-conflict.log" "$TMP/partial-setup-conflict.log" "$TMP/partial-policy-route.log" "$TMP/partial-forwarding.log" "$TMP/partial-ipv4-forwarding.log" "$TMP/partial-ipv4-forwarding-restore-failure.log" "$TMP/reload-failure.log" "$TMP/reload-route-failure.log" "$TMP/reload-immutable.log" "$TMP/shutdown-cleanup-failure.log" "$TMP/shutdown-forwarding-restore-failure.log" "$TMP/shutdown-ipv6-forwarding-restore-failure.log" "$TMP/preexisting-forwarding.log" "$TMP/forwarding-management-disabled.log"; do
        if [[ -f "$log" ]]; then
            cat "$log" >&2
        fi
    done
    exit 1
}

expect_startup_failure() {
    local log="$1"
    local description="$2"
    local path_prefix="${3:-}"
    if [[ -n "$path_prefix" ]]; then
        ip netns exec "$NS" env PATH="$path_prefix:$PATH" "$BIN" --config "$TMP/config.toml" >"$TMP/$log" 2>&1 &
    else
        ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" >"$TMP/$log" 2>&1 &
    fi
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
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "0" ]] || fail "IPv4 forwarding was not restored after rejecting $description"
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]] || fail "IPv6 forwarding was not restored after rejecting $description"
    if ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1; then
        fail "vpn-relay nftables table leaked after rejecting $description"
    fi
    for iface in wg-server awg-primary awg-secondary; do
        if ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1; then
            fail "TUN interface $iface leaked after rejecting $description"
        fi
    done
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
nft_table = "vpn_relay_it"
manage_ip_forwarding = true

[interfaces.wg-server]
type = "wg"
ipv6_enabled = false
address = ["10.10.0.1/24"]
listen_port = 51820
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
socket_fwmark = 4097

[interfaces.awg-primary]
type = "awg"
ipv6_enabled = true
address = ["10.20.0.2/32"]
listen_port = 51821
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
socket_fwmark = 4098

[interfaces.awg-primary.awg]
h1 = "1"
h2 = "2"
h3 = "3"
h4 = "4"
random_trailers = false
disable_cookies = false

[interfaces.awg-secondary]
type = "awg"
ipv6_enabled = false
address = ["10.30.0.2/32"]
listen_port = 51822
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
socket_fwmark = 4099

[interfaces.awg-secondary.awg]
s3 = 0
s4 = 0
h1 = "1-100"
h2 = "101-200"
h3 = "201-300"
h4 = "301-400"

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
NETNS_INODE="$(ip netns exec "$NS" stat -Lc '%i' /proc/self/ns/net)"
ip -n "$NS" link set lo up
# The daemon must enable forwarding for its lifetime and restore the original
# namespace values when it exits.
ip netns exec "$NS" sysctl -qw net.ipv4.ip_forward=0
ip netns exec "$NS" sysctl -qw net.ipv6.conf.all.forwarding=0
ip -n "$NS" link add main0 type dummy
ip -n "$NS" link set main0 up
ip -n "$NS" route replace default dev main0
ip -n "$NS" -6 route replace default dev main0

# A separate administrator-owned base chain at an earlier hook priority must
# coexist with vpn-relay and survive its shutdown unchanged.
ip netns exec "$NS" nft add table inet foreign_filter
ip netns exec "$NS" nft 'add chain inet foreign_filter input { type filter hook input priority -10; policy accept; }'
ip netns exec "$NS" nft 'add chain inet foreign_filter forward { type filter hook forward priority -10; policy accept; }'
ip netns exec "$NS" nft 'add chain inet foreign_filter output { type filter hook output priority -10; policy accept; }'

# A foreign table with the configured name must be preserved. Startup must
# fail and roll back policy rules and TUN devices instead of deleting it.
ip netns exec "$NS" nft add table inet vpn_relay_it
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
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "0" ]] || fail "IPv4 forwarding changed after nftables ownership conflict"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]] || fail "IPv6 forwarding changed after nftables ownership conflict"
ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || fail "foreign nftables table was deleted"
if ip netns exec "$NS" ip -4 rule show | grep -Eq 'fwmark 0x(80000000|80000001|1001)'; then
    fail "policy rules leaked after nftables ownership conflict"
fi
for iface in wg-server awg-primary awg-secondary; do
    if ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1; then
        fail "TUN interface $iface leaked after startup failure"
    fi
done
ip netns exec "$NS" nft delete table inet vpn_relay_it
ip netns exec "$NS" nft list chain inet foreign_filter input >/dev/null || fail "foreign INPUT base chain was modified"
ip netns exec "$NS" nft list chain inet foreign_filter forward >/dev/null || fail "foreign FORWARD base chain was modified"
ip netns exec "$NS" nft list chain inet foreign_filter output >/dev/null || fail "foreign OUTPUT base chain was modified"

# A foreign rule that happens to use the daemon's priority, mark and table
# must not be adopted or removed merely because its selectors look identical.
ip -n "$NS" -4 rule add priority 9000 fwmark 0x1001 lookup main
ip -n "$NS" -6 rule add priority 9000 fwmark 0x1001 lookup main
expect_startup_failure policy-conflict.log "foreign policy rules"
ip -n "$NS" -4 rule show | grep -Fq 'fwmark 0x1001 lookup main' || fail "foreign IPv4 policy rule was removed"
ip -n "$NS" -6 rule show | grep -Fq 'fwmark 0x1001 lookup main' || fail "foreign IPv6 policy rule was removed"
ip -n "$NS" -4 rule del priority 9000 fwmark 0x1001 lookup main
ip -n "$NS" -6 rule del priority 9000 fwmark 0x1001 lookup main

# A broader fwmark rule at a higher precedence must not shadow the daemon's
# socket mark even when it does not occupy the reserved priority 9000 slot.
ip -n "$NS" -4 rule add priority 8000 fwmark 0x1000/0xffff0000 lookup main
ip -n "$NS" -6 rule add priority 8000 fwmark 0x1000/0xffff0000 lookup main
expect_startup_failure policy-shadow-conflict.log "policy rule that shadows a reserved socket fwmark"
ip -n "$NS" -4 rule show | grep -Fq 'fwmark 0x1000/0xffff0000 lookup main' || fail "foreign masked IPv4 fwmark rule was removed"
ip -n "$NS" -6 rule show | grep -Fq 'fwmark 0x1000/0xffff0000 lookup main' || fail "foreign masked IPv6 fwmark rule was removed"
ip -n "$NS" -4 rule del priority 8000 fwmark 0x1000/0xffff0000 lookup main
ip -n "$NS" -6 rule del priority 8000 fwmark 0x1000/0xffff0000 lookup main

# Pre-existing routes in reserved IPv4 and IPv6 tables must both be preserved.
ip -n "$NS" -4 route replace default dev main0 table 10000 proto static
ip -n "$NS" -6 route replace default dev main0 table 10000 proto static
expect_startup_failure route-conflict.log "foreign routing-table routes"
ip -n "$NS" -4 route show table 10000 | grep -Fq 'default dev main0 proto static' || fail "foreign IPv4 route in table 10000 was overwritten"
ip -n "$NS" -6 route show table 10000 | grep -Fq 'default dev main0 proto static' || fail "foreign IPv6 route in table 10000 was overwritten"
ip -n "$NS" -4 route del default dev main0 table 10000 proto static
ip -n "$NS" -6 route del default dev main0 table 10000 proto static

# Force a failure after two interfaces have already been created and configured.
# Interface names are processed in sorted order (awg-primary, awg-secondary,
# wg-server), so the pre-existing dummy link makes the final TUN creation fail.
ip -n "$NS" link add wg-server type dummy
ip -n "$NS" link set wg-server up
ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" >"$TMP/partial-setup-conflict.log" 2>&1 &
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
    fail "daemon did not reject a TUN name conflict after partial interface setup"
fi
set +e
wait "$DAEMON_PID"
partial_status=$?
set -e
DAEMON_PID=""
[[ $partial_status -ne 0 ]] || fail "daemon accepted a TUN name conflict after partial setup"
ip netns exec "$NS" ip link show dev wg-server >/dev/null 2>&1 || fail "rollback deleted the administrator-owned conflicting link"
for iface in awg-primary awg-secondary; do
    if ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1; then
        fail "partially-created TUN interface $iface leaked after startup rollback"
    fi
done
ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 && fail "nftables policy leaked after partial setup rollback"
if ip -n "$NS" -4 rule show | grep -Eq 'fwmark 0x(80000000|80000001|1001|1002)'; then
    fail "policy routing leaked after partial setup rollback"
fi
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "0" ]] || fail "partial setup failure changed IPv4 forwarding"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]] || fail "partial setup failure changed IPv6 forwarding"
ip -n "$NS" link del wg-server

# Inject an iproute2 failure after the first egress has installed its IPv4
# route and rule. Rollback must remove those partial resources as well as the
# socket rules and the fail-closed nftables table.
REAL_IP="$(command -v ip)"
mkdir -p "$TMP/fail-ip"
cat >"$TMP/fail-ip/ip" <<EOF
#!/bin/sh
if [ "\$1" = "-6" ] && [ "\$2" = "route" ] && [ "\$3" = "replace" ] \
    && [ "\$4" = "default" ] && [ "\$6" = "awg-primary" ] && [ "\$8" = "10000" ]; then
    echo "injected IPv6 policy-route failure" >&2
    exit 42
fi
exec "$REAL_IP" "\$@"
EOF
chmod +x "$TMP/fail-ip/ip"
expect_startup_failure partial-policy-route.log "injected IPv6 policy-route failure" "$TMP/fail-ip"
for family in -4 -6; do
    if ip -n "$NS" "$family" rule show | grep -Eq 'fwmark 0x(80000000|80000001|1001|1002|1003)'; then
        fail "policy rules leaked after partial policy-routing failure for $family"
    fi
done
for table in 10000 10001; do
    for family in -4 -6; do
        if ip -n "$NS" "$family" route show table "$table" | grep -Eq 'default dev (awg-primary|awg-secondary) proto 242'; then
            fail "policy routes leaked from table $table after partial policy-routing failure for $family"
        fi
    done
done

# Fail IPv6 forwarding after IPv4 forwarding has already been enabled. The
# daemon must restore IPv4 immediately and remove the routes, TUNs and nft
# policy that were installed earlier in startup.
REAL_SYSCTL="$(command -v sysctl)"
mkdir -p "$TMP/fail-sysctl"
cat >"$TMP/fail-sysctl/sysctl" <<EOF
#!/bin/sh
if [ "\$1" = "-w" ] && [ "\$2" = "net.ipv6.conf.all.forwarding=1" ]; then
    echo "injected IPv6 forwarding failure" >&2
    exit 42
fi
exec "$REAL_SYSCTL" "\$@"
EOF
chmod +x "$TMP/fail-sysctl/sysctl"
expect_startup_failure partial-forwarding.log "injected IPv6 forwarding failure" "$TMP/fail-sysctl"
for family in -4 -6; do
    if ip -n "$NS" "$family" rule show | grep -Eq 'fwmark 0x(80000000|80000001|1001|1002|1003)'; then
        fail "policy rules leaked after partial forwarding failure for $family"
    fi
done
for table in 10000 10001; do
    for family in -4 -6; do
        if ip -n "$NS" "$family" route show table "$table" | grep -Eq 'default dev (awg-primary|awg-secondary) proto 242'; then
            fail "policy routes leaked from table $table after partial forwarding failure for $family"
        fi
    done
done

# A failed IPv4 enable write is ambiguous: the sysctl may have changed before
# the command reported an error. Simulate that exact condition and require both
# families, routes, TUN links and nftables state to be restored.
REAL_SYSCTL_STARTUP="$(command -v sysctl)"
mkdir -p "$TMP/fail-ipv4-enable-sysctl"
cat >"$TMP/fail-ipv4-enable-sysctl/sysctl" <<EOF
#!/bin/sh
if [ "\$1" = "-w" ] && [ "\$2" = "net.ipv4.ip_forward=1" ]; then
    "$REAL_SYSCTL_STARTUP" "\$@" || exit "\$?"
    echo "injected IPv4 forwarding enable-after-write failure" >&2
    exit 42
fi
exec "$REAL_SYSCTL_STARTUP" "\$@"
EOF
chmod +x "$TMP/fail-ipv4-enable-sysctl/sysctl"
expect_startup_failure partial-ipv4-forwarding.log "IPv4 forwarding enable-after-write failure" "$TMP/fail-ipv4-enable-sysctl"
grep -Fq "injected IPv4 forwarding enable-after-write failure" "$TMP/partial-ipv4-forwarding.log" || fail "IPv4 enable-after-write failure was not observed"

# If the ambiguous IPv4 enable failure is followed by a failure restoring the
# original IPv6 value, startup must retain the already-installed fail-closed
# nftables policy instead of claiming a clean rollback.
mkdir -p "$TMP/fail-ipv4-enable-restore-sysctl"
cat >"$TMP/fail-ipv4-enable-restore-sysctl/sysctl" <<EOF
#!/bin/sh
if [ "\$1" = "-w" ] && [ "\$2" = "net.ipv4.ip_forward=1" ]; then
    "$REAL_SYSCTL_STARTUP" "\$@" || exit "\$?"
    echo "injected IPv4 forwarding enable-after-write failure" >&2
    exit 42
fi
if [ "\$1" = "-w" ] && [ "\$2" = "net.ipv6.conf.all.forwarding=0" ]; then
    echo "injected IPv6 forwarding restore failure after IPv4 enable error" >&2
    exit 43
fi
exec "$REAL_SYSCTL_STARTUP" "\$@"
EOF
chmod +x "$TMP/fail-ipv4-enable-restore-sysctl/sysctl"
if ip netns exec "$NS" env PATH="$TMP/fail-ipv4-enable-restore-sysctl:$PATH" "$BIN" --config "$TMP/config.toml" >"$TMP/partial-ipv4-forwarding-restore-failure.log" 2>&1; then
    fail "daemon accepted an IPv4 enable failure followed by an IPv6 restore failure"
fi
grep -Fq "injected IPv4 forwarding enable-after-write failure" "$TMP/partial-ipv4-forwarding-restore-failure.log" || fail "ambiguous IPv4 enable failure was not reported"
grep -Fq "injected IPv6 forwarding restore failure after IPv4 enable error" "$TMP/partial-ipv4-forwarding-restore-failure.log" || fail "IPv6 restore failure was not reported"
grep -Fq "startup aborted with forwarding state uncertain; retaining nftables policy" "$TMP/partial-ipv4-forwarding-restore-failure.log" || fail "startup did not retain fail-closed policy after forwarding rollback failure"
ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || fail "fail-closed nftables policy was removed after forwarding rollback failure"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "0" ]] || fail "IPv4 forwarding was not restored after ambiguous enable failure"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]] || fail "IPv6 forwarding unexpectedly changed during failed restore"
for iface in wg-server awg-primary awg-secondary; do
    if ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1; then
        fail "TUN interface $iface leaked after forwarding rollback failure"
    fi
done
for family in -4 -6; do
    if ip -n "$NS" "$family" rule show | grep -q 'proto 242'; then
        fail "policy rules leaked after forwarding rollback failure for $family"
    fi
done
ip netns exec "$NS" nft delete table inet vpn_relay_it

REAL_NFT="$(command -v nft)"
REAL_IP="$(command -v ip)"
mkdir -p "$TMP/fail-nft-bin"
cat >"$TMP/fail-nft-bin/ip" <<EOF
#!/bin/sh
if [ -f "$TMP/fail-route" ] && [ "\$1" = "-4" ] && [ "\$2" = "route" ] \
    && [ "\$3" = "replace" ] && [ "\$6" = "awg-secondary" ] && [ "\$8" = "11001" ]; then
    echo "injected reload policy-route failure" >&2
    exit 42
fi
if [ -f "$TMP/fail-old-route-cleanup" ] && [ "\$1" = "-4" ] && [ "\$2" = "route" ] \
    && [ "\$3" = "del" ] && [ "\$8" = "11001" ]; then
    rm -f "$TMP/fail-old-route-cleanup"
    echo "injected old policy-route cleanup failure" >&2
    exit 42
fi
exec "$REAL_IP" "\$@"
EOF
cat >"$TMP/fail-nft-bin/nft" <<EOF
#!/bin/sh
if [ -f "$TMP/fail-nft" ] && [ "\$1" = "-f" ]; then
    cat >/dev/null
    echo "injected nftables transaction failure" >&2
    exit 42
fi
exec "$REAL_NFT" "\$@"
EOF
chmod +x "$TMP/fail-nft-bin/ip" "$TMP/fail-nft-bin/nft"

ip netns exec "$NS" env PATH="$TMP/fail-nft-bin:$PATH" "$BIN" --config "$TMP/config.toml" >"$TMP/daemon.log" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 30); do
    ready=1
    ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || ready=0
    for iface in wg-server awg-primary awg-secondary; do
        ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1 || ready=0
    done
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || ready=0
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "1" ]] || ready=0
    ip -n "$NS" -4 rule show | grep -Fq 'fwmark 0x80000000 lookup 10000 proto 242' || ready=0
    if [[ $ready -eq 1 ]]; then
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        fail "daemon exited during startup"
    fi
    sleep 1
done
ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || fail "nftables table was not installed"
for iface in wg-server awg-primary awg-secondary; do
    ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1 || fail "TUN interface $iface was not created"
done
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || fail "IPv4 forwarding was not enabled during startup"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "1" ]] || fail "IPv6 forwarding was not enabled during startup"

# A second daemon in the same namespace must be rejected without disturbing
# the already-running instance or its networking state.
ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" >"$TMP/duplicate.log" 2>&1 &
DUPLICATE_PID=$!
set +e
wait "$DUPLICATE_PID"
duplicate_status=$?
set -e
[[ $duplicate_status -ne 0 ]] || fail "daemon accepted a duplicate instance in the same namespace"
grep -q "already running" "$TMP/duplicate.log" || fail "duplicate instance was rejected for an unexpected reason"
kill -0 "$DAEMON_PID" 2>/dev/null || fail "original daemon exited after duplicate startup attempt"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || fail "duplicate startup changed IPv4 forwarding"

[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || fail "IPv4 forwarding was not enabled"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "1" ]] || fail "IPv6 forwarding was not enabled"

for family in -4 -6; do
    rules="$(ip -n "$NS" "$family" rule show)"
    grep -Fq 'fwmark 0x1001 lookup main proto 242' <<<"$rules" || fail "socket rule lacks vpn-relay ownership tag for $family"
    grep -Fq 'fwmark 0x80000000 lookup 10000 proto 242' <<<"$rules" || fail "primary rule lacks vpn-relay ownership tag for $family"
    routes="$(ip -n "$NS" "$family" route show table 10000)"
    grep -Fq 'default dev awg-primary proto 242' <<<"$routes" || fail "primary route lacks vpn-relay ownership tag for $family"
done
rules="$(ip -n "$NS" -4 rule show)"
grep -Fq 'fwmark 0x80000001 lookup 10001 proto 242' <<<"$rules" || fail "secondary IPv4 rule lacks vpn-relay ownership tag; rules: $rules"
routes="$(ip -n "$NS" -4 route show table 10001)"
grep -Fq 'default dev awg-secondary proto 242' <<<"$routes" || fail "secondary IPv4 route lacks vpn-relay ownership tag"
if ip -n "$NS" -6 rule show | grep -Fq 'fwmark 0x80000001 lookup 10001'; then
    fail "IPv6 policy rule was installed for IPv6-disabled egress"
fi
if ip -n "$NS" -6 route show table 10001 2>/dev/null | grep -q .; then
    fail "IPv6 route was installed for IPv6-disabled egress"
fi

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
    "0x1001 main0"; do
    read -r mark expected <<<"$spec"
    result="$(ip netns exec "$NS" ip -6 route get 2001:db8::9 mark "$mark")"
    grep -q "dev $expected" <<<"$result" || fail "IPv6 mark $mark expected $expected, got: $result"
done

chain="$(ip netns exec "$NS" nft list chain inet vpn_relay_it prerouting)"
forward_chain="$(ip netns exec "$NS" nft list chain inet vpn_relay_it forward)"
grep -Fq 'iifname @managed_interfaces drop' <<<"$forward_chain" || fail "managed ingress isolation drop is missing"
grep -Fq 'oifname @managed_interfaces drop' <<<"$forward_chain" || fail "managed egress isolation drop is missing"
blocked_set="$(ip netns exec "$NS" nft list set inet vpn_relay_it ipv6_blocked_interfaces)"
grep -Fq '"awg-secondary"' <<<"$blocked_set" || fail "IPv6-disabled egress is absent from the blocked-interface set"
grep -Fq '"wg-server"' <<<"$blocked_set" || fail "IPv6-disabled ingress is absent from the blocked-interface set"
grep -Fq 'iifname @ipv6_blocked_interfaces meta nfproto ipv6 drop' <<<"$chain" || fail "IPv6 ingress drop is missing"
grep -Fq 'oifname @ipv6_blocked_interfaces meta nfproto ipv6 drop' <<<"$forward_chain" || fail "IPv6 egress drop is missing"
output_chain="$(ip netns exec "$NS" nft list chain inet vpn_relay_it output)"
grep -Fq 'oifname @ipv6_blocked_interfaces meta nfproto ipv6 drop' <<<"$output_chain" || fail "locally generated IPv6 egress drop is missing"
grep -Fq 'ct direction reply meta mark set 0' <<<"$chain" || fail "reply packet mark reset is missing"

grep -Eq 'iifname "wg-server" ct state new ip daddr 195.142.0.0/16 meta mark set 0x80000001 ct mark set .*0x50010000 return' <<<"$chain" || fail "secondary exception rule missing"
grep -Eq 'iifname "wg-server" ct state new ip daddr 0.0.0.0/0 meta mark set 0x80000000 ct mark set .*0x50030000 return' <<<"$chain" || fail "primary default rule missing"

# Exercise full runtime reload through the Unix control socket. The candidate
# changes a routing selector, adds an INPUT exception and installs a peer. First
# force nftables to fail after the peer commit; the daemon must roll the peer set
# back and remain healthy with the old nftables table still active.
cp "$TMP/config.toml" "$TMP/config-before-reload.toml"
sed -i 's/195.142.0.0\/16/198.51.100.0\/24/' "$TMP/config.toml"
# Move the default route from awg-primary to awg-secondary and allocate a
# disjoint fwmark range. This exercises parallel old/new policy resources.
sed -i '0,/^\[\[routing.rules\]\]/{s/^\[\[routing.rules\]\]/[routing]\nmark_base = 0x90000000\n\n[[routing.rules]]/}' "$TMP/config.toml"
sed -i 's/egress = "awg-primary"/egress = "awg-secondary"/g' "$TMP/config.toml"
cat >>"$TMP/config.toml" <<'TOML'

[[interfaces.wg-server.peers]]
public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
allowed_ips = ["10.10.0.2/32"]

[firewall.input]
[[firewall.input.rules]]
interface = "wg-server"
source = "10.10.0.2/32"
protocol = "udp"
ports = [53]
TOML

# Reserve the first dynamic table slot with foreign state. Reload must skip
# this slot rather than adopting or deleting another process's resources.
ip -n "$NS" -4 route add 203.0.113.0/24 dev lo table 11000 proto 99
ip -n "$NS" -4 rule add priority 12000 fwmark 0x40000000 lookup 11000

# Inject failure while staging the new egress route. The old policy
# route and nft classifier must remain active and no partial new route may leak.
touch "$TMP/fail-route"
if ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" --reload >"$TMP/reload-route-failure.log" 2>&1; then
    fail "runtime reload unexpectedly succeeded with injected policy-route failure"
fi
rm -f "$TMP/fail-route"
kill -0 "$DAEMON_PID" 2>/dev/null || fail "daemon exited after policy-route staging rollback"
chain_after_route_failure="$(ip netns exec "$NS" nft list chain inet vpn_relay_it prerouting)"
grep -Fq 'ip daddr 195.142.0.0/16' <<<"$chain_after_route_failure" || fail "route failure changed the active nftables classifier"
if ip -n "$NS" -4 rule show | grep -Fq 'fwmark 0x90000000 lookup 11001 proto 242'; then
    fail "route failure left behind a staged policy-routing rule"
fi
if ip -n "$NS" -4 route show table 11001 | grep -q .; then
    fail "route failure left behind a staged policy-routing route"
fi
ip -n "$NS" -4 route show table 10000 | grep -Fq 'default dev awg-primary proto 242' || fail "route failure removed the previous active egress route"

touch "$TMP/fail-nft"
if ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" --reload >"$TMP/reload-failure.log" 2>&1; then
    fail "runtime reload unexpectedly succeeded with injected nftables failure"
fi
rm -f "$TMP/fail-nft"
kill -0 "$DAEMON_PID" 2>/dev/null || fail "daemon exited after successful peer rollback"
chain_after_failed_reload="$(ip netns exec "$NS" nft list chain inet vpn_relay_it prerouting)"
grep -Fq 'ip daddr 195.142.0.0/16' <<<"$chain_after_failed_reload" || fail "failed reload changed the active routing classifier"
if grep -Fq 'ip daddr 198.51.100.0/24' <<<"$chain_after_failed_reload"; then
    fail "failed reload partially installed the new routing classifier"
fi
if ip -n "$NS" -4 rule show | grep -Fq 'fwmark 0x90000000 lookup 11001 proto 242'; then
    fail "failed reload left behind a staged policy-routing rule"
fi
if ip -n "$NS" -4 route show table 11001 | grep -q .; then
    fail "failed reload left behind a staged policy-routing route"
fi

# Retry without failure injection. The new routing selector, firewall exception
# and peer set must become active together from the daemon's point of view.
ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" --reload >"$TMP/reload-success.log" 2>&1 || fail "runtime reload failed after removing nftables failure injection"
chain_after_reload="$(ip netns exec "$NS" nft list chain inet vpn_relay_it prerouting)"
grep -Fq 'ip daddr 198.51.100.0/24' <<<"$chain_after_reload" || fail "successful reload did not install the new routing selector"
if grep -Fq 'ip daddr 195.142.0.0/16' <<<"$chain_after_reload"; then
    fail "successful reload retained the old routing selector"
fi
ip -n "$NS" -4 rule show | grep -Fq 'fwmark 0x90000000 lookup 11001 proto 242' || fail "successful reload did not install the new routing rule"
ip -n "$NS" -4 route show table 11001 | grep -Fq 'default dev awg-secondary proto 242' || fail "successful reload did not install the new egress route"
ip -n "$NS" -4 route show table 11000 | grep -Fq '203.0.113.0/24 dev lo' || fail "reload modified the foreign route table"
ip -n "$NS" -4 rule show | grep -Fq 'fwmark 0x40000000 lookup 11000' || fail "reload modified the foreign rule referencing table 11000"
for old_mark in 0x80000000 0x80000001; do
    if ip -n "$NS" -4 rule show | grep -Fq "fwmark $old_mark"; then
        fail "successful reload retained an old routing mark rule ($old_mark)"
    fi
done
for old_table in 10000 10001; do
    if ip -n "$NS" -4 route show table "$old_table" | grep -q .; then
        fail "successful reload retained an old egress route table ($old_table)"
    fi
done
input_after_reload="$(ip netns exec "$NS" nft list chain inet vpn_relay_it input)"
grep -Fq 'ip saddr 10.10.0.2 udp dport 53' <<<"$input_after_reload" || fail "successful reload did not install the new INPUT exception"
for family in -4 -6; do
    for socket_mark in 0x1001 0x1002 0x1003; do
        ip -n "$NS" "$family" rule show | grep -Fq "fwmark $socket_mark lookup main proto 242" || fail "reload changed socket policy-routing rule $socket_mark for $family"
    done
done

# The legacy peer-only operation must remain available and must not replace the
# current firewall/routing plan with unrelated changes from the file.
sed -i 's/10.10.0.2\/32/10.10.0.3\/32/g' "$TMP/config.toml"
ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" --replace-peers wg-server >"$TMP/replace-peers.log" 2>&1 || fail "legacy peer-only replacement failed after runtime reload"
kill -0 "$DAEMON_PID" 2>/dev/null || fail "daemon exited after peer-only replacement"

# An immutable tunnel parameter change must be rejected without disturbing the
# currently active runtime configuration.
cp "$TMP/config.toml" "$TMP/config-before-immutable-reload.toml"
sed -i 's/listen_port = 51820/listen_port = 51830/' "$TMP/config.toml"
if ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" --reload >"$TMP/reload-immutable.log" 2>&1; then
    fail "runtime reload accepted an immutable tunnel listen-port change"
fi
mv "$TMP/config-before-immutable-reload.toml" "$TMP/config.toml"
kill -0 "$DAEMON_PID" 2>/dev/null || fail "daemon exited after rejecting an immutable reload"
input_after_rejected_reload="$(ip netns exec "$NS" nft list chain inet vpn_relay_it input)"
grep -Fq 'ip saddr 10.10.0.2 udp dport 53' <<<"$input_after_rejected_reload" || fail "rejected immutable reload changed the active firewall policy"

# A failure while retiring the old routes happens after nftables has switched.
# The daemon must report a fatal transition, stop, and retry cleanup of both
# the partially-retired old plan and the newly active plan during Drop.
sed -i 's/0x90000000/0xA0000000/g; s/egress = "awg-secondary"/egress = "awg-primary"/g' "$TMP/config.toml"
touch "$TMP/fail-old-route-cleanup"
if ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" --reload >"$TMP/reload-old-route-cleanup.log" 2>&1; then
    fail "runtime reload succeeded despite injected old-route cleanup failure"
fi
grep -Fq 'old policy routes could not be removed' "$TMP/reload-old-route-cleanup.log" || fail "reload did not report fatal old-route cleanup failure"
if wait "$DAEMON_PID"; then
    fail "daemon exited successfully after fatal old-route cleanup failure"
fi
DAEMON_PID=""
# The fatal daemon must have removed its control socket as part of shutdown;
# a subsequent management request must not reach a stale listener.
if ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" --reload >"$TMP/reload-after-fatal.log" 2>&1; then
    fail "control socket accepted a reload after fatal daemon shutdown"
fi
if ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1; then
    fail "daemon-owned nftables table survived fatal cleanup shutdown"
fi
for table in 11001 11002; do
    if ip -n "$NS" -4 route show table "$table" | grep -q .; then
        fail "policy routes survived fatal cleanup shutdown in table $table"
    fi
done
if ip -n "$NS" -4 rule show | grep -q 'proto 242'; then
    fail "vpn-relay policy rules survived fatal cleanup shutdown"
fi
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "0" ]] || fail "IPv4 forwarding was not restored after fatal cleanup"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]] || fail "IPv6 forwarding was not restored after fatal cleanup"
for iface in wg-server awg-primary awg-secondary; do
    if ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1; then
        fail "TUN interface $iface survived fatal cleanup shutdown"
    fi
done

[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "0" ]] || fail "IPv4 forwarding value was not restored"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]] || fail "IPv6 forwarding value was not restored"

if ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1; then
    fail "daemon-owned nftables table survived shutdown"
fi
ip netns exec "$NS" nft list chain inet foreign_filter input >/dev/null || fail "foreign INPUT base chain was modified"
ip netns exec "$NS" nft list chain inet foreign_filter forward >/dev/null || fail "foreign FORWARD base chain was modified"
ip netns exec "$NS" nft list chain inet foreign_filter output >/dev/null || fail "foreign OUTPUT base chain was modified"
if ip netns exec "$NS" ip -4 rule show | grep -Eq 'fwmark 0x8000000[01]'; then
    fail "inner packet policy rule survived shutdown"
fi
if ip netns exec "$NS" ip -4 rule show | grep -q 'fwmark 0x1001'; then
    fail "outer socket policy rule survived shutdown"
fi
for family in -4 -6; do
    if ip -n "$NS" "$family" rule show | grep -q 'proto 242'; then
        fail "vpn-relay policy rule survived shutdown for $family"
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

# A failed policy-rule cleanup during graceful shutdown must retain the
# nftables policy. Let startup complete before enabling the ip wrapper failure,
# then request graceful shutdown through SIGTERM (handled by the daemon).
REAL_IP_SHUTDOWN="$(command -v ip)"
mkdir -p "$TMP/fail-shutdown-ip"
cat >"$TMP/fail-shutdown-ip/ip" <<EOF
#!/bin/sh
if [ -f "$TMP/fail-shutdown-rule-delete" ] && [ "\$1" = "-4" ] \
    && [ "\$2" = "rule" ] && [ "\$3" = "del" ] \
    && [ "\$4" = "priority" ] && [ "\$5" = "9000" ]; then
    echo "injected shutdown policy-rule cleanup failure" >&2
    exit 42
fi
exec "$REAL_IP_SHUTDOWN" "\$@"
EOF
chmod +x "$TMP/fail-shutdown-ip/ip"
ip netns exec "$NS" env PATH="$TMP/fail-shutdown-ip:$PATH" "$BIN" --config "$TMP/config.toml" >"$TMP/shutdown-cleanup-failure.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 30); do
    ready=1
    ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || ready=0
    ip -n "$NS" -4 rule show | grep -Fq 'fwmark 0x1001 lookup main proto 242' || ready=0
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || ready=0
    [[ $ready -eq 1 ]] && break
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        fail "daemon exited before shutdown-cleanup failure test became ready"
    fi
    sleep 1
done
[[ $ready -eq 1 ]] || fail "daemon did not become ready for shutdown-cleanup failure test"
touch "$TMP/fail-shutdown-rule-delete"
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" || fail "daemon failed while handling graceful shutdown cleanup failure"
DAEMON_PID=""
ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || fail "nftables fail-closed policy was removed despite policy-rule cleanup failure"
ip -n "$NS" -4 rule show | grep -Fq 'fwmark 0x1001 lookup main proto 242' || fail "injected policy rule unexpectedly disappeared during failed cleanup"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "0" ]] || fail "IPv4 forwarding was not restored after shutdown cleanup failure"
grep -Fq "shutdown cleanup incomplete; retaining fail-closed nftables policy" "$TMP/shutdown-cleanup-failure.log" || fail "daemon did not report retained fail-closed policy"
# A failed IPv4 forwarding restore during graceful shutdown must also retain
# the nftables policy, while restoration of IPv6 must still be attempted.
REAL_SYSCTL_SHUTDOWN="$(command -v sysctl)"
mkdir -p "$TMP/fail-shutdown-sysctl"
cat >"$TMP/fail-shutdown-sysctl/sysctl" <<EOF
#!/bin/sh
if [ -f "$TMP/fail-shutdown-forwarding-restore" ] && [ "\$1" = "-w" ] \
    && [ "\$2" = "net.ipv4.ip_forward=0" ]; then
    echo "injected shutdown IPv4 forwarding restore failure" >&2
    exit 42
fi
exec "$REAL_SYSCTL_SHUTDOWN" "\$@"
EOF
chmod +x "$TMP/fail-shutdown-sysctl/sysctl"
ip netns exec "$NS" env PATH="$TMP/fail-shutdown-sysctl:$PATH" "$BIN" --config "$TMP/config.toml" >"$TMP/shutdown-forwarding-restore-failure.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 30); do
    ready=1
    ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || ready=0
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || ready=0
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "1" ]] || ready=0
    [[ $ready -eq 1 ]] && break
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        fail "daemon exited before shutdown-forwarding failure test became ready"
    fi
    sleep 1
done
[[ $ready -eq 1 ]] || fail "daemon did not become ready for shutdown-forwarding failure test"
touch "$TMP/fail-shutdown-forwarding-restore"
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" || fail "daemon failed while handling graceful shutdown forwarding restore failure"
DAEMON_PID=""
ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || fail "nftables fail-closed policy was removed despite IPv4 forwarding restore failure"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || fail "injected IPv4 forwarding restore unexpectedly succeeded"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]] || fail "IPv6 forwarding was not restored after IPv4 restore failure"
grep -Fq "injected shutdown IPv4 forwarding restore failure" "$TMP/shutdown-forwarding-restore-failure.log" || fail "daemon log omitted injected IPv4 forwarding restore failure"
grep -Fq "shutdown cleanup incomplete; retaining fail-closed nftables policy" "$TMP/shutdown-forwarding-restore-failure.log" || fail "daemon did not report retained fail-closed policy after forwarding restore failure"
# Repair the deliberately retained state with the real sysctl executable.
ip netns exec "$NS" "$REAL_SYSCTL_SHUTDOWN" -w net.ipv4.ip_forward=0 >/dev/null
ip netns exec "$NS" nft delete table inet vpn_relay_it

# Exercise the other forwarding family independently: an IPv6 restore failure
# must preserve the policy without preventing IPv4 from being restored.
mkdir -p "$TMP/fail-shutdown-ipv6-sysctl"
cat >"$TMP/fail-shutdown-ipv6-sysctl/sysctl" <<EOF
#!/bin/sh
if [ -f "$TMP/fail-shutdown-ipv6-forwarding-restore" ] && [ "\$1" = "-w" ] \
    && [ "\$2" = "net.ipv6.conf.all.forwarding=0" ]; then
    echo "injected shutdown IPv6 forwarding restore failure" >&2
    exit 42
fi
exec "$REAL_SYSCTL_SHUTDOWN" "\$@"
EOF
chmod +x "$TMP/fail-shutdown-ipv6-sysctl/sysctl"
ip netns exec "$NS" env PATH="$TMP/fail-shutdown-ipv6-sysctl:$PATH" "$BIN" --config "$TMP/config.toml" >"$TMP/shutdown-ipv6-forwarding-restore-failure.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 30); do
    ready=1
    ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || ready=0
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || ready=0
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "1" ]] || ready=0
    [[ $ready -eq 1 ]] && break
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        fail "daemon exited before IPv6 shutdown-forwarding failure test became ready"
    fi
    sleep 1
done
[[ $ready -eq 1 ]] || fail "daemon did not become ready for IPv6 shutdown-forwarding failure test"
touch "$TMP/fail-shutdown-ipv6-forwarding-restore"
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" || fail "daemon failed while handling graceful IPv6 forwarding restore failure"
DAEMON_PID=""
ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || fail "nftables fail-closed policy was removed despite IPv6 forwarding restore failure"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "0" ]] || fail "IPv4 forwarding was not restored after IPv6 restore failure"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "1" ]] || fail "injected IPv6 forwarding restore unexpectedly succeeded"
grep -Fq "injected shutdown IPv6 forwarding restore failure" "$TMP/shutdown-ipv6-forwarding-restore-failure.log" || fail "daemon log omitted injected IPv6 forwarding restore failure"
grep -Fq "shutdown cleanup incomplete; retaining fail-closed nftables policy" "$TMP/shutdown-ipv6-forwarding-restore-failure.log" || fail "daemon did not retain fail-closed policy after IPv6 forwarding restore failure"
ip netns exec "$NS" "$REAL_SYSCTL_SHUTDOWN" -w net.ipv6.conf.all.forwarding=0 >/dev/null
ip netns exec "$NS" nft delete table inet vpn_relay_it

# Forwarding may already be enabled by the host before vpn-relay starts.
# The daemon must preserve that original state rather than unconditionally
# disabling forwarding during graceful shutdown.
ip netns exec "$NS" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$NS" sysctl -qw net.ipv6.conf.all.forwarding=1
ip netns exec "$NS" "$BIN" --config "$TMP/config.toml" >"$TMP/preexisting-forwarding.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 30); do
    ready=1
    ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || ready=0
    for iface in wg-server awg-primary awg-secondary; do
        ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1 || ready=0
    done
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || ready=0
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "1" ]] || ready=0
    [[ $ready -eq 1 ]] && break
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        fail "daemon exited before pre-existing forwarding state test became ready"
    fi
    sleep 1
done
[[ $ready -eq 1 ]] || fail "daemon did not become ready with pre-existing forwarding enabled"
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" || fail "daemon failed while restoring pre-existing forwarding state"
DAEMON_PID=""
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || fail "daemon disabled pre-existing IPv4 forwarding during shutdown"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "1" ]] || fail "daemon disabled pre-existing IPv6 forwarding during shutdown"
if ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1; then
    fail "daemon-owned nftables table survived shutdown with pre-existing forwarding"
fi
for iface in wg-server awg-primary awg-secondary; do
    if ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1; then
        fail "TUN interface $iface survived shutdown with pre-existing forwarding"
    fi
done
ip netns exec "$NS" sysctl -qw net.ipv4.ip_forward=0
ip netns exec "$NS" sysctl -qw net.ipv6.conf.all.forwarding=0

# When forwarding management is disabled, vpn-relay must leave both sysctls
# untouched across startup and shutdown, even if their initial values differ.
cp "$TMP/config.toml" "$TMP/config-no-forwarding-management.toml"
sed -i 's/manage_ip_forwarding = true/manage_ip_forwarding = false/' "$TMP/config-no-forwarding-management.toml"
ip netns exec "$NS" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$NS" sysctl -qw net.ipv6.conf.all.forwarding=0
ip netns exec "$NS" "$BIN" --config "$TMP/config-no-forwarding-management.toml" >"$TMP/forwarding-management-disabled.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 30); do
    ready=1
    ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1 || ready=0
    for iface in wg-server awg-primary awg-secondary; do
        ip netns exec "$NS" ip link show dev "$iface" >/dev/null 2>&1 || ready=0
    done
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || ready=0
    [[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]] || ready=0
    [[ $ready -eq 1 ]] && break
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        fail "daemon exited before forwarding-management-disabled test became ready"
    fi
    sleep 1
done
[[ $ready -eq 1 ]] || fail "daemon did not become ready with forwarding management disabled"
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID" || fail "daemon failed while forwarding management was disabled"
DAEMON_PID=""
[[ "$(ip netns exec "$NS" sysctl -n net.ipv4.ip_forward)" == "1" ]] || fail "daemon changed IPv4 forwarding while management was disabled"
[[ "$(ip netns exec "$NS" sysctl -n net.ipv6.conf.all.forwarding)" == "0" ]] || fail "daemon changed IPv6 forwarding while management was disabled"
if ip netns exec "$NS" nft list table inet vpn_relay_it >/dev/null 2>&1; then
    fail "daemon-owned nftables table survived shutdown with forwarding management disabled"
fi
ip netns exec "$NS" sysctl -qw net.ipv4.ip_forward=0

echo "vpn-relay namespace integration test passed"
