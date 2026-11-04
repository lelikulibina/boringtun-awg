#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BTRouted_BIN:-$ROOT/target/debug/btrouted}"
PROTO="${1:-wg}"
case "$PROTO" in
    wg|awg3_1) ;;
    *) echo "usage: $0 [wg|awg3_1]" >&2; exit 2 ;;
esac

SUFFIX="$$"
SERVER_NS="btrouted-srv-$SUFFIX"
CLIENT_NS="btrouted-cli-$SUFFIX"
SERVER_VETH="bts$SUFFIX"
CLIENT_VETH="btc$SUFFIX"
TMP="$(mktemp -d)"
SERVER_PID=""
CLIENT_PID=""

cleanup() {
    for pid in "$CLIENT_PID" "$SERVER_PID"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
    echo "btrouted peer traffic test ($PROTO): $*" >&2
    for log in "$TMP/server.log" "$TMP/client.log"; do
        if [[ -f "$log" ]]; then
            cat "$log" >&2
        fi
    done
    exit 1
}

[[ $EUID -eq 0 ]] || fail "must run as root"
[[ -x "$BIN" ]] || fail "btrouted binary not found at $BIN"
[[ -c /dev/net/tun ]] || fail "/dev/net/tun is unavailable"
for command in ip nft wg ping; do
    command -v "$command" >/dev/null || fail "$command is required"
done

SERVER_PRIVATE="$(wg genkey)"
SERVER_PUBLIC="$(printf '%s' "$SERVER_PRIVATE" | wg pubkey)"
CLIENT_PRIVATE="$(wg genkey)"
CLIENT_PUBLIC="$(printf '%s' "$CLIENT_PRIVATE" | wg pubkey)"

ip netns add "$SERVER_NS"
ip netns add "$CLIENT_NS"
ip link add "$SERVER_VETH" type veth peer name "$CLIENT_VETH"
ip link set "$SERVER_VETH" netns "$SERVER_NS"
ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" link set lo up
ip -n "$SERVER_NS" link set "$SERVER_VETH" up
ip -n "$CLIENT_NS" link set "$CLIENT_VETH" up
ip -n "$SERVER_NS" address add 192.0.2.1/24 dev "$SERVER_VETH"
ip -n "$CLIENT_NS" address add 192.0.2.2/24 dev "$CLIENT_VETH"

cat >"$TMP/server.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "btrouted_peer_srv_$SUFFIX"

[[interfaces]]
name = "wg-peer-test"
protocol = "$PROTO"
role = "server"
addresses = ["10.77.0.1/24"]
listen_port = 51871
private_key = "$SERVER_PRIVATE"
socket_fwmark = 5001

[[interfaces.peers]]
name = "test-client"
public_key = "$CLIENT_PUBLIC"
allowed_ips = ["10.77.0.2/32"]
TOML

cat >"$TMP/client.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "btrouted_peer_cli_$SUFFIX"

[[interfaces]]
name = "wg-peer-test"
protocol = "$PROTO"
role = "client"
addresses = ["10.77.0.2/24"]
listen_port = 51872
private_key = "$CLIENT_PRIVATE"
socket_fwmark = 5002

[[interfaces.peers]]
name = "test-server"
public_key = "$SERVER_PUBLIC"
endpoint = "192.0.2.1:51871"
allowed_ips = ["10.77.0.1/32"]
persistent_keepalive_secs = 1
TOML

"$BIN" --config "$TMP/server.toml" --check >/dev/null
"$BIN" --config "$TMP/client.toml" --check >/dev/null

ip netns exec "$SERVER_NS" "$BIN" --config "$TMP/server.toml" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
ip netns exec "$CLIENT_NS" "$BIN" --config "$TMP/client.toml" >"$TMP/client.log" 2>&1 &
CLIENT_PID=$!

for _ in $(seq 1 40); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then fail "server daemon exited during startup"; fi
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then fail "client daemon exited during startup"; fi
    if ip -n "$SERVER_NS" link show dev wg-peer-test >/dev/null 2>&1 \
        && ip -n "$CLIENT_NS" link show dev wg-peer-test >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done
ip -n "$SERVER_NS" link show dev wg-peer-test >/dev/null 2>&1 || fail "server TUN did not appear"
ip -n "$CLIENT_NS" link show dev wg-peer-test >/dev/null 2>&1 || fail "client TUN did not appear"

# A successful ping requires an authenticated handshake and real encrypted
# packet delivery over the veth-backed UDP underlay.
ip netns exec "$CLIENT_NS" ping -n -c 5 -W 2 10.77.0.1 || fail "client-to-server tunnel traffic failed"
ip netns exec "$SERVER_NS" ping -n -c 5 -W 2 10.77.0.2 || fail "server-to-client tunnel traffic failed"

sleep 2
grep -q "peer statistics" "$TMP/server.log" || fail "server did not publish peer statistics"
grep -q "peer statistics" "$TMP/client.log" || fail "client did not publish peer statistics"

echo "btrouted peer traffic test passed: protocol=$PROTO, bidirectional ICMP over encrypted tunnel"
