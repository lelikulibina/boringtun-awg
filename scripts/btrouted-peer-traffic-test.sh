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
SERVER_IPERF_PID=""
CLIENT_IPERF_PID=""

cleanup() {
    for pid in "$CLIENT_IPERF_PID" "$SERVER_IPERF_PID" "$CLIENT_PID" "$SERVER_PID"; do
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

dump_namespace_diagnostics() {
    local ns="$1"
    ip netns list >&2 || true
    if ! ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
        return
    fi
    echo "--- diagnostics for namespace $ns ---" >&2
    ip -n "$ns" -details link show >&2 || true
    ip -n "$ns" address show >&2 || true
    ip -n "$ns" -4 rule show >&2 || true
    ip -n "$ns" -6 rule show >&2 || true
    ip -n "$ns" -4 route show table all >&2 || true
    ip -n "$ns" -6 route show table all >&2 || true
    ip netns exec "$ns" nft -a list ruleset >&2 || true
    if [[ "$ns" == "$CLIENT_NS" ]]; then
        ip -n "$ns" -4 route get 192.0.2.1 mark 5002 >&2 || true
        ip -n "$ns" -4 route get 192.0.2.1 mark 0x80000000 >&2 || true
    fi
}

fail() {
    echo "btrouted peer traffic test ($PROTO): $*" >&2
    dump_namespace_diagnostics "$CLIENT_NS"
    dump_namespace_diagnostics "$SERVER_NS"
    for log in "$TMP/server.log" "$TMP/client.log" "$TMP/server-iperf.log" "$TMP/client-iperf.log"; do
        if [[ -f "$log" ]]; then
            echo "--- $log ---" >&2
            cat "$log" >&2
        fi
    done
    exit 1
}

[[ $EUID -eq 0 ]] || fail "must run as root"
[[ -x "$BIN" ]] || fail "btrouted binary not found at $BIN"
[[ -c /dev/net/tun ]] || fail "/dev/net/tun is unavailable"
for command in ip nft wg ping iperf3 python3 tcpdump timeout; do
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

[interfaces.wg-peer-test]
protocol = "$PROTO"
role = "server"
addresses = ["10.77.0.1/24"]
listen_port = 51871
private_key = "$SERVER_PRIVATE"
socket_fwmark = 5001

[[interfaces.wg-peer-test.peers]]
public_key = "$CLIENT_PUBLIC"
allowed_ips = ["10.77.0.2/32"]
TOML

cat >"$TMP/client.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "btrouted_peer_cli_$SUFFIX"

[interfaces.wg-peer-test]
protocol = "$PROTO"
role = "client"
addresses = ["10.77.0.2/24"]
listen_port = 51872
private_key = "$CLIENT_PRIVATE"
socket_fwmark = 5002

[[interfaces.wg-peer-test.peers]]
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

# TUN creation happens before policy routing and nftables installation. Wait
# for the daemon's externally observable routing state instead of racing the
# short interval between interface creation and Runtime::start completion.
socket_route=""
inner_route=""
routing_ready=0
for _ in $(seq 1 40); do
    socket_route="$(ip -n "$CLIENT_NS" route get 192.0.2.1 mark 5002 2>&1 || true)"
    inner_route="$(ip -n "$CLIENT_NS" route get 192.0.2.1 mark 0x80000000 2>&1 || true)"
    if grep -q "dev $CLIENT_VETH" <<<"$socket_route" \
        && grep -q "dev wg-peer-test" <<<"$inner_route" \
        && ip netns exec "$CLIENT_NS" nft list table inet "btrouted_peer_cli_$SUFFIX" >/dev/null 2>&1 \
        && ip netns exec "$SERVER_NS" nft list table inet "btrouted_peer_srv_$SUFFIX" >/dev/null 2>&1; then
        routing_ready=1
        break
    fi
    sleep 0.25
done
[[ "$routing_ready" -eq 1 ]] || fail "daemon routing setup did not become ready (socket: $socket_route; inner: $inner_route)"

# Outer encrypted UDP sockets must use the main underlay route, while packets
# carrying the inner-routing mark must use the TUN egress table. This catches
# accidental mark overlap and the most common tunnel-loop regression.
grep -q "dev $CLIENT_VETH" <<<"$socket_route" || fail "outer UDP socket mark escaped the underlay route: $socket_route"
grep -q "dev wg-peer-test" <<<"$inner_route" || fail "inner routing mark did not select the TUN egress: $inner_route"

# A successful ping requires an authenticated handshake and real encrypted
# packet delivery over the veth-backed UDP underlay.
ip netns exec "$CLIENT_NS" ping -n -c 5 -W 2 10.77.0.1 || fail "client-to-server tunnel traffic failed"
ip netns exec "$SERVER_NS" ping -n -c 5 -W 2 10.77.0.2 || fail "server-to-client tunnel traffic failed"

# Observe the real encrypted UDP transport: it must be visible on the physical
# underlay veth and must never reappear as an outer packet on the TUN device.
ip netns exec "$CLIENT_NS" timeout 5 tcpdump -nn -i "$CLIENT_VETH" -c 1 \
    'udp and dst host 192.0.2.1 and dst port 51871' >"$TMP/underlay-udp.log" 2>&1 \
    || fail "encrypted UDP transport was not observed on the underlay"
set +e
ip netns exec "$CLIENT_NS" timeout 3 tcpdump -nn -i wg-peer-test -c 1 \
    'udp and dst host 192.0.2.1 and dst port 51871' >"$TMP/tun-outer-udp.log" 2>&1
tun_capture_status=$?
set -e
[[ "$tun_capture_status" -eq 124 ]] || fail "outer encrypted UDP leaked into the TUN (tcpdump status $tun_capture_status)"


# Exercise TCP streams and UDP datagrams over the encrypted TUN path.
ip netns exec "$SERVER_NS" iperf3 -s >"$TMP/server-iperf.log" 2>&1 &
SERVER_IPERF_PID=$!
ip netns exec "$CLIENT_NS" iperf3 -s >"$TMP/client-iperf.log" 2>&1 &
CLIENT_IPERF_PID=$!
sleep 1
kill -0 "$SERVER_IPERF_PID" 2>/dev/null || fail "server iperf3 did not start"
kill -0 "$CLIENT_IPERF_PID" 2>/dev/null || fail "client iperf3 did not start"

run_iperf() {
    local label="$1"
    local minimum_bytes="$2"
    shift 2
    local output="$TMP/$label.json"
    ip netns exec "$CLIENT_NS" iperf3 "$@" --json >"$output" || fail "$label failed"
    python3 - "$output" "$label" "$minimum_bytes" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
received = result.get("end", {}).get("sum_received", {})
byte_count = received.get("bytes", 0)
minimum_bytes = int(sys.argv[3])
if byte_count < minimum_bytes:
    raise SystemExit(f"{sys.argv[2]} received only {byte_count} bytes; expected at least {minimum_bytes}")
if "lost_percent" in received and received["lost_percent"] > 2.0:
    raise SystemExit(f"{sys.argv[2]} UDP loss too high: {received['lost_percent']:.2f}%")
print(f"{sys.argv[2]}: received={byte_count} bytes" + (f", UDP loss={received['lost_percent']:.2f}%" if "lost_percent" in received else ""))
PY
}

# TCP: transfer 8 MiB in each direction with parallel streams.
run_iperf tcp-client-to-server 8388608 -c 10.77.0.1 -n 8M -P 2
run_iperf tcp-server-to-client 8388608 -c 10.77.0.1 -n 8M -P 2 -R

# UDP: sustained datagrams with 1200-byte payloads in both directions.
run_iperf udp-client-to-server 1000 -c 10.77.0.1 -u -b 3M -t 3 -l 1200
run_iperf udp-server-to-client 1000 -c 10.77.0.1 -u -b 3M -t 3 -l 1200 -R

sleep 2

assert_peer_counters() {
    local side="$1"
    local log="$2"
    local stats
    # Strip ANSI color sequences before matching structured tracing fields.
    stats="$(python3 - "$log" <<'PY'
import re
import sys
with open(sys.argv[1], encoding="utf-8", errors="replace") as stream:
    for line in stream:
        line = re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", line)
        if "peer statistics" in line:
            print(line, end="")
PY
    )"
    [[ -n "$stats" ]] || fail "$side did not publish peer statistics"
    grep -Eq 'tx_bytes=[1-9][0-9]*.*rx_bytes=[1-9][0-9]*|rx_bytes=[1-9][0-9]*.*tx_bytes=[1-9][0-9]*' <<<"$stats" \
        || fail "$side peer TX/RX byte counters did not both increase"
}

assert_peer_counters server "$TMP/server.log"
assert_peer_counters client "$TMP/client.log"

# Restart the remote daemon without restarting the local peer. Persistent
# keepalive must re-establish the session and restore bidirectional delivery.
kill -TERM "$SERVER_PID" || fail "could not stop server daemon for reconnect test"
wait "$SERVER_PID" || fail "server daemon failed during reconnect shutdown"
SERVER_PID=""
sleep 1
ip netns exec "$SERVER_NS" "$BIN" --config "$TMP/server.toml" >"$TMP/server-restarted.log" 2>&1 &
SERVER_PID=$!
recovered=0
for _ in $(seq 1 40); do
    kill -0 "$SERVER_PID" 2>/dev/null || fail "server daemon exited after restart"
    if ip netns exec "$CLIENT_NS" ping -n -c 1 -W 1 10.77.0.1 >/dev/null 2>&1; then
        recovered=1
        break
    fi
    sleep 0.5
done
[[ "$recovered" -eq 1 ]] || fail "peer did not recover encrypted traffic after remote daemon restart"
ip netns exec "$SERVER_NS" ping -n -c 3 -W 2 10.77.0.2 || fail "reverse traffic failed after reconnect"

echo "btrouted peer traffic test passed: protocol=$PROTO, bidirectional ICMP/TCP/UDP, socket-mark routing, reconnect/handshake recovery"
