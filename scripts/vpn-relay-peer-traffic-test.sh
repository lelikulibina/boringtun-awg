#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${VPN_RELAY_BIN:-$ROOT/target/debug/vpn-relay}"
PROTO="${1:-wg}"
case "$PROTO" in
    wg|awg) ;;
    *) echo "usage: $0 [wg|awg]" >&2; exit 2 ;;
esac

SUFFIX="$$"
SERVER_NS="vpn-relay-srv-$SUFFIX"
CLIENT_NS="vpn-relay-cli-$SUFFIX"
SERVER_VETH="bts$SUFFIX"
CLIENT_VETH="btc$SUFFIX"
TMP="$(mktemp -d)"
SERVER_PID=""
CLIENT_PID=""
SERVER_IPERF_PID=""
CLIENT_IPERF_PID=""
CONTINUOUS_PING_PID=""
CONTINUOUS_REVERSE_PING_PID=""
PEER_UPDATE_PING_PID=""
PEER_UPDATE_REVERSE_PING_PID=""
TCP_PIDS=()
SERVER_NS_INODE=""
CLIENT_NS_INODE=""

cleanup() {
    for pid in "${TCP_PIDS[@]}" "$PEER_UPDATE_REVERSE_PING_PID" "$PEER_UPDATE_PING_PID" "$CONTINUOUS_REVERSE_PING_PID" "$CONTINUOUS_PING_PID" "$CLIENT_IPERF_PID" "$SERVER_IPERF_PID" "$CLIENT_PID" "$SERVER_PID"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    if [[ -n "$CLIENT_NS_INODE" ]]; then
        rm -f "/run/vpn-relay-netns-$CLIENT_NS_INODE.marks"
    fi
    if [[ -n "$SERVER_NS_INODE" ]]; then
        rm -f "/run/vpn-relay-netns-$SERVER_NS_INODE.marks"
    fi
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
        ip -n "$ns" -4 route get 10.77.0.1 >&2 || true
    fi
}

fail() {
    echo "vpn-relay peer traffic test ($PROTO): $*" >&2
    dump_namespace_diagnostics "$CLIENT_NS"
    dump_namespace_diagnostics "$SERVER_NS"
    for log in "$TMP/server.log" "$TMP/client.log" "$TMP/server-iperf.log" "$TMP/client-iperf.log" "$TMP/peer-update-continuous-ping.log" "$TMP/peer-update-continuous-reverse-ping.log" "$TMP/reload-peer-add.log" "$TMP/reload-peer-remove.log" "$TMP/reload-dns-failure.log" "$TMP/forged-reply-client.log" "$TMP/forged-reply-tun.log" "$TMP/unmanaged-input-server.log" "$TMP/unmanaged-input-reply-tun.log" "$TMP/" "$TMP/"; do
        if [[ -f "$log" ]]; then
            echo "--- $log ---" >&2
            cat "$log" >&2
        fi
    done
    exit 1
}

[[ $EUID -eq 0 ]] || fail "must run as root"
[[ -x "$BIN" ]] || fail "vpn-relay binary not found at $BIN"
[[ -c /dev/net/tun ]] || fail "/dev/net/tun is unavailable"
for command in ip nft ping python3 tcpdump timeout iperf3; do
    command -v "$command" >/dev/null || fail "$command is required"
done

# Generate WireGuard-compatible X25519 keys with the runner's Python
# cryptography package. This avoids requiring the separate wireguard-tools
# package just to run wg genkey/wg pubkey in this isolated test.
readarray -t SERVER_KEYS < <(python3 - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

private = X25519PrivateKey.generate()
print(base64.b64encode(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode())
print(base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
PY
)
readarray -t CLIENT_KEYS < <(python3 - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

private = X25519PrivateKey.generate()
print(base64.b64encode(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode())
print(base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
PY
)
SERVER_PRIVATE="${SERVER_KEYS[0]}"
SERVER_PUBLIC="${SERVER_KEYS[1]}"
CLIENT_PRIVATE="${CLIENT_KEYS[0]}"
CLIENT_PUBLIC="${CLIENT_KEYS[1]}"

ip netns add "$SERVER_NS"
SERVER_NS_INODE="$(ip netns exec "$SERVER_NS" stat -Lc '%i' /proc/self/ns/net)"
ip netns add "$CLIENT_NS"
CLIENT_NS_INODE="$(ip netns exec "$CLIENT_NS" stat -Lc '%i' /proc/self/ns/net)"
ip link add "$SERVER_VETH" type veth peer name "$CLIENT_VETH"
ip link set "$SERVER_VETH" netns "$SERVER_NS"
ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" link set lo up
ip -n "$SERVER_NS" link set "$SERVER_VETH" up
ip -n "$CLIENT_NS" link set "$CLIENT_VETH" up
ip -n "$SERVER_NS" address add 192.0.2.1/24 dev "$SERVER_VETH"
ip -n "$CLIENT_NS" address add 192.0.2.2/24 dev "$CLIENT_VETH"
# Secondary underlay addresses let the test spoof a reply without changing
# the endpoint route used by the encrypted UDP transport.
ip -n "$SERVER_NS" address add 192.0.2.10/24 dev "$SERVER_VETH"
ip -n "$CLIENT_NS" address add 192.0.2.20/24 dev "$CLIENT_VETH"
ip -n "$SERVER_NS" address add 192.0.2.11/24 dev "$SERVER_VETH"
ip -n "$CLIENT_NS" address add 192.0.2.21/24 dev "$CLIENT_VETH"

cat >"$TMP/server.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_peer_srv_$SUFFIX"

[interfaces.wg-peer-test]
type = "$PROTO"
address = ["10.77.0.1/24"]
listen_port = 51871
private_key = "$SERVER_PRIVATE"
socket_fwmark = 5001

[[interfaces.wg-peer-test.peers]]
public_key = "$CLIENT_PUBLIC"
allowed_ips = ["10.77.0.2/32", "192.0.2.20/32", "192.0.2.21/32"]

# Exercise INPUT and OUTPUT defaults: server allows TCP/8080 and iperf3 TCP/UDP 5201; the client
# also allows TCP/8081 for isolated negative probes so the negative probes isolate the server hooks.
[firewall.input]
[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["10.77.0.2/32"]
protocol = "icmp"

[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["10.77.0.2/32"]
protocol = "tcp"
ports = [8080, 5201]

[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["10.77.0.2/32"]
protocol = "udp"
ports = [5201]

[firewall.output]
[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["10.77.0.2/32"]
protocol = "icmp"

[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["10.77.0.2/32"]
protocol = "tcp"
ports = [8080, 5201]

[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["10.77.0.2/32"]
protocol = "udp"
ports = [5201]
TOML

if [[ "$PROTO" == "awg" ]]; then
    cat >>"$TMP/server.toml" <<'AWG'
[interfaces.wg-peer-test.awg]
random_trailers = false
disable_cookies = false
AWG
fi

cat >"$TMP/client.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_peer_cli_$SUFFIX"

[interfaces.wg-peer-test]
type = "$PROTO"
address = ["10.77.0.2/24"]
listen_port = 51872
private_key = "$CLIENT_PRIVATE"
socket_fwmark = 5002

[[interfaces.wg-peer-test.peers]]
public_key = "$SERVER_PUBLIC"
endpoint = "192.0.2.1:51871"
allowed_ips = ["10.77.0.1/32", "192.0.2.10/32", "192.0.2.11/32"]
persistent_keepalive_secs = 1

[firewall.input]
[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["10.77.0.1/32"]
protocol = "icmp"

[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["10.77.0.1/32"]
protocol = "tcp"
ports = [8080, 8081, 5201]

[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["10.77.0.1/32"]
protocol = "udp"
ports = [5201]

[firewall.output]
[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["10.77.0.1/32"]
protocol = "icmp"

[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["10.77.0.1/32"]
protocol = "tcp"
ports = [8080, 8081, 5201]

[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["10.77.0.1/32"]
protocol = "udp"
ports = [5201]

# Used only by the conntrack reply-isolation regression probe below.
[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["192.0.2.10/32"]
protocol = "udp"
ports = [18080]
TOML

if [[ "$PROTO" == "awg" ]]; then
    cat >>"$TMP/client.toml" <<'AWG'
[interfaces.wg-peer-test.awg]
random_trailers = false
disable_cookies = false
AWG
fi

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
# Force only the spoof-test destination through the tunnel. The primary
# endpoint (192.0.2.1) remains on the physical underlay for socket-fwmark tests.
ip -n "$CLIENT_NS" route replace 192.0.2.10/32 dev wg-peer-test
spoof_route="$(ip -n "$CLIENT_NS" route get 192.0.2.10 2>&1 || true)"
grep -q "dev wg-peer-test" <<<"$spoof_route" || fail "spoof-test destination did not route through TUN: $spoof_route"
ip -n "$SERVER_NS" route replace 192.0.2.21/32 dev wg-peer-test
reply_route="$(ip -n "$SERVER_NS" route get 192.0.2.21 2>&1 || true)"
grep -q "dev wg-peer-test" <<<"$reply_route" || fail "reply-isolation destination did not route through TUN: $reply_route"

# TUN creation happens before policy routing and nftables installation. Wait
# for the daemon's externally observable routing state instead of racing the
# short interval between interface creation and Runtime::start completion.
socket_route=""
inner_route=""
routing_ready=0
for _ in $(seq 1 40); do
    socket_route="$(ip -n "$CLIENT_NS" route get 192.0.2.1 mark 5002 2>&1 || true)"
    inner_route="$(ip -n "$CLIENT_NS" route get 10.77.0.1 2>&1 || true)"
    if grep -q "dev $CLIENT_VETH" <<<"$socket_route" \
        && grep -q "dev wg-peer-test" <<<"$inner_route" \
        && ip netns exec "$CLIENT_NS" nft list table inet "vpn_relay_peer_cli_$SUFFIX" >/dev/null 2>&1 \
        && ip netns exec "$SERVER_NS" nft list table inet "vpn_relay_peer_srv_$SUFFIX" >/dev/null 2>&1; then
        routing_ready=1
        break
    fi
    sleep 0.25
done
[[ "$routing_ready" -eq 1 ]] || fail "daemon routing setup did not become ready (socket: $socket_route; inner: $inner_route)"

# A foreign base chain at an earlier priority must not override vpn-relay's
# later managed-interface verdict. Its accept verdict is deliberately broad.
ip netns exec "$SERVER_NS" nft -f - <<NFT
table inet foreign_filter_$SUFFIX {
    chain input {
        type filter hook input priority -10; policy accept;
        counter accept
    }
    chain output {
        type filter hook output priority -10; policy accept;
        counter accept
    }
}
NFT

# Outer encrypted UDP sockets must use the main underlay route, while
# packets addressed to the remote tunnel peer must use the TUN interface.
# This catches accidental socket-mark overlap and tunnel-loop regressions.
grep -q "dev $CLIENT_VETH" <<<"$socket_route" || fail "outer UDP socket mark escaped the underlay route: $socket_route"
grep -q "dev wg-peer-test" <<<"$inner_route" || fail "remote tunnel address did not route through the TUN: $inner_route"

# A successful ping requires an authenticated handshake and real encrypted
# packet delivery over the veth-backed UDP underlay.
ip netns exec "$CLIENT_NS" ping -n -c 5 -W 2 10.77.0.1 || fail "client-to-server tunnel traffic failed"
ip netns exec "$SERVER_NS" ping -n -c 5 -W 2 10.77.0.2 || fail "server-to-client tunnel traffic failed"

# Start listeners on both peers. Port 8080 is explicitly allowed by
# the server; port 8081 is used to prove server INPUT and OUTPUT deny-by-default.
start_tcp_listener() {
    local ns="$1" port="$2" log="$3"
    ip netns exec "$ns" python3 -u -c '
import socket, sys
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", int(sys.argv[1])))
sock.listen()
while True:
    conn, _ = sock.accept()
    with conn:
        conn.sendall(b"ok")
' "$port" >"$TMP/$log" 2>&1 &
    TCP_PIDS+=("$!")
}
start_tcp_listener "$SERVER_NS" 8080 server-tcp-8080.log
start_tcp_listener "$SERVER_NS" 8081 server-tcp-8081.log
start_tcp_listener "$CLIENT_NS" 8080 client-tcp-8080.log
start_tcp_listener "$CLIENT_NS" 8081 client-tcp-8081.log
start_tcp_listener6() {
    local ns="$1" port="$2" log="$3"
    ip netns exec "$ns" python3 -u -c '
import socket, sys
sock = socket.socket(socket.AF_INET6)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("::", int(sys.argv[1])))
sock.listen()
while True:
    conn, _ = sock.accept()
    with conn:
        conn.sendall(b"ok")
' "$port" >"$TMP/$log" 2>&1 &
    TCP_PIDS+=("$!")
}
start_tcp_listener6 "$SERVER_NS" 8082 server-tcp6-8082.log
start_tcp_listener6 "$SERVER_NS" 8083 server-tcp6-8083.log
start_tcp_listener6 "$CLIENT_NS" 8082 client-tcp6-8082.log
start_tcp_listener6 "$CLIENT_NS" 8083 client-tcp6-8083.log
sleep 0.5

# Local loopback traffic must remain outside managed-TUN INPUT/OUTPUT policy.
ip netns exec "$SERVER_NS" python3 - <<'PY'
import socket
with socket.create_connection(("127.0.0.1", 8081), timeout=2) as conn:
    conn.settimeout(2)
    response = conn.recv(2)
    if response != b"ok":
        raise SystemExit(f"loopback returned unexpected payload: {response!r}")
print("loopback INPUT/OUTPUT bypass: allowed")
PY

expect_tcp() {
    local ns="$1" address="$2" port="$3" expected="$4" label="$5"
    local source
    if [[ "$ns" == "$CLIENT_NS" ]]; then source="10.77.0.2"; else source="10.77.0.1"; fi
    ip netns exec "$ns" python3 - "$address" "$port" "$expected" "$label" "$source" <<'PY'
import socket, sys
address, port, expected, label, source = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
try:
    with socket.create_connection((address, port), timeout=1.5, source_address=(source, 0)) as conn:
        conn.settimeout(1.5)
        payload = conn.recv(2)
        if expected == "deny":
            raise SystemExit(f"{label}: connection unexpectedly succeeded")
        if payload != b"ok":
            raise SystemExit(f"{label}: unexpected response {payload!r}")
except OSError as error:
    if expected == "allow":
        raise SystemExit(f"{label}: expected connection failed: {error}")
    print(f"{label}: blocked as expected")
else:
    print(f"{label}: allowed as expected")
PY
}
expect_tcp "$CLIENT_NS" 10.77.0.1 8080 allow "client to server allowed INPUT/OUTPUT"
expect_tcp "$SERVER_NS" 10.77.0.2 8080 allow "server to client allowed INPUT/OUTPUT"

foreign_counter() {
    ip netns exec "$SERVER_NS" nft list chain inet "foreign_filter_$SUFFIX" "$1" \
        | grep -oE 'counter packets [0-9]+' | awk '{print $3}'
}
foreign_input_before="$(foreign_counter input)"
foreign_output_before="$(foreign_counter output)"
expect_tcp "$CLIENT_NS" 10.77.0.1 8081 deny "server INPUT default deny"
expect_tcp "$SERVER_NS" 10.77.0.2 8081 deny "server OUTPUT default deny"

foreign_input_after="$(foreign_counter input)"
foreign_output_after="$(foreign_counter output)"
[[ "$foreign_input_after" -gt "$foreign_input_before" ]] || fail "foreign INPUT accept chain did not observe the denied packet"
[[ "$foreign_output_after" -gt "$foreign_output_before" ]] || fail "foreign OUTPUT accept chain did not observe the denied packet"

# The physical request is deliberately untracked in the client namespace:
# this keeps the forged reverse packet a NEW local flow on the client, so its
# OUTPUT allow rule can transmit it through the TUN. The server still tracks
# the original underlay flow and sees the TUN packet as its ESTABLISHED reply.
ip netns exec "$CLIENT_NS" nft -f - <<NFT
table inet vpn_relay_test_notrack_$SUFFIX {
    chain prerouting {
        type filter hook prerouting priority raw; policy accept;
        iifname "$CLIENT_VETH" ip saddr 192.0.2.10 ip daddr 192.0.2.20 \
            udp sport 18080 udp dport 18081 notrack
    }
}
NFT
ip netns exec "$SERVER_NS" sysctl -q -w net.ipv4.conf.all.rp_filter=0
ip netns exec "$SERVER_NS" sysctl -q -w net.ipv4.conf.default.rp_filter=0
ip netns exec "$SERVER_NS" sysctl -q -w "net.ipv4.conf.${SERVER_VETH}.rp_filter=0"
ip netns exec "$SERVER_NS" sysctl -q -w net.ipv4.conf.wg-peer-test.rp_filter=0

# A host-originated UDP flow uses the physical underlay and therefore must not
# acquire vpn-relay's managed-flow conntrack tag. A peer then forges its reply
# through the TUN using the exact reverse tuple. The packet must reach the TUN
# (AllowedIPs and routing are valid) but INPUT must drop it because the
# conntrack entry was not authorized by a managed OUTPUT rule.
ip netns exec "$CLIENT_NS" python3 -u - <<'PY' >"$TMP/forged-reply-client.log" 2>&1 &
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("192.0.2.20", 18081))
sock.settimeout(4)
payload, _ = sock.recvfrom(128)
if payload != b"host-flow-probe":
    raise SystemExit(f"unexpected probe payload: {payload!r}")
print("client received host-flow probe")
sock.sendto(b"forged-reply", ("192.0.2.10", 18080))
print("client sent forged reply through managed TUN")
PY
spoof_pid=$!
TCP_PIDS+=("$spoof_pid")
ip netns exec "$CLIENT_NS" timeout 5 tcpdump -nn -i "$CLIENT_VETH" -c 1 \
    'udp and src host 192.0.2.10 and dst host 192.0.2.20 and dst port 18081' \
    >"$TMP/forged-reply-underlay.log" 2>&1 &
underlay_capture_pid=$!
TCP_PIDS+=("$underlay_capture_pid")
sleep 0.25
ip netns exec "$SERVER_NS" timeout 5 tcpdump -nn -i wg-peer-test -c 1 \
    'udp and src host 192.0.2.20 and dst host 192.0.2.10 and dst port 18080' \
    >"$TMP/forged-reply-tun.log" 2>&1 &
capture_pid=$!
TCP_PIDS+=("$capture_pid")
sleep 0.25
ip netns exec "$SERVER_NS" python3 - <<'PY'
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("192.0.2.10", 18080))
sock.settimeout(2)
sock.sendto(b"host-flow-probe", ("192.0.2.20", 18081))
try:
    payload, _ = sock.recvfrom(128)
except socket.timeout:
    print("reply to unmanaged host flow blocked on managed INPUT")
else:
    raise SystemExit(f"untagged reply bypassed managed INPUT deny: {payload!r}")
PY
wait "$underlay_capture_pid" || fail "host-flow probe did not reach client over unmanaged underlay"
wait "$capture_pid" || fail "forged reply did not reach the server TUN; test is inconclusive"
wait "$spoof_pid" || fail "client failed to send the forged conntrack reply"

# Symmetric OUTPUT check: a client request reaches a host service over the
# unmanaged physical interface. The service's reply is routed toward the
# managed TUN, but the original flow never passed managed INPUT and therefore
# has no host-flow tag. OUTPUT must drop the reply before it reaches the TUN.
ip netns exec "$CLIENT_NS" sysctl -q -w net.ipv4.conf.all.rp_filter=0
ip netns exec "$CLIENT_NS" sysctl -q -w net.ipv4.conf.default.rp_filter=0
ip netns exec "$CLIENT_NS" sysctl -q -w "net.ipv4.conf.${CLIENT_VETH}.rp_filter=0"
ip netns exec "$CLIENT_NS" sysctl -q -w net.ipv4.conf.wg-peer-test.rp_filter=0
ip netns exec "$CLIENT_NS" timeout 3 tcpdump -nn -i wg-peer-test -c 1 \
    'udp and src host 192.0.2.11 and dst host 192.0.2.21 and dst port 18081' \
    >"$TMP/unmanaged-input-reply-tun.log" 2>&1 &
capture_pid=$!
TCP_PIDS+=("$capture_pid")
ip netns exec "$SERVER_NS" python3 -u - "$TMP/unmanaged-input-server.received" <<'PY' >"$TMP/unmanaged-input-server.log" 2>&1 &
import socket
import sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("192.0.2.11", 18080))
sock.settimeout(3)
payload, _ = sock.recvfrom(128)
if payload != b"unmanaged-input-probe":
    raise SystemExit(f"unexpected request payload: {payload!r}")
with open(sys.argv[1], "w", encoding="utf-8") as marker:
    marker.write("received\\n")
print("server received unmanaged INPUT probe")
try:
    sock.sendto(b"unmanaged-input-reply", ("192.0.2.21", 18081))
except PermissionError:
    print("managed OUTPUT rejected reply to unmanaged INPUT flow")
else:
    print("host service attempted reply over managed TUN")
PY
server_reply_pid=$!
TCP_PIDS+=("$server_reply_pid")
sleep 0.25
ip netns exec "$CLIENT_NS" python3 - <<'PY'
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("192.0.2.21", 18081))
sock.settimeout(2)
sock.sendto(b"unmanaged-input-probe", ("192.0.2.11", 18080))
try:
    payload, _ = sock.recvfrom(128)
except socket.timeout:
    print("reply to unmanaged INPUT flow blocked on managed OUTPUT")
else:
    raise SystemExit(f"untagged reply bypassed managed OUTPUT deny: {payload!r}")
PY
set +e
wait "$server_reply_pid"
server_reply_status=$?
set -e
[[ -f "$TMP/unmanaged-input-server.received" ]] || fail "server did not receive unmanaged INPUT probe"
if ! grep -Fq "managed OUTPUT rejected reply" "$TMP/unmanaged-input-server.log" \
    && ! grep -Fq "PermissionError: [Errno 1] Operation not permitted" "$TMP/unmanaged-input-server.log"; then
    fail "server did not report an OUTPUT firewall rejection (exit $server_reply_status)"
fi
set +e
wait "$capture_pid"
output_capture_status=$?
set -e
[[ "$output_capture_status" -eq 124 ]] || fail "reply to unmanaged INPUT flow reached the client TUN (tcpdump status $output_capture_status)"

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


# Exercise real TCP and UDP throughput in both directions with iperf3.
# The server firewall explicitly permits the iperf3 control/data port 5201.
ip netns exec "$SERVER_NS" iperf3 -s -p 5201 --forceflush >"$TMP/server-iperf.log" 2>&1 &
SERVER_IPERF_PID=$!
sleep 0.5
kill -0 "$SERVER_IPERF_PID" 2>/dev/null || fail "iperf3 server did not start"

run_iperf_probe() {
    local proto="$1" direction="$2" logfile="$TMP/iperf-$proto-$direction.json"
    local args=(-c 10.77.0.1 -p 5201 -J)
    if [[ "$proto" == "tcp" ]]; then
        args+=(-n 8M)
    else
        args+=(-u -b 3M -t 3 -l 1200)
    fi
    [[ "$direction" == "reverse" ]] && args+=(-R)
    timeout 20s ip netns exec "$CLIENT_NS" iperf3 "${args[@]}" >"$logfile" 2>&1 \
        || fail "iperf3 $proto $direction transfer failed"
    if ! python3 - "$logfile" "$proto" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    report = json.load(stream)
end = report.get("end", {})
candidates = [end.get("sum_received"), end.get("sum")]
candidates += [item.get("receiver") for item in end.get("streams", [])]
stats = next((item for item in candidates if isinstance(item, dict) and "bytes" in item), None)
if stats is None:
    raise SystemExit("iperf3 JSON has no receiver statistics")
received = int(stats.get("bytes", 0))
if sys.argv[2] == "tcp":
    if received < 8 * 1024 * 1024:
        raise SystemExit(f"TCP receiver got only {received} bytes")
else:
    lost = float(stats.get("lost_percent", 100.0))
    if received < 100_000 or lost > 2.0:
        raise SystemExit(f"UDP receiver got {received} bytes with {lost:.2f}% loss")
    print(f"UDP receiver: {received} bytes, {lost:.2f}% loss")
PY
    then
        fail "iperf3 $proto $direction receiver statistics invalid"
    fi
}
for proto in tcp udp; do
    for direction in forward reverse; do
        run_iperf_probe "$proto" "$direction"
    done
done

# Keep authenticated tunnel traffic flowing while the server atomically
# switches its nftables policy repeatedly. Toggle an unrelated INPUT exception
# to force a fresh nftables transaction without changing the probe's permission.
cp "$TMP/server.toml" "$TMP/server-before-traffic-reload.toml"
toggle_reload_rule() {
    python3 - "$TMP/server.toml" "$1" <<'PY'
import sys
path, action = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    config = stream.read()
rule = """[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["10.77.0.3/32"]
protocol = "icmp"

"""
if action == "add":
    anchor = "[firewall.output]\n"
    if config.count(anchor) != 1 or rule in config:
        raise SystemExit("cannot safely add runtime-reload probe rule")
    config = config.replace(anchor, rule + anchor, 1)
elif action == "remove":
    if config.count(rule) != 1:
        raise SystemExit("cannot safely remove runtime-reload probe rule")
    config = config.replace(rule, 1)
else:
    raise SystemExit(f"unknown action: {action}")
with open(path, "w", encoding="utf-8") as stream:
    stream.write(config)
PY
}
ip netns exec "$CLIENT_NS" ping -n -i 0.05 -c 100 -W 2 10.77.0.1 >"$TMP/reload-continuous-ping.log" 2>&1 &
CONTINUOUS_PING_PID=$!
ip netns exec "$SERVER_NS" ping -n -i 0.05 -c 100 -W 2 10.77.0.2 >"$TMP/reload-continuous-reverse-ping.log" 2>&1 &
CONTINUOUS_REVERSE_PING_PID=$!
sleep 0.2
for action in add remove add; do
    toggle_reload_rule "$action"
    ip netns exec "$SERVER_NS" "$BIN" --config "$TMP/server.toml" --reload \
        >>"$TMP/reload-during-traffic.log" 2>&1 \
        || fail "server runtime reload ($action) failed while tunnel packets were flowing"
done
if ! wait "$CONTINUOUS_PING_PID"; then
    fail "client-to-server authenticated traffic failed during repeated runtime reload"
fi
if ! wait "$CONTINUOUS_REVERSE_PING_PID"; then
    fail "server-to-client authenticated traffic failed during repeated runtime reload"
fi
grep -Eq '100 packets transmitted, 100 received, 0% packet loss' "$TMP/reload-continuous-ping.log" \
    || fail "client-to-server packet loss detected during repeated runtime reload"
grep -Eq '100 packets transmitted, 100 received, 0% packet loss' "$TMP/reload-continuous-reverse-ping.log" \
    || fail "server-to-client packet loss detected during repeated runtime reload"
kill -0 "$SERVER_PID" 2>/dev/null || fail "server daemon exited after traffic reload"
ip netns exec "$CLIENT_NS" ping -n -c 3 -W 2 10.77.0.1 \
    || fail "tunnel traffic did not recover after repeated runtime reload"

# Exercise a real peer AllowedIPs transition while authenticated traffic is
# flowing. Add new IPv4 source addresses to the existing client peer,
# apply the server config without restarting either daemon, and prove that
# packets sourced from those addresses are accepted only during the new config.
ip -n "$CLIENT_NS" address add 10.77.0.22/32 dev wg-peer-test
python3 - "$TMP/server.toml" add <<'PY'
import sys
path, action = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    config = stream.read()
old = 'allowed_ips = ["10.77.0.2/32", "192.0.2.20/32", "192.0.2.21/32"]'
new = 'allowed_ips = ["10.77.0.2/32", "10.77.0.22/32", "192.0.2.20/32", "192.0.2.21/32"]'
if action == "add":
    if config.count(old) != 1:
        raise SystemExit("cannot find unique server peer AllowedIPs entry")
    config = config.replace(old, new, 1)
    config += """
[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["10.77.0.22/32"]
protocol = "icmp"

[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["10.77.0.22/32"]
protocol = "icmp"
"""
elif action == "remove":
    if config.count(new) != 1:
        raise SystemExit("cannot find unique updated server peer AllowedIPs entry")
    config = config.replace(new, old, 1)
    for block in (
        '''[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["10.77.0.22/32"]
protocol = "icmp"

''',
        '''[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["10.77.0.22/32"]
protocol = "icmp"
''',
    ):
        if config.count(block) != 1:
            raise SystemExit("cannot find unique temporary peer firewall rule")
        config = config.replace(block, 1)
else:
    raise SystemExit(f"unknown peer update action: {action}")
with open(path, "w", encoding="utf-8") as stream:
    stream.write(config)
PY

# Keep both traffic directions active across the peer-set commit and rollback
# to the original AllowedIPs set. This detects one-way datapath interruption.
# iputils ping may enforce a one-second interval on restricted runners;
# use a finite packet count instead of killing the probe after 20 seconds.
ip netns exec "$CLIENT_NS" ping -n -c 20 -W 2 10.77.0.1 \
    >"$TMP/peer-update-continuous-ping.log" 2>&1 &
PEER_UPDATE_PING_PID=$!
ip netns exec "$SERVER_NS" ping -n -c 20 -W 2 10.77.0.2 \
    >"$TMP/peer-update-continuous-reverse-ping.log" 2>&1 &
PEER_UPDATE_REVERSE_PING_PID=$!
sleep 0.2
ip netns exec "$SERVER_NS" "$BIN" --config "$TMP/server.toml" --reload \
    >"$TMP/reload-peer-add.log" 2>&1 || fail "server peer AllowedIPs addition failed"
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.22 -c 4 -W 2 10.77.0.1 \
    || fail "IPv4 packet from newly allowed peer address did not pass after reload"
    || fail "IPv6 packet from newly allowed peer address did not pass after reload"

python3 - "$TMP/server.toml" remove <<'PY'
import sys
path, action = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    config = stream.read()
old = 'allowed_ips = ["10.77.0.2/32", "192.0.2.20/32", "192.0.2.21/32"]'
new = 'allowed_ips = ["10.77.0.2/32", "10.77.0.22/32", "192.0.2.20/32", "192.0.2.21/32"]'
if config.count(new) != 1:
    raise SystemExit("cannot find updated server peer AllowedIPs entry")
config = config.replace(new, old, 1)
for block in (
    '''[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["10.77.0.22/32"]
protocol = "icmp"

''',
    '''[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["10.77.0.22/32"]
protocol = "icmp"
''',
):
    if config.count(block) != 1:
        raise SystemExit("cannot find unique temporary peer firewall rule")
    config = config.replace(block, 1)
with open(path, "w", encoding="utf-8") as stream:
    stream.write(config)
PY
ip netns exec "$SERVER_NS" "$BIN" --config "$TMP/server.toml" --reload \
    >"$TMP/reload-peer-remove.log" 2>&1 || fail "server peer AllowedIPs removal failed"
if ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.22 -c 2 -W 1 10.77.0.1 \
    >"$TMP/reload-peer-deny-ipv4.log" 2>&1; then
    fail "IPv4 packet from removed peer address passed after reload"
fi
ip netns exec "$CLIENT_NS" ping -n -c 3 -W 2 10.77.0.1 \
    || fail "existing peer traffic stopped after AllowedIPs removal"
if ! wait "$PEER_UPDATE_PING_PID"; then
    fail "client-to-server traffic failed during peer AllowedIPs updates"
fi
if ! wait "$PEER_UPDATE_REVERSE_PING_PID"; then
    fail "server-to-client traffic failed during peer AllowedIPs updates"
fi
grep -Eq '20 packets transmitted, 20 received, 0% packet loss' "$TMP/peer-update-continuous-ping.log" \
    || fail "client-to-server packet loss detected during peer AllowedIPs updates"
grep -Eq '20 packets transmitted, 20 received, 0% packet loss' "$TMP/peer-update-continuous-reverse-ping.log" \
    || fail "server-to-client packet loss detected during peer AllowedIPs updates"
kill -0 "$SERVER_PID" 2>/dev/null || fail "server daemon exited after peer AllowedIPs reload"

# A newly added peer with an unresolvable endpoint must fail during preflight,
# before the live peer set is touched. The established peer must keep passing
# traffic in both directions after the rejected reload.
cp "$TMP/server.toml" "$TMP/server-before-dns-failure.toml"
BAD_PEER_PUBLIC="$(python3 - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
key = X25519PrivateKey.generate()
print(base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
PY
)"
cat >>"$TMP/server.toml" <<TOML

[[interfaces.wg-peer-test.peers]]
public_key = "$BAD_PEER_PUBLIC"
endpoint = "vpn-relay-dns-failure.invalid:51871"
allowed_ips = ["10.77.0.33/32"]
TOML
if ip netns exec "$SERVER_NS" "$BIN" --config "$TMP/server.toml" --reload \
    >"$TMP/reload-dns-failure.log" 2>&1; then
    fail "runtime reload unexpectedly accepted an unresolvable peer endpoint"
fi
cp "$TMP/server-before-dns-failure.toml" "$TMP/server.toml"
ip netns exec "$CLIENT_NS" ping -n -c 3 -W 2 10.77.0.1 \
    || fail "existing client-to-server session was disrupted by DNS preflight failure"
ip netns exec "$SERVER_NS" ping -n -c 3 -W 2 10.77.0.2 \
    || fail "existing server-to-client session was disrupted by DNS preflight failure"
kill -0 "$SERVER_PID" 2>/dev/null || fail "server daemon exited after DNS preflight failure"

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
        line = re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", line)
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

echo "vpn-relay peer traffic test passed: tunnel_type=$PROTO, bidirectional ICMP/TCP/UDP, socket-mark routing, reconnect/handshake recovery"
