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
TCP_PIDS=()
SERVER_NS_INODE=""
CLIENT_NS_INODE=""

cleanup() {
    for pid in "${TCP_PIDS[@]}" "$CLIENT_IPERF_PID" "$SERVER_IPERF_PID" "$CLIENT_PID" "$SERVER_PID"; do
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
    for log in "$TMP/server.log" "$TMP/client.log" "$TMP/server-iperf.log" "$TMP/client-iperf.log" "$TMP/forged-reply-client.log" "$TMP/forged-reply-tun.log" "$TMP/unmanaged-input-server.log" "$TMP/unmanaged-input-reply-tun.log"; do
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
for command in ip nft wg ping iperf3 python3 tcpdump timeout; do
    command -v "$command" >/dev/null || fail "$command is required"
done

SERVER_PRIVATE="$(wg genkey)"
SERVER_PUBLIC="$(printf '%s' "$SERVER_PRIVATE" | wg pubkey)"
CLIENT_PRIVATE="$(wg genkey)"
CLIENT_PUBLIC="$(printf '%s' "$CLIENT_PRIVATE" | wg pubkey)"

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
ipv6_enabled = true
address = ["10.77.0.1/24", "fd77::1/64"]
listen_port = 51871
private_key = "$SERVER_PRIVATE"
socket_fwmark = 5001

[[interfaces.wg-peer-test.peers]]
public_key = "$CLIENT_PUBLIC"
allowed_ips = ["10.77.0.2/32", "fd77::2/128", "fd77::3/128", "192.0.2.20/32", "192.0.2.21/32"]

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
source = ["fd77::2/128"]
protocol = "icmpv6"

[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["fd77::2/128"]
protocol = "tcp"
ports = [8082]

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
destination = ["fd77::2/128"]
protocol = "icmpv6"

[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["fd77::2/128"]
protocol = "tcp"
ports = [8082]
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
ipv6_enabled = true
address = ["10.77.0.2/24", "fd77::2/64"]
listen_port = 51872
private_key = "$CLIENT_PRIVATE"
socket_fwmark = 5002

[[interfaces.wg-peer-test.peers]]
public_key = "$SERVER_PUBLIC"
endpoint = "192.0.2.1:51871"
allowed_ips = ["10.77.0.1/32", "fd77::1/128", "192.0.2.10/32", "192.0.2.11/32"]
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
source = ["fd77::1/128"]
protocol = "icmpv6"

[[firewall.input.rules]]
interface = "wg-peer-test"
source = ["fd77::1/128"]
protocol = "tcp"
ports = [8082, 8083]

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
destination = ["fd77::1/128"]
protocol = "icmpv6"

[[firewall.output.rules]]
interface = "wg-peer-test"
destination = ["fd77::1/128"]
protocol = "tcp"
ports = [8082, 8083]
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
ip netns exec "$CLIENT_NS" ping -6 -n -c 3 -W 2 fd77::1 || fail "IPv6 client-to-server tunnel traffic failed"
ip netns exec "$SERVER_NS" ping -6 -n -c 3 -W 2 fd77::2 || fail "IPv6 server-to-client tunnel traffic failed"

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

expect_tcp6() {
    local ns="$1" address="$2" port="$3" expected="$4" label="$5"
    local source
    if [[ "$ns" == "$CLIENT_NS" ]]; then source="fd77::2"; else source="fd77::1"; fi
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
expect_tcp6 "$CLIENT_NS" fd77::1 8082 allow "IPv6 client to server allowed INPUT/OUTPUT"
expect_tcp6 "$SERVER_NS" fd77::2 8082 allow "IPv6 server to client allowed INPUT/OUTPUT"
expect_tcp6 "$CLIENT_NS" fd77::1 8083 deny "IPv6 server INPUT default deny"
expect_tcp6 "$SERVER_NS" fd77::2 8083 deny "IPv6 server OUTPUT default deny"

# Add the secondary source only after the baseline traffic checks so it cannot
# influence the kernel source-address selection in earlier probes.
ip -n "$CLIENT_NS" -6 address add fd77::3/128 dev wg-peer-test

# ICMPv6 uses the same explicit allow-list semantics as TCP. A second,
# authenticated client address is deliberately absent from the server INPUT
# source selector: the echo request must reach the TUN but receive no reply.
ip netns exec "$SERVER_NS" timeout 5 tcpdump -nn -i wg-peer-test -c 1 \
    'icmp6 and src host fd77::3 and dst host fd77::1 and icmp6[0] == 128' \
    >"$TMP/icmpv6-input-deny.log" 2>&1 &
capture_pid=$!
TCP_PIDS+=("$capture_pid")
sleep 0.25
if ip netns exec "$CLIENT_NS" ping -6 -n -I fd77::3 -c 1 -W 2 fd77::1; then
    fail "server INPUT accepted ICMPv6 from a source outside its explicit allow rule"
fi
wait "$capture_pid" || fail "ICMPv6 INPUT deny probe did not reach the server TUN"

# The server OUTPUT allow rule names only fd77::2. Sending to the other
# authenticated client address must be denied before a packet reaches its TUN.
ip netns exec "$CLIENT_NS" timeout 3 tcpdump -nn -i wg-peer-test -c 1 \
    'icmp6 and src host fd77::1 and dst host fd77::3 and icmp6[0] == 128' \
    >"$TMP/icmpv6-output-deny.log" 2>&1 &
capture_pid=$!
TCP_PIDS+=("$capture_pid")
sleep 0.25
if ip netns exec "$SERVER_NS" ping -6 -n -I fd77::1 -c 1 -W 1 fd77::3; then
    fail "server OUTPUT accepted ICMPv6 to a destination outside its explicit allow rule"
fi
set +e
wait "$capture_pid"
icmpv6_output_capture_status=$?
set -e
[[ "$icmpv6_output_capture_status" -eq 124 ]] || fail "denied ICMPv6 OUTPUT packet reached the client TUN (tcpdump status $icmpv6_output_capture_status)"


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

echo "vpn-relay peer traffic test passed: tunnel_type=$PROTO, bidirectional ICMP/TCP/UDP, socket-mark routing, reconnect/handshake recovery"
