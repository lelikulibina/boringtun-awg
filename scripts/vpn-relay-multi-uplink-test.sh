#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${VPN_RELAY_BIN:-$ROOT/target/debug/vpn-relay}"
SUFFIX="$$"
CLIENT_NS="btr-mc-$SUFFIX"
SECOND_CLIENT_NS="btr-mc2-$SUFFIX"
ROUTER_NS="btr-mr-$SUFFIX"
PRIMARY_NS="btr-mp-$SUFFIX"
SECONDARY_NS="btr-ms-$SUFFIX"
CLIENT_VETH="mc$SUFFIX"
SECOND_CLIENT_VETH="m2c$SUFFIX"
ROUTER_SECOND_CLIENT_VETH="r2c$SUFFIX"
ROUTER_CLIENT_VETH="rc$SUFFIX"
ROUTER_PRIMARY_VETH="rp$SUFFIX"
PRIMARY_VETH="pu$SUFFIX"
ROUTER_SECONDARY_VETH="rs$SUFFIX"
SECONDARY_VETH="su$SUFFIX"
TMP="$(mktemp -d)"
CLIENT_PID=""
SECOND_CLIENT_PID=""
ROUTER_PID=""
PRIMARY_PID=""
SECONDARY_PID=""
ROUTE_RELOAD_PING_PID=""
PEER_RELOAD_PING_PID=""
IPERF_PIDS=()
NETNS_INODES=()

cleanup() {
    for pid in "${IPERF_PIDS[@]}" "$CLIENT_PID" "$SECOND_CLIENT_PID" "$ROUTER_PID" "$PRIMARY_PID" "$SECONDARY_PID" "$ROUTE_RELOAD_PING_PID" "$PEER_RELOAD_PING_PID"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SECOND_CLIENT_NS" 2>/dev/null || true
    ip netns del "$ROUTER_NS" 2>/dev/null || true
    ip netns del "$PRIMARY_NS" 2>/dev/null || true
    ip netns del "$SECONDARY_NS" 2>/dev/null || true
    for inode in "${NETNS_INODES[@]}"; do
        rm -f "/run/vpn-relay-netns-$inode.marks"
    done
    rm -rf "$TMP"
}
trap cleanup EXIT

dump_namespace() {
    local ns="$1"
    echo "--- namespace $ns ---" >&2
    ip -n "$ns" -details link show >&2 || true
    ip -n "$ns" address show >&2 || true
    ip -n "$ns" -4 rule show >&2 || true
    ip -n "$ns" -4 route show table all >&2 || true
    ip -n "$ns" -6 rule show >&2 || true
    ip -n "$ns" -6 route show table all >&2 || true
    ip netns exec "$ns" nft -a list ruleset >&2 || true
}

fail() {
    echo "vpn-relay multi-uplink test: $*" >&2
    for ns in "$CLIENT_NS" "$SECOND_CLIENT_NS" "$ROUTER_NS" "$PRIMARY_NS" "$SECONDARY_NS"; do
        if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
            dump_namespace "$ns"
        fi
    done
    for log in "$TMP"/*.log; do
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

python3 - "$TMP/keys.env" <<'PY'
import base64, sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
names=("CLIENT","SECOND_CLIENT","ROUTER_INGRESS","ROUTER_PRIMARY","PRIMARY","ROUTER_SECONDARY","SECONDARY")
with open(sys.argv[1],"w",encoding="ascii") as out:
    for name in names:
        key=X25519PrivateKey.generate()
        private=base64.b64encode(key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())).decode()
        public=base64.b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()
        out.write(f"{name}_PRIVATE={private}\n{name}_PUBLIC={public}\n")
PY
source "$TMP/keys.env"

for ns in "$CLIENT_NS" "$SECOND_CLIENT_NS" "$ROUTER_NS" "$PRIMARY_NS" "$SECONDARY_NS"; do
    ip netns add "$ns"
    NETNS_INODES+=("$(ip netns exec "$ns" stat -Lc '%i' /proc/self/ns/net)")
    ip -n "$ns" link set lo up
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
done

ip link add "$CLIENT_VETH" type veth peer name "$ROUTER_CLIENT_VETH"
ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
ip link set "$ROUTER_CLIENT_VETH" netns "$ROUTER_NS"
ip -n "$CLIENT_NS" address add 192.0.2.2/24 dev "$CLIENT_VETH"
ip -n "$ROUTER_NS" address add 192.0.2.1/24 dev "$ROUTER_CLIENT_VETH"
ip -n "$CLIENT_NS" link set "$CLIENT_VETH" up
ip -n "$ROUTER_NS" link set "$ROUTER_CLIENT_VETH" up

ip link add "$SECOND_CLIENT_VETH" type veth peer name "$ROUTER_SECOND_CLIENT_VETH"
ip link set "$SECOND_CLIENT_VETH" netns "$SECOND_CLIENT_NS"
ip link set "$ROUTER_SECOND_CLIENT_VETH" netns "$ROUTER_NS"
ip -n "$SECOND_CLIENT_NS" address add 192.0.3.2/24 dev "$SECOND_CLIENT_VETH"
ip -n "$ROUTER_NS" address add 192.0.3.1/24 dev "$ROUTER_SECOND_CLIENT_VETH"
ip -n "$SECOND_CLIENT_NS" link set "$SECOND_CLIENT_VETH" up
ip -n "$ROUTER_NS" link set "$ROUTER_SECOND_CLIENT_VETH" up

ip link add "$ROUTER_PRIMARY_VETH" type veth peer name "$PRIMARY_VETH"
ip link set "$ROUTER_PRIMARY_VETH" netns "$ROUTER_NS"
ip link set "$PRIMARY_VETH" netns "$PRIMARY_NS"
ip -n "$ROUTER_NS" address add 198.18.1.1/30 dev "$ROUTER_PRIMARY_VETH"
ip -n "$PRIMARY_NS" address add 198.18.1.2/30 dev "$PRIMARY_VETH"
ip -n "$ROUTER_NS" link set "$ROUTER_PRIMARY_VETH" up
ip -n "$PRIMARY_NS" link set "$PRIMARY_VETH" up

ip link add "$ROUTER_SECONDARY_VETH" type veth peer name "$SECONDARY_VETH"
ip link set "$ROUTER_SECONDARY_VETH" netns "$ROUTER_NS"
ip link set "$SECONDARY_VETH" netns "$SECONDARY_NS"
ip -n "$ROUTER_NS" address add 198.18.2.1/30 dev "$ROUTER_SECONDARY_VETH"
ip -n "$SECONDARY_NS" address add 198.18.2.2/30 dev "$SECONDARY_VETH"
ip -n "$ROUTER_NS" link set "$ROUTER_SECONDARY_VETH" up
ip -n "$SECONDARY_NS" link set "$SECONDARY_VETH" up

# The destination addresses exist only behind their intended uplink. A packet
# sent through the wrong tunnel cannot succeed, so successful replies prove
# the complete nftables -> fwmark -> policy route -> peer path.
ip -n "$PRIMARY_NS" address add 203.0.113.1/32 dev lo
ip -n "$SECONDARY_NS" address add 195.142.1.1/32 dev lo
ip -n "$SECONDARY_NS" address add 79.100.22.1/32 dev lo
ip -n "$PRIMARY_NS" address add 198.51.101.1/32 dev lo
ip -n "$PRIMARY_NS" address add 198.51.100.2/32 dev lo
ip -n "$PRIMARY_NS" address add 198.51.100.3/32 dev lo
ip -n "$SECONDARY_NS" address add 198.51.100.2/32 dev lo

cat >"$TMP/client.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_mu_client_$SUFFIX"

[interfaces.wg-client]
type = "wg"
address = ["10.77.0.2/24"]
listen_port = 51876
private_key = "$CLIENT_PRIVATE"
socket_fwmark = 5004

[[interfaces.wg-client.peers]]
public_key = "$ROUTER_INGRESS_PUBLIC"
endpoint = "192.0.2.1:51871"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive_secs = 1
[firewall.input]
[[firewall.input.rules]]
interface = "wg-client"
source = ["0.0.0.0/0"]

[firewall.output]
[[firewall.output.rules]]
interface = "wg-client"
destination = ["0.0.0.0/0"]

TOML

cat >"$TMP/second-client.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_mu_client2_$SUFFIX"

[interfaces.wg-client-2]
type = "wg"
address = ["10.77.0.3/24"]
listen_port = 51877
private_key = "$SECOND_CLIENT_PRIVATE"
socket_fwmark = 5005

[[interfaces.wg-client-2.peers]]
public_key = "$ROUTER_INGRESS_PUBLIC"
endpoint = "192.0.3.1:51871"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive_secs = 1
[firewall.input]
[[firewall.input.rules]]
interface = "wg-client-2"
source = ["0.0.0.0/0"]

[firewall.output]
[[firewall.output.rules]]
interface = "wg-client-2"
destination = ["0.0.0.0/0"]

TOML

cat >"$TMP/router.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_mu_router_$SUFFIX"
manage_ip_forwarding = true

[interfaces.wg-ingress]
type = "wg"
address = ["10.77.0.1/24"]
listen_port = 51871
private_key = "$ROUTER_INGRESS_PRIVATE"
socket_fwmark = 5001

[[interfaces.wg-ingress.peers]]
public_key = "$CLIENT_PUBLIC"
allowed_ips = ["10.77.0.0/24"]

[[interfaces.wg-ingress.peers]]
public_key = "$SECOND_CLIENT_PUBLIC"
allowed_ips = ["10.77.0.3/32"]

[interfaces.awg-primary]
type = "awg"
address = ["10.20.0.1/24"]
listen_port = 51872
private_key = "$ROUTER_PRIMARY_PRIVATE"
socket_fwmark = 5002

[interfaces.awg-primary.awg]
random_trailers = false
disable_cookies = false

[[interfaces.awg-primary.peers]]
public_key = "$PRIMARY_PUBLIC"
endpoint = "198.18.1.2:51873"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive_secs = 1

[interfaces.awg-secondary]
type = "awg"
address = ["10.30.0.1/24"]
listen_port = 51874
private_key = "$ROUTER_SECONDARY_PRIVATE"
socket_fwmark = 5003

[interfaces.awg-secondary.awg]
s3 = 0
s4 = 0
h1 = "1-100"
h2 = "101-200"
h3 = "201-300"
h4 = "301-400"

[[interfaces.awg-secondary.peers]]
public_key = "$SECONDARY_PUBLIC"
endpoint = "198.18.2.2:51875"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive_secs = 1

[firewall.input]
[[firewall.input.rules]]
interface = "wg-ingress"
source = ["10.77.0.2/32", "10.77.0.3/32"]

[firewall.output]
[[firewall.output.rules]]
interface = "wg-ingress"
destination = ["10.77.0.2/32", "10.77.0.3/32"]

[[routing.rules]]
priority = 5
ingress = "wg-ingress"
source = "10.77.0.2/32"
destination = "198.51.100.2/32"
egress = "awg-secondary"

[[routing.rules]]
priority = 10
ingress = "wg-ingress"
source = ["10.77.0.2/32", "10.77.0.3/32"]
destination = ["195.142.0.0/16", "79.100.22.0/24"]
egress = "awg-secondary"

[[routing.rules]]
priority = 20
ingress = "wg-ingress"
source = "10.77.0.2/32"
destination = "198.51.100.0/24"
egress = "awg-primary"
nat = "snat"
nat_to = "10.20.0.99"

# This broader rule overlaps the exact-source SNAT rule above. The exact
# source must retain its higher-priority static SNAT decision; the second
# client must select masquerade for the same destination and egress.
[[routing.rules]]
priority = 21
ingress = "wg-ingress"
source = "10.77.0.0/24"
destination = "198.51.100.0/24"
egress = "awg-primary"
nat = "masquerade"

[[routing.rules]]
priority = 100
ingress = "wg-ingress"
source = "10.77.0.2/32"
destination = "203.0.113.0/24"
egress = "awg-primary"
nat = "masquerade"

TOML

cat >"$TMP/primary.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_mu_primary_$SUFFIX"

[interfaces.up-primary]
type = "awg"
address = ["10.20.0.2/24"]
listen_port = 51873
private_key = "$PRIMARY_PRIVATE"
socket_fwmark = 6001

[interfaces.up-primary.awg]
random_trailers = false
disable_cookies = false

[[interfaces.up-primary.peers]]
public_key = "$ROUTER_PRIMARY_PUBLIC"
allowed_ips = ["10.20.0.1/32", "10.20.0.99/32", "10.77.0.3/32"]
[firewall.input]
[[firewall.input.rules]]
interface = "up-primary"
source = ["10.77.0.0/24", "10.20.0.1/32", "10.20.0.99/32"]

[firewall.output]
[[firewall.output.rules]]
interface = "up-primary"
destination = ["10.77.0.0/24", "10.20.0.1/32", "10.20.0.99/32"]

TOML

cat >"$TMP/secondary.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_mu_secondary_$SUFFIX"

[interfaces.up-secondary]
type = "awg"
address = ["10.30.0.2/24"]
listen_port = 51875
private_key = "$SECONDARY_PRIVATE"
socket_fwmark = 6002

[interfaces.up-secondary.awg]
s3 = 0
s4 = 0
h1 = "1-100"
h2 = "101-200"
h3 = "201-300"
h4 = "301-400"

[[interfaces.up-secondary.peers]]
public_key = "$ROUTER_SECONDARY_PUBLIC"
allowed_ips = ["10.30.0.1/32", "10.77.0.2/32", "10.77.0.3/32"]

[firewall.input]
[[firewall.input.rules]]
interface = "up-secondary"
source = ["10.77.0.0/24", "10.30.0.1/32"]

[firewall.output]
[[firewall.output.rules]]
interface = "up-secondary"
destination = ["10.77.0.0/24", "10.30.0.1/32"]
TOML

for config in client second-client router primary secondary; do
    "$BIN" --config "$TMP/$config.toml" --check >/dev/null || fail "$config configuration validation failed"
done

ip netns exec "$PRIMARY_NS" "$BIN" --config "$TMP/primary.toml" >"$TMP/primary.log" 2>&1 &
PRIMARY_PID=$!
ip netns exec "$SECONDARY_NS" "$BIN" --config "$TMP/secondary.toml" >"$TMP/secondary.log" 2>&1 &
SECONDARY_PID=$!
ip netns exec "$ROUTER_NS" "$BIN" --config "$TMP/router.toml" >"$TMP/router.log" 2>&1 &
ROUTER_PID=$!

wait_interface() {
    local ns="$1" iface="$2" pid="$3" table="$4"
    for _ in $(seq 1 40); do
        kill -0 "$pid" 2>/dev/null || fail "daemon for $iface exited during startup"
        if ip -n "$ns" link show dev "$iface" >/dev/null 2>&1 \
            && ip netns exec "$ns" nft list table inet "$table" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    fail "interface or nftables table for $iface did not become ready"
}
wait_interface "$PRIMARY_NS" up-primary "$PRIMARY_PID" "vpn_relay_mu_primary_$SUFFIX"
wait_interface "$SECONDARY_NS" up-secondary "$SECONDARY_PID" "vpn_relay_mu_secondary_$SUFFIX"
wait_interface "$ROUTER_NS" wg-ingress "$ROUTER_PID" "vpn_relay_mu_router_$SUFFIX"
wait_interface "$ROUTER_NS" awg-primary "$ROUTER_PID" "vpn_relay_mu_router_$SUFFIX"
wait_interface "$ROUTER_NS" awg-secondary "$ROUTER_PID" "vpn_relay_mu_router_$SUFFIX"

# A foreign, earlier FORWARD chain accepts everything. vpn-relay must still
# enforce its later managed-interface isolation verdict.
ip netns exec "$ROUTER_NS" nft -f - <<NFT
table inet foreign_filter_$SUFFIX {
    chain forward {
        type filter hook forward priority -10; policy accept;
        counter accept
    }
}
NFT

# Start ingress clients only after the router has bound its UDP listener and
# registered all peers. Starting them concurrently creates a startup race:
# the first handshake can arrive before wg-ingress is ready and is then lost.
ip netns exec "$CLIENT_NS" "$BIN" --config "$TMP/client.toml" >"$TMP/client.log" 2>&1 &
CLIENT_PID=$!
ip netns exec "$SECOND_CLIENT_NS" "$BIN" --config "$TMP/second-client.toml" >"$TMP/second-client.log" 2>&1 &
SECOND_CLIENT_PID=$!

wait_interface "$CLIENT_NS" wg-client "$CLIENT_PID" "vpn_relay_mu_client_$SUFFIX"
wait_interface "$SECOND_CLIENT_NS" wg-client-2 "$SECOND_CLIENT_PID" "vpn_relay_mu_client2_$SUFFIX"

# Install the return routes only after the daemon has created the remote TUNs.
ip -n "$PRIMARY_NS" route replace 10.77.0.2/32 dev up-primary
ip -n "$PRIMARY_NS" route replace 10.77.0.3/32 dev up-primary
ip -n "$SECONDARY_NS" route replace 10.77.0.2/32 dev up-secondary
ip -n "$SECONDARY_NS" route replace 10.77.0.3/32 dev up-secondary

ip -n "$CLIENT_NS" route replace 203.0.113.1/32 dev wg-client
ip -n "$CLIENT_NS" route replace 195.142.1.1/32 dev wg-client
ip -n "$CLIENT_NS" route replace 79.100.22.1/32 dev wg-client
ip -n "$CLIENT_NS" route replace 198.51.101.1/32 dev wg-client
ip -n "$CLIENT_NS" route replace 198.51.100.2/32 dev wg-client
ip -n "$CLIENT_NS" route replace 198.51.100.3/32 dev wg-client
ip -n "$SECOND_CLIENT_NS" route replace 203.0.113.1/32 dev wg-client-2
ip -n "$SECOND_CLIENT_NS" route replace 195.142.1.1/32 dev wg-client-2
ip -n "$SECOND_CLIENT_NS" route replace 198.51.100.3/32 dev wg-client-2

# Assert the daemon installed the intended classifier and mark mapping.
chain="$(ip netns exec "$ROUTER_NS" nft list chain inet "vpn_relay_mu_router_$SUFFIX" prerouting)"
forward_chain="$(ip netns exec "$ROUTER_NS" nft list chain inet "vpn_relay_mu_router_$SUFFIX" forward)"
nat_chain="$(ip netns exec "$ROUTER_NS" nft list chain inet "vpn_relay_mu_router_$SUFFIX" postrouting)"
output_chain="$(ip netns exec "$ROUTER_NS" nft list chain inet "vpn_relay_mu_router_$SUFFIX" output)"
grep -Fq 'iif @managed_interfaces drop' <<<"$forward_chain" || fail "managed ingress isolation drop is missing"
grep -Fq 'oif @managed_interfaces drop' <<<"$forward_chain" || fail "managed egress isolation drop is missing"
grep -Fq 'iifname "wg-ingress" iif !=' <<<"$chain" || fail "same-name replacement guard is missing"
grep -Eq 'iif "?wg-ingress"? oif "?awg-primary"? ct mark & 0xffff0000 == 0x[0-9a-f]+ meta nfproto ipv4 masquerade' <<<"$nat_chain" || fail "primary IPv4 masquerade rule is missing"

grep -Eq 'iif "?wg-ingress"? ct state new ip saddr { 10.77.0.2/31 } ip daddr { 79.100.22.0/24, 195.142.0.0/16 } meta mark set 0x80000001' <<<"$chain" && grep -Eq 'ct mark set .*0x50020000 return' <<<"$chain" || fail "secondary IPv4 source/destination CIDR arrays are missing"
grep -Eq 'iif "?wg-ingress"? ct state new ip saddr 10.77.0.2 ip daddr 203.0.113.0/24 meta mark set 0x80000000 ct mark set .*0x[0-9a-f]+ return' <<<"$chain" || fail "primary destination-limited classifier is missing"


# INPUT must preserve the original peer source address; source NAT is only
# valid for an authorized FORWARD decision.
ip netns exec "$ROUTER_NS" timeout 5 tcpdump -nn -i wg-ingress -c 1 \
    'icmp and src host 10.77.0.2 and dst host 10.77.0.1 and icmp[0] == 8' \
    >"$TMP/nat-input-local.log" 2>&1 &
capture_pid=$!
sleep 0.25
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 3 -W 2 10.77.0.1 \
    || fail "client could not establish the ingress WG tunnel"
wait "$capture_pid" || fail "could not capture local INPUT packet"
grep -Fq '10.77.0.2 > 10.77.0.1' "$TMP/nat-input-local.log" || fail "INPUT packet source was unexpectedly translated"

# OUTPUT to a peer must also retain the router's TUN address rather than
# inheriting any FORWARD SNAT/masquerade decision.
ip netns exec "$CLIENT_NS" timeout 5 tcpdump -nn -i wg-client -c 1 \
    'icmp and src host 10.77.0.1 and dst host 10.77.0.2 and icmp[0] == 8' \
    >"$TMP/nat-output-local.log" 2>&1 &
capture_pid=$!
sleep 0.25
ip netns exec "$ROUTER_NS" ping -n -I 10.77.0.1 -c 1 -W 2 10.77.0.2 \
    || fail "router local OUTPUT probe to ingress peer failed"
wait "$capture_pid" || fail "could not capture local OUTPUT packet"
grep -Fq '10.77.0.1 > 10.77.0.2' "$TMP/nat-output-local.log" || fail "OUTPUT packet source was unexpectedly translated"


ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 3 -W 2 10.77.0.1 \
    || fail "second client could not establish the ingress WG tunnel"

# Peers on the same WG server are isolated from one another. The kernel has
# a connected route back through the same TUN, but there is no explicit rule.
foreign_forward_before="$(ip netns exec "$ROUTER_NS" nft list chain inet "foreign_filter_$SUFFIX" forward | grep -oE 'counter packets [0-9]+' | awk '{print $3}')"
if ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 2 -W 1 10.77.0.2 >/dev/null 2>&1; then
    fail "two peers on one WG server communicated without a routing rule"
fi

foreign_forward_after="$(ip netns exec "$ROUTER_NS" nft list chain inet "foreign_filter_$SUFFIX" forward | grep -oE 'counter packets [0-9]+' | awk '{print $3}')"
[[ "$foreign_forward_after" -gt "$foreign_forward_before" ]] || fail "foreign FORWARD accept chain did not observe peer-isolation traffic"

# A valid ingress interface is not sufficient: the source selector must match.
if ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 2 -W 1 203.0.113.1 >/dev/null 2>&1; then
    fail "source selector mismatch was routed through an uplink"
fi

# A valid source is not sufficient either: destinations outside every rule
# must not escape through the host's ordinary routing table.

# Capture both managed uplinks while probing a destination with no routing
# decision. The packet must be denied before FORWARD/NAT can emit it.
ip netns exec "$PRIMARY_NS" timeout 4 tcpdump -nn -i up-primary -c 1 \
    'icmp and dst host 198.51.101.1' >"$TMP/nat-denied-forward-primary.log" 2>&1 &
primary_capture=$!
ip netns exec "$SECONDARY_NS" timeout 4 tcpdump -nn -i up-secondary -c 1 \
    'icmp and dst host 198.51.101.1' >"$TMP/nat-denied-forward-secondary.log" 2>&1 &
secondary_capture=$!
sleep 0.25
if ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 2 -W 1 198.51.101.1 >/dev/null 2>&1; then
    fail "unmatched IPv4 destination escaped routing isolation"
fi
set +e
wait "$primary_capture"
primary_denied_status=$?
wait "$secondary_capture"
secondary_denied_status=$?
set -e
[[ "$primary_denied_status" -eq 124 ]] || fail "denied IPv4 FORWARD packet reached primary uplink (tcpdump status $primary_denied_status)"
[[ "$secondary_denied_status" -eq 124 ]] || fail "denied IPv4 FORWARD packet reached secondary uplink (tcpdump status $secondary_denied_status)"

# Overlapping rules must use the lowest numeric priority. Both uplinks host
# this address, so a successful probe alone is insufficient: observe the
# selected remote TUN and require the priority-5 secondary path.
ip netns exec "$SECONDARY_NS" timeout 5 tcpdump -nn -i up-secondary -c 1 \
    'icmp and dst host 198.51.100.2' >"$TMP/priority-secondary.log" 2>&1 &
capture_pid=$!
sleep 0.25
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 1 -W 2 198.51.100.2 \
    || fail "overlapping-priority probe failed"
wait "$capture_pid" || fail "priority-5 secondary rule did not receive overlapping traffic"
grep -Eq '10\.77\.0\.2 > 198\.51\.100\.2' "$TMP/priority-secondary.log" \
    || fail "overlapping rules did not select the first matching non-NAT rule"

# Each address is hosted only by its intended remote uplink server.
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 4 -W 2 203.0.113.1 \
    || fail "default traffic did not traverse awg-primary"
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 4 -W 2 195.142.1.1 \
    || fail "195.142.0.0/16 traffic did not traverse awg-secondary"
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 4 -W 2 79.100.22.1 \
    || fail "79.100.22.0/24 traffic did not traverse awg-secondary"

# Add a destination reachable through both remote uplinks but not covered
# by any other routing selector, so the reload probe cannot pass via fallback.
ip -n "$PRIMARY_NS" address add 198.51.102.2/32 dev lo
ip -n "$SECONDARY_NS" address add 198.51.102.2/32 dev lo
ip -n "$CLIENT_NS" route replace 198.51.102.2/32 dev wg-client

# Change a live routing decision and its NAT action without restarting the
# router. The same destination exists behind both uplinks, so packet capture
# proves the selected egress; the translated source proves the new NAT action.
# Keep an established bidirectional flow on an unchanged decision active while
# the router stages candidate routes and atomically switches nftables policy.
python3 - "$TMP/router.toml" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as stream:
    config = stream.read()
old = '''[[routing.rules]]
priority = 5
ingress = "wg-ingress"
source = "10.77.0.2/32"
destination = "198.51.100.2/32"
egress = "awg-secondary"
'''
new = '''[routing]
mark_base = 0x90000000

[[routing.rules]]
priority = 5
ingress = "wg-ingress"
source = "10.77.0.2/32"
destination = "198.51.102.2/32"
egress = "awg-primary"
nat = "masquerade"
'''
if config.count(old) != 1:
    raise SystemExit("cannot find unique priority-5 routing rule for reload")
config = config.replace(old, new, 1)
with open(path, "w", encoding="utf-8") as stream:
    stream.write(config)
PY
"$BIN" --config "$TMP/router.toml" --check >/dev/null \
    || fail "runtime routing/NAT reload candidate did not validate"
ip netns exec "$PRIMARY_NS" timeout 5 tcpdump -nn -i up-primary -c 1 \
    'icmp and src host 10.20.0.1 and dst host 198.51.102.2' \
    >"$TMP/runtime-reload-primary-capture.log" 2>&1 &
primary_reload_capture=$!
ip netns exec "$SECONDARY_NS" timeout 3 tcpdump -nn -i up-secondary -c 1 \
    'icmp and dst host 198.51.102.2' \
    >"$TMP/runtime-reload-secondary-capture.log" 2>&1 &
secondary_reload_capture=$!
sleep 0.25
ip netns exec "$CLIENT_NS" ping -n -i 0.05 -c 100 -W 2 203.0.113.1 \
    >"$TMP/runtime-reload-continuous-ping.log" 2>&1 &
ROUTE_RELOAD_PING_PID=$!
sleep 0.2
ip netns exec "$ROUTER_NS" "$BIN" --config "$TMP/router.toml" --reload \
    >"$TMP/runtime-routing-nat-reload.log" 2>&1 \
    || fail "runtime routing/NAT reload failed while both uplinks were active"
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -e 5150 -c 1 -W 3 198.51.102.2 \
    || fail "packet did not traverse the new primary masquerade decision after reload"
wait "$primary_reload_capture" \
    || fail "reloaded routing decision did not send translated traffic through primary uplink"
grep -Fq '10.20.0.1 > 198.51.102.2' "$TMP/runtime-reload-primary-capture.log" \
    || fail "runtime reload did not apply the new primary masquerade source address"
set +e
wait "$secondary_reload_capture"
secondary_reload_status=$?
set -e
[[ "$secondary_reload_status" -eq 124 ]] \
    || fail "old secondary routing decision remained active after runtime reload"
if ! wait "$ROUTE_RELOAD_PING_PID"; then
    fail "bidirectional traffic on the unchanged primary route failed during routing/NAT reload"
fi
ROUTE_RELOAD_PING_PID=""
grep -Eq '100 packets transmitted, 100 received, 0% packet loss' "$TMP/runtime-reload-continuous-ping.log" \
    || fail "packet loss detected on the unchanged primary route during routing/NAT reload"

# Remove the second ingress peer while the first peer carries a continuous
# bidirectional flow. This exercises the live peer-set commit independently
# from routing/NAT policy changes: the unaffected peer must lose no packets,
# while the removed peer must stop reaching the router.
python3 - "$TMP/router.toml" "$SECOND_CLIENT_PUBLIC" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as stream:
    config = stream.read()
peer = f'''[[interfaces.wg-ingress.peers]]
public_key = "{sys.argv[2]}"
allowed_ips = ["10.77.0.3/32"]

'''
if config.count(peer) != 1:
    raise SystemExit("cannot find unique second ingress peer for removal probe")
config = config.replace(peer, "", 1)
with open(path, "w", encoding="utf-8") as stream:
    stream.write(config)
PY
"$BIN" --config "$TMP/router.toml" --check >/dev/null \
    || fail "peer-removal reload candidate did not validate"
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -i 0.05 -c 100 -W 2 203.0.113.1 \
    >"$TMP/peer-removal-continuous-ping.log" 2>&1 &
PEER_RELOAD_PING_PID=$!
sleep 0.2
ip netns exec "$ROUTER_NS" "$BIN" --config "$TMP/router.toml" --reload \
    >"$TMP/runtime-peer-removal-reload.log" 2>&1 \
    || fail "runtime reload failed while removing an unrelated ingress peer"

# The removed peer's more-specific 10.77.0.3/32 ownership must fall back to
# the surviving peer's 10.77.0.0/24 prefix. Exercise that handoff while the
# unaffected .2 flow above is still sending packets.
ip -n "$CLIENT_NS" address add 10.77.0.3/32 dev wg-client
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.3 -c 3 -W 2 10.77.0.1 \
    || fail "AllowedIPs ownership did not hand off to the surviving broader-prefix peer"
ip -n "$CLIENT_NS" address del 10.77.0.3/32 dev wg-client

if wait "$PEER_RELOAD_PING_PID"; then
    PEER_RELOAD_PING_PID=""
else
    fail "unaffected peer traffic failed while another ingress peer was removed"
fi
grep -Eq '100 packets transmitted, 100 received, 0% packet loss' "$TMP/peer-removal-continuous-ping.log" \
    || fail "packet loss detected on the unaffected peer during peer removal"
set +e
ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 3 -W 1 10.77.0.1 \
    >"$TMP/removed-peer-connectivity.log" 2>&1
removed_peer_status=$?
set -e
[[ "$removed_peer_status" -ne 0 ]] || fail "removed ingress peer still reached the router"

# Restore the peer so the remaining multi-uplink checks can continue to cover
# its source selectors and overlapping AllowedIPs behavior.
python3 - "$TMP/router.toml" "$SECOND_CLIENT_PUBLIC" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as stream:
    config = stream.read()
anchor = "[interfaces.awg-primary]"
peer = f'''[[interfaces.wg-ingress.peers]]
public_key = "{sys.argv[2]}"
allowed_ips = ["10.77.0.3/32"]

'''
if config.count(anchor) != 1 or sys.argv[2] in config:
    raise SystemExit("cannot safely restore the removed ingress peer")
config = config.replace(anchor, peer + anchor, 1)
with open(path, "w", encoding="utf-8") as stream:
    stream.write(config)
PY
"$BIN" --config "$TMP/router.toml" --check >/dev/null \
    || fail "peer-restoration reload candidate did not validate"
ip netns exec "$ROUTER_NS" "$BIN" --config "$TMP/router.toml" --reload \
    >"$TMP/runtime-peer-restoration-reload.log" 2>&1 \
    || fail "runtime reload failed while restoring the ingress peer"
# Re-adding a removed peer creates a fresh cryptographic peer instance.
# Let the client's 1-second persistent keepalive establish the new session
# before asserting data-plane recovery; do not treat the expected handshake
# interval as a failed restoration.
restored_peer_ready=0
for _ in $(seq 1 10); do
    if ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 1 -W 1 10.77.0.1 \
        >"$TMP/restored-peer-connectivity.log" 2>&1; then
        restored_peer_ready=1
        break
    fi
    sleep 1
done
[[ "$restored_peer_ready" -eq 1 ]] || fail "restored ingress peer did not regain connectivity after fresh handshake"

# Update the same peer's AllowedIPs from .3/32 to .4/32 without changing its
# public key. While the router commits that peer update, keep .2 traffic live,
# verify .4 moves to the updated peer, and verify .3 falls back to the broader
# prefix owned by the first peer.
ip -n "$SECOND_CLIENT_NS" address add 10.77.0.4/32 dev wg-client-2
python3 - "$TMP/router.toml" "$SECOND_CLIENT_PUBLIC" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as stream:
    config = stream.read()
old_peer = f'''[[interfaces.wg-ingress.peers]]
public_key = "{sys.argv[2]}"
allowed_ips = ["10.77.0.3/32"]'''
new_peer = f'''[[interfaces.wg-ingress.peers]]
public_key = "{sys.argv[2]}"
allowed_ips = ["10.77.0.4/32"]'''
if config.count(old_peer) != 1:
    raise SystemExit("cannot find unique second ingress peer for AllowedIPs update")
config = config.replace(old_peer, new_peer, 1)
old_source = 'source = ["10.77.0.2/32", "10.77.0.3/32"]'
new_source = 'source = ["10.77.0.2/32", "10.77.0.3/32", "10.77.0.4/32"]'
old_destination = 'destination = ["10.77.0.2/32", "10.77.0.3/32"]'
new_destination = 'destination = ["10.77.0.2/32", "10.77.0.3/32", "10.77.0.4/32"]'
if config.count(old_source) != 2 or config.count(old_destination) != 1:
    raise SystemExit("unexpected router firewall/routing selectors for AllowedIPs update")
config = config.replace(old_source, new_source)
config = config.replace(old_destination, new_destination)
with open(path, "w", encoding="utf-8") as stream:
    stream.write(config)
PY
"$BIN" --config "$TMP/router.toml" --check >/dev/null \
    || fail "AllowedIPs update reload candidate did not validate"
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -i 0.05 -c 100 -W 2 203.0.113.1 \
    >"$TMP/allowedips-update-continuous-ping.log" 2>&1 &
PEER_RELOAD_PING_PID=$!
sleep 0.2
ip netns exec "$ROUTER_NS" "$BIN" --config "$TMP/router.toml" --reload \
    >"$TMP/runtime-allowedips-update-reload.log" 2>&1 \
    || fail "runtime reload failed while updating peer AllowedIPs"
ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.4 -c 3 -W 2 10.77.0.1 \
    || fail "updated peer did not acquire its new 10.77.0.4/32 AllowedIPs address"
set +e
ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 2 -W 1 10.77.0.1 \
    >"$TMP/allowedips-old-address-rejected.log" 2>&1
old_allowedip_status=$?
set -e
[[ "$old_allowedip_status" -ne 0 ]] || fail "updated peer retained its former 10.77.0.3/32 ownership"
ip -n "$CLIENT_NS" address add 10.77.0.3/32 dev wg-client
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.3 -c 3 -W 2 10.77.0.1 \
    || fail "former .3/32 address did not hand off to the broader-prefix peer"
ip -n "$CLIENT_NS" address del 10.77.0.3/32 dev wg-client
if wait "$PEER_RELOAD_PING_PID"; then
    PEER_RELOAD_PING_PID=""
else
    fail "unaffected peer traffic failed during AllowedIPs update"
fi
grep -Eq '100 packets transmitted, 100 received, 0% packet loss' "$TMP/allowedips-update-continuous-ping.log" \
    || fail "packet loss detected on the unaffected peer during AllowedIPs update"

# Restore the original .3/32 ownership and source selectors for the remaining
# multi-uplink checks, then remove the temporary .4 address from the client.
python3 - "$TMP/router.toml" "$SECOND_CLIENT_PUBLIC" <<'PY'
import sys
path = sys.argv[1]
with open(path, encoding="utf-8") as stream:
    config = stream.read()
old_peer = f'''[[interfaces.wg-ingress.peers]]
public_key = "{sys.argv[2]}"
allowed_ips = ["10.77.0.4/32"]'''
new_peer = f'''[[interfaces.wg-ingress.peers]]
public_key = "{sys.argv[2]}"
allowed_ips = ["10.77.0.3/32"]'''
if config.count(old_peer) != 1:
    raise SystemExit("cannot find unique updated ingress peer for restoration")
config = config.replace(old_peer, new_peer, 1)
old_source = 'source = ["10.77.0.2/32", "10.77.0.3/32", "10.77.0.4/32"]'
new_source = 'source = ["10.77.0.2/32", "10.77.0.3/32"]'
old_destination = 'destination = ["10.77.0.2/32", "10.77.0.3/32", "10.77.0.4/32"]'
new_destination = 'destination = ["10.77.0.2/32", "10.77.0.3/32"]'
if config.count(old_source) != 2 or config.count(old_destination) != 1:
    raise SystemExit("unexpected router firewall/routing selectors during AllowedIPs restoration")
config = config.replace(old_source, new_source)
config = config.replace(old_destination, new_destination)
with open(path, "w", encoding="utf-8") as stream:
    stream.write(config)
PY
"$BIN" --config "$TMP/router.toml" --check >/dev/null \
    || fail "AllowedIPs restoration reload candidate did not validate"
ip netns exec "$ROUTER_NS" "$BIN" --config "$TMP/router.toml" --reload \
    >"$TMP/runtime-allowedips-restoration-reload.log" 2>&1 \
    || fail "runtime reload failed while restoring peer AllowedIPs"
ip -n "$SECOND_CLIENT_NS" address del 10.77.0.4/32 dev wg-client-2
ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 3 -W 2 10.77.0.1 \
    || fail "restored peer AllowedIPs did not restore .3/32 connectivity"

# The second WG peer is included in the secondary source CIDR array but not in
ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 4 -W 2 195.142.1.1 \
    || fail "second IPv4 source-array member was not routed through awg-secondary"

# Static SNAT must use the configured address rather than infer it from
# the egress interface. This destination is hosted only behind awg-primary.
ip netns exec "$PRIMARY_NS" timeout 5 tcpdump -nn -i up-primary -c 1 \
    'icmp and src host 10.20.0.99 and dst host 198.51.100.3' \
    >"$TMP/nat-static-snat-capture.log" 2>&1 &
capture_pid=$!
sleep 0.25
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 1 -W 2 198.51.100.3 \
    || fail "static SNAT IPv4 probe failed"
wait "$capture_pid" || fail "could not capture static SNAT IPv4 packet"
grep -Fq '10.20.0.99 > 198.51.100.3' "$TMP/nat-static-snat-capture.log" \
    || fail "static SNAT did not use configured nat_to address 10.20.0.99"

# A broader overlapping decision on the same egress must not override the
# exact-source decision above. Client .3 selects masquerade; client .2 keeps
# the static SNAT address 10.20.0.99.
ip netns exec "$PRIMARY_NS" timeout 5 tcpdump -nn -i up-primary -c 1 \
    'icmp and src host 10.20.0.1 and dst host 198.51.100.3' \
    >"$TMP/nat-overlap-masquerade-capture.log" 2>&1 &
capture_pid=$!
sleep 0.25
ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 1 -W 2 198.51.100.3 \
    || fail "overlapping routing decision masquerade probe failed"
wait "$capture_pid" || fail "could not capture overlapping routing decision packet"
grep -Fq '10.20.0.1 > 198.51.100.3' "$TMP/nat-overlap-masquerade-capture.log" \
    || fail "broader overlapping rule did not select masquerade"

# Observe inner packets at the remote TUNs. This proves NAT semantics rather
# than merely checking that a masquerade statement exists in nftables.
ip netns exec "$PRIMARY_NS" timeout 5 tcpdump -nn -i up-primary -c 1 \
    'icmp and dst host 203.0.113.1' >"$TMP/nat-masquerade-capture.log" 2>&1 &
capture_pid=$!
sleep 0.25
# This destination has an explicit routing decision for client .2 only.
# Pick a fresh ICMP identifier so conntrack cannot reuse the earlier probe.
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -e 4242 -c 1 -W 2 203.0.113.1 \
    || fail "masqueraded IPv4 probe failed"
wait "$capture_pid" || fail "could not capture masqueraded IPv4 packet"
grep -Eq '10\.20\.0\.1 > 203\.0\.113\.1' "$TMP/nat-masquerade-capture.log" \
    || fail "masquerade did not replace the source with the primary TUN address"

ip netns exec "$SECONDARY_NS" timeout 5 tcpdump -nn -i up-secondary -c 1 \
    'icmp and dst host 195.142.1.1' >"$TMP/nat-none-capture.log" 2>&1 &
capture_pid=$!
sleep 0.25
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 1 -W 2 195.142.1.1 \
    || fail "non-NAT IPv4 probe failed"
wait "$capture_pid" || fail "could not capture non-NAT IPv4 packet"
grep -Eq '10\.77\.0\.2 > 195\.142\.1\.1' "$TMP/nat-none-capture.log" \
    || fail "nat=none changed the original IPv4 source address"

# Masquerade must resolve the egress address for each new flow. Linux
# otherwise removes secondary addresses when the primary address is deleted.
ip netns exec "$ROUTER_NS" sysctl -q -w net.ipv4.conf.awg-primary.promote_secondaries=1
ip -n "$ROUTER_NS" addr add 10.20.0.99/24 dev awg-primary
ip -n "$ROUTER_NS" addr del 10.20.0.1/24 dev awg-primary
ip -n "$ROUTER_NS" -4 addr show dev awg-primary | grep -Fq "inet 10.20.0.99/24" \
    || fail "replacement IPv4 address was removed with the former primary address"
primary_table="$(ip -n "$ROUTER_NS" -4 rule show | awk '
    $4 == "fwmark" && $5 == "0x90000000" {
        for (i = 1; i <= NF; i++) if ($i == "lookup") { print $(i + 1); exit }
    }')"
[[ -n "$primary_table" ]] || fail "primary policy-routing table could not be identified"
ip -n "$ROUTER_NS" -4 route show table "$primary_table" \
    | grep -Eq '^default dev awg-primary( |$)' \
    || fail "primary policy route disappeared during the IPv4 address replacement"
ip netns exec "$PRIMARY_NS" timeout 5 tcpdump -nn -i up-primary -c 1 \
    'icmp and src host 10.20.0.99 and dst host 203.0.113.1' \
    >"$TMP/nat-masquerade-address-change.log" 2>&1 &
capture_pid=$!
sleep 0.25
# Use a distinct ICMP identifier to force a new conntrack mapping after the
# primary egress address changes.
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -e 4243 -c 1 -W 2 203.0.113.1 \
    || fail "masquerade probe failed after changing the egress TUN address"
wait "$capture_pid" || fail "could not capture masquerade packet after egress address change"
grep -Fq '10.20.0.99 > 203.0.113.1' "$TMP/nat-masquerade-address-change.log" \
    || fail "masquerade continued using the old egress address after address change"

# AWG-secondary has no ingress routing rule. Even though the kernel has a
# connected route to the WG client subnet, an AWG server must not initiate a
# new connection through the router to a WG client.
if ip netns exec "$SECONDARY_NS" ping -n -I 10.30.0.2 -c 2 -W 1 10.77.0.2 >/dev/null 2>&1; then
    fail "AWG-secondary initiated traffic reached a WG client without a routing rule"
fi

# Run real iperf3 servers on each isolated uplink. Separate ports keep the
start_iperf_listener() {
    local ns="$1" port="$2" bind="$3" label="$4"
    # Bind the UDP data socket to the same destination address used by the
    # client. Wildcard binding lets iperf3 select the TUN address as its UDP
    # source for a loopback-hosted destination, so the client never accepts
    # the server's UDP stream and the test stalls after the 4-byte probe.
    ip netns exec "$ns" iperf3 -s -B "$bind" -p "$port" --forceflush >"$TMP/$label.log" 2>&1 &
    IPERF_PIDS+=("$!")
}
for spec in "PRIMARY_NS 5201 203.0.113.1 p-tcp" "SECONDARY_NS 5202 195.142.1.1 s16" "SECONDARY_NS 5203 79.100.22.1 s24"; do
    read -r ns port bind label <<<"$spec"
    start_iperf_listener "${!ns}" "$port" "$bind" "$label"
done
sleep 0.5
for pid in "${IPERF_PIDS[@]}"; do
    kill -0 "$pid" 2>/dev/null || fail "iperf3 listener failed to start"
done

run_iperf() {
    local proto="$1" label="$2" target="$3" port="$4"
    local direction args=() logfile uplink_ns uplink_iface router_iface capture_pid
    local -a capture_pids=()
    case "$label" in
        primary*) uplink_ns="$PRIMARY_NS"; uplink_iface="up-primary"; router_iface="awg-primary" ;;
        secondary*) uplink_ns="$SECONDARY_NS"; uplink_iface="up-secondary"; router_iface="awg-secondary" ;;
        *) fail "unknown iperf3 uplink label: $label" ;;
    esac
    for direction in forward reverse; do
        args=(-c "$target" -p "$port" -J)
        if [[ "$proto" == "tcp" ]]; then
            args+=(-n 8M)
        else
            args+=(-u -b 3M -t 3 -l 1200)
            # Keep packet-level evidence at each hop if an UDP stream stalls.
            ip netns exec "$CLIENT_NS" timeout 20 tcpdump -nn -i wg-client \
                "udp and host $target and port $port" >"$TMP/iperf-$label-$direction-client.log" 2>&1 &
            capture_pids+=("$!")
            IPERF_PIDS+=("$!")
            ip netns exec "$ROUTER_NS" timeout 20 tcpdump -nn -i "$router_iface" \
                "udp and host $target and port $port" >"$TMP/iperf-$label-$direction-router.log" 2>&1 &
            capture_pids+=("$!")
            IPERF_PIDS+=("$!")
            ip netns exec "$uplink_ns" timeout 20 tcpdump -nn -i "$uplink_iface" \
                "udp and host $target and port $port" >"$TMP/iperf-$label-$direction-server.log" 2>&1 &
            capture_pids+=("$!")
            IPERF_PIDS+=("$!")
            sleep 0.2
        fi
        [[ "$direction" == "reverse" ]] && args+=(-R)
        # .log is included in fail() diagnostics so iperf3's partial JSON/error
        # output is retained when a client reaches its timeout.
        logfile="$TMP/iperf-$label-$proto-$direction.log"
        timeout 20s ip netns exec "$CLIENT_NS" iperf3 "${args[@]}" >"$logfile" 2>&1 \
            || fail "$label $direction $proto iperf3 stream failed"
        for capture_pid in "${capture_pids[@]}"; do
            kill -TERM "$capture_pid" 2>/dev/null || true
            wait "$capture_pid" 2>/dev/null || true
        done
        capture_pids=()
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
            fail "$label $direction $proto iperf3 receiver statistics invalid"
        fi
    done
}
run_iperf tcp primary-default 203.0.113.1 5201
run_iperf udp primary-default 203.0.113.1 5201
run_iperf tcp secondary-16 195.142.1.1 5202
run_iperf udp secondary-16 195.142.1.1 5202
run_iperf tcp secondary-24 79.100.22.1 5203
run_iperf udp secondary-24 79.100.22.1 5203

# Encrypted outer UDP must use each underlay veth and must never appear on
# either AWG TUN. Keepalives and the traffic above keep the sockets active.
ip netns exec "$ROUTER_NS" timeout 5 tcpdump -nn -i "$ROUTER_PRIMARY_VETH" -c 1 \
    'udp and dst host 198.18.1.2 and dst port 51873' >"$TMP/primary-underlay.log" 2>&1 \
    || fail "primary encrypted UDP was not observed on its underlay"
ip netns exec "$ROUTER_NS" timeout 5 tcpdump -nn -i "$ROUTER_SECONDARY_VETH" -c 1 \
    'udp and dst host 198.18.2.2 and dst port 51875' >"$TMP/secondary-underlay.log" 2>&1 \
    || fail "secondary encrypted UDP was not observed on its underlay"

set +e
ip netns exec "$ROUTER_NS" timeout 3 tcpdump -nn -i awg-primary -c 1 \
    'udp and dst host 198.18.1.2 and dst port 51873' >"$TMP/primary-tun-outer-udp.log" 2>&1
primary_tun_status=$?
ip netns exec "$ROUTER_NS" timeout 3 tcpdump -nn -i awg-secondary -c 1 \
    'udp and dst host 198.18.2.2 and dst port 51875' >"$TMP/secondary-tun-outer-udp.log" 2>&1
secondary_tun_status=$?
set -e
[[ "$primary_tun_status" -eq 124 ]] || fail "primary outer encrypted UDP leaked into awg-primary (tcpdump status $primary_tun_status)"
[[ "$secondary_tun_status" -eq 124 ]] || fail "secondary outer encrypted UDP leaked into awg-secondary (tcpdump status $secondary_tun_status)"

# Restart each remote uplink server independently. The router's persistent
# keepalive must force a fresh handshake and restore traffic without restarting
# the router or client.
kill -TERM "$PRIMARY_PID" || fail "could not stop primary uplink server"
wait "$PRIMARY_PID" || fail "primary uplink server failed during shutdown"
PRIMARY_PID=""
ip netns exec "$PRIMARY_NS" "$BIN" --config "$TMP/primary.toml" >"$TMP/primary-restarted.log" 2>&1 &
PRIMARY_PID=$!
wait_interface "$PRIMARY_NS" up-primary "$PRIMARY_PID" "vpn_relay_mu_primary_$SUFFIX"
ip -n "$PRIMARY_NS" route replace 10.77.0.2/32 dev up-primary
primary_recovered=0
for _ in $(seq 1 40); do
    if ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 1 -W 1 203.0.113.1 >/dev/null 2>&1; then
        primary_recovered=1
        break
    fi
    sleep 0.25
done
[[ "$primary_recovered" -eq 1 ]] || fail "primary uplink did not recover traffic after remote daemon restart"

kill -TERM "$SECONDARY_PID" || fail "could not stop secondary uplink server"
wait "$SECONDARY_PID" || fail "secondary uplink server failed during shutdown"
SECONDARY_PID=""
ip netns exec "$SECONDARY_NS" "$BIN" --config "$TMP/secondary.toml" >"$TMP/secondary-restarted.log" 2>&1 &
SECONDARY_PID=$!
wait_interface "$SECONDARY_NS" up-secondary "$SECONDARY_PID" "vpn_relay_mu_secondary_$SUFFIX"
ip -n "$SECONDARY_NS" route replace 10.77.0.2/32 dev up-secondary
secondary_recovered=0
for _ in $(seq 1 40); do
    if ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 1 -W 1 195.142.1.1 >/dev/null 2>&1 \
        && ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 1 -W 1 79.100.22.1 >/dev/null 2>&1; then
        secondary_recovered=1
        break
    fi
    sleep 0.25
done
[[ "$secondary_recovered" -eq 1 ]] || fail "secondary uplink did not recover both exception routes after remote daemon restart"

# Nested AllowedIPs must resolve to the most-specific peer. The first
# client owns the broad prefixes while the second client owns the more-specific
# .3 addresses. Spoofing .3 from the first peer must be rejected by BoringTun
# before the packet is written to the router TUN.
ip -n "$CLIENT_NS" address add 10.77.0.3/32 dev wg-client

ip netns exec "$ROUTER_NS" timeout 3 tcpdump -nn -i wg-ingress -c 1 \
    'icmp and src host 10.77.0.3 and dst host 10.77.0.1' \
    >"$TMP/overlapping-allowedips-v4.log" 2>&1 &
capture_pid=$!
sleep 0.25
if ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.3 -c 1 -W 1 10.77.0.1; then
    fail "BoringTun accepted IPv4 source spoofing from a peer that owns only an overlapping broader prefix"
fi
set +e
wait "$capture_pid"
overlap_v4_status=$?
set -e
[[ "$overlap_v4_status" -eq 124 ]] || fail "IPv4 source spoofing reached router TUN despite more-specific AllowedIPs ownership (tcpdump status $overlap_v4_status)"

echo "vpn-relay multi-uplink test passed: IPv4 routing/NAT, bidirectional ICMP/TCP/UDP, continuous traffic during routing/NAT reload and peer removal, AllowedIPs update and ownership handoff under load, outer UDP underlay isolation, independent uplink handshake recovery"
