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
IPERF_PIDS=()

cleanup() {
    for pid in "${IPERF_PIDS[@]}" "$CLIENT_PID" "$SECOND_CLIENT_PID" "$ROUTER_PID" "$PRIMARY_PID" "$SECONDARY_PID"; do
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
for command in ip nft wg ping iperf3 python3 tcpdump timeout; do
    command -v "$command" >/dev/null || fail "$command is required"
done

CLIENT_PRIVATE="$(wg genkey)"
CLIENT_PUBLIC="$(printf '%s' "$CLIENT_PRIVATE" | wg pubkey)"
SECOND_CLIENT_PRIVATE="$(wg genkey)"
SECOND_CLIENT_PUBLIC="$(printf '%s' "$SECOND_CLIENT_PRIVATE" | wg pubkey)"
ROUTER_INGRESS_PRIVATE="$(wg genkey)"
ROUTER_INGRESS_PUBLIC="$(printf '%s' "$ROUTER_INGRESS_PRIVATE" | wg pubkey)"
ROUTER_PRIMARY_PRIVATE="$(wg genkey)"
ROUTER_PRIMARY_PUBLIC="$(printf '%s' "$ROUTER_PRIMARY_PRIVATE" | wg pubkey)"
PRIMARY_PRIVATE="$(wg genkey)"
PRIMARY_PUBLIC="$(printf '%s' "$PRIMARY_PRIVATE" | wg pubkey)"
ROUTER_SECONDARY_PRIVATE="$(wg genkey)"
ROUTER_SECONDARY_PUBLIC="$(printf '%s' "$ROUTER_SECONDARY_PRIVATE" | wg pubkey)"
SECONDARY_PRIVATE="$(wg genkey)"
SECONDARY_PUBLIC="$(printf '%s' "$SECONDARY_PRIVATE" | wg pubkey)"

for ns in "$CLIENT_NS" "$SECOND_CLIENT_NS" "$ROUTER_NS" "$PRIMARY_NS" "$SECONDARY_NS"; do
    ip netns add "$ns"
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
ip -n "$PRIMARY_NS" -6 address add 2001:db8:1::1/128 dev lo
ip -n "$SECONDARY_NS" address add 195.142.1.1/32 dev lo
ip -n "$SECONDARY_NS" address add 79.100.22.1/32 dev lo
ip -n "$PRIMARY_NS" address add 198.51.101.1/32 dev lo
ip -n "$PRIMARY_NS" address add 198.51.100.2/32 dev lo
ip -n "$SECONDARY_NS" address add 198.51.100.2/32 dev lo
ip -n "$SECONDARY_NS" -6 address add 2001:db8:195:1::1/128 dev lo
ip -n "$PRIMARY_NS" -6 address add 2001:db8:2::1/128 dev lo

cat >"$TMP/client.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_mu_client_$SUFFIX"

[interfaces.wg-client]
type = "wg"
ipv6_enabled = true
address = ["10.77.0.2/24", "fd77::2/64"]
listen_port = 51876
private_key = "$CLIENT_PRIVATE"
socket_fwmark = 5004

[[interfaces.wg-client.peers]]
public_key = "$ROUTER_INGRESS_PUBLIC"
endpoint = "192.0.2.1:51871"
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive_secs = 1
[firewall.input]
[[firewall.input.rules]]
interface = "wg-client"
source = ["10.77.0.1/32", "fd77::1/128"]

[firewall.output]
[[firewall.output.rules]]
interface = "wg-client"
destination = ["10.77.0.1/32", "fd77::1/128"]

TOML

cat >"$TMP/second-client.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_mu_client2_$SUFFIX"

[interfaces.wg-client-2]
type = "wg"
ipv6_enabled = true
address = ["10.77.0.3/24", "fd77::3/64"]
listen_port = 51877
private_key = "$SECOND_CLIENT_PRIVATE"
socket_fwmark = 5005

[[interfaces.wg-client-2.peers]]
public_key = "$ROUTER_INGRESS_PUBLIC"
endpoint = "192.0.3.1:51871"
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive_secs = 1
[firewall.input]
[[firewall.input.rules]]
interface = "wg-client-2"
source = ["10.77.0.1/32", "fd77::1/128"]

[firewall.output]
[[firewall.output.rules]]
interface = "wg-client-2"
destination = ["10.77.0.1/32", "fd77::1/128"]

TOML

cat >"$TMP/router.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_mu_router_$SUFFIX"
manage_ip_forwarding = true

[interfaces.wg-ingress]
type = "wg"
ipv6_enabled = true
address = ["10.77.0.1/24", "fd77::1/64"]
listen_port = 51871
private_key = "$ROUTER_INGRESS_PRIVATE"
socket_fwmark = 5001

[[interfaces.wg-ingress.peers]]
public_key = "$CLIENT_PUBLIC"
allowed_ips = ["10.77.0.2/32", "fd77::2/128"]

[[interfaces.wg-ingress.peers]]
public_key = "$SECOND_CLIENT_PUBLIC"
allowed_ips = ["10.77.0.3/32", "fd77::3/128"]

[interfaces.awg-primary]
type = "awg"
ipv6_enabled = true
address = ["10.20.0.1/24", "fd20::1/64"]
listen_port = 51872
private_key = "$ROUTER_PRIMARY_PRIVATE"
socket_fwmark = 5002

[interfaces.awg-primary.awg]
random_trailers = false
disable_cookies = false

[[interfaces.awg-primary.peers]]
public_key = "$PRIMARY_PUBLIC"
endpoint = "198.18.1.2:51873"
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive_secs = 1

[interfaces.awg-secondary]
type = "awg"
ipv6_enabled = true
address = ["10.30.0.1/24", "fd30::1/64"]
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
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive_secs = 1

[firewall.input]
[[firewall.input.rules]]
interface = "wg-ingress"
source = ["10.77.0.2/32", "10.77.0.3/32", "fd77::2/128", "fd77::3/128"]

[firewall.output]
[[firewall.output.rules]]
interface = "wg-ingress"
destination = ["10.77.0.2/32", "10.77.0.3/32", "fd77::2/128", "fd77::3/128"]

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
nat = "masquerade"

[[routing.rules]]
priority = 100
ingress = "wg-ingress"
source = "10.77.0.2/32"
destination = "203.0.113.0/24"
egress = "awg-primary"
nat = "masquerade"

[[routing.rules]]
priority = 30
ingress = "wg-ingress"
source = ["fd77::2/128", "fd77::3/128"]
destination = "2001:db8:195::/48"
egress = "awg-secondary"

[[routing.rules]]
priority = 200
ingress = "wg-ingress"
source = "fd77::2/128"
destination = "2001:db8:1::/48"
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
ipv6_enabled = true
address = ["10.20.0.2/24", "fd20::2/64"]
listen_port = 51873
private_key = "$PRIMARY_PRIVATE"
socket_fwmark = 6001

[interfaces.up-primary.awg]
random_trailers = false
disable_cookies = false

[[interfaces.up-primary.peers]]
public_key = "$ROUTER_PRIMARY_PUBLIC"
allowed_ips = ["10.20.0.1/32", "fd20::1/128", "fd77::2/128"]
[firewall.input]
[[firewall.input.rules]]
interface = "up-primary"
source = ["10.77.0.0/24", "fd77::/64", "10.20.0.1/32", "fd20::1/128"]

[firewall.output]
[[firewall.output.rules]]
interface = "up-primary"
destination = ["10.77.0.0/24", "fd77::/64", "10.20.0.1/32", "fd20::1/128"]

TOML

cat >"$TMP/secondary.toml" <<TOML
[daemon]
log_level = "debug"
stats_interval_secs = 1
nft_table = "vpn_relay_mu_secondary_$SUFFIX"

[interfaces.up-secondary]
type = "awg"
ipv6_enabled = true
address = ["10.30.0.2/24", "fd30::2/64"]
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
allowed_ips = ["10.77.0.2/32", "10.77.0.3/32", "fd77::2/128", "fd77::3/128"]

[firewall.input]
[[firewall.input.rules]]
interface = "up-secondary"
source = ["10.77.0.0/24", "fd77::/64", "10.30.0.1/32", "fd30::1/128"]

[firewall.output]
[[firewall.output.rules]]
interface = "up-secondary"
destination = ["10.77.0.0/24", "fd77::/64", "10.30.0.1/32", "fd30::1/128"]
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
ip -n "$PRIMARY_NS" -6 route replace fd77::2/128 dev up-primary
ip -n "$SECONDARY_NS" route replace 10.77.0.2/32 dev up-secondary
ip -n "$SECONDARY_NS" route replace 10.77.0.3/32 dev up-secondary
ip -n "$SECONDARY_NS" -6 route replace fd77::2/128 dev up-secondary
ip -n "$SECONDARY_NS" -6 route replace fd77::3/128 dev up-secondary

ip -n "$CLIENT_NS" route replace 203.0.113.1/32 dev wg-client
ip -n "$CLIENT_NS" route replace 195.142.1.1/32 dev wg-client
ip -n "$CLIENT_NS" route replace 79.100.22.1/32 dev wg-client
ip -n "$CLIENT_NS" route replace 198.51.101.1/32 dev wg-client
ip -n "$CLIENT_NS" route replace 198.51.100.2/32 dev wg-client
ip -n "$CLIENT_NS" -6 route replace 2001:db8:1::1/128 dev wg-client
ip -n "$CLIENT_NS" -6 route replace 2001:db8:195:1::1/128 dev wg-client
ip -n "$CLIENT_NS" -6 route replace 2001:db8:2::1/128 dev wg-client
ip -n "$SECOND_CLIENT_NS" route replace 203.0.113.1/32 dev wg-client-2
ip -n "$SECOND_CLIENT_NS" route replace 195.142.1.1/32 dev wg-client-2
ip -n "$SECOND_CLIENT_NS" -6 route replace 2001:db8:1::1/128 dev wg-client-2
ip -n "$SECOND_CLIENT_NS" -6 route replace 2001:db8:195:1::1/128 dev wg-client-2

# Assert the daemon installed the intended classifier and mark mapping.
chain="$(ip netns exec "$ROUTER_NS" nft list chain inet "vpn_relay_mu_router_$SUFFIX" prerouting)"
forward_chain="$(ip netns exec "$ROUTER_NS" nft list chain inet "vpn_relay_mu_router_$SUFFIX" forward)"
nat_chain="$(ip netns exec "$ROUTER_NS" nft list chain inet "vpn_relay_mu_router_$SUFFIX" postrouting)"
grep -Fq 'iifname @managed_interfaces drop' <<<"$forward_chain" || fail "managed ingress isolation drop is missing"
grep -Fq 'oifname @managed_interfaces drop' <<<"$forward_chain" || fail "managed egress isolation drop is missing"
grep -Fq 'iifname "wg-ingress" oifname "awg-primary" ct mark 0x80000000 ip saddr 10.77.0.2 ip daddr 203.0.113.0/24 masquerade' <<<"$nat_chain" || fail "primary IPv4 masquerade rule is missing"
grep -Fq 'iifname "wg-ingress" oifname "awg-primary" ct mark 0x80000000 ip6 saddr fd77::2 ip6 daddr 2001:db8:1::/48 masquerade' <<<"$nat_chain" || fail "primary IPv6 masquerade rule is missing"

grep -Fq 'iifname "wg-ingress" ct state new ip saddr { 10.77.0.2/31 } ip daddr { 79.100.22.0/24, 195.142.0.0/16 } meta mark set 0x80000001 ct mark set meta mark return' <<<"$chain" || fail "secondary IPv4 source/destination CIDR arrays are missing"
grep -Fq 'iifname "wg-ingress" ct state new ip saddr 10.77.0.2 ip daddr 203.0.113.0/24 meta mark set 0x80000000 ct mark set meta mark return' <<<"$chain" || fail "primary destination-limited classifier is missing"
grep -Fq 'iifname "wg-ingress" ct state new ip6 saddr { fd77::2/127 } ip6 daddr 2001:db8:195::/48 meta mark set 0x80000001 ct mark set meta mark return' <<<"$chain" || fail "secondary IPv6 source array classifier is missing"
grep -Fq 'iifname "wg-ingress" ct state new ip6 saddr fd77::2 ip6 daddr 2001:db8:1::/48 meta mark set 0x80000000 ct mark set meta mark return' <<<"$chain" || fail "IPv6 primary destination-limited classifier is missing"

ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 3 -W 2 10.77.0.1 \
    || fail "client could not establish the ingress WG tunnel"

ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 3 -W 2 10.77.0.1 \
    || fail "second client could not establish the ingress WG tunnel"

# Peers on the same WG server are isolated from one another. The kernel has
# a connected route back through the same TUN, but there is no explicit rule.
if ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 2 -W 1 10.77.0.2 >/dev/null 2>&1; then
    fail "two peers on one WG server communicated without a routing rule"
fi

# A valid ingress interface is not sufficient: the source selector must match.
if ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 2 -W 1 203.0.113.1 >/dev/null 2>&1; then
    fail "source selector mismatch was routed through an uplink"
fi
if ip netns exec "$SECOND_CLIENT_NS" ping -6 -n -I fd77::3 -c 2 -W 1 2001:db8:1::1 >/dev/null 2>&1; then
    fail "IPv6 source selector mismatch was routed through an uplink"
fi

# A valid source is not sufficient either: destinations outside every rule
# must not escape through the host's ordinary routing table.
if ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 2 -W 1 198.51.101.1 >/dev/null 2>&1; then
    fail "unmatched IPv4 destination escaped routing isolation"
fi
if ip netns exec "$CLIENT_NS" ping -6 -n -I fd77::2 -c 2 -W 1 2001:db8:2::1 >/dev/null 2>&1; then
    fail "unmatched IPv6 destination escaped routing isolation"
fi

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

# The second WG peer is included in the secondary source CIDR array but not in
# the primary rule. Verify both IPv4 and IPv6 membership at packet level.
ip netns exec "$SECOND_CLIENT_NS" ping -n -I 10.77.0.3 -c 4 -W 2 195.142.1.1 \
    || fail "second IPv4 source-array member was not routed through awg-secondary"
ip netns exec "$SECOND_CLIENT_NS" ping -6 -I fd77::3 -c 4 -W 2 2001:db8:195:1::1 \
    || fail "second IPv6 source-array member was not routed through awg-secondary"
ip netns exec "$CLIENT_NS" ping -6 -n -I fd77::2 -c 4 -W 2 2001:db8:1::1 \
    || fail "IPv6 default traffic did not traverse awg-primary"
ip netns exec "$CLIENT_NS" ping -6 -n -I fd77::2 -c 4 -W 2 2001:db8:195:1::1 \
    || fail "IPv6 exception traffic did not traverse awg-secondary"

# Observe inner packets at the remote TUNs. This proves NAT semantics rather
# than merely checking that a masquerade statement exists in nftables.
ip netns exec "$PRIMARY_NS" timeout 5 tcpdump -nn -i up-primary -c 1 \
    'icmp and dst host 203.0.113.1' >"$TMP/nat-masquerade-capture.log" 2>&1 &
capture_pid=$!
sleep 0.25
ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 1 -W 2 203.0.113.1 \
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

ip netns exec "$SECONDARY_NS" timeout 5 tcpdump -nn -i up-secondary -c 1 \
    'icmp6 and dst host 2001:db8:195:1::1' >"$TMP/nat-none-v6-capture.log" 2>&1 &
capture_pid=$!
sleep 0.25
ip netns exec "$CLIENT_NS" ping -6 -n -I fd77::2 -c 1 -W 2 2001:db8:195:1::1 \
    || fail "non-NAT IPv6 probe failed"
wait "$capture_pid" || fail "could not capture non-NAT IPv6 packet"
grep -Eq 'fd77::2 > 2001:db8:195:1::1' "$TMP/nat-none-v6-capture.log" \
    || fail "nat=none changed the original IPv6 source address"

ip netns exec "$PRIMARY_NS" timeout 5 tcpdump -nn -i up-primary -c 1 \
    'icmp6 and dst host 2001:db8:1::1' >"$TMP/nat-masquerade-v6-capture.log" 2>&1 &
capture_pid=$!
sleep 0.25
ip netns exec "$CLIENT_NS" ping -6 -n -I fd77::2 -c 1 -W 2 2001:db8:1::1 \
    || fail "masqueraded IPv6 probe failed"
wait "$capture_pid" || fail "could not capture masqueraded IPv6 packet"
grep -Eq 'fd20::1 > 2001:db8:1::1' "$TMP/nat-masquerade-v6-capture.log" \
    || fail "IPv6 masquerade did not replace the source with the primary TUN address"

# AWG-secondary has no ingress routing rule. Even though the kernel has a
# connected route to the WG client subnet, an AWG server must not initiate a
# new connection through the router to a WG client.
if ip netns exec "$SECONDARY_NS" ping -n -I 10.30.0.2 -c 2 -W 1 10.77.0.2 >/dev/null 2>&1; then
    fail "AWG-secondary initiated traffic reached a WG client without a routing rule"
fi

# Add TCP listeners behind each uplink and verify forward and reverse streams.
ip netns exec "$PRIMARY_NS" iperf3 -s -B 203.0.113.1 -p 5201 >"$TMP/iperf-primary.log" 2>&1 &
IPERF_PIDS+=("$!")
ip netns exec "$SECONDARY_NS" iperf3 -s -B 195.142.1.1 -p 5202 >"$TMP/iperf-secondary-16.log" 2>&1 &
IPERF_PIDS+=("$!")
ip netns exec "$SECONDARY_NS" iperf3 -s -B 79.100.22.1 -p 5203 >"$TMP/iperf-secondary-24.log" 2>&1 &
IPERF_PIDS+=("$!")
ip netns exec "$PRIMARY_NS" iperf3 -s -6 -B 2001:db8:1::1 -p 5204 >"$TMP/iperf-primary-v6.log" 2>&1 &
IPERF_PIDS+=("$!")
ip netns exec "$SECONDARY_NS" iperf3 -s -6 -B 2001:db8:195:1::1 -p 5205 >"$TMP/iperf-secondary-v6.log" 2>&1 &
IPERF_PIDS+=("$!")
sleep 1

run_tcp() {
    local label="$1" target="$2" port="$3"
    for direction in forward reverse; do
        local output="$TMP/$label-$direction.json"
        local args=(-c "$target" -p "$port" -n 1M --json)
        [[ "$direction" == reverse ]] && args+=(-R)
        ip netns exec "$CLIENT_NS" iperf3 "${args[@]}" >"$output" \
            || fail "$label $direction TCP stream failed"
        python3 - "$output" "$label $direction" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
received = result.get("end", {}).get("sum_received", {}).get("bytes", 0)
if received < 500_000:
    raise SystemExit(f"{sys.argv[2]} received only {received} TCP bytes")
print(f"{sys.argv[2]}: received={received} bytes")
PY
    done
}

run_tcp primary-default 203.0.113.1 5201
run_tcp secondary-16 195.142.1.1 5202
run_tcp secondary-24 79.100.22.1 5203
run_tcp primary-v6 2001:db8:1::1 5204
run_tcp secondary-v6 2001:db8:195:1::1 5205

run_udp() {
    local label="$1" target="$2" port="$3"
    for direction in forward reverse; do
        local output="$TMP/$label-$direction-udp.json"
        local args=(-c "$target" -p "$port" -u -b 1M -t 2 -l 1200 --json)
        [[ "$direction" == reverse ]] && args+=(-R)
        ip netns exec "$CLIENT_NS" iperf3 "${args[@]}" >"$output" \
            || fail "$label $direction UDP stream failed"
        python3 - "$output" "$label $direction" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
received = result.get("end", {}).get("sum_received", {})
byte_count = received.get("bytes", 0)
loss = received.get("lost_percent", 0.0)
if byte_count < 100_000:
    raise SystemExit(f"{sys.argv[2]} received only {byte_count} UDP bytes")
if loss > 5.0:
    raise SystemExit(f"{sys.argv[2]} UDP loss too high: {loss:.2f}%")
print(f"{sys.argv[2]} UDP: received={byte_count} bytes, loss={loss:.2f}%")
PY
    done
}

run_udp primary-default 203.0.113.1 5201
run_udp secondary-16 195.142.1.1 5202
run_udp secondary-24 79.100.22.1 5203
run_udp primary-v6 2001:db8:1::1 5204
run_udp secondary-v6 2001:db8:195:1::1 5205

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
ip -n "$PRIMARY_NS" -6 route replace fd77::2/128 dev up-primary
primary_recovered=0
for _ in $(seq 1 40); do
    if ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 1 -W 1 203.0.113.1 >/dev/null 2>&1 \
        && ip netns exec "$CLIENT_NS" ping -6 -I fd77::2 -c 1 -W 1 2001:db8:1::1 >/dev/null 2>&1; then
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
ip -n "$SECONDARY_NS" -6 route replace fd77::2/128 dev up-secondary
secondary_recovered=0
for _ in $(seq 1 40); do
    if ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 1 -W 1 195.142.1.1 >/dev/null 2>&1 \
        && ip netns exec "$CLIENT_NS" ping -n -I 10.77.0.2 -c 1 -W 1 79.100.22.1 >/dev/null 2>&1 \
        && ip netns exec "$CLIENT_NS" ping -6 -I fd77::2 -c 1 -W 1 2001:db8:195:1::1 >/dev/null 2>&1; then
        secondary_recovered=1
        break
    fi
    sleep 0.25
done
[[ "$secondary_recovered" -eq 1 ]] || fail "secondary uplink did not recover both exception routes after remote daemon restart"

echo "vpn-relay multi-uplink test passed: IPv4/IPv6 static default/exceptions, bidirectional ICMP/TCP/UDP, outer UDP underlay isolation, independent uplink handshake recovery"
