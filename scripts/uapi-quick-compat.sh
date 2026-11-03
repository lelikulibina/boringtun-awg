#!/usr/bin/env bash
# Exercise the real upstream wg-quick/awg-quick scripts against boringtun-cli.
# Run as root on Linux: this creates and removes disposable TUN interfaces.
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run this test as root (sudo)." >&2
  exit 2
fi

BT_BIN="$(realpath "${1:-target/release/boringtun-cli}")"
for tool in wg wg-quick awg awg-quick ip; do
  command -v "$tool" >/dev/null || { echo "ERROR: missing required tool: $tool" >&2; exit 2; }
done
[[ -x "$BT_BIN" ]] || { echo "ERROR: BoringTun binary is not executable: $BT_BIN" >&2; exit 2; }
[[ -c /dev/net/tun ]] || { echo "ERROR: /dev/net/tun is unavailable" >&2; exit 2; }

WORK="$(mktemp -d)"
QUICK_BIN="$WORK/quick-bin"
BT_LAUNCHER="$QUICK_BIN/boringtun-launcher"
WG_IFACE="wgq0"
AWG_IFACE="awgq0"
WG_UP=0
AWG_UP=0

cleanup() {
  local status=$?
  set +e
  if [[ $AWG_UP -eq 1 ]]; then PATH="$QUICK_BIN:$PATH" WG_QUICK_USERSPACE_IMPLEMENTATION="$BT_LAUNCHER" awg-quick down "$WORK/awgq0.conf"; fi
  if [[ $WG_UP -eq 1 ]]; then PATH="$QUICK_BIN:$PATH" WG_QUICK_USERSPACE_IMPLEMENTATION="$BT_LAUNCHER" wg-quick down "$WORK/wgq0.conf"; fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT INT TERM

umask 022
wg genkey > "$WORK/wg-private"
wg genkey > "$WORK/wg-peer-private"
awg genkey > "$WORK/awg-private"
awg genkey > "$WORK/awg-peer-private"
WG_PRIVATE="$(cat "$WORK/wg-private")"
WG_PEER_PUBLIC="$(wg pubkey < "$WORK/wg-peer-private")"
AWG_PRIVATE="$(cat "$WORK/awg-private")"
AWG_PEER_PUBLIC="$(awg pubkey < "$WORK/awg-peer-private")"

# Stage byte-for-byte copies of the installed quick scripts beside an ip shim.
# The shim makes only the kernel link-create probe fail, guaranteeing that the
# original scripts take their documented userspace-implementation fallback
# even on hosts with WireGuard/AmneziaWG kernel modules available.
mkdir -p "$QUICK_BIN"
cp -L "$(command -v wg-quick)" "$QUICK_BIN/wg-quick"
cp -L "$(command -v awg-quick)" "$QUICK_BIN/awg-quick"
IP_REAL="$(command -v ip)"
cat > "$QUICK_BIN/ip" <<EOF
#!/usr/bin/env bash
args=("\$@")
if [[ "\${args[0]}" == link && "\${args[1]}" == add ]]; then
  index=2
  [[ "\${args[index]}" == dev ]] && ((index+=1))
  iface="\${args[index]}"
  ((index+=1))
  [[ "\${args[index]}" == type ]] && ((index+=1))
  kind="\${args[index]}"
  if [[ "\$iface" == "$WG_IFACE" && "\$kind" == wireguard ]]; then
    echo "uapi test: force wg-quick userspace fallback" >&2
    exit 1
  fi
  if [[ "\$iface" == "$AWG_IFACE" && "\$kind" == amneziawg ]]; then
    echo "uapi test: force awg-quick userspace fallback" >&2
    exit 1
  fi
fi
exec "$IP_REAL" "\${args[@]}"
EOF
chmod +x "$QUICK_BIN/ip"
cat > "$BT_LAUNCHER" <<EOF
#!/usr/bin/env bash
iface="\$1"
"$BT_BIN" --disable-drop-privileges "\$iface"
socket="/var/run/wireguard/\${iface}.sock"
for _ in \$(seq 1 50); do
  [[ -S "\$socket" ]] && break
  sleep 0.1
done
if [[ ! -S "\$socket" ]]; then
  echo "BoringTun did not publish its UAPI socket: \$socket" >&2
  ls -ld /var/run/wireguard /var/run/amneziawg 2>&1 || true
  exit 1
fi
# The daemon may chown its runtime directory to the invoking sudo user.
# Keep the temporary CI socket reachable by the root-owned wg/awg clients.
chmod 0777 /var/run/wireguard /var/run/amneziawg
chmod 0666 "\$socket"
echo "UAPI launcher diagnostics for \$iface:" >&2
id >&2
ls -ldn /var/run/wireguard /var/run/amneziawg >&2
ls -ln "\$socket" "/var/run/amneziawg/\${iface}.sock" >&2
ps -eo pid,uid,gid,stat,args | grep '[b]oringtun-cli' >&2 || true
python3 - "\$socket" <<'PY'
import socket, sys
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(2)
client.connect(sys.argv[1])
client.sendall(b"get=1\n\n")
print("UAPI get response:", client.recv(65536).decode("ascii", "replace"), file=sys.stderr)
client.close()
PY
EOF
chmod +x "$BT_LAUNCHER"

cat > "$WORK/wgq0.conf" <<EOF
[Interface]
PrivateKey = $WG_PRIVATE
Address = 10.77.0.1/24
ListenPort = 51871
Table = off

[Peer]
PublicKey = $WG_PEER_PUBLIC
AllowedIPs = 10.77.0.2/32
Endpoint = 127.0.0.1:51872
EOF

cat > "$WORK/awgq0.conf" <<EOF
[Interface]
PrivateKey = $AWG_PRIVATE
Address = 10.78.0.1/24
ListenPort = 51881
Table = off
Jc = 1
Jmin = 8
Jmax = 16
S1 = 64
S2 = 64
S3 = 64
S4 = 64
H1 = 100
H2 = 200
H3 = 300
H4 = 400
DisableCookies = true

[Peer]
PublicKey = $AWG_PEER_PUBLIC
AllowedIPs = 10.78.0.2/32
Endpoint = 127.0.0.1:51882
PersistentKeepalive = 15
EOF
chmod 600 "$WORK/"*.conf "$WORK/"*private

assert_boringtun_running() {
  local iface="$1" proc
  for _ in $(seq 1 30); do
    for proc in /proc/[0-9]*; do
      [[ -e "$proc/exe" ]] || continue
      [[ "$(readlink -f "$proc/exe" 2>/dev/null)" == "$BT_BIN" ]] || continue
      if tr '\0' ' ' < "$proc/cmdline" 2>/dev/null | grep -Fq -- "$iface"; then
        return 0
      fi
    done
    sleep 0.1
  done
  echo "FAIL: $iface was not backed by the requested BoringTun process; quick may have selected the kernel module" >&2
  exit 1
}

assert_contains() {
  local haystack="$1" needle="$2" context="$3"
  if ! grep -Fqi -- "$needle" <<<"$haystack"; then
    echo "FAIL: $context: expected to find '$needle'" >&2
    echo "$haystack" >&2
    exit 1
  fi
}

echo "== wg-quick: start userspace BoringTun =="
WG_UP=1
PATH="$QUICK_BIN:$PATH" WG_QUICK_USERSPACE_IMPLEMENTATION="$BT_LAUNCHER" wg-quick up "$WORK/wgq0.conf"
assert_boringtun_running "$WG_IFACE"
wg_show="$(wg show "$WG_IFACE")"
assert_contains "$wg_show" "listening port: 51871" "wg show via UAPI"
wg_dump="$(wg show "$WG_IFACE" dump)"
assert_contains "$wg_dump" "$WG_PEER_PUBLIC" "wg dump peer readback"

# Exercise UAPI set=1 after initial setconf, then verify get=1 through wg.
wg set "$WG_IFACE" fwmark 0x1234
wg set "$WG_IFACE" peer "$WG_PEER_PUBLIC" endpoint 127.0.0.1:51873 persistent-keepalive 25 allowed-ips 10.77.0.3/32
wg_dump="$(wg show "$WG_IFACE" dump)"
assert_contains "$wg_dump" "127.0.0.1:51873" "wg endpoint update/readback"
assert_contains "$wg_dump" "10.77.0.3/32" "wg AllowedIPs update/readback"
assert_contains "$wg_dump" "25" "wg persistent keepalive readback"
wg_conf="$(wg showconf "$WG_IFACE")"
assert_contains "$wg_conf" "$WG_PRIVATE" "wg showconf private key readback"

echo "== wg-quick: stop =="
WG_QUICK_USERSPACE_IMPLEMENTATION="$BT_LAUNCHER" wg-quick down "$WORK/wgq0.conf"
WG_UP=0
if ip link show "$WG_IFACE" >/dev/null 2>&1; then
  echo "FAIL: wg-quick down left $WG_IFACE present" >&2
  exit 1
fi

echo "== awg-quick: start userspace BoringTun =="
AWG_UP=1
PATH="$QUICK_BIN:$PATH" WG_QUICK_USERSPACE_IMPLEMENTATION="$BT_LAUNCHER" awg-quick up "$WORK/awgq0.conf"
assert_boringtun_running "$AWG_IFACE"
awg_show="$(awg show "$AWG_IFACE")"
assert_contains "$awg_show" "listening port: 51881" "awg show via UAPI"
awg_dump="$(awg show "$AWG_IFACE" dump)"
assert_contains "$awg_dump" "$AWG_PEER_PUBLIC" "awg dump peer readback"

# Update both generic WireGuard and Amnezia-specific state through awg's UAPI client.
awg set "$AWG_IFACE" peer "$AWG_PEER_PUBLIC" endpoint 127.0.0.1:51883 persistent-keepalive 30 allowed-ips 10.78.0.3/32
awg_dump="$(awg show "$AWG_IFACE" dump)"
assert_contains "$awg_dump" "127.0.0.1:51883" "awg endpoint update/readback"
assert_contains "$awg_dump" "10.78.0.3/32" "awg AllowedIPs update/readback"
assert_contains "$awg_dump" "30" "awg persistent keepalive readback"
awg_conf="$(awg showconf "$AWG_IFACE")"
assert_contains "$awg_conf" "$AWG_PRIVATE" "awg showconf private key readback"
assert_contains "$awg_conf" "Jc = 1" "AWG Jc readback"
assert_contains "$awg_conf" "S1 = 64" "AWG S1 readback"
assert_contains "$awg_conf" "H4 = 400" "AWG H4 readback"
assert_contains "$awg_conf" "DisableCookies = true" "AWG 3.1 flag readback"

echo "== awg-quick: stop =="
WG_QUICK_USERSPACE_IMPLEMENTATION="$BT_LAUNCHER" awg-quick down "$WORK/awgq0.conf"
AWG_UP=0
if ip link show "$AWG_IFACE" >/dev/null 2>&1; then
  echo "FAIL: awg-quick down left $AWG_IFACE present" >&2
  exit 1
fi

echo "PASS: upstream wg-quick and awg-quick both configure, query, update and remove BoringTun UAPI devices."
