# UAPI compatibility test with upstream quick scripts

Run on Linux as root with `/dev/net/tun`, `wg`, `wg-quick`, `awg`, and
`awg-quick` installed:

```sh
cargo build --release -p boringtun-cli
sudo bash scripts/uapi-quick-compat.sh "$PWD/target/release/boringtun"
```

The test deliberately invokes the distribution/upstream quick scripts rather
than reimplementing their setup logic. Both scripts launch BoringTun through
`WG_QUICK_USERSPACE_IMPLEMENTATION` and then use their native CLI (`wg` or
`awg`) to exercise the Unix-socket UAPI.

Coverage includes interface creation and teardown, setconf, UAPI get/dump,
private-key and peer readback, endpoint/AllowedIPs/keepalive updates,
and AmneziaWG J/S/H plus DisableCookies configuration readback. No peer needs
to be reachable: this is a control-plane/UAPI compatibility test, not a
wire-protocol handshake test.

The CI workflow builds `awg` and `awg-quick` from the official
`amnezia-vpn/amneziawg-tools` repository at a pinned commit and uses the
Ubuntu `wireguard-tools` package for the original `wg` and `wg-quick`.
