![boringtun logo banner](./banner.png)

# BoringTun

## Warning
Boringtun is currently undergoing a restructuring. You should probably not rely on or link to 
the master branch right now. Instead you should use the crates.io page.

- boringtun: [![crates.io](https://img.shields.io/crates/v/boringtun.svg)](https://crates.io/crates/boringtun)
- boringtun-cli [![crates.io](https://img.shields.io/crates/v/boringtun-cli.svg)](https://crates.io/crates/boringtun-cli)

**BoringTun** is an implementation of the [WireGuard<sup>®</sup>](https://www.wireguard.com/) protocol designed for portability and speed.

**BoringTun** is successfully deployed on millions of [iOS](https://apps.apple.com/us/app/1-1-1-1-faster-internet/id1423538627) and [Android](https://play.google.com/store/apps/details?id=com.cloudflare.onedotonedotonedotone&hl=en_US) consumer devices as well as thousands of Cloudflare Linux servers. 

The project consists of two parts:

* The executable `boringtun-cli`, a [userspace WireGuard](https://www.wireguard.com/xplatform/) 
  implementation for Linux and macOS.
* The library `boringtun` that can be used to implement fast and efficient WireGuard client apps on various platforms, including iOS and Android. It implements the underlying WireGuard protocol, without the network or tunnel stacks, those can be implemented in a platform idiomatic way.

### Installation

You can install this project using `cargo`:

```
cargo install boringtun-cli
```

### Building

- Library only: `cargo build --lib --no-default-features --release [--target $(TARGET_TRIPLE)]`
- Executable: `cargo build --bin boringtun-cli --release [--target $(TARGET_TRIPLE)]`

By default the executable is placed in the `./target/release` folder. You can copy it to a desired location manually, or install it using `cargo install --bin boringtun --path .`.

### Running

As per the specification, to start a tunnel use:

`boringtun-cli [-f/--foreground] INTERFACE-NAME`

The tunnel can then be configured using [wg](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg.8), as a regular WireGuard tunnel, or any other tool.

It is also possible to use with [wg-quick](https://git.zx2c4.com/WireGuard/about/src/tools/man/wg-quick.8) by setting the environment variable `WG_QUICK_USERSPACE_IMPLEMENTATION` to `boringtun`. For example:

`sudo WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun-cli WG_SUDO=1 wg-quick up CONFIGURATION`

### Testing

Testing this project has a few requirements:

- `sudo`: required to create tunnels. When you run `cargo test` you'll be prompted for your password.
- Docker: you can install it [here](https://www.docker.com/get-started). If you are on Ubuntu/Debian you can run `apt-get install docker.io`.

### AmneziaWG extensions

This branch contains AmneziaWG 3.0/3.1 extensions. Linux interop CI tests 16 directional scenarios against official `amneziawg-go` v3.1.20260828, 14 against official `amneziawg-go` v3.0.0, and two vanilla WireGuard scenarios against pinned official `wireguard-go`. The default CI suite therefore covers 32 directional scenarios. Coverage includes vanilla WireGuard/AWG 2.x baselines, 1 MiB integrity transfers with AWG 3.0 and 3.1 features, header protection, CPA, randomized timers, CPS, rekey recovery, and the combined AWG 3.1 profile. The exhaustive 44-scenario v3.1 matrix, including isolated extensions and long rekey lifecycle checks, is available with `--full`; with the additional v3.0 and WireGuard references this runs 60 directional scenarios. The PCAP verifier checks framing and packet structure, not byte-for-byte equality of every datagram; Windows is disabled and macOS is outside the current merge gate. The operational guide is [docs/AMNEZIAWG_3_1_CONFIGURATION.md](docs/AMNEZIAWG_3_1_CONFIGURATION.md); the version history, parameter semantics, limits, interoperability matrix, and upstream edge cases are documented in [docs/AMNEZIAWG_PROTOCOL_COMPATIBILITY.md](docs/AMNEZIAWG_PROTOCOL_COMPATIBILITY.md).


## Linux multi-tunnel router daemon

The workspace includes the experimental `vpn-relay` Linux daemon. It creates WG/AWG TUN devices directly through BoringTun's typed device API; daemon-managed devices do not expose UAPI sockets.

Build and validate the example configuration:

```sh
cargo build -p vpn-relay --bin vpn-relay
sudo install -d -m 0750 /etc/vpn-relay
sudo install -m 0600 vpn-relay/vpn-relay.example.toml /etc/vpn-relay/config.toml
sudo target/debug/vpn-relay --config /etc/vpn-relay/config.toml --check
```

Import an existing WireGuard or AmneziaWG profile directly into the daemon configuration:

```sh
sudo target/debug/vpn-relay --config /etc/vpn-relay/config.toml --import wg0.conf wg-primary
```

If the interface name already exists, the importer asks before replacing it. Use `--yes` for non-interactive replacement. The import changes only the selected interface; other interfaces and routing rules remain intact. A missing `ListenPort` is imported as automatic UDP port selection. Unsupported wg-quick directives (for example `DNS`, `Table`, and hooks) are listed in the import report rather than silently applied.

The daemon configuration uses the singular `address` key, matching the original WireGuard/AmneziaWG `Address` directive. AmneziaWG protocol generation is inferred and validated inside BoringTun from the configured parameters and enabled features; no separate version setting is needed. Interface direction is not configured separately: `routing.rules` defines ingress and egress, and a tunnel may participate in either or both directions. Routing packet marks are allocated only for distinct egress interfaces referenced by those rules.

Replace all example keys and endpoint hostnames before starting the daemon. Then run:

```sh
sudo target/debug/vpn-relay --config /etc/vpn-relay/config.toml
```

To apply a modified configuration without restarting the daemon, first edit the
same TOML file and then run:

```sh
sudo target/debug/vpn-relay --config /etc/vpn-relay/config.toml --reload
```

The reload operation validates the complete candidate configuration and
preflights changed peer endpoints before touching live state. Peer sets are
committed with rollback on failure, and routing/firewall/NAT rules are switched
through one nftables transaction. Peer commits across multiple tunnel devices
are sequential rather than globally simultaneous; if a later step fails, prior
peer sets are restored. A failed rollback causes the daemon to stop.

Runtime reload can change peer sets, routing decisions/selectors/NAT,
INPUT/OUTPUT firewall rules, `routing.mark_base`, and the set of routing egress
interfaces. When routing marks or egress resources change, the daemon allocates
a disjoint mark range and unused route-table/rule-priority slots, installs the
new policy routes before the nftables transaction, then removes old routes only
after nftables switches to the new marks. Old and new mark ranges must not
overlap. A failed nftables transaction leaves the old classifier active and
removes staged routes; cleanup or peer rollback failure puts the daemon into
fatal shutdown. Tunnel identity/lifecycle parameters (interface set/type,
addresses, MTU, IPv6 setting, listen port, private key, socket mark and AWG
parameters), `daemon.nft_table`, `daemon.manage_ip_forwarding` and
`daemon.log_level` still require a restart. The statistics interval may change.

The existing `--replace-peers INTERFACE` command remains available for updating
one interface's peer set from the configuration file without applying other
file changes.

The daemon requires Linux TUN support, `iproute2`, and `nftables`. It installs policy routes and an nftables table named in `[daemon].nft_table`; the table is tagged as daemon-owned and conflicting unowned tables or policy-routing slots are rejected. SIGINT/SIGTERM triggers worker shutdown and cleanup.

A privileged network-namespace smoke/integration test is available at `scripts/vpn-relay-netns-test.sh`. It exercises WG/AWG device creation, IPv4/IPv6 fwmark routing, nftables rule installation, collision rollback, and graceful cleanup. The daemon is experimental; run it in an isolated test environment before production use.

**Forwarding warning:** keep `daemon.manage_ip_forwarding = false` on a shared host unless you explicitly accept global host/router sysctl changes. Enabling it writes the namespace-wide IPv4 and IPv6 forwarding sysctls; Linux applies host/router-mode changes across interfaces (including IPv6 Router Advertisement behaviour). Prefer a dedicated network namespace, or enable forwarding externally and leave this option disabled.

## Supported platforms

Target triple                 |Binary|Library|
------------------------------|:----:|------|
x86_64-unknown-linux-gnu      |  ✓   | ✓    |
aarch64-unknown-linux-gnu     |  ✓   | ✓    |
armv7-unknown-linux-gnueabihf |  ✓   | ✓    |
x86_64-apple-darwin           |  ✓   | ✓    |
x86_64-pc-windows-msvc        |      | ✓    |
aarch64-apple-ios             |      | ✓    |
armv7-apple-ios               |      | ✓    |
armv7s-apple-ios              |      | ✓    |
aarch64-linux-android         |      | ✓    |
arm-linux-androideabi         |      | ✓    |

<sub>Other platforms may be added in the future</sub>

#### Linux

`x86-64`, `aarch64` and `armv7` architectures are supported. The behaviour should be identical to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/), with the following difference:

`boringtun` will drop privileges when started. When privileges are dropped it is not possible to set `fwmark`. If `fwmark` is required, such as when using `wg-quick`, run with `--disable-drop-privileges` or set the environment variable `WG_SUDO=1`.

You will need to give the executable the `CAP_NET_ADMIN` capability using: `sudo setcap cap_net_admin+epi boringtun`. sudo is not needed.

#### macOS

The behaviour is similar to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/). Specifically the interface name must be `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select the lowest available. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

---

#### FFI bindings

The library exposes a set of C ABI bindings, those are defined in the `wireguard_ffi.h` header file. The C bindings can be used with C/C++, Swift (using a bridging header) or C# (using [DLLImport](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportattribute?view=netcore-2.2) with [CallingConvention](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportattribute.callingconvention?view=netcore-2.2) set to `Cdecl`).

#### JNI bindings

The library exposes a set of Java Native Interface bindings, those are defined in `src/jni.rs`.

## License

The project is licensed under the [3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the 3-Clause BSD License, shall be licensed as above, without any additional terms or conditions.

If you want to contribute to this project, please read our [`CONTRIBUTING.md`].

[`CONTRIBUTING.md`]: https://github.com/cloudflare/.github/blob/master/CONTRIBUTING.md

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. BoringTun is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
