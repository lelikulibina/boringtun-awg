#!/usr/bin/env python3
"""AWG 3.1 bidirectional interoperability matrix: BoringTun <-> amneziawg-go.

Requires Linux, root, iproute2, ping, Python `cryptography`, boringtun-cli built
with the device feature, and the official amneziawg-go v3 binary. All interfaces and links live
in uniquely named disposable network namespaces; host routes are not changed.

Usage: sudo python3 scripts/awg31-go-interop.py ./target/release/boringtun-cli ./amneziawg-go
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

PORT = 51820
SERVER_LINK, CLIENT_LINK = "10.55.0.1", "10.55.0.2"
SERVER_TUN, CLIENT_TUN = "10.77.0.1", "10.77.0.2"
S_AND_H = """jc=4
jmin=50
jmax=1000
s1=120
s2=130
s3=110
s4=80
h1=169887817
h2=390382747
h3=1033691040
h4=1526332224
"""
HPK = "42" * 32

PROFILES = [
    ("HeaderProtectionKey", f"header_protection_key={HPK}\n"),
    ("ContentPaddingAddition", "content_padding_addition=16-64\n"),
    ("RandomTrailers", "random_trailers=true\n"),
    ("DisableCookies", "disable_cookies=true\n"),
    (
        "randomized timers",
        "rekey_after_time=119-120\nrekey_timeout=5-6\n"
        "reject_after_time=179-180\nkeepalive_timeout=9-10\n"
        "max_handshake_attempts=18-19\n",
    ),
    (
        "all AWG 3.1 extensions combined",
        f"header_protection_key={HPK}\n"
        "content_padding_addition=16-64\nrandom_trailers=true\n"
        "disable_cookies=true\nrekey_after_time=119-120\n"
        "rekey_timeout=5-6\nreject_after_time=179-180\n"
        "keepalive_timeout=9-10\nmax_handshake_attempts=18-19\n",
    ),
]


def run(*args: str, check: bool = True, capture: bool = False) -> str:
    result = subprocess.run(
        args, check=check, text=True,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
    )
    return result.stdout.strip() if capture else ""


def uapi(iface: str, request: str) -> str:
    paths = (f"/var/run/amneziawg/{iface}.sock",
             f"/var/run/wireguard/{iface}.sock")
    path = next((p for p in paths if os.path.exists(p)), None)
    if path is None:
        raise RuntimeError(f"UAPI socket for {iface} did not appear")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(path)
        conn.sendall(request.encode())
        chunks = []
        while True:
            part = conn.recv(4096)
            if not part:
                break
            chunks.append(part)
            if b"\n\n" in b"".join(chunks):
                break
    response = b"".join(chunks).decode()
    if "errno=0" not in response:
        raise RuntimeError(f"UAPI set/get failed for {iface}: {response}")
    return response


def wait_socket(iface: str, process: subprocess.Popen, timeout: float = 12) -> None:
    paths = (f"/var/run/amneziawg/{iface}.sock",
             f"/var/run/wireguard/{iface}.sock")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(os.path.exists(p) for p in paths):
            return
        if process.poll() is not None:
            raise RuntimeError(f"{iface} exited early with status {process.returncode}")
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for UAPI socket: {iface}")


def set_peer(iface: str, private: str, public: str, endpoint: str,
             allowed: str, awg: str) -> None:
    request = (
        "set=1\n"
        f"private_key={private}\n"
        f"listen_port={PORT if endpoint == 'none' else PORT + 1}\n"
        f"{awg}"
        f"public_key={public}\n"
        f"allowed_ip={allowed}\n"
        + (f"endpoint={endpoint}\npersistent_keepalive_interval=5\n"
           if endpoint != "none" else "")
        + "\n"
    )
    response = uapi(iface, request)
    if "errno=0" not in response:
        raise RuntimeError(f"could not configure {iface}: {response}")


def wait_handshake(server_iface: str, client_ns: str, server_ip: str) -> None:
    deadline = time.monotonic() + 22
    while time.monotonic() < deadline:
        run("ip", "netns", "exec", client_ns, "ping", "-c1", "-W1",
            server_ip, check=False)
        status = uapi(server_iface, "get=1\n\n")
        for line in status.splitlines():
            if line.startswith("last_handshake_time_sec="):
                value = line.split("=", 1)[1]
                if value.isdigit() and int(value) > 0:
                    # A successful ping proves encrypted traffic in both
                    # directions, not just a completed Noise handshake.
                    run("ip", "netns", "exec", client_ns, "ping", "-c3",
                        "-W2", server_ip)
                    return
        time.sleep(0.4)
    raise RuntimeError("no handshake/traffic before timeout")


def run_profile(bt: str, go: str, name: str, extra: str) -> None:
    token = uuid.uuid4().hex[:10]
    ns_server, ns_client = f"awg31s{token}", f"awg31c{token}"
    bt_iface, go_iface = f"bt31{token}", f"go31{token}"
    veth_server, veth_client = f"avs{token}", f"avc{token}"
    processes: list[subprocess.Popen] = []
    links_created = False
    workdir = tempfile.TemporaryDirectory(prefix="awg31-interop-")
    logs = Path(workdir.name)

    def ns(ns_name: str, *cmd: str) -> None:
        run("ip", "netns", "exec", ns_name, *cmd)

    try:
        run("ip", "netns", "add", ns_server)
        run("ip", "netns", "add", ns_client)
        run("ip", "link", "add", veth_server, "type", "veth",
            "peer", "name", veth_client)
        links_created = True
        run("ip", "link", "set", veth_server, "netns", ns_server)
        run("ip", "link", "set", veth_client, "netns", ns_client)
        for namespace in (ns_server, ns_client):
            ns(namespace, "ip", "link", "set", "lo", "up")
        ns(ns_server, "ip", "addr", "add", f"{SERVER_LINK}/30",
           "dev", veth_server)
        ns(ns_client, "ip", "addr", "add", f"{CLIENT_LINK}/30",
           "dev", veth_client)
        ns(ns_server, "ip", "link", "set", veth_server, "up")
        ns(ns_client, "ip", "link", "set", veth_client, "up")
        ns(ns_client, "ping", "-c1", "-W3", SERVER_LINK)

        def keypair() -> tuple[str, str]:
            private = os.urandom(32)
            public = X25519PrivateKey.from_private_bytes(private).public_key()
            raw_public = public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            return private.hex(), raw_public.hex()

        server_private, server_public = keypair()
        client_private, client_public = keypair()

        bt_log = open(logs / "boringtun.log", "w", encoding="utf-8")
        go_log = open(logs / "amneziawg-go.log", "w", encoding="utf-8")
        bt_proc = subprocess.Popen(
            ["ip", "netns", "exec", ns_server, bt,
             "--foreground", "--disable-drop-privileges", bt_iface],
            stdout=bt_log, stderr=subprocess.STDOUT,
        )
        processes.append(bt_proc)
        go_proc = subprocess.Popen(
            ["ip", "netns", "exec", ns_client, go, "-f", go_iface],
            stdout=go_log, stderr=subprocess.STDOUT,
        )
        processes.append(go_proc)
        wait_socket(bt_iface, bt_proc)
        wait_socket(go_iface, go_proc)

        awg = S_AND_H + extra
        set_peer(bt_iface, server_private, client_public, "none",
                 f"{CLIENT_TUN}/32", awg)
        set_peer(go_iface, client_private, server_public,
                 f"{SERVER_LINK}:{PORT}", f"{SERVER_TUN}/32", awg)

        ns(ns_server, "ip", "addr", "add", f"{SERVER_TUN}/24", "dev", bt_iface)
        ns(ns_server, "ip", "link", "set", bt_iface, "up", "mtu", "1420")
        ns(ns_client, "ip", "addr", "add", f"{CLIENT_TUN}/32", "dev", go_iface)
        ns(ns_client, "ip", "link", "set", go_iface, "up", "mtu", "1420")
        ns(ns_client, "ip", "route", "add", f"{SERVER_TUN}/32", "dev", go_iface)
        wait_handshake(bt_iface, ns_client, SERVER_TUN)
        print(f"PASS {name}: handshake + bidirectional traffic")
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for iface in (bt_iface, go_iface):
            for directory in ("/var/run/amneziawg", "/var/run/wireguard"):
                path = f"{directory}/{iface}.sock"
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
        run("ip", "netns", "del", ns_client, check=False)
        run("ip", "netns", "del", ns_server, check=False)
        if links_created:
            run("ip", "link", "del", veth_server, check=False)
        workdir.cleanup()


def main() -> int:
    if os.geteuid() != 0:
        print("Run as root (creates disposable network namespaces).", file=sys.stderr)
        return 2
    if len(sys.argv) != 3:
        print(__doc__.split("Usage:", 1)[1].strip(), file=sys.stderr)
        return 2
    bt, go = (str(Path(p).resolve()) for p in sys.argv[1:])
    for binary in (bt, go):
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            print(f"not an executable file: {binary}", file=sys.stderr)
            return 2
    failures = 0
    for name, extra in PROFILES:
        try:
            run_profile(bt, go, name, extra)
        except Exception as error:
            failures += 1
            print(f"FAIL {name}: {error}", file=sys.stderr)
    print(f"SUMMARY: {len(PROFILES) - failures} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
