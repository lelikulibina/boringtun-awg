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
    ("vanilla WireGuard baseline", "", False),
    ("AWG 2.x baseline", "", True),
    ("HeaderProtectionKey", f"header_protection_key={HPK}\n", True),
    ("ContentPaddingAddition", "content_padding_addition=16-64\n", True),
    ("RandomTrailers", "random_trailers=true\n", True),
    ("DisableCookies", "disable_cookies=true\n", True),
    (
        "randomized timers",
        "rekey_after_time=119-120\nrekey_timeout=5-6\n"
        "reject_after_time=179-180\nkeepalive_timeout=9-10\n"
        "max_handshake_attempts=18-19\n",
        True,
    ),
    (
        "all AWG 3.1 extensions combined",
        f"header_protection_key={HPK}\n"
        "content_padding_addition=16-64\nrandom_trailers=true\n"
        "disable_cookies=true\nrekey_after_time=119-120\n"
        "rekey_timeout=5-6\nreject_after_time=179-180\n"
        "keepalive_timeout=9-10\nmax_handshake_attempts=18-19\n",
        True,
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


def run_profile(
    bt: str, go: str, name: str, extra: str,
    awg_enabled: bool, bt_is_server: bool,
) -> None:
    token = uuid.uuid4().hex[:10]
    ns_server, ns_client = f"awg31s{token}", f"awg31c{token}"
    bt_iface, go_iface = f"bt31{token}", f"go31{token}"
    veth_server, veth_client = f"avs{token}", f"avc{token}"
    processes: list[subprocess.Popen] = []
    log_files = []
    links_created = False
    workdir = tempfile.TemporaryDirectory(prefix="awg31-interop-")
    logs = Path(workdir.name)

    server_iface = bt_iface if bt_is_server else go_iface
    client_iface = go_iface if bt_is_server else bt_iface
    server_name = "boringtun" if bt_is_server else "amneziawg-go"
    client_name = "amneziawg-go" if bt_is_server else "boringtun"
    role = f"{server_name} server"

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

        server_binary = bt if bt_is_server else go
        client_binary = go if bt_is_server else bt
        server_command = (
            [server_binary, "--foreground", "--disable-drop-privileges", server_iface]
            if bt_is_server else [server_binary, "-f", server_iface]
        )
        client_command = (
            [client_binary, "-f", client_iface]
            if bt_is_server else
            [client_binary, "--foreground", "--disable-drop-privileges", client_iface]
        )

        server_log = open(logs / f"{server_name}-server.log", "w", encoding="utf-8")
        client_log = open(logs / f"{client_name}-client.log", "w", encoding="utf-8")
        log_files.extend((server_log, client_log))
        server_proc = subprocess.Popen(
            ["ip", "netns", "exec", ns_server, *server_command],
            stdout=server_log, stderr=subprocess.STDOUT,
        )
        processes.append(server_proc)
        client_proc = subprocess.Popen(
            ["ip", "netns", "exec", ns_client, *client_command],
            stdout=client_log, stderr=subprocess.STDOUT,
        )
        processes.append(client_proc)
        wait_socket(server_iface, server_proc)
        wait_socket(client_iface, client_proc)

        awg = (S_AND_H if awg_enabled else "") + extra
        set_peer(server_iface, server_private, client_public, "none",
                 f"{CLIENT_TUN}/32", awg)
        set_peer(client_iface, client_private, server_public,
                 f"{SERVER_LINK}:{PORT}", f"{SERVER_TUN}/32", awg)

        ns(ns_server, "ip", "addr", "add", f"{SERVER_TUN}/24", "dev", server_iface)
        ns(ns_server, "ip", "link", "set", server_iface, "up", "mtu", "1420")
        ns(ns_client, "ip", "addr", "add", f"{CLIENT_TUN}/32", "dev", client_iface)
        ns(ns_client, "ip", "link", "set", client_iface, "up", "mtu", "1420")
        ns(ns_client, "ip", "route", "add", f"{SERVER_TUN}/32", "dev", client_iface)
        wait_handshake(server_iface, ns_client, SERVER_TUN)
        print(f"PASS {name} ({role}): handshake + bidirectional traffic")
    except Exception:
        for log_path in logs.glob("*.log"):
            tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-12:]
            if tail:
                print(f"--- {name} ({role}): {log_path.name} ---", file=sys.stderr)
                print("\n".join(tail), file=sys.stderr)
        raise
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for log_file in log_files:
            log_file.close()
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
    total = 0
    for name, extra, awg_enabled in PROFILES:
        for bt_is_server in (True, False):
            total += 1
            try:
                run_profile(bt, go, name, extra, awg_enabled, bt_is_server)
            except Exception as error:
                failures += 1
                role = "BoringTun server" if bt_is_server else "amneziawg-go server"
                print(f"FAIL {name} ({role}): {error}", file=sys.stderr)
    print(f"SUMMARY: {total - failures}/{total} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
