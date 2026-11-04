#!/usr/bin/env python3
"""AWG 3.1 bidirectional interoperability matrix: BoringTun <-> amneziawg-go.

Requires Linux, root, iproute2, ping, Python `cryptography`, boringtun-cli built
with the device feature, and the official amneziawg-go v3 binary. All interfaces and links live
in uniquely named disposable network namespaces; host routes are not changed.

Usage: sudo python3 scripts/awg31-go-interop.py ./target/release/boringtun-cli ./amneziawg-go [--full] [--performance] [--awg30 ./amneziawg-go-3.0] [--wireguard ./wireguard-go]
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

PORT = 51820
SERVER_LINK, CLIENT_LINK = "10.55.0.1", "10.55.0.2"
SERVER_TUN, CLIENT_TUN = "10.77.0.1", "10.77.0.2"
S1, S2, S3, S4 = 284, 659, 1045, 12
RT_S_PREFIX = 64
S_AND_H = f"""jc=4
jmin=50
jmax=1000
s1={S1}
s2={S2}
s3={S3}
s4={S4}
h1=169887817
h2=390382747
h3=1033691040
h4=1526332224
"""
HPK = "42" * 32
# RandomTrailers needs identical S offsets to avoid the upstream first-match
# classifier mistaking transport packets for fixed-size handshake messages.
S_AND_H_RT = (
    f"jc=4\njmin=50\njmax=1000\n"
    f"s1={RT_S_PREFIX}\ns2={RT_S_PREFIX}\n"
    f"s3={RT_S_PREFIX}\ns4={RT_S_PREFIX}\n"
    + "h1=" + S_AND_H.split("h1=", 1)[1]
)

PROFILES = [
    ("vanilla WireGuard baseline", "", False),
    ("AWG 2.x baseline", "", True),
    # Version-focused 1 MiB integrity transfers. AWG 3.0 adds header
    # protection, content padding and randomized protocol timers; AWG 3.1
    # adds RandomTrailers and DisableCookies on top of those 3.0 features.
    # CPS I1-I5 are tested independently below because they are not a 3.0-only
    # feature and must not be used as a substitute for the 3.0 transport tests.
    ("bulk data integrity — WireGuard", "", False),
    ("bulk data integrity — AWG 2.0", "", True),
    (
        "bulk data integrity — AWG 3.0",
        f"header_protection_key={HPK}\n"
        "content_padding_addition=16-64\n"
        "rekey_after_time=119-120\nrekey_timeout=5-6\n"
        "reject_after_time=179-180\nkeepalive_timeout=9-10\n"
        "max_handshake_attempts=18-19\n",
        True,
    ),
    (
        "bulk data integrity — AWG 3.1",
        f"header_protection_key={HPK}\n"
        "content_padding_addition=16-64\n"
        "disable_cookies=true\n"
        "rekey_after_time=119-120\nrekey_timeout=5-6\n"
        "reject_after_time=179-180\nkeepalive_timeout=9-10\n"
        "max_handshake_attempts=18-19\n"
        "random_trailers=true\n",
        True,
    ),
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
        "accelerated rekey",
        "rekey_after_time=2-2\nrekey_timeout=2-2\n"
        "reject_after_time=30-30\nkeepalive_timeout=2-2\n"
        "max_handshake_attempts=3-3\n",
        True,
    ),
    (
        "rekey packet-loss recovery",
        "rekey_after_time=2-2\nrekey_timeout=2-2\n"
        "reject_after_time=30-30\nkeepalive_timeout=2-2\n"
        "max_handshake_attempts=3-3\n",
        True,
    ),
    (
        "bulk data integrity",
        "",
        True,
    ),
    (
        "long peer lifecycle soak",
        "rekey_after_time=2-2\nrekey_timeout=2-2\n"
        "reject_after_time=30-30\nkeepalive_timeout=2-2\n"
        "max_handshake_attempts=3-3\n",
        True,
    ),
    (
        "all AWG 3.1 extensions combined",
        f"header_protection_key={HPK}\n"
        "content_padding_addition=16-64\n"
        "disable_cookies=true\nrekey_after_time=119-120\n"
        "rekey_timeout=5-6\nreject_after_time=179-180\n"
        "keepalive_timeout=9-10\nmax_handshake_attempts=18-19\n"
        "random_trailers=true\n",
        True,
    ),
    # CPS I1-I5: recognizable fixed datagrams let the pcap verifier prove
    # that each configured signature is actually emitted before the WG
    # initiation, not merely accepted by UAPI.
    ("CPS I1", "i1=<b 0x41574733312d49312d435053>\n", True),
    ("CPS I2", "i2=<b 0x41574733312d49322d435053>\n", True),
    ("CPS I3", "i3=<b 0x41574733312d49332d435053>\n", True),
    ("CPS I4", "i4=<b 0x41574733312d49342d435053>\n", True),
    ("CPS I5", "i5=<b 0x41574733312d49352d435053>\n", True),
    (
        "CPS I1-I5 combined",
        "i1=<b 0x41574733312d49312d435053>\n"
        "i2=<b 0x41574733312d49322d435053>\n"
        "i3=<b 0x41574733312d49332d435053>\n"
        "i4=<b 0x41574733312d49342d435053>\n"
        "i5=<b 0x41574733312d49352d435053>\n",
        True,
    ),
]


# Fast CI/development suite: cover both protocol baselines, 3.0 and 3.1
# bulk-transfer integrity, the combined 3.1 feature path, packet-loss rekey
# recovery, and all CPS slots. The exhaustive per-extension matrix and long
# lifecycle soak remain available with --full.
QUICK_PROFILES = [
    profile for profile in PROFILES
    if profile[0] in {
        "vanilla WireGuard baseline",
        "AWG 2.x baseline",
        "bulk data integrity — AWG 3.0",
        "bulk data integrity — AWG 3.1",
        "accelerated rekey",
        "rekey packet-loss recovery",
        "all AWG 3.1 extensions combined",
        "CPS I1-I5 combined",
    }
]

# AWG 3.0 compatibility must be tested against the actual v3.0.0 reference,
# not merely by switching BoringTun's sender-local CPA algorithm while both
# endpoints still run the v3.1 Go implementation. Exclude 3.1-only UAPI keys.
AWG30_PROFILES = [
    profile for profile in PROFILES
    if profile[0] in {
        "vanilla WireGuard baseline",
        "AWG 2.x baseline",
        "bulk data integrity — AWG 3.0",
        "HeaderProtectionKey",
        "ContentPaddingAddition",
        "randomized timers",
        "CPS I1-I5 combined",
    }
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


def last_handshake_time(iface: str) -> int:
    status = uapi(iface, "get=1\n\n")
    for line in status.splitlines():
        if line.startswith("last_handshake_time_sec="):
            value = line.split("=", 1)[1]
            return int(value) if value.isdigit() else 0
    return 0


def wait_handshake(server_iface: str, client_ns: str, server_ip: str) -> int:
    deadline = time.monotonic() + 22
    while time.monotonic() < deadline:
        run("ip", "netns", "exec", client_ns, "ping", "-c1", "-W1",
            server_ip, check=False)
        handshake_time = last_handshake_time(server_iface)
        if handshake_time > 0:
            return handshake_time
        time.sleep(0.4)
    raise RuntimeError("no handshake/traffic before timeout")


def wait_rekey(
    server_iface: str, client_ns: str, server_ip: str, initial_handshake_time: int,
) -> None:
    """Wait for the original initiator to complete an accelerated send-side rekey."""
    deadline = time.monotonic() + 14
    while time.monotonic() < deadline:
        run("ip", "netns", "exec", client_ns, "ping", "-c1", "-W1",
            server_ip, check=False)
        current_handshake_time = last_handshake_time(server_iface)
        if current_handshake_time > initial_handshake_time:
            run("ip", "netns", "exec", client_ns, "ping", "-c3",
                "-W2", server_ip)
            return
        time.sleep(0.2)
    raise RuntimeError(
        "no completed send-side rekey observed before timeout "
        f"(initial={initial_handshake_time}, current={last_handshake_time(server_iface)})"
    )



def drop_client_egress_during_rekey(
    client_ns: str, client_link: str, server_ip: str,
) -> int:
    """Drop only the expected AWG H1 rekey datagram and verify its filter counter."""
    # This profile uses the shared S1 value, H1=169887817
    # (wire bytes 49:48:20:0a), no HeaderProtection and no RandomTrailers.
    # From the IPv4-header start, H1 is at 20 (IPv4) + 8 (UDP) + S1.
    run("ip", "netns", "exec", client_ns, "tc", "qdisc", "add", "dev",
        client_link, "root", "handle", "1:", "prio")
    try:
        run(
            "ip", "netns", "exec", client_ns, "tc", "filter", "add", "dev",
            client_link, "protocol", "ip", "parent", "1:", "prio", "1", "u32",
            "match", "ip", "protocol", "17", "0xff",
            "match", "ip", "dst", f"{SERVER_LINK}/32",
            "match", "ip", "dport", str(PORT), "0xffff",
            "match", "u32", "0x4948200a", "0xffffffff", "at", str(20 + 8 + S1),
            "action", "drop",
        )
        # The send-side rekey timer is lazy: without outbound traffic, the
        # peer need not emit H1 when RekeyAfterTime expires. Keep the tunnel
        # active while the filter is installed and poll its counter until the
        # targeted H1 is actually dropped or the rekey window expires.
        deadline = time.monotonic() + 14.0
        dropped = 0
        stats = ""
        while time.monotonic() < deadline:
            run(
                "ip", "netns", "exec", client_ns, "ping", "-c1", "-W1",
                server_ip, check=False,
            )
            stats = run(
                "ip", "netns", "exec", client_ns, "tc", "-s", "filter",
                "show", "dev", client_link, "parent", "1:", capture=True,
            )
            match = re.search(r"dropped (\d+)", stats)
            dropped = int(match.group(1)) if match else 0
            if dropped > 0:
                break
            time.sleep(0.2)
    finally:
        run("ip", "netns", "exec", client_ns, "tc", "qdisc", "del",
            "dev", client_link, "root", check=False)
    if dropped < 1:
        raise RuntimeError(
            "tc did not drop the targeted H1 rekey datagram; "
            f"filter stats: {stats}"
        )
    print(f"PACKET-LOSS: tc dropped {dropped} matching H1 rekey datagram(s)")
    return dropped


def verify_udp_roundtrip(server_ns: str, client_ns: str) -> None:
    """Verify an actual bidirectional UDP payload through the encrypted tunnel."""
    server_code = (
        "import socket; "
        "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
        f"s.bind(('{SERVER_TUN}', 39001)); "
        "s.settimeout(14); "
        "data, addr=s.recvfrom(256); "
        "s.sendto(b'awg31-udp-reply:' + data, addr); "
        "print(data.decode(), flush=True)"
    )
    client_code = (
        "import socket, time\n"
        "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.settimeout(1.5)\n"
        f"target=('{SERVER_TUN}', 39001)\n"
        "data=None\n"
        "deadline=time.monotonic()+12\n"
        "while time.monotonic()<deadline:\n"
        "    s.sendto(b'probe', target)\n"
        "    try:\n"
        "        data, _=s.recvfrom(256)\n"
        "        break\n"
        "    except socket.timeout:\n"
        "        pass\n"
        "assert data == b'awg31-udp-reply:probe', data"
    )
    server = subprocess.Popen(
        ["ip", "netns", "exec", server_ns, "python3", "-c", server_code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        time.sleep(0.1)
        run("ip", "netns", "exec", client_ns, "python3", "-c", client_code)
        stdout, stderr = server.communicate(timeout=15)
        if server.returncode != 0:
            raise RuntimeError(f"UDP server failed: {stderr.strip() or stdout.strip()}")
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=1)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()




BULK_TRANSFER_HELPER = r"""
import hashlib
import socket
import struct
import sys
import time

mode, address, port, total_size, block_size = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])

def recv_exact(conn, length):
    chunks = []
    remaining = length
    while remaining:
        part = conn.recv(min(remaining, 1024 * 1024))
        if not part:
            raise RuntimeError(f"unexpected EOF with {remaining} bytes remaining")
        chunks.append(part)
        remaining -= len(part)
    return b"".join(chunks)

if mode == "recv":
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, port))
    listener.listen(1)
    listener.settimeout(180)
    conn, _ = listener.accept()
    listener.close()
    with conn:
        conn.settimeout(180)
        digest = hashlib.sha256()
        blocks = total = 0
        while total < total_size:
            header = recv_exact(conn, 8)
            sequence = struct.unpack("!Q", header)[0]
            expected_sequence = blocks
            if sequence != expected_sequence:
                raise RuntimeError(f"block sequence mismatch: got {sequence}, expected {expected_sequence}")
            length = min(block_size, total_size - total)
            payload = recv_exact(conn, length)
            expected_byte = bytes([sequence % 251])
            if payload != expected_byte * length:
                raise RuntimeError(f"payload corruption in block {sequence}")
            digest.update(payload)
            total += length
            blocks += 1
        result = digest.digest()
        conn.sendall(struct.pack("!Q", total) + result)
        print(f"BULK-RECEIVE bytes={total} blocks={blocks} sha256={digest.hexdigest()}", flush=True)
elif mode == "send":
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(180)
    deadline = time.monotonic() + 15
    while True:
        try:
            conn.connect((address, port))
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    with conn:
        digest = hashlib.sha256()
        blocks = total = 0
        while total < total_size:
            length = min(block_size, total_size - total)
            payload = bytes([blocks % 251]) * length
            conn.sendall(struct.pack("!Q", blocks) + payload)
            digest.update(payload)
            total += length
            blocks += 1
        ack = recv_exact(conn, 40)
        received_total = struct.unpack("!Q", ack[:8])[0]
        received_digest = ack[8:]
        if received_total != total:
            raise RuntimeError(f"receiver byte count mismatch: {received_total} != {total}")
        if received_digest != digest.digest():
            raise RuntimeError("receiver SHA-256 does not match sender SHA-256")
        print(f"BULK-SEND bytes={total} blocks={blocks} sha256={digest.hexdigest()} ACK=verified", flush=True)
else:
    raise RuntimeError(f"unknown mode: {mode}")
"""


def verify_bulk_data_transfer(
    server_ns: str, client_ns: str, helper_path: Path,
    total_size: int = 1 * 1024 * 1024,
    block_size: int = 64 * 1024,
) -> None:
    """Transfer and verify a large TCP stream in both tunnel directions."""
    helper_path.write_text(BULK_TRANSFER_HELPER, encoding="utf-8")
    scenarios = (
        ("client->server", client_ns, server_ns, SERVER_TUN),
        ("server->client", server_ns, client_ns, CLIENT_TUN),
    )
    for direction, sender_ns, receiver_ns, receiver_ip in scenarios:
        receiver = subprocess.Popen(
            [
                "ip", "netns", "exec", receiver_ns, "python3", str(helper_path),
                "recv", receiver_ip, "39002", str(total_size), str(block_size),
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            sender_output = run(
                "ip", "netns", "exec", sender_ns, "python3", str(helper_path),
                "send", receiver_ip, "39002", str(total_size), str(block_size),
                capture=True,
            )
            receiver_stdout, receiver_stderr = receiver.communicate(timeout=190)
            if receiver.returncode != 0:
                raise RuntimeError(
                    f"{direction} receiver failed: {receiver_stderr.strip() or receiver_stdout.strip()}"
                )
            print(f"BULK {direction}: {sender_output}")
            print(f"BULK {direction}: {receiver_stdout.strip()}")
        finally:
            if receiver.poll() is None:
                receiver.terminate()
                try:
                    receiver.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    receiver.kill()
                    receiver.wait()




def verify_iperf3(
    server_ns: str, client_ns: str, output_dir: Path, scenario: str,
    duration: int = 8,
) -> None:
    """Measure TCP/UDP throughput in both directions through the encrypted tunnel."""
    if shutil.which("iperf3") is None:
        raise RuntimeError("iperf3 is required; install the iperf3 package")
    output_dir.mkdir(parents=True, exist_ok=True)
    measurements = []
    tests = (
        ("tcp-1-stream", []),
        ("tcp-4-streams", ["-P", "4"]),
        ("udp-100-mbit", ["-u", "-b", "100M"]),
    )
    directions = (
        ("client-to-server", client_ns, server_ns, SERVER_TUN),
        ("server-to-client", server_ns, client_ns, CLIENT_TUN),
    )
    port = 39003

    for direction, sender_ns, receiver_ns, receiver_ip in directions:
        for test_name, extra_args in tests:
            server = subprocess.Popen(
                [
                    "ip", "netns", "exec", receiver_ns, "iperf3",
                    "-s", "-1", "-p", str(port), "-J",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                time.sleep(0.3)
                if server.poll() is not None:
                    stdout, stderr = server.communicate()
                    raise RuntimeError(
                        f"iperf3 server exited early: {stderr.strip() or stdout.strip()}"
                    )
                client_output = run(
                    "ip", "netns", "exec", sender_ns, "iperf3",
                    "-c", receiver_ip, "-p", str(port),
                    "-t", str(duration), "-J", *extra_args, capture=True,
                )
                server_stdout, server_stderr = server.communicate(
                    timeout=duration + 15
                )
                if server.returncode != 0:
                    raise RuntimeError(
                        f"iperf3 server failed: {server_stderr.strip() or server_stdout.strip()}"
                    )
                report = json.loads(client_output)
                end = report.get("end", {})
                received = end.get("sum_received") or end.get("sum") or {}
                sent = end.get("sum_sent") or end.get("sum") or {}
                bits_per_second = received.get("bits_per_second")
                if bits_per_second is None:
                    raise RuntimeError(
                        f"iperf3 report has no receiver throughput: {client_output[-2000:]}"
                    )
                item = {
                    "scenario": scenario,
                    "direction": direction,
                    "test": test_name,
                    "duration_seconds": duration,
                    "bytes_received": received.get("bytes"),
                    "bits_per_second": bits_per_second,
                    "throughput_mbps": bits_per_second / 1_000_000,
                    "tcp_retransmits": sent.get("retransmits"),
                    "udp_lost_percent": received.get("lost_percent"),
                    "udp_lost_packets": received.get("lost_packets"),
                    "udp_packets": received.get("packets"),
                }
                measurements.append(item)
                print(
                    f"IPERF3 {scenario} {direction} {test_name}: "
                    f"{item['throughput_mbps']:.2f} Mbit/s "
                    f"retransmits={item['tcp_retransmits']} "
                    f"udp_loss={item['udp_lost_percent']}"
                )
            finally:
                if server.poll() is None:
                    server.terminate()
                    try:
                        server.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()

    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", scenario)
    result_path = output_dir / f"{safe_name}.json"
    result_path.write_text(
        json.dumps(measurements, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"IPERF3-RESULTS: {result_path} ({len(measurements)} measurements)")

def disable_packet_offloads(namespace: str, interface: str) -> None:
    """Disable segmentation/coalescing on both veth ends for wire-accurate PCAPs."""
    run(
        "ip", "netns", "exec", namespace, "ethtool", "-K", interface,
        "gro", "off", "gso", "off", "tso", "off",
    )
    features = run(
        "ip", "netns", "exec", namespace, "ethtool", "-k", interface,
        capture=True,
    )
    for feature in (
        "generic-receive-offload",
        "generic-segmentation-offload",
        "tcp-segmentation-offload",
    ):
        match = re.search(
            rf"^\s*{re.escape(feature)}:\s+(on|off)",
            features, re.MULTILINE,
        )
        if match is None or match.group(1) != "off":
            raise RuntimeError(
                f"could not disable {feature} on {namespace}/{interface}: "
                f"{match.group(1) if match else 'feature unavailable'}"
            )


def verify_wire_pcap(
    pcap_path: Path,
    *,
    awg_enabled: bool,
    header_protection: bool,
    random_trailers: bool,
    expected_handshakes: int,
    expected_signatures: list[bytes],
    expected_initiations: int | None = None,
) -> None:
    """Decode captured UDP envelopes and assert normalized wire semantics.

    Noise ephemeral keys and nonces are random, so byte-for-byte equality
    between independent peers is not a valid differential criterion. Decode
    the protected type and verify direction, envelope sizes and framing.
    """
    raw = pcap_path.read_bytes()
    if len(raw) < 24:
        raise RuntimeError("wire capture is empty or truncated")
    magic = raw[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise RuntimeError(f"unsupported pcap magic: {magic.hex()}")
    link_type = struct.unpack_from(endian + "I", raw, 20)[0]
    if link_type != 1:
        raise RuntimeError(f"expected Ethernet pcap (link type 1), got {link_type}")

    if awg_enabled:
        # The RandomTrailers profiles deliberately use a separate equal-S
        # profile (64 bytes) to avoid upstream's ambiguous first-match parser.
        # Decode at the offsets actually configured for this run, not the
        # default S1-S4 values used by the non-RT interoperability profiles.
        s_values = (RT_S_PREFIX,) * 4 if random_trailers else (S1, S2, S3, S4)
        prefixes = dict(zip((1, 2, 3, 4), s_values))
    else:
        prefixes = {1: 0, 2: 0, 3: 0, 4: 0}
    h_tags = (
        {1: 169887817, 2: 390382747, 3: 1033691040, 4: 1526332224}
        if awg_enabled else {1: 1, 2: 2, 3: 3, 4: 4}
    )
    base_sizes = {1: 148, 2: 92, 3: 64, 4: 32}
    counts = {
        "client_to_server": {1: 0, 2: 0, 3: 0, 4: 0},
        "server_to_client": {1: 0, 2: 0, 3: 0, 4: 0},
    }
    hp_key = bytes.fromhex(HPK) if header_protection else None
    offset = 24
    packets = 0
    datagram_index = 0
    seen_signatures: set[bytes] = set()
    signature_positions: dict[bytes, int] = {}
    first_handshake_position = None

    while offset + 16 <= len(raw):
        _sec, _usec, captured_len, _original_len = struct.unpack_from(
            endian + "IIII", raw, offset
        )
        offset += 16
        frame = raw[offset:offset + captured_len]
        offset += captured_len
        if len(frame) < 14 or int.from_bytes(frame[12:14], "big") != 0x0800:
            continue
        ip = frame[14:]
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl + 8:
            continue
        src_port, dst_port, udp_len, _checksum = struct.unpack_from("!HHHH", ip, ihl)
        if src_port != 51820 and dst_port != 51820:
            continue
        ip_total_len = struct.unpack_from("!H", ip, 2)[0]
        if udp_len < 8:
            raise RuntimeError(f"invalid UDP length {udp_len} in {pcap_path.name}")
        if ip_total_len != ihl + udp_len:
            raise RuntimeError(
                f"IP/UDP length mismatch in {pcap_path.name}: "
                f"IPv4 total length={ip_total_len}, IHL={ihl}, UDP length={udp_len}; "
                "packet capture may contain GRO/GSO aggregation"
            )
        if ip_total_len > len(ip):
            raise RuntimeError(
                f"truncated IPv4 packet in {pcap_path.name}: "
                f"captured={len(ip)}, IPv4 total length={ip_total_len}"
            )
        payload = ip[ihl + 8:ihl + udp_len]
        if len(payload) < 4:
            continue
        packets += 1
        datagram_index += 1
        direction = "server_to_client" if src_port == 51820 else "client_to_server"
        is_signature = False
        for signature in expected_signatures:
            if payload.startswith(signature):
                seen_signatures.add(signature)
                signature_positions.setdefault(signature, datagram_index)
                is_signature = True
        if is_signature:
            continue
        # Each Noise message has its own independently configured S prefix.
        # Using S1 for every packet kind hides transport (type-4) headers,
        # whose prefix is S4, and misclassifies response/cookie envelopes too.
        kind_prefixes = prefixes
        if len(payload) < 4:
            continue
        # Header protection leaves the tag at the message-kind-specific offset.
        # Try each configured offset and accept only a decoded known type tag.
        candidates = [
            (kind, payload[prefix_len:prefix_len + 4])
            for kind, prefix_len in kind_prefixes.items()
            if len(payload) >= prefix_len + 4
        ]
        kind = None
        tag_bytes = None
        for candidate_kind, encrypted_tag in candidates:
            if hp_key is not None:
                if len(payload) < 12:
                    continue
                nonce = payload[:12]
                cipher = Cipher(
                    algorithms.ChaCha20(hp_key, b"\x00" * 4 + nonce),
                    mode=None,
                ).encryptor()
                stream = cipher.update(b"\x00" * 4)
                candidate_tag = bytes(a ^ b for a, b in zip(encrypted_tag, stream))
            else:
                candidate_tag = encrypted_tag
            decoded = int.from_bytes(candidate_tag, "little")
            if decoded == h_tags[candidate_kind]:
                kind = candidate_kind
                tag_bytes = candidate_tag
                break
        if kind is None:
            # Jc junk packets are not WireGuard message envelopes.
            continue

        packet_size = len(payload)
        minimum = prefixes[kind] + base_sizes[kind]
        if packet_size < minimum:
            raise RuntimeError(
                f"truncated type-{kind} envelope: {packet_size} < {minimum}"
            )
        if kind != 4 and not random_trailers and packet_size != minimum:
            raise RuntimeError(
                f"type-{kind} fixed envelope has length {packet_size}, expected {minimum}"
            )
        # RandomTrailers is bounded by the peer's learned UDP window,
        # not by DefaultUdpWindow (500). In upstream amneziawg-go,
        # Peer.randomTrailer() returns zero until that learned window can
        # accommodate the complete prefixed handshake envelope. Therefore
        # the only invariant available from a standalone PCAP is the minimum
        # envelope size checked above; a fixed 500-byte cap is incorrect
        # when S1/S2/S3 prefixes are configured.
        counts[direction][kind] += 1
        if kind == 1 and first_handshake_position is None:
            first_handshake_position = datagram_index

    if packets == 0:
        raise RuntimeError("pcap contains no UDP tunnel traffic on port 51820")
    required = {"client_to_server": (1, 4), "server_to_client": (2, 4)}
    for direction, kinds in required.items():
        for kind in kinds:
            minimum_count = (
                expected_initiations
                if kind == 1 and expected_initiations is not None
                else expected_handshakes if kind in (1, 2) else 1
            )
            if counts[direction][kind] < minimum_count:
                raise RuntimeError(
                    f"pcap missing type-{kind} from {direction}: "
                    f"observed {counts[direction][kind]}, expected >= {minimum_count}"
                )
    missing_signatures = set(expected_signatures) - seen_signatures
    if missing_signatures:
        missing_hex = ", ".join(value.hex() for value in sorted(missing_signatures))
        raise RuntimeError(f"pcap missing configured CPS signature datagrams: {missing_hex}")
    if expected_signatures and first_handshake_position is not None:
        signature_order = [signature_positions[value] for value in expected_signatures]
        if signature_order != sorted(signature_order):
            raise RuntimeError("CPS signature datagrams were not emitted in I1-I5 slot order")
        last_signature_position = max(signature_order)
        if last_signature_position >= first_handshake_position:
            raise RuntimeError(
                "CPS signature datagrams were not all sent before the first handshake initiation"
            )

    print(
        "PCAP "
        f"client->server={counts['client_to_server']} "
        f"server->client={counts['server_to_client']} "
        f"signatures={len(seen_signatures)} "
        f"datagrams={packets}"
    )


def run_profile(
    bt: str, go: str, name: str, extra: str,
    awg_enabled: bool, bt_is_server: bool, performance: bool = False,
    same_implementation: str | None = None,
    extended_matrix: bool = False, legacy_cpa: bool = False,
    reference_name: str = "amneziawg-go",
) -> None:
    token = uuid.uuid4().hex[:10]
    ns_server, ns_client = f"awg31s{token}", f"awg31c{token}"
    # UAPI sockets live in the host filesystem (/var/run/*), not inside
    # network namespaces. Therefore even peers in separate netns must have
    # distinct interface names; reusing one name for a homogeneous pair makes
    # the second process fail with "unix socket in use".
    bt_iface, go_iface = f"bt31{token}s", f"go31{token}s"
    bt_client_iface, go_client_iface = f"bt31{token}c", f"go31{token}c"
    veth_server, veth_client = f"avs{token}", f"avc{token}"
    processes: list[subprocess.Popen] = []
    log_files = []
    links_created = False
    capture_proc = None
    capture_log = None
    workdir = tempfile.TemporaryDirectory(prefix="awg31-interop-")
    logs = Path(workdir.name)
    if same_implementation is None:
        server_is_bt = bt_is_server
        client_is_bt = not bt_is_server
    else:
        if same_implementation not in ("boringtun", "amneziawg-go"):
            raise ValueError(f"unknown same implementation: {same_implementation}")
        server_is_bt = client_is_bt = same_implementation == "boringtun"
    server_iface = bt_iface if server_is_bt else go_iface
    client_iface = bt_client_iface if client_is_bt else go_client_iface
    server_name = "boringtun" if server_is_bt else reference_name
    client_name = "boringtun" if client_is_bt else reference_name
    role = f"{server_name}-to-{client_name}" if same_implementation else f"{server_name} server"
    capture_dir = Path("target/awg31-wire-pcaps")
    capture_dir.mkdir(parents=True, exist_ok=True)
    capture_path = capture_dir / (
        f"{name.replace(' ', '_')}-{role.replace(' ', '_')}.pcap"
    )

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
        # Disable offloads on both ends: GRO can merge received datagrams and
        # GSO/TSO can expose oversized pre-segmentation packets to tcpdump.
        disable_packet_offloads(ns_server, veth_server)
        disable_packet_offloads(ns_client, veth_client)
        ns(ns_client, "ping", "-c1", "-W3", SERVER_LINK)
        capture_log = open(logs / "tcpdump.log", "w", encoding="utf-8")
        capture_proc = subprocess.Popen(
            [
                "ip", "netns", "exec", ns_server, "tcpdump", "-U", "-n",
                "-i", veth_server, "-s", "65535", "-w", str(capture_path), "udp port 51820",
            ],
            stdout=capture_log,
            stderr=subprocess.STDOUT,
        )
        time.sleep(0.2)
        if capture_proc.poll() is not None:
            raise RuntimeError("tcpdump exited before the interop scenario started")

        def keypair() -> tuple[str, str]:
            private = os.urandom(32)
            public = X25519PrivateKey.from_private_bytes(private).public_key()
            raw_public = public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            return private.hex(), raw_public.hex()

        server_private, server_public = keypair()
        client_private, client_public = keypair()

        server_binary = bt if server_is_bt else go
        client_binary = bt if client_is_bt else go
        server_command = (
            [server_binary, "--foreground", "--disable-drop-privileges", server_iface]
            if server_is_bt else [server_binary, "-f", server_iface]
        )
        client_command = (
            [client_binary, "--foreground", "--disable-drop-privileges", client_iface]
            if client_is_bt else [client_binary, "-f", client_iface]
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

        awg_base = S_AND_H_RT if "random_trailers=true" in extra else S_AND_H
        awg = (awg_base if awg_enabled else "") + extra
        # CPA is sender-local. For the AWG 3.0 profile, select BoringTun's
        # legacy MTU-bounded algorithm only on BoringTun endpoints; upstream
        # Go has no such UAPI key and uses the semantics of its pinned version.
        bt_awg = awg + (
            "content_padding_mode=mtu\n"
            if legacy_cpa and "content_padding_addition=" in awg else ""
        )
        server_awg = bt_awg if server_is_bt else awg
        client_awg = bt_awg if client_is_bt else awg
        set_peer(server_iface, server_private, client_public, "none",
                 f"{CLIENT_TUN}/32", server_awg)
        set_peer(client_iface, client_private, server_public,
                 f"{SERVER_LINK}:{PORT}", f"{SERVER_TUN}/32", client_awg)

        ns(ns_server, "ip", "addr", "add", f"{SERVER_TUN}/24", "dev", server_iface)
        ns(ns_server, "ip", "link", "set", server_iface, "up", "mtu", "1420")
        ns(ns_client, "ip", "addr", "add", f"{CLIENT_TUN}/32", "dev", client_iface)
        ns(ns_client, "ip", "link", "set", client_iface, "up", "mtu", "1420")
        ns(ns_client, "ip", "route", "add", f"{SERVER_TUN}/32", "dev", client_iface)
        initial_handshake_time = wait_handshake(server_iface, ns_client, SERVER_TUN)
        if performance:
            verify_iperf3(
                ns_server, ns_client, Path("target/awg31-performance"),
                f"{name}-{role}",
            )
            verify_udp_roundtrip(ns_server, ns_client)
        elif name in ("accelerated rekey", "long peer lifecycle soak"):
            handshake_time = initial_handshake_time
            cycle_count = (
                120 if name == "long peer lifecycle soak"
                else 30 if extended_matrix else 1
            )
            for cycle in range(cycle_count):
                wait_rekey(server_iface, ns_client, SERVER_TUN, handshake_time)
                handshake_time = last_handshake_time(server_iface)
                verify_udp_roundtrip(ns_server, ns_client)
                print(
                    f"REKEY soak cycle {cycle + 1}/{cycle_count} completed ({role})"
                )
        elif name.startswith("bulk data integrity"):
            verify_bulk_data_transfer(
                ns_server, ns_client, logs / "bulk-transfer.py"
            )
            verify_udp_roundtrip(ns_server, ns_client)
        elif name == "rekey packet-loss recovery":
            drop_client_egress_during_rekey(ns_client, veth_client, SERVER_TUN)
            wait_rekey(server_iface, ns_client, SERVER_TUN, initial_handshake_time)
            verify_udp_roundtrip(ns_server, ns_client)
        else:
            ns(ns_client, "ping", "-c3", "-W2", SERVER_TUN)
            verify_udp_roundtrip(ns_server, ns_client)
        capture_proc.terminate()
        capture_proc.wait(timeout=3)
        capture_proc = None
        capture_log.close()
        capture_log = None
        verify_wire_pcap(
            capture_path,
            awg_enabled=awg_enabled,
            header_protection="header_protection_key=" in extra,
            random_trailers="random_trailers=true" in extra,
            expected_handshakes=(
                121 if name == "long peer lifecycle soak"
                else (30 if extended_matrix else 1) + 1 if name == "accelerated rekey"
                else 2 if name == "rekey packet-loss recovery"
                else 1
            ),
            # The capture runs on the server-side veth: it sees the initial
            # initiation and the successful retry, while tc's client-egress
            # filter counter proves the intervening H1 datagram was dropped.
            expected_initiations=(
                2 if name == "rekey packet-loss recovery"
                else (
                    121 if name == "long peer lifecycle soak"
                    else cycle_count + 1 if name == "accelerated rekey"
                    else 1
                )
            ),
            expected_signatures=[
                bytes.fromhex(value)
                for value in re.findall(r"i[1-5]=<b 0x([0-9a-fA-F]+)>", extra)
            ],
        )
        print(f"PASS {name} ({role}): handshake + bidirectional ICMP/UDP + normalized pcap")
    except Exception:
        for log_path in logs.glob("*.log"):
            tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-12:]
            if tail:
                print(f"--- {name} ({role}): {log_path.name} ---", file=sys.stderr)
                print("\n".join(tail), file=sys.stderr)
        raise
    finally:
        if capture_proc is not None:
            capture_proc.terminate()
            try:
                capture_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                capture_proc.kill()
                capture_proc.wait()
        if capture_log is not None:
            capture_log.close()
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
        for iface in (bt_iface, go_iface, bt_client_iface, go_client_iface):
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
    options = list(sys.argv[3:])
    awg30 = None
    wireguard = None
    if "--awg30" in options:
        index = options.index("--awg30")
        if index + 1 >= len(options):
            print("--awg30 requires a path to the official AWG 3.0 binary", file=sys.stderr)
            return 2
        awg30 = str(Path(options[index + 1]).resolve())
        del options[index:index + 2]
    if "--wireguard" in options:
        index = options.index("--wireguard")
        if index + 1 >= len(options):
            print("--wireguard requires a path to the official wireguard-go binary", file=sys.stderr)
            return 2
        wireguard = str(Path(options[index + 1]).resolve())
        del options[index:index + 2]
    if set(options) - {"--performance", "--full"} or ("--performance" in options and "--full" in options) or len(options) != len(set(options)):
        print(__doc__.split("Usage:", 1)[1].strip(), file=sys.stderr)
        return 2
    performance = "--performance" in options
    full_matrix = "--full" in options
    bt, go = (str(Path(p).resolve()) for p in sys.argv[1:3])
    if performance and shutil.which("iperf3") is None:
        print("iperf3 is required for --performance mode", file=sys.stderr)
        return 2
    for binary in (bt, go, *((awg30,) if awg30 else ()), *((wireguard,) if wireguard else ())):
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            print(f"not an executable file: {binary}", file=sys.stderr)
            return 2
    failures = 0
    total = 0
    if performance:
        # Homogeneous endpoint pairs isolate each implementation's own
        # datapath: amneziawg-go <-> amneziawg-go and BoringTun <-> BoringTun.
        for implementation in ("amneziawg-go", "boringtun"):
            for name, extra, awg_enabled in (PROFILES[0], PROFILES[5]):
                total += 1
                try:
                    run_profile(
                        bt, go, name, extra, awg_enabled, True,
                        performance=True, same_implementation=implementation,
                    )
                except Exception as error:
                    failures += 1
                    print(
                        f"FAIL {name} ({implementation}-to-{implementation}): {error}",
                        file=sys.stderr,
                    )
    else:
        selected_profiles = PROFILES if full_matrix else QUICK_PROFILES
        suite_name = "full" if full_matrix else "quick"
        print(f"MODE: {suite_name} interoperability suite ({len(selected_profiles) * 2} directional scenarios)")
        for name, extra, awg_enabled in selected_profiles:
            for bt_is_server in (True, False):
                total += 1
                try:
                    run_profile(
                        bt, go, name, extra, awg_enabled, bt_is_server,
                        extended_matrix=full_matrix,
                        legacy_cpa=(name == "bulk data integrity — AWG 3.0"),
                    )
                except Exception as error:
                    failures += 1
                    role = "BoringTun server" if bt_is_server else "amneziawg-go server"
                    print(f"FAIL {name} ({role}): {error}", file=sys.stderr)
    if awg30 is not None and not performance:
        print(f"MODE: official AWG 3.0.0 reference suite ({len(AWG30_PROFILES) * 2} directional scenarios)")
        for name, extra, awg_enabled in AWG30_PROFILES:
            for bt_is_server in (True, False):
                total += 1
                try:
                    run_profile(
                        bt, awg30, name, extra, awg_enabled, bt_is_server,
                        legacy_cpa=True,
                        reference_name="amneziawg-go-v3.0.0",
                    )
                except Exception as error:
                    failures += 1
                    role = "BoringTun server" if bt_is_server else "amneziawg-go v3.0.0 server"
                    print(f"FAIL AWG 3.0.0 / {name} ({role}): {error}", file=sys.stderr)
    if wireguard is not None and not performance:
        print("MODE: official WireGuard reference suite (2 directional scenarios)")
        for bt_is_server in (True, False):
            total += 1
            try:
                run_profile(
                    bt, wireguard, PROFILES[0][0], "", False, bt_is_server,
                    reference_name="wireguard-go",
                )
            except Exception as error:
                failures += 1
                role = "BoringTun server" if bt_is_server else "wireguard-go server"
                print(f"FAIL vanilla WireGuard ({role}): {error}", file=sys.stderr)
    print(f"SUMMARY: {total - failures}/{total} passed, {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
