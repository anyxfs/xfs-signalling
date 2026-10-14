"""Explicit network smoke test; never run as part of offline unit tests.

Sends an RFC 5389 binding request. Reports reachability, not the mapped IP.
Usage: python tools/check_stun.py
"""
import concurrent.futures
import argparse
import secrets
import socket
import struct
import time

HOSTS = ["stun.l.google.com", "stun1.l.google.com",
         "stun2.l.google.com", "stun3.l.google.com"]
COOKIE = 0x2112A442


def probe(host):
    host, port = host.rsplit(":", 1) if ":" in host else (host, "19302")
    port = int(port)
    endpoint = f"{host}:{port}"
    started = time.monotonic()
    transaction = secrets.token_bytes(12)
    request = struct.pack("!HHI12s", 0x0001, 0, COOKIE, transaction)
    try:
        # IPv4 reachability only; IPv6 and NAT traversal need separate coverage.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.connect((host, port))
            for _ in range(2):
                sock.send(request)
                try:
                    response = sock.recv(2048)
                    break
                except socket.timeout:
                    pass
            else:
                return endpoint, False, "timeout (2 attempts)"
        if len(response) < 20:
            raise ValueError("short response")
        typ, length, cookie, tx = struct.unpack("!HHI12s", response[:20])
        if (typ, cookie, tx) != (0x0101, COOKIE, transaction) or length != len(response)-20 or length % 4:
            raise ValueError("invalid binding response")
        offset, mapped = 20, False
        while offset < len(response):
            if offset+4 > len(response):
                raise ValueError("truncated attribute header")
            kind, size = struct.unpack("!HH", response[offset:offset+4])
            value = response[offset+4:offset+4+size]
            if len(value) != size:
                raise ValueError("truncated attribute")
            if kind in (0x0020, 0x0001) and size >= 2:
                mapped |= (value[1] == 1 and size == 8) or (value[1] == 2 and size == 20)
            offset += 4 + ((size+3)//4)*4
        if not mapped or offset != len(response):
            raise ValueError("missing mapped address or invalid padding")
        return endpoint, True, f"binding OK, {round((time.monotonic()-started)*1000)} ms"
    except (OSError, ValueError) as error:
        return endpoint, False, str(error)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("endpoints", nargs="*", help="host:port (IPv4 probe); defaults to Google STUN")
    args = parser.parse_args()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(probe, args.endpoints or HOSTS))
    for host, ok, detail in results:
        print(f"{host} {'PASS' if ok else 'FAIL'} {detail}")
    raise SystemExit(0 if all(ok for _, ok, _ in results) else 1)
