#!/usr/bin/env python3
"""
ROCKET Shield — self-test tool

Opens many TCP connections against a target you own, to verify the agent
actually detects and blocks the pattern. This is NOT a load-testing or
attack tool for third-party targets — it refuses to run against anything
that isn't localhost or a private (RFC1918/link-local) address, since
that's the only thing "testing your own defense" ever needs.

Usage:
    python selftest.py --target 127.0.0.1 --port 3389 --connections 300

Run this from:
  - The same machine, targeting 127.0.0.1 — quick sanity check that the
    agent's connection-scan logic works at all.
  - A different device on your LAN, targeting the laptop's local IP
    (e.g. 192.168.1.23) — more realistic, since it exercises the actual
    per-source-IP tracking (the "attacker" now has a real, distinct IP
    the agent has to recognize).

After running, check:
    Get-NetFirewallRule -DisplayName "RocketShield_Block_*"
on the protected machine — the test source IP should appear within a
few seconds of crossing the threshold (default 150 connections).
"""

import argparse
import ipaddress
import socket
import sys
import threading
import time


def is_allowed_target(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except (socket.gaierror, ValueError):
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def open_connection(host: str, port: int, hold_seconds: float, results: list):
    try:
        s = socket.create_connection((host, port), timeout=3)
        results.append(True)
        time.sleep(hold_seconds)
        s.close()
    except OSError:
        results.append(False)


def main():
    ap = argparse.ArgumentParser(
        description="ROCKET Shield self-test: flood your own machine to verify detection"
    )
    ap.add_argument(
        "--target",
        required=True,
        help="Target host — must be localhost or a private-network IP"
    )
    ap.add_argument(
        "--port",
        type=int,
        required=True,
        help="Port the agent is watching (e.g. 3389, 80, 443)"
    )
    ap.add_argument(
        "--connections",
        type=int,
        default=300,
        help="Number of connections to open (default 300)"
    )
    ap.add_argument(
        "--hold-seconds",
        type=float,
        default=2.0,
        help="How long each connection stays open"
    )
    args = ap.parse_args()

    if not is_allowed_target(args.target):
        print(
            f"[!] Refusing: '{args.target}' is not localhost "
            "or a private-network address."
        )
        print("    This tool only tests machines you own on a private network.")
        sys.exit(1)

    print(
        f"[*] Opening {args.connections} connections "
        f"to {args.target}:{args.port} ..."
    )

    results = []
    threads = []

    for i in range(args.connections):
        t = threading.Thread(
            target=open_connection,
            args=(args.target, args.port, args.hold_seconds, results)
        )
        t.start()
        threads.append(t)
        time.sleep(0.01)

    for t in threads:
        t.join()

    ok = sum(results)

    print(
        f"[*] Done. {ok}/{args.connections} connections succeeded, "
        f"{len(results) - ok} refused/failed."
    )

    print("[*] Now check the protected machine for a block rule:")
    print('    Get-NetFirewallRule -DisplayName "RocketShield_Block_*"   (Windows)')
    print("    nft list set inet rocket_shield dynamic_blocklist         (Linux)")
    print("    pfctl -t rocket_blocklist -T show                        (macOS/BSD)")


if __name__ == "__main__":
    main()