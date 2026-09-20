#!/usr/bin/env python3

import os
import signal
import subprocess
import time
from collections import defaultdict

try:
    import psutil
except ImportError:
    psutil = None


RUNNING = True
BLOCKED = set()


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def block_ip(ip):
    if not ip or ip in BLOCKED:
        return

    BLOCKED.add(ip)

    run_command([
        "pfctl",
        "-t",
        "rocket_shield_blocked",
        "-T",
        "add",
        ip,
    ])

    print(f"[BLOCK] {ip}")


def unblock_ip(ip):
    if ip not in BLOCKED:
        return

    BLOCKED.discard(ip)

    run_command([
        "pfctl",
        "-t",
        "rocket_shield_blocked",
        "-T",
        "delete",
        ip,
    ])


def get_connections():
    if psutil is None:
        return []

    try:
        connections = psutil.net_connections(kind="inet")
    except Exception:
        return []

    result = []

    for connection in connections:
        if not connection.raddr:
            continue

        try:
            remote_ip = connection.raddr.ip
            remote_port = connection.raddr.port
        except AttributeError:
            continue

        result.append({
            "ip": remote_ip,
            "port": remote_port,
            "status": connection.status,
        })

    return result


def monitor_connections():
    counters = defaultdict(int)

    for connection in get_connections():
        ip = connection["ip"]

        if ip in BLOCKED:
            continue

        counters[ip] += 1

    for ip, count in counters.items():
        if count >= 100:
            block_ip(ip)

    return counters


def ensure_pf_table():
    run_command([
        "pfctl",
        "-t",
        "rocket_shield_blocked",
        "-T",
        "show",
    ])


def signal_handler(signum, frame):
    global RUNNING
    RUNNING = False


def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("[*] ROCKET Shield macOS agent started.")

    if os.geteuid() != 0:
        print("[!] Warning: root privileges are recommended.")

    ensure_pf_table()

    while RUNNING:
        counters = monitor_connections()

        total = sum(counters.values())

        print(
            f"[STATUS] active_remote_connections={total} "
            f"blocked={len(BLOCKED)}"
        )

        time.sleep(5)

    print("[*] ROCKET Shield macOS agent stopped.")


if __name__ == "__main__":
    main()