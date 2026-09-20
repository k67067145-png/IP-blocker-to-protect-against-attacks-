#!/usr/bin/env python3
"""
ROCKET Shield — FreeBSD / OpenBSD Agent

Both ship pf natively (macOS's pf is derived from the same codebase), so
this is the same approach as macos/macos_agent.py: a dynamic pf table
fed by connection-rate + EWMA-baseline detection.

Differences from the macOS agent worth knowing:
  - OpenBSD's pf syntax is very close to FreeBSD/macOS but table/anchor
    handling in pf_baseline.conf here targets both; if you hit a syntax
    error on load, check `man pf.conf` for your specific release — pf
    has drifted slightly between the BSDs over the years.
  - psutil support on OpenBSD is limited/unofficial. If `pip install
    psutil` fails, use the `netstat`-based fallback in scan_connections()
    below (auto-selected).

Run as root:
    pip install psutil   # or skip — falls back to netstat parsing
    python3 bsd_agent.py
"""

import re
import subprocess
import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger("rocket-agent-bsd")

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False
    log.warning(
        "psutil not available — using netstat fallback "
        "(less efficient, still works)"
    )

PF_TABLE = "rocket_blocklist"
SCAN_INTERVAL_SEC = 1.0
CONN_RATE_THRESHOLD = 150
BLOCK_DURATION_MIN = 15
WATCHED_PORTS = {80, 443, 22}

NETSTAT_LINE_RE = re.compile(
    r"^\S+\s+\d+\s+\d+\s+\S+\.(?P<lport>\d+)\s+"
    r"(?P<raddr>[\d.]+)\.(?P<rport>\d+)\s"
)


@dataclass
class EwmaBaseline:
    alpha: float = 0.1
    mean: dict = field(default_factory=dict)
    variance: dict = field(default_factory=dict)

    def update(self, metric, value):
        if metric not in self.mean:
            self.mean[metric] = value
            self.variance[metric] = 0.0
            return

        diff = value - self.mean[metric]
        incr = self.alpha * diff

        self.mean[metric] += incr

        self.variance[metric] = (
            (1 - self.alpha)
            * (self.variance[metric] + diff * incr)
        )

    def is_anomalous(self, metric, value, z_thresh=4.0):
        if metric not in self.mean:
            return False

        std = self.variance[metric] ** 0.5

        if std < 1e-6:
            return False

        return (
            (value - self.mean[metric]) / std
            > z_thresh
        )


class PfBlocklist:
    def block(self, ip: str):
        subprocess.run(
            [
                "pfctl",
                "-t",
                PF_TABLE,
                "-T",
                "add",
                ip,
            ],
            capture_output=True,
            check=False,
        )

        log.warning(
            "Blocked %s via pf table %s",
            ip,
            PF_TABLE,
        )

    def unblock(self, ip: str):
        subprocess.run(
            [
                "pfctl",
                "-t",
                PF_TABLE,
                "-T",
                "delete",
                ip,
            ],
            capture_output=True,
            check=False,
        )


def scan_connections_psutil():
    counts = defaultdict(int)

    try:
        for c in psutil.net_connections(kind="tcp"):
            if not c.raddr:
                continue

            if (
                c.laddr
                and c.laddr.port not in WATCHED_PORTS
            ):
                continue

            counts[c.raddr.ip] += 1

    except (
        psutil.AccessDenied,
        PermissionError,
    ):
        log.error(
            "Run as root to enumerate connections"
        )

    return counts


def scan_connections_netstat():
    """BSD netstat -an output parsing fallback for systems without psutil."""

    counts = defaultdict(int)

    try:
        out = subprocess.run(
            [
                "netstat",
                "-an",
                "-p",
                "tcp",
            ],
            capture_output=True,
            text=True,
            timeout=3,
        )

    except (
        subprocess.SubprocessError,
        FileNotFoundError,
    ):
        return counts

    for line in out.stdout.splitlines():
        m = NETSTAT_LINE_RE.match(line)

        if not m:
            continue

        lport = int(
            m.group("lport")
        )

        if lport not in WATCHED_PORTS:
            continue

        counts[
            m.group("raddr")
        ] += 1

    return counts


def scan_connections():
    return (
        scan_connections_psutil()
        if HAVE_PSUTIL
        else scan_connections_netstat()
    )


def main():
    pf = PfBlocklist()
    baseline = EwmaBaseline()

    blocked_at: dict[str, float] = {}

    log.info(
        "ROCKET Shield BSD agent started — "
        "watching ports %s",
        WATCHED_PORTS,
    )

    while True:
        counts = scan_connections()

        for ip, count in counts.items():
            if ip in blocked_at:
                continue

            baseline.update(
                "conn_per_ip",
                count,
            )

            if (
                count >= CONN_RATE_THRESHOLD
                or baseline.is_anomalous(
                    "conn_per_ip",
                    count,
                )
            ):
                pf.block(ip)

                blocked_at[ip] = time.time()

        now = time.time()

        expired = [
            ip
            for ip, timestamp in blocked_at.items()
            if now - timestamp
            > BLOCK_DURATION_MIN * 60
        ]

        for ip in expired:
            pf.unblock(ip)

            del blocked_at[ip]

            log.info(
                "Unblocked %s (TTL expired)",
                ip,
            )

        time.sleep(
            SCAN_INTERVAL_SEC
        )


if __name__ == "__main__":
    main()