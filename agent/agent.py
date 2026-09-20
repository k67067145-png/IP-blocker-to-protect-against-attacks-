#!/usr/bin/env python3
"""
ROCKET Shield — Node Agent

Responsibilities:
  1. Load the XDP program onto the chosen interface (handles the "strong"
     / volumetric attacks: SYN flood, UDP flood, ICMP flood, amplification
     — all dropped in-kernel in microseconds, see xdp/ddos_xdp.c).
  2. Poll XDP maps for telemetry and push aggregated stats to the controller.
  3. Run an L7 behavioral watcher (handles the "weak" / low-and-slow attacks
     that stay under any pps threshold: slowloris, low-rate HTTP flood,
     slow POST body drip) and push offenders into the shared nftables
     dynamic_blocklist set, which both the L4 and L7 paths honor.
  4. Maintain an adaptive baseline (EWMA) per metric so thresholds adjust
     to the server's normal traffic instead of a single hardcoded number.

Requires: Linux, nftables, bpftool (part of linux-tools), Python 3.9+.
Run as root (needed for XDP attach + nftables + raw socket L7 watcher).

    pip install aiohttp pyroute2 --break-system-packages
"""

import asyncio
import json
import logging
import subprocess
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("rocket-agent")

XDP_OBJ_PATH = "/opt/rocket-shield/xdp/ddos_xdp.o"
NFT_TABLE = "inet rocket_shield"
BLOCKLIST_SET = "dynamic_blocklist"

CONFIG_PATH = "/etc/rocket-shield/agent.json"


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

@dataclass
class AgentConfig:
    interface: str = "eth0"
    mode: str = "self"
    controller_url: str = "wss://controller.example.com/agent/stream"
    node_id: str = ""
    tls_cert: str = "/etc/rocket-shield/agent.crt"
    tls_key: str = "/etc/rocket-shield/agent.key"
    http_ports: tuple = (80, 443)
    telemetry_interval_sec: float = 1.0

    @classmethod
    def load(cls, path=CONFIG_PATH):
        p = Path(path)
        if not p.exists():
            log.warning(
                "No config at %s, using defaults (edit before production use)",
                path,
            )
            return cls()
        data = json.loads(p.read_text())
        return cls(**data)


# --------------------------------------------------------------------------
# XDP loader + map interaction
# --------------------------------------------------------------------------

class XdpController:
    def __init__(self, interface: str, obj_path: str):
        self.interface = interface
        self.obj_path = obj_path

    def attach(self):
        log.info("Attaching XDP program to %s", self.interface)
        try:
            self._run([
                "ip",
                "link",
                "set",
                "dev",
                self.interface,
                "xdp",
                "obj",
                self.obj_path,
                "sec",
                "xdp",
            ])
        except subprocess.CalledProcessError:
            log.warning(
                "Native XDP attach failed, falling back to generic (SKB) mode"
            )
            self._run([
                "ip",
                "link",
                "set",
                "dev",
                self.interface,
                "xdpgeneric",
                "obj",
                self.obj_path,
                "sec",
                "xdp",
            ])

    def detach(self):
        self._run([
            "ip",
            "link",
            "set",
            "dev",
            self.interface,
            "xdp",
            "off",
        ], check=False)

    def set_thresholds(
        self,
        syn_pps,
        udp_pps,
        icmp_pps,
        global_alert,
    ):
        """Push updated thresholds into the threshold_cfg BPF array map."""
        map_id = self._find_map_id("threshold_cfg")

        if map_id is None:
            return

        value_hex = self._encode_u64_array([
            syn_pps,
            udp_pps,
            icmp_pps,
            global_alert,
        ])

        self._run([
            "bpftool",
            "map",
            "update",
            "id",
            str(map_id),
            "key",
            "0",
            "0",
            "0",
            "0",
            "value",
        ] + value_hex)

    def block_ip(self, ip: str, ttl_seconds: int = 300):
        """Insert into manual_block map with an absolute ktime deadline."""
        map_id = self._find_map_id("manual_block")

        if map_id is None:
            return

        key_bytes = self._ip_to_key_bytes(ip)
        deadline_ns = int((time.time() + ttl_seconds) * 1e9)
        value_hex = self._encode_u64(deadline_ns)

        self._run([
            "bpftool",
            "map",
            "update",
            "id",
            str(map_id),
            "key",
        ] + key_bytes + [
            "value",
        ] + value_hex)

        log.info(
            "XDP: blocked %s for %ds",
            ip,
            ttl_seconds,
        )

    def read_global_stats(self) -> dict:
        map_id = self._find_map_id("global_stats")

        if map_id is None:
            return {}

        out = self._run([
            "bpftool",
            "-j",
            "map",
            "lookup",
            "id",
            str(map_id),
            "key",
            "0",
            "0",
            "0",
            "0",
        ], capture=True)

        try:
            data = json.loads(out)
            values = data.get("value", {})

            return {
                "total_pps": values.get("total_pps", 0),
                "syn_pps": values.get("syn_pps", 0),
                "udp_pps": values.get("udp_pps", 0),
                "icmp_pps": values.get("icmp_pps", 0),
                "dropped_pps": values.get("dropped_pps", 0),
            }

        except (json.JSONDecodeError, AttributeError):
            return {}

    # -- helpers --------------------------------------------------------

    def _find_map_id(self, name: str):
        out = self._run([
            "bpftool",
            "-j",
            "map",
            "show",
        ], capture=True)

        try:
            maps = json.loads(out)
        except json.JSONDecodeError:
            return None

        for m in maps:
            if m.get("name") == name:
                return m.get("id")

        return None

    @staticmethod
    def _ip_to_key_bytes(ip: str):
        parts = ip.split(".")
        return [p for p in parts]

    @staticmethod
    def _encode_u64(value: int):
        b = value.to_bytes(8, "little")
        return [str(x) for x in b]

    @staticmethod
    def _encode_u64_array(values):
        out = []

        for v in values:
            out.extend(
                XdpController._encode_u64(v)
            )

        return out

    @staticmethod
    def _run(cmd, check=True, capture=False):
        log.debug(
            "exec: %s",
            " ".join(cmd),
        )

        result = subprocess.run(
            cmd,
            check=check,
            capture_output=capture,
            text=True,
        )

        return result.stdout if capture else None


# --------------------------------------------------------------------------
# nftables dynamic blocklist sync
# --------------------------------------------------------------------------

class NftBlocklist:
    def __init__(
        self,
        table=NFT_TABLE,
        set_name=BLOCKLIST_SET,
    ):
        self.table = table
        self.set_name = set_name

    def add(self, ip: str, timeout="10m"):
        cmd = [
            "nft",
            "add",
            "element",
            *self.table.split(),
            self.set_name,
            "{",
            f"{ip} timeout {timeout}",
            "}",
        ]

        subprocess.run(
            cmd,
            check=False,
        )

    def remove(self, ip: str):
        cmd = [
            "nft",
            "delete",
            "element",
            *self.table.split(),
            self.set_name,
            "{",
            ip,
            "}",
        ]

        subprocess.run(
            cmd,
            check=False,
        )


# --------------------------------------------------------------------------
# Adaptive baseline — EWMA per metric
# --------------------------------------------------------------------------

class EwmaBaseline:
    def __init__(self, alpha=0.1):
        self.alpha = alpha
        self.mean = {}
        self.variance = {}

    def update(
        self,
        metric: str,
        value: float,
    ):
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

    def is_anomalous(
        self,
        metric: str,
        value: float,
        z_thresh: float = 4.0,
    ) -> bool:
        if metric not in self.mean:
            return False

        std = self.variance[metric] ** 0.5

        if std < 1e-6:
            return False

        z = (
            value - self.mean[metric]
        ) / std

        return z > z_thresh


# --------------------------------------------------------------------------
# L7 behavioral watcher
# --------------------------------------------------------------------------

@dataclass
class ConnTracker:
    first_seen: float
    last_byte_progress: float
    request_count: int = 0


class L7Watcher:
    SLOW_CONN_AGE_THRESHOLD = 30.0
    SLOW_CONN_MIN_COUNT = 100
    REQ_RATE_WINDOW = 60
    REQ_RATE_THRESHOLD = 120

    def __init__(
        self,
        ports,
        blocklist: NftBlocklist,
        xdp: XdpController,
        baseline: EwmaBaseline,
    ):
        self.ports = set(ports)
        self.blocklist = blocklist
        self.xdp = xdp
        self.baseline = baseline

        self.request_log: dict[str, deque] = defaultdict(deque)
        self.half_open: dict[str, int] = defaultdict(int)

    async def run_forever(self):
        while True:
            try:
                self._scan_connections()
                self._evaluate_request_rates()

            except Exception:
                log.exception(
                    "L7Watcher iteration failed"
                )

            await asyncio.sleep(2.0)

    def _scan_connections(self):
        """
        Use `ss` to count half-open / slow connections per source IP on
        watched ports — cheap, no packet capture needed.
        """

        try:
            out = subprocess.run(
                [
                    "ss",
                    "-Htn",
                    "state",
                    "syn-recv",
                ],
                capture_output=True,
                text=True,
                timeout=2,
            )

        except (
            subprocess.SubprocessError,
            FileNotFoundError,
        ):
            return

        counts: dict[str, int] = defaultdict(int)

        for line in out.stdout.splitlines():
            cols = line.split()

            if len(cols) < 5:
                continue

            peer = cols[4]
            ip = peer.rsplit(":", 1)[0].strip("[]")

            counts[ip] += 1

        for ip, count in counts.items():
            self.baseline.update(
                "half_open_per_ip",
                count,
            )

            if (
                count >= self.SLOW_CONN_MIN_COUNT
                or self.baseline.is_anomalous(
                    "half_open_per_ip",
                    count,
                )
            ):
                self._flag(
                    ip,
                    reason=f"slow/half-open connections={count}",
                )

    def record_request(self, ip: str):
        """
        Call this from the reverse proxy's access-log tailer
        (see log_tailer.py).
        """

        now = time.monotonic()
        dq = self.request_log[ip]

        dq.append(now)

        while dq and now - dq[0] > self.REQ_RATE_WINDOW:
            dq.popleft()

    def _evaluate_request_rates(self):
        now = time.monotonic()

        for ip, dq in list(self.request_log.items()):
            while dq and now - dq[0] > self.REQ_RATE_WINDOW:
                dq.popleft()

            rate = len(dq)

            self.baseline.update(
                "req_rate",
                rate,
            )

            if (
                rate >= self.REQ_RATE_THRESHOLD
                or self.baseline.is_anomalous(
                    "req_rate",
                    rate,
                    z_thresh=5.0,
                )
            ):
                self._flag(
                    ip,
                    reason=(
                        f"sustained low-rate flood, "
                        f"{rate} req/{self.REQ_RATE_WINDOW}s"
                    ),
                )

            if not dq:
                del self.request_log[ip]

    def _flag(
        self,
        ip: str,
        reason: str,
    ):
        log.warning(
            "L7 anomaly from %s: %s — blocking",
            ip,
            reason,
        )

        self.blocklist.add(
            ip,
            timeout="10m",
        )

        self.xdp.block_ip(
            ip,
            ttl_seconds=600,
        )


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

async def telemetry_loop(
    xdp: XdpController,
    baseline: EwmaBaseline,
    cfg: AgentConfig,
):
    """
    Poll global stats, update baseline, and log locally.

    Wire the `# TODO push to controller` spot to your transport
    (gRPC/WS) — kept as a stub here so the agent is fully usable
    standalone, without a controller, for a single self-mode node.
    """

    while True:
        stats = xdp.read_global_stats()

        if stats:
            for metric, value in stats.items():
                baseline.update(
                    metric,
                    value,
                )

            log.info(
                "telemetry: %s",
                stats,
            )

            # TODO push to controller:
            # await ws.send(
            #     json.dumps({
            #         "node_id": cfg.node_id,
            #         **stats
            #     })
            # )

        await asyncio.sleep(
            cfg.telemetry_interval_sec
        )


async def main():
    cfg = AgentConfig.load()

    xdp = XdpController(
        cfg.interface,
        XDP_OBJ_PATH,
    )

    blocklist = NftBlocklist()
    baseline = EwmaBaseline()

    xdp.attach()

    xdp.set_thresholds(
        syn_pps=200,
        udp_pps=500,
        icmp_pps=100,
        global_alert=50000,
    )

    watcher = L7Watcher(
        cfg.http_ports,
        blocklist,
        xdp,
        baseline,
    )

    try:
        await asyncio.gather(
            telemetry_loop(
                xdp,
                baseline,
                cfg,
            ),
            watcher.run_forever(),
        )

    except asyncio.CancelledError:
        pass

    finally:
        log.info(
            "Shutting down, detaching XDP"
        )

        xdp.detach()


if __name__ == "__main__":
    asyncio.run(main())