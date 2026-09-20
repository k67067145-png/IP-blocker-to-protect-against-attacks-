#!/usr/bin/env python3
"""
Tails an nginx/OpenResty/BunkerWeb access log (combined format) and feeds
per-IP request timestamps into L7Watcher.record_request(). Run alongside
agent.py (imported directly, or as a separate process publishing over a
local Unix socket — shown here as direct import for simplicity).

nginx log_format expected (default 'combined' works):
    $remote_addr - $remote_user [$time_local] "$request" $status ...
"""

import re
import time

LOG_LINE_RE = re.compile(r'^(?P<ip>[\da-fA-F:.]+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d+)')


def tail_f(path: str):
    with open(path, "r") as f:
        f.seek(0, 2)  # seek to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line


def watch_access_log(path: str, watcher):
    """watcher: an L7Watcher instance from agent.py"""
    for line in tail_f(path):
        m = LOG_LINE_RE.match(line)
        if not m:
            continue
        watcher.record_request(m.group("ip"))


if __name__ == "__main__":
    import sys
    import asyncio
    from agent import L7Watcher, NftBlocklist, XdpController, EwmaBaseline, AgentConfig, XDP_OBJ_PATH

    log_path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/nginx/access.log"
    cfg = AgentConfig.load()
    xdp = XdpController(cfg.interface, XDP_OBJ_PATH)
    watcher = L7Watcher(cfg.http_ports, NftBlocklist(), xdp, EwmaBaseline())

    watch_access_log(log_path, watcher)