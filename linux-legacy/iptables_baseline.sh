#!/usr/bin/env bash
#
# ROCKET Shield — iptables fallback baseline
# For hosts where nftables/XDP aren't usable: many budget VPS (OpenVZ/LXC
# containers share the host kernel and can't load XDP), older distros,
# and most consumer Linux laptop kernels shipped without full eBPF tooling.
#
# Functionally equivalent to nftables/ddos_baseline.nft: SYN/UDP/ICMP rate
# limiting, per-IP new-connection caps (catches low-and-slow), ipset-backed
# dynamic blocklist that the agent's L7Watcher also writes to.

set -euo pipefail
IFACE="${1:-eth0}"

# ipset for dynamic blocking (agent writes here for L7-detected offenders)
ipset create rocket_blocklist hash:ip timeout 600 -exist
ipset create rocket_blocklist6 hash:ip family inet6 timeout 600 -exist

iptables -N ROCKET_SHIELD 2>/dev/null || iptables -F ROCKET_SHIELD
iptables -C INPUT -j ROCKET_SHIELD 2>/dev/null || iptables -I INPUT -j ROCKET_SHIELD

# fast path: known-bad
iptables -A ROCKET_SHIELD -m set --match-set rocket_blocklist src -j DROP

# loopback / established
iptables -A ROCKET_SHIELD -i lo -j ACCEPT
iptables -A ROCKET_SHIELD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A ROCKET_SHIELD -m conntrack --ctstate INVALID -j DROP

# ICMP: rate-limited, never fully dead
iptables -A ROCKET_SHIELD -p icmp --icmp-type echo-request -m limit --limit 50/s --limit-burst 20 -j ACCEPT
iptables -A ROCKET_SHIELD -p icmp --icmp-type echo-request -j DROP

# SYN flood: per-source new-connection rate cap via hashlimit
iptables -A ROCKET_SHIELD -p tcp --syn -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-name synflood --hashlimit-mode srcip \
    --hashlimit-above 1000/sec --hashlimit-burst 200 \
    -j SET --add-set rocket_blocklist src --exist
iptables -A ROCKET_SHIELD -p tcp --syn -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-name synflood --hashlimit-mode srcip \
    --hashlimit-above 1000/sec -j DROP
iptables -A ROCKET_SHIELD -p tcp --syn -m limit --limit 5000/s --limit-burst 500 -j ACCEPT
iptables -A ROCKET_SHIELD -p tcp --syn -j DROP

# UDP flood
iptables -A ROCKET_SHIELD -p udp -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-name udpflood --hashlimit-mode srcip \
    --hashlimit-above 200/sec --hashlimit-burst 50 \
    -j SET --add-set rocket_blocklist src --exist
iptables -A ROCKET_SHIELD -p udp -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-name udpflood --hashlimit-mode srcip \
    --hashlimit-above 200/sec -j DROP

# Amplification source ports — drop unsolicited large UDP replies
for port in 53 123 11211 1900 19; do
    iptables -A ROCKET_SHIELD -p udp --sport "$port" -m conntrack --ctstate NEW -j DROP
done

# Low-and-slow: cap new connections/min per source on web ports
iptables -A ROCKET_SHIELD -p tcp --dport 80 -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-name httpslow --hashlimit-mode srcip \
    --hashlimit-above 30/min --hashlimit-burst 30 \
    -j SET --add-set rocket_blocklist src --exist
iptables -A ROCKET_SHIELD -p tcp --dport 443 -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-name httpsslow --hashlimit-mode srcip \
    --hashlimit-above 30/min --hashlimit-burst 30 \
    -j SET --add-set rocket_blocklist src --exist

# SSH brute force
iptables -A ROCKET_SHIELD -p tcp --dport 22 -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-name sshbrute --hashlimit-mode srcip \
    --hashlimit-above 10/min \
    -j SET --add-set rocket_blocklist src --exist

# allow the rest through
iptables -A ROCKET_SHIELD -j RETURN

echo "[*] iptables ROCKET_SHIELD chain installed on ${IFACE}"
echo "[*] Persist with: iptables-save > /etc/iptables/rules.v4  (or netfilter-persistent save)"