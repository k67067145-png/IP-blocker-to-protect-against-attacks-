#!/usr/bin/env bash
set -euo pipefail

PREFIX="/opt/rocket-shield"
CONFIG_DIR="/etc/rocket-shield"

echo "[*] Installing ROCKET Shield BSD agent..."

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run this installer as root."
    exit 1
fi

mkdir -p "$PREFIX"
mkdir -p "$CONFIG_DIR"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

install -m 0755 \
    "$SCRIPT_DIR/bsd_agent.py" \
    "$PREFIX/bsd_agent.py"

install -m 0644 \
    "$SCRIPT_DIR/pf_baseline.conf" \
    "$CONFIG_DIR/pf_baseline.conf"

echo "[*] Loading pf baseline..."

if command -v pfctl >/dev/null 2>&1; then
    pfctl -f "$CONFIG_DIR/pf_baseline.conf"

    if pfctl -e >/dev/null 2>&1; then
        echo "[+] pf enabled."
    else
        echo "[!] pf may already be enabled."
    fi
else
    echo "[!] pfctl was not found."
    exit 1
fi

echo "[*] Creating startup configuration..."

case "$(uname -s)" in
    FreeBSD)
        cat > /etc/rc.d/rocket_shield_agent <<'EOF'
#!/bin/sh
#
# PROVIDE: rocket_shield_agent
# REQUIRE: NETWORKING pf
# KEYWORD: shutdown

. /etc/rc.subr

name="rocket_shield_agent"
rcvar="rocket_shield_agent_enable"
command="/usr/local/bin/python3"
command_args="/opt/rocket-shield/bsd_agent.py"
pidfile="/var/run/${name}.pid"

load_rc_config "$name"
: ${rocket_shield_agent_enable:="NO"}

run_rc_command "$1"
EOF

        chmod 0755 /etc/rc.d/rocket_shield_agent

        echo 'rocket_shield_agent_enable="YES"' \
            >> /etc/rc.conf

        echo "[+] FreeBSD startup configuration created."
        ;;

    OpenBSD)
        echo "[*] OpenBSD detected."
        echo "[*] Start the agent from your preferred rc/service manager."
        ;;

    *)
        echo "[!] Unsupported BSD variant: $(uname -s)"
        ;;
esac

echo
echo "[+] ROCKET Shield BSD agent installed."
echo "[+] Agent: $PREFIX/bsd_agent.py"
echo "[+] PF config: $CONFIG_DIR/pf_baseline.conf"