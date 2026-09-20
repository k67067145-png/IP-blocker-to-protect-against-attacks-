#!/usr/bin/env bash
set -euo pipefail

PREFIX="/opt/rocket-shield"
CONFIG_DIR="/etc/rocket-shield"

echo "[*] Installing ROCKET Shield macOS agent..."

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run this installer as root."
    exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

mkdir -p "$PREFIX"
mkdir -p "$CONFIG_DIR"

install -m 0755 \
    "$SCRIPT_DIR/macos_agent.py" \
    "$PREFIX/macos_agent.py"

if [ -f "$SCRIPT_DIR/pf_baseline.conf" ]; then
    install -m 0644 \
        "$SCRIPT_DIR/pf_baseline.conf" \
        "$CONFIG_DIR/pf_baseline.conf"
fi

echo "[*] Checking Python..."

if command -v python3 >/dev/null 2>&1; then
    echo "[+] Python 3 found: $(command -v python3)"
else
    echo "[!] Python 3 was not found."
    exit 1
fi

echo "[*] Checking PF..."

if command -v pfctl >/dev/null 2>&1; then
    echo "[+] pfctl found."

    if [ -f "$CONFIG_DIR/pf_baseline.conf" ]; then
        pfctl -f "$CONFIG_DIR/pf_baseline.conf"
    fi
else
    echo "[!] pfctl was not found."
fi

echo
echo "[+] ROCKET Shield macOS agent installed."
echo "[+] Agent: $PREFIX/macos_agent.py"
echo "[+] Config: $CONFIG_DIR"
echo
echo "[*] Start manually with:"
echo "    python3 $PREFIX/macos_agent.py"