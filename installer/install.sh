#!/usr/bin/env bash
set -euo pipefail

PREFIX="/opt/rocket-shield"
CONFIG_DIR="/etc/rocket-shield"
SERVICE_FILE="/etc/systemd/system/rocket-shield-agent.service"

echo "[*] Installing ROCKET Shield..."

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run this installer as root."
    exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"

mkdir -p "$PREFIX"
mkdir -p "$CONFIG_DIR"

echo "[*] Installing agent..."

install -m 0755 \
    "$PROJECT_DIR/agent/agent.py" \
    "$PREFIX/agent.py"

if [ -f "$PROJECT_DIR/agent/log_tailer.py" ]; then
    install -m 0755 \
        "$PROJECT_DIR/agent/log_tailer.py" \
        "$PREFIX/log_tailer.py"
fi

if [ -f "$PROJECT_DIR/nftables/ddos_baseline.nft" ]; then
    install -m 0644 \
        "$PROJECT_DIR/nftables/ddos_baseline.nft" \
        "$CONFIG_DIR/ddos_baseline.nft"
fi

echo "[*] Checking dependencies..."

for command in python3 ip nft ss; do
    if command -v "$command" >/dev/null 2>&1; then
        echo "[+] $command found"
    else
        echo "[!] $command not found"
    fi
done

echo "[*] Installing systemd service..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=ROCKET Shield defensive network protection agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $PREFIX/agent.py
Restart=always
RestartSec=5

NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "$SERVICE_FILE"

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable rocket-shield-agent.service

    echo "[+] systemd service installed."
    echo "[*] Start with:"
    echo "    systemctl start rocket-shield-agent.service"
else
    echo "[!] systemctl not found."
    echo "[!] Service file was still installed at:"
    echo "    $SERVICE_FILE"
fi

echo
echo "[+] ROCKET Shield installation completed."
echo "[+] Agent: $PREFIX/agent.py"
echo "[+] Config: $CONFIG_DIR"