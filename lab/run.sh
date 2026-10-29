#!/usr/bin/env bash
# Build and start the Node2Shell lab: one vulnerable target, one patched control.
# Both bind to 127.0.0.1 only. Authorized, local testing only.
set -euo pipefail
cd "$(dirname "$0")"

VULN_PORT=8091    # Node 24.22.0 - vulnerable Brotli decoder, version visible
PATCHED_PORT=8092 # Node 24.22.1 - fixed
STEALTH_PORT=8093 # Node 24.22.0 - vulnerable, but version hidden (behavioral-only detection)

echo "[*] Building vulnerable target (node 24.22.0)..."
docker build -q --build-arg NODE_VERSION=24.22.0 -t node2shell-lab:vuln . >/dev/null

echo "[*] Building patched control (node 24.22.1)..."
docker build -q --build-arg NODE_VERSION=24.22.1 -t node2shell-lab:patched . >/dev/null

docker rm -f node2shell-vuln node2shell-patched node2shell-stealth >/dev/null 2>&1 || true

echo "[*] Starting containers..."
docker run -d --name node2shell-vuln    -p 127.0.0.1:${VULN_PORT}:3000    node2shell-lab:vuln    >/dev/null
docker run -d --name node2shell-patched -p 127.0.0.1:${PATCHED_PORT}:3000 node2shell-lab:patched >/dev/null
docker run -d --name node2shell-stealth -e HIDE_VERSION=1 -p 127.0.0.1:${STEALTH_PORT}:3000 node2shell-lab:vuln >/dev/null

sleep 2
echo
echo "[+] Lab is up:"
echo "    VULNERABLE (version visible) : http://127.0.0.1:${VULN_PORT}/   (node 24.22.0)"
echo "    PATCHED    (control)         : http://127.0.0.1:${PATCHED_PORT}/   (node 24.22.1)"
echo "    STEALTH    (version hidden)  : http://127.0.0.1:${STEALTH_PORT}/   (node 24.22.0, behavioral-only)"
echo
echo "    Try: python3 ../scanner/n2s_scan.py -u http://127.0.0.1:${VULN_PORT}/api/orders --probe"
