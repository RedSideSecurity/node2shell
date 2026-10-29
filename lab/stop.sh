#!/usr/bin/env bash
# Stop and remove the Node2Shell lab containers.
set -euo pipefail
docker rm -f node2shell-vuln node2shell-patched node2shell-stealth >/dev/null 2>&1 || true
echo "[+] Lab stopped."
