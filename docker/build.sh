#!/bin/bash
# vault_kernel Docker build script
# Builds the kernel module inside a Docker container with matching kernel headers.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
OUT_DIR="$SCRIPT_DIR/out"

echo "[*] Building vault_kernel kernel module in Docker..."
echo "    Source: $ROOT/src"
echo "    Output: $OUT_DIR"

mkdir -p "$OUT_DIR"

docker compose -f "$SCRIPT_DIR/docker-compose.yml" build builder
docker compose -f "$SCRIPT_DIR/docker-compose.yml" run --rm builder

if [ -f "$OUT_DIR/vault_kernel.ko" ]; then
    echo "[+] Build successful!"
    echo "    Module: $OUT_DIR/vault_kernel.ko"
    modinfo "$OUT_DIR/vault_kernel.ko" 2>/dev/null || echo "    (modinfo not available in WSL)"
else
    echo "[-] Build failed — vault_kernel.ko not found in $OUT_DIR"
    exit 1
fi
