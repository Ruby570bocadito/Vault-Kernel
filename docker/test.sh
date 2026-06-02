#!/bin/bash
# vault_kernel — Docker test runner
# Brings up multi-node test environment
# Usage: bash docker/test.sh [build|up|down|test]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"

case "${1:-help}" in
    build)
        echo "[*] Building kernel module in Docker..."
        mkdir -p "$SCRIPT_DIR/out"
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" build builder
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" run --rm builder
        echo "[+] Build done. Output: $SCRIPT_DIR/out/"
        ;;

    up)
        echo "[*] Starting multi-node test environment..."
        echo "    Topology: attacker(172.30.0.100) ↔ victim-1(172.30.0.10) + victim-2(172.30.0.20)"
        docker compose -f "$SCRIPT_DIR/docker-compose.test.yml" up -d
        echo "[+] Environment ready"
        echo "    Connect: docker exec -it vault_kernel-attacker bash"
        ;;

    down)
        echo "[*] Tearing down test environment..."
        docker compose -f "$SCRIPT_DIR/docker-compose.test.yml" down -v
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" down -v 2>/dev/null || true
        echo "[+] Done"
        ;;

    test)
        echo "[*] Running integration test..."
        echo "[!] Note: Full kernel module testing requires a native Linux VM"
        echo "    Docker containers share the host kernel — cannot load LKMs"
        echo ""
        echo "    To test on a real VM:"
        echo "    1. Copy vault_kernel.ko and client to the VM"
        echo "    2. sudo insmod vault_kernel.ko"
        echo "    3. sudo bash tests/integration.sh"
        ;;

    *)
        echo "vault_kernel Docker test environment"
        echo ""
        echo "Usage: bash docker/test.sh <command>"
        echo ""
        echo "Commands:"
        echo "  build   Build kernel module in Docker"
        echo "  up      Start multi-node test network"
        echo "  down    Stop and clean up"
        echo "  test    Show testing instructions"
        echo ""
        echo "Architecture:"
        echo "  vault_kernel-attacker  (172.30.0.100) — C2 / attacker machine"
        echo "  vault_kernel-victim-1  (172.30.0.10)  — SSH + nginx + netcat"
        echo "  vault_kernel-victim-2  (172.30.0.20)  — minimal services"
        echo "  vault_kernel-net       bridge, 172.30.0.0/24"
        ;;
esac
