#!/bin/bash
# vault_kernel — Docker lab runner
# Builds the kernel module and manages the multi-node lab network.
# Usage: bash docker/test.sh [build|up|down|test]
#
# All commands operate on the single docker/docker-compose.yml.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="docker compose -f $SCRIPT_DIR/docker-compose.yml"

case "${1:-help}" in
    build)
        echo "[*] Building kernel module in Docker..."
        mkdir -p "$SCRIPT_DIR/out"
        $COMPOSE build builder
        $COMPOSE run --rm builder
        echo "[+] Build done. Output: $SCRIPT_DIR/out/"
        ;;

    up)
        echo "[*] Starting multi-node lab network..."
        echo "    Topology: attacker(172.30.0.100) - victim-1(172.30.0.10) + victim-2(172.30.0.20)"
        $COMPOSE up -d victim-1 victim-2 attacker
        echo "[+] Environment ready"
        echo "    Connect: docker exec -it vault_kernel-attacker bash"
        ;;

    down)
        echo "[*] Tearing down lab network..."
        $COMPOSE down -v
        echo "[+] Done"
        ;;

    test)
        echo "[*] Running integration test..."
        echo "[!] Note: Full kernel module testing requires a native Linux VM"
        echo "    Docker containers share the host kernel — cannot load LKMs"
        echo ""
        echo "    Payload-level regression tests run anywhere:"
        echo "      bash tests/test_payloads.sh"
        echo ""
        echo "    To test on a real VM:"
        echo "    1. Copy vault_kernel.ko and the client to the VM"
        echo "    2. sudo insmod vault_kernel.ko"
        echo "    3. sudo bash tests/integration.sh"
        echo "    4. Dry-run a dropper without touching the kernel:"
        echo "       INSMOD=/bin/true bash dropper.sh"
        ;;

    *)
        echo "vault_kernel Docker lab environment"
        echo ""
        echo "Usage: bash docker/test.sh <command>"
        echo ""
        echo "Commands:"
        echo "  build   Build kernel module in Docker"
        echo "  up      Start multi-node lab network"
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
