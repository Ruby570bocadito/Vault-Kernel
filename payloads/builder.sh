#!/bin/bash
# vault_kernel — Payload builder wrapper
# Quick CLI for payload.py. For interactive mode, run: python3 payload.py
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/payload.py" "$@"
