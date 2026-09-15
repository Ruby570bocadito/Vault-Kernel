#!/usr/bin/env bash
# Functional test for completions/vault_kernel.bash (v3.9) and
# completions/vault_kernel.zsh (v3.11, parity section).
#
# The completion script is deliberately self-contained (no
# bash-completion package helpers), so this test can source it and drive
# the completion function directly through COMP_WORDS/COMP_CWORD — the
# same interface readline uses — and assert on COMPREPLY. No device, no
# root, no kernel: safe to run anywhere bash exists (CI included).
#
# Coverage:
#   1. The script is syntactically valid (bash -n) and registers both
#      client binaries with `complete`.
#   2. Level-1 completion offers the full command surface.
#   3. Subcommand completion offers the documented flags per command.
#   4. hide-file/unhide-file fall back to filesystem paths.
#   5. Positional commands (give-root, shell, ...) complete nothing.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPLETIONS="$SCRIPT_DIR/../completions/vault_kernel.bash"

PASS=0
FAIL=0

check() {
    # check <desc> <expected-substring-or-""> ...: asserts that the
    # completion output words contain every expected token.
    local desc="$1"; shift
    local expected=("$@")
    local missing=0
    for tok in "${expected[@]}"; do
        local found=0
        local w
        for w in "${COMPREPLY[@]:-}"; do
            [[ "$w" == "$tok" ]] && found=1
        done
        [[ $found -eq 0 ]] && { missing=1; break; }
    done
    if [[ $missing -eq 0 ]]; then
        PASS=$((PASS + 1))
        echo "  ok  - $desc"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL- $desc (got: ${COMPREPLY[*]:-<empty>}; want: ${expected[*]})"
    fi
}

run_completion() {
    # run_completion <word0> <word1> ... <cur>: simulate readline state.
    COMP_WORDS=("$@")
    COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
    COMPREPLY=()
    _vault_kernel_completions
}

echo "== completions/vault_kernel.bash =="

# 1. Syntax + registration.
if bash -n "$COMPLETIONS"; then
    PASS=$((PASS + 1)); echo "  ok  - bash -n (syntax)"
else
    FAIL=$((FAIL + 1)); echo "  FAIL- bash -n (syntax)"
fi

# shellcheck source=/dev/null disable=SC1091
source "$COMPLETIONS"
if complete -p vault_kernel >/dev/null 2>&1 && \
   complete -p vault_kernel_cli.py >/dev/null 2>&1; then
    PASS=$((PASS + 1)); echo "  ok  - complete registered for both CLIs"
else
    FAIL=$((FAIL + 1)); echo "  FAIL- complete registration missing"
fi

# 2. Level-1: the whole command surface (both clients' union).
run_completion vault_kernel ""
check "level-1 lists commands" status doctor give-root hide-file \
    hide-pid hide-port list stats watch shell magic magic-encode keylog \
    keylog-clear capture hide-module unhide-module reset version help

# Level-1 partial: "hi" -> hide-file, hide-pid, hide-module.
run_completion vault_kernel "hi"
check "level-1 prefix 'hi'" hide-file hide-pid hide-module

# 3. Flags per command.
run_completion vault_kernel keylog ""
check "keylog flags" --follow --timestamps --interval --output
run_completion vault_kernel capture ""
check "capture flags" --out
run_completion vault_kernel stats ""
check "stats flags" --json
run_completion vault_kernel watch ""
check "watch flags" --interval --once --count
run_completion vault_kernel status ""
check "status flags" --json

# 4. File operands fall back to the filesystem: in an empty temp dir with
# one file, "hide-file <TAB>" must offer it.
TMPDIR_TEST="$(mktemp -d)"
touch "$TMPDIR_TEST/secret.txt"
if (
    cd "$TMPDIR_TEST" || exit 1
    run_completion vault_kernel hide-file ""
    for w in "${COMPREPLY[@]:-}"; do
        [[ "$w" == "secret.txt" ]] && exit 0
    done
    exit 1
); then
    PASS=$((PASS + 1)); echo "  ok  - hide-file offers filesystem paths"
else
    FAIL=$((FAIL + 1)); echo "  FAIL- hide-file offers filesystem paths"
fi
rm -rf "$TMPDIR_TEST"

# 5. Positional commands complete nothing (no flags invented).
run_completion vault_kernel give-root ""
check "give-root: no completions" ""
run_completion vault_kernel shell ""
check "shell: no completions" ""

# ---------------------------------------------------------------------------
# zsh completion (v3.11): parity with the bash surface.
#   - `zsh -n` syntax check when zsh is installed (skipped otherwise —
#     the file stays checked by the parity greps below in every run).
#   - Command surface and flags are compared TEXTUALLY against the bash
#     script, so the two files cannot drift apart silently.
# ---------------------------------------------------------------------------
ZSH_FILE="$SCRIPT_DIR/../completions/vault_kernel.zsh"
echo
echo "== completions/vault_kernel.zsh =="

if [[ -f "$ZSH_FILE" ]]; then
    PASS=$((PASS + 1)); echo "  ok  - file exists"
else
    FAIL=$((FAIL + 1)); echo "  FAIL- file missing: $ZSH_FILE"
fi

if command -v zsh >/dev/null 2>&1; then
    if zsh -n "$ZSH_FILE" 2>/dev/null; then
        PASS=$((PASS + 1)); echo "  ok  - zsh -n (syntax)"
    else
        FAIL=$((FAIL + 1)); echo "  FAIL- zsh -n (syntax)"
    fi
else
    echo "  ..  - zsh not installed: syntax check skipped (parity greps still run)"
fi

# Parity: the zsh file must mention EVERY command of the bash surface.
missing_cmds=0
for cmd in status doctor give-root hide-file unhide-file hide-pid \
           unhide-pid hide-port unhide-port list stats watch shell \
           magic magic-encode keylog keylog-clear capture hide-module \
           unhide-module reset version help; do
    if ! grep -q -- "$cmd" "$ZSH_FILE"; then
        missing_cmds=1
        echo "  FAIL- zsh missing command: $cmd"
    fi
done
if [[ $missing_cmds -eq 0 ]]; then
    PASS=$((PASS + 1)); echo "  ok  - command surface parity (23 commands)"
else
    FAIL=$((FAIL + 1))
fi

# Parity: every documented flag must appear in both files.
missing_flags=0
for flag in --json --interval --once --count --follow --timestamps --output \
            --stop-after --out --stdout; do
    if ! grep -q -- "$flag" "$ZSH_FILE"; then
        missing_flags=1
        echo "  FAIL- zsh missing flag: $flag"
    fi
    if ! grep -q -- "$flag" "$COMPLETIONS"; then
        missing_flags=1
        echo "  FAIL- bash missing flag: $flag (added in zsh first?)"
    fi
done
if [[ $missing_flags -eq 0 ]]; then
    PASS=$((PASS + 1)); echo "  ok  - flag parity (10 flags, both files)"
else
    FAIL=$((FAIL + 1))
fi

echo
echo "Results: $PASS passed / $FAIL failed"
[[ $FAIL -eq 0 ]]
