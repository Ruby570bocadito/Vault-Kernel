#compdef vault_kernel vault_kernel_cli.py
# vault_kernel — zsh completion (v3.12)
#
# Parity twin of completions/vault_kernel.bash (same command surface,
# same flags — the CLIs share one grammar, ADR 18/19). Self-contained:
# it uses only zsh's builtin completion system (compdef/_arguments), no
# external completion package, so it works in minimal lab shells.
#
# Install (manual):
#   mkdir -p ~/.zsh/functions && cp completions/vault_kernel.zsh ~/.zsh/functions/_vault_kernel
#   fpath=(~/.zsh/functions $fpath) && autoload -Uz compinit && compinit
# or drop it anywhere in your $fpath as _vault_kernel.
#
# Flags per command mirror the CLIs' usage texts:
#   doctor/list/stats/status  --json
#   watch              --interval --once --count --count
#   keylog             --follow --timestamps --interval --output --stop-after
#   capture            --out --stdout
#   hide-file/unhide-file fall back to file names (_files).

_vault_kernel() {
    local -a commands
    commands=(
        'status:Check if rootkit is loaded'
        'doctor:Diagnose module/client state (lab sanity check)'
        'give-root:Escalate a process to root (default: self)'
        'hide-file:Hide a file/directory'
        'unhide-file:Reveal a hidden file/directory'
        'hide-pid:Hide a process from ps, top, /proc'
        'unhide-pid:Reveal a hidden process'
        'hide-port:Hide a TCP/UDP port from netstat, ss'
        'unhide-port:Reveal a hidden port'
        'list:List all hidden items'
        'stats:Show module stats (version, hooks, counts)'
        'watch:Live view of stats + hidden list'
        'shell:Trigger reverse shell'
        'magic:Set magic packet trigger word'
        'magic-encode:Print the kill() trigger for a word+port'
        'keylog:Read captured keystrokes'
        'keylog-clear:Clear keylogger buffer'
        'capture:Evidence bundle: stats + hidden + keylog as JSON'
        'hide-module:Hide rootkit from lsmod'
        'unhide-module:Make rootkit visible in lsmod'
        'reset:Clear ALL hidden files, PIDs and ports'
        'version:Print client version'
        'help:Print usage'
    )

    _arguments -C \
        '1:command:->cmd' \
        '*::argument:->args'

    case $state in
        cmd)
            _describe -t commands 'vault_kernel command' commands
            ;;
        args)
            case $words[1] in
                doctor|list|stats|status)
                    _arguments '--json[emit machine-readable JSON]'
                    ;;
                watch)
                    _arguments \
                        '--interval[refresh interval in ms (default 1000, min 50)]:MS:' \
                        '--once[render a single frame and exit (no ANSI control)]' \
                        '--count[render N frames and exit (finite window)]:N:' \
                        '--count[render N frames and exit (finite window)]:N:'
                    ;;
                keylog)
                    _arguments \
                        '--follow[stream new keystrokes until stopped]' \
                        '--timestamps[prefix each follow event with [HH:MM:SS]]' \
                        '--interval[poll interval in ms for --follow (default 500, min 50)]:MS:' \
                        '--output[also append every event to FILE (0600)]:FILE:_files' \
                        '--stop-after[stop cleanly after N events]:N:'
                    ;;
                capture)
                    _arguments \
                        '--out[write the bundle to FILE (0600)]:FILE:_files' \
                        '--stdout[with --out: also print the JSON to stdout]'
                    ;;
                hide-file|unhide-file)
                    _arguments '1:name:_files'
                    ;;
            esac
            ;;
    esac
}

_vault_kernel "$@"
