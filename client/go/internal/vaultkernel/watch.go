package ioctl

import (
	"fmt"
	"sort"
	"strings"
)

// RenderWatchPanel builds the full-frame text printed by `watch` on
// every refresh (no change annotations — see RenderWatchPanelDiff).
// It is a PURE function — the CLI owns only the clear-screen/refresh
// loop — so the layout is unit-testable without a device. Layout
// (values are the raw report strings, keys sorted):
//
//	vault_kernel watch — refresh 1000 ms — updated 01:42:10 — Ctrl-C to stop
//	== stats ==
//	hooks_installed : 7
//	hooks_planned   : 7
//	...
//	== hidden ==
//	pids : 1234, 567
//	files: secret.txt, my dir/with space.txt
//	ports: (none)
//
// Empty hidden sections render as "(none)"; a missing stats report
// renders a "(no stats)" placeholder line instead of an empty frame.
func RenderWatchPanel(stats map[string]string, hl HiddenList, intervalMs int, refreshedAt string) string {
	return RenderWatchPanelDiff(stats, nil, hl, intervalMs, refreshedAt)
}

// RenderWatchPanelDiff is the change-aware form of the watch panel
// (v3.10): when prev is a NON-nil parsed report from the previous
// refresh, every stat whose value changed is annotated with
// " (was <old>)" and every key that did not exist before gets
// " (new)" — an operator running the live loop sees WHAT moved
// without diffing frames by eye. prev == nil renders the classic
// panel unchanged (first frame, --once, and every legacy caller).
// Only the stats section is annotated: the module's own counters
// (hidden_files/pids/ports) already reflect changes in the hidden
// lists (ADR 20).
func RenderWatchPanelDiff(stats, prev map[string]string, hl HiddenList, intervalMs int, refreshedAt string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "vault_kernel watch — refresh %d ms — updated %s — Ctrl-C to stop\n",
		intervalMs, refreshedAt)
	b.WriteString("===============================================\n")

	if len(stats) == 0 {
		b.WriteString("stats: (no stats)\n")
	} else {
		b.WriteString("== stats ==\n")
		keys := make([]string, 0, len(stats))
		width := 0
		for k := range stats {
			keys = append(keys, k)
			if len(k) > width {
				width = len(k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			suffix := ""
			if prev != nil {
				if old, seen := prev[k]; seen {
					if old != stats[k] {
						suffix = " (was " + old + ")"
					}
				} else {
					suffix = " (new)"
				}
			}
			fmt.Fprintf(&b, "%-*s : %s%s\n", width, k, stats[k], suffix)
		}
	}

	b.WriteString("== hidden ==\n")
	fmt.Fprintf(&b, "pids : %s\n", renderHiddenItems(intsToStrings(hl.PIDs)))
	fmt.Fprintf(&b, "files: %s\n", renderHiddenItems(hl.Files))
	fmt.Fprintf(&b, "ports: %s\n", renderHiddenItems(intsToStrings(hl.Ports)))
	return b.String()
}

// renderHiddenItems joins the items of one hidden section for the
// panel, or "(none)" when the section is empty.
func renderHiddenItems(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}

func intsToStrings(xs []int) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, fmt.Sprintf("%d", x))
	}
	return out
}
