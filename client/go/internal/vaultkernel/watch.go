package ioctl

import (
	"fmt"
	"sort"
	"strings"
)

// RenderWatchPanel builds the full-frame text printed by `watch` on
// every refresh. It is a PURE function — the CLI owns only the
// clear-screen/refresh loop — so the layout is unit-testable without a
// device. Layout (values are the raw report strings, keys sorted):
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
			fmt.Fprintf(&b, "%-*s : %s\n", width, k, stats[k])
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
