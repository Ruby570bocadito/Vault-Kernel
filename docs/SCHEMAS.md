# Machine-Readable Output Schemas

Contract reference for the JSON output of the two CLIs (Go and Python).
Every document carries a **`schema`** field (ADR 17, v3.7): scripts can
pin `jq -e '.schema == 1'` and detect format changes instead of failing
silently. Both clients emit byte-identical documents for the same
module state — the parity is pinned by unit tests in BOTH clients
(`TestMarshalStatsJSON`, `TestDoctorJSONEnvelopeParity`,
`TestListJsonEndToEnd`, and the Python mirrors).

**Versioning policy:** the `schema` integer only increments when a
field changes MEANING or SHAPE. Additive fields keep the value at `1`.
The version of the producing CLIENT is a separate field
(`client_version`) and is NOT part of this contract.

---

## `stats --json`

Source: `GET_STATS` report parsed by `ParseStatsReport` (Go) /
`parse_stats_report` (Python); numeric values are emitted as JSON
numbers, the rest as strings. The example below is the exact document
for the fixture report pinned by the unit tests (`statsReportFixture`
in `report_test.go`, `STATS_REPORT` in `test_cli_parsing.py`) — a
module with all 7 hooks installed and one hidden file/pid/port each:

```json
{
  "schema": 1,
  "module": "vault_kernel",
  "version": "3.8",
  "hooks_installed": 7,
  "hooks_planned": 7,
  "module_hidden": 0,
  "hidden_files": 1,
  "hidden_pids": 1,
  "hidden_ports": 1,
  "keylog_bytes": 0,
  "uptime_s": 42
}
```

| Field | Type | Notes |
|-------|------|-------|
| `schema` | int | Output contract version (this document) |
| `module` | string | Always `vault_kernel` |
| `version` | string | Module version from `src/core.h` |
| `hooks_installed` / `hooks_planned` | int | Hook counters from `GET_STATS` |
| `module_hidden` | int | `1` once hidden from lsmod/sysfs |
| `hidden_files` / `hidden_pids` / `hidden_ports` | int | Current hide-list sizes |
| `keylog_bytes` | int | Keylogger buffer fill |
| `uptime_s` | int | Seconds since module load |

Any extra `key=value` pair the module adds in the future appears as an
additional field (number if it parses as an integer, string otherwise).

---

## `list --json`

Source: `LIST_HIDDEN` report parsed by `ParseHiddenList` /
`parse_hidden_list`. Sections are always present and always arrays —
empty sections are `[]`, never `null` (pinned by
`TestMarshalHiddenJSON` / `TestListJsonEndToEnd`):

```json
{
  "schema": 1,
  "pids": [1234, 567],
  "files": ["secret.txt", "my dir/with space.txt"],
  "ports": [8080]
}
```

| Field | Type | Notes |
|-------|------|-------|
| `schema` | int | Output contract version |
| `pids` | int[] | Hidden PIDs |
| `files` | string[] | Hidden file/dir names, verbatim (may contain spaces) |
| `ports` | int[] | Hidden TCP/UDP ports, host byte order |

---

## `doctor --json`

Exit code: `0` when the module answers (warnings do not fail), `1` when
the module is unreachable — the document is printed in BOTH cases, so
failure paths are machine-readable too. Presence rules (pinned by
`TestDoctorJSONEnvelopeParity` and the Python e2e tests since v3.6):
pointer-backed fields appear **only when the check actually ran** —
when a check runs and fails the field is present as `false`, and it is
absent only when the run stopped before reaching it.

```json
{
  "schema": 1,
  "client_version": "3.8",
  "device_present": true,
  "device_open": true,
  "stats_responds": true,
  "module_version": "3.8",
  "version_match": true,
  "uptime_s": 42,
  "hooks_installed": 7,
  "hooks_planned": 7,
  "module_in_sysfs": false,
  "keylog_responds": true,
  "list_responds": true,
  "warnings": 0
}
```

| Field | Type | Presence | Notes |
|-------|------|----------|-------|
| `schema` | int | always | Output contract version |
| `client_version` | string | always | Version of the CLI producing the document |
| `device_present` | bool | always | `/dev/vault_kernel` exists |
| `device_open` | bool | if open was attempted | Absent when the device is missing |
| `stats_responds` | bool | if GET_STATS attempted | Absent when the open failed |
| `module_version` | string | if stats answered | Module-reported version |
| `version_match` | bool | if module reported one | `client_version == module_version` |
| `uptime_s` | int | if stats answered and numeric | |
| `hooks_installed` / `hooks_planned` | int | if stats answered | |
| `module_in_sysfs` | bool | if stats answered | `false` = module hidden from lsmod/sysfs |
| `keylog_responds` | bool | if KEYLOG_READ attempted | Warning (never fatal) when false |
| `list_responds` | bool | if LIST_HIDDEN attempted | Warning (never fatal) when false |
| `warnings` | int | always | Count of non-fatal warnings |

Example failure document (device absent — the same shape both clients
produce, `test_doctor_json_device_missing_fails`):

```json
{
  "schema": 1,
  "client_version": "3.8",
  "device_present": false,
  "warnings": 0
}
```

---

## Compatibility notes

- The `schema` field is additive (v3.7): consumers written against the
  pre-schema documents keep working; new consumers should assert it.
- `stats --json` key order is not contractual (Go marshals a map);
  `list --json` and `doctor --json` key order matches the tables above.
- The text (non-JSON) output of these commands is NOT covered by this
  contract — it is for humans; parse the JSON variants in scripts.
