# `doctor --json`

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
  "client_version": "3.10",
  "device_present": true,
  "device_open": true,
  "stats_responds": true,
  "module_version": "3.10",
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
  "client_version": "3.10",
  "device_present": false,
  "warnings": 0
}
```
