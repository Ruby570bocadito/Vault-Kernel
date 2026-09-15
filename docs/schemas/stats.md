# `stats --json`

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
  "version": "3.11",
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

**Key order is NOT contractual** — Go marshals the envelope from a map
(sorted by the encoder) while Python sorts explicitly; consumers must
never depend on it. Consumers wanting a stable key order plus a
timestamp should use [capture.md](capture.md) instead.
