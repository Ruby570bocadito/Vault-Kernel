# `capture` — evidence bundle JSON

One document freezing the module state for a lab report: stats, the
hidden list and the keylog buffer in a single snapshot, so a report
can cite ONE file instead of stitching three command outputs.

Producers: `capture` in both clients (Go `runCapture`/`buildCaptureReport`,
Python `capture()`/`build_capture_bundle`), pinned by
`TestBuildCaptureReport` / `TestBuildCaptureBundle`.

- Without `--out FILE` the document goes to stdout (like `--json`).
- With `--out FILE` the file is written **0600** — bundles may contain
  keystrokes — and a one-line summary goes to stdout instead.
- `captured_at` is the UTC RFC3339 instant of the SNAPSHOT, taken after
  the three buffers were read (it bounds them from above, it is not a
  per-event time; the keylog buffer carries no timestamps by itself).

```json
{
  "schema": 1,
  "captured_at": "2026-09-15T10:30:05Z",
  "client_version": "3.10",
  "module_in_sysfs": false,
  "stats": {
    "hidden_files": 1,
    "hidden_pids": 1,
    "hidden_ports": 1,
    "hooks_installed": 7,
    "hooks_planned": 7,
    "keylog_bytes": 5,
    "module": "vault_kernel",
    "module_hidden": 0,
    "uptime_s": 42,
    "version": "3.10"
  },
  "hidden": {
    "pids": [1234],
    "files": ["secret.txt"],
    "ports": [8080]
  },
  "keylog": "typed text"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `schema` | int | Output contract version (this document) |
| `captured_at` | string | UTC RFC3339 instant of the snapshot |
| `client_version` | string | Version of the CLI producing the bundle |
| `module_in_sysfs` | bool | `false` = module hidden from lsmod/sysfs |
| `stats` | object | The `stats --json` conversion (numbers where numeric, keys sorted) — see [stats.md](stats.md) |
| `hidden` | object | `{pids, files, ports}`, same shape as `list --json` — see [list.md](list.md) |
| `keylog` | string | Raw keylog buffer content, verbatim (`""` when empty) |

Envelope key order is contractual and identical in both clients (the
example above is the exact order both emit). `stats` keys are sorted
alphabetically in BOTH clients — the Go JSON encoder sorts map keys and
the Python mirror sorts explicitly to keep the documents byte-
comparable.
