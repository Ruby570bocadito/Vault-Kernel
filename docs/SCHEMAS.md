# Machine-Readable Output Schemas

Contract reference for the JSON output of the two CLIs (Go and Python).
Every document carries a **`schema`** field (ADR 17, v3.7): scripts can
pin `jq -e '.schema == 1'` and detect format changes instead of failing
silently. Both clients emit byte-identical documents for the same
module state — the parity is pinned by unit tests in BOTH clients.

**Versioning policy:** the `schema` integer only increments when a
field changes MEANING or SHAPE. Additive fields keep the value at `1`.
The version of the producing CLIENT is a separate field
(`client_version`) and is NOT part of this contract.

## The four documents

| Document | Command | Contract |
|----------|---------|----------|
| Stats envelope | `stats --json` | [schemas/stats.md](schemas/stats.md) |
| Hidden list | `list --json` | [schemas/list.md](schemas/list.md) |
| Diagnostics | `doctor --json` | [schemas/doctor.md](schemas/doctor.md) |
| Evidence bundle | `capture` / `capture --out FILE` | [schemas/capture.md](schemas/capture.md) |

The `capture` bundle (v3.9) wraps the SAME conversions as `stats
--json` and `list --json` under one timestamped envelope — when you
change one of those contracts, check `capture` too.

## Compatibility notes

- The `schema` field is additive (v3.7): consumers written against the
  pre-schema documents keep working; new consumers should assert it.
- `stats --json` key order is not contractual (Go marshals a map);
  `list --json`, `doctor --json` and `capture` key order matches the
  tables in their per-command pages.
- The text (non-JSON) output of these commands is NOT covered by this
  contract — it is for humans; parse the JSON variants in scripts.

History: this used to be a single page; it was split per command when
`capture` became the fourth document (ronda 6, v3.9 — the trigger the
v3.8 backlog had left conditioned).
