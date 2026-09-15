# `status` — module presence JSON

The "is it planted?" check as a document (v3.10): the fifth entry of
the machine-readable contract. Built for lab scripts that need to gate
on module presence WITHOUT root — `status` never opens the device, so
the command works for any user while every other JSON command requires
the CAP_SYS_ADMIN open.

Producers: `status --json` in both clients (Go `runStatus`/
`buildStatusReport`, Python `status()`/`build_status_document`), pinned
by `TestBuildStatusReport` / `TestBuildStatusDocument`.

```json
{
  "schema": 1,
  "device_present": true,
  "module_in_sysfs": false,
  "modinfo": {
    "filename": "/lib/modules/6.1.0/vault_kernel.ko",
    "version": "3.12",
    "author": "ruby570bocadito",
    "description": "vault_kernel kernel rootkit"
  }
}
```

| Field | Type | Notes |
|-------|------|-------|
| `schema` | int | Output contract version (this document) |
| `device_present` | bool | `/dev/vault_kernel` exists — the only always-reliable loaded signal |
| `module_in_sysfs` | bool | `/sys/module/vault_kernel` visible; `false` means lsmod-hidden (or not loaded) |
| `modinfo` | object | OPTIONAL — see the best-effort policy below |

Envelope key order is contractual and identical in both clients (the
example above is the exact order both emit); the same holds for the
`modinfo` sub-keys (`filename`, `version`, `author`, `description`).
A modinfo field the system did not report is omitted from the object
(`omitempty` in Go, filtered dict in Python) — never rendered as null
or empty string.

## The `modinfo` best-effort policy

The section appears ONLY when **both** conditions hold:

1. `device_present` is true (the module is loaded — there is no module
   metadata to show otherwise), AND
2. `modinfo vault_kernel` ran successfully and produced at least one
   contract key.

When the section is absent the key is OMITTED from the document, not
null — consumers check `has("modinfo")`, exactly like the doctor
document's optional check fields. Reasons for absence are not
distinguished on purpose: a missing modinfo binary, a module not
installed under `/lib/modules`, or an lsmod-hidden module all mean
"no metadata available" and the JSON stays honest about what it knows.

`modinfo` reads the module FILE from disk, not the kernel module list —
that is why an lsmod-hidden module can still produce a full section
when the `.ko` is installed in `/lib/modules` (and why, in the common
insmod-from-workdir lab flow, the section is legitimately absent).

## Text mode note

The TEXT output of `status` is for humans and NOT covered by the JSON
contract. Since v3.10 both clients print the same fixed-key modinfo
lines (`version`, `author`, `description`) parsed by the exact-key
`parse_modinfo`/`parseModinfo` pair — the previous Python
substring-matching printed `srcversion` too, and the Go client printed
no modinfo at all.
