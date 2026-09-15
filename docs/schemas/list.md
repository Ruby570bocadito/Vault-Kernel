# `list --json`

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

Key order matches the table above in both clients (the embedded-struct
envelope keeps it stable).
