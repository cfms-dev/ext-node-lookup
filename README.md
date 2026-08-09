# CFMS Node Lookup Extension

`node_lookup` adds one authenticated CFMS action that resolves a human-readable
absolute node path to its database ID chain. A result is returned only when the
caller can read every node in the path, including the root and all ancestors.

The initial release targets CFMS server `0.4.1.260801_alpha`, protocol 21.

## Installation

Clone or copy this repository into the server extension catalog so that its
manifest is located at:

```text
cfms_on_websocket/src/include/extensions/node_lookup/manifest.toml
```

Enable it in `config.toml` and restart the server:

```toml
[extensions]
enabled = ["node_lookup"]
```

The server advertises the `node_lookup` extension flag while the extension is
enabled. The action is not added to the lockdown whitelist.

## Protocol

Send an authenticated request with a replay-protection nonce and timestamp:

```json
{
  "action": "node_lookup",
  "username": "alice",
  "token": "<token>",
  "nonce": "<at-least-16-characters>",
  "timestamp": 1786200000,
  "data": {
    "path": "/projects/cfms_on_websocket"
  }
}
```

A successful lookup includes the root ID:

```json
{
  "code": 200,
  "data": {
    "node_ids": ["/", "projects-id", "repository-id"]
  },
  "message": "Node path resolved successfully"
}
```

The root path `/` resolves to `{"node_ids": ["/"]}`. Intermediate nodes must
be directories. The terminal node may be a directory or a document with an
active revision.

## Path encoding

Paths are absolute UTF-8 strings. A slash separates encoded path segments;
percent escapes are decoded exactly once after splitting the path:

- a slash inside a node name is written as `%2F`;
- a percent sign inside a node name is written as `%25`;
- unescaped Unicode and spaces are accepted;
- relative paths, empty segments, trailing slashes, `.` and `..` segments,
  NUL, malformed escapes, and invalid UTF-8 are rejected;
- paths are limited to 4096 encoded characters, 128 segments, and 255 decoded
  characters per segment.

For example, `/teams%2Fsecurity/100%25` addresses the two node names
`teams/security` and `100%`. A literal node name `%2F` is written as `%252F`.

## Security behavior

Authentication alone permits invoking the action; no `search` permission is
required. Existing read rules, inheritance, direct and group object access
entries, and user blocks are evaluated for every node. A direct grant on the
terminal node never makes hidden ancestors visible, and
`super_list_directory` is not treated as an implicit bypass.

Missing, deleted, inaccessible, structurally invalid, and unpublished document
paths all produce the same response, without a visible prefix:

```json
{
  "code": 404,
  "data": {},
  "message": "Node path not found"
}
```

Successful audit entries target only the terminal ID. Failure entries do not
include the submitted path or partial IDs. The handler uses the server's normal
request rate control with a default cost of 3 and does not cache authorization
results.

## Testing

Use the server's uv environment. Tests create only temporary SQLite databases
and never use the server's `app.db`:

```powershell
$env:CFMS_SERVER_ROOT = "D:\projects\cfms_on_websocket"
uv run --project $env:CFMS_SERVER_ROOT pytest tests -v
```
