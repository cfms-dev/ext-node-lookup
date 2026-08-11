# CFMS Node Lookup Extension

`node_lookup` adds one authenticated CFMS action that resolves a human-readable
absolute node path to its database ID chain. A result is returned only when the
caller can read every node in the path, including the root and all ancestors.

Version `0.2.0` targets CFMS server `0.4.1.260811_alpha` or newer, protocol
21. Its version 2 manifest lets the server reject incompatible installations
before importing the extension.

## Installation

Download either `node_lookup-X.Y.Z.tar.gz` or `node_lookup-X.Y.Z.zip` from the
corresponding [GitHub Release](https://github.com/cfms-dev/ext_node_lookup/releases).
You may verify the downloaded archive with the accompanying `SHA256SUMS.txt`:

```bash
sha256sum --check --ignore-missing SHA256SUMS.txt
```

Extract the archive directly into the server extension catalog. For example,
on Linux:

```bash
tar -xzf node_lookup-X.Y.Z.tar.gz \
  -C cfms_on_websocket/src/include/extensions
```

The resulting manifest must be located at:

```text
cfms_on_websocket/src/include/extensions/node_lookup/manifest.toml
```

When installing directly from source, create that `node_lookup` directory, copy
the contents of this repository's `src/` directory into it, and then copy
`manifest.toml` into the same directory. `README.md` and `LICENSE` may also be
copied for reference.

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

## Performance

For non-root paths, the resolver uses one recursive database query for the
complete path. Each recursive step joins through the server's existing active
`parent + name` index, so sibling count does not require a linear scan. Access
rules, object grants, and user blocks are then loaded in batches and evaluated
once over the returned chain.

Database round trips therefore remain constant as path depth grows; only the
number of rows and in-process authorization checks grows linearly. The test
suite enforces a fixed query budget at the maximum supported depth and verifies
the SQLite index plan as well as SQLite and MySQL query compilation. Results are
intentionally not cached, because doing so could expose stale authorization or
rename/move state.

## Testing

Use the server's uv environment. Tests create only temporary SQLite databases
and never use the server's `app.db`:

```powershell
$env:CFMS_SERVER_ROOT = "D:\projects\cfms_on_websocket"
uv run --project $env:CFMS_SERVER_ROOT pytest tests -v
```
