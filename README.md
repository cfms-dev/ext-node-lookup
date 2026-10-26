# CFMS Node Lookup Extension

`node_lookup` adds one authenticated CFMS action that resolves a human-readable
absolute node path to its database ID chain. A result is returned only when the
caller can read every node in the path, including the root and all ancestors.

Version `0.4.0` targets CFMS server `0.13.0`, protocol 29, and Python 3.15 or
newer. Its version 2 manifest declares a minimum server version of `0.13.0`.
The action is `node_lookup.node.resolve`; the legacy `node_lookup` action is
not registered.

## Installation

Download either `node_lookup-X.Y.Z.tar.gz` or `node_lookup-X.Y.Z.zip` from the
corresponding [GitHub Release](https://github.com/cfms-dev/ext_node_lookup/releases).
You may verify the downloaded archive with the accompanying `SHA256SUMS.txt`:

```bash
sha256sum --check --ignore-missing SHA256SUMS.txt
```

Install the ZIP with the server's maintenance command, run from the server tree:

```bash
maintain extension install /absolute/path/node_lookup-X.Y.Z.zip --sha256 <digest>
maintain extension enable node_lookup
```

Use `maintain extension upgrade` instead of `install` for an existing installation.
Restart the server after enabling or upgrading the extension. The ZIP contains
`manifest.toml` and `_extension.py` directly at its root.

Alternatively, extract the tar.gz archive, which includes a `node_lookup/`
directory, directly into the server extension catalog. For example, on Linux:

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
  "action": "node_lookup.node.resolve",
  "token": "<token>",
  "nonce": "<at-least-16-characters>",
  "timestamp": 1786200000,
  "data": {
    "path": "/projects/cfms_on_websocket"
  }
}
```

Use a current timestamp and a fresh nonce for each request. The server derives the
user UUID from the verified token; no envelope username is needed. The token must
include the `GENERAL` purpose. Missing or invalid tokens return `401`; valid
tokens without the required purpose return `403`.

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
entries, and user blocks are evaluated for every node. User and group grants
remain in separate principal namespaces, and group grants apply only through a
currently active membership. A direct grant on the terminal node never makes
hidden ancestors visible, and
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

Audit entries identify the caller by UUID (`user_id`). Successful entries target
only the terminal ID. Failure entries do not include the submitted path or
partial IDs. The handler uses the server's normal
request rate control with a default cost of 3 and does not cache authorization
results.

## Performance

For non-root paths, the resolver uses one recursive database query for the
complete path. Each recursive step joins through the server's existing active
`parent_id + active_name` index, so sibling count does not require a linear scan.
Access rules, object grants, and user blocks are then loaded in batches and evaluated
once over the returned chain.

Database round trips therefore remain constant as path depth grows; only the
number of rows and in-process authorization checks grows linearly. The test
suite enforces a fixed query budget at the maximum supported depth and verifies
the SQLite index plan as well as SQLite, PostgreSQL, and MySQL query compilation.
Results are intentionally not cached, because doing so could expose stale authorization or
rename/move state.

## Testing

Use the server's uv environment. Tests create only temporary SQLite databases
and never use the server's `app.db`:

```powershell
$env:CFMS_SERVER_ROOT = "D:\projects\cfms_on_websocket"
uv run --no-sync --project $env:CFMS_SERVER_ROOT pytest tests -v
```

CI and release validation use CFMS commit ref
`v0.13.0` (0.13.0). Install that checkout's
development dependencies with `uv sync --project <server-root> --dev --all-extras`
before running tests locally.
