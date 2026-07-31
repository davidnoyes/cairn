---
name: cairn-artifact
description: Build and publish web artifacts (single-page apps with optional shared SQLite data) to a Cairn server using the cairn CLI. Use when asked to create, publish, update, or share an artifact, dashboard, tool, or mini-app on Cairn, or to read/write an artifact's shared database.
---

# Publishing artifacts to Cairn

An artifact is a directory with an `index.html` (plus any relative assets),
hosted at a stable URL by a Cairn server. Each published *version* owns a
shared SQLite database and a file storage that all viewers of that version
read and write through `cairn.js`. Read `cairnjs-reference.md` in this skill
directory before writing code that uses the shared database, file storage or
user APIs.

## Prerequisites

Check once per session:

```sh
cairn whoami --json
```

- If the binary is missing, build it from this repo: `go build ./cmd/cairn`.
- If not authenticated, either environment variables are set
  (`CAIRN_HOST` + `CAIRN_API_KEY`) or a stored login exists
  (`cairn login --host <url> --email <email> --password <password>`).
  Ask the user for a host and credentials if neither works — do not guess.

## Workflow

### 1. Build the artifact directory

Create a self-contained directory (e.g. `./artifact/`):

- `index.html` at the root — required.
- Relative asset paths only (`./app.js`, `fetch('data.json')`). Never absolute
  paths like `/app.js`: the artifact is served under
  `/artifacts/{id}/{versionId}/`.
- For client-side routing use hash routing, or extension-less paths (they fall
  back to `index.html`).
- To use the shared database or user info, include
  `<script src="./cairn.js"></script>` — the server injects this file into
  every version's URL space; do not create it yourself.
- Create the schema with the run-once migration helper, never with plain
  `CREATE TABLE` at startup (concurrent viewers would race):

```js
await cairn.ready();
await cairn.db.migrate('001-init', [
  {sql: 'CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT NOT NULL)'}
]);
```

### 2. Test locally before publishing

Opening the directory without a Cairn server runs `cairn.js` in debug mode:
an in-browser SQLite persisted in browser storage, user `{id: 0, name:
"Debug"}`. Serve it with any static server (`python3 -m http.server -d
./artifact`) and check the browser console for errors, or at minimum verify
the directory has `index.html` at its root.

### 3. Publish

First publication — create the artifact and attach the current session id as
a resource so it can be found again later:

```sh
cairn push ./artifact --artifact "<artifact-name>" --create \
  --name v1 --changelog "<what this version is>" --json
cairn artifact create --name x --resource claude-session=<session-id>  # only if creating without push
```

To attach the session to an artifact created via `push --create`:

```sh
curl -sf -X POST "$CAIRN_HOST/api/artifacts/<artifactId>/resources" \
  -H "Authorization: Bearer $CAIRN_API_KEY" -H 'Content-Type: application/json' \
  -d '{"type":"claude-session","value":"<session-id>"}'
```

The `--json` output contains the artifact id, version id and the URL. Always
report the URLs to the user:

- full screen: `<host>/artifacts/<artifactId>/`
- shared view (metadata + version picker): `<host>/shared/<artifactId>`

Public vs private: add `--public` to `push --create` (or
`cairn artifact update <id> --public true|false`) — public means anyone with
the link can view and read data; private requires sign-in. Ask the user if
unclear.

### 4. Iterate vs release

- **Iterating on work in progress** — overwrite the current version; its
  shared database is preserved:

  ```sh
  cairn push ./artifact --artifact <id> --overwrite latest
  ```

- **Publishing a new release** — new version, fresh empty database, old
  version stays reachable:

  ```sh
  cairn push ./artifact --artifact <id> --name v2 --changelog "<changes>"
  ```

  If the new version needs the old data, migrate it client-side: read from the
  previous version with `cairn.db.query(sql, params, {version: '<oldVid>'})`
  (read-only) inside a `cairn.db.migrate()` step.

### 5. Inspect data when needed

```sh
cairn db query --artifact <id> --json "SELECT * FROM items LIMIT 10"
cairn db query --artifact <id> --params '["x"]' "INSERT INTO items (body) VALUES (?)"
```

(For `db query`, flags must come before the SQL string — it is the final
positional argument.)

File storage (uploads/downloads target the latest version unless `--version`):

```sh
cairn files list --artifact <id> --json
cairn files put ./local.png --artifact <id> --path images/local.png
cairn files get images/local.png --artifact <id> --out ./local.png
cairn files delete images/local.png --artifact <id>
```

## Addressing artifacts

Anywhere an artifact id is expected (`--artifact`, API paths, page URLs), you
may also pass an exact artifact name or a **resource value such as a Claude
session id**. A reference matching several artifacts fails with a 409 — fall
back to the artifact id. So to find "the artifact from this session":
`cairn artifact show <session-id> --json`.

## Rules

- Never hand-build upload zips or POST multipart yourself; use `cairn push`.
- One SQL statement per `query` call; use `batch`/`migrate` for scripts.
- Store binary or large data (images, exports, attachments) in the file
  storage (`cairn.files`, `cairn files`), never as base64 blobs in the shared
  database; keep the database for structured rows that reference file paths.
- Do not store secrets in artifact files or the shared database: everything is
  readable by all users of the server (and by anyone, if public).
- On errors the CLI exits non-zero with a message on stderr; `--json` output
  goes to stdout.
