---
name: cairn-artifact
description: Build and publish web artifacts (single-page apps with optional shared SQLite data) to a Cairn server using the cairn CLI. Use when asked to create, publish, update, or share an artifact, dashboard, tool, or mini-app on Cairn, or to read/write an artifact's shared database.
---

# Publishing artifacts to Cairn

An artifact is a directory with an `index.html` (plus any relative assets),
hosted at a stable URL by a Cairn server. Each published *version* owns a
shared SQLite database and a file storage that its members read and write
through `cairn.js`. The server stores only ciphertext: `cairn` and the browser
encrypt and decrypt. Read the cairn.js reference in this skill directory
before writing code that uses the shared database, file storage or user APIs.

## Prerequisites

Check once per session:

```sh
cairn whoami --json
```

- If the binary is missing, build it from this repo: `go build ./cmd/cairn`.
- If not authenticated, either environment variables are set (`CAIRN_HOST` +
  `CAIRN_API_KEY`, the full key from `cairn login` or API keys on the app's
  Account tab) or a stored login exists (`cairn login --host <url> --email
  <email> --password-stdin`, with the password on stdin).
- A new account needs `cairn signup --host <url> --email <email> --name
  <name> --password-stdin`. It prints a recovery code. Show it to the user
  and tell them to save it. Never store it yourself.
- Ask the user for a host and credentials if none of these work. Do not guess.

## Workflow

### 1. Build the artifact directory

Create a self-contained directory (for example `./artifact/`):

- `index.html` at the root is required.
- Use relative asset paths only (`./app.js`, `fetch('data.json')`). Never use
  absolute paths like `/app.js`: the artifact is served under
  `<artifactId>.<content-domain>/<versionId>/`.
- For client-side routing, use hash routing or extension-less paths (they fall
  back to `index.html`).
- To use the shared database or user info, include
  `<script src="./cairn.js"></script>`. The server provides this file in every
  version's URL space. Do not create it yourself.
- Markdown `mermaid` code fences rendered to HTML (by pandoc, marked,
  markdown-it, and so on) render automatically in the shared shell view,
  themed dark or light to match their background. Add
  `<script src="./mermaid.js"></script>` (also server-provided) for the same
  in the full-screen view.
- Create the schema with the run-once migration helper, never with plain
  `CREATE TABLE` at startup (concurrent viewers would race):

```js
await cairn.ready();
await cairn.db.migrate('001-init', [
  {sql: 'CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT NOT NULL)'}
]);
```

### 2. Test locally before publishing

Opening the directory without a Cairn server runs `cairn.js` in debug mode: an
in-browser SQLite persisted in browser storage, user `{id: 0, name: "Debug"}`.
Serve it with any static server (`python3 -m http.server -d ./artifact`) and
check the browser console for errors. At minimum, verify the directory has
`index.html` at its root. Sharing and public links do not exist in debug mode.

### 3. Publish

To find the artifact again later, create it first. Then attach the session id
as a resource, and push:

```sh
cairn artifact create "<artifact-name>" --description "<what it is>" \
  --resource claude-session=<session-id> --json
cairn push ./artifact --artifact <artifactId> \
  --name v1 --changelog "<what this version is>" --json
```

Without a session to attach, `cairn push ./artifact --artifact "<name>"
--create ...` creates the artifact and pushes in one step. `--resource` works
only on `artifact create`: `cairn` blinds the value on your machine, so a raw
`POST /api/artifacts/<id>/resources` with plain text is refused.

Every new artifact is private. The `push --json` output has the artifact id,
the version id and a `url`, which is the full-screen address on the app host.
Report these to the user, built from the host:

- shared view (verifying shell, metadata, version picker): `cairn open <id>`
  prints `<host>/shared/<artifactId>`
- full screen: `cairn open <id> --full`

Do not report the `<artifactId>.<content-domain>` address. It works only
inside the shell.

### 4. Iterate vs release

- **Iterating on work in progress.** Overwrite the current version. Its shared
  database is preserved:

  ```sh
  cairn push ./artifact --artifact <id> --overwrite latest
  ```

- **Publishing a new release.** This creates a new version with a fresh empty
  database. The old version stays reachable:

  ```sh
  cairn push ./artifact --artifact <id> --name v2 --changelog "<changes>"
  ```

  If the new version needs the old data, migrate it client-side. Read from the
  previous version with `cairn.db.query(sql, params, {version: '<oldVid>'})`
  (read-only) inside a `cairn.db.migrate()` step.

### 5. Share

Only the owner shares. Ask the user for the person's email first.

```sh
cairn share <id> bob@example.com --role viewer   # or editor
cairn members <id>                               # roles, fingerprints, pins
cairn unshare <id> bob@example.com
cairn team <id> none|viewer|editor               # the whole team
cairn approve <id> [carol@example.com]           # list, or approve one
cairn public <id> on|off [--writes on|off]       # prints the public link
```

`share` prints the person's fingerprint. Do not mark it verified yourself. Tell
the user to compare it with that person over another channel (in person, a
call), then run `cairn pin bob@example.com --verified`. If a key changed
after pinning, `share` and `pin` refuse and print both fingerprints. Pass
`--accept-new-key` only after the user confirms the new one.

An anonymous visitor gets 404 unless they hold the public link. The key is in
the link's fragment (after `#`), so give the whole link to the user unchanged.
`unshare` and `public <id> off` start a new epoch. If one stops partway, run
`cairn reseal <id>`. For `review`, `vouch`, `transfer`, `successor`, and
`rotate-keys`, run `cairn <command> -h`. The README covers them under
**Sharing** and **Successors and key rotation**.

### 6. Inspect data when needed

`db` commands run on `cairn`'s own decrypted copy of the database. The server
cannot run SQL.

```sh
cairn db query --artifact <id> --json "SELECT * FROM items LIMIT 10"
cairn db query --artifact <id> --params '["x"]' "INSERT INTO items (body) VALUES (?)"
cairn db batch --artifact <id> --file statements.json   # [{"sql","params"}]
cairn db revisions --artifact <id> --json               # the 10 the server keeps
cairn db restore --artifact <id> --revision 7
cairn db download --artifact <id> --out items.db
```

For `db query`, flags must come before the SQL string, which is the final
positional argument. Files are encrypted too. Uploads and downloads target the
latest version unless `--version` is set:

```sh
cairn files list --artifact <id> --json
cairn files put ./local.png --artifact <id> --path images/local.png
cairn files get images/local.png --artifact <id> --out ./local.png
cairn files delete images/local.png --artifact <id>
```

### 7. Restore or migrate

To move artifacts from a server that predates encryption, take a
`cairn backup` snapshot there, sign in on the new server, and run
`cairn import BACKUP-DIR [--json]`. Public artifacts arrive private.

## Addressing artifacts

`--artifact` and `cairn open` take an artifact id, the exact name of one of
your artifacts, or a resource value such as a Claude session id. `cairn`
resolves names and resource values on your machine, so they work only for
artifacts you can open. Page URLs and raw API paths need the artifact id. A
name or value that matches several artifacts fails and lists the ids: use an
id. To find the artifact from this session: `cairn artifact show <session-id>
--json`.

## Rules

- Never hand-build upload zips or POST multipart yourself. Use `cairn push`.
- One SQL statement per `query` call. Use `batch` or `migrate` for scripts.
- Store binary or large data (images, exports, attachments) in the file
  storage (`cairn.files`, `cairn files`), never as base64 blobs in the shared
  database. A database revision over the server limit (50 MiB by default) is
  refused.
- Do not store secrets in artifact files or the shared database. The server
  cannot read them, but every member (and every holder of a public link) can.
- On errors `cairn` exits non-zero with a message on stderr. `--json` output
  goes to stdout.
