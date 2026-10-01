# Cairn

Cairn is a self-hosted server for uploading, managing and hosting collections
of **artifacts** — single-page web apps with optional shared SQLite data — an
open alternative to Claude Artifacts for small trusted teams and AI-agent
workflows.

One Go binary contains the server, an admin UI, and a client CLI designed to
be driven by AI agents.

```
┌───────────────┐   cairn push    ┌──────────────────────────────┐
│  agent / dev  │ ──────────────▶ │  cairn serve                 │
└───────────────┘                 │  ├─ /artifacts/{id}/{vid}/   │  full screen
        ▲                         │  ├─ /shared/{id}             │  framed + metadata
        │ cairn db query          │  ├─ /admin                   │  admin UI
        └──────────────────────── │  └─ /api/...                 │  JSON APIs
                                  └──────────────────────────────┘
                                     data/ (SQLite + files)
```

## Concepts

- **Artifact** — uuid, name, description, public/private flag, associated
  *resources* (e.g. a Claude session id), and a sequence of versions.
- **Version** — uuid, name, changelog, and a directory with at least an
  `index.html`. Each version also owns a lazily-created SQLite database shared
  by everyone who uses that version, accessed through a raw-SQL HTTP API, and
  a **file storage** where clients upload and download arbitrary files.
  Versions can be re-uploaded in place (work-in-progress iteration) — the
  shared database and file storage survive re-uploads.
- **Users** — created by admins; no email verification, no self-signup. A new
  account has no password: **the user chooses one at first sign-in**.
- **API keys** — created by admins, tied to a user, revocable. For CLIs and
  agents.

### Trust model (read this)

Cairn trusts its users, deliberately: every authenticated user can manage
artifacts and run **raw SQL** against artifact databases, and artifacts are
served same-origin with the APIs. This keeps everything simple and is fine for
a small circle of invited people. Do **not** point untrusted crowds at a Cairn
instance. Guardrails exist (per-query timeout, row caps, read-only access for
anonymous visitors of public artifacts) but they are guardrails, not a sandbox.

## Quick start

```sh
go build ./cmd/cairn

# First run creates the admin account — no password on the command line:
# you choose it in the browser at first sign-in
./cairn serve --data-dir data --admin-email you@example.com

open http://localhost:8787/admin
```

Create users and API keys in the admin UI (or via `/api/admin/...`). Accounts
— the bootstrap admin included — sign in at `/login` and choose their password
on the spot. (Automation can still pre-set the admin password with
`--admin-password` / `CAIRN_ADMIN_PASSWORD`.)

### Push your first artifact

```sh
./cairn login --host http://localhost:8787 --email you@example.com
./cairn push examples/guestbook --artifact guestbook --create \
    --name v1 --changelog "first version"
./cairn open guestbook            # prints the URL
```

### Docker

```sh
docker run -p 8787:8787 -v cairn-data:/data \
  -e CAIRN_ADMIN_EMAIL=you@example.com \
  ghcr.io/aloisdeniel/cairn:latest
```

Or `docker compose up -d` with the repo's [`docker-compose.yml`](docker-compose.yml)
(hosted Docker managers can point straight at the GitHub repo). To build the
image yourself instead: `docker build -t cairn .`

## URLs

| URL | Meaning |
|---|---|
| `/artifacts/{id}` | redirects to the latest version |
| `/artifacts/{id}/{versionId}/` | a version, full screen (canonical) |
| `/shared/{id}` / `/shared/{id}/{versionId}` | version embedded in a shell frame with metadata and a version picker |
| `/admin` | admin UI |
| `/login`, `/logout` | session pages |

Private artifacts redirect anonymous visitors to `/login?next=…`. Because a
version is always served under its own directory URL, relative paths inside
the SPA (`./app.js`, `fetch('data.json')`) just work; extension-less paths
fall back to `index.html` for client-side routing, missing assets 404.

## Writing an artifact

A version is a directory with an `index.html`. Include the client library with
a relative script tag — the server injects it into every version's URL space:

```html
<script src="./cairn.js"></script>
<script>
  await cairn.ready();
  const me = await cairn.me();               // null when anonymous
  await cairn.db.migrate('001-schema', [     // run-once, concurrency-safe
    {sql: 'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)'}
  ]);
  await cairn.db.query('INSERT INTO notes (body) VALUES (?)', ['hi']);
  const res = await cairn.db.query('SELECT * FROM notes');  // {columns, rows}
  const dir = await cairn.users();           // global user directory
</script>
```

`cairn.db.query(sql, params, {version: otherVersionId})` reads another
version's database (read-only) — use it to migrate data forward after
publishing a new version. `cairn.db.batch([...])` runs statements in one
transaction.

Each version also has a **file storage** for binary data that does not belong
in SQLite (images, exports, attachments):

```js
await cairn.files.upload('photos/cat.png', blob);   // Blob/File/string; auth required
await cairn.files.list();                           // [{path, size, modifiedAt}]
const blob = await cairn.files.download('photos/cat.png');  // null when absent
img.src = cairn.files.url('photos/cat.png');        // direct URL (remote mode)
await cairn.files.remove('photos/cat.png');
```

Like the database, file storage is per-version, survives re-uploads, and is
readable anonymously on public artifacts while writes require authentication.
`list`/`download`/`url` accept `{version: otherVersionId}` for read-only
access to a sibling version's files.

**Local debug mode.** Open the same directory without a Cairn server (any
static file server, or `file://`) and `cairn.js` switches to an in-browser
SQLite (sql.js/WebAssembly) persisted in browser storage; `cairn.me()` returns
`{id: 0, name: "Debug"}`. First load fetches sql.js from a CDN and caches it
for offline use; fully offline setups can drop `sql-wasm.js`/`sql-wasm.wasm`
next to `index.html`. See `examples/guestbook`.

**Mermaid diagrams.** A `mermaid` code fence rendered to HTML by pandoc
(`<pre class="mermaid"><code>...</code></pre>`) or a Markdown renderer using a
`language-mermaid` code class renders as a diagram automatically — no script
tag needed in the shell view (`/shared/{id}`), which injects `/mermaid.js` for
you; full-screen artifacts (`/artifacts/{id}/{vid}/`) that want the same
outside the shell can add `<script src="./mermaid.js"></script>` themselves.
Mermaid is vendored into the binary, so this works fully offline. Each
diagram picks Mermaid's dark or light theme from the background it sits on —
its own, else the nearest ancestor's, else the page's `color-scheme` and the
viewer's OS setting. A gradient counts as the average of its colors; a
background image is not read. To force a theme, start the diagram with
`%%{init: {'theme': 'forest'}}%%`. Diagrams must be in the page when it
finishes loading: an app that adds one later (after fetching its content, for
example) should include `./mermaid.js` itself and call `mermaid.run()` once
the diagram is in place.

More examples in [`examples/`](examples/): [`poll`](examples/poll/) — a
multi-file artifact (CSS, JS, SVG assets, a fetched `config.json`) —
[`drive`](examples/drive/) — a shared file drive built entirely on the
per-version file storage (uploads, folders, thumbnails, downloads) — and
[`todo-react`](examples/todo-react/) — TypeScript + React bundled with esbuild,
where a typed `TodoStore` hides every cairn.js detail from the UI.

## HTTP API

Authentication: `Authorization: Bearer <jwt>` (from `POST /api/auth/login`) or
`Bearer <api-key>`, or the session cookie set at login. Reads of public
artifacts need no auth; **writes always need auth**.

The `{id}` segment of artifact routes (APIs and page URLs alike) accepts
either the artifact id or a **resource reference** — a resource value such as
a Claude session id, or a resource row id. If the reference matches more than
one artifact the request fails with `409 Conflict`; use the artifact id then.

```
POST   /api/auth/login                      {email, password[, confirm]}
GET    /api/me
GET|PUT /api/me/keyring                    your sealed keyring: {rev, keyring}; PUT needs rev+1, else 409 {error, rev}
GET    /api/users                           directory: id, name, email (any authed user)
GET    /api/artifacts                       ?name= ?limit= ?offset=
POST   /api/artifacts                       {id, name, description, membership, wraps, estate}
GET|PATCH|DELETE /api/artifacts/{id}
POST   /api/artifacts/{id}/resources        {type, value}
DELETE /api/artifacts/{id}/resources/{rid}
GET    /api/artifacts/{id}/versions
POST   /api/artifacts/{id}/versions         multipart zip: archive, name, changelog
GET|PATCH|DELETE /api/artifacts/{id}/versions/{vid}
PUT    /api/artifacts/{id}/versions/{vid}   re-upload (data survives)
POST   /api/artifacts/{id}/versions/{vid}/db/query   {sql, params}
POST   /api/artifacts/{id}/versions/{vid}/db/batch   {statements: [{sql, params}]}
GET    /api/artifacts/{id}/versions/{vid}/db/download
GET    /api/artifacts/{id}/versions/{vid}/files      list: [{path, size, modifiedAt}]
GET    /api/artifacts/{id}/versions/{vid}/files/{path}   download (ranges supported)
PUT    /api/artifacts/{id}/versions/{vid}/files/{path}   raw body upload (overwrites)
DELETE /api/artifacts/{id}/versions/{vid}/files/{path}
GET    /api/admin/users|keys ...            admin management
```

Notes on the SQL proxy: one statement per `query` call (use `batch` for
scripts/transactions); write access is enforced at the connection level
(anonymous requests run on a `query_only` pool), never by parsing SQL; BLOBs
are returned base64-encoded; results are capped (`--max-query-rows`).

## CLI for agents

Set two environment variables and every command works headlessly:

```sh
export CAIRN_HOST=https://cairn.example.com
export CAIRN_API_KEY=cairn_xxxxxxxx_yyyyyyyy    # from the admin UI

cairn whoami --json
cairn artifact list --json
cairn push ./dist --artifact my-app --create --json   # prints the URLs
cairn push ./dist --artifact my-app --overwrite latest
cairn db query --artifact my-app --json "SELECT COUNT(*) FROM notes"
cairn files put ./report.pdf --artifact my-app --path exports/report.pdf
cairn files list --artifact my-app --json
cairn files get exports/report.pdf --artifact my-app --out ./report.pdf
```

All commands accept `--json`; errors exit non-zero with a message on stderr.
Associate an agent session with `cairn artifact create --resource
claude-session=<id>` or `POST /api/artifacts/{id}/resources` — afterwards the
session id works anywhere an artifact id or name does:

```sh
cairn push ./dist --artifact <claude-session-id> --overwrite latest
cairn db query --artifact <claude-session-id> "SELECT ..."
```

### Sharing

Only the owner shares, and only within the artifact's current epoch: adding
a member and promoting a viewer to editor work now; removing or demoting a
member needs a new epoch, which a later release adds.

```sh
cairn share my-app bob@example.com                 # add as viewer
cairn share my-app bob@example.com --role editor   # or promote
cairn members my-app                               # roles, fingerprints, pin states
cairn team my-app viewer                           # share with the whole team
cairn approve my-app                               # team members waiting
cairn approve my-app carol@example.com             # approve one, by name
cairn pin bob@example.com --verified               # after comparing fingerprints
cairn public my-app on                             # print a public link
cairn public my-app on --writes on                 # let signed-in link holders write
```

`cairn share` prints the user's fingerprint and pins it, unverified, the
first time it sees them. Compare the fingerprint with them over another
channel, then run `cairn pin --verified`. If their keys change after they
were pinned, for example after an account reset without the recovery code,
`share` and `pin` refuse. They print both fingerprints and the reset time;
pass `--accept-new-key` once you have confirmed the new one. `share` also
refuses anyone the owner excluded from the artifact, and refuses outright
when the directory lists two accounts with the same email or fingerprint.

`cairn team` shares an artifact with the whole team as `viewer` or `editor`,
or stops with `none`. A new member gets nothing until the owner or an editor
approves them by name. `cairn approve ARTIFACT` lists who is waiting, with
their fingerprints. Compare a fingerprint with the person first. Running
`cairn approve ARTIFACT USER` is itself your confirmation. An approved member
can read right away. The owner's next `cairn team` or `cairn share` lists them
with the team's role, and an editor team's members can write only from then
on. The owner's client lists an approved member only when the signed approval
checks out, and otherwise prints their name and fingerprint. `approve` refuses
anyone the owner excluded. It refuses a user whose pinned key changed unless
you pass `--accept-new-key`. If a user's key changed after you approved or
listed them, the owner runs `cairn share` again. Setting `none` while an
approved member holds a key needs a new epoch, which a later release adds.

`cairn public ARTIFACT on` makes the artifact readable by anyone who holds
its link, and prints the link. The key is in the part after the `#`, which a
browser never sends to the server, so share the link only with people who
should read the artifact. A visitor's client checks the artifact's
membership against the link before it trusts it. Public writes are off at
first. Run `cairn public ARTIFACT on --writes on` to let a signed-in link
holder write to the database and files. Turning a public link off needs a
new epoch, which a later release adds.

Pins and the latest verified membership record of each artifact live in
your keyring, sealed on the server. Each machine keeps a small anchor for
it in its `cairn` config file, so a server that serves an older keyring, or a
shorter membership chain, gets refused. `cairn logout` keeps the anchor.

A refusal means the server is serving an older or altered keyring, for
example after a restore from backup, or that someone tampered with it. The
error prints the config path and the entry to look at. Confirm with your
administrator which it is. If the server was restored, remove the `anchors`
entry for `<host> <user ID> <fingerprint>` from that file. The next command
then trusts the keyring the server serves.

A device with no anchor, such as a new config file or cleared browser
storage, trusts the first keyring it sees. Headless use with `CAIRN_HOST` and
`CAIRN_API_KEY` keeps its anchor in the same config file, so point
`CAIRN_CONFIG` at a persistent, writable file. Otherwise each run starts
with no anchor and gets no rollback protection.

A ready-made **Claude Code skill** ships in
[`.claude/skills/cairn-artifact/`](.claude/skills/cairn-artifact/SKILL.md): it
teaches Claude the whole build → test locally → publish → iterate workflow and
the `cairn.js` API. It is picked up automatically when working inside this
repo; copy the directory into any other project's `.claude/skills/` (or
`~/.claude/skills/` for global use) to let Claude publish artifacts from
there.

## Operations

- **Data layout** — everything lives under `--data-dir`: `cairn.db`
  (metadata), `secret.key` (JWT signing), `content/` (extracted version
  uploads), `dbs/` (per-version shared databases), `files/` (per-version file
  storage).
- **Backup** — `cairn backup --data-dir data --out backup/` snapshots live
  SQLite databases with `VACUUM INTO` and copies the rest. Safe while the
  server runs.
- **Config** — flags > `CAIRN_*` env (`CAIRN_ADDR`, `CAIRN_DATA_DIR`,
  `CAIRN_BASE_URL`, `CAIRN_TOKEN_TTL`, `CAIRN_MAX_UPLOAD_MB`, …). Set
  `--base-url https://…` behind TLS so cookies are marked Secure.
- **Password reset** — an admin resets the account; the user picks a new
  password at next sign-in. Tokens are invalidated instantly on reset/disable.

## Cairn vs. Claude Artifacts

| | Claude Artifacts | Cairn |
|---|---|---|
| Hosting | claude.ai, Anthropic accounts | self-hosted, your domain, your disk |
| Content | single-page, strict CSP | full multi-file SPA dirs, no CSP wall |
| Shared data | capability-gated runtime | first-class SQLite (raw SQL, transactions, cross-version migration, downloadable file) + per-version file storage |
| Versioning | product history | explicit versions + changelogs, stable URLs, re-upload |
| Automation | Claude's Artifact tool | any agent via CLI/API keys — model-agnostic |
| AI runtime | `window.claude` in page | none built in |
| Security | sandboxed for untrusted viewers | trust-based, invited users only |

## Development

```sh
go test ./...        # unit + integration tests
./scripts/e2e.sh     # full end-to-end smoke test against a real server
```
