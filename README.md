# Cairn

Cairn is a self-hosted server for uploading, managing and hosting collections
of **artifacts** — single-page web apps with optional shared SQLite data — an
open alternative to Claude Artifacts for small trusted teams and AI-agent
workflows.

One Go binary contains the server, a web app, and a client CLI designed to
be driven by AI agents.

```
┌───────────────┐   cairn push    ┌──────────────────────────────┐
│  agent / dev  │ ──────────────▶ │  cairn serve                 │
└───────────────┘                 │  ├─ /full/{id}/{vid}         │  full screen
        ▲                         │  ├─ /shared/{id}             │  framed + metadata
        │ cairn db query          │  ├─ /app                     │  web app
        └──────────────────────── │  └─ /api/...                 │  JSON APIs
                                  └──────────────────────────────┘
                                     data/ (SQLite + files)
```

## Concepts

- **Artifact** — uuid, name, description, public/private flag, associated
  *resources* (e.g. a Claude session id), and a sequence of versions. The
  server holds the name and description encrypted, and each resource as a
  blind index.
- **Version** — uuid, encrypted name and changelog, and a directory with at
  least an `index.html`. Each version also owns a lazily-created SQLite
  database shared by everyone who uses that version, and a **file storage**
  where clients upload and download arbitrary files. The server stores both
  encrypted: the browser, or the `cairn` command, decrypts them and runs SQL
  on its own copy.
  Versions can be re-uploaded in place (work-in-progress iteration) — the
  shared database and file storage survive re-uploads.
- **Users** — sign up themselves, in the browser or with `cairn signup`, from an
  allowed email domain, and verify their email. The `--admin-email` address
  becomes an administrator when it signs up.
- **API keys** — created by `cairn login` for a device, tied to a user,
  revocable. For CLIs and agents.

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

# log:// writes each email, with its link, to the server log
./cairn serve --data-dir data --admin-email you@example.com \
  --smtp-url log:// --public-url http://localhost:8787

open http://localhost:8787/signup
```

To create the administrator account, sign up with the `--admin-email` address.
The verification link appears in the server log.

### Sign up in the browser

Open `/signup` on your server. You need an email address that the server
allows: a domain set with `--signup-domain`, or the `--admin-email` address.

1. Enter your email, your name, and a password. Choose a long passphrase. The
   page refuses a password that its strength estimator scores below 3 of 4.
2. Save the recovery code the page shows. Cairn shows it once. Without it, a
   password reset gives you new keys, and artifacts that others shared with you
   stay unreadable until they share them again.
3. Open the link in the verification email. It works for 24 hours.
4. Sign in at `/login`.

If you forget your password, open `/forgot`. The emailed link works for 30
minutes. On the reset page, enter your recovery code to keep your keys, or
choose new keys.

Your browser stretches the password and creates your keys on your device, so
the server never sees the password. The page keeps your unwrapped keys in
IndexedDB as non-extractable keys, and clears them when you sign out.

Until Cairn serves artifacts from separate content origins, an artifact you
open runs on the same origin as your keys and can use them. Open only artifacts
you trust.

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
| `/shared/{id}` / `/shared/{id}/{versionId}` | version embedded in a shell frame with metadata and a version picker |
| `/full/{id}` / `/full/{id}/{versionId}` | the same frame full screen, with no header |
| `/artifacts/{id}…` | redirects to the same path under `/shared/`, for old links |
| `/app` | the signed-in home: artifacts, sharing, API keys, account, and users for an administrator; `/admin` redirects here |
| `/login`, `/logout` | session pages |
| `/signup`, `/verify`, `/forgot`, `/reset` | account pages; the emailed links open `/verify` and `/reset` |

The shell pages (`/shared/…` and `/full/…`) carry no artifact data and check
no access: the page's script reads the artifact through the API, which does.
Because a version is always served under its own directory URL, relative paths inside
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

The database runs in the page. `cairn.js` loads sql.js from the server, never
from a CDN, and fetches the latest revision of the version's database. It
runs each query or batch on that copy, in a transaction. When a statement
changes the database, `cairn.js` uploads the whole file as a new encrypted
revision. If another page wrote first, it fetches the newer revision and runs
the statements again, up to five times. So:

- Keep the database small. The server refuses a revision over
  `--max-db-mb` (50 MiB by default), and the change does not land. Put images
  and other large data in file storage.
- One statement per `query` call; use `batch` for scripts.
- BLOB values come back base64-encoded.
- The server keeps the newest 10 revisions of each version's database.

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
stored encrypted, with no file names on the server. Anyone who can open the
artifact can read both. Writing needs the owner or an editor, or a signed-in
holder of the public link while public writes are on.
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
you; full-screen artifacts (`/full/{id}/{vid}`) that want the same
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
either the artifact id or a **resource reference**: a resource's stored blind
index, or its row id. The server never sees a raw value such as a Claude
session id, so only `cairn`, which computes the blind index, accepts one. If
the reference matches more than one artifact, the request fails with
`409 Conflict`; use the artifact id then.

```
POST   /api/auth/login                      {email, password[, confirm]}
GET    /api/me
GET|PUT /api/me/keyring                    your sealed keyring: {rev, keyring}; PUT needs rev+1, else 409 {error, rev}
GET    /api/users                           directory: id, name, email (any authed user)
GET    /api/artifacts                       ?limit= ?offset=
POST   /api/artifacts                       {id, membership, wraps, estate}
GET|DELETE /api/artifacts/{id}
PUT    /api/artifacts/{id}/meta/{name|description}   encrypted field: {record, blob}
POST   /api/artifacts/{id}/resources        {type, value}; value is a 64-hex blind index
DELETE /api/artifacts/{id}/resources/{rid}
GET    /api/artifacts/{id}/versions
POST   /api/artifacts/{id}/versions         multipart: version, manifest, encrypted blobs
GET|DELETE /api/artifacts/{id}/versions/{vid}
PUT    /api/artifacts/{id}/versions/{vid}/meta/{name|changelog}   encrypted field: {record, blob}
PUT    /api/artifacts/{id}/versions/{vid}   re-upload (data survives)
GET|PUT /api/artifacts/{id}/versions/{vid}/db   latest encrypted revision; PUT needs If-Match
GET    /api/artifacts/{id}/versions/{vid}/db/revisions        the 10 kept, newest first
GET    /api/artifacts/{id}/versions/{vid}/db/revisions/{rev}  one kept revision
GET    /api/artifacts/{id}/versions/{vid}/files              encrypted file metadata
GET|PUT|DELETE /api/artifacts/{id}/versions/{vid}/files/{address}   one encrypted file
GET    /api/admin/users|keys ...            admin management
```

The server never runs SQL and cannot read a database or a stored file. Each
database revision and each file is sealed and signed by the client that wrote
it, and readers check the signature before they use it. Use `cairn.js` or
the `cairn` command, which do this for you; the wire formats are in
[`design/e2e-api.md`](design/e2e-api.md#client-side-database-and-files).

## CLI for agents

Set two environment variables and every command works headlessly:

```sh
export CAIRN_HOST=https://cairn.example.com
export CAIRN_API_KEY=cairn_xxxxxxxx_yyyyyyyy    # from the app's API keys tab

cairn whoami --json
cairn artifact list --json
cairn push ./dist --artifact my-app --create --json   # prints the URLs
cairn push ./dist --artifact my-app --overwrite latest
cairn db query --artifact my-app --json "SELECT COUNT(*) FROM notes"
cairn files put ./report.pdf --artifact my-app --path exports/report.pdf
cairn files list --artifact my-app --json
cairn files get exports/report.pdf --artifact my-app --out ./report.pdf
cairn db batch --artifact my-app < statements.json   # [{"sql", "params"}], one transaction
cairn db revisions --artifact my-app --json          # the 10 the server keeps
cairn db restore --artifact my-app --revision 7      # a kept revision becomes the latest
cairn db download --artifact my-app --out notes.db
```

Commands that print a result accept `--json`; errors exit non-zero with a
message on stderr.
Associate an agent session with `cairn artifact create --resource
claude-session=<id>`. Afterwards the session id works in any `cairn` command
that takes an artifact id or name:

```sh
cairn push ./dist --artifact <claude-session-id> --overwrite latest
cairn db query --artifact <claude-session-id> "SELECT ..."
```

### Sharing

Only the owner shares. Adding a member and promoting a viewer to editor stay
within the artifact's current epoch. Removing a member, demoting an editor,
making a public artifact private, and ending a team share while an approved
member holds a key each start a new epoch, with a new key that nobody removed
ever held.

```sh
cairn share my-app bob@example.com                 # add as viewer
cairn share my-app bob@example.com --role editor   # or promote
cairn share my-app bob@example.com --role viewer   # or demote: a new epoch
cairn unshare my-app bob@example.com               # remove: a new epoch
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
pass `--accept-new-key` once you have confirmed the new one. `share` refuses
outright when the directory lists two accounts with the same email or
fingerprint.

`cairn unshare ARTIFACT USER` removes a member and starts a new epoch. Every
user a new epoch removes goes into the artifact's excluded list, with their
fingerprint. The command prints who it excluded and why. Sharing with an
excluded user by name lists them again and drops the entry. A new epoch needs
every member listed under their current key, so it refuses, naming the
member, when a listed member's keys changed: run `cairn share --accept-new-key`
for them, or `cairn unshare` them. A member whose account was deleted blocks
every new epoch the same way. The refusal names their user ID, and
`cairn unshare ARTIFACT USER-ID` removes them. If the artifact is public, the
command also prints the new public link, and the old one stops working.

A new epoch also seals the artifact's data again under the new key: the
latest database revision of every version, every stored file, and the latest
version. The command prints what it sealed, and anything it left alone with
the reason, for example a version waiting for the owner's review. If it stops
part way, say on a network error, the new epoch still stands: run
`cairn reseal ARTIFACT` to finish. It is safe to run again.

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
approved member holds a key starts a new epoch that excludes them. A new
epoch on a team artifact lists each approved member whose approval checks
out, and excludes every one it cannot list, because `cairn` never asks
questions. The owner lists an excluded member again with `cairn share`.

`cairn public ARTIFACT on` makes the artifact readable by anyone who holds
its link, and prints the link. The key is in the part after the `#`, which a
browser never sends to the server, so share the link only with people who
should read the artifact. A visitor's client checks the artifact's
membership against the link before it trusts it. Public writes are off at
first. Run `cairn public ARTIFACT on --writes on` to let a signed-in link
holder write to the database and files. `cairn public ARTIFACT off` starts a
new epoch, so the old link stops working.

A link holder has no pinned state, so a server can show you an older part of
the artifact's membership chain. For example, it can hide a later record
that turned public writes off or removed an editor, as long as the artifact
is still public at the link's epoch. To turn a link off, make the artifact
private in a new epoch.

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

When you remove an editor, the versions they pushed need your vouch before
anyone runs them. `cairn review` lists those versions, and `cairn vouch`
signs one after you have looked at it. Clients refuse to run a version that
needs a vouch.

```sh
cairn review my-app                # versions waiting for your vouch
cairn vouch my-app VERSION         # vouch for one
```

To hand an artifact to an editor, the owner offers ownership. The artifact
stays with the owner until the editor accepts. A new offer closes the
earlier one. The editor can decline, and the owner can withdraw the offer.

```sh
cairn transfer my-app bob@example.com   # offer; add --accept-new-key if bob's keys changed
cairn transfer accept my-app            # bob accepts; the old owner stays an editor
cairn transfer accept my-app --drop-previous-owner   # or a new epoch excludes them
cairn transfer decline my-app           # bob declines
cairn transfer withdraw my-app          # the owner withdraws the offer
```

If an administrator handed an artifact to a new owner, `push`, `share`,
`vouch`, and the other commands that change it refuse until you confirm the
handover with the people involved and pass `--accept-new-owner`.

A ready-made **Claude Code skill** ships in
[`.claude/skills/cairn-artifact/`](.claude/skills/cairn-artifact/SKILL.md): it
teaches Claude the whole build → test locally → publish → iterate workflow and
the `cairn.js` API. It is picked up automatically when working inside this
repo; copy the directory into any other project's `.claude/skills/` (or
`~/.claude/skills/` for global use) to let Claude publish artifacts from
there.

### Successors and key rotation

A successor is one user you choose who can read the artifacts you own if you
cannot. They never read what others shared with you. Nobody becomes a
successor without a code from their own device, so a server cannot swap in a
different key.

```sh
cairn successor code                                     # carol runs this and sends you the code
cairn successor nominate carol@example.com --code CODE   # asks for your password
cairn successor status                                   # your successor, any request, who named you
cairn successor remove                                   # remove your successor
cairn successor notice-email me@example.org              # a personal address for notices
```

To read an owner's artifacts, the successor runs `cairn successor request
USER`. Cairn tells the owner by email, by a banner in the app, and by a
warning in `cairn`. If the owner does not refuse, access starts 14 days after
the request. To refuse, the owner runs `cairn successor refuse`, uses the
**Refuse** button in the app, or opens the `/refuse` page on the server. The
`/refuse` page needs no session, so it works on a deactivated account. It
takes the email address and the password or the recovery code. A refusal
ends the request and keeps the nomination. The **Successor** tab in `/app`
does the same as these commands.

After the server releases access to a successor, it refuses the owner's
changes until the owner runs `cairn rotate-keys`.

`cairn rotate-keys` replaces your keys and prints a new recovery code. Save
it, because the old one stops working. It also revokes every API key and
moves each artifact you own to a new epoch. Run it after a leaked key, a lost
device, or a successor release. Because it revokes API keys, unset
`CAIRN_HOST` and `CAIRN_API_KEY` and sign in with `cairn login` first.

```sh
cairn rotate-keys                  # asks for your password
cairn rotate-keys --keep-epochs    # keep your artifacts at their current epochs
```

The design is in
[`design/e2e-trust-model.md`](design/e2e-trust-model.md#successor).

## Moving from an older server

A server from before end-to-end encryption cannot upgrade in place: the new
server starts empty and never holds plaintext. `cairn import` moves your
artifacts across from a snapshot instead.

1. On the old server, take a snapshot: `cairn backup --data-dir data --out
   backup/`. It is safe while the old server runs.
2. On the new server, sign up, then sign in with `cairn login`.
3. Run `cairn import backup/` (add `--json` for a script). It encrypts each
   artifact on your machine, uploads it as a private artifact you own, and
   reads it back to compare it with the snapshot.

The import reads the snapshot in place and only reads it. It never writes into
the snapshot, and it refuses a live data directory, so always import a
`cairn backup` copy. It also refuses a symbolic link anywhere among the
snapshot's content, databases, and stored files.

If the import fails, or you press Ctrl-C, it deletes the artifact it was
importing and lists the ones it finished. A second Ctrl-C stops it at once,
and can leave that artifact behind unlisted; find it with
`cairn artifact list`. A second run imports everything again, so delete the
finished ones first with `cairn artifact delete`.

Artifacts that were public arrive private. The import lists them with their
new IDs, and marks them in the list it prints when it stops early. Run
`cairn public <id> on` to publish one again. When you are done, delete the
snapshot and wipe the old server.

## Operations

- **Data layout** — everything lives under `--data-dir`: `cairn.db`
  (metadata), `secret.key` (JWT signing), `content/` (extracted version
  uploads), `dbs/` (encrypted database revisions), `files/` (encrypted
  stored files).
- **Backup** — `cairn backup --data-dir data --out backup/` snapshots live
  SQLite databases with `VACUUM INTO` and copies the rest. Safe while the
  server runs.
- **Config** — flags > `CAIRN_*` env (`CAIRN_ADDR`, `CAIRN_DATA_DIR`,
  `CAIRN_BASE_URL`, `CAIRN_TOKEN_TTL`, `CAIRN_MAX_UPLOAD_MB`, …). Set
  `--base-url https://…` behind TLS so cookies are marked Secure.
- **Password reset** — an admin resets the account; the user picks a new
  password at next sign-in. Tokens are invalidated instantly on reset/disable.

### Content domain and public URL

Cairn serves each artifact on its own host name, `<artifact ID>.<content
domain>`, so that an artifact cannot reach the app or another artifact.

- `--public-url` (or `CAIRN_PUBLIC_URL`) is the address people use for the app
  and for every emailed link, such as `https://cairn.example.com`.
- `--content-domain` (or `CAIRN_CONTENT_DOMAIN`) is the domain the artifacts
  use, such as `cairn-content.net`. With a localhost public URL it defaults to
  `localhost`. Otherwise you must set it.

The two must be separate sites: Cairn refuses a content domain that is the
public URL's host, a parent or child of it, or shares a registrable domain
with it. `cairn.example.com` and `content.example.com` fail that test, so
register a second domain.

The content domain needs wildcard DNS, so that `*.cairn-content.net` points at
the server, and a wildcard TLS certificate for `*.cairn-content.net`. Your
reverse proxy must send both the public URL's host and every host under the
content domain to Cairn.

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

### Verifying a server

`cairn verify` checks that a server serves the files and pages of a signed
release without change. It checks the server you are signed in to, or the
`URL` you give.

```sh
cairn verify --version v1.1.0 https://cairn.example.com
```

Sign in with `cairn login` first. Otherwise the check skips `/app` and fails,
unless you pass `--allow-skip`. Use `--manifest FILE` to check against a
manifest file, and `--key KEY` (repeatable) to trust another release public
key. [Check a server](deploy/gcp/README.md#check-a-server) explains what a
pass proves.
