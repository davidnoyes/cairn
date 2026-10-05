# Cairn — developer notes

Self-hosted artifact server ("open Claude Artifacts"): one Go binary =
server + app UI + agent-oriented command-line tool, with end-to-end
encryption: the server stores only ciphertext. See README.md for user-facing
docs and `design/e2e-*.md` (trust model, API, wire formats, execution plan)
for the design.

## Commands

```sh
go build ./cmd/cairn     # build the binary
go test ./...            # unit + integration tests (httptest, temp dirs)
go test -tags e2eclock ./cmd/cairn -run TestE2EClock   # CLI on a test clock
./scripts/e2e.sh         # end-to-end smoke test against a real server
gofmt -l . && go vet ./... && go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...
npm ci                   # dev tools only (ESLint, Playwright); nothing ships
npx eslint .
node --test internal/server/web/*_test.mjs   # web/ JS unit tests
npx playwright test      # browser e2e (browser/*.spec.mjs); install browsers first
./scripts/mutate.sh      # mutation checks; MUTATIONS=file tries one list, MUTATE_SHARD=i/n splits
./scripts/fuzz.sh        # every Go fuzz test; FUZZTIME=10s
./scripts/build-argon2-wasm.sh   # rebuild vendored wasm; CI fails on a diff
```

CI (`.github/workflows/test.yml`) runs the first group on every push; fuzz,
mutations, and Playwright only on `e2e/*` branches.

## Map

- `cmd/cairn/` — subcommand dispatch (`main.go` lists every command). `serve.go`
  (server), `backup.go`, `import_cmds.go` (import a pre-encryption backup),
  `verify_cmd.go`, `client_cmds.go` (signup/login/artifact/push/open),
  `share_cmds.go`, `transfer_cmds.go`, `successor_cmds.go`, `rotate_cmds.go`,
  `data_cmds.go` (db/files/reseal), `config.go` (command-line state at
  `~/.config/cairn/config.json`, override with `CAIRN_CONFIG`; headless via
  `CAIRN_HOST` + `CAIRN_API_KEY`).
- `cmd/cairn-release/` — makes the release key and signs the manifest.
  `cmd/argon2wasm/` — Argon2id compiled to wasm for the browser.
- `internal/e2e/` — the crypto core (seal, blobs, wrap, signatures, membership
  chain, keyring, rotation). `internal/server/web/e2e.mjs` is its browser twin;
  `testdata/vectors.json` ties them byte for byte.
- `internal/access/` — the permission table as one pure function.
  `internal/membership/` — acceptance rules for signed membership records.
- `internal/store/` — metadata SQLite (`modernc.org/sqlite`, pure Go).
  Embedded migrations in `migrations/*.sql` run at open. `layout.go` defines
  the data dir: `content/{artifactID}/{contentDir}/` for a version's ciphertext
  manifest and blobs, `dbs/{artifactID}/{versionID}/` for encrypted database
  revisions, `files/{artifactID}/{versionID}/` for encrypted stored files —
  deliberately separate so re-uploads never touch data.
- `internal/auth/` — bcrypt passwords, hand-rolled HS256 JWT (claims include
  `tkv` = token_version for instant revocation). API keys live in `internal/e2e`.
- `internal/mail/` — mailer (`smtp://` or `log://`). `internal/clock/` — clock
  interface; `Fake` moves tests past expiries and the successor's wait.
- `internal/sqlrun/` — runs one statement and holds the single-statement
  scanner (the driver executes multi-statement input otherwise!); used by the
  `db` commands of the command-line tool on a decrypted copy.
- `internal/release/` — signed release manifest (`manifest.json`, embedded) and
  the checker behind `cairn verify`.
- `internal/server/` — HTTP. `routes.go` is the route table. Serving model:
  the app origin serves account pages, `/app`, and the JSON APIs; an artifact
  renders at `/shared/{id}[/{vid}[/{path}]]` (or `/full/...`), a shell page that
  verifies the membership chain, then frames the artifact's own content origin
  `<artifactID>.<CAIRN_CONTENT_DOMAIN>` (`contentorigin.go`). That origin serves
  only `/_cairn/` files (boot page, service worker, `cairn.js`) and a
  content-token API; the worker decrypts blobs in the browser.
  `/artifacts/{id}` paths redirect to `/shared/`. `web/` holds embedded assets,
  mostly one `.html` + `.js`/`.mjs` pair per page (`login`, `signup`, `app`,
  `shell`, `boot`), `sw.js`, `keystore.mjs`, `cairn.js` (client lib; falls
  back to sql.js-in-browser with user `{id: 0, name: "Debug"}` when not served
  by Cairn), and `vendor/` (sql.js, Mermaid, Argon2 wasm).
- `internal/client/` — Go API client used by the command-line tool (does the encryption,
  signing, and membership checks).
- `browser/` — Playwright specs. `design/` — e2e design docs. `deploy/gcp/` —
  deployment guide and VM startup script.
- `examples/` — reference artifacts: `guestbook` (single file, exercised by
  e2e), `poll` (multi-file + assets + config fetch), `drive` (file storage as
  a shared drive; no database), `todo-react` (TypeScript + React + esbuild;
  push its `dist/`, `src/store.ts` wraps cairn.js).
- `.claude/skills/cairn-artifact/` — Claude Code skill for building and
  publishing artifacts with the command-line tool; keep it in sync when its
  flags or the cairn.js API change.

## Invariants worth keeping

- The server never sees plaintext content, metadata values, passwords, or
  keys; the browser and the command-line tool do all crypto. A client checks
  every answer (membership chain, version signature) and never trusts the
  server.
- Versions are re-uploadable; replacement is a content-dir pointer swap
  (`SwapVersionContent`) + RemoveAll of the old dir. Never write into a live
  content dir.
- Pushes: `fs.ValidPath` names only, no symlinks, `index.html` at root
  (checked client-side in `internal/client/client.go`).
- Access is one table, `internal/access`. Every `/api/artifacts/{id}` route
  goes through `artifactRoute(action, h)`; no access is a 404, administrators
  included. Handlers use `requestArtifact(r)` — never `r.PathValue("id")` — as
  the artifact id for storage paths and queries (`{id}` may be a resource
  reference; 409 on ambiguity).
- Membership records are signed by the owner and accepted only through
  `internal/membership`; removing a member starts a new epoch, and clients
  never accept data from a lower epoch.
- Accounts are self-signup (`--signup-domain`) with emailed verification; the
  password is stretched on the client. No administrator endpoint sets a
  password; they only grant roles, deactivate, delete, or offer an ownership
  transfer. Emailed links are built from `--public-url`, never a request
  header.
- Browser pages load scripts only from files under the app CSP (`csp.go`), with
  no inline code, and build DOM with `textContent` (Trusted Types).
- The app origin never runs artifact code. The content domain must not share a
  registrable domain with the app (`contentdomain.go` refuses to start); content
  hosts ignore cookies and may be framed only by the app origin.
- A release manifest is signed with the release key by `cairn-release sign`
  before the build and embeds in the binary; `GET /.well-known/cairn-release`
  serves it. Adding or changing an embedded asset or template changes the
  manifest, and `cairn verify` compares what a server sends against it.
- Mutation list (`scripts/mutations.txt`): each search text must occur once and
  still compile; check the lines when you edit a guarded function.
