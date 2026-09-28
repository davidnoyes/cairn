# Cairn — developer notes

Self-hosted artifact server ("open Claude Artifacts"): one Go binary =
server + admin UI + agent-oriented CLI. See README.md for user-facing docs.

## Commands

```sh
go build ./cmd/cairn     # build the binary
go test ./...            # unit + integration tests (httptest, temp dirs)
./scripts/e2e.sh         # end-to-end smoke test against a real server
gofmt -l . && go vet ./...
node --test internal/server/web/*_test.mjs   # shell.js unit tests (no npm deps)
```

## Map

- `cmd/cairn/` — subcommand dispatch. `serve.go` (server), `backup.go`,
  `client_cmds.go` (login/artifact/push/db/open), `config.go` (CLI state at
  `~/.config/cairn/config.json`, override with `CAIRN_CONFIG`; headless via
  `CAIRN_HOST` + `CAIRN_API_KEY`).
- `internal/store/` — metadata SQLite (`modernc.org/sqlite`, pure Go).
  Embedded migrations in `migrations/*.sql` run at open. `layout.go` defines
  the data dir: `content/{artifactID}/{contentDir}/` for extracted uploads,
  `dbs/{artifactID}/{versionID}.db` for shared databases,
  `files/{artifactID}/{versionID}/` for per-version file storage —
  deliberately separate so re-uploads never touch data.
- `internal/auth/` — bcrypt passwords, hand-rolled HS256 JWT (claims include
  `tkv` = token_version for instant revocation), API keys
  `cairn_<keyid>_<secret>` stored as SHA-256.
- `internal/versiondb/` — per-version DB manager: refcounted handle cache,
  **read/write enforced by connection pools** (anonymous → `query_only` pool),
  single-statement scanner (the driver executes multi-statement input
  otherwise!), batch = one transaction.
- `internal/server/` — HTTP. `routes.go` is the route table. Serving model:
  `/artifacts/{id}` 302→ `/artifacts/{id}/{vid}/` (canonical, trailing slash)
  so relative paths resolve; SPA fallback only for extension-less
  `Accept: text/html` requests. `web/` holds embedded assets: `login.html`,
  `shell.html` (iframe wrapper), `admin.html` (vanilla-JS admin UI over the
  JSON APIs), `cairn.js` (client lib; falls back to sql.js-in-browser with
  user `{id: 0, name: "Debug"}` when not served by Cairn).
- `internal/client/` — Go API client used by the CLI (zips + multipart push).
- `examples/` — reference artifacts: `guestbook` (single file, exercised by
  e2e), `poll` (multi-file + assets + config fetch), `drive` (file storage as
  a shared drive; no database), `todo-react` (TypeScript + React + esbuild;
  push its `dist/`, `src/store.ts` wraps cairn.js).
- `.claude/skills/cairn-artifact/` — Claude Code skill for building and
  publishing artifacts with the CLI; keep it in sync when CLI flags or the
  cairn.js API change.

## Invariants worth keeping

- Versions are re-uploadable; replacement is a content-dir pointer swap
  (`SwapVersionContent`) + RemoveAll of the old dir. Never write into a live
  content dir.
- Never classify SQL as read/write by parsing — connection-level only.
- Uploaded zips: `fs.ValidPath` names only, no symlinks, decompressed-size
  budget, `index.html` required at root (single wrapping top dir is stripped).
- First-login-sets-password is the intended trust model (no invite tokens);
  `confirm` field guards typos. Admin "reset password" returns the account to
  the unclaimed state.
- Users are trusted with everything authenticated; anonymous gets read-only
  access to public artifacts. Keep new endpoints on that line.
- The `{id}` segment of artifact routes is a *reference*: artifact id first,
  else resource value/row id (409 on ambiguity). Handlers must use
  `requestArtifact(r)` (set by `withArtifact`/`publicAware`) — never
  `r.PathValue("id")` — as the artifact id for storage paths and queries.
