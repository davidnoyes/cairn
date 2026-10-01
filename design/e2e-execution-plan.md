# End-to-end encryption — execution and test plan

Status: **draft for review**. This plan delivers the
[end-to-end encrypted trust model](e2e-trust-model.md). The design says what
to build; this document says in what order, how each step is tested, and
what "done" means for each milestone.

## Ground rules

These apply to every milestone:

- **One branch per milestone**, named `e2e/m<N>-<topic>`, cut from the
  integration branch `feat/e2e-trust-model`. A milestone merges into the
  integration branch when its definition of done holds. The integration branch
  merges into `main` only after milestone 9, because no milestone before it
  leaves a server that a team can switch to.
- **Red, then green.** Every behavior starts as a failing test. The commit
  history shows the test landing before, or with, the code that passes it.
- **Integration and browser tests are written first.** Each milestone opens by
  committing its end-to-end tests, marked as expected failures, so the
  milestone's goal is fixed before any code is written.
- **The server keeps working.** Every milestone leaves `go test ./...`,
  `node --test`, and `./scripts/e2e.sh` passing. A milestone that replaces an
  endpoint replaces its e2e step in the same branch.
- **Review gate.** `senior-dev-review` and `senior-qa-review` review every
  milestone branch before it merges. The crypto core in milestone 1 and the
  isolation work in milestone 4 also get a fresh security architect review.
- **Tests never touch the real server.** Every script and test clears
  `CAIRN_HOST` and `CAIRN_API_KEY` and sets `CAIRN_CONFIG` to a temporary
  path.

### Definition of done for a milestone

1. Every test listed for the milestone exists and passes.
2. Statement coverage is at least 70% for each Go package and JavaScript
   module the milestone adds or changes. Critical paths are covered whatever
   the percentage says.
3. Each critical check the milestone adds has a recorded mutation that makes a
   test fail. See [Mutation checks](#mutation-checks).
4. `gofmt`, `go vet`, `staticcheck`, and ESLint report nothing.
5. CI passes on the branch.
6. Both review agents have reported, and each finding is fixed or answered.
7. The design doc still matches what was built, or is updated in the same
   branch.

## Test layers

| Layer | Tool | What it covers | Runs in |
| --- | --- | --- | --- |
| Go unit | `go test` | Crypto, store, auth, permission checks, command-line helpers | Every push |
| JavaScript unit | `node --test` on `.mjs` files | Browser crypto module, shell logic, `frame.js`, service worker routing | Every push |
| Cross-language vectors | Go and Node, one shared JSON file | Go and the browser produce and accept identical bytes | Every push |
| Go integration | `httptest` with a temporary data directory | Every endpoint, the permission table, sessions, mail flows, the successor clock | Every push |
| Command-line end to end | `scripts/e2e.sh` against a built binary | The commands a user runs, from sign-up to import | Every push |
| Browser end to end | Playwright on Chromium, Firefox, and WebKit | Content origins, the frame sandbox, the service worker, the UI | Every push from milestone 4 |
| Real Safari | `safaridriver`, or a manual checklist | What Playwright's WebKit build cannot vouch for | Before each release |

### Shared test fixtures

Build these once, in milestone 0 or the milestone that first needs them, and
reuse them everywhere:

- **Fake clock.** The server takes a `Clock` interface. Tests advance it to
  check link expiry, rate-limit windows, token lifetimes, and the 14-day
  successor wait without sleeping.
- **Mail capture.** The mailer is an interface. Tests use an in-memory capture
  that records each message, so a test can read the reset link out of the
  "email" it would have sent. `scripts/e2e.sh` runs the server with
  `--smtp-url` pointing at a tiny SMTP capture server built into the test
  binary, not at a real relay.
- **Deterministic randomness for vectors only.** Crypto functions take an
  `io.Reader` for randomness. Production passes `crypto/rand`. Only the vector
  generator passes a seeded reader, so vectors are reproducible.
- **Test users.** A helper signs up and verifies a user in one call, returning
  a client holding that user's keys. Integration tests start from two or three
  of these.
- **Hostile names.** One list of strings, such as
  `<img src=x onerror=alert(1)>`, a right-to-left override, a 10,000-character
  name, and a lone surrogate. Every list view and every metadata field is
  tested against it.

### Cross-language test vectors

The browser and the `cairn` tool must agree byte for byte, or one cannot read
what the other wrote. `internal/e2e/testdata/vectors.json` holds one entry per
primitive and format:

- HKDF for each label.
- Argon2id at the floor parameters.
- AES-GCM blob headers and STREAM chunks, including the last-chunk flag.
- ECIES wraps, with their context.
- Ed25519 signatures over each signed structure.
- Fingerprints, `linkToken`, and file addresses.

Go generates the file. A Go test and a Node test each check every entry.
Each side also writes fresh output with real randomness, and the other side
reads it, so agreement is tested in both directions, not only against fixed
bytes. Every entry has negative cases as well: a flipped bit, a truncated
stream, a dropped or reordered chunk, a blob moved to another path, version,
or artifact, and a wrap moved to another epoch or recipient. All must fail.

### Browser end to end

Playwright drives Chromium, Firefox, and WebKit against a real `cairn serve`.
Tests use `*.localhost` content origins locally, and a second registrable
domain through `/etc/hosts` entries and a local CA in CI, so the cross-site
behavior under test is the same as production.

Playwright's WebKit build is not Safari, and storage partitioning is exactly
where the two can differ. Before each release, run the browser suite's smoke
subset against Safari through `safaridriver`. Where that cannot run, work
through a short manual checklist, recorded in the release notes:

- A private artifact renders.
- A public link renders in a private window.
- Database writes persist across a reload.
- Signing out and back in still renders the artifact.

### Mutation checks

Coverage shows a line ran, not that a test would notice it breaking. Every
critical check gets a listed mutation in `scripts/mutations.txt`: a file, a
line pattern, and its replacement, such as inverting a signature check or
skipping the epoch comparison. `scripts/mutate.sh` applies each one in a
temporary copy of the tree, runs the relevant tests, and fails if any mutation
survives. CI runs it on milestone branches, not on every push.

The checks with mutations:

- Each authenticated-decryption result check.
- The Argon2id parameter floor.
- Signature and signer checks on versions, revisions, and membership records.
- The highest-epoch check.
- Every row of the permission table.
- `linkToken` comparison.
- Content-origin token scope.
- `Sec-Fetch-Site` and `Origin` checks.
- Navigation message validation and `safeNext`.
- The successor clock and refusal.

## Milestone 0 — groundwork

Branch: `e2e/m0-groundwork`.

1. **Bring the branch up to date.** Merge `main` into `feat/e2e-trust-model`,
   which brings `shell.js`, `mermaid-boot.js`, their tests, and `vendor/`.
   Check: `go test ./...`, `node --test internal/server/web/`, and
   `./scripts/e2e.sh` all pass.
2. **Add a CI test workflow**, `.github/workflows/test.yml`, running on every
   push and pull request:
   - `gofmt -l .` and `go vet ./...`
   - `staticcheck ./...`
   - `go test -race -coverprofile=cover.out ./...`, with a coverage report
   - `node --test --experimental-test-coverage` over every `*_test.mjs`
   - ESLint over `internal/server/web/*.js`, excluding `vendor/`
   - `./scripts/e2e.sh`

   Check: the workflow passes on the branch, and fails when a test is broken
   on purpose.
3. **Add the fixtures** listed in [Shared test fixtures](#shared-test-fixtures):
   the clock and mailer interfaces, and the mail capture.
   Check: unit tests for each.
4. **Vendor sql.js** into `internal/server/web/vendor/`, which `cairn.js` now
   loads from a CDN, with its license and a checksum test, as Mermaid is.
   Check: the guestbook example works with the network off.

The open redirect in today's `safeNext` is fixed separately, on its own branch
from `main`, because it affects the running server now. See
[Before milestone 0](#before-milestone-0).

## Milestone 1 — crypto core

Branch: `e2e/m1-crypto`. The Go package `internal/e2e`, and the JavaScript
module `internal/server/web/e2e.js`, built side by side with one vector file.

1. Commit the vector file's schema and an empty generator. Commit the Go and
   Node vector tests, which fail.
2. Implement each primitive in Go, test first, in this order: labels and HKDF,
   AES-GCM with associated data, the STREAM blob format, ECIES with context,
   Ed25519 over canonical encodings, fingerprints, and `linkToken`.
3. Generate the vectors. Implement each primitive in JavaScript on WebCrypto
   until the Node test passes, then add the reverse-direction tests.
4. **Argon2id.** Spike two candidate WebAssembly builds, then choose one.
   Weigh audit history, size, speed at 64 MiB on a mid-range laptop, and
   license. Vendor the choice with a checksum test.
   Check: the browser and Go's `x/crypto/argon2` agree on the vectors.
5. Enforce the parameter floor on both sides, test first.

Tests:

- Every vector, positive and negative, in both languages.
- Fuzz tests in Go on the blob and header parsers. A malformed input must
  return an error, never panic.
- A test that no two labels in the label table are equal.

Done when: both languages pass every vector in both directions, the fuzz tests
run for 60 seconds each in CI without a crash, and a security architect review
has reported.

## Milestone 2 — accounts and sessions

Branch: `e2e/m2-accounts`.

Integration tests written first:

- Sign up with an allowed domain, receive the verification mail, follow the
  link, and sign in. A disallowed domain is refused, and no `--signup-domain`
  means no sign-up at all.
- `cairn login` creates a device key. A later command needs no password.
- Prelogin for an unknown email returns a stable fake salt and the default
  parameters. Sign-in for an unknown user takes about as long as for a known
  one.
- A reset with the recovery code keeps both public keys. A reset without it
  gets new keys, archives the old wraps, notifies other sessions, and marks
  the account as reset on its date.
- The archived `MK` can be restored with the old recovery code.
- No administrator endpoint can set a password, create an account, or create
  an API key for someone else.
- The fifth failed sign-in in a window is rate limited. Limits apply per
  account and per IP address.

Steps, each test first:

1. Schema for users, key bundles, archived wraps, device keys, and
   verification and reset tokens. Fresh databases only; no migration from
   today's schema.
2. Self-signup, verification, prelogin, and login, with the mail interface.
3. Split API keys and device keys.
4. Reset by email link, recovery-code rewrap, and archive.
5. The `__Host-` strict cookie, the JSON and `Sec-Fetch-Site` checks, and
   rate limits.
6. The app CSP. Move the inline scripts in `login.html` and `admin.html` to
   files. Add the client-side strength check with a vendored estimator.

Security regressions added: forged cross-site POST refused (H1); form-encoded
body refused (H1); no fake-salt difference between known and unknown accounts
(M3); a reset leaves archived wraps intact (M1); emailed links use
`--public-url` whatever `Host` says (L3).

## Milestone 3 — ownership and sharing

Branch: `e2e/m3-sharing`.

Integration tests written first:

- User B cannot list, read, or write user A's artifact until A shares it, and
  loses access when A removes them.
- A viewer cannot write. An editor can write and push, but cannot share,
  publish, or delete.
- A team share wraps for every member. A new member gets nothing until an
  owner or editor approves them by name. A viewer's client never wraps.
- A public link serves ciphertext only with the right `linkToken`, and stops
  when the artifact is made private.
- Public writes need both `linkToken` and a session, and are refused while the
  switch is off.
- Removing a member creates a new epoch. The removed member's old `AK` reads
  nothing written afterward.
- A client refuses to encrypt under an epoch older than the highest it pinned.
- A changed key blocks a silent re-share. A rotation signed by the old key
  shows "keys rotated" instead.
- Ownership transfer needs the owner's consent while the owner is active.

Steps, each test first:

1. Ownership, members, wrapped keys, and estate-key wraps in the schema.
2. The permission table as one function, tested row by row.
3. Signed membership records and the highest-epoch check.
4. Pins and verification states in the user's encrypted keyring.
5. Team shares with approval, and public links.
6. Epochs and revocation, including the editor-removal review list.
7. **Rotate keys.**

Security regressions added: approval required for a new team member, and a
key change never treated as a new member (H2); a viewer cannot wrap (H2);
stale-epoch encryption refused (H6); link-derived tokens are public-scoped
(H3).

## Milestone 4 — encrypted content and isolation

Branch: `e2e/m4-isolation`. The largest milestone, and the riskiest.

Browser tests written first, on all three engines:

- A private artifact renders, and every file under the data directory is
  ciphertext. The test greps the data directory for a marker string from the
  artifact.
- A hostile artifact cannot:
  - navigate the top page;
  - read the app's cookie;
  - send a request to the app API with the session;
  - call share, publish, or delete with its content-origin token;
  - get the shell to navigate to a path outside `/shared/<uuid>`.
- A public link renders in a fresh browser profile, and the key leaves the
  address bar.
- Internal links replace the whole page; external links open a new tab;
  Mermaid renders inside the frame.
- Links and diagrams work in full screen.
- After the browser stops the service worker, the next request recovers
  through the handshake.
- Nothing is written to Cache Storage or IndexedDB on the content origin.

Steps, each test first:

1. `serve` flags `--public-url` and `--content-domain`, host routing, and the
   startup check that the two are separate sites. Remove `--trust-proxy` if
   it exists by then.
2. Encrypted push: the `cairn` tool checks the tree, encrypts, signs the
   manifest, and uploads. Drop zip upload.
3. Content-origin serving: the boot page, `frame-ancestors`, and
   `Cache-Control: no-cache` on the worker.
4. The service worker: handshake, decryption, signature checks, media types,
   and SPA fallback.
5. The sandboxed frame and the shell's handshake and navigation checks.
6. `frame.js`, ported from `shell.js` and `mermaid-boot.js`, with their
   existing tests moved across.
7. Full screen as an app-origin page.

Security regressions added: everything in the hostile-artifact list (H1, H3,
H6); `frame-ancestors 'none'` on app pages (H1); worker update headers (M4);
no plaintext in content-origin storage (L1); key removed from the address
bar (L2).

Done when: the browser suite passes on all three engines, the Safari check
has been run once by hand, and a security architect review has reported.

## Milestone 5 — client-side database and files

Branch: `e2e/m5-data`.

Tests written first:

- Every example in `examples/` works unchanged, through the browser suite.
- Two browsers writing at once both land, through the `412` retry.
- A removed editor's write is refused by the server, and a revision signed by
  a non-editor is refused by clients.
- The server keeps the last 10 revisions, and the owner can restore one.
- A database larger than the size cap is refused.
- File names do not appear anywhere under the data directory.
- `cairn db query` and `cairn db batch` match the browser's results.

Steps, each test first: encrypted database blobs with revisions and
`If-Match`; `cairn.js` on the bundled sql.js; signed revisions; revision
retention; encrypted files addressed by `fileKey`; the `cairn db` commands.
Remove `internal/versiondb` once nothing uses it.

## Milestone 6 — app UI

Branch: `e2e/m6-ui`.

Browser tests written first:

- The full share walkthrough: share with a user, verify their fingerprint,
  make public, copy the link, make private.
- The hostile-names list renders as text in every list and dialog, and the
  test fails if any string becomes markup.
- A password prompt never appears over an artifact.
- API keys, the recovery code, and successor settings can be managed from the
  UI.

Steps: the artifact lists, the share dialog, key management, and account
settings, each rendered on the client with `textContent` only and under
Trusted Types.

## Milestone 7 — successor

Branch: `e2e/m7-successor`. Integration tests with the fake clock, written
first:

- Nomination fails without the code from the successor's device.
- A request notifies the user by mail, banner, and `cairn` warning.
- A refusal on day 13 blocks access, including from a deactivated account
  through `authKey` or the recovery code.
- Deactivating the user during a request is recorded and shown to them.
- Silence until day 14 releases the estate key. The successor reads the
  user's own artifacts, but not one that was shared with the user.
- The user signing in after a release is made to rotate keys.

Security regressions added: refusal survives deactivation, and the estate key
does not open shared artifacts (H5, M2).

## Milestone 8 — deploy integrity

Branch: `e2e/m8-deploy`.

1. A signed release manifest of every embedded web asset, built in CI.
2. `cairn verify`, tested to pass against a release build and fail when one
   served file changes.
3. CI builds and signs the image from the protected branch only. The VM's
   startup script refuses an image whose signature does not verify.
4. A deployment guide covering Cloud DNS, Certificate Manager, the load
   balancer, the VM, the log sink in a separate project, and the alerts.

Check by hand on a staging project: deploy an unsigned image and see it
refused; change a DNS record and see the alert fire.

## Milestone 9 — import and docs

Branch: `e2e/m9-import`.

Tests written first:

- `scripts/e2e.sh` builds a server the old way, fills it, takes a backup, and
  imports it into a fresh server. Every artifact, version, database, file, and
  resource compares equal after decryption.
- The import lists artifacts that used to be public.
- Interrupting the import leaves no temporary files.

Then the README, the `cairn-artifact` skill, and the `CLAUDE.md` invariants.
Finally, import your real server's backup into a staging server and compare.

## Security regression map

Each finding from the security review has at least one test that fails if the
fix is removed.

| Finding | Test | Milestone |
| --- | --- | --- |
| H1 separate content domain | Startup refuses a shared registrable domain; forged cross-site and form-encoded requests refused; a hostile artifact cannot reach the session | 2, 4 |
| H2 key directory | New pins start unverified; team joiners need approval; viewers never wrap; nomination needs the successor's code | 3, 7 |
| H3 shell phishing | Top navigation blocked; navigation messages validated; `safeNext` rejects `/\evil.com`; no password prompt over an artifact | 0, 4, 6 |
| H4 app-origin rendering | Hostile names render as text everywhere; CSP and Trusted Types headers present | 2, 6 |
| H5 successor veto | Refusal works after deactivation; deactivation during a request is shown | 7 |
| H6 token scope and forgery | Content-origin token cannot share or publish; unsigned or wrongly signed versions refused; stale epoch refused | 3, 4, 5 |
| H7 STREAM construction | Negative vectors for truncation, reordering, and moved blobs; no key and nonce reuse across rewrites | 1 |
| M1 code-less reset | Archived wraps survive and restore | 2 |
| M2 estate key | Successor cannot open shared artifacts; rotation required after release | 7 |
| M3 stretching and sign-in | Parameter floor; fake prelogin; rate limits; timing for unknown users | 1, 2 |
| M4 deploy integrity | Worker update headers; `cairn verify` detects a changed file; unsigned image refused | 4, 8 |
| M5 import hygiene | No temporary files after an interrupt | 9 |
| M6 key rotation | Rotation invalidates API keys, recovery code, and successor wrap | 3 |
| L1 keys in memory only | No content-origin storage writes | 4 |
| L2 key in the address bar | Key removed; `linkToken` only in a header | 4 |
| L3 emailed links | Links built from `--public-url` | 2 |
| L4 database restore | Last 10 revisions kept and restorable | 5 |
| L5 recovery code guidance | Sign-up asks for one group back | 6 |
| L6 ownership transfer | Consent needed while the owner is active | 3 |

## Dependencies and risks

- **Network access for tooling.** Playwright, ESLint, and `staticcheck` all
  download from the internet. CI has it; this machine's sandbox does not, so
  installing them locally needs the sandbox off, once.
- **Argon2id in WebAssembly** is the one new third-party crypto component. The
  spike in milestone 1 decides it, and the security review covers the choice.
- **Safari.** Partitioning differences between Playwright's WebKit and real
  Safari would surface late. The manual check in milestone 4 brings that
  forward.
- **Milestone 4 is large.** If it runs long, split it after step 4 into
  encrypted serving and frame hardening. Both halves keep the server
  working.
- **Upstream drift.** The fork diverges from `aloisdeniel/cairn` from
  milestone 2 onward, so later upstream fixes have to be ported by hand.

## Before milestone 0

Today's `safeNext` accepts `/\evil.com`, which browsers treat as
`//evil.com`, so signing in can redirect to another site. Fix it on
`fix/safe-next` from `main`, test first, independent of this plan, and merge
it into the integration branch with milestone 0.
