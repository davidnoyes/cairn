# End-to-end encrypted trust model

Status: **draft for review**. Nothing in this document is implemented yet.

## Goal

Today every signed-in user can read and write every artifact, and the server
holds all content in plaintext. This design reverses that:

- An artifact is private to its owner by default.
- The owner can share it with named users, or make it public.
- The server stores only ciphertext for private and shared artifacts. An
  administrator, an operator with shell access, or anyone holding a backup
  cannot read them.
- Cairn can run behind a reverse proxy that terminates TLS.

## Threat model

### What the design protects

| Adversary | Can read private content? |
| --- | --- |
| A Cairn administrator using the administration UI or API | No |
| An operator with the data directory or a backup | No |
| Another signed-in user who has no share | No |
| A shared artifact written by another user, running in your browser | Only that artifact, which you can already read |

### What the design does not protect

State these limits in the README, because they are inherent to encryption in
a web app:

- **The server delivers the JavaScript that does the crypto.** An operator who
  modifies the served code can capture keys the next time a user signs in. The
  `cairn` command-line tool does not have this weakness, because it runs its
  own code.
- **Metadata stays visible:** user emails and names, artifact IDs, owners,
  who shares with whom, the public flag, timestamps, and approximate sizes.
- **The server can delete data or serve an older copy.** Authenticated
  encryption stops forged or swapped content, but it cannot prove freshness.
- **The server could substitute a public key** when you share with someone.
  The share dialog shows key fingerprints and warns when a pinned key changes,
  which turns this into a detectable attack rather than a silent one.
- **Public means public.** A public artifact's key is stored in the clear so
  anonymous visitors can read it, and so can an administrator.

## Key hierarchy

```text
password ──PBKDF2──► stretched ──HKDF──┬─► authKey  (sent to server, bcrypt-stored)
                                       └─► kek      (never leaves the client)

recovery code ──HKDF──► recoveryKek

MK (random 256-bit master key)
  ├─ stored as AES-GCM(kek, MK) and AES-GCM(recoveryKek, MK)
  ├─ wraps the user's X25519 private key
  └─ derives indexKey (HMAC) for resource lookups

AK (random 256-bit artifact key, one per artifact per epoch)
  ├─ wrapped to each member's X25519 public key (owner included)
  ├─ stored in the clear while the artifact is public
  └─ derives one key per blob: HKDF(AK, blobID)
```

Both WebCrypto and the Go standard library provide every primitive below. No
WebAssembly crypto is needed.

- PBKDF2-HMAC-SHA256 with 600,000 iterations and a per-user random salt.
- HKDF-SHA256 for every derived key.
- AES-256-GCM for all symmetric encryption.
- X25519 plus HKDF plus AES-GCM for wrapping a key to a user (ECIES).
- Content blobs use 64 KiB chunks, each with its own GCM tag, so the client can
  seek and stream. The associated data binds each blob to its artifact,
  version, and path, so the server cannot swap one file for another.

The recovery code is 128 random bits shown once as base32 groups. It has
enough entropy to skip stretching.

## Accounts and sign-in

The server never sees the password or anything it could derive `kek` from.

1. The client calls `POST /api/auth/prelogin` with an email and receives the
   salt and iteration count. For an unknown email the server returns a
   deterministic fake salt, so the endpoint does not reveal which accounts
   exist.
2. The client derives `authKey` and `kek`, then sends `authKey` to
   `POST /api/auth/login`.
3. The server checks `authKey` against its bcrypt hash, sets the session
   cookie, and returns the user's encrypted key bundle.
4. The client unwraps `MK`, then stores the private key and `indexKey` in
   IndexedDB as non-extractable `CryptoKey` objects. `MK` itself is not kept.
   Actions that need it, such as creating an API key, ask for the password
   again.
5. Signing out clears IndexedDB.

The first-login-sets-password model stays. At claim time the client generates
`MK`, the key pair, and the recovery code, then uploads only wrapped material.

### API keys and the command-line tool

An API key must not let the server unwrap `MK`, yet the server sees the
bearer on every request. So a key has two secrets:

```text
cairn_<keyid>_<authSecret>_<keySecret>
```

The command-line tool sends only `cairn_<keyid>_<authSecret>` as the bearer.
It uses `keySecret` locally to unwrap its copy of `MK`, which the server
stores as `AES-GCM(HKDF(keySecret), MK)`.

- Users create their own API keys. An administrator can no longer create a key
  for someone else, because the administrator cannot wrap that user's `MK`.
- `cairn login` derives keys from the password locally, then creates a device
  API key and saves it to the local config file. Later commands do not prompt.
- Headless use through `CAIRN_API_KEY` works unchanged: the variable holds the
  full four-part string.

### Recovery and administrator reset

- An administrator reset returns the account to the unclaimed state and
  deletes the password-wrapped `MK`. The recovery-wrapped copy stays.
- At the next claim, the user enters the recovery code, the client unwraps
  `MK`, and the new password wraps it again. No data is lost.
- Without the code, the client generates a new `MK` and key pair. The user's
  old private artifacts stay unreadable, unless another member re-shares them
  to the new public key. The owner can delete the unreadable ones.
- An administrator can still deactivate and delete accounts and artifacts.
  The administrator can deny service, but cannot read.

## Ownership, sharing, and epochs

New metadata:

- `artifacts.owner_id`
- `artifact_members(artifact_id, user_id, role)`, where the role is `viewer`
  or `editor`
- `artifact_keys(artifact_id, epoch, user_id, wrapped_ak)`
- `artifacts.public_ak` and `artifacts.public_epoch`, set only while public

Permissions, enforced by the server on every endpoint:

| Action | Owner | Editor | Viewer | Other signed-in user | Anonymous |
| --- | --- | --- | --- | --- | --- |
| Read content, database, and files | Yes | Yes | Yes | If public | If public |
| Write database and files | Yes | Yes | No | If public and the owner allows signed-in writes | No |
| Push a version | Yes | Yes | No | No | No |
| Share, unshare, publish, delete | Yes | No | No | No | No |

Epochs handle revocation. When the owner removes a member or makes a public
artifact private, the client creates a new `AK` epoch and wraps it to the
remaining members. New writes use the new epoch. Earlier content stays under
the old key, since the removed party could already read it.

To share, the owner's client fetches the recipient's public key, shows its
fingerprint, and pins it in the owner's own encrypted keyring. A later change
to that key triggers a warning.

## Artifact isolation

This is the part that makes sharing safe. An artifact is arbitrary HTML and
JavaScript. If it ran on the app origin, a shared artifact from another user
could use your stored private key to unwrap every artifact key you hold.

So each artifact is served from its own origin, and the app origin never runs
artifact code:

| Origin | Example | Serves |
| --- | --- | --- |
| App | `https://cairn.example.com` | Sign-in, your artifact list, the shell, the administration UI |
| Content | `https://<artifactID>.usercontent.example.com` | One artifact's pages, plus the service worker |

- Session cookies are host-only on the app origin, so content origins never
  receive them.
- Content origins allow framing only by the app origin, through
  `frame-ancestors`.
- For local use, `http://<artifactID>.localhost:8787` works without TLS or DNS,
  because browsers treat `localhost` subdomains as secure contexts. Check this
  on Safari during milestone 4.

## Serving a private artifact

1. The shell on the app origin unwraps `AK`, and requests a short-lived access
   token scoped to one artifact and the viewer's role.
2. The shell frames `https://<id>.usercontent…/_cairn/boot`. The boot page
   registers the service worker, accepts `AK` and the token by `postMessage`
   (checking the sender is the app origin), then loads the version.
3. The service worker intercepts each request, fetches the ciphertext blob,
   decrypts it, and returns the plaintext with a media type taken from the
   file extension. It also applies the SPA fallback that the server applies
   today.
4. The service worker injects `/_cairn/frame.js` into HTML responses.
   `frame.js` opens external links in a new tab and renders Mermaid. Both
   features currently live in the app-origin shell, and move here because the
   shell can no longer reach into a cross-origin frame.

Full-screen view becomes an app-origin page with the shell chrome hidden, so
the same key handover works.

Public artifacts skip all of this: the server holds the plaintext `AK`, so it
decrypts and serves them directly, and anonymous visitors need no service
worker.

## Shared database

The server-side SQL proxy cannot survive, because the server cannot read the
database. It moves into the client:

- Each version's database is one encrypted blob with a revision number.
- `cairn.db.query` runs in the browser on sql.js, which is bundled into the
  binary. Before each query, the client revalidates its copy with a
  conditional request.
- `cairn.db.batch` loads the latest copy, runs the statements in one
  transaction, encrypts the result, and uploads it with `If-Match`. When
  another writer got there first, the server returns `412`, and the client
  reloads the database and re-runs the batch, up to a retry limit.
- The server rejects databases larger than a configurable cap, 50 MB by
  default. Whole-database writes suit the small databases artifacts use, not
  large ones.
- `cairn db query` and `cairn db batch` on the command line do the same with
  the Go SQLite driver on a temporary file in a private directory.

The public `cairn.js` API keeps its shape, so existing artifacts, including
everything in `examples/`, need no changes. The `internal/versiondb` package
and its connection-pool read-only enforcement go away: a reader without write
access simply cannot upload a new database.

## File storage and uploads

- Each file is a blob addressed by `HMAC(fileKey, path)`. Its real name and
  size travel in an encrypted metadata record, so file names are hidden.
- `cairn push` no longer uploads a zip. The `cairn` tool checks the tree,
  which must have `index.html` at the root and no symlinks, then encrypts each
  file and uploads a manifest plus blobs in one request. The server can no
  longer check the tree, since it cannot read it.
- Artifact and version names, descriptions, changelogs, and resource values are
  encrypted with `AK`. A resource lookup, such as `cairn open <session-id>`,
  uses a blind index, `HMAC(indexKey, type‖value)`, so it resolves only among
  your own artifacts.

## Deploying behind a TLS proxy

New `serve` flags:

- `--public-url https://cairn.example.com` sets the app origin, and turns on
  `Secure` cookies when the scheme is `https`.
- `--content-domain usercontent.example.com` sets the parent domain for
  per-artifact origins. The server routes requests by `Host`.
- `--trust-proxy` honors `X-Forwarded-Proto` and `X-Forwarded-Host` from the
  proxy. Without it, those headers are ignored.

The repository gains an example Caddy configuration and a Compose service. Per-artifact
origins need a wildcard DNS record and a wildcard certificate, which in
turn means an ACME DNS challenge. Document that trade-off plainly.

## Migrating from upstream

The running upstream server holds plaintext artifacts with no owner.

1. `cairn migrate --owner <email>` assigns every artifact to that user and
   marks each one as legacy plaintext. The public flag is kept. The server
   serves legacy artifacts to the owner only, as it does today.
2. On the owner's first sign-in to the new version, the server accepts the old
   password once, which is the last time it sees a password, and switches the
   account to `authKey`. Then the client generates keys and shows the recovery
   code.
3. `cairn migrate encrypt` on the command line downloads each legacy artifact, encrypts
   it locally, uploads it, and asks the server to delete the plaintext copy.
   Browser sign-in can offer the same step for small artifacts.

## What breaks

- The HTTP API changes: the database endpoints, zip upload, and API keys an
  administrator creates all go. Only the `cairn.js` API and the `cairn`
  commands keep their shape.
- `shell.html` and the administration artifact list are rendered on the
  client, because the server cannot read names.
- The fork diverges sharply from upstream `aloisdeniel/cairn`, so merging
  later upstream changes becomes manual work.

## Milestones

Each milestone ships with its tests and leaves the server working.

| # | Milestone | Proof it works |
| --- | --- | --- |
| 1 | Crypto core — the Go package `internal/e2e` and a JavaScript module | Go and Node check the same test vectors in both directions |
| 2 | Accounts: prelogin, `authKey`, key bundles, recovery, split API keys, device keys for the `cairn` tool | Integration test: claim, sign in, `cairn login`, administrator reset, recovery restores data |
| 3 | Ownership and sharing: owner, members, roles, epochs, private by default | Integration test: user B cannot list or read A's artifact until A shares it |
| 4 | Encrypted content, content origins, service worker, TLS flags, `frame.js` | Headless Chrome: a private artifact renders, and the files on disk are ciphertext |
| 5 | Client-side database and files, bundled sql.js, `cairn db` commands | Every example works; two concurrent writers both land |
| 6 | App UI: your artifacts, artifacts shared with you, share dialog, API keys, recovery | Headless Chrome walkthrough of the share flow |
| 7 | Migration and docs: `migrate`, README, skill, `CLAUDE.md` invariants | Migrate a copy of your real data directory, then compare every artifact |

## Decisions to confirm

1. **One origin per artifact.** Each artifact gets its own subdomain, which
   needs wildcard DNS and a wildcard certificate at the proxy. The cheaper
   alternative is one shared content origin: shared artifacts could still
   not reach your keys, but they could read each other's. Recommended: one
   origin per artifact.
2. **Client-side database with whole-database writes.** This fits artifact
   databases up to tens of megabytes, and gets slow beyond that.
3. **PBKDF2 rather than Argon2id.** PBKDF2 is native in browsers. Argon2id
   resists GPU cracking better, but needs a WebAssembly module.
4. **Roles and public writes.** `viewer` and `editor` roles, and a per-artifact
   switch that lets any signed-in user write to a public artifact's database.
   Keep that switch on for existing public artifacts, so guestbook-style apps
   keep working.
5. **Encrypted metadata.** Names, descriptions, changelogs, resource values,
   and file names are all encrypted.
6. **Hard divergence from upstream.** This is acceptable in exchange for the
   preceding decisions.
