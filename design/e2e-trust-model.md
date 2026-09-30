# End-to-end encrypted trust model

Status: **decisions agreed**. Nothing in this document is implemented yet.

## Goal

Today every signed-in user can read and write every artifact, and the server
holds all content in plaintext. This design reverses that, for a team instance
hosted in GCP where every member can publish:

- An artifact is private to its owner by default.
- The owner can share it with named users, with the whole team, with anyone
  holding a link, or make it public.
- The server stores only ciphertext for private and shared artifacts. An
  administrator, the owner's manager, an operator with access to the GCP
  project, or anyone holding a backup or disk snapshot cannot read them.
- No administrator can recover a user's data, and neither can several acting
  together. Only the user, or a successor the user chose, can.
- Cairn can run behind a reverse proxy or load balancer that terminates TLS.

## Threat model

### What the design protects

| Adversary | Can read private content? |
| --- | --- |
| A Cairn administrator using the administration UI or API | No |
| Two or more administrators acting together | No |
| An operator with the data directory, a backup, or a disk snapshot | No |
| Someone who controls the user's mailbox | No. They can reset the password and take over the account, but not read existing work |
| Another signed-in user who has no share | No |
| A shared artifact written by another user, running in your browser | Only that artifact, which you can already read |
| The successor the user nominated | Yes, 14 days after asking, unless the user refuses |

### What the design does not protect

State these limits in the README, because they are inherent to encryption in
a web app:

- **The server delivers the JavaScript that does the crypto.** An operator who
  modifies the served code can capture keys the next time a user signs in. The
  `cairn` command-line tool does not have this weakness, because it runs its
  own code. [Deploy integrity](#deploy-integrity) makes such a change
  visible, not impossible.
- **Metadata stays visible:** user emails and names, artifact IDs, owners,
  who shares with whom, the public flag, timestamps, and approximate sizes.
- **The server can delete data or serve an older copy.** Authenticated
  encryption stops forged or swapped content, but it cannot prove freshness.
- **The server could substitute a public key** when you share with someone.
  The share dialog shows key fingerprints and warns when a pinned key changes,
  which turns this into a detectable attack rather than a silent one.
- **Public means public.** A public artifact's key is stored in the clear so
  anonymous visitors can read it, and so can an administrator. A link share
  keeps the key out of the server's reach instead.
- **The successor's waiting period is enforced by the server.** A successor
  working with an administrator who can edit the database could skip it. The
  user chose that one person, and can remove them at any time.
- **Losing both the password and the recovery code loses the user's private
  work.** This is the price of no administrator recovery, and the sign-up
  screen says so.

## Key hierarchy

```text
password ──Argon2id──► stretched ──HKDF──┬─► authKey  (sent to server, bcrypt-stored)
                                         └─► kek      (never leaves the client)

recovery code ──HKDF──► recoveryKek

MK (random 256-bit master key)
  ├─ stored as AES-GCM(kek, MK) and AES-GCM(recoveryKek, MK)
  ├─ wrapped to the successor's X25519 public key, if the user nominated one
  ├─ wraps the user's X25519 private key
  └─ derives indexKey (HMAC) for resource lookups

AK (random 256-bit artifact key, one per artifact per epoch)
  ├─ wrapped to each member's X25519 public key (owner included)
  ├─ carried after the # of a link share, never sent to the server
  ├─ stored in the clear while the artifact is public
  └─ derives one key per blob: HKDF(AK, blobID)
```

WebCrypto and the Go standard library provide every primitive below except
Argon2id. The browser gets Argon2id from a WebAssembly module vendored into
the binary, as Mermaid is; Go gets it from `golang.org/x/crypto/argon2`.

- Argon2id with 64 MiB of memory, 3 passes, and a per-user random salt. The
  parameters are stored per user, so they can be raised later without
  breaking existing accounts. Argon2id resists GPU guessing far better than
  PBKDF2, which matters because disk snapshots are exactly what an offline
  attacker would start from.
- HKDF-SHA256 for every derived key.
- AES-256-GCM for all symmetric encryption.
- X25519 plus HKDF plus AES-GCM for wrapping a key to a user (ECIES).
- Content blobs use 64 KiB chunks, each with its own GCM tag, so the client can
  seek and stream. The associated data binds each blob to its artifact,
  version, and path, so the server cannot swap one file for another.

The recovery code is 128 random bits shown as base32 groups. It has enough
entropy to skip stretching.

## Accounts and sign-in

The server never sees the password or anything it could derive `kek` from.

1. The client calls `POST /api/auth/prelogin` with an email and receives the
   salt and Argon2id parameters. For an unknown email the server returns a
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

### Self-signup

Self-signup replaces first-login-sets-password, and administrators no longer
create accounts.

1. Anyone with an address in an allowed domain signs up at `/signup` with an
   email and a password. `--signup-domain` sets the allowed domains; without
   it, self-signup is off, so a server on the internet is never open to
   everyone by accident.
2. The client generates `MK`, the key pair, and the recovery code, then
   uploads only wrapped material.
3. The client shows the recovery code, offers it as a download, and asks the
   user to retype one group to prove they saved it. The screen states that
   nobody, including an administrator, can recover their work without the
   password or this code.
4. The server emails a single-use verification link. The account stays
   inactive until the user follows it.

The address given by `--admin-email` receives the administrator role when it
signs up. `--admin-password` goes away, because a password the server chose
would give the server `kek`. Administrators can grant and remove roles and
deactivate accounts. They cannot set passwords or change a user's email.

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

### Password reset and recovery

There is no administrator reset and no administrator recovery of any kind. A
route that let an administrator into one user's data, even a user who has
left, would let them into anyone's.

1. **Forgot password** emails a single-use link that expires after 30
   minutes. The server stores only a hash of its token.
2. The link lets the user choose a new password. It proves control of the
   mailbox and nothing more, so it never carries key material: the server
   writes the email, and mailbox administrators can read it.
3. The client then asks for the recovery code.
   - With the code, the client unwraps `MK` and wraps it again under the new
     password. Nothing is lost, and the key pair stays the same, so nobody
     sees a key-change warning.
   - Without the code, the client generates a new `MK` and key pair. The
     user's old private work stays unreadable. Artifacts others shared with
     them can be shared again after the sharer sees the key-change warning and
     checks the new fingerprint. The user can delete the unreadable artifacts.

While signed in, a user can generate a new recovery code, which replaces the
recovery-wrapped `MK`. A user changes their own email by following a link sent
to the new address.

An administrator can still deactivate and delete accounts and artifacts. The
administrator can deny service, but cannot read.

A passkey that supports the WebAuthn PRF extension can later wrap `MK` too, so
a forgotten password usually costs nothing. That is a later milestone.

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
| Write database and files | Yes | Yes | No | If public and public writes are on | No |
| Push a version | Yes | Yes | No | No | No |
| Share, unshare, publish, delete | Yes | No | No | No | No |

Public writes are a per-artifact switch. It is on for artifacts that were
public before migration, so guestbook-style apps keep working, and off by
default for new artifacts.

The owner has four ways to share:

- **Named users**, each as `viewer` or `editor`.
- **The whole team.** The client wraps `AK` to every member's public key. A
  member who joins later receives it the next time someone with access opens
  the artifact.
- **Anyone with the link.** The link carries `AK` after the `#`, which
  browsers never send, so the server never sees it. Link holders read as
  viewers.
- **Public.** The server holds `AK` in the clear, and anonymous visitors can
  read without a key in the link. Use this for material meant for everyone.

Epochs handle revocation. When the owner removes a member, disables a link, or
makes a public artifact private, the client creates a new `AK` epoch and wraps
it to the remaining members. New writes use the new epoch. Earlier content
stays under the old key, since the removed party could already read it.

### Key-change warnings

To share, the owner's client fetches the recipient's public key, shows its
fingerprint, and pins it in the owner's own encrypted keyring. When a pinned
key changes, the client warns before sharing again, and the owner compares the
fingerprint with the recipient directly, as Signal does with safety numbers.

This is what protects shares if an administrator edits the database to take
over an account. Recovery with the recovery code keeps the original key pair,
so a warning always means something changed that the owner should check.

## When someone leaves

Changing a leaver's email and resetting their password gets into the account,
but not the data, exactly as for any other reset without the recovery code.

- **Shared work survives.** Everyone an artifact was shared with already holds
  its key, and a departure takes nothing from them.
- **Ownership transfer.** An administrator can make any existing editor the
  owner. The editor already holds `AK`, so this changes a record without
  granting new access.
- **Private work needs a successor.** Without one, it is unrecoverable, and
  the administrator can delete it.

### Successor

A user can nominate one other user as their successor, or nobody. This is the
only route to someone else's private work, and only the owner can open it.

1. The user picks a successor. Their client shows the successor's fingerprint,
   wraps `MK` to the successor's public key, and uploads the result. The
   server stores it but does not release it.
2. The successor asks for access. The server records the time and emails the
   user.
3. For 14 days, the user can refuse from any signed-in session, which cancels
   the request.
4. After 14 days without a refusal, the server releases the wrapped `MK` to the
   successor, whose client unwraps it and can read everything the user could.
   An administrator can then transfer ownership to the successor.

The user can change or remove their successor at any time; removal deletes the
wrapped copy. A reset without the recovery code creates a new `MK`, so the
client asks the user to nominate their successor again.

Two points sit outside the code:

- Share team work with the team as a norm, so most of what matters survives a
  departure without a successor.
- Check the company's retention policy. Private work here is unrecoverable by
  design, apart from the successor.

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
   `frame.js` takes over what `shell.js` does today: external links open in a
   new tab, links to other Cairn pages ask the shell by `postMessage` to
   replace the whole page, and documents with diagrams get Mermaid. These move
   because the shell can no longer reach into a cross-origin frame.

Full-screen view becomes an app-origin page with the shell chrome hidden, so
the same key handover works, and so do links and Mermaid. Today, full screen
opens the artifact directly and draws no diagrams unless the artifact loads
Mermaid itself.

A link share works the same way for anonymous visitors: the shell reads `AK`
from the `#` and hands it over. Public artifacts skip all of this: the server
holds the plaintext `AK`, so it decrypts and serves them directly, and
anonymous visitors need no service worker.

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
- `--signup-domain example.com` turns on self-signup for that domain, and may
  be repeated.
- `--smtp-url smtp://user:pass@host:587` sets the mail server for
  verification and reset links. Self-signup requires it.

Per-artifact origins need a wildcard DNS record and a wildcard certificate.

- **GCP, the target deployment.** Cloud DNS holds the wildcard record, and
  Certificate Manager issues the wildcard certificate with DNS authorization
  for an external HTTPS load balancer. Cairn keeps its data in SQLite and a
  local directory, so it runs on a Compute Engine VM or a single-replica GKE
  workload with a persistent disk, not on Cloud Run. Mail goes through the
  Google Workspace SMTP relay or a provider such as SendGrid.
- **Self-hosting.** The repository gains an example Caddy configuration and a
  Compose service. A wildcard certificate there means an ACME DNS challenge.
  Document that trade-off plainly.

## Deploy integrity

An administrator who can deploy modified code can capture keys, and no web app
design prevents that. These measures make it leave a trace:

- **Only CI builds release images.** It builds them from the repository and
  signs them, and GCP Binary Authorization refuses any other image.
- **The Cairn administrator role and GCP deploy rights are held by different
  people**, or deploys need a second approver.
- **`cairn verify`** compares the web assets the server delivers with the
  signed release manifest. It runs on the user's own machine, where the server
  cannot tamper with it.

With these in place, the promise to users is: an administrator cannot read
your work without leaving a trace in the deploy history.

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
- Administrators lose password reset, account creation, and
  `--admin-password`. First-login-sets-password becomes self-signup, so the
  `CLAUDE.md` invariant that describes it changes.
- Self-signup and password reset need a mail server, which Cairn has never
  needed before.
- `shell.html` and the administration artifact list are rendered on the
  client, because the server cannot read names.
- The fork diverges sharply from upstream `aloisdeniel/cairn`, so merging
  later upstream changes becomes manual work.

## Milestones

Each milestone ships with its tests and leaves the server working.

| # | Milestone | Proof it works |
| --- | --- | --- |
| 1 | Crypto core — the Go package `internal/e2e`, a JavaScript module, and vendored Argon2id | Go and Node check the same test vectors in both directions |
| 2 | Accounts: self-signup, mail, verification and reset links, prelogin, `authKey`, key bundles, recovery code, split API keys, device keys for the `cairn` tool | Integration test: sign up, verify, sign in, `cairn login`; a reset with the code keeps the key pair, one without it gets a new one; no administrator endpoint can set a password |
| 3 | Ownership and sharing: owner, members, roles, team and link shares, epochs, key-change warnings, ownership transfer, private by default | Integration test: user B cannot list or read A's artifact until A shares it; a changed key blocks a silent re-share |
| 4 | Encrypted content, content origins, service worker, TLS flags, `frame.js` | Headless Chrome: a private artifact renders, and the files on disk are ciphertext |
| 5 | Client-side database and files, bundled sql.js, `cairn db` commands | Every example works; two concurrent writers both land |
| 6 | App UI: your artifacts, artifacts shared with you, share dialog, API keys, recovery code, successor settings | Headless Chrome walkthrough of the share flow |
| 7 | Successor: nomination, request, 14-day wait, refusal, release | Integration test with a fake clock: a refusal on day 13 blocks access; silence until day 14 releases it, and the successor reads a private artifact |
| 8 | Deploy integrity and GCP: signed CI images, `cairn verify`, deployment guide | `cairn verify` passes against a release and fails when one served file changes |
| 9 | Migration and docs: `migrate`, README, skill, `CLAUDE.md` invariants | Migrate a copy of your real data directory, then compare every artifact |

Passkey unlock through the WebAuthn PRF extension follows as a later
milestone.

## Decisions

1. **One origin per artifact.** Team members publish, and an artifact shared
   with you must not be able to read your other work. Only separate origins
   guarantee that. The wildcard DNS record and certificate cost little on GCP.
2. **Client-side database with whole-database writes.** This fits artifact
   databases up to tens of megabytes, and gets slow beyond that. Team
   artifacts are small.
3. **Argon2id rather than PBKDF2**, for its resistance to offline guessing
   from snapshots, at the cost of a vendored WebAssembly module.
4. **Roles, sharing, and public writes.** `viewer` and `editor` roles; team,
   link, and public sharing; public writes on for existing public artifacts
   and off by default for new ones.
5. **Encrypted metadata.** Names, descriptions, changelogs, resource values,
   and file names are all encrypted. Titles alone would tell a manager a great
   deal.
6. **Hard divergence from upstream**, after offering the link-handling and
   Mermaid work upstream.
7. **Self-signup** restricted by domain, with email verification.
8. **No administrator recovery.** Passwords are reset only by an emailed link,
   and data returns only with the recovery code. Two-administrator recovery
   was considered and dropped: two administrators acting together could read
   anyone's work, and making that detectable needed a key holder outside the
   administrator group.
9. **An opt-in successor with a 14-day waiting period**, plus ownership
   transfer to existing editors, for colleagues who leave.
10. **Deploy integrity** through signed CI images, separated roles, and
    `cairn verify`.
