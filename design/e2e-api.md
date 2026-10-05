# End-to-end encryption — HTTP API and commands

Status: **reference for implementation**. This document fixes the endpoints,
request bodies, and command-line flags that the
[trust model](e2e-trust-model.md) describes in prose. Byte formats are in
[wire formats](e2e-wire-formats.md); every field shown as `b64` here is
base64url without padding. Each milestone adds its section.

## Accounts and sessions

Milestone 2 replaces today's accounts. Administrators no longer create
accounts, set passwords, or create API keys.

### Server flags

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--public-url` | `CAIRN_PUBLIC_URL` | The external URL. Every emailed link is built from it, never from a request header. An `https` URL turns on the `__Host-` cookie. Replaces `--base-url`. |
| `--signup-domain` | `CAIRN_SIGNUP_DOMAINS` | An email domain that may sign up. Repeat the flag, or separate domains with commas in the variable. Without one, only `--admin-email` can sign up. |
| `--admin-email` | `CAIRN_ADMIN_EMAIL` | This address may always sign up, and becomes an administrator when it does. |
| `--smtp-url` | `CAIRN_SMTP_URL` | `smtp://[user:pass@]host:port`, or `log://` to write each message to the server log. Required. |
| `--mail-from` | `CAIRN_MAIL_FROM` | The sender address. Defaults to `cairn@` followed by the public URL's host. |

`--admin-password` is removed. A server started without `--smtp-url` refuses
to start, because sign-up and reset cannot work without mail.

### Data directory

The new schema applies to fresh data directories only. A data directory
whose `users` table already holds rows from an earlier server is refused at
startup, with a message that points at `cairn import`.

### Common rules

- **Addresses** are normalized before every lookup and comparison, as
  `normalize` in [wire formats](e2e-wire-formats.md#password-stretching)
  describes. Only ASCII letters are lowercased, so two addresses that differ
  by any other case belong to different accounts. The domain is everything
  after the last `@`. A domain matches `--signup-domain`, normalized the same
  way, exactly; subdomains are not included.
- **Errors** are `{"error": "message"}` with the status shown. Rate-limited
  requests get `429` with a `Retry-After` header in seconds.
- **Request protection** applies to every `POST`, `PUT`, `PATCH`, and `DELETE`
  under `/api/` that does not carry an `Authorization` header, including the
  unauthenticated endpoints below:
  - `Content-Type` must be `application/json`, or `application/octet-stream`
    for a file or an encrypted blob, otherwise `415`. A browser cannot send
    either type to another site without a preflight request, which Cairn
    never approves. A `DELETE` with no body skips this check, because a
    browser cannot send a `DELETE` to another site without a preflight
    either. `multipart/form-data` passes too when `Sec-Fetch-Site` is
    `same-origin`: the browser uploads a version, a database revision, or a
    stored file that way, and a form posted from another site cannot carry
    that header.
  - If `Sec-Fetch-Site` is present, it must be `same-origin`. If it is absent
    and `Origin` is present, `Origin` must equal the public URL's origin.
    Otherwise `403`.
- **Session cookie.** `__Host-cairn_session` when the public URL is `https`,
  otherwise `cairn_session`. Always `HttpOnly`, `Path=/`, `SameSite=Strict`,
  and `Secure` under `https`. It holds a JWT whose `tkv` claim is the user's
  token version, as today.
- **Rate limits** count failures in a sliding 15-minute window, measured on
  the server's clock:
  - Five failed sign-ins per account, and 20 per client IP address. The next
    attempt in the window gets `429`, even with the right key.
  - Three emails per address per hour, across sign-up, verification, and
    reset. Requests over the limit still answer as if they succeeded.
- **Timing.** Sign-in runs bcrypt against a fixed dummy hash for an unknown
  account, so the response time does not reveal whether it exists.

### Key bundle

A user's wrapped key material, written by the client at sign-up and returned
at sign-in. The server checks lengths and the parameter floor, and nothing
else; it cannot check the contents.

```json
{
  "kdf": {"alg": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": "b64"},
  "mkPassword": "b64, MK sealed under kek",
  "mkRecovery": "b64, MK sealed under recoveryKek",
  "x25519Pub": "b64, 32 bytes",
  "x25519Priv": "b64, sealed",
  "ed25519Pub": "b64, 32 bytes",
  "ed25519Priv": "b64, sealed",
  "ek": "b64, sealed"
}
```

Each sealed 32-byte key is 61 bytes. A request with any other length gets
`400`.

### Tokens in emailed links

Verification and reset links carry a 32-byte random token in the URL
fragment, which browsers never send to a server:

- Verification: `<public-url>/verify#token=<b64>`, valid for 24 hours.
- Reset: `<public-url>/reset#token=<b64>`, valid for 30 minutes.

The server stores only `hex(SHA-256(token))`. A token works once. The page
reads the fragment and posts the token in a JSON body.

### Endpoints

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `POST /api/auth/signup` | None | Create an unverified account |
| `POST /api/auth/verify` | None | Follow a verification link |
| `POST /api/auth/prelogin` | None | Get the salt and parameters |
| `POST /api/auth/login` | None | Sign in |
| `POST /api/auth/logout` | Session | Sign out |
| `POST /api/auth/forgot` | None | Send a reset link |
| `POST /api/auth/reset/begin` | None | Read what a reset needs |
| `POST /api/auth/reset/complete` | None | Finish a reset |
| `GET /api/me` | Any | The signed-in user |
| `GET /api/me/bundle` | Any | The user's key bundle |
| `PUT /api/me/password` | Session | Change the password |
| `PUT /api/me/recovery` | Session | Replace the recovery code |
| `GET /api/me/archives` | Any | Bundles archived by a reset |
| `GET /api/keys` | Any | The user's own API keys |
| `POST /api/keys` | Session | Create an API key |
| `DELETE /api/keys/{id}` | Any | Revoke one of the user's own keys |
| `GET /api/users` | Any | The user directory, with public keys |
| `GET /api/users/{id}` | Any | One user, with public keys |
| `GET /api/admin/users` | Administrator | All accounts, including unverified |
| `PATCH /api/admin/users/{id}` | Administrator | Grant or remove a role; deactivate |
| `DELETE /api/admin/users/{id}` | Administrator | Delete an account |

"Session" means the cookie, or a JWT from sign-in in the `Authorization`
header. "Any" adds an API key. There is no other administrator endpoint for
users or keys.

#### Sign-up

`POST /api/auth/signup`:

```json
{"email": "ada@example.com", "name": "Ada", "authKey": "b64", "bundle": {}}
```

- `400` when the bundle is malformed or below the floor, or `name` is longer
  than 200 characters. `403` when the domain is not allowed.
- Otherwise always `202 {"status": "check-email"}`. The answer is the
  same whether or not the address has an account, so sign-up does not reveal
  which addresses do.
  - New address: create the unverified account and email a verification
    link.
  - Unverified account: replace it with this one, and email a new link.
  - Verified account: change nothing, and email the owner that someone tried
    to sign up with their address.

`POST /api/auth/verify` with `{"token": "b64"}` marks the account verified,
or gets `400` for an unknown, used, or expired token.

#### Sign-in

`POST /api/auth/prelogin` with `{"email": "…"}` returns the user's `kdf`
object. For an address with no verified account it returns the default
parameters and the salt `HMAC-SHA256(serverSecret,
enc("cairn/v1/prelogin", email))`, cut to 16 bytes, so the response looks
the same and stays stable across calls. `email` is normalized first, as the
wire-format spec describes, so changing the case of an address does not
change the fake salt. The fake response always uses the current default
parameters, so raising the defaults raises them for fake responses too.

`POST /api/auth/login`:

```json
{"email": "ada@example.com", "authKey": "b64", "client": "cli"}
```

- `401 {"error": "invalid email or password"}` for an unknown account or a
  wrong key. Both count as failures for the rate limits.
- After a correct key: `403` with `"verify your email first"` or
  `"account deactivated"`.
- `200` sets the session cookie and returns:

  ```json
  {"user": {}, "bundle": {}, "token": "JWT, only when client is cli"}
  ```

  The JWT appears in the body only for `"client": "cli"`, so a browser page
  never holds it in script.

#### Password reset

1. `POST /api/auth/forgot` with `{"email": "…"}` always answers
   `202 {"status": "check-email"}`. For a verified account it emails a reset
   link.
2. `POST /api/auth/reset/begin` with `{"token": "b64"}` checks the token
   without using it, and returns `{"id", "email", "mkRecovery",
   "x25519Pub", "ed25519Pub", "ed25519Priv"}`. The token stays valid for
   `complete`. The `id` and the sealed `ed25519Priv` let a device that holds
   only the link and the recovery code sign the proof. Opening the key needs
   `MK`, so the response reveals no more than `mkRecovery` already does.
3. `POST /api/auth/reset/complete` uses the token, in one of two modes:
   - **With the recovery code**:

     ```json
     {"token": "b64", "mode": "recovery", "authKey": "b64",
      "kdf": {}, "mkPassword": "b64", "proof": "b64"}
     ```

     `proof` is a signature with purpose `reset` from the user's existing
     Ed25519 key, which only the holder of `MK` can produce. The server
     verifies it, then replaces `authKey`, `kdf`, and `mkPassword`. The key
     pairs, the recovery wrap, and API keys stay.
   - **Without it**:

     ```json
     {"token": "b64", "mode": "new", "authKey": "b64", "bundle": {}}
     ```

     The server archives the whole current bundle and the wrapped `MK` of
     every API key, revokes every API key, stores the new bundle, deletes the
     user's keyring, and sets the user's `resetAt` to now. The keyring was
     sealed under the old `MK`, so `GET /api/me/keyring` answers rev 0 and
     empty afterward. With the recovery code, `MK` is unchanged and so is
     the keyring.

   Both modes increase the token version, which signs out every other
   session, and email the user that the password was reset.

#### Signed-in account

- `GET /api/me` returns `{"id", "email", "name", "isAdmin", "createdAt",
  "resetAt"}`. `resetAt` is empty unless a reset without the recovery code
  happened.
- `GET /api/me/bundle` returns the bundle. With an API key it adds
  `"apiKey": {"id", "mk"}`, where `mk` is that key's sealed `MK`.
- `PUT /api/me/password` takes `{"authKey", "newAuthKey", "kdf",
  "mkPassword"}`. `authKey` is the current one; a wrong one is a sign-in
  failure for the rate limits. The token version increases and a new cookie
  is set.
- `PUT /api/me/recovery` takes `{"authKey", "mkRecovery"}`.
- `GET /api/me/archives` returns `[{"id", "archivedAt", "bundle",
  "apiKeys": [{"id", "mk"}]}]`, newest first. The client restores the old
  `MK` by opening the archived `mkRecovery` with the old recovery code.

#### API keys

`POST /api/keys`:

```json
{"authKey": "b64", "name": "laptop", "device": true,
 "keyId": "16 hex", "authSecret": "32 hex", "mk": "b64"}
```

The client generates all three parts and sends `keySecret` to nobody. The
server checks `authKey`, the formats, and that `keyId` is unused, then stores
`hex(SHA-256(authSecret))` and `mk`. It answers `201 {"id", "name",
"device", "createdAt"}`.

The bearer for later requests is `cairn_<keyId>_<authSecret>`.
`GET /api/keys` returns `[{"id", "name", "device", "createdAt",
"lastUsedAt"}]`, without revoked keys.

#### Directory and administration

- `GET /api/users` lists verified, active users as `{"id", "name", "email",
  "x25519Pub", "ed25519Pub", "resetAt"}`. Clients compute fingerprints.
- `GET /api/admin/users` adds `isAdmin`, `disabled`, `verified`, and
  `createdAt`, and includes unverified accounts.
- `PATCH /api/admin/users/{id}` takes `{"isAdmin": bool, "disabled": bool}`,
  either optional. Deactivating increases the token version, which signs the
  user out everywhere, and blocks their API keys.

### Pages

The app pages are `/signup`, `/verify`, `/login`, `/forgot`, `/reset`, and
`/admin`. They send this Content Security Policy, and load scripts only from
files:

```text
default-src 'self'; script-src 'self' 'wasm-unsafe-eval';
object-src 'none'; base-uri 'none'; frame-ancestors 'none';
form-action 'self'; require-trusted-types-for 'script'
```

Milestone 4 adds `frame-src` for the content domain. The pages do password
stretching in a worker, keep unwrapped keys in IndexedDB as non-extractable
`CryptoKey` objects, and clear IndexedDB at sign-out. WebKit silently drops a
record that holds an X25519 `CryptoKey`. Sign-in therefore reads the record
back, and where it is missing, stores the X25519 private key encrypted under
a non-extractable AES-GCM key instead, to be unwrapped into a non-extractable
key when the record is loaded. Script on the app origin could unwrap that
copy as extractable, so it is used only where the browser leaves no choice.
Sign-in fails if the browser stores neither record. Sign-out keeps the
[keyring anchor](e2e-wire-formats.md#the-keyring) in `localStorage`, because
it holds nothing secret and the next sign-in needs it. The sign-up and reset
pages refuse a password that the vendored strength estimator scores below 3.

### Commands

Every command that prompts for a password also accepts `--password-stdin`,
which reads one line. Scripts and tests use it.

| Command | Does |
| --- | --- |
| `cairn signup --host URL --email E [--name N]` | Generates keys, signs up, and prints the recovery code |
| `cairn confirm-email LINK` | Follows a verification link |
| `cairn login --host URL --email E` | Signs in, creates a device key, and saves it |
| `cairn logout` | Revokes the device key and forgets it, but keeps the keyring anchor |
| `cairn whoami` | Prints the user and their fingerprint |
| `cairn forgot --host URL --email E` | Asks for a reset link |
| `cairn reset LINK (--recovery-code CODE \| --no-recovery-code)` | Sets a new password; keeps the keys only with the code |
| `cairn keys list` | Lists the user's API keys |
| `cairn keys revoke ID` | Revokes one |

`cairn signup` asks the user to retype one group of the recovery code, unless
`--password-stdin` is set. `cairn reset --no-recovery-code` warns that the
user's own artifacts become unreadable, and needs `--yes` when standard input
is not a terminal.

The config file stores the host, the email, the full four-part API key, and
the keyring anchor for each account, which `cairn logout` keeps.
`CAIRN_API_KEY` holds the same four-part string.

## Ownership and sharing

Milestone 3 gives every artifact an owner, members, signed membership
records, and wrapped keys. Content stays as it is until milestone 4 encrypts
it, but the keys, the records, and the access rules are final. Every check
below is for access and consistency. Clients still verify every record
themselves, because the server is not trusted to.

### Access

The server checks each request against these access levels:

1. **Owner.** The caller is `artifacts.owner_id`.
2. **Member.** The caller is listed in the latest membership record, as
   `editor` or `viewer`. A member whose current fingerprint differs from the
   record's `fp` for them, after a rotation or a reset, can read but not
   write, until the owner lists them again under the new fingerprint.
3. **Team member.** The record's `team` is not `none`, the caller holds a
   wrap for the current epoch, and the record does not list them. This is
   `viewer` access until the owner lists them. A team member without a wrap
   has no access at all.
4. **Link holder.** The artifact is public, and the request carries
   `X-Cairn-Link-Token` whose hash matches. A link holder who is also signed
   in can write the database and files while public writes are on.
5. **None.**

A request may do whatever any level that matches allows. A signed-in viewer
who also presents the link token can therefore write while public writes are
on. `access` in a response names the first level that matches.

What each level may do is the permission table in the
[trust model](e2e-trust-model.md#ownership-sharing-and-epochs). Two rules sit
on top of it:

- A request with no access gets `404`, never `401` or `403`, so a
  non-administrator cannot tell whether the artifact exists. An administrator
  gets the same `404`, but can list a user's artifacts through
  `GET /api/admin/users/{id}/artifacts`.
- The `{id}` segment of an artifact route resolves only among artifacts the
  caller can read, so a resource reference cannot reveal someone else's
  artifact through a `409`.

Share, unshare, make public, transfer, delete, and push need a session or an
API key. Milestone 4 adds a content-origin token, scoped to one artifact. It
is a sign-in JWT with an `art` claim that names its artifact. It works on an
allowlist, and every other route, API or page, refuses it with `404`:

- Reads of its own artifact's versions, database, and files.
- Writes to its own artifact's database and files, where the role allows
  them.
- `GET /api/artifacts/{id}/membership` for its own artifact, and
  `GET /api/users/{id}` for each user its latest record lists. A
  `GET /api/users/{id}` request for anyone other than the latest record's
  owner and members answers `404`.
- `GET /api/me`.

Milestone 3 builds the allowlist check, and tests it with a token the test
mints, so the list is fixed before milestone 4 issues real tokens.

In this milestone the browser cannot open a public link yet. The milestone 4
service worker sends `X-Cairn-Link-Token` on each request.

### Membership records

A membership record is the `membership` envelope from
[wire formats](e2e-wire-formats.md#signatures). The server accepts a record
only when all of these hold:

- It verifies under the owner's current Ed25519 public key, and the body
  parses strictly.
- `artifact` is the artifact, `owner` is its owner, and `ownerFp` is the
  owner's current fingerprint.
- `seq` is one more than the latest record's, or 1 for the first.
- `prev` is `hex(SHA-256)` of the latest record's body, or empty for the
  first. A stale `prev` gets `409`, so two concurrent changes cannot both
  land.
- `members` is sorted by user ID, has no duplicates, and does not list the
  owner. Each role is `viewer` or `editor`, and `team` is `none`, `viewer`, or
  `editor`.
- `excluded` is sorted by user ID and has no duplicates. No entry names the
  owner, and no entry matches a member by user ID, fingerprint, or
  normalized email.
- For each member the previous record does not list, and each member whose
  `fp` differs from the previous record's, `fp` is the fingerprint of that
  user's current keys. Such a member must be a verified, active user, and no
  other user ID may share their fingerprint or normalized email. The server
  does not check `fp` for anyone else, so a member who rotates their keys
  stays listed under the old `fp` until the owner updates it.
- `epoch` is either the current epoch or the next one.
- `transfer` and `handover` are empty. Only an accepted transfer sets them.

A record at the **same epoch** keeps `akCommit`. It can add members, promote
a viewer, change `team`, turn public writes on or off, and make the artifact
public. It cannot remove a member, demote an editor, make a public artifact
private, or add a user to `excluded`. So it cannot change `team` to `none`
while a team member holds a wrap, because that drops the team member.

A record at the **next epoch** has a new `akCommit`. It is required to remove
a member, demote an editor, make a public artifact private, or change `team`
to `none` while a team member holds a wrap. It is allowed at any other time.

A next-epoch record must list or exclude every team member who holds a wrap.
The owner's client lists, with the role that `team` grants, each one whose
approval passes the checks in [Team approval](#team-approval), and asks the
owner about the rest. `cairn` cannot ask, so it excludes the rest and prints
each with the reason; excluding fails closed, and the owner lists one again by
name with `cairn share`. A team member whose keys changed after they were
wrapped to is excluded under the fingerprint in the owner's pin, because the
server accepts only a fingerprint it can account for. With no pin for an
earlier key, the client refuses and tells the owner to share with them by
name, then remove them. Every user a record
removes or drops goes into `excluded` under their fingerprint and normalized
email. The entry stays there until an owner record lists them again. The
server refuses a record that leaves a removed member or a team member out of
both lists, and a record that drops a user from `excluded` without listing
them. The owner's client lists a user who matches an entry only when the
owner shares with them by name, which drops the entry.

Each change carries the wraps it needs, and the server refuses a change whose
wraps do not match exactly:

| Change | Wraps required |
| --- | --- |
| Same epoch | Every epoch, for each listed member the record adds |
| Next epoch | The new epoch, for every listed member; and every earlier epoch, for each listed member the record adds |

A record **adds** a member, for every epoch, when that member holds no wrap
for that epoch under their current fingerprint. That covers a new member, a
member whose key changed through a reset, and a previous owner kept as an
editor. A wrap that members re-made for themselves when they rotated their
keys counts, so updating a rotated member's `fp` needs no new wrap.

A next-epoch record lists every member under their current fingerprint, so
the owner lists a member whose key changed under the new `fp` or removes them.
The owner's client refuses a next-epoch change while a member it keeps is
listed under an old fingerprint, or under keys that contradict the owner's
pin, and names the member. A member whose account was deleted cannot be
wrapped to, so the client refuses to keep them and names their user ID, which
`cairn unshare` accepts. Their `excluded` entry carries that ID in place of an
email, because the server takes any email for a user it no longer has. It
takes any for a deactivated user too, whom no client can read from the
directory.

When the artifact stays public across a next epoch, the new record carries the
hash of the new epoch's link token, and the client prints the new link; the
old link stops working.

The owner holds no wraps. The owner reads every epoch through the estate
copy.

A wrap is `{"user", "epoch", "wrapped"}`, 81 bytes in `b64`. The server stores
the recipient's current fingerprint with it. A next-epoch change also carries
the estate copy of the new `AK`, `{"epoch", "sealed"}`, 61 bytes in `b64`.

When a record removes a member, the server deletes that member's wraps. When
a record starts a new epoch, the server also deletes every wrap held by a
user the record does not list.

The server checks every rule in one transaction that locks the artifact row.
Pushes, revisions, file writes, and approvals take the same lock, so none of
them can land between the checks and an epoch change.

Clients check every record again, and refuse the whole chain when any check
fails:

- Each record verifies under the key of the owner it names, as
  [wire formats](e2e-wire-formats.md#signatures) describes. That owner's
  chain is anchored at the client's pin for the creator or the public link's
  `o` for the first record, and at the `fp` the preceding record lists for
  each later owner. The latest record verifies under the current owner's
  current key.
- Each `prev` is the hash of the record before it, and `seq` goes up by one.
- Each `epoch` is the previous one or one more, and `akCommit` changes
  exactly when `epoch` does.
- The chain is at least as long as the `seq` stored in the keyring, and the
  record at that `seq` hashes to the stored `head`. A shorter chain is a
  rollback, and a different hash is a fork.
- A new epoch's `AK` differs from every earlier epoch's `AK`. The server's
  `akCommit` check cannot show this, because the commitment includes the
  epoch.
- A change of owner follows the rules in
  [Ownership transfer](#ownership-transfer).

### Endpoints for sharing

| Method and path | Access | Purpose |
| --- | --- | --- |
| `GET /api/artifacts` | Any | Artifacts the caller can read |
| `POST /api/artifacts` | Any | Create an artifact with its first record |
| `GET /api/artifacts/{id}` | Read | The artifact, with the caller's access |
| `PATCH /api/artifacts/{id}` | Owner, editor | Rename, or change the description |
| `DELETE /api/artifacts/{id}` | Owner | Delete the artifact |
| `GET /api/artifacts/{id}/membership` | Read | Every membership record, oldest first |
| `PUT /api/artifacts/{id}/membership` | Owner | Add a membership record |
| `GET /api/artifacts/{id}/keys` | Owner, member, team member | The caller's wraps |
| `POST /api/artifacts/{id}/keys` | Owner, editor | Approve a team member |
| `GET /api/artifacts/{id}/pending` | Owner, editor | Team members waiting, and changed keys |
| `GET /api/artifacts/{id}/review` | Owner | Versions that need a vouch |
| `PUT /api/artifacts/{id}/versions/{vid}/vouch` | Owner | Vouch for a version |
| `POST /api/artifacts/{id}/transfer` | Owner | Offer ownership to an editor |
| `DELETE /api/artifacts/{id}/transfer` | Owner, offered user | Withdraw or decline the offer |
| `POST /api/artifacts/{id}/transfer/accept` | Offered user | Accept ownership |
| `GET /api/me/keyring` | Any | The sealed keyring |
| `PUT /api/me/keyring` | Any | Replace the sealed keyring |
| `POST /api/me/rotate` | Session | Rotate keys |
| `GET /api/users/{id}/rotations` | Any | A user's rotation records |
| `GET /api/admin/users/{id}/artifacts` | Administrator | Artifacts a user owns |
| `POST /api/admin/artifacts/{id}/transfer` | Administrator | Offer ownership when the owner is deactivated |
| `DELETE /api/admin/artifacts/{id}` | Administrator | Delete when the owner is deactivated |

"Read" is any access level other than `none`. "Any" means any signed-in
caller, as in milestone 2. The version, database, and file endpoints keep
their paths and follow the permission table. A version push records the
pusher.

A version push, a database revision, and a file write each declare the epoch
they were written under. The server refuses any epoch but the current one
with `409`, while it holds the artifact's lock, so a write cannot land under
the old epoch after an epoch change.

Until content is encrypted, the epoch travels in the `X-Cairn-Epoch` request
header, a positive decimal without leading zeros (anything else is `400`),
and the header is optional: `cairn.js` does not send it. A write that omits
it takes the current epoch. Milestone 4 makes it required on a version push,
and milestone 5 on a database revision and a file write. A push compares the
epoch in the same statement that writes the version.

A database exec or batch and a file write that declare an epoch share the
artifact's lock with each other. A membership change takes it exclusively,
so no epoch change lands during one of these writes. The lock is held in
the server process, not in the metadata database, so a slow statement
delays changes to its own artifact only. A database exec or batch holds it
for as long as it runs, and a file write only for the move into place. The
server does not yet record the epoch of these writes. Milestone 5 moves them
into the metadata store and records it.

#### Creating an artifact

`POST /api/artifacts`:

```json
{"id": "UUID", "name": "Poll", "description": "",
 "membership": {"body": "b64", "sig": "b64", "signer": "user ID"},
 "wraps": [{"user": "ID", "epoch": 1, "wrapped": "b64"}],
 "estate": [{"epoch": 1, "sealed": "b64"}]}
```

The client generates the ID, because the first record is signed over it. The
ID must be a random UUID, version 4, or the answer is `400`. An ID already in
use gets `409`. That answer reveals that the ID exists, but a random ID
cannot be guessed, so the leak is negligible.

The record has epoch 1, `seq` 1, an empty `prev`, an empty `excluded`, and
the caller as owner. It may already list members. `wraps` covers every
listed member, and `estate` covers epoch 1. The answer is `201` with the
artifact.

`GET /api/artifacts/{id}` and each entry of `GET /api/artifacts` return:

```json
{"id", "name", "description", "owner", "access", "epoch", "team",
 "public", "publicWrites", "transfer", "createdAt", "updatedAt"}
```

`access` is `owner`, `editor`, `viewer`, `team`, or `link`. `transfer` is
`null`, or `{"to", "by", "at", "offer"}` while an offer is open, where `by` is
`owner` or `admin`. `offer` is the owner's signed offer envelope, which the
offered user hashes into the accepting record, and `null` for an
administrator's offer. `POST /api/artifacts/{id}/transfer` returns the same
object. `PATCH` takes `name` and `description` only; `public` is gone from
both requests.

#### Changing membership

`PUT /api/artifacts/{id}/membership`:

```json
{"membership": {"body": "b64", "sig": "b64", "signer": "user ID"},
 "wraps": [{"user": "ID", "epoch": 2, "wrapped": "b64"}],
 "estate": [{"epoch": 2, "sealed": "b64"}],
 "linkTokenHash": "64 hex"}
```

`linkTokenHash` is `hex(SHA-256(linkToken))` for the record's epoch. It is
required when the record is public, and refused otherwise. The server keeps
one hash, `public_token_hash`, and the epoch it belongs to, `public_epoch`.
Each public record replaces both, and the server deletes both when the
artifact becomes private. A public artifact that moves to a new epoch needs
the new epoch's hash, so the old link stops working.

Any new membership record closes an open offer, because it moves `prev`.

The answer is `200 {"epoch"}`.

`GET /api/artifacts/{id}/membership` returns, in every scope:

```json
{"records": [envelope, ...], "offers": {"64 hex": envelope},
 "owners": {"64 hex": {"x25519", "ed25519"}},
 "rotations": {"user ID": [envelope, ...]},
 "successors": {"seq": envelope},
 "ownerChanges": {"seq": "YYYY-MM-DD"}}
```

- `offers` maps the `transfer` hash in each accepting record to the offer
  envelope it accepted.
- `owners` holds the public keys behind every distinct `ownerFp` in the
  chain, keyed by fingerprint. The client hashes each pair itself, and
  ignores a pair that does not hash to its key.
- `rotations` holds the rotation records, oldest first, of every owner the
  chain names and every member the latest record lists.
- `successors` maps the `seq` of each record whose `handover` is `admin` to
  the previous owner's latest `successor` record, when there is one.
- `ownerChanges` maps the `seq` of each record that sets `transfer` or
  `handover` to the date the server stored it. It is `{}` when there are none.
  The handover notice shows the date.

A link holder can read the records, because every holder of `AK` checks
`akCommit`. A link holder may not be signed in, so cannot read the user
directory. For link scope the answer adds
`"keys": {"user ID": {"x25519", "ed25519"}}` for every listed editor. The
client anchors the owner's chain at the link's `o`, never at keys the server
serves.

A reader needs only `AK` and the chain, so editor keys decide only whose
writes a visitor trusts. The client checks each editor's keys against the
records' `fp` values. It leaves an editor out of its trusted writers when
the keys are missing, which happens after the server deletes the user, or do
not hash to the listed `fp`, which happens after a rotation. The link still
opens. Go `VerifyLinkChain` and JavaScript `verifyLinkChain` return the
chain with the trusted editors' keys, by user ID.

A link holder has no pinned state, so a server can show them an older
prefix of the chain. For example, it can hide a later record that turned
public writes off or removed an editor, as long as the artifact was still
public at the link's epoch. Turning a link off needs a new epoch.

Link verification follows owner key rotations. The answer carries
`rotations` for every owner the chain names, in link scope too, and
`VerifyLinkChain` checks each record's `ownerFp` against them. A record
whose `ownerFp` differs from `o` verifies only when a rotation chain links
`o` to it. So a link made before the owner ran `cairn rotate-keys
--keep-epochs` still opens.

#### Keys

`GET /api/artifacts/{id}/keys` returns the caller's own wraps, or for the
owner the estate copies, with an empty `wraps`:

```json
{"wraps": [{"epoch": 1, "wrapped": "b64", "fp": "64 hex"}],
 "estate": [{"epoch": 1, "sealed": "b64"}]}
```

#### Team approval

`GET /api/artifacts/{id}/pending` lists users the caller's client should ask
about:

```json
[{"id", "name", "email", "x25519Pub", "ed25519Pub", "state", "approval"}]
```

- `new`: the record's `team` is not `none`, and this verified, active user
  holds no wrap for the current epoch, is not listed, and matches no
  `excluded` entry by user ID, fingerprint, or normalized email.
- `approved`: shown to the owner only. The user holds a wrap for the current
  epoch through an approval, and is not listed. `approval` is the signed
  `approval` envelope stored with it, and is `null` in every other state.
- `keyChanged`: the user holds a wrap, or is listed, under a fingerprint that
  is no longer theirs, or holds a wrap through an approval made for one. No
  rotation record the server holds explains the change.
- `rotated`: shown to the owner only. As `keyChanged`, but a chain of
  rotation records leads from the old fingerprint to the current one. The
  owner's client asks whether to start a new epoch, in case the old keys
  leaked, and updates `fp` in its next record.

The client checks `GET /api/users/{id}/rotations` itself in both changed
states, and treats a `rotated` user whose chain does not verify as
`keyChanged`. Excluded users never appear.

The server's word that a user is `approved` is not enough. The owner's client
lists an approved user in its next membership record, with the role that
`team` grants, only when all four of these hold:

1. The approval's signer is the owner, or an editor in the current record:
   their key hashes to the listed `fp`, or a rotation chain links it to that
   key.
2. `artifact` is this artifact, and `epoch` is the current epoch.
3. `user` is the user, and `fp` is the fingerprint of the keys the server
   serves for them.
4. The user matches no `excluded` entry by user ID, fingerprint, or
   normalized email, and no other user ID in the directory shares their
   fingerprint or normalized email.

When any check fails, the client asks the owner about that user by name and
fingerprint, as for a `new` user. It never lists them without asking.

`POST /api/artifacts/{id}/keys` approves a `new` user, after the person at
the client has confirmed their name and fingerprint:

```json
{"user": "ID", "fp": "64 hex", "approval": envelope,
 "wraps": [{"epoch": 1, "wrapped": "b64"}]}
```

`approval` is an `approval` envelope the caller signed. Before it asks, the
caller's client makes the fourth check in the list, and refuses a user who
fails it. The server stores `approval` with the wraps, and refuses the
request with:

- `403` from a viewer or a team member, because a viewer's client never wraps
  keys.
- `409` when the record's `team` is `none`.
- `409` when the user already holds a wrap or is listed. A changed key is
  never a new member. The owner shares again through a membership record that
  lists the new fingerprint.
- `409` when the user matches an `excluded` entry by user ID, fingerprint,
  or normalized email, or another user ID shares their fingerprint or
  normalized email.
- `409` when `fp` is not the user's current fingerprint.
- `400` when `approval` does not verify under the caller's current key, or
  its `artifact`, `epoch`, `user`, or `fp` differs from the artifact, the
  current epoch, or the request.
- `400` unless `wraps` covers every epoch.

The server runs these checks in one transaction that locks the artifact row.

The owner cannot check what a wrap holds. Only the recipient can open it, so a
bad wrap from an approver shows up when the approved user tries to read, and a
new epoch repairs it.

An approved team member can read. They can write only once the owner lists
them, because clients refuse anything signed by someone a record does not
list.

New members receive every epoch, so they read the whole history. That has
two costs:

- An editor's approval grants the whole history, not only what is written
  from then on. An editor can grant as much as the owner can.
- An approval that races a next-epoch record loses its access to the new
  epoch. When the record lands first, the approval's wraps no longer cover
  every epoch, and the server refuses it with `400`. When the approval lands
  first, the owner's client must list or exclude the user, and the server
  refuses a record that does neither. Either way, the user reads the new
  epoch only after an editor approves them again or the owner lists them.

#### Reviewing a removed editor's versions

Removing an editor and demoting an editor to viewer run the same flow, and
both need the next epoch. The owner's client re-encrypts the latest version,
its database, and its files under the new epoch, and signs the new database
revision and file records itself. It then asks the owner to review each
version the editor pushed. `review` and vouches cover versions only. The
owner's own signatures on the re-encrypted revision and records cover the
rest, because clients refuse a revision or a record whose signer is no
longer an editor.

`GET /api/artifacts/{id}/review` lists versions whose pusher is neither the
owner nor a listed editor, and that have no vouch:
`[{"id", "seq", "pushedBy", "createdAt"}]`. A version whose pusher's account
was deleted is listed too, with `pushedBy` set to `null`.

`pushedBy` is a convenience. The owner's client builds its own review list
from the signers of the version manifests, and uses the server's list only
to fetch them. Milestone 4, which adds signed manifests, implements that.

`PUT /api/artifacts/{id}/versions/{vid}/vouch` takes `{"vouch": envelope}`.
The server checks that the owner signed it, and that `artifact` and `version`
match. From milestone 4 on, it also checks `manifest` against the stored
manifest. Until then `manifest` is the empty string, the server refuses any
other value, and it cannot check a vouch against the version's content.
Replacing a version's content deletes its vouch, so the owner's vouch never
covers content they did not review.

Before you vouch, your client checks a manifest's signature under any key
pair whose fingerprint the verified membership chain lists for the signer:
the current directory key, or an old or new key from their rotation records,
so an editor who rotated keys after pushing can still be vouched. A deleted
account, or one an administrator turned off, is in neither place, so your
client refuses the vouch and says the signer's keys are no longer
published. Delete the version, or push its content again yourself.

`GET /api/artifacts/{id}/versions/{vid}` returns `pushedBy` and `vouch`, which
is the envelope or `null`.

#### Ownership transfer

1. The owner offers ownership with `POST /api/artifacts/{id}/transfer`
   `{"to": "user ID", "offer": envelope}`. `offer` is a `transfer` envelope
   the owner signed, with `prev` set to the hash of the latest record's body.
   The user must be a listed editor. While an offer is open, a new one also
   carries `membership`, a same-epoch record that closes the old offer, and
   its `prev` names that record. With no offer open, a request that carries
   `membership` is refused with `409`.
2. An administrator can make an offer with
   `POST /api/admin/artifacts/{id}/transfer` `{"to": "user ID"}`, only while
   the owner's account is deactivated. Otherwise the answer is `409`, because
   an active owner must agree. The user must be a listed editor, or the
   owner's successor after the server has released the estate copy to them.
   A successor who is not a member opens every epoch's `AK` from the
   owner's estate copies, through the `EK` released to them. The server
   emails the owner that an administrator offered their artifact to someone
   else.
3. The offered user accepts with `POST /api/artifacts/{id}/transfer/accept`:
   `{"membership", "wraps", "estate", "linkTokenHash"}`, as for a membership
   change.

When it takes an offer, the server checks that the owner signed it, that
`artifact`, `from`, and `to` match, and that `prev` is the latest record's
hash. At the offer and again at accept, the offered user's current
fingerprint must equal the `fp` the latest record lists for them, and for an
owner's offer, `toFp` too. Otherwise the answer is `409`.

The accepting record is signed by the new owner, names them as `owner`, and
does not list them as a member. Its `ownerFp` is the new owner's
fingerprint, and its `prev` is the latest record's hash. It sets `transfer`
to the hash of the offer body, or `handover` to `admin` for an
administrator's offer. The server checks it as any other record, but under
the new owner's key. Accept also re-checks, in one transaction that locks
the artifact row:

- The user is still a listed editor, and their `fp` still matches. For an
  administrator's offer to the released successor, the user is still the
  owner's successor instead.
- An owner's offer still names the latest record as `prev`. Any membership
  change since the offer makes it stale, and the owner offers again.
- For an administrator's offer, the owner is still deactivated.

The previous owner counts as a current member. To keep them, the record
lists them as `editor`, with a wrap of every epoch, because an owner holds
estate copies and no wraps. Leaving them out is a removal, so it needs the
next epoch and puts them in `excluded`. `estate` covers every epoch, under
the new owner's `EK`. On success the server changes the owner, deletes the
previous owner's estate copies and the new owner's wraps, closes the offer,
and emails the previous owner.

Clients accept a change of owner only when the record sets either
`transfer` or `handover`, and the new owner's key hashes to the `fp` the
immediately preceding record lists for them as `editor`. When `handover` is
`admin` and the new owner is not listed, their key must instead hash to the
fingerprint in the previous owner's verified successor record, described
next. Without such a record, a client refuses the change.

When `transfer` is set, it must be the hash of an offer in `offers`, and the
client checks that the offer:

- Verifies under the previous owner's key whose fingerprint is the preceding
  record's `ownerFp`, reached through the previous owner's rotation chain.
- Names this artifact as `artifact`, and the previous owner as `from`.
- Names the new owner as `to`, and as `toFp` the `fp` the preceding record
  lists for them, where they are an `editor`.
- Has `prev` equal to the hash of the preceding record's body.

When `handover` is `admin`, the change is silent only when the new owner is
the previous owner's nominated successor. The client checks the record in
`successors`: it verifies under the previous owner's key, reached through
their rotation chain, its `user` is the previous owner, its `successor` is
the new owner, its `successorFp` is the new owner's fingerprint, and its
`action` is `nominate`. Successor records arrive in
milestone 7, so until then every handover shows the notice. The client
cannot tell whether the server withheld a later record that removed the
nomination.

Otherwise every member's client, on every device, shows this notice on the
artifact each time it opens it:

```text
ownership was handed over by an administrator on DATE
```

`DATE` is the day the server recorded for the accepting record. The notice
cannot be dismissed for good. A client refuses to write to the artifact until
the person at the client acknowledges the handover, which the keyring records
as `ack`. In the web app the person chooses **Don't ask again**; the command
line needs `--accept-new-owner` once. Either one unblocks writing and nothing
more, so the notice still shows. A link-scope visitor gets no prompt, and
sees the same notice. There is no waiting period, because a deactivated owner
cannot sign in to refuse.

The acknowledgement gates only what relies on the chain's owner key. Writing a
membership record, pushing a version, and the other writes that verify the
chain need it, and so do accepting and withdrawing an offer. Database and
file writes do not verify the chain and do not rely on the owner key, so the
acknowledgement does not gate them. Declining an offer signs nothing, so it
does not need one either.

An administrator's offer exists only while the owner is deactivated, and the
directory lists active users only. So a client refuses an offer that the
server calls an administrator's while the directory still lists the latest
owner, because `by` is unauthenticated. The deactivated owner cannot be kept
as an editor, because the client has no keys of theirs to wrap to. So
accepting an administrator's offer drops the previous owner by default, in a
next-epoch record, as `--drop-previous-owner` does for an owner's offer.

A client that opens an artifact for the first time anchors its chain at the
creator's fingerprint from the directory, and pins it unverified. A
deactivated creator has no directory entry (`404`), so the client takes the
keys the server served in `owners` for record 0's `ownerFp` instead. Both are
server-served and unverified, so the trust level is the same, and the chain
check still refuses keys that do not hash to `ownerFp`. Any other lookup
error still fails.

The owner withdraws an offer with `DELETE /api/artifacts/{id}/transfer`
`{"membership": envelope, "linkTokenHash": "64 hex"}`, a same-epoch record.
`linkTokenHash` goes with it while the artifact is public, as with any public
record, and the closing record of a second offer carries it the same way. It
moves `prev`, so the old offer can never be accepted. The offered user declines
with the same call and no body. Either call answers `200 {"ok": true}`. With no
offer open it answers `409`, and any other listed member gets `403`. Whether or
not an offer is open, a link holder gets `403` from this call and from
accepting, and a caller with no access gets `404`.

`GET /api/admin/users/{id}/artifacts` returns
`[{"id", "editors": [{"id", "name"}]}]`, so an administrator can choose an
editor. It returns no artifact name, because milestone 4 encrypts names.
`DELETE /api/admin/artifacts/{id}` deletes an artifact only while its owner
is deactivated.

#### Keyring

`GET /api/me/keyring` returns `{"rev": 0, "keyring": ""}` until the first
write. `PUT /api/me/keyring` takes `{"rev", "keyring"}`, where `keyring` is
the sealed keyring in `b64`, at most 1 MiB. `rev` must be one more than the
stored `rev`. Otherwise the answer is `409 {"error", "rev"}`, so a second
device reads again and merges instead of overwriting.

The outer `rev` is only for this check. Clients trust the `rev` sealed inside
the keyring, and refuse a keyring whose two values differ. They also keep the
anchor that [wire formats](e2e-wire-formats.md#the-keyring) describes, and
refuse a keyring older than it. Both clients key the anchor by user ID and
the user's own fingerprint, so after a reset without the recovery code they
start with no anchor and accept the empty keyring. Sign-out in the browser
and `cairn logout` both keep the anchor. A new device has no anchor, so it
has no rollback protection until it first reads the keyring.

A keyring that fails to open is an error, never an empty keyring.

#### Rotating keys

`POST /api/me/rotate`:

```json
{"authKey": "b64", "bundle": {},
 "rotation": {"body": "b64", "sig": "b64", "signer": "user ID", "newSig": "b64"},
 "keyring": {"rev": 13, "keyring": "b64"},
 "wraps": [{"artifact": "ID", "epoch": 1, "wrapped": "b64"}],
 "estate": [{"artifact": "ID", "epoch": 1, "sealed": "b64"}],
 "records": [{"artifact": "ID", "membership": {},
              "wraps": [{"user": "ID", "epoch": 2, "wrapped": "b64"}],
              "linkTokenHash": "64 hex"}]}
```

By default, rotation moves every artifact the caller owns to the next epoch,
because the old keys may have leaked. `cairn rotate-keys --keep-epochs` keeps
the current epochs.

The server checks:

- `authKey`, as a sign-in for the rate limits.
- The bundle, as at sign-up. Its `kdf` must equal the current one, because
  the password does not change.
- The rotation record: signed by the current Ed25519 key, with `newSig` by
  the bundle's. Its `user` is the caller, its `seq` is one more than the last,
  `old` is the current public keys, and `new` is the bundle's.
- `keyring` is the keyring sealed under the new `MK`, with `rev` one more
  than the stored `rev`.
- `wraps` replaces, one for one, every wrap the caller holds under their
  current fingerprint. A wrap left under an earlier fingerprint by a
  password-only reset stays as it is, because the caller cannot open it, so
  owners still see that user as `keyChanged`.
- `records` holds one new head record for every artifact the caller owns,
  signed by the new key, with `ownerFp` set to the new fingerprint. Inside
  the transaction, the server verifies each one under the bundle's new
  Ed25519 key, not the stored one, and checks it as a membership change, at
  either epoch. Its `wraps` and `linkTokenHash` are the ones that change
  needs. When the artifacts the records name differ from the ones the caller
  owns, the answer is `409`, naming the artifact. An artifact transferred,
  created, or deleted after the client read the list causes this, so the
  client reads the list again and retries.
- `estate` replaces every estate copy of every artifact the caller owns,
  sealed under the new `EK`, and adds the copy of each new epoch.

In one transaction, which locks the caller's user row and every artifact row
it touches, the server stores the new bundle and keyring, replaces the wraps
and estate copies, adds the records, revokes every API key, deletes the
successor's copy, and stores the rotation record. It also closes every open
transfer offer made by or to the caller, because the new head records move
`prev` and the caller's fingerprint changes. The token version increases.

The answer is:

```text
200 {"seq", "epochs": {"artifact ID": epoch},
     "transfers": [{"artifact", "from", "to", "at"}]}
```

It carries the new rotation `seq`, the epoch of every artifact the caller owns,
and every change of owner to or from the caller in the last 30 days by the
server's clock, and it sets a new cookie. `from` and `to` are user IDs, `at`
is `YYYY-MM-DD`, and `transfers` is `[]` when there are none.

The client then shows the new recovery code, and the new public link of
every public artifact that moved to a new epoch, because each old link stops
working. It also warns about every artifact transferred to or from the
caller in the last 30 days, because whoever held the old key could have
signed an offer or accepted one.

Owners of artifacts shared with the rotating user see them as `rotated` in
`pending`, and are asked whether to start a new epoch too.

`GET /api/users/{id}/rotations` returns `{"records": [envelope, ...]}`,
oldest first. A client that has pinned an earlier key follows the chain from
its pin and shows **keys rotated** when every step verifies. The rotation
raises no warning, but a verified pin drops to unverified, shown as
**rotated, not re-verified**. A client that finds two different rotation
records with the same `seq` raises a hard warning, as
[wire formats](e2e-wire-formats.md#the-keyring) describes.

### Commands for sharing

`ARTIFACT` is an artifact ID or a reference, as today. `USER` is an email
address.

| Command | Does |
| --- | --- |
| `cairn artifact create NAME` | Generates the first key and record, and creates the artifact |
| `cairn members ARTIFACT` | Lists the owner and members, with roles, fingerprints, and pin states |
| `cairn share ARTIFACT USER [--role viewer\|editor]` | Shows the fingerprint, pins it, and shares; demoting an editor starts a new epoch |
| `cairn unshare ARTIFACT USER` | Removes a member and starts a new epoch |
| `cairn team ARTIFACT none\|viewer\|editor` | Shares with the whole team, or stops; stopping starts a new epoch while a team member holds a wrap |
| `cairn public ARTIFACT on\|off [--writes on\|off]` | Makes the artifact public, and prints the public link, or private |
| `cairn approve ARTIFACT [USER]` | Lists team members waiting, or approves one |
| `cairn pin USER [--verified]` | Shows a user's fingerprint and pin state, or marks it verified |
| `cairn review ARTIFACT` | Lists versions that need a vouch |
| `cairn vouch ARTIFACT VERSION` | Vouches for a version |
| `cairn transfer ARTIFACT USER` | Offers ownership to an editor |
| `cairn transfer accept\|decline ARTIFACT` | Answers an offer |
| `cairn transfer withdraw ARTIFACT` | Withdraws an offer, through a new membership record |
| `cairn rotate-keys [--keep-epochs]` | Rotates keys, moves every artifact the user owns to a new epoch, prints the new recovery code and each new public link, and creates a new device key |

`cairn share` and `cairn approve` refuse a user whose pinned key changed. They
print both fingerprints and the date of any reset, and need
`--accept-new-key` to go ahead. A key change that a rotation chain explains
shows as **keys rotated** and needs no flag, but a verified pin becomes
unverified. A fork in a rotation chain always needs `--accept-new-key`.
`cairn approve` also refuses a user who matches an excluded entry, or who
shares a fingerprint or email with another user ID. Every command that
encrypts refuses an epoch lower than the one in the keyring.

Every command that opens an artifact after an administrator's handover
prints the notice from [Ownership transfer](#ownership-transfer), unless the
new owner is the previous owner's verified successor. Every command that
writes to it refuses until the person acknowledges the handover with
`--accept-new-owner`, once.

`cairn rotate-keys` asks for the password, because it needs a session; every
API key stops working when it finishes.

## Encrypted content and serving

Milestone 4. A version's files reach the server already encrypted, and each
artifact renders on its own content origin, decrypted by a service worker
that the app-origin shell hands the keys to. Milestone 5 encrypts the
database and stored files; see
[Client-side database and files](#client-side-database-and-files). Artifact
and version names, descriptions, and changelogs stay readable to the server
until milestone 6, which encrypts them as `meta` records alongside the lists
the client renders.

### Content domain

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--content-domain` | `CAIRN_CONTENT_DOMAIN` | The domain under which each artifact gets its own host, `<artifact ID>.<content domain>`. The scheme and port are the public URL's, or the listen address's port when there is no public URL, left out when it is the scheme's default. |

When the public URL's host is `localhost`, `127.0.0.1`, or `[::1]`, the flag
defaults to `localhost`, so artifacts load from
`http://<artifact ID>.localhost:<port>`. Otherwise the server refuses to start
without it.

The server also refuses to start when the content domain:

- is an IP address, or has a label over 63 characters or is over 253
  characters in all;
- equals the public URL's host, or either one is a subdomain of the other;
- shares a registrable domain with the public URL's host, by the Public Suffix
  List.

`localhost` passes the last check, because `localhost` has no registrable
domain, so each `<artifact ID>.localhost` is a site of its own.

It also refuses a public URL that is not `http` or `https` with a host.

Routing compares the host name only: the server lowercases `Host` and drops
any port, because a browser leaves out a default one. A host that is a single
lowercase UUID label followed by the content domain goes to the content
origin's routes. Any other host that is the content domain or under it, with
or without a trailing dot, gets a plain `404` with `Cache-Control: no-store`
and never reaches an app route. The exception is a content domain that is
also the app's host, as with `localhost` beside a `localhost` public URL:
that host itself still reaches the app. Every other request goes to the app's
routes, as before.

### Content-origin routes

| Path | Serves |
| --- | --- |
| `/_cairn/boot` | The boot page, which registers the worker and runs the handshake |
| `/_cairn/sw.js` | The service worker |
| `/_cairn/frame.js` | The script the worker adds to every HTML page |
| `/_cairn/*` | The other static assets: `e2e.mjs` and what it imports, `cairn.js`, `mermaid.js`, `sql-wasm.js`, and `sql-wasm.wasm` |
| `/api/...` | The content-origin token's allowlist, for this host's artifact only |

- On a content host, an `/api/` route outside the allowlist answers `404`,
  whatever credentials the request carries, and so does an allowlisted route
  whose `{id}` does not resolve to the host's artifact.
- On a content host, the server ignores the `Cookie` header. An
  `Authorization` header must carry a content-origin token whose `art` claim
  names the host's artifact, or the request gets `401`.
- `GET` and `HEAD` of `/_cairn/boot`, and any other `GET` or `HEAD` that asks
  for HTML, get the boot page, which takes over once the worker runs.
  Anything else gets `404`.
- Every response sends `X-Content-Type-Options: nosniff`, and every HTML
  response sends
  `Content-Security-Policy: frame-ancestors <app origin>`.
- `/_cairn/sw.js` sends `Cache-Control: no-cache` and
  `Service-Worker-Allowed: /`. It is served only when the query is exactly
  `app=<app origin>`, naming this server's app origin once, and anything else
  gets `404`. Artifact code shares the content origin, so it could otherwise
  register the worker naming an app origin of its choosing, which the worker
  would then let frame its pages.
- Every `/api/` response, on a content host and on the app origin, sends
  `Content-Security-Policy: sandbox; default-src 'none'; frame-ancestors 'none'`.
  A stored file opened directly by its address therefore never runs as a page
  on either origin.

Session cookies are host-only on the app origin, so no request to a content
host carries one.

### Content-origin tokens

`POST /api/artifacts/{id}/content-token` needs a session, not an API key, and
read access to the artifact. It answers `{"token", "expiresAt"}`: a sign-in JWT
whose `art` claim names the artifact, valid for 10 minutes. A caller whose only
access is a public link also sends `X-Cairn-Link-Token`, and gets a token with
link-scope access and nothing more. The shell asks for a new token a minute
before the old one expires and passes it to the worker. It retries a failed
renewal every 10 seconds while the old token lasts, except a 401 or 403,
which it reports at once.

An anonymous visitor gets no token. The worker sends the link token alone.

### Pushing a version

`POST /api/artifacts/{id}/versions` takes `multipart/form-data`:

- `version`, a JSON part:
  `{"id", "epoch", "manifestHash", "name", "changelog"}`. `id` is a UUID the
  client chose, because the manifest and every blob's context name it. The
  server refuses an `id` that is not a lowercase UUID, or that any version
  already uses, with `409`. `epoch` must be the artifact's current epoch,
  or the server refuses the push with `409`. A push that names no epoch,
  or one below 1, is malformed and gets `400`.
  `manifestHash` is `hex(SHA-256)` of the manifest envelope's body. The part
  is at most 1 MiB; a larger one gets `400`.
- `manifest`, the version's signed manifest, sealed as a blob with kind
  `manifest`.
- One `blob` part per file, whose filename is the blob ID: 32 lowercase `hex`
  characters, chosen at random by the client.

The server cannot read any of it, so it checks only the shape:

- the caller may push;
- the push has at least one blob, because every version has an
  `index.html`;
- every blob ID is well formed and appears once;
- every blob and the manifest start with the blob header and are long
  enough to hold one tagged chunk;
- the manifest part is at most 16 MiB, or the server answers `413`;
- the total size is within `--max-upload-mb`.

It stores the parts under a fresh content directory, as `manifest` and
`blobs/<blob ID>`, and records `epoch`, `manifestHash`, and `pushedBy`. It
stores each part's bytes as sent, and ignores any
`Content-Transfer-Encoding` header on it.

`PUT /api/artifacts/{id}/versions/{vid}` replaces a version's content with
the same parts. The `id` in `version` must equal `{vid}`, and the
replacement swaps content directories as before and deletes the vouch.

A request that carries a part of the old zip push (`name`, `changelog`,
`archive`, or `file`) is refused with `400`, and a message telling the person
to update the `cairn` tool, whichever part comes first.

### Reading a version

| Method and path | Returns |
| --- | --- |
| `GET /api/artifacts/{id}/versions/{vid}/manifest` | The manifest blob |
| `GET /api/artifacts/{id}/versions/{vid}/blobs/{blob}` | One file's blob |

Both send `application/octet-stream` and `Cache-Control: no-store`, and both
join the content-origin token's allowlist. `GET .../versions/{vid}` adds
`epoch` and `manifestHash` to what it returns.

A vouch's `manifest` must now equal the version's `manifestHash`.

A version is trusted when either of these holds:

- Its manifest is signed by someone the latest membership record lists as
  owner or editor, under the key listed for them or one a rotation chain links
  to it.
- The current owner vouched for its `manifestHash`.

Otherwise the shell does not render it, and says that the person who pushed
it is no longer an editor and the owner has not reviewed it.

### The handshake

The shell runs on the app origin at `/shared/{id}` and `/shared/{id}/{vid}`.
It verifies the membership chain and the version as the command-line client
does, and gets `AK` for the version's epoch:

- from the caller's wrap, when they are signed in and listed;
- from the link's `#k`, for a public link. The shell first removes the
  fragment from the address bar with `history.replaceState`. A fragment that
  is not a link is reported only when the caller is not a member, so a
  member's bookmark with a page anchor still opens. The shell keeps a link's
  fragment in memory and adds it back to the version picker's address and the
  full screen link, so a link holder can change version. A member's page
  anchor is not carried.

It frames `<content origin>/_cairn/boot`, sandboxed as the
[trust model](e2e-trust-model.md#artifact-isolation) describes. Every message
is an object with a `cairn` field naming its type:

| From | To | Message |
| --- | --- | --- |
| Boot page | Shell | `{"cairn": "ready", "version", "path"}` |
| Shell | Boot page | `{"cairn": "keys", "artifact", "version", "epoch", "ak", "signer", "manifestHash", "token", "tokenExpires", "linkToken", "context", "path"}` |
| Shell | Frame | `{"cairn": "token", "token", "tokenExpires"}` |
| Frame | Shell | `{"cairn": "need-keys", "version"}` |
| Frame | Shell | `{"cairn": "navigate", "href"}` |

- The shell sends to the content origin's exact origin, never `*`, and acts
  on a message only when its `source` is the frame's window and its `origin`
  is the content origin.
- The boot page sends to the app origin, which the server writes into the
  page, and acts only on messages from `parent` with that origin.
- `ready` and `need-keys` name a version. The shell answers only for a
  version of the same artifact, and verifies that version first. For the
  page's own version, when the server does not have it, the shell shows that
  the version was not found. A version the frame names that the server does
  not have gets no answer and shows nothing, since the artifact's code could
  name any version.
- In `keys`, `ak` and `linkToken` are `b64`, and `token`, `tokenExpires`, and
  `linkToken` may be `null`. `signer` is `{"user", "ed25519"}`, the key the
  manifest must verify under, or `null` when the version is trusted through a
  vouch. `context` is
  `{"artifact": {"id", "name", "description"}, "users": [{"id", "name", "email"}]}`,
  where `users` lists the latest record's owner and members, or is empty for
  an anonymous visitor.

The boot page passes `keys` to the active worker of the registration its
own `register` call returned, waits for it to confirm, then replaces its own
location with `/<version><path>`:

- It never uses `navigator.serviceWorker.ready`. Artifact code shares the
  origin and can register at a narrower scope, which `ready` would then
  resolve to. The boot page unregisters every registration whose scope is not
  the origin root, and the worker refuses to start at any other scope.
- It waits for an installing worker to activate, and shows an error if the
  worker fails to install.
- The worker need not control the boot page. Firefox leaves the boot page
  uncontrolled on a repeat visit, and the worker serves the navigation to the
  version either way.

The shell, the boot page, and the worker each refuse a `version` and `path`
whose address, once the browser resolves dot segments, including
percent-encoded ones, would leave `/<version>/`. A path that would take the
frame to `/api/` or `/_cairn/` therefore gets no keys.

### The service worker

The worker keeps every `keys` message in memory, by version, and writes
nothing to Cache Storage, IndexedDB, or any other storage. It opens a
version before serving any of it:

1. It fetches the manifest blob and opens it with `AK`.
2. It checks that `manifestHash` is the hash of the envelope's body.
3. When `signer` is set, it checks that the envelope's `signer` is that user
   and its signature verifies under that key.
4. It checks that the body's `artifact`, `version`, and `epoch` match.

Any failure shows an error page, and nothing from the version is served.
The error page holds no script, and it and the worker's plain-text `404` and
`503` answers send no `frame-ancestors`.

For a request to `/<version>/<path>`, the worker:

- Looks the path up in the manifest. A navigation to a path with no file
  extension that the manifest does not hold gets `index.html`, as the SPA
  fallback does today. Any other missing path gets `404`.
- Serves `cairn.js`, `mermaid.js`, `sql-wasm.js`, and `sql-wasm.wasm` at the
  version's root from `/_cairn/` when the manifest has no file of that name
  there, so a relative `<script src="./cairn.js">` keeps working. On a
  content origin, `cairn.js` takes the artifact ID from the host's first
  label and the version ID from the first path segment, and calls the API
  through the worker.
- Fetches the blob, checks its SHA-256 against the manifest, opens it with
  the context `content`, the version, and the path, and checks its size.
- Answers with a media type taken from the extension,
  `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, and on HTML,
  `Content-Security-Policy: frame-ancestors <app origin>`. It inserts
  `<script src="/_cairn/frame.js"></script>` at the start of every HTML
  document.

For a request to `/api/`, including a navigation such as a link to
`cairn.db.downloadURL`, the worker adds `Authorization: Bearer <token>`
when it has a token, and `X-Cairn-Link-Token` when it has a link token. It
answers two reads itself, from `context`, so they never reach the server:
`GET /api/artifacts/{id}` and `GET /api/users`. That keeps `cairn.artifact()`
and `cairn.users()` working without widening the allowlist, and limits the
users an artifact can list to the people who can open it.

A navigation therefore reaches the server with the token behind it. Every
`/api/` response carries the sandboxed CSP that refuses framing, so a stored
file served there never runs as a document. Any site can start a navigation,
so the worker answers one that is not a `GET`, such as a form's `POST`, with
`405` and sends nothing. Otherwise a form on another site could write as the
viewer. The cost is that an artifact
cannot show `cairn.files.url(...)` in an `<iframe>` or `<object>`, such as a
PDF preview.

A download link to an `/api/` URL works only where the browser sends it
through the worker. Measured with Playwright in 2026-10:

| Engine | `<a download href="/api/...">` |
| --- | --- |
| Firefox | Goes through the worker, and downloads |
| Chromium | Canceled |
| WebKit | Skips the worker, so it reaches the server with no token, and gets `404` |

A blob URL from `cairn.files.download` downloaded in Chromium. Playwright saw
no download from one in Firefox or WebKit. Milestone 5 hands downloads to the
shell instead; see [Downloads](#downloads).

It never intercepts `/_cairn/`.

When the browser has stopped the worker, it has no keys. For a navigation it
answers with the boot page, which runs the handshake again. For any other
request it asks the page, through `frame.js`, to send `need-keys`, and waits
up to 10 seconds.

### Navigation and full screen

`frame.js` opens external links in a new tab, and asks the shell to navigate
for a link to another Cairn page, under the rules in the
[trust model](e2e-trust-model.md#serving-a-private-artifact). It also loads
Mermaid when the page has a diagram.

Full screen is `/full/{id}` and `/full/{id}/{vid}`: the shell with its chrome
hidden, until there is a status to show, such as a prompt to sign in. There,
a `navigate` to `/shared/<uuid>/<uuid>` opens
`/full/<uuid>/<uuid>`.

### App pages in milestone 4

- The shell page's Content Security Policy adds
  `frame-src <scheme>://*.<content domain>[:<port>]`. The full screen page
  adds it too, and no other page does.
- `/artifacts/{id}` and every path under it redirect to the same path under
  `/shared/`, so existing links keep working. The server no longer serves an
  artifact's files from the app origin.
- The shell page carries no artifact data and checks no access. It names the
  artifact's ID, the version and path asked for, and the content origin, and
  nothing else: the shell's script reads the name, description, and versions
  through the API, which enforces access. A `{id}` that is not a lowercase
  UUID is a resource reference, which resolves with the caller's access to a
  redirect to the same path under the artifact's UUID, or `404` when it does
  not resolve. A `{vid}` that is not a lowercase UUID is `404`, and so is a
  path after it with a segment that, once percent-decoded, is empty, `.`, or
  `..`, or holds `/`, `\`, or a NUL byte. Only the last segment may be empty.

### Commands in milestone 4

`cairn push` checks the tree as the server used to: `index.html` at the root,
no symlinks, and every name a valid UTF-8 path. The server enforces the size
limit, `--max-upload-mb`, and the client cannot learn it, so when the server
answers `413` the client reports that the upload is larger than the server's
limit. It then:

1. Chooses the version ID and the blob IDs.
2. Seals each file under the current epoch's `AK`.
3. Signs the manifest, then seals it under the same key.
4. Uploads the lot.

`cairn open` prints the `/shared/` address, or the `/full/` address with
`--full`. `--shared` is still accepted and does nothing.

## Client-side database and files

Milestone 5. The server stores each version's database and files as blobs
it cannot read. Clients decrypt them, run SQL on their own copy, and upload
a new encrypted copy for every write. The server keeps no file names: each
stored file goes under its address, and its path is inside an encrypted
metadata blob.

### Server flags in milestone 5

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--max-db-mb` | `CAIRN_MAX_DB_MB` | The largest database revision the server accepts, as an encrypted blob, in MiB. Defaults to 50. |

A stored file is limited by `--max-upload-mb`, as before.

### Data directory in milestone 5

| Path | Holds |
| --- | --- |
| `dbs/<artifact>/<version>/<revision>` | One encrypted database revision |
| `files/<artifact>/<version>/<address>` | One encrypted stored file |

Deleting a version or an artifact deletes its database revisions and stored
files: both the rows and the directories. `cairn backup` copies both trees.

### Database revisions

A version's database is a series of revisions, numbered from 1. Each is the
whole SQLite file, sealed as a blob with kind `database` and the revision
number as `name`, and signed with a `revision` envelope.

| Method and path | Access | Does |
| --- | --- | --- |
| `GET /api/artifacts/{id}/versions/{vid}/db` | Read | Returns the latest revision |
| `PUT /api/artifacts/{id}/versions/{vid}/db` | Write data | Adds a revision |
| `GET /api/artifacts/{id}/versions/{vid}/db/revisions` | Read | Lists the revisions kept |
| `GET /api/artifacts/{id}/versions/{vid}/db/revisions/{rev}` | Read | Returns one revision |

All four join the content-origin token's allowlist.

A revision is returned as `application/octet-stream` with
`Cache-Control: no-store`, and these headers:

| Header | Value |
| --- | --- |
| `ETag` | `"<revision>"` |
| `X-Cairn-Revision` | The revision number |
| `X-Cairn-Epoch` | The epoch it was sealed under |
| `X-Cairn-Record` | `b64` of the `revision` envelope, as JSON |
| `X-Cairn-Signer-Key` | `b64` of the Ed25519 key the server checked the envelope against when it took the write |

`GET .../db` answers `304` when `If-None-Match` names the latest revision,
and `404` when the version has no database yet. `GET .../db/revisions/{rev}`
answers `404` for a revision the server no longer keeps.

`PUT .../db` takes `multipart/form-data` with two parts, in this order:

- `record`, the `revision` envelope as JSON, at most 64 KiB;
- `blob`, the sealed database.

It must send `If-Match: "<revision>"`, naming the latest revision, or `"0"`
when the version has no database. The server refuses:

| Status | When |
| --- | --- |
| `428` | `If-Match` is missing or not a quoted number |
| `412` | `If-Match` does not name the latest revision. The answer carries the latest `ETag`. |
| `413` | The blob is larger than `--max-db-mb` |
| `400` | A part is missing, out of order, or malformed; the envelope does not decode strictly; or the blob has no blob header |
| `403` | The envelope's signer is not the caller, or it does not verify under the caller's current Ed25519 key |
| `409` | The body's `epoch` is not the artifact's current epoch |
| `400` | The body's `artifact` or `version` is not this one, its `revision` is not the latest plus one, or its `sha256` is not the blob's |

The server checks the epoch and takes the write under the epoch lock, as a
push does. On success it answers `200` with `{"revision"}` and the new
`ETag`. It then keeps the newest 10 revisions and deletes the rest.

`GET .../db/revisions` answers, newest first:

```json
[{"revision": 12, "epoch": 3, "size": 40960, "writtenBy": "<user ID>", "createdAt": "<RFC 3339>"}]
```

The server's checks stop a reader of the artifact from writing; they prove
nothing to a client, which trusts the server for none of them. A client
checks a revision as
[Checking data a client reads](#checking-data-a-client-reads) describes.

### Stored files

A stored file has an address, `hex(HMAC-SHA256(fileKey, path))` under the
epoch it was written in. It is two blobs, each with its own `record`
envelope:

- the file, sealed with kind `file` and the address as `name`;
- its metadata, sealed with kind `file-meta` and the address as `name`, whose
  plaintext is `{"v":1,"path","size","modifiedAt"}`. `size` is the file's
  plaintext size, and `modifiedAt` is an RFC 3339 time.

Both blobs name the address rather than the path, so a client can open the
metadata of a file whose path it does not yet know.

| Method and path | Access | Does |
| --- | --- | --- |
| `GET /api/artifacts/{id}/versions/{vid}/files` | Read | Lists the stored files |
| `GET /api/artifacts/{id}/versions/{vid}/files/{address}` | Read | Returns one file |
| `PUT /api/artifacts/{id}/versions/{vid}/files/{address}` | Write data | Stores or replaces one file |
| `DELETE /api/artifacts/{id}/versions/{vid}/files/{address}` | Write data | Deletes one file |

All four join the content-origin token's allowlist. `{address}` is 64
lowercase `hex` characters, or the route answers `404`.

`GET .../files` answers:

```json
[{"address", "epoch", "size", "updatedAt", "record", "meta", "metaRecord", "signerKey"}]
```

`record` and `metaRecord` are the envelopes as JSON objects, `meta` is the
metadata blob in `b64`, `size` is the file blob's size, and `signerKey` is
`b64` of the Ed25519 key the server checked both envelopes against.

`GET .../files/{address}` returns the file blob as `application/octet-stream`
with `Cache-Control: no-store`, `X-Cairn-Epoch`, `X-Cairn-Record`, and
`X-Cairn-Signer-Key`, or `404`.

`PUT .../files/{address}` takes `multipart/form-data` with four parts, in this
order: `record`, `blob`, `metaRecord`, and `meta`. The records are at most
64 KiB each, the metadata blob at most 4 KiB, and the file blob at most
`--max-upload-mb`, or the server answers `413`. The server refuses with the
statuses of `PUT .../db`, except `412` and `428`, when:

- either envelope is not signed by the caller under their current key;
- either body names another artifact or version, or an epoch other than the
  current one;
- `record` does not have kind `file`, or `metaRecord` kind `file-meta`, or
  either `name` is not `{address}`;
- either `sha256` is not that of its blob, or either blob has no blob header.

A replacement swaps the file in whole; a reader sees the old file or the new
one. `DELETE` answers `204`, or `404` when there is no file at the address.
A delete carries no signature, so anyone who may write data can delete any
stored file of the version, and a client cannot tell a deleted file from one
the server hid.

### Checking data a client reads

A client accepts a revision, a file, or a file's metadata only when all of
these hold:

1. The envelope decodes strictly and verifies under the key the server
   supplied.
2. That key belongs to someone who may write. The latest membership record
   must list the signer as owner or editor, and the key must be the one
   listed for them or one a rotation chain links to it. While `publicWrites`
   is on, any signer is accepted, as the
   [wire formats](e2e-wire-formats.md#signatures) say.
3. The body's `artifact`, `version`, and `kind` and `name` or `revision`
   match what was asked for, its `sha256` is the blob's, and the client holds
   `AK` for its `epoch`.
4. The blob opens with that `AK` and the context the body names.
5. For metadata, `FileAddress(fileKey(epoch), path)` equals the address. A
   server that moved a metadata blob onto another file's address fails here.
6. For a revision, the number is no lower than the highest the client had
   seen for that version, since it started, when it sent the request. A
   write that lands while the read is in flight does not count against it.
   A `304` is held to the same floor, for the revision it confirms. The
   service worker forgets this when the browser stops it, so the check
   narrows a rollback without closing it.

A client never accepts a revision or a file from an epoch below the
version's own. A restore is the one exception; see
[Commands in milestone 5](#commands-in-milestone-5).

### Epoch changes

A record that starts a new epoch, made by `cairn unshare`, `cairn public`,
`cairn share` demoting an editor, or `cairn approve`, makes the new epoch's
`AK` the only one a public link opens. The command therefore re-seals,
under the new epoch and signed by the person running it:

- the latest revision of every version's database, as a new revision;
- every stored file of every version, at its new address, deleting the old
  one;
- the latest version, when someone the new record still trusts signed it,
  as a replacement with the same version ID.

It re-seals only what it can verify under the record before the change. A
revision or a file signed by someone an earlier change removed is left as it
is, and the database cannot be read until someone writes to it again or the
owner restores a revision. The latest version is re-sealed only when the
latest record still lists its signer as owner or editor; otherwise it waits
for the owner's review. The command lists everything it left alone, with the
reason, and still exits zero: what it left needs a person, not a retry.

If re-sealing fails part way, `cairn reseal ARTIFACT` runs it again. It is
safe to run at any time, and it does not write a file it already copied a
second time.

Re-sealing a removed editor's last revision means the owner signs data that
editor wrote. They wrote it while they could write, and the server refuses
any write they try after the record that removes them.

### The worker's data routes

The service worker answers these routes itself, in plaintext, and never
forwards them to the server. Every answer carries the `/api/` sandbox CSP
and `X-Content-Type-Options: nosniff`.

| Method and path | Does |
| --- | --- |
| `GET .../db` | Returns the plaintext SQLite file, with `ETag: "<revision>"`. Answers `304`, with the `ETag` the page sent, to a matching `If-None-Match`, and `404` when there is no database. |
| `PUT .../db` | Takes the plaintext SQLite file with `If-Match: "<revision>"`, seals and signs it, and uploads it. Passes on the server's `412`, `409`, and `413`. |
| `GET .../db/download` | The plaintext file as an attachment named `database.db` |
| `GET .../files` | `[{"path", "size", "modifiedAt"}]`, one entry per path, from the highest epoch that has it. An entry that fails a check is left out, with a console warning. |
| `GET .../files/{path...}` | The file, with a media type taken from the extension |
| `PUT .../files/{path...}` | Seals, signs, and stores the request body under the current epoch, then deletes the same path's addresses under earlier epochs |
| `DELETE .../files/{path...}` | Deletes the path's address under every epoch, oldest first, so a delete that fails part way leaves the newest copy. Answers `404` when none had it. |

`{path...}` follows the rules `cairn.files` already applies: no empty, `.`,
or `..` segment, and no backslash. A path looks up its address under
each epoch from the current one down to the version's, and uses the first
the server has.

`cairn.js` reads the version's database through `GET .../db` into sql.js and
keeps it with its revision. Before each query or batch it sends
`If-None-Match`, so it runs on the latest copy. A query or batch runs in a
transaction on that copy. The client treats it as a write when, after it
runs, `total_changes()`, `PRAGMA schema_version`, or `PRAGMA user_version`
differs from before; it never parses the SQL. A statement that changes only
another header field, such as `PRAGMA application_id` or
`PRAGMA journal_mode`, leaves all three as they were, so it is not sent. A
write is exported and sent
with `PUT .../db`. On `412` the client reloads the latest revision and runs
the statements again, up to five times. A statement string that holds more
than one statement is refused, as the server refused it before. A query that
names another version with `{version}` may read its database but not change
it: `cairn.js` rolls back and refuses a statement that would. This guards
the helper, not the data: a page may send its own `PUT` to any version it may
write.

sql.js loads from `/_cairn/sql-wasm.js` only, never from a CDN, so an
artifact on a content origin works with no access to the internet.

### Keys and signing

The `keys` message gains four fields:

| Field | Holds |
| --- | --- |
| `aks` | `{"<epoch>": b64(AK)}` for every epoch from the version's to the current one that the caller holds |
| `currentEpoch` | The artifact's current epoch |
| `writers` | `{"<user ID>": [b64(Ed25519 key), …]}`: the latest record's owner and editors, each with the key listed for them and the keys a rotation chain links to it |
| `publicWrites` | Whether the latest record allows public writes |

The worker holds no signing key. For a write it asks the page that made the
request to have the shell sign:

1. The worker sends `{"cairn": "sign", "purpose", "bodies"}` to that window
   client, with a `MessagePort`.
2. `frame.js` passes it to the shell with the port.
3. The shell answers on the port with `{"cairn": "signed", "envelopes"}`, in
   the order of `bodies`, or `{"cairn": "sign-error", "error"}`.

The shell builds each body itself from the fields it is sent, and signs only
when all of these hold:

- `purpose` is `revision` or `record`;
- `artifact` is the shell's artifact, `version` is a lowercase UUID, and
  `epoch` is the current epoch;
- for a revision, `revision` is a positive integer; for a record, `kind` is
  `file` or `file-meta` and `name` is 64 lowercase `hex` characters;
- `sha256` is 64 lowercase `hex` characters;
- the caller is signed in and is the owner or a listed editor, or opened the
  artifact with a public link while `publicWrites` is on.

The frame runs the artifact's code, so the artifact can ask for any
signature these rules allow. That is the same as the write access the caller
already has, and the server still checks every write.

### Downloads

`frame.js` takes over a click of an `<a download>` whose `href` is on the
content origin or is a `blob:` URL, including a click made from script. It
fetches the bytes through the worker and sends
`{"cairn": "download", "name", "bytes"}` to the shell. The shell makes the
name safe and starts the download from its own page, as
`application/octet-stream`. A browser treats that as a top-level download,
which works in Chromium, Firefox, and WebKit alike.

### Commands in milestone 5

`cairn db query` and the new `cairn db batch` download the latest revision,
check it as the browser does, and open it in a private temporary directory
with mode `0700`. They run the statements on one connection, detect a write
the same way, upload a write with `If-Match`, and retry on `412`. A query's
output is the same as before, and a batch prints one result per statement.

Every `db` and `files` command takes `--artifact <id|name>` and
`--version <vid>`, which defaults to the latest version.

| Command | Does |
| --- | --- |
| `cairn db query [--params '[...]'] "<sql>"` | Runs one statement |
| `cairn db batch [--file <path>]` | Runs a JSON array of `{"sql", "params"}` from the file, or from standard input, in one transaction |
| `cairn db revisions` | Lists the revisions the server keeps |
| `cairn db restore --revision <n>` | Uploads that revision's plaintext as a new revision, signed by the caller |
| `cairn db download [--out <file>]` | Writes the latest revision's plaintext, to `database.db` by default |
| `cairn files list`, `get`, `put`, `delete` | Work by path, as before, through addresses |
| `cairn reseal ARTIFACT` | Runs the re-sealing an epoch change does |

A restore accepts a revision signed by anyone the membership chain has ever
listed as owner or editor, because an old revision may predate a removal.
For the same reason, it accepts a revision from an epoch below the
version's own: re-sealing the latest version raises its epoch past the
revisions the server kept. The restored copy is sealed under the current
epoch.
Anyone who may write data may restore, not only the owner: a restore is a
write like any other.

## Encrypted metadata and the app UI

Milestone 6 encrypts the last plaintext the server holds about an artifact,
and gives every signed-in user a page to manage artifacts, sharing, keys,
and their account in the browser.

### Metadata fields

Each field is one sealed blob, covered by a signed `record`:

| Scope | `version` | Fields | Who may write |
| --- | --- | --- | --- |
| Artifact | Empty | `name`, `description` | Owner, editor |
| Version | Version ID | `name`, `changelog` | Owner, editor |

- The plaintext is UTF-8 of at most 16 KiB (`e2e.MaxMetaPlaintext`). An empty
  plaintext is a field with no value.
- The blob is sealed with the current epoch's `AK`, with kind `meta`, the
  artifact ID, `version` as in the table, and the field as `name`.
- The `record` body is `{"v": 1, "artifact", "version", "kind": "meta",
  "name": field, "epoch", "sha256"}`, where `sha256` is `hex(SHA-256)` of the
  sealed blob.
- A public writer may not write metadata, so a link holder cannot rename an
  artifact.

`PUT /api/artifacts/{id}/meta/{field}` writes an artifact field, and
`PUT /api/artifacts/{id}/versions/{vid}/meta/{field}` a version field. Both
take `{"record": envelope, "blob": "b64"}` and answer `200 {"ok": true}`.
The access is the owner's or an editor's. The server refuses, with `400`, an
unknown field, a record that does not decode strictly, names another
artifact, version, kind, or field, or whose `sha256` is not the blob's, and a
blob that is not a sealed blob. It refuses a blob over 17 KiB with `413`, a
signature that does not verify under the caller's current Ed25519 key with
`403`, and any epoch but the current one with `409`, while it holds the
artifact's lock. A write replaces the field.

The artifact views gain `"meta": {field: item}`, and each version view
gains the same for its own fields. An item is `{"record": envelope,
"signerKey": "b64", "blob": "b64"}`, and a field nobody wrote is absent.
`name`, `description`, and `changelog` leave every request and answer.
`PATCH /api/artifacts/{id}` and `PATCH /api/artifacts/{id}/versions/{vid}`
are removed, as are the `name` and `changelog` parts of a version push.
`POST /api/artifacts` no longer takes `name` or `description`: the client
creates the artifact, then writes its fields. Mail that named an artifact
names its ID instead.

A client reads a field the way it reads a stored file's record. It opens the
record under `signerKey`, and accepts the signer only when the latest
membership record lists them as owner or editor. The key must be theirs,
either as listed or reached through their rotation chain. It checks the
blob's hash, opens the blob with the record's epoch's `AK`, and refuses
invalid UTF-8. A field that fails any
check, or whose epoch's `AK` the reader does not hold, shows as unreadable,
and the artifact shows under its ID.

An [epoch change](#epoch-changes) also re-seals every field the client can
verify under the record before the change, signed by the person making the
change. A link holder has only the current epoch's `AK`, so without this
they could read no name.

### Resources

`POST /api/artifacts/{id}/resources` takes `{"type", "value"}`, where
`value` is a [blind index](e2e-wire-formats.md#public-links-file-addresses-and-blind-indexes),
64 lowercase `hex` characters, computed with the caller's `indexKey`. Any
other value is `400`, so the server never holds a resource value. The
`cairn` tool resolves a reference by computing its index under each type
its artifacts' resources carry, then matching. Because `indexKey` comes from
the caller's `MK`, a reference resolves only for the user who added it.
`cairn artifact show` lists each resource by type and row ID: the value
cannot be read back. Rotating keys replaces `MK`, so a resource added before
a rotation no longer resolves, and the client cannot index it again because
it never kept the value. To keep a reference working, add it again after the
rotation.

### The app page

`/app` is every signed-in user's home. `/` sends a signed-in visitor there,
and `/admin` redirects to it. Like the other app pages it carries no user
data: its script checks sign-in through `GET /api/me` and sends a visitor
with no session to `/login`. It has three tabs, a fourth for
administrators, and a successor tab from milestone 7:

- **Artifacts** — *Your artifacts* and *Shared with you*. Each row opens the
  artifact, then shows its name and description from the encrypted fields,
  its access, whether it is public, and when it changed. The owner can open
  the share dialog and delete the artifact.
- **API keys** — list and revoke keys, and create one. Creating a key asks
  for the password again, and shows the full key once.
- **Account** — change the password, and make a new recovery code, which
  also asks for the password and shows the code once.
- **Successor** — added in milestone 7.
- **Users** — administrators only, as the old `/admin` page.

The share dialog lists the members with their name, email, role, current
fingerprint, and pin state. The owner can share with a user by email as
editor or viewer, change a role, remove a member, mark a fingerprint as
verified after comparing it, and accept a changed key after a warning. The
public section turns the public link and public writes on and off. It
labels the link as carrying the key, and copies it only when the owner asks.
A change that starts a new epoch re-seals, in the browser, what
`cairn reseal` would, and lists what it left alone.

Team approval, reviewing versions, ownership transfer, and key rotation stay
in the `cairn` tool.

`/login` serves every visitor, signed in or not, because the server cannot
tell whether the browser holds the keys that sign-in unlocked. The page's
script sends a visitor whose session and keys it finds straight to `next`;
anyone else signs in again, which unlocks the keys.

Every page renders names, emails, descriptions, and changelogs with
`textContent` only, under the Trusted Types policy, which refuses any string
assigned as markup. The shell page never asks for a password, so an
artifact cannot appear under a password prompt.
