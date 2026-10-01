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

- **Addresses** are trimmed and lowercased before every lookup and
  comparison. The domain is everything after the last `@`. A domain matches
  `--signup-domain` exactly; subdomains are not included.
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
    either.
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
   without using it, and returns `{"email", "mkRecovery", "x25519Pub",
   "ed25519Pub"}`. The token stays valid for `complete`.
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
     every API key, revokes every API key, stores the new bundle, and sets
     the user's `resetAt` to now.

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
`CryptoKey` objects, and clear IndexedDB at sign-out. The sign-up and reset
pages refuse a password that the vendored strength estimator scores below 3.

### Commands

Every command that prompts for a password also accepts `--password-stdin`,
which reads one line. Scripts and tests use it.

| Command | Does |
| --- | --- |
| `cairn signup --host URL --email E [--name N]` | Generates keys, signs up, and prints the recovery code |
| `cairn confirm-email LINK` | Follows a verification link |
| `cairn login --host URL --email E` | Signs in, creates a device key, and saves it |
| `cairn logout` | Revokes the device key and forgets it |
| `cairn whoami` | Prints the user and their fingerprint |
| `cairn forgot --host URL --email E` | Asks for a reset link |
| `cairn reset LINK (--recovery-code CODE \| --no-recovery-code)` | Sets a new password; keeps the keys only with the code |
| `cairn keys list` | Lists the user's API keys |
| `cairn keys revoke ID` | Revokes one |

`cairn signup` asks the user to retype one group of the recovery code, unless
`--password-stdin` is set. `cairn reset --no-recovery-code` warns that the
user's own artifacts become unreadable, and needs `--yes` when standard input
is not a terminal.

The config file stores the host, the email, and the full four-part API key.
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
   record's `fp` for them can read but not write, until the owner lists them
   again under the new fingerprint.
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
works on an allowlist, and every other route under `/api/` refuses it with
`404`:

- Reads of its own artifact's versions, database, and files.
- Writes to its own artifact's database and files, where the role allows
  them.

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
- `excluded` is sorted by user ID, has no duplicates, and lists neither the
  owner nor a member.
- For each member the previous record does not list, and each member whose
  `fp` differs from the previous record's, `fp` is the fingerprint of that
  user's current keys. Such a member must be a verified, active user. The
  server does not check `fp` for anyone else, so a member who rotates their
  keys stays listed under the old `fp` until the owner updates it.
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
The owner's client lists them automatically, with the role that `team`
grants, unless the owner chooses to drop them. Every user a record removes or
drops goes into `excluded`, and stays there until an owner record lists them
again. The server refuses a record that leaves a removed member or a team
member out of both lists, and a record that drops a user from `excluded`
without listing them.

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

- Each record verifies under the owner's key, as
  [wire formats](e2e-wire-formats.md#signatures) describes: the latest under
  the owner's current key, and older ones under the key their `ownerFp`
  names, which must be in the owner's rotation chain.
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
with `409`, inside the transaction that holds the artifact row lock, so a
write cannot land under the old epoch after an epoch change.

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
`null`, or `{"to", "by", "at"}` while an offer is open, where `by` is `owner`
or `admin`. `PATCH` takes `name` and `description` only; `public` is gone from
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

A record that removes or demotes the user a transfer offer names closes the
offer.

The answer is `200 {"epoch"}`.

`GET /api/artifacts/{id}/membership` returns:

```json
{"records": [envelope, ...], "offers": {"64 hex": envelope}}
```

`offers` maps the `transfer` hash in each accepting record to the offer
envelope it accepted. A link holder can read the records, because every
holder of `AK` checks `akCommit`. A link holder may not be signed in, so
cannot read the user directory. For link scope the answer adds
`"keys": {"user ID": {"x25519", "ed25519"}}` for the owner and every listed
editor, and `"rotations": [envelope, ...]`, the owner's rotation records, so
older records verify. The client checks each editor's keys against the
records' `fp` values. It pins the owner's keys on first use, as it would for
any first visit.

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
[{"id", "name", "email", "x25519Pub", "ed25519Pub", "state"}]
```

- `new`: the record's `team` is not `none`, and this verified, active user
  holds no wrap for the current epoch, is not listed, and is not excluded.
- `approved`: shown to the owner only. The user holds a wrap for the current
  epoch through an approval, and is not listed. The owner's client
  lists them in its next membership record, with the role that `team`
  grants, without asking.
- `keyChanged`: the user holds a wrap, or is listed, under a fingerprint that
  is no longer theirs, and no rotation record the server holds explains the
  change.
- `rotated`: shown to the owner only. As `keyChanged`, but a chain of
  rotation records leads from the old fingerprint to the current one. The
  owner's client asks whether to start a new epoch, in case the old keys
  leaked, and updates `fp` in its next record.

The client checks `GET /api/users/{id}/rotations` itself in both changed
states, and treats a `rotated` user whose chain does not verify as
`keyChanged`. Excluded users never appear.

`POST /api/artifacts/{id}/keys` approves a `new` user, after the person at
the client has confirmed their name and fingerprint:

```json
{"user": "ID", "fp": "64 hex", "wraps": [{"epoch": 1, "wrapped": "b64"}]}
```

The server refuses the request with:

- `403` from a viewer or a team member, because a viewer's client never wraps
  keys.
- `409` when the record's `team` is `none`.
- `409` when the user already holds a wrap or is listed. A changed key is
  never a new member. The owner shares again through a membership record that
  lists the new fingerprint.
- `409` when the record excludes the user. The editor's client refuses to
  approve an excluded user before it asks.
- `409` when `fp` is not the user's current fingerprint.
- `400` unless `wraps` covers every epoch.

The server runs these checks in one transaction that locks the artifact row.

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
`[{"id", "seq", "pushedBy", "createdAt"}]`.

`pushedBy` is a convenience. The owner's client builds its own review list
from the signers of the version manifests, and uses the server's list only
to fetch them. Milestone 4, which adds signed manifests, implements that.

`PUT /api/artifacts/{id}/versions/{vid}/vouch` takes `{"vouch": envelope}`.
The server checks that the owner signed it, and that `artifact` and `version`
match. From milestone 4 on, it also checks `manifest` against the stored
manifest. `GET /api/artifacts/{id}/versions/{vid}` returns `pushedBy` and
`vouch`, which is the envelope or `null`.

#### Ownership transfer

1. The owner offers ownership with `POST /api/artifacts/{id}/transfer`
   `{"to": "user ID", "offer": envelope}`. `offer` is a `transfer` envelope
   the owner signed, with `prev` set to the hash of the latest record's body.
   The user must be a listed editor. A new offer replaces the old one.
2. An administrator can make an offer with
   `POST /api/admin/artifacts/{id}/transfer` `{"to": "user ID"}`, only while
   the owner's account is deactivated. Otherwise the answer is `409`, because
   an active owner must agree. The server emails the owner that an
   administrator offered their artifact to someone else.
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

- The user is still a listed editor, and their `fp` still matches.
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

Clients accept a change of owner only when both hold:

- The new owner's key hashes to the `fp` the immediately preceding record
  lists for them as `editor`.
- The record's `transfer` is the hash of an offer, from `offers`, that the
  previous owner signed against that preceding record. Or the record's
  `handover` is `admin`.

An administrator's handover is treated like a key change. The client shows
this warning, and goes on only when the person at the client acknowledges
it:

```text
ownership taken over by an administrator; the previous owner did not sign this
```

The command line needs `--accept-new-owner`. Once the client stores a `seq`
past that record, it does not ask again.

Either side withdraws or declines with `DELETE /api/artifacts/{id}/transfer`.

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
the keyring, and refuse a keyring whose two values differ. A new device has
no stored `rev` to compare against.

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
- `wraps` replaces every wrap the caller holds, one for one.
- `records` holds one new head record for every artifact the caller owns,
  signed by the new key, with `ownerFp` set to the new fingerprint. Each is
  checked as a membership change, at either epoch. Its `wraps` and
  `linkTokenHash` are the ones that change needs.
- `estate` replaces every estate copy of every artifact the caller owns,
  sealed under the new `EK`, and adds the copy of each new epoch.

In one transaction, which locks the caller's user row and every artifact row
it touches, the server stores the new bundle and keyring, replaces the wraps
and estate copies, adds the records, revokes every API key, deletes the
successor's copy, and stores the rotation record. The token version
increases, and the answer sets a new cookie. The client then shows the new
recovery code.

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
| `cairn rotate-keys [--keep-epochs]` | Rotates keys, moves every artifact the user owns to a new epoch, prints the new recovery code, and creates a new device key |

`cairn share` and `cairn approve` refuse a user whose pinned key changed. They
print both fingerprints and the date of any reset, and need
`--accept-new-key` to go ahead. A key change that a rotation chain explains
shows as **keys rotated** and needs no flag, but a verified pin becomes
unverified. A fork in a rotation chain always needs `--accept-new-key`.
`cairn approve` also refuses an excluded user. Every command that encrypts
refuses an epoch lower than the one in the keyring.

Every command that reads an artifact refuses an administrator's handover it
has not seen before. It prints the warning from
[Ownership transfer](#ownership-transfer), and needs `--accept-new-owner` to
go ahead.

`cairn rotate-keys` asks for the password, because it needs a session; every
API key stops working when it finishes.
