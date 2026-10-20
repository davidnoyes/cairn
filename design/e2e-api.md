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

- `GET /api/me` returns `{"id", "email", "name", "role", "isAdmin",
  "createdAt", "resetAt"}`. `role` is `admin`, `member`, or `viewer`, and
  `isAdmin` is true exactly when it is `admin`. `resetAt` is empty unless a
  reset without the recovery code happened.
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
  "role", "x25519Pub", "ed25519Pub", "resetAt"}`. Clients compute
  fingerprints, and offer a viewer account only the viewer role.
- `GET /api/admin/users` adds `isAdmin`, `disabled`, `verified`, and
  `createdAt`, and includes unverified accounts.
- `PATCH /api/admin/users/{id}` takes `{"role": "admin"|"member"|"viewer",
  "disabled": bool}`, either optional. The older `"isAdmin": bool` still works
  (true makes an administrator, false a member), but not together with
  `role`. An administrator cannot remove their own administrator role.
  Deactivating increases the token version, which signs the user out
  everywhere, and blocks their API keys.
- A viewer account is refused every artifact write with `403 {"error": "a
  viewer account cannot change anything"}`, and so are creating an artifact
  and accepting ownership. An ownership offer to one is a `409`. Its own
  account upkeep works as for anyone: password, recovery code, keyring, key
  rotation, successor, API keys, and passkeys.

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

`cairn signup` shows the recovery code again with one group blanked out, and
asks the user to fill in that group from their saved copy, unless
`--password-stdin` is set.
`cairn reset --no-recovery-code` warns that the user's own artifacts become
unreadable, and needs `--yes` when standard input is not a terminal.

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
| `PUT /api/artifacts/{id}/meta/{field}` | Owner, editor | Set the encrypted name or description |
| `DELETE /api/artifacts/{id}` | Owner | Delete the artifact |
| `GET /api/artifacts/{id}/membership` | Read | Every membership record, oldest first |
| `PUT /api/artifacts/{id}/membership` | Owner | Add a membership record |
| `GET /api/artifacts/{id}/keys` | Owner, member, team member | The caller's wraps |
| `POST /api/artifacts/{id}/keys` | Owner, editor | Approve a team member |
| `GET /api/artifacts/{id}/pending` | Owner, editor, released successor | Team members waiting, and changed keys |
| `GET /api/artifacts/{id}/review` | Owner | Versions that need a vouch |
| `PUT /api/artifacts/{id}/versions/{vid}/vouch` | Owner | Vouch for a version |
| `PUT /api/artifacts/{id}/versions/{vid}/meta/{field}` | Owner, editor | Set the encrypted name or changelog |
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

Link verification checks administrator handovers the same way. The answer
carries `successors` in link scope too, and `VerifyLinkChain` and
`verifyLinkChain` apply the member's successor check. A handover to a user
the preceding record does not list verifies only with the previous owner's
successor record. Without that record, the link refuses the chain.

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
- `approved`: shown only to the owner, a released successor, and the user an
  open offer names, because each of them may sign the next record. The user
  holds a wrap for the current epoch through an approval, and is not listed.
  `approval` is the signed `approval` envelope stored with it, and is `null`
  in every other state.
- `keyChanged`: the user holds a wrap, or is listed, under a fingerprint that
  is no longer theirs, or holds a wrap through an approval made for one. No
  rotation record the server holds explains the change.
- `rotated`: shown only to the owner, a released successor, and the user an
  open offer names. As `keyChanged`, but a chain of rotation records leads
  from the old fingerprint to the current one. The owner's client asks whether
  to start a new epoch, in case the old keys leaked, and updates `fp` in its
  next record.

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
`action` is `nominate`. The key is the one whose fingerprint is the
preceding record's `ownerFp`. A nomination signed before the previous owner
rotated keys therefore no longer counts. That case fails safe: a listed new
owner gets the notice, and an unlisted one is refused. A rotation deletes the
successor's copy anyway, so the owner nominates again after rotating. The
client cannot tell whether the server withheld a later record that removed
the nomination.

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
- In an artifact the caller owns, an epoch with no estate copy before the
  rotation, which a manager started, may be missing from both `wraps` and
  `estate`. The caller's wrap at that epoch then stays as it is, under the
  current fingerprint, and the epoch keeps no estate copy. Every other epoch
  needs both. The owner's client leaves such an epoch out only when its wrap
  does not open; see [Managers](#managers).

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
| Frame | Shell | `{"cairn": "login"}` |

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
  `{"artifact": {"id", "name", "description"}, "users": [{"id", "name", "email"}],`
  `"versions": [{"id", "seq", "name", "changelog", "createdAt"}]}`.
  `users` lists the latest record's owner and members, or is empty for an
  anonymous visitor. `versions` lists the versions the shell opened for its
  picker, newest first. Each name and changelog is the one the shell opened.
- `login` carries nothing. The frame cannot reach the sign-in page, so
  `cairn.login()` asks the shell to go there. The shell goes to
  `/login?next=<its path>`, and for a public link adds the link's fragment,
  which the sign-in page passes on to `next`. The fragment never reaches the
  server.

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
answers three reads itself, from `context`, so they never reach the server:
`GET /api/artifacts/{id}`, `GET /api/users`, and
`GET /api/artifacts/{id}/versions`. That keeps `cairn.artifact()`,
`cairn.users()`, and `cairn.versions()` working without widening the
allowlist, limits the users an artifact can list to the people who can open
it, and gives `cairn.versions()` the names and changelogs the server holds
only sealed.

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

A record carries no sequence number, only its epoch. A server can therefore
answer with an earlier value of a field that was signed in the same epoch,
and a client accepts it. This is accepted: the earlier value was written by
someone allowed to write it, and an epoch change re-seals every field, so a
rolled-back value cannot outlive the epoch it was signed in.

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
with no session to `/login`. It has two tabs, and a third for
administrators:

- **Artifacts** — *Your artifacts* and *Shared with you*. Each row opens the
  artifact, then shows its name and description from the encrypted fields,
  its access, whether it is public, and when it changed. The owner can open
  the share dialog and delete the artifact.
- **Account** — the user's own settings, one section after another:
  - **Password** changes the password.
  - **Recovery code** makes a new recovery code, which asks for the
    password and shows the code once.
  - **API keys** lists and revokes keys, and creates one. Creating a key
    asks for the password again, and shows the full key once.
  - The successor sections, which
    [The successor in the browser](#the-successor-in-the-browser) describes.
- **Admin** — administrators only. Its **Users** section does what the old
  `/admin` page did. Later administrator tools get their own sections here.

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

A pending request shows a banner on every tab, with a **Refuse** button.
After a release the banner says the successor has access, and that the user
must run `cairn rotate-keys` before they can change anything.

`/refuse` takes an email address and the password or the recovery code, and
refuses a pending request, as [Refusing](#refusing) describes. It works for a
deactivated account, and shows when an administrator deactivated it during
the request.

`/login` serves every visitor, signed in or not, because the server cannot
tell whether the browser holds the keys that sign-in unlocked. The page's
script sends a visitor whose session and keys it finds straight to `next`;
anyone else signs in again, which unlocks the keys.

Every page renders names, emails, descriptions, and changelogs with
`textContent` only, under the Trusted Types policy, which refuses any string
assigned as markup. The shell page never asks for a password, so an
artifact cannot appear under a password prompt.

## Successor

Milestone 7 builds the successor from the
[trust model](e2e-trust-model.md#successor). A user nominates one other user,
who can read the artifacts the user owns 14 days after asking, unless the
user refuses first.

### Nominating a successor

1. The successor reads their [successor
   code](e2e-wire-formats.md#successor-code) on their own device, and gives
   it to the user.
2. The user's client looks the successor up in the directory, and refuses
   the code unless the served keys produce it.
3. The client signs a `successor` record with `action` set to `nominate`,
   wraps `EK` to the successor's X25519 key, and sends both.

The wrap uses purpose `ek`, the user's own ID as `artifact`, epoch `0`, and
the successor's ID as the recipient.

### Endpoints for the successor

| Method and path | Auth | Purpose |
| --- | --- | --- |
| `GET /api/me/successor` | Any | The caller's successor and any request |
| `PUT /api/me/successor` | Session | Nominate a successor, or replace one |
| `DELETE /api/me/successor` | Any | Remove the successor |
| `DELETE /api/me/successor/request` | Any | Refuse a pending request |
| `PUT /api/me/notice-email` | Session | Set or clear a personal address for notices |
| `GET /api/successions` | Any | The users who nominated the caller |
| `POST /api/successions/{user}/request` | Any | Ask for access to a user's artifacts |
| `POST /api/auth/refuse/begin` | None | Read what a refusal with the recovery code needs |
| `POST /api/auth/refuse` | None | Refuse from the refusal page |

`GET /api/me/successor` returns:

```json
{"successor": {"id", "name", "email", "x25519Pub", "ed25519Pub"},
 "record": envelope, "nominatedAt": "RFC 3339", "seq": 2,
 "request": {"requestedAt", "releaseAt", "released": false,
             "deactivatedAt": ""}}
```

`successor`, `record`, and `request` are `null` when there is none. `seq` is
the last `successor` record the user signed, or `0`, and the next record
uses one more.

`PUT /api/me/successor` takes:

```json
{"authKey": "b64", "successor": "user ID", "record": envelope,
 "wrapped": "b64"}
```

The server checks `authKey` as a sign-in for the rate limits. It refuses
with `400` a successor who is the caller or is not a verified, active user,
a wrap that is not 81 bytes, and a record that does not verify under the
caller's current Ed25519 key. The record's `user` must be the caller, its
`successor` the named user, its `action` `nominate`, and its `successorFp`
the successor's current fingerprint. A `seq` other than one more than the
last answers `409 {"error", "seq"}`, with `seq` the last record the user
signed. In one transaction the server replaces
any earlier nomination, ends any pending request, and stores the record. It
answers `200 {"seq"}`.

`DELETE /api/me/successor` takes `{"record": envelope}`, a record with
`action` set to `remove`, the current successor as `successor`, and an empty
`successorFp`. It is checked the same way. The server deletes the
nomination, the wrapped copy, and any pending request, and answers
`200 {"seq"}`, or `409` when there is no successor.

`PUT /api/me/notice-email` takes `{"email": "…"}`, or an empty string to
clear it. The server emails a verification link for the new address, as at
sign-up, and uses the address only once it is verified. It answers
`202 {"status": "check-email"}`, or `200 {"ok": true}` when it clears the
address.

### Asking for access

`GET /api/successions` returns, for each user whose current nomination
names the caller:

```json
[{"user": {"id", "name", "email", "x25519Pub", "ed25519Pub"},
  "record": envelope, "nominatedAt",
  "requestedAt": "", "releaseAt": "", "released": false,
  "wrapped": "b64, only once released"}]
```

The list includes a deactivated user, because that is when a successor most
needs it. The client verifies `record` under the user's key, and checks that
its `successor` is the caller and its `successorFp` the caller's own
fingerprint, before it uses `wrapped`.

`POST /api/successions/{user}/request` takes no body. The server records the
time, and answers `200 {"requestedAt", "releaseAt"}`. It answers `404` when
that user has not nominated the caller, and `409` while a request is pending
or after a release. It also answers `409` when the nomination's
`successorFp` is not the caller's current fingerprint: a successor who
rotated or reset since the nomination cannot open `wrapped`, so the user
must nominate them again. The check that the caller is still the nominee and
the write are one transaction, so a request from a successor the user has
just replaced never lands on the new nomination. The server then tells the
user three ways:

- An email to the account address and to any verified personal address. It
  names the successor and the release date, and links to `/refuse`.
- `GET /api/me` adds `succession`, which the app shows as a banner on every
  tab: `{"successor": {"id", "name", "email"}, "requestedAt", "releaseAt",
  "released", "deactivatedAt"}`. It is `null` with no request pending or
  released.
- Every authenticated response to the user carries
  `Cairn-Notice: succession-requested`, and the `cairn` tool prints a warning
  on standard error.

### Refusing

A refusal ends the request; the nomination stays. The server emails the
successor that the user refused. A new nomination also ends a pending
request, and the mail says whether it replaced the successor or named them
again.

The mail about a request, to the user and to the successor, is sent without
the per-address limit that applies to sign-up and reset mail. Anyone can
spend that limit with reset requests for an address, and a user who never
hears of a request cannot refuse it.

- **Signed in**, from any session or API key:
  `DELETE /api/me/successor/request` answers `200 {"ok": true}`, or `409`
  with no request pending. After a release, the check that the user rotates
  answers first, with its own `409`.
- **On the `/refuse` page**, whether or not the account is deactivated.
  `POST /api/auth/refuse` takes `{"email", "authKey"}`, after a prelogin, or
  `{"email", "proof"}` for the recovery code. A wrong key or proof answers
  `401 {"error": "invalid email or password"}` and counts as a failed
  sign-in for the rate limits.

For the recovery code, `POST /api/auth/refuse/begin` with `{"email"}`
returns `{"id", "mkRecovery", "ed25519Priv", "requestedAt"}`. The client
opens `MK` with the code, opens the signing key, and signs a `refusal`
record naming that `requestedAt` as `proof`. For an address with no pending
request, the answer has the same shape, with values derived from the server
secret and the email under `cairn/v1/refuse-fake`, so it does not reveal
whether a request is pending. The fake `requestedAt` is a time in the last
14 days that holds for 14 days and then moves on, as a real one gives way to
the fake at its release.

The answer still changes when a request is made, at a time that need not
fall on that 14-day boundary. Anyone who polls an address can therefore
tell that a request is pending for it. This is accepted. Hiding it would
mean serving the account's real `mkRecovery` and `ed25519Priv` at all times
rather than only during a request. That would widen the window for an
offline attack on the recovery code, which is worth more than the fact that
a request exists, and the user is mailed about the request anyway.

After a correct key or proof, the page's call answers:

```text
200 {"refused": true, "successor": {"name", "email"}, "requestedAt",
     "deactivatedAt"}
```

or `409`. Its error says whether no request is pending or the request was
already released, which only a correct key or proof learns. `deactivatedAt`
is the time an
administrator deactivated the account while the request was pending, or
empty. An administrator cannot block a refusal by deactivating the user, and
cannot hide that they did.

### Release

A request with no refusal is released at `requestedAt` plus 14 days, by the
server's clock. Nothing is written at that moment; every read compares the
time. After a release:

- `GET /api/successions` returns `wrapped`. The successor's client unwraps
  `EK`, and opens each artifact's `AK` from the estate copies.
- The successor has `successor` access to every artifact the user owns,
  between `team` and `link` in the order under [Access](#access). It may read
  content, the database, files, membership, and keys, and accept an
  administrator's offer, and nothing else. `GET /api/artifacts/{id}/keys`
  returns the user's estate copies, and `GET /api/artifacts` lists the
  artifacts with `access` set to `successor`. It covers the artifacts the user
  owns, and never those shared with the user.
- `GET /api/me` adds `mustRotate: true` for the user. Every write under
  `/api/` from the user answers
  `409 {"error": "rotate your keys first …"}` and carries
  `Cairn-Notice: rotate-keys`, except rotating keys, signing out, creating
  and revoking API keys, and asking for a content token, which only reads.

A release cannot be refused, and the nomination can be neither removed nor
replaced: both answer `409`. Rotating keys deletes the nomination, the
wrapped copy, and the request, which ends the successor's access. A reset
without the recovery code archives the nomination and its wrapped copy with
the bundle, and ends any request; an archived copy is never released.

Two events end things without a record:

- Deleting either account deletes the nomination and any request.
- Reactivating a deactivated user keeps `deactivatedAt`, so the record of the
  deactivation survives until the request ends.

Administrator handover follows [Ownership transfer](#ownership-transfer).
`successors` in `GET /api/artifacts/{id}/membership` now carries the
previous owner's latest `successor` record, so a handover to a nominated
successor is silent.

### Commands for the successor

| Command | Does |
| --- | --- |
| `cairn successor code` | Prints the user's own successor code |
| `cairn successor status` | Shows the user's successor, any request, and who nominated the user |
| `cairn successor nominate USER --code CODE` | Asks for the password, checks the code, and nominates the user |
| `cairn successor remove` | Removes the successor |
| `cairn successor refuse` | Refuses a pending request |
| `cairn successor request USER` | Asks for access to a user's artifacts |
| `cairn successor notice-email ADDRESS` | Sets a personal address for notices; an empty string clears it |

After a release, the successor reads the user's artifacts with the usual
commands. They also read each artifact's pending list, so their accept of an
administrator's offer carries the approved team members over. They cannot
approve anyone. Every command that encrypts refuses an artifact the caller reaches
only as a successor.

### The successor in the browser

The successor sections of the app's **Account** tab do what the commands do:

- **Your successor** shows the current successor and any request, and
  nominates someone from their email, their code, and the user's password.
  A wrong code changes nothing.
- **Your code** shows the user's own successor code.
- **Notice address** sets or clears the personal address for notices.
- **Users who named you** lists each nomination of the caller, with a button
  to ask for access. Once a nomination is released, the row links to each
  artifact the nominating user owns, and the viewer opens it from the estate
  copies.

Two banners appear at the top of every tab:

- While a request is pending, the user sees who asked and when it releases,
  with a **Refuse** button.
- After a release, the user sees that the successor can read their
  artifacts, and that Cairn refuses their changes until they rotate keys.

The page rereads `GET /api/me` at each tab change, and after a refusal the
server turns down, so a request made, refused, or released since the page
loaded shows without a reload.

The `/refuse` page needs no session, so it works for a deactivated account.
The user enters their email, then their password or their recovery code.
On success the page names the successor and the request it refused, and
says so when an administrator deactivated the account during the request.
A recovery code fails the same way whether it is wrong or no request is
pending, since the fake answer cannot tell them apart, so the error names
both.

The viewer reaches an artifact as a successor only when the caller holds no
wrap for it and the server serves estate copies. It then reads the owner's
entry in `GET /api/successions`. It refuses a nomination that is not released,
and one whose record does not verify under the owner's key or does not name
the caller. It unwraps `EK`, opens each estate copy, checks it against the
membership record, and zeroes `EK` afterwards.

### Accepted risks for the successor

- **A replayed nomination.** The chain check reads the previous owner's latest
  `successor` record as the server serves it. A server colluding with an
  administrator could serve an older record that the owner has since replaced,
  and make a handover to the successor it names silent. This needs the owner
  to have nominated that user at some point, and the handover still shows in
  the chain.
- **Polling a refusal.** As described under [Refusing](#refusing), anyone who
  polls `POST /api/auth/refuse/begin` for an address can tell that a request
  is pending.

## Deploy integrity

Milestone 8 lets anyone check that a server sends browsers the files and pages
of a signed release. See [Deploy integrity](e2e-trust-model.md#deploy-integrity).

### Release manifest

A release build embeds a manifest signed with the release key, with the
`release` purpose in [wire formats](e2e-wire-formats.md#signatures). It lists:

- Every file the server sends as embedded, by origin and path, with its
  SHA-256. These are the app's scripts, styles, and vendored WebAssembly, and
  the `/_cairn/` files of the content origin.
- The source of every HTML template. A page depends on the deployment, so
  `cairn verify` renders the template itself and compares the result.

The release workflow signs the manifest with `cairn-release sign` before it
builds, so the manifest is not one of the assets it lists. A build without
the release key embeds no manifest.

`GET /.well-known/cairn-release` needs no session and answers on the app
origin only:

```json
{"manifest": <the signed envelope, or null>,
 "appOrigin": "https://cairn.example.com",
 "contentOrigin": "https://*.example-usercontent.com",
 "google": false, "passkeys": true}
```

Only `manifest` is signed. `appOrigin` must be the origin `cairn verify` was
pointed at, compared in lowercase with any default port dropped.
`contentOrigin` must have the same scheme and port as `appOrigin`, and a `*`
label, which the check replaces with a random artifact ID. `google` and
`passkeys` are the sign-in mode the account pages render for, so the check
renders them the same way. They only choose a branch of a signed template, so
a server that misstates them changes a data attribute, never code.

### Commands for deploy integrity

| Command | Does |
| --- | --- |
| `cairn verify [URL]` | Checks the server at `URL`, or the logged-in server, against its signed manifest |
| `cairn verify --manifest FILE` | Checks against a manifest file instead of the one the server serves |
| `cairn verify --key KEY` | Trusts a release public key, base64url, as well as the compiled-in keys (repeatable) |
| `cairn verify --version V` | Fails unless the manifest is for release `V` |
| `cairn verify --allow-skip` | Passes even when a page was skipped for want of a login |
| `cairn-release keygen` | Prints a new release key: the secret for `CAIRN_RELEASE_KEY`, and its public key |
| `cairn-release public` | Prints the public key of `CAIRN_RELEASE_KEY` |
| `cairn-release sign -version V` | Signs this tree's manifest with `CAIRN_RELEASE_KEY` into `internal/release/manifest.json` |

`cairn verify` fetches every asset and every page and reports each one that
differs, as well as each one that fails to load. It exits non-zero if any
does, and when any page is skipped, unless `--allow-skip` is given. It
follows no redirects, and compares bodies, not headers. Without `--version`,
a pass means the server runs some genuine signed release, not a particular
one. It checks these pages:

- `/login`, `/signup`, `/verify`, `/forgot`, `/reset`, and `/refuse`
- `/shared/{id}` and `/full/{id}`
- `/_cairn/boot` on the content origin

It also checks `/app` when the logged-in host is the server checked. It sends
the login's bearer for that page alone, and to no other host. Without a login,
it skips `/app`, and that skip fails the check unless `--allow-skip` is
given.

A server could send genuine files to the checker and altered ones to a
target. `cairn verify` is a spot check, not the control.

## Managers

Milestone R2 of [roles, groups, and folders](rbac-folders.md) adds the
**manager** role. An owner lists a member as `manager`. A manager can do
everything an editor can, and also signs member lists: share, unshare, change
roles below manager, approve and list team members, make the artifact public
or private, and start a new epoch. Only the owner adds, removes, or changes a
manager, transfers ownership, deletes the artifact, or vouches for a version.

### Manager-signed records

A record signed by a manager is a version 2 body: the version 1 fields plus
`signer` and `signerFp`, both required.

```json
{"v": 2, "...": "every version 1 field", "signer": "user ID", "signerFp": "64 hex"}
```

- `signer` is the manager's user ID and `signerFp` the fingerprint of the key
  that signed it. The envelope's `signer` is the same user ID.
- A record the owner signs stays version 1, so every existing chain stays
  valid. A version 1 body has neither field; a version 2 body has both, and
  `signer` is never the owner.
- `role` in a member entry is `viewer`, `editor`, or `manager`.

A version 2 record is accepted, by the server and by every client, only when
all of these hold, on top of every rule for a version 1 record:

- The previous record lists `signer` as `manager`. A first record is never
  version 2.
- The record verifies under the key `signerFp` names. A client reaches that
  key through the manager's rotation chain from the `fp` the previous record
  lists for them; the server requires `signerFp` to be the manager's current
  fingerprint.
- `owner` is the previous record's owner, and `ownerFp` follows from the
  previous record's by the owner's rotation chain, as for an owner's record
  that keeps the owner.
- `transfer` and `handover` are empty.
- Every entry with role `manager`, in the previous record or this one, appears
  in both with the same `user`, `role`, and `fp`. A manager can therefore add
  no manager, remove none, change none's role or `fp`, and cannot remove or
  change their own entry.
- A viewer account is never a new `editor` or `manager`, in any record.
- Every entry in the previous record's `excluded` is still in this record's.
  A manager therefore cannot list a user anyone removed again: only the owner
  re-shares an excluded user, so a manager cannot undo the owner's removal of
  someone, a manager included.

An owner's record that removes a manager, or demotes one to viewer, starts a
new epoch, as removing an editor does. Demoting a manager to editor stays in
the same epoch, because both hold the same keys.

### Wraps when a manager starts an epoch

The owner holds no wraps and reads each epoch through the estate copy, which
only the owner can seal. So a next-epoch record signed by a manager carries,
instead of an estate copy, a wrap of the new epoch for the owner: the owner
counts as a listed member for that epoch's wraps. The server refuses an
estate copy in a manager's change.

The owner's client adds the missing estate copy the next time it opens the
artifact, from its own wrap:

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `PUT /api/artifacts/{id}/estate/{epoch}` | The owner, with any credential | `{"sealed"}`, the estate copy of that epoch's `AK`, accepted only when the epoch exists and has none |

Until then, a released successor cannot read that epoch, and the owner's
client reads it through its wrap.

Before sealing the new epoch's `AK` to the owner, a manager's client checks
the owner's key from the directory against the chain: its fingerprint is the
latest record's `ownerFp`, or the owner's rotation chain links the two.
Otherwise it refuses, because a server could serve its own key in the owner's
place and so learn the new `AK`.

A wrap for the owner that does not open, or whose `AK` does not match the
epoch's `akCommit`, must not lock the owner out. The owner's client leaves
that epoch out, names it as unreadable, and carries on with every action that
does not need it, so the owner can still remove the manager who sent it and
start a new epoch. The unreadable epoch's content stays unreadable to the
owner.

Key rotation is one of those actions. The owner's client leaves the
unreadable epoch out of both `wraps` and `estate`, and the server accepts
that for an epoch that had no estate copy before the rotation. The owner's
wrap at that epoch stays as it is, under the old fingerprint, as a wrap left
by a password-only reset does, and the epoch stays without an estate copy.

### Who counts as a writer

A client accepts a manifest, revision, record, or approval signed by the
owner, an editor, or a manager listed under that key, by the same rules as an
editor today. The server's permission table gives a manager every editor
action plus `Share`, `ApproveMember`, and `ListPending`; `Delete`,
`Transfer`, and `ReviewVersions` stay with the owner. An ownership offer may
go to a listed editor or manager.

### Commands for managers

- `cairn share ITEM USER --role manager` works for the owner only.
- A manager runs `cairn share`, `cairn unshare`, `cairn public`, and
  `cairn team` like the owner, for roles below manager.
- `cairn members` shows each record's signer when it is not the owner.

### Left for later

When an owner removes a manager, the plan has the client list the member-list
changes that manager signed, for review. R2 records each record's signer, so
the list can be built later; it does not show it yet.

## Folders

Milestone F1 of the [roles, groups, and folders plan](rbac-folders.md). A
folder is an artifact with no content: it has an owner, a signed member list,
epochs, its own key, and encrypted metadata, and it has no versions,
database, or files. In F1 a folder is private to its owner. Sharing a folder,
and what its sharing means for the items inside, arrive with F2.

### Folder data

- `artifacts.kind` is `artifact` or `folder`, `artifact` by default.
- `artifacts.parent_id` names the folder an item sits in, or is null at the
  top level. It references `artifacts(id)` with `ON DELETE SET NULL`, so an
  item whose folder disappears lands at the top level rather than being lost.
- The artifact view gains `kind` and `parent`. `parent` is the folder's ID
  only when the caller can read that folder, and null otherwise, so a reader
  of a shared item does not learn where its owner keeps it.
- A folder's name and description are the artifact `name` and `description`
  metadata fields, sealed under the folder's own key like any artifact's.

### Endpoints for folders

| Method and path | Access | Purpose |
| --- | --- | --- |
| `POST /api/artifacts` | Any, not a viewer account | Create an artifact or a folder, optionally inside a folder |
| `PUT /api/artifacts/{id}/parent` | Owner of the item | Move the item into a folder, or to the top level |
| `DELETE /api/artifacts/{id}` | Owner | Delete an artifact, or an empty folder |

`POST /api/artifacts` takes two more optional fields: `kind`, `artifact` or
`folder`, and `parent`, a folder ID. `PUT .../parent` takes
`{"parent": "<folder ID>"}`, or `{"parent": null}` for the top level, and
answers with the item's view.

### Server checks for folders

- **Placing an item.** On create and on move, `parent`, when set, must be a
  folder (`kind` is `folder`) that the caller owns, and the caller must own
  the item. Otherwise the answer is `404` for a folder the caller cannot read,
  and `403` for one they can read but do not own.
- **Depth.** A folder chain is at most 16 deep: from the top level down to an
  item's parent, at most 16 folders. A move counts the deepest folder in the
  moved subtree. A create or move that would exceed it is refused with `409`.
- **Cycles.** A folder cannot move into itself or into a folder inside it:
  `409`.
- **No content.** A folder refuses every version, push, database, file,
  manifest, blob, review, resource, and content-token route with `409` and
  `a folder holds no content`.
- **Private in F1.** A membership record for a folder must list no members,
  keep `team` at `none`, and keep `public` and `publicWrites` off. Otherwise
  it is refused with `409` and `folders cannot be shared yet`. An ownership
  offer for a folder is refused with `409` and `a folder cannot be
  transferred`, in every milestone.
- **Deleting.** A folder that still holds items is refused with `409` and
  `the folder is not empty`. The client deletes the contents first.
- **Transfers.** An item keeps its folder when its ownership changes, as
  in Google Drive, whether the new owner accepts an offer or an
  administrator hands the item over. The accepting record names the same
  folder and keeps the inherited entries, so the new owner need not read
  the folder. The folder's owner stays an inherited manager, unless they
  are the new owner. The artifact view names the folder's owner in
  `folderOwner`, by user ID, to the item's owner, its managers, and the
  user an open offer names, even when they cannot read the folder. The
  server refuses an accepting record that does not list that user as a
  manager, so a false `folderOwner` only makes the acceptance fail. Until
  F3 the item moved to the new owner's top level.

The tree's shape is visible to the server, and it is not signed: the server
sees which items sit together, and a hostile server could show an item in
the wrong folder. Names stay sealed, so it never learns what anything is
called.

### Clients for folders

- **Listing.** `GET /api/artifacts` returns folders with everything else. A
  client builds the tree from `kind` and `parent`.
- **Deleting a folder.** The client lists the folder's subtree, deletes every
  artifact in it, then each folder from the deepest up, and the folder last.
  It reports progress, and running it again finishes an interrupted delete.
  Before it starts, the page and the command-line tool show how many folders
  and artifacts the delete removes.
- **Opening a folder's address.** `/shared/{id}` for a folder shows that the
  item is a folder, and links back to it on the **Artifacts** tab.

### Commands for folders

All take `--json`. A `FOLDER` or `ITEM` is an ID or an exact name, as
elsewhere.

- `cairn folder create NAME [--in FOLDER]` creates a folder.
- `cairn folder list [FOLDER]` prints the tree under a folder, or the whole
  tree of the caller's own items.
- `cairn folder delete FOLDER [--yes]` deletes a folder and everything in it,
  after printing what the delete removes and asking, unless `--yes` is
  given.
- `cairn move ITEM --to FOLDER` or `cairn move ITEM --top` moves an item.
- `cairn push DIR --artifact NAME --create --in FOLDER` creates the artifact
  inside a folder.
- `cairn artifact create NAME --in FOLDER` does the same without a push.
- `cairn artifact list` prints each item's folder path, and `--json` adds
  `kind` and `parent`.
- `cairn artifact update FOLDER --name NAME` renames a folder, as it renames
  an artifact.

### The tree on the Artifacts tab

- **Your artifacts** becomes a tree of the caller's own items: folders first,
  then artifacts, each sorted by name. A breadcrumb over it shows the folder
  in view, and clicking a folder opens it.
- **New folder** creates a folder in the one in view.
- Each own item has **Move to…**, which offers the top level and every own
  folder it can move into, and it can be dragged onto a folder row or a
  breadcrumb.
- A folder row has **Rename** and **Delete**. Delete states how many folders
  and artifacts it removes, and shows progress.
- **Shared with you** stays a flat list in F1.

## Groups

Milestone R3a of the [roles, groups, and folders plan](rbac-folders.md): a
group is a named set of users, kept as a signed chain of group records. This
milestone builds the records, their checks, and managing groups. Sharing an
artifact with a group arrives with R3b, and in the browser with R3c.

### Group records

A group record is a `group` envelope, with the body in
[Signatures](e2e-wire-formats.md#signatures):

- The creator signs the first record: `seq` 1, `prev` empty, and the creator
  listed as `manager` under `signerFp`.
- Each later record is signed by a user listed as `manager` in the previous
  record. The key that signed it is the one listed for them there, or one
  their rotation chain links to it, as for a manager's membership record.
- Every record keeps the same `group`, and lists at least one manager.
- A manager may add and remove members and managers, change roles, rename
  the group, and remove themselves while another manager remains.

Each signer's key is anchored the way a member's key is in a share. The
client takes the signer's current key from the directory and follows it from
its pin for that user: the pinned key, or one the signer's rotation chain
links forward from it. A changed key that no rotation explains is refused
until the person at the client accepts it, and an unpinned signer is pinned
as unverified. The key that signed a record is that current key, or an
earlier one the signer's rotation chain links to it. Without this, a server
could serve a whole chain signed by keys it made for real user IDs.

A client accepts a group's chain only when every record passes these rules
and each signature verifies. It then checks the chain against the keyring's
`groups` entry, refusing one that is shorter or forked, and stores the new
`seq` and `head`. It does this before it shows a group's members, and before
it adds a member or signs a record. The Go client in `internal/e2e` and the
browser in `e2e.mjs` check the same vectors, in a `group` section of
`vectors.json`.

### Endpoints for groups

| Method and path | Access | Purpose |
| --- | --- | --- |
| `GET /api/groups` | Any | Every group, with its name, its latest `seq`, its number of members, and the caller's role in it |
| `POST /api/groups` | Any, not a viewer account | Create a group with its first record |
| `GET /api/groups/{id}` | Any | The group, with every record, oldest first |
| `PUT /api/groups/{id}` | A manager of the group | Add the next record |
| `DELETE /api/groups/{id}` | A manager, or an administrator | Delete the group |

A group's name and members are visible to every signed-in user, like the
directory, so any caller reads every group. `POST` and `PUT` take
`{"record": envelope}` and answer with the group. The group view is
`{"id", "name", "seq", "members", "role", "records", "signers"}`: `members`
is the count, `role` is the caller's role or empty, and `records` and
`signers` are present only in `GET /api/groups/{id}` and the answers to
`POST` and `PUT`. `signers` maps the user ID of everyone who signed a record
to `{"x25519", "ed25519", "rotations"}`: their current public keys and their
rotation records, oldest first. It includes a deactivated account, which the
directory leaves out, so a group stays readable after a manager leaves.
These keys are served by the server, so a client anchors them as
[Group records](#group-records) describes before it uses them.

### Server checks for groups

- The envelope's signer is the caller, its signature verifies under the
  caller's current key, and `signerFp` is the caller's current fingerprint. A
  viewer account signs no group record: `403`.
- **First record.** `group` is a random lowercase UUID never used before,
  by a group that exists or one that was deleted, `seq` is 1, `prev` is
  empty, and the caller is listed as `manager`. The server keeps the ID of
  each deleted group for this, so a client that holds a deleted group's head
  never meets a new chain under the same ID.
- **Later record.** `seq` is one more than the stored latest, `prev` is the
  hash of its body, and the caller is listed as `manager` in it, under their
  current fingerprint or one their rotation records link to it. A record
  that lost a race answers `409`, so the client reads the group again.
- Every user a record adds, or whose entry changes, is a verified and active
  account, listed under their current fingerprint. A record may not make a
  viewer account a manager. An entry carried over unchanged is not checked
  again, so a deactivated member stays listed until a manager removes them.
- The body passes the rules in
  [Signatures](e2e-wire-formats.md#signatures): its keys, the sorted unique
  members, the size limits, the name, and at least one manager.
- Deleting a group removes its records. An artifact shared with it loses
  that share at once, from R3b on.
- An account that signed a record of a group that still exists cannot be
  deleted: `409`, as for an account that owns artifacts. An administrator
  deactivates it instead, and the group view keeps serving its keys.

### Clients for groups

- Adding a member uses their fingerprint from the directory, checked against
  the caller's pin as a share does: a changed key is refused until the
  person at the client accepts it.
- A command or page shows a group's members only from a chain it accepted,
  with each member's fingerprint and pin state.
- A signer still listed in the directory must have the same current key
  there as in `signers`; a difference is refused. This stops a server from
  planting a pin of its own key for a real user when it first serves a group.
- A client stores a group's new head in the keyring only if the keyring still
  holds the head it checked against. If another device stored a newer head in
  the meantime, the client reads the group again rather than show the older
  chain.
- Deleting a group removes its entry from the caller's keyring. Nothing else
  removes an entry, so a server that claims a group is gone cannot clear the
  record of its newest head.
- A `GROUP` argument is a group ID or an exact name. Names need not be
  unique, so a name two groups share is refused as ambiguous.

### Commands for groups

All take `--json`.

- `cairn group create NAME [--member USER]...`
- `cairn group list`
- `cairn group show GROUP`, with each member's role, fingerprint, and pin
  state
- `cairn group add GROUP USER [--manager] [--accept-new-key]`
- `cairn group remove GROUP USER`
- `cairn group rename GROUP NAME`
- `cairn group delete GROUP`

### A tab for groups

A **Groups** tab lists every group, the caller's own first, with the
caller's role in each. **New group** creates one. Opening a group shows its
members, with role, fingerprint state, and email. A manager can add a member
by email, as member or manager, change a role, remove a member, rename the
group, and delete it. An administrator can delete any group.

## Sharing with groups

Milestone R3b of the [roles, groups, and folders plan](rbac-folders.md): an
owner or manager shares an artifact with a group, the way the team share
works today, and the team share is named **Everyone**. The browser shares
with groups from R3c; until then it reads such an artifact but refuses to
change its member list, as it does while a team share is on.

### Groups in a member list

A membership record lists its groups in `groups`, each with a role, `viewer`
or `editor` (see [Signatures](e2e-wire-formats.md#signatures)). Like the team
share, a group grants nothing by itself:

- **Newcomers.** A verified, active member of a listed group who is not
  listed, not excluded, and holds no wrap is pending, as `new`. An owner,
  manager, or listed editor approves them by name and fingerprint, and their
  client seals every epoch's key to them, exactly as a team approval does.
- **Reading.** An unlisted user who holds a wrap at the current epoch reads
  the artifact while the team share is on, or while they are a member of a
  listed group in that group's latest record. The server checks this on each
  request, so it never writes.
- **Leaving.** A user who leaves every listed group, and is not covered by
  the team share, stops matching at once: the server answers `404`. They
  show as `left` in the pending list, still holding the key, and the next
  epoch must list or exclude them, as for any unlisted holder.
- **Consent goes with the key.** An approval seals the epoch's key to a
  user, and that key stays with them until the next epoch. A user who left
  and is added back to a listed group before then reads again without a new
  approval, because they still hold the key an approver gave them.
- **Listing.** At the next epoch an approved user is listed under the highest
  role among the team share and the listed groups that hold them, from
  verified group chains. A viewer account is listed as `viewer` whatever that
  role is. A user who no longer qualifies is excluded instead.
- **Deleted groups.** A deleted group grants nothing. A record may keep
  listing it, and the next change made by a client drops it. A record may not
  add a group that does not exist.

### Server checks for groups in member lists

- The `groups` entries pass the rules in
  [Signatures](e2e-wire-formats.md#signatures), and every group a record adds
  exists. A manager's record may change `groups`, as it may change `team`.
- A same-epoch record may not leave an unlisted holder who qualified before
  it without a reason to read after it: dropping a group, or lowering the
  team share to `none`, while that leaves a holder uncovered needs a new
  epoch. A holder who had already left is not counted, because the record
  does not change what they can do.
- A next-epoch record lists or excludes every unlisted holder, as today.
- `POST /api/artifacts/{id}/keys` approves a user only while the team share
  is on or the user is a member of a listed group.
- `GET /api/artifacts/{id}/pending` adds `group`, the IDs of the listed
  groups that hold each `new` or `approved` user, and the state `left`.
- The server keeps the latest record's groups in a table, so the access check
  reads group membership without parsing records.

### Clients for groups in member lists

Before it approves a newcomer or lists an approved user, a client verifies
the chain of each listed group that holds them, anchored as in
[Group records](#group-records). The newcomer's fingerprint must equal the
one their group record lists; a difference is a key-change warning, as for
any share. A user the server lists under a group whose verified chain does
not hold them is not approved and not listed.

### Commands for sharing with groups

The second argument of `cairn share` and `cairn unshare` is a user when it
holds `@`, and the team share when it is `everyone`. An argument shaped like
an ID matches a group by its ID only, and otherwise a user ID; any other
argument is a group's exact name. A group's name is chosen by its managers,
so a name never stands in for an ID: a group named after someone's user ID
cannot take a share meant for that user. The command names the group it
acted on, with its ID.

- `cairn share ITEM GROUP --role viewer|editor` lists the group, then
  approves each of its current members whose checks pass, and names the rest
  as pending.
- `cairn unshare ITEM GROUP` drops the group, in a new epoch when someone
  held the key only through it.
- `cairn share ITEM everyone --role viewer|editor` and
  `cairn unshare ITEM everyone` turn the team share on and off. `cairn team`
  keeps working.
- `cairn approve ITEM` lists newcomers with the groups that hold them, and
  users who left with the hint to run `cairn unshare ITEM USER`, which
  excludes an unlisted holder in a new epoch.
- `cairn members ITEM` shows the listed groups with their names and roles.

### Sharing with groups in the browser

Milestone R3c brings the team share and group shares to the browser, which
until then refuses to change a member list that uses either.

- **The share dialog** lists users, groups, and **Everyone**, with the roles
  each may take: a user `viewer`, `editor`, or `manager`; a group or Everyone
  `viewer` or `editor`. Adding a group or Everyone writes the record, then
  approves the members whose checks pass, as `cairn share` does, and names
  the rest as waiting.
- **Waiting and left.** The dialog shows newcomers waiting for approval, with
  the group that holds each, their fingerprint, and **Approve**, and users
  who left, as still holding the key, with **Remove**, which starts a new
  epoch that excludes them.
- **Editors approve too.** An editor sees the waiting newcomers and
  **Approve** in the same dialog, and nothing else in it. The **Artifacts**
  tab marks each row with newcomers the caller can approve, and how many.
- **Every new epoch** the browser starts lists approved users and excludes
  users who left, under the same rules as the Go client, so the browser and
  the command-line tool build the same records from the same state.
- A group that no longer exists is dropped from the next record the browser
  writes, and the dialog says so.
- **Left for later.** The browser does not yet relist a listed member whose
  keys rotated, as the Go client does. A change that needs a new epoch while
  such a member is listed is refused with `member-key-changed`, naming them,
  and `cairn share` relists them.

## Shared folders

Milestone F2 of the [roles, groups, and folders plan](rbac-folders.md):
sharing a folder shares everything inside it, the way a shared folder in
Google Drive does. Every item in a folder still belongs to the folder's
owner in F2; items other people own arrive with F3.

### What a folder may list

A folder's member list may now list users, as `viewer`, `editor`, or
`manager`, and groups, as `viewer` or `editor`. It still keeps the team share
at `none` and stays private, because neither carries a mark of where it came
from. A folder's editors rename it; its owner and managers share it.

### Inherited entries

A member entry, and a `groups` entry, may carry `via`: the ID of the folder
it comes from. An entry without `via` is a direct grant. See
[Signatures](e2e-wire-formats.md#signatures).

- **More, never fewer.** A new membership record for an item inside a folder
  lists every user and group its parent folder lists, with at least the
  parent's role. A deactivated or unverified account, and a deleted group, are
  not required, because a record may not add them. A folder's own record
  already holds its ancestors' entries, so checking the parent covers every
  level. A record that drops an inherited
  entry, or lowers it below the parent's role, is refused while the item sits
  in that folder.
- **Marking.** An entry that exists only because of a folder carries `via`,
  naming the nearest folder that lists that user or group. An entry with a
  direct grant carries no `via`, and its role is the higher of the direct
  role and every inherited one. The raised role stays when the item leaves
  the folder, because the entry no longer records what the direct grant
  was. A folder's owner with a direct grant on an item placed in their
  folder therefore stays a manager of it afterwards; its owner can lower the
  entry by sharing again.
- **A mark must be true.** An entry with `via` names a folder that contains
  the item, and that folder's latest record lists that user or group.
- **Reading.** An entry with `via` counts only while that folder still
  contains the item and still lists the user or group. The server checks
  this on every request, so unsharing a folder, or moving an item out of it,
  stops access at once. Until the item's next epoch, such a user shows as
  `left` in the pending list, still holding the key, like a user who left a
  group.
- **The folder's role is the ceiling.** An entry with `via` grants no more
  than the role the folder currently gives that user, and the item is
  pending while its entry says more. Lowering someone on a folder, from
  editor to viewer, therefore takes effect on every item at once, before
  their records catch up.
- **Which folder a mark names.** `via` names the nearest folder that lists
  the user or group itself, which may hold the item's parent rather than be
  it. A change to that folder's record then reaches the whole subtree at
  once.

### Placement is signed

The server's tree is unsigned, so it must never decide whose keys an item is
sealed to. Each membership record therefore names its item's folder:

- A record may carry `folder`, the ID of the folder the item sits in, and
  leaves it out at the top level. See
  [Signatures](e2e-wire-formats.md#signatures).
- The server refuses a new record whose `folder` differs from the item's
  `parent`.
- A client copies a folder's entries into an item's record only when the
  item's latest verified record names that folder in `folder`, or when the
  client itself is placing the item there, by creating it or moving it,
  because then its user chose the folder. A fan-out walks only items whose
  record names the folder it came from, and refuses any other item the
  server lists as pending, naming it.
- A folder's own record names its parent the same way, so each level of
  the chain is signed by someone who could sign that folder.
- Display, and the server's own access checks, still use the server's tree:
  a server that lies about it can only hide items or show them in the wrong
  place, and it already decides who it serves.

### Fan-out

Sharing or unsharing a folder is one change to the folder, followed by one
change to each item inside it.

- **Sharing.** The client writes the folder's record, then, for each item in
  the folder's subtree, a same-epoch record that adds the new entries with
  `via` and seals every epoch's key to the new members.
- **Unsharing.** The client writes the folder's record, then, for each item,
  a next-epoch record that excludes users who held the item only through the
  folder, and re-seals its latest version, database, and files, as any
  removal does.
- **Moving.** Moving an item into a folder is followed by a record that
  names the folder and adds its entries. Moving it out is followed by a
  next-epoch record that excludes users who had it only through the folders
  it left.
- **Pending.** An item whose record lacks entries its parent requires is
  pending. The artifact view carries `inherit`: `ok`, or `pending` while the
  item's record is missing entries its parent lists or holds entries whose
  `via` no longer holds. A client finishes a fan-out by working through the
  pending items, so running the same command again resumes an interrupted
  one, and the page offers to finish it.
- **Progress.** The page and the command-line tool show how many items are
  done, because each item lands on its own.

### Server checks for shared folders

- A folder's record may list users and groups, under the rules for any
  member list; the team share and public stay refused with `409`.
- A new record for an item in a folder passes the more-never-fewer rule
  against its parent's latest record, and every `via` it carries is true.
  Otherwise the answer is `409`, and it names the entry at fault.
- Access ignores an entry whose `via` folder no longer contains the item or
  no longer lists that user or group.
- The artifact view carries `inherit`.

### Commands for shared folders

- `cairn share FOLDER USER|GROUP --role ...` and `cairn unshare FOLDER
  USER|GROUP` share and unshare a folder, then fan out with progress.
- `cairn move` fans out after a move.
- `cairn members ITEM` marks inherited entries with the folder they come
  from.

### The share dialog for a folder

The share dialog opens for a folder as for an artifact. It shows inherited
entries grayed, with the folder they come from, and does not offer to remove
or lower them. Sharing or unsharing shows progress over the items inside,
and a folder or item that is pending offers **Finish sharing**.

**Shared with you** becomes a tree in the same way as **Your artifacts**: a
shared folder opens to the items inside it that the caller can read, with a
breadcrumb. An item whose folder the caller cannot read stays at the top of
the list.

## Folders with other people's items

Milestone F3 of the [roles, groups, and folders plan](rbac-folders.md):
folder contents work as in Google Drive, so a folder can hold items that
other people own.

### Placing an item in someone else's folder

- An item may sit in a folder whose owner is someone else. Creating or
  moving an item into a folder needs editor access to the folder, or
  manager or owner access, and the caller must own the item or manage it.
  Moving an item out of a folder, or removing it, needs editor access to the
  folder it leaves, and puts it at the top level of its owner. The item's
  owner may always take it out, even after losing that access, so they can
  always clear a pending item of their own.
- Moving an item from one folder to another needs both: editor access to
  the folder it leaves and to the one it enters. The checks for depth and
  cycles stay as in F1.
- A folder's editors may create folders inside it. Each new folder belongs to
  the editor who creates it.
- A manager of an item may move it, but only its owner signs where it is: a
  manager's record may not change `folder`. The item shows as pending until
  its owner places it, with `cairn apply` or a move.
- **The folder's owner manages what is in it.** An item someone else owns
  lists the owner of its folder as an inherited `manager`, with `via` naming
  that folder, as a folder in Google Drive lets its owner edit and share what
  is inside. The more-never-fewer rule requires this entry like any other, a
  record listing them below `manager` is refused, and the entry ends when the
  item leaves the folder. The item's owner adds the entry when placing the
  item, because only an owner changes an item's managers.

### Inheritance others have to apply

The client that shares a folder signs the records of the items it can sign:
those its user owns or manages. Because a folder's owner manages everything
under it, a share by the folder's owner signs every item at once. Two cases
still wait on an item's owner, as in F2:

- someone other than the folder's owner shares it, and the item is not theirs
  to sign;
- the share adds a manager, which changes the item's managers, so only its
  owner signs it. A fan-out reports such an item as waiting on its owner.

- **Listed, not readable.** A member of a folder sees each item inside it.
  An item they cannot read yet appears as a stub, with its ID, its kind, its
  owner, and `inherit` `pending`, and no name, because its name is sealed
  under a key they do not hold yet. The page shows it as an item its owner
  has yet to share with them.
- **Applying.** `cairn apply` signs every pending record the caller can: it
  adds missing inherited entries, sealing each epoch's key to the new
  members, and starts a new epoch where a `via` entry no longer holds. It
  also approves the newcomers whose checks pass, as `cairn share` does for a
  group.
- **Applying automatically.** Sharing is the action, so no one has to apply
  a share by hand. A client that can sign applies the pending records by
  itself whenever it runs. The page does so after it loads the **Artifacts**
  lists, once per item and state, and shows what it did. The command-line
  tool does so before any command that can unlock the caller's keys, and
  prints a summary on standard error, so standard output is unchanged. This
  automatic apply signs inheritance only. Approving a group's newcomers stays
  a decision, made with **Approve** or an explicit `cairn apply`.
- **An item its folder no longer shows.** The server leaves `parent` null
  when the caller cannot read the item's folder, so a reader does not learn
  where its owner keeps it. To the item's owner and managers, such a view
  also carries `hiddenParent: true`. Applying leaves that item alone and
  reports that it needs a move. **Remove from folder**, or `cairn move` to
  the top level, takes it out.
- **An item the server moved to the top level.** An item with `parent` null
  and no `hiddenParent`, whose record still names a folder, was moved out by
  the server, because its folder was deleted or an editor removed it.
  Applying signs a record naming no folder, on the server's word. This is
  accepted: the server controls the item's folder anyway, and the new record
  only removes what the folder's members held.
- **Removal stays immediate.** Taking access away still needs no one to
  apply anything: the server stops serving at once, and the new epoch
  follows when the item's owner or a manager applies it.

### Deleting a folder with other people's items

Only the folder's owner deletes it. Before it starts, the page and the
command-line tool show what happens to everything inside. The page counts
what it deletes and what moves, and names the owners of what moves; the
command-line tool lists each item that moves, with its owner:

- Items the owner owns are deleted, folders included, down to any folder
  someone else owns.
- A folder someone else owns moves to that person's top level with
  everything inside it, and so does any other item someone else owns.
- The server refuses to delete a folder that still holds an item its owner
  owns, so the client deletes those first. Removing the folder then moves the
  remaining items to their owners' top levels, through
  `ON DELETE SET NULL`. People who had those items only through the deleted
  folder lose them at once on the server.

### Commands for other people's items

- `cairn apply [--json]` applies every pending record and approval the
  caller can, and prints what it did and what still waits on someone else.
  Other commands apply pending records, but not approvals, by themselves.
- `cairn folder list` shows stubs as `(not shared with you yet, owned by
  EMAIL)`.
