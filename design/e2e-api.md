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
