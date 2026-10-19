# Google sign-in and passkey unlock

Status: **implemented**. This document extends the
[trust model](e2e-trust-model.md) and the [HTTP API](e2e-api.md). It changes
how a person proves who they are. It does not change what the server can
read.

## Goal

A team that runs Google Workspace wants Cairn to use Google Accounts, so
that:

- Signing in uses the company's Google Account, with its MFA.
- Turning off someone's Google Account stops them signing in.
- Sign-up is limited to the Workspace domain without a verification email.

Every guarantee in the trust model still holds. Google, a Workspace
administrator, or the Cairn operator can at most sign in as a user. None of
them can read that user's work.

Two separate secrets do two separate jobs:

| Job | Without Google | With Google |
| --- | --- | --- |
| Prove who you are | The password, as `authKey` | A Google sign-in, then `authKey` |
| Unlock your keys | The password, as `kek` | The password, as `kek`, or a passkey you enrolled |

With Google configured, the password is still the passphrase that unlocks
`MK`. Google cannot replace it, because Google gives the browser nothing
secret that Google and the server do not also know.

**Passkey unlock** is opt-in for each user, on any server. A user who enrolls
a passkey that supports the WebAuthn PRF extension can sign in with it in
place of the passphrase. The passphrase and recovery code still exist and
still work.

## Changes to the threat model

These rows join the table in
[What the design protects](e2e-trust-model.md#what-the-design-protects):

| Adversary | Can read private content? |
| --- | --- |
| Someone who controls the user's Google Account, including a Workspace administrator who resets it | No. They pass the Google step, but still need the passphrase or an enrolled passkey. Guessing the passphrase goes through the server's sign-in rate limit, because the server returns the key bundle only after `authKey` checks out |
| Someone holding an unlocked device with an enrolled passkey | Yes, if they also pass the passkey's user verification: a fingerprint or the device PIN. This is the same as anyone who can unlock that device's password manager |

And these limits join
[What the design does not protect](e2e-trust-model.md#what-the-design-does-not-protect):

- **Turning off a Google Account does not end sessions or API keys.** A
  session lasts until it expires, and a device API key keeps working. To cut
  someone off at once, an administrator deactivates their Cairn account.
- **The server decides whether the Google step is required.** A malicious
  operator can skip it. This changes nothing, because the Google step was
  never what protected the content.

## Google sign-in

### Server flags

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--google-client-id` | `CAIRN_GOOGLE_CLIENT_ID` | The OAuth 2.0 client ID. Setting it turns on Google sign-in. |
| `--google-client-secret` | `CAIRN_GOOGLE_CLIENT_SECRET` | The OAuth 2.0 client secret. Required with the client ID. |

The redirect URI is `--public-url` followed by `/auth/google/callback`, so a
server with a client ID and no public URL refuses to start. Register that URI
on the OAuth 2.0 client in the GCP console.

`--smtp-url` stays required. Successor notices and reset notices still go by
mail.

### Google proofs

A Google proof is a single-use, server-side record that says a browser
completed Google sign-in for an address, a few minutes ago. It is the only
thing the Google step produces, and it carries no key material.

- The server stores the SHA-256 of a 32-byte random token, the normalized
  address, the Google display name, an expiry, and the time it was used.
- A proof expires 10 minutes after it is made.
- The browser holds the token in an `HttpOnly`, `SameSite=Strict` cookie,
  `__Host-cairn_google` behind `https` and `cairn_google` otherwise.
- The command-line tool receives a token of its own; see
  [The command-line tool](#the-command-line-tool).

### The flow

1. A page sends the browser to `GET /auth/google?next=<path>`.
2. The server makes a random `state` and a PKCE verifier. It stores both,
   with `next` after the safe-next rule, in a short-lived `HttpOnly`,
   `SameSite=Lax` cookie scoped to `/auth/google`. That cookie is
   `__Secure-cairn_oauth` behind `https`. It must be `Lax`, because Google
   sends the browser back with a cross-site navigation.
3. The server redirects to Google's authorization endpoint with
   `scope=openid email profile`, the `state`, the PKCE challenge, and
   `prompt=select_account`.
4. Google redirects to `GET /auth/google/callback`. The server checks `state`
   in constant time, then exchanges the code at Google's token endpoint with
   the client secret and the PKCE verifier.
5. The server checks the ID token. On success it makes a Google proof, sets
   the proof cookie, and redirects to `next`.

The ID token comes straight from Google's token endpoint over TLS,
authenticated with the client secret, so OpenID Connect allows the server to
skip checking its signature. The server still checks every claim:

- `iss` is `https://accounts.google.com` or `accounts.google.com`.
- `aud` is the client ID.
- `exp` has not passed.
- `email` is present and `email_verified` is true.
- When the address's domain is one of the `--signup-domain` values, `hd`
  equals that domain. This refuses a personal Google Account created with a
  company address, which the Workspace administrator does not control. The
  `--admin-email` address is exempt when its domain is not a signup domain.

Any failure renders the sign-in page with an error, and makes no proof.

### What a proof unlocks

| Endpoint | Without Google | With Google |
| --- | --- | --- |
| `GET /api/auth/google` | `404` | `{"email", "name"}` for the proof cookie, or `401`. It does not use the proof |
| `POST /api/auth/signup` | Unchanged | Requires a proof for the same address. The account is verified at once and no mail is sent. An address that already has an account gets `409`, because the caller proved they own it |
| `POST /api/auth/login` | Unchanged | Requires a proof for the same address, from the cookie or the `googleProof` field. The proof is used only when sign-in succeeds, so a mistyped passphrase can be retried until it expires |
| `POST /api/auth/forgot` | Unchanged | Requires a proof. Instead of mailing a link, it answers `{"token"}`, the same reset token the link carries, and uses the proof. The page continues at `/reset#token=…` |
| `POST /api/auth/passkey/finish` | No proof | Requires a proof for the credential's owner, and uses it |

Without a proof, each of these answers `403` with
`{"error": "sign in with Google first"}`. A proof for another address answers
the same.

`POST /api/auth/refuse` and `/refuse` need no proof. A user who has left the
company refuses a successor's request after their Google Account is gone, so
the refusal must not depend on it.

`GET /api/auth/config` answers `{"google": bool}` on every server, so the
command-line tool knows which flow to run.

### Pages

- **`/login`** shows **Continue with Google** while there is no proof. With a
  proof, it shows the address as text and asks for the passphrase, plus
  **Unlock with a passkey**. Without Google, the page keeps its email and
  password form and adds **Sign in with a passkey**.
- **`/signup`** shows **Continue with Google** first. With a proof, the
  address is fixed, and the page asks for a name and a passphrase, shows the
  recovery code, then signs in with the passphrase just chosen.
- **`/forgot`** shows **Continue with Google**. With a proof, it asks the
  server for the reset token and opens `/reset`.

The server renders each page with `data-google` set, so the page knows the
mode before it makes a request. The pages load no inline script, under the
app CSP.

### The command-line tool

`cairn login` reads `GET /api/auth/config`. Without Google, it runs today's
flow. With Google:

1. The tool listens on `127.0.0.1` on a random port, and makes a random
   `state` of at least 16 characters.
2. It opens `/auth/cli?port=<port>&state=<state>` in the browser and prints
   that URL too.
3. Without a proof, the page sends the browser through Google and back.
4. With a proof, the page names the address. It asks the user to confirm
   signing in the tool on this computer.
5. On confirmation the page sends `POST /api/auth/cli` with
   `{"port", "state"}`. The server uses the cookie's proof, makes a new proof
   for the same address that expires in 2 minutes, and answers
   `{"redirect": "http://127.0.0.1:<port>/callback?state=…&email=…&proof=…"}`.
6. The page navigates to that address. The tool checks `state`, then asks
   for the passphrase in the terminal and signs in as before, with the proof
   in `googleProof`. It then creates its device API key.

`cairn signup` and `cairn forgot` refuse on a Google server and point to the
web pages, because both need a browser for the Google step anyway.

## Passkey unlock

### Keys

```text
passkey PRF output ──HKDF("cairn/v1/passkey", user ID, credential ID)──► passkeyKek
MK stored as AES-GCM(passkeyKek, MK), bound to "mk" and the credential ID
```

The PRF input is the UTF-8 bytes of `cairn/v1/passkey-prf`, the same for
every credential. The authenticator mixes in a secret of its own, so the
output differs for every credential and never leaves the client. Both labels
join the label table in
[wire formats](e2e-wire-formats.md), with a test vector.

### Enrolling

Enrolling needs `MK`, so it asks for the passphrase, on the app's
**Account** tab only.

1. The page runs `unlock` with the passphrase, which yields `authKey` and
   `MK`.
2. It calls `navigator.credentials.create` with these options:
   - The app host as the relying party ID.
   - The user ID as the user handle.
   - A resident key, required.
   - User verification, required.
   - The PRF extension, asked to evaluate the PRF input.
3. When the result does not report PRF as enabled, the page stops and says
   this passkey cannot unlock Cairn. Nothing is stored.
4. When `create` returned no PRF output, the page runs
   `navigator.credentials.get` for that one credential to get it.
5. It derives `passkeyKek`, seals `MK`, and sends `POST /api/me/passkeys`.

The server checks `authKey`, as it does before creating an API key. It
stores the credential ID, the public key as SPKI, the COSE algorithm, a name,
and the sealed `MK`.

Registration verifies no attestation, and the server sends no challenge. With
attestation set to `none`, a challenge proves nothing that the session and the
fresh `authKey` have not already proved.

### Unlocking

1. The page asks `POST /api/auth/passkey/begin` for a challenge. The server
   keeps the challenge in memory, single use, for 2 minutes.
2. It calls `navigator.credentials.get` with the challenge, the relying
   party ID, user verification required, no credential list, and the PRF
   input.
3. It sends `POST /api/auth/passkey/finish` with the credential ID, the
   client data, the authenticator data, the signature, and the user handle.
4. The server checks the assertion, starts a session, and answers like
   sign-in, plus `passkeyMk`, that credential's sealed `MK`.
5. The page derives `passkeyKek` from the PRF output, opens `MK`, and opens
   the rest of the bundle the same way a passphrase sign-in does.

The server refuses the assertion unless every check passes:

- The credential exists, and its user is verified and not deactivated.
- The client data's `type` is `webauthn.get`, its `challenge` is one the
  server issued and has not used, and its `origin` is the public URL's
  origin.
- The authenticator data starts with the SHA-256 of the relying party ID,
  and has both the user-present and user-verified flags set.
- The signature verifies over the authenticator data followed by the SHA-256
  of the client data, under the stored key. Ed25519, ECDSA P-256 with
  SHA-256, and RSA PKCS#1 v1.5 with SHA-256 are accepted.
- When the stored signature counter or the new one is nonzero, the new one
  is greater.
- With Google configured, there is a proof for the credential owner's
  address.

A failure counts against the IP address in the sign-in rate limit.

The relying party ID is the app host. Artifacts run on a separately
registered content domain, so an artifact cannot ask for an assertion.

### Lifecycle

| Event | Passkeys |
| --- | --- |
| Password change | Kept: `MK` is unchanged |
| New recovery code | Kept |
| Reset with the recovery code | Kept, as API keys are |
| Reset without the recovery code | Archived with the bundle and removed, as API keys are |
| Key rotation | Removed, because `MK` changes. The user enrolls again |
| Account deleted | Removed with it |

Actions that need `MK` in the browser, such as creating an API key, changing
the passphrase, or rotating keys, still ask for the passphrase. A passkey
signs a user in. It does not stand in for the passphrase when the server
checks a fresh `authKey`.

## Endpoints

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /auth/google` | None | Starts Google sign-in |
| `GET /auth/google/callback` | None | Finishes it and makes a proof |
| `GET /auth/cli` | None | The page that hands a proof to the command-line tool |
| `GET /api/auth/config` | None | `{"google": bool}` |
| `GET /api/auth/google` | Proof cookie | The proof's address and name |
| `POST /api/auth/cli` | Proof cookie | A proof for the command-line tool |
| `POST /api/auth/passkey/begin` | None | `{"challenge", "rpId"}` |
| `POST /api/auth/passkey/finish` | None, plus a proof on a Google server | Signs in with a passkey |
| `GET /api/me/passkeys` | Any | The caller's passkeys: `id`, `name`, `createdAt`, `lastUsedAt` |
| `POST /api/me/passkeys` | Session | Enrolls a passkey, with a fresh `authKey` |
| `DELETE /api/me/passkeys/{id}` | Any | Removes one |

Every `POST` under `/api/` keeps the request protection that
[Sessions and request protection](e2e-trust-model.md#sessions-and-request-protection)
describes: each needs a JSON body and a same-origin request.

## Data

Migration `011_google_proofs.sql` adds `google_proofs`: `hash`, `email`,
`name`, `expires_at`, `used_at`. It has no user ID, because a proof can come
before the account exists.

Migration `012_passkeys.sql` adds:

- `passkeys`: `id` (the credential ID, base64url), `user_id`, `name`,
  `public_key`, `alg`, `sign_count`, `mk`, `created_at`, `last_used_at`.
- A `passkeys` column on `bundle_archives`, holding the removed passkeys'
  credential IDs and sealed `MK`, as `api_keys` does.

## Accepted risks

- **The proof travels in a loopback URL** to the command-line tool, so it can
  appear in browser history. It is single use, lasts 2 minutes, and is
  useless without the passphrase.
- **Browser support for PRF is uneven.** Enrollment refuses an authenticator
  that does not support it, so nobody ends up with a passkey that cannot
  unlock.
- **A refused enrollment can leave a credential** on the authenticator that
  Cairn never stored. The page says so, and the user can delete it in their
  password manager.

## Milestones and tests

Each milestone leaves the server working, with its tests, and passes the
review gate.

| # | Milestone | Proof it works |
| --- | --- | --- |
| G1 | Google identity on the server: flags, the flow, ID token checks including `hd`, proofs, and the proof rules for sign-up, sign-in, and forgot | Go integration tests against a fake Google: a sign-in without a proof, with another address's proof, or with a used or expired proof is refused; a bad `state`, issuer, audience, expiry, unverified email, or missing `hd` makes no proof; a full sign-in succeeds; a mistyped passphrase leaves the proof usable |
| G2 | The web pages in Google mode | JavaScript unit tests of each flow with a fake `fetch`; a Playwright spec against a second server pointed at a fake Google: sign up, sign out, sign in, and reset with the recovery code |
| G3 | The command-line tool's Google login | A Go test that drives `cairn login` through `/auth/cli`, the fake Google, and the loopback listener, then runs a command with the saved key; a wrong `state` is refused |
| P1 | Passkeys on the server: migration, enrollment, challenges, assertion checks, lifecycle | Go tests with a software authenticator for each algorithm: every check in the list refuses when broken, a replayed challenge fails, rotation removes passkeys, a reset without the code archives them, and a Google server requires a proof |
| P2 | Passkeys in the browser: enrollment and removal on the **Account** tab, unlock on `/login` | JavaScript unit tests with a fake `navigator.credentials`; a Playwright spec on Chromium with a virtual authenticator that supports PRF: enroll, sign out, unlock with the passkey, open a private artifact |

The fake Google answers only in a binary built with the `e2egoogle` tag,
which reads its address from `CAIRN_TEST_GOOGLE_URL`. A release binary always
talks to Google.
