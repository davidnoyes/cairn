# End-to-end encrypted trust model

Status: **decisions agreed**, including the fixes from the security review.
Nothing in this document is implemented yet.

## Goal

Today every signed-in user can read and write every artifact, and the server
holds all content in plaintext. This design reverses that, for a team instance
hosted in GCP where every member can publish:

- An artifact is private to its owner by default.
- The owner can share it with named users or the whole team, or make it
  public, which means anyone who holds its public link.
- The server stores only ciphertext, for every artifact. An administrator, the
  owner's manager, an operator with access to the GCP project, or anyone
  holding a backup or disk snapshot cannot read any of them.
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
| An operator with write access to the live database | Not through a verified key. They can swap a key nobody has verified yet, or add a fake account for someone to approve into a team share; both leave a trace in GCP audit logs |
| Someone who controls the user's mailbox | No. They can reset the password and take over the account, but not read existing work |
| Another signed-in user who has no share | No |
| A shared artifact written by another user, running in your browser | Only that artifact, which you can already read. It cannot share, publish, or delete it, even when you own it |
| The successor the user nominated | Only the artifacts the user owns, 14 days after asking, unless the user refuses |
| An administrator handing a deactivated owner's artifact to an editor | No. The editor could already read it, and unless the editor is the owner's nominated successor, every member sees a notice of the handover |
| Anyone holding a public link | That one artifact only, until the owner makes it private |

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
- **The server can delete data or serve an older copy.** Signatures and
  authenticated encryption stop content forged by anyone who is not a current
  owner or editor, but they cannot prove that a copy is the latest one. Each
  client remembers the newest keyring and membership record it has seen and
  refuses an older one, which narrows this to data the client has not seen
  before. The keyring anchor that records this survives sign-out.
- **A new device has no rollback protection.** A browser or a `cairn`
  install that has never opened the account has no anchor, so it accepts
  whatever keyring the server serves first, however old.
- **The server can freeze a member on an old epoch.** It can keep serving a
  member an old membership record, so that member's client keeps encrypting
  under the old epoch. Until the client sees the new epoch, a removed user can
  read that member's new writes. The server's own epoch check does not help,
  because the server is the one skipping it.
- **A leaked old key can sign a fake rotation.** While someone holds a user's
  old key, a client that has not yet seen the user's real rotation can be
  shown a rotation to a key of the attacker's choosing. A client that has
  seen the real one raises the fork warning instead.
- **An editor's approval grants the whole history.** When an editor
  approves a team member, that person receives every epoch's `AK`, so they
  can read every earlier version, not only the ones after they joined.
- **Sign-in can reveal that an account exists, over time.** Prelogin answers
  an unknown address with a stable fake salt. A real account's salt changes
  when its password changes, and the fake one changes when someone signs up,
  so a person who asks repeatedly can tell the two apart.
- **The server could substitute a public key** the first time you share with
  someone. A fingerprint shows as unverified until you compare it with the
  person directly, and a later change raises a warning.
- **A team share trusts the team roster the server shows.** A new member
  receives the key only when an owner or editor approves them by name, so a
  fake account needs someone to approve it. The approver signs the approval,
  and the owner's client adds an approved member to the record only when
  that signature checks out, so the server cannot claim an approval nobody
  made.
- **A public link is the key.** Anyone who holds it can read the artifact,
  including people outside the company it is forwarded to. A link pasted into
  a chat app is stored by that app, so the app's administrators can read the
  artifact too. Making the artifact private stops the link working, but
  cannot take back a copy someone already saved.
- **A link holder has no pinned state.** The server can show them an older
  prefix of the membership chain, such as one from before a record that
  turned public writes off or removed an editor, as long as the artifact is
  still public at the link's epoch. Turning a link off needs a new epoch.
- **Artifact code can read its own artifact's key.** Every page of an artifact
  shares one origin, so code in the artifact can obtain the key it is
  decrypted with. That gives it nothing beyond what it can already read.
- **The successor's waiting period is enforced by the server.** A successor
  who holds a copy of the database or a backup can skip it, because the
  wrapped estate key is already in that copy. The user chose that one person,
  and can remove them at any time.
- **The server can hide a successor's removal.** When an administrator hands
  an artifact to a successor, clients check the user's signed nomination, but
  they cannot tell whether the server withheld a later record that removed
  it. A withheld removal makes the handover silent when it should show the
  administrator's notice.
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
  ├─ wraps the user's X25519 private key (encryption)
  ├─ wraps the user's Ed25519 private key (signing)
  ├─ wraps EK, the user's estate key
  └─ derives indexKey (HMAC) for resource lookups

EK (random 256-bit estate key)
  ├─ wraps every AK of every artifact the user owns
  └─ wrapped to the successor's X25519 public key, if the user nominated one

AK (random 256-bit artifact key, one per artifact per epoch)
  ├─ wrapped to each member's X25519 public key; the owner reaches it through EK
  ├─ carried after the # of a public link, never sent to the server
  ├─ derives linkToken, which the server stores as a hash
  ├─ derives fileKey, which addresses files as HMAC(fileKey, path)
  └─ derives a fresh key for every blob write
```

A user's fingerprint is a SHA-256 hash over both public keys, shown as short
groups for comparing aloud.

WebCrypto and the Go standard library provide every primitive below except
Argon2id. The browser gets Argon2id from a WebAssembly module vendored into
the binary, as Mermaid is; Go gets it from `golang.org/x/crypto/argon2`.

- Argon2id with 64 MiB of memory, 3 passes, and a per-user random salt. The
  parameters are stored per user, so they can be raised later without
  breaking existing accounts. The web client and the `cairn` tool refuse
  anything below 64 MiB, 3 passes, or a 16-byte salt, so the server can raise
  the parameters but never lower them. Argon2id resists GPU guessing far
  better than PBKDF2, which matters because disk snapshots are exactly what an
  offline attacker would start from.
- HKDF-SHA256 for every derived key.
- AES-256-GCM for all symmetric encryption.
- X25519 plus HKDF plus AES-GCM for wrapping a key to a user (ECIES).
- Ed25519 for signatures, over a canonical encoding that starts with a
  purpose label.

The recovery code is 128 random bits shown as base32 groups. It has enough
entropy to skip stretching.

### Labels, streams, and binding

Each rule here closes a specific gap: key reuse, truncation, or the server
moving ciphertext from one place to another.

- **Labels.** Every derivation uses a fixed, versioned HKDF label, such as
  `cairn/v1/auth`, `cairn/v1/kek`, `cairn/v1/index`, `cairn/v1/link-token`,
  `cairn/v1/file-key`, `cairn/v1/blob`, and `cairn/v1/wrap`. No two purposes
  share a label, so `linkToken`, which the server sees, reveals nothing about
  any other key.
- **A fresh key per blob write.** Each write picks a random 256-bit salt and
  stores it, with a format version, in an authenticated header. The blob key
  is `HKDF(AK, salt, "cairn/v1/blob" ‖ artifact ‖ version ‖ kind ‖ path)`,
  where `kind` is content, file, database, or metadata. Rewriting the same
  path or database therefore never reuses a key and nonce.
- **Chunked streams.** Blobs use 64 KiB chunks in the STREAM construction, as
  age and Tink do. Each chunk's nonce is an 11-byte chunk counter followed by
  a 1-byte last-chunk flag, so the server cannot drop, reorder, or truncate
  chunks without detection. The client can still seek.
- **Database revisions.** A database blob's associated data includes its
  revision number.
- **Key wrapping.** The ECIES derivation includes the purpose, artifact,
  epoch, recipient user ID, recipient public key, and ephemeral public key. A
  wrapped key cannot be moved to another artifact, epoch, or person.
- **Metadata.** Each encrypted metadata record is bound to its artifact,
  version, and field.

## Accounts and sign-in

The server never sees the password or anything it could derive `kek` from.

1. The client calls `POST /api/auth/prelogin` with an email and receives the
   salt and Argon2id parameters. For an unknown email the server returns a
   salt of `HMAC(serverSecret, normalizedEmail)` and the default parameters,
   so the endpoint does not reveal which accounts exist.
2. The client derives `authKey` and `kek`, then sends `authKey` to
   `POST /api/auth/login`.
3. The server checks `authKey` against its bcrypt hash, sets the session
   cookie, and returns the user's encrypted key bundle. It runs bcrypt for
   unknown accounts too, so timing does not reveal them either. Sign-in is
   rate limited per account and per IP address.
4. The client unwraps `MK`, then stores the private keys, `EK`, and `indexKey`
   in IndexedDB as non-extractable `CryptoKey` objects. `MK` itself is not
   kept. Actions that need it, such as creating an API key, ask for the
   password again, and only on a full-page app screen, never over an
   artifact. An artifact that draws a password prompt is therefore always a
   fake.
5. Signing out clears IndexedDB. It keeps the keyring anchor, a revision
   number and a hash that hold nothing secret, in `localStorage`, so the next
   sign-in on that browser still refuses an older keyring. `cairn logout`
   keeps the anchor in its config file the same way.

Because the server can no longer see the password, the client enforces its
strength with a vendored estimator, such as zxcvbn, requiring a score of 3 or
higher.

### Sessions and request protection

The app origin holds a usable private key, so its pages get the strictest
protection the browser offers:

- **Cookie.** With an `https` public URL, the session cookie is
  `__Host-cairn_session`: `Secure`, `HttpOnly`, `Path=/`, and
  `SameSite=Strict`. A strict cookie is not sent on a navigation that arrives
  from another site, so app pages must not depend on it when they first load.
  Authentication is checked on the API calls the page makes afterward.
- **Forged requests.** Every state-changing endpoint called with the cookie
  requires `Content-Type: application/json` and `Sec-Fetch-Site:
  same-origin`, falling back to an `Origin` check. Requests that carry an API
  key in the `Authorization` header are exempt, because a browser never
  attaches one by itself.
- **Content Security Policy.** App pages send `default-src 'self'`,
  `script-src 'self' 'wasm-unsafe-eval'`, `object-src 'none'`,
  `base-uri 'none'`, `frame-src` limited to the content domain,
  `frame-ancestors 'none'`, and `require-trusted-types-for 'script'`. The
  inline scripts in `login.html` and `admin.html` move to files.
- **Rendering.** Names, descriptions, changelogs, file names, and resource
  values are written by other members. The app origin renders them only as
  text, never as HTML. Mermaid, Markdown, and anything else that renders
  member-written content runs on a content origin.

### Self-signup

Self-signup replaces first-login-sets-password, and administrators no longer
create accounts.

1. Anyone with an address in an allowed domain signs up at `/signup` with an
   email and a password. `--signup-domain` sets the allowed domains; without
   it, self-signup is off, so a server on the internet is never open to
   everyone by accident.
2. The client generates `MK`, both key pairs, `EK`, and the recovery code,
   then uploads only wrapped material.
3. The client shows the recovery code and suggests saving it in a password
   manager or on paper, because a shared drive or an email is a poor place. It
   asks the user to retype one group to prove they saved it. The screen
   states that nobody,
   including an administrator, can recover their work without the password or
   this code.
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
- A leaked key, together with an old backup, still unwraps `MK`. The remedy is
  [rotating your keys](#rotating-your-keys). Per-artifact keys for CI, which
  wrap a single `AK`, are a later addition.

### Password reset and recovery

There is no administrator reset and no administrator recovery of any kind. A
route that let an administrator into one user's data, even a user who has
left, would let them into anyone's.

1. **Forgot password** emails a single-use link that expires after 30
   minutes. The server stores only a hash of its token. Every emailed link is
   built from `--public-url`, never from a request header.
2. The link lets the user choose a new password. It proves control of the
   mailbox and nothing more, so it never carries key material: the server
   writes the email, and mailbox administrators can read it.
3. The client then asks for the recovery code.
   - With the code, the client unwraps `MK` and wraps it again under the new
     password. Nothing is lost, and the key pairs stay the same, so nobody
     sees a key-change warning.
   - Without the code, the client generates a new `MK` and new key pairs. The
     user's old private work stays unreadable. Artifacts others shared with
     them can be shared again after the sharer sees the key-change warning and
     checks the new fingerprint.

A reset without the code never deletes the old wrapped keys: the
password-wrapped and recovery-wrapped `MK`, device keys, and the successor's
copy of `EK`. The server archives them. If the real user turns up later with
their recovery code, they restore the old `MK` from the archive. The reset
notifies every signed-in session and every `cairn` device. The share dialog
shows "reset without recovery code" with its date next to that user's
fingerprint.

While signed in, a user can generate a new recovery code, which replaces the
recovery-wrapped `MK`. A user changes their own email by following a link sent
to the new address.

An administrator can still deactivate and delete accounts and artifacts. The
administrator can deny service, but cannot read.

A passkey that supports the WebAuthn PRF extension can later wrap `MK` too, so
a forgotten password usually costs nothing. That is a later milestone.

### Rotating your keys

**Rotate keys** replaces `MK`, both key pairs, and `EK`. The client unwraps
every `AK` the user holds and wraps it to the new public key. It also
invalidates every API key, the recovery code, and the successor's copy, and
then shows a new recovery code.

The old signing key signs a statement naming the new public keys. Other
members' clients check it and show "keys rotated" without a warning, because
only the real user could have signed it. Use it after a leaked API key, a lost
device, a leaked recovery code, or a successor release.

Rotation also moves every artifact you own to a new epoch, unless you opt out,
because whoever held your old keys could read the old epoch's `AK`. Owners of
artifacts shared with you are asked whether to start a new epoch too.
Rotation closes any ownership offer made by or to you. The client shows the
new link of each public artifact it moved, and lists the artifacts
transferred to or from you in the last 30 days, for you to check.

## Ownership, sharing, and epochs

New metadata:

- `artifacts.owner_id`
- `artifact_members(artifact_id, user_id, role)`, where the role is `viewer`
  or `editor`
- `artifact_keys(artifact_id, epoch, user_id, wrapped_ak)`
- `artifact_estate_keys(artifact_id, epoch, wrapped_ak)`, the owner's copy
  under `EK`
- `artifacts.public_token_hash` and `artifacts.public_epoch`, set only while
  public

Every artifact has three levels of access:

| Level | Who can open it | Signed in? | Can an administrator read it? |
| --- | --- | --- | --- |
| Private | The owner, and the successor after the waiting period | Yes | No |
| Shared | Named users as `viewer` or `editor`, or the whole team | Yes | Only if it was shared with them, including as a team member |
| Public | Anyone holding the public link | No | Only if they are given the link |

- **Private** is the default.
- **Shared with named users** wraps `AK` to each user's public key.
- **Shared with the whole team** wraps `AK` to every member's public key. When
  someone joins the team later, the next owner or editor to open the artifact
  is asked to approve them, by name and fingerprint, before their client wraps
  `AK` for them. A viewer's client never wraps keys for anyone. A member whose
  key changed is never treated as a new member.
- **Public** gives the artifact a public link, `/shared/<id>#<AK>`. Browsers
  never send the part after the `#`, so the server never sees the key. The
  link also carries the first owner's fingerprint, so a visitor's client
  checks the owner's signatures against it, not against keys the server
  serves. The
  client also sends the server a hash of `linkToken`. A visitor presents
  `linkToken`, derived from the key in the link, and the server serves
  ciphertext only when it matches. Making the artifact private deletes the
  hash, so the link stops working on the server as well as in the browser.

Rules for public links:

- The shell removes the key from the address bar with `history.replaceState`
  as soon as it has read it.
- `linkToken` travels only in a request header, never in a URL, so load
  balancer logs never record it.
- A key in a link is ignored when the visitor's own keyring already holds that
  artifact's key, so a crafted link cannot substitute a key.
- A token obtained through a public link has public scope: it can read, and
  it can write only if the visitor is signed in and public writes are on.

Every artifact also has a plain link, `/shared/<id>`, and the plain link opens
for anyone with access, because their own keyring holds `AK`. The owner can
send it to a member they shared with, and it opens for them. Sent to anyone
else, it shows a sign-in page or a no-access page. Only the public link
carries the key, so the share dialog labels it clearly and copies it only
while the artifact is public.

Permissions, enforced by the server on every endpoint:

| Action | Owner | Editor | Viewer | Public link holder |
| --- | --- | --- | --- | --- |
| Read content, database, and files | Yes | Yes | Yes | Yes |
| Write database and files | Yes | Yes | No | If signed in and public writes are on |
| Push a version | Yes | Yes | No | No |
| Share, unshare, make public, delete | Yes | No | No | No |

Share, unshare, make public, delete, and push work only with the app-origin
session or an API key. The token handed to an artifact's content origin can
read, and can write the database and files if the role allows it, and nothing
more. Code in an artifact therefore cannot share or publish it, even when its
owner is the one viewing it.

Public writes are a per-artifact switch, off by default, for guestbook-style
apps. The server allows a write only with a matching `linkToken` and a signed-in
session, so the public link alone lets nobody write.

### Signed versions and membership

Encryption alone proves only that the writer held `AK`, which every viewer and
public-link holder does. Signatures prove who wrote it:

- The owner signs each membership record: the epoch, a commitment to the
  epoch's `AK`, the members with their roles and fingerprints, and the public
  and public-writes settings. A client refuses an `AK` that does not match
  the commitment, so the server cannot plant a key it chose.
- Whoever pushes a version signs its manifest. Whoever writes the database
  signs the new revision. Whoever writes a stored file or a metadata record
  signs that too.
- An owner or editor who approves a team member signs the approval. The
  owner's client lists that member only when the signature checks out.
- Before rendering or writing, a client checks that each signer is the owner,
  or an editor under the current signed membership record. While public
  writes are on, any signed-in link holder may write the database and
  records, so that data proves nothing about who wrote it.
- A client remembers the highest epoch it has seen for each artifact, and
  never encrypts under an older one. The server cannot trick editors into
  writing under a key a removed member still holds.

### Epochs and revocation

The owner's client creates a new `AK` epoch and wraps it to the remaining
members whenever someone who held the old `AK` should lose it:

- The owner removes a member, or demotes an editor to viewer.
- The owner makes a public artifact private.
- The owner stops a team share while a team member holds a wrap.
- The owner rotates their keys, unless they opt out.

A new epoch works like this:

1. The owner's client re-encrypts the latest version, its database, and its
   files under the new epoch. Earlier versions stay under their old keys,
   since the removed party could already read them.
2. Removing an editor lists the versions that editor pushed. The owner signs
   each one to vouch for it, or deletes it. Until the owner vouches for one,
   clients refuse to run it, so a removed editor's code cannot keep running
   for everyone else.

The server keeps the last 10 encrypted database revisions, so the owner can
restore one after an editor or public writer wipes the database.

### Key-change warnings

To share, the owner's client fetches the recipient's public keys, shows the
fingerprint, and pins it in the owner's own encrypted keyring:

- **Unverified.** A pin starts unverified, because the first fingerprint
  comes from the server.
- **Verified.** The owner compares the fingerprint with the recipient in
  person or on a call, as Signal does with safety numbers, then marks it
  verified.
- **Changed.** When a pinned key changes, the client warns before sharing
  again. A reset without the recovery code shows as a warning with its date.
- **Rotated.** A rotation that the old key signed shows as **keys rotated**,
  without a warning. It still drops a verified pin to unverified, shown as
  **rotated, not re-verified**, because a stolen old key could have signed
  it. Compare the new fingerprint again to restore the verified state.
- **Forked.** The client remembers the last rotation it accepted for each
  pin. Two different rotations with the same sequence number raise a hard
  warning, because they mean someone other than the user signed with the old
  key.

This is what protects shares if an operator edits the database to take over
an account. Recovery with the recovery code keeps the original key pairs, so
a warning always means something changed that the owner should check.

## When someone leaves

The company controls a leaver's mailbox. Resetting their password through it
gets into the account, but not the data, exactly as for any other reset
without the recovery code.

- **Shared work survives.** Everyone an artifact was shared with already holds
  its key, and a departure takes nothing from them.
- **Ownership transfer.** While the owner is active, the owner must agree,
  by signing an offer that names the editor and the latest membership
  record. Withdrawing the offer writes a new record, so the old offer can
  never be accepted. The editor already holds `AK`, so a transfer changes a
  record without granting new access.
- **Handover by an administrator.** An administrator can make an existing
  editor the owner once the owner's account is deactivated. The handover is
  silent only when the editor is the successor the owner nominated in a
  record they signed. Otherwise every member's client shows a notice that an
  administrator handed the artifact over. It shows on every device, every
  time the artifact opens.
  Acknowledging it lets a member write again, but the notice stays. There is
  no waiting period, because a deactivated owner cannot sign in to refuse.
- **Private work needs a successor.** Without one, it is unrecoverable, and
  the administrator can delete it.

### Successor

A user can nominate one other user as their successor, or nobody. This is the
only route to someone else's private work, and only the owner can open it.
The successor receives `EK`, which opens the artifacts the user owns. It does
not open `MK`, so the successor never reads what others shared with the user,
or anything the user creates after rotating their keys.

1. The user picks a successor. The successor's own device shows a short code,
   and the user enters it, so the nomination cannot complete with a
   substituted key. The user's client then wraps `EK` to the successor's
   public key and uploads it. The server stores it but does not release it.
2. The successor asks for access. The server records the time and notifies
   the user by email, by a banner in the app, and by a warning in the `cairn`
   tool. A user can add a personal email address for these notices.
3. For 14 days, the user can refuse, which cancels the request. Refusal works
   from any signed-in session. It also works on a deactivated account, on a
   dedicated page that checks `authKey` or the recovery code, so an
   administrator cannot block a refusal by deactivating the user. Deactivation
   during a pending request is recorded and shown to the user on that page.
4. After 14 days without a refusal, the server releases the wrapped `EK` to
   the successor, whose client unwraps it and can read every artifact the user
   owns. An administrator can then transfer ownership to the successor,
   even when the successor is not a member of the artifact. If the
   user signs in again, the client makes them rotate their keys.

The user can change or remove their successor at any time; removal deletes the
wrapped copy. Removing it needs a request signed with the user's current
signing key, so after a reset without the recovery code, the old successor
copy stays archived. Each new successor nomination repeats the code check.

Two points sit outside the code:

- Share team work with the team as a norm, so most of what matters survives a
  departure without a successor.
- Check the company's retention policy. Private work here is unrecoverable by
  design, apart from the successor.

## Artifact isolation

This is the part that makes sharing safe. An artifact is arbitrary HTML and
JavaScript. If it ran on the app origin, a shared artifact from another user
could use your stored private key to unwrap every artifact key you hold.

So each artifact is served from its own origin, on a separately registered
domain, and the app origin never runs artifact code:

| Origin | Example | Serves |
| --- | --- | --- |
| App | `https://cairn.example.com` | Sign-in, your artifact list, the shell, the administration UI |
| Content | `https://<artifactID>.example-usercontent.com` | One artifact's pages, plus the service worker |

- **A separate site.** The content domain must not share a registrable domain
  with the app. Under one domain, an artifact would count as the same site as
  the app: it could send requests carrying the session cookie, plant cookies
  for the app, and read cookies the company scopes to that domain. Listing the
  content domain in the private section of the Public Suffix List also makes
  artifacts cross-site to each other.
- Session cookies are host-only on the app origin, so content origins never
  receive them.
- Content origins allow framing only by the app origin, through
  `frame-ancestors`.
- **The frame is sandboxed**: `sandbox="allow-scripts allow-same-origin
  allow-forms allow-popups allow-popups-to-escape-sandbox allow-downloads"`,
  with no `allow-top-navigation`. An artifact cannot send the whole page to a
  fake sign-in screen. `allow-same-origin` must stay, because without it the
  frame has no origin of its own and cannot run a service worker. It is safe
  here, because the frame's origin is a different site.
- **Service workers in a cross-site frame.** Chrome 115 and later, Safari, and
  Firefox all allow them, and keep their storage separate for each top-level
  site. A content origin is only ever framed by the app, so it always lands in
  the same partition. Safari also clears that storage when the session ends,
  which suits a design that stores no keys there.
- For local use, `http://<artifactID>.localhost:8787` works without TLS or DNS,
  because browsers treat `localhost` subdomains as secure contexts. Check this
  on Safari during milestone 4.

## Serving a private artifact

1. The shell on the app origin unwraps `AK`, and requests a short-lived access
   token scoped to one artifact. The token can read, and write the database
   and files if the role allows it, and nothing more.
2. The shell frames `https://<id>.example-usercontent.com/_cairn/boot`. The boot
   page registers the service worker and posts "ready" to the shell. Only in
   reply does the shell send `AK` and the token, with the exact content origin
   as the target. The boot page checks the sender is the app origin, then
   loads the version.
3. The service worker holds `AK` and the token in memory only. If the browser
   stops it, it asks the shell again through the same handshake. It never
   writes a key or a decrypted response to storage, including Cache Storage.
   The worker script is served with `Cache-Control: no-cache` and registered
   with `updateViaCache: 'none'`, so a bad worker cannot outlive a fixed
   deploy.
4. The service worker checks the version's signature and its signer, then
   intercepts each request, fetches the ciphertext blob, decrypts it, and
   returns the plaintext with a media type taken from the file extension. It
   also applies the SPA fallback that the server applies today.
5. The service worker injects `/_cairn/frame.js` into HTML responses.
   `frame.js` takes over what `shell.js` does today: external links open in a
   new tab, links to other Cairn pages ask the shell by `postMessage` to
   replace the whole page, and documents with diagrams get Mermaid. These move
   because the shell can no longer reach into a cross-origin frame.

The shell acts on a navigation request only when all of these hold:

- The message comes from the artifact frame's window, and from its content
  origin.
- The target is on the app origin, and its path is `/shared/<uuid>` or
  `/shared/<uuid>/<uuid>`.

The shell drops the target's query and fragment before navigating.

Full-screen view becomes an app-origin page with the shell chrome hidden, so
the same key handover works, and so do links and Mermaid. Today, full screen
opens the artifact directly and draws no diagrams unless the artifact loads
Mermaid itself.

A public link works the same way for anonymous visitors: the shell reads `AK`
from the `#`, derives `linkToken`, and hands both over. The server never
decrypts anything, whatever the access level.

## Shared database

The server-side SQL proxy cannot survive, because the server cannot read the
database. It moves into the client:

- Each version's database is one encrypted blob with a revision number.
- `cairn.db.query` runs in the browser on sql.js, which is bundled into the
  binary. Before each query, the client revalidates its copy with a
  conditional request.
- `cairn.db.batch` loads the latest copy, runs the statements in one
  transaction, encrypts and signs the result, and uploads it with `If-Match`.
  When another writer got there first, the server returns `412`, and the
  client reloads the database and re-runs the batch, up to a retry limit.
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

- Each file is a blob addressed by `HMAC(fileKey, path)`, where `fileKey`
  comes from the epoch's `AK`. Its real name and size travel in an encrypted
  metadata record, so file names are hidden. Re-encrypting under a new epoch
  gives the files new addresses.
- `cairn push` no longer uploads a zip. The `cairn` tool checks the tree,
  which must have `index.html` at the root and no symlinks, then encrypts each
  file and uploads a signed manifest plus blobs in one request. The server can
  no longer check the tree, since it cannot read it.
- Artifact and version names, descriptions, changelogs, and resource values are
  encrypted with `AK`. A resource lookup, such as `cairn open <session-id>`,
  uses a blind index, `HMAC(indexKey, type‖value)`, so it resolves only among
  your own artifacts.

## Deploying behind a TLS proxy

New `serve` flags:

- `--public-url https://cairn.example.com` sets the app origin, and turns on
  `Secure` and `__Host-` cookies when the scheme is `https`. Every emailed
  link is built from it.
- `--content-domain example-usercontent.com` sets the parent domain for
  per-artifact origins. The server routes requests by `Host`, and refuses to
  start if the content domain shares a registrable domain with the public
  URL.
- `--signup-domain example.com` turns on self-signup for that domain, and may
  be repeated.
- `--smtp-url smtp://user:pass@host:587` sets the mail server for
  verification and reset links. Self-signup requires it.

Cairn reads no forwarded headers. The GCP load balancer passes the original
`Host` header to the backend, and the scheme and app address come from
`--public-url`, so nothing a client sends can change either.

Per-artifact origins need a wildcard DNS record and a wildcard certificate.

- **GCP, the target deployment.** Cloud DNS holds the wildcard record, and
  Certificate Manager issues the wildcard certificate with DNS authorization
  for an external HTTPS load balancer. Cairn keeps its data in SQLite and a
  local directory, so it runs on a Compute Engine VM with a persistent disk,
  not on Cloud Run. Mail goes through the Google Workspace SMTP relay or a
  provider such as SendGrid.
- **Self-hosting.** The repository gains an example Caddy configuration and a
  Compose service. A wildcard certificate there means an ACME DNS challenge.
  Document that trade-off plainly.

## Deploy integrity

An administrator who can deploy modified code can capture keys, and no web app
design prevents that. Nor can it stop an operator who edits the live database
from swapping a key nobody has verified. These measures make both leave a
trace:

- **Only CI builds release images.** It builds them from a protected branch
  that accepts only reviewed, signed commits, and signs each image. The VM
  runs only an image whose signature it checks at deploy.
- **Audit logs out of the deployer's reach.** GCP audit logs go to a log sink
  in a project the deployer cannot change. Alerts fire on deploys, on changes
  to DNS, the load balancer, certificates, and IAM, and on SSH to the VM or
  attaching its disk.
- **The Cairn administrator role and GCP deploy rights are held by different
  people**, or deploys need a second approver.
- **`cairn verify`** compares the web assets the server delivers with the
  signed release manifest. It runs on the user's own machine, where the server
  cannot tamper with it. A server could serve genuine files to the checker and
  altered ones to its target, so treat it as a spot check, not the control.

With these in place, the promise to users is: an administrator cannot read
your work without leaving a trace in GCP audit logs that the administrator
cannot change.

GCP Binary Authorization enforces signed images, but it runs on GKE and Cloud
Run, not on a plain Compute Engine VM. Move to a single-replica GKE workload
with Binary Authorization when someone other than the Cairn administrator
holds the GCP deploy rights. Until then, the administrator could switch the
policy off, which the audit log would record anyway.

## Importing from an existing server

The new server starts empty, and nothing upgrades in place, so it never holds
plaintext, legacy records, or a password. Your own artifacts from an existing
Cairn server move across by import:

1. Take a snapshot of the old server with `cairn backup`, which copies its
   databases consistently even while it runs.
2. Sign up on the new server, and sign in with `cairn login`.
3. Run `cairn import <backup-dir>`. For every artifact, the tool reads each
   version's content, database, and files from the snapshot, encrypts them
   locally, and pushes them to the new server. Version names, changelogs, and
   resources come across, and resources get blind-index entries.
4. Imported artifacts arrive private and owned by you. The tool lists the ones
   that were public on the old server, so you can decide which to make public
   again.

The import reads the snapshot directly, so the old server needs no new
endpoint, and it keeps running until you retire it. The tool keeps temporary
files in a private directory that it deletes on exit, including on an
interrupt. When the import is done, delete the backup, keep it out of any
synced folder until then, and wipe the old server.

## What breaks

- The HTTP API changes: the database endpoints, zip upload, and API keys an
  administrator creates all go. Only the `cairn.js` API and the `cairn`
  commands keep their shape.
- Administrators lose password reset, account creation, and
  `--admin-password`. First-login-sets-password becomes self-signup, so the
  `CLAUDE.md` invariant that describes it changes.
- Self-signup and password reset need a mail server, which Cairn has never
  needed before.
- Artifacts need a second registered domain.
- An existing server cannot upgrade in place. Its artifacts move to a fresh
  server by import.
- "Public" no longer means readable by anyone who knows the artifact ID. It
  means readable by anyone who holds the public link, which carries the key.
- `shell.html` and the administration artifact list are rendered on the
  client, because the server cannot read names.
- The session cookie is renamed and becomes strict, so app pages check
  sign-in through API calls, not when the page first loads.
- The fork diverges sharply from upstream `aloisdeniel/cairn`, so merging
  later upstream changes becomes manual work.

## Milestones

Each milestone ships with its tests and leaves the server working. The
[execution and test plan](e2e-execution-plan.md) breaks each one into steps
and lists its tests.

| # | Milestone | Proof it works |
| --- | --- | --- |
| 1 | Crypto core — the Go package `internal/e2e`, a JavaScript module, and vendored Argon2id: labels, STREAM, ECIES with context, Ed25519, fingerprints, the Argon2id floor | Go and Node check the same test vectors in both directions; tampered, truncated, reordered, and moved ciphertext all fail |
| 2 | Accounts and sessions: self-signup, mail, verification and reset links, prelogin, `authKey`, key bundles, recovery code, split API keys, device keys, archived wraps, cookie and request protection, app CSP, rate limits | Integration test: sign up, verify, sign in, `cairn login`; a reset with the code keeps the key pairs, one without it gets new ones and archives the old; a forged cross-site request fails; no administrator endpoint can set a password |
| 3 | Ownership and sharing: owner, members, roles, team shares with approval, public links with `linkToken`, signed membership, epochs, key verification states, key rotation, ownership transfer, private by default | Integration test: user B cannot list or read A's artifact until A shares it; a changed key blocks a silent re-share; a public link stops working once the artifact is private; a rotation signed by the old key raises no warning |
| 4 | Encrypted content, content origins, sandboxed frame, handshake, service worker, signed versions, `frame.js`, the new serve flags | Browser tests on Chromium, Firefox, and WebKit: a private artifact renders, the files on disk are ciphertext, and a hostile artifact cannot navigate the page, share itself, or reach the app's cookie |
| 5 | Client-side database and files, bundled sql.js, signed revisions, retained revisions, `cairn db` commands | Every example works; two concurrent writers both land; a removed editor's write is refused |
| 6 | App UI: your artifacts, artifacts shared with you, share dialog, API keys, recovery code, successor settings | Browser walkthrough of the share flow; hostile names render as text in every list |
| 7 | Successor: estate key, verified nomination, request, 14-day wait, refusal including from a deactivated account, release, rotation afterward | Integration test with a fake clock: a refusal on day 13 blocks access, including after deactivation; silence until day 14 releases it, and the successor reads the user's own artifacts but not one shared with the user |
| 8 | Deploy integrity on a GCP VM: signed CI images, signature check at deploy, audit log sink and alerts, `cairn verify`, deployment guide | `cairn verify` passes against a release and fails when one served file changes; an unsigned image is refused |
| 9 | Import and docs: `cairn import`, README, skill, `CLAUDE.md` invariants | Import a backup of your real server into a fresh one, then compare every artifact |

Passkey unlock through the WebAuthn PRF extension, a tamper-evident log of
public keys, and per-artifact CI keys follow as later milestones.

## Decisions

1. **One origin per artifact, on a separately registered domain.** Team
   members publish, and an artifact shared with you must not be able to read
   your other work or act as you in the app. Only separate sites guarantee
   that.
2. **Client-side database with whole-database writes.** This fits artifact
   databases up to tens of megabytes, and gets slow beyond that. Team
   artifacts are small.
3. **Argon2id rather than PBKDF2**, for its resistance to offline guessing
   from snapshots, at the cost of a vendored WebAssembly module. Clients
   enforce a minimum, so the server cannot weaken it.
4. **Three access levels: private, shared, and public.** Shared means named
   users as `viewer` or `editor`, or the whole team. Public means anyone with
   the public link, which carries the key, so the server cannot read a public
   artifact either. A server-readable public mode was considered and dropped:
   it was the only way an administrator could read an artifact, and it offered
   little beyond link previews in chat apps. Public writes are off by default.
5. **Encrypted metadata.** Names, descriptions, changelogs, resource values,
   and file names are all encrypted. Titles alone would tell a manager a great
   deal.
6. **Hard divergence from upstream.** Nothing from this fork is offered back
   to `aloisdeniel/cairn`.
7. **Self-signup** restricted by domain, with email verification.
8. **No administrator recovery.** Passwords are reset only by an emailed link,
   and data returns only with the recovery code. Two-administrator recovery
   was considered and dropped: two administrators acting together could read
   anyone's work, and making that detectable needed a key holder outside the
   administrator group.
9. **An opt-in successor with a 14-day waiting period**, holding an estate key
   that opens only the user's own artifacts, plus ownership transfer to
   existing editors, for colleagues who leave.
10. **Deploy integrity on a VM first**, through signed CI images, audit logs
    out of the deployer's reach, separated roles, and `cairn verify`. Binary
    Authorization on GKE follows once the deploy rights sit with someone other
    than the administrator.
11. **A fresh server.** Nothing upgrades in place; existing artifacts arrive
    by `cairn import` from a backup.
12. **Signed versions and membership.** Every user has a signing key, and
    clients run only content signed by a current owner or editor.
