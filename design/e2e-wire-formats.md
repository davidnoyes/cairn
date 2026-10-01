# End-to-end encryption — wire formats

Status: **reference for implementation**. This document fixes the exact bytes
that the [trust model](e2e-trust-model.md) leaves open, so the Go package
`internal/e2e` and the browser module `internal/server/web/e2e.mjs` agree
byte for byte. The cross-language test vectors in
`internal/e2e/testdata/vectors.json` enforce every rule here.

## Conventions

- **Bytes in JSON** are base64url without padding, shown here as `b64(x)`.
- **IDs** are the server's UUID strings: user, artifact, and version IDs.
- **Integers inside derived inputs**, such as an epoch or a revision, are
  decimal ASCII with no leading zeros: epoch 3 is the string `3`.
- **Strings** are their UTF-8 bytes, without normalization.
- **`enc(f1, f2, …)`** is the canonical encoding of a list of byte strings:
  each field as a 4-byte big-endian length followed by its bytes. It is used
  for every HKDF `info`, every associated-data value, and every signed or
  hashed input, so no two lists of fields can encode to the same bytes.
- **`derive(ikm, salt, label, f…)`** is HKDF-SHA256 with input key material
  `ikm`, the given salt (empty when none is named), and
  `info = enc(label, f…)`, producing 32 bytes.
- **`hex(x)`** is lowercase hexadecimal.

## Labels

Every derivation and every domain-separated input starts with one of these
labels. No two are equal, and a test enforces it.

| Label | Used for |
| --- | --- |
| `cairn/v1/auth` | `authKey`, from the stretched password |
| `cairn/v1/kek` | `kek`, from the stretched password |
| `cairn/v1/recovery` | `recoveryKek`, from the recovery code |
| `cairn/v1/api-key` | The key that unwraps an API key's copy of `MK` |
| `cairn/v1/mk-seal` | `mkSealKey`, from `MK` |
| `cairn/v1/index` | `indexKey`, from `MK` |
| `cairn/v1/ek-seal` | `ekSealKey`, from `EK` |
| `cairn/v1/link-token` | `linkToken`, from `AK` |
| `cairn/v1/file-key` | `fileKey`, from `AK` |
| `cairn/v1/blob` | A blob key, from `AK` |
| `cairn/v1/wrap` | An ECIES wrap key |
| `cairn/v1/seal` | Associated data for a sealed value |
| `cairn/v1/sig` | The message prefix for a signature |
| `cairn/v1/fingerprint` | The fingerprint hash input |
| `cairn/v1/blind` | The blind-index input |
| `cairn/v1/prelogin` | The fake salt for an unknown account |

Raw keys are never used for two purposes. `MK` and `EK` are only ever HKDF
input; everything they protect goes through a key derived from them.

## Password stretching

The server stores Argon2id parameters per user and returns them from
prelogin:

```json
{"alg": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": "b64(16 bytes)"}
```

- `m` is memory in KiB, `t` is passes, and `p` is lanes.
- **Floor.** Clients refuse `alg` other than `argon2id`, `m` below 65536,
  `t` below 3, `p` outside 1 to 4, or a salt shorter than 16 bytes or longer
  than 64. The server can raise the parameters, never lower them.
- `stretched = Argon2id(password, salt, t, m, p)`, 32 bytes.
- `authKey = derive(stretched, "", "cairn/v1/auth")`.
- `kek = derive(stretched, "", "cairn/v1/kek")`.

The client sends `b64(authKey)` to the server, which stores its bcrypt hash.

## Recovery code

- 16 random bytes, encoded as RFC 4648 base32 in uppercase without padding,
  then split into groups of four with hyphens: 26 characters as six groups of
  four and one of two, in the shape `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX`.
- Parsing ignores case, spaces, and hyphens, and fails on anything else.
- `recoveryKek = derive(code, "", "cairn/v1/recovery")`, over the 16 bytes.

## API keys

```text
cairn_<keyid>_<authSecret>_<keySecret>
```

- `keyid` is 8 random bytes, `authSecret` 16, and `keySecret` 32, each in
  `hex`, so the underscore separator never appears inside a part.
- The bearer sent to the server is `cairn_<keyid>_<authSecret>`. The server
  stores `hex(SHA-256(authSecret))`, where `authSecret` is the hex string.
- `apiKeyKek = derive(keySecret, "", "cairn/v1/api-key", keyid)`, over the 32
  raw bytes of `keySecret`. It seals the key's copy of `MK`.

## Keys derived from the master, estate, and artifact keys

| Key | Derivation |
| --- | --- |
| `mkSealKey` | `derive(MK, "", "cairn/v1/mk-seal")` |
| `indexKey` | `derive(MK, "", "cairn/v1/index")` |
| `ekSealKey` | `derive(EK, "", "cairn/v1/ek-seal")` |
| `linkToken` | `derive(AK, "", "cairn/v1/link-token", artifact, epoch)` |
| `fileKey` | `derive(AK, "", "cairn/v1/file-key", artifact, epoch)` |

## Sealed values

A sealed value is a small secret encrypted under a symmetric key with
AES-256-GCM:

```text
seal(key, fields, plaintext) = 0x01 ‖ nonce(12) ‖ AES-GCM(key, nonce, plaintext, ad)
ad = enc("cairn/v1/seal", fields…)
```

The nonce is random. Opening checks the version byte and fails on any
authentication error. Every sealed value in the system:

| Value | Key | Fields |
| --- | --- | --- |
| `MK` under the password | `kek` | `mk` |
| `MK` under the recovery code | `recoveryKek` | `mk` |
| `MK` under an API key | `apiKeyKek` | `mk`, `keyid` |
| X25519 private key, 32 bytes | `mkSealKey` | `x25519` |
| Ed25519 private key seed, 32 bytes | `mkSealKey` | `ed25519` |
| `EK` | `mkSealKey` | `ek` |
| The user's keyring, JSON | `mkSealKey` | `keyring` |
| An artifact's `AK`, the owner's estate copy | `ekSealKey` | `estate`, artifact, epoch |

## Blobs

Every piece of artifact content is a blob: a version's files and manifest,
each database revision, each stored file, and each encrypted metadata
record. A blob is a header followed by STREAM chunks.

```text
header = "CRNB" ‖ 0x01 ‖ salt(32)                       37 bytes
key    = derive(AK, salt, "cairn/v1/blob", artifact, version, kind, name)
chunk  = AES-GCM(key, nonce_i, plaintext_i, ad = header)
nonce_i = i as 11 bytes big-endian ‖ last-chunk flag (0x01 last, 0x00 not)
blob   = header ‖ chunk_0 ‖ … ‖ chunk_(n-1)
```

- The salt is 32 random bytes chosen for every write, so rewriting the same
  path or database never reuses a key and nonce.
- Plaintext splits into 65,536-byte chunks. The last chunk holds the
  remainder, and an empty plaintext is a single empty chunk, so every blob
  has at least one chunk. A plaintext that fills its last chunk exactly has
  no extra empty chunk after it.
- Each encrypted chunk is its plaintext plus a 16-byte tag, so every chunk
  but the last is 65,552 bytes.
- **Decryption** reads the header, then takes 65,552-byte chunks with flag
  `0x00` while more than 65,552 bytes remain, and treats the rest as the last
  chunk, with flag `0x01`. Truncation at a chunk boundary therefore fails,
  because the new final chunk was sealed as not last. So do a dropped or
  reordered chunk, a changed header, and a blob moved to another context.

Blob contexts:

| Kind | `version` | `name` | Holds |
| --- | --- | --- | --- |
| `content` | Version ID | Path in the version | One file of a pushed version |
| `manifest` | Version ID | Empty | The version's signed manifest |
| `database` | Version ID | Revision number | One database revision |
| `file` | Version ID | Path | One stored file |
| `file-meta` | Version ID | Path | A stored file's metadata record |
| `meta` | Version ID, or empty for the artifact | Field name | One metadata record |

## Key wrapping

An `AK`, or a user's `EK` for their successor, is wrapped to a user's X25519
public key with ephemeral-static ECIES:

```text
eph       = fresh X25519 key pair
shared    = X25519(eph.private, recipientPub)          refuse all zeros
wrapKey   = derive(shared, "", "cairn/v1/wrap",
                   purpose, artifact, epoch, recipientID, recipientPub, eph.public)
wrapped   = 0x01 ‖ eph.public(32) ‖ AES-GCM(wrapKey, nonce = 12 zero bytes, key, ad = "")
```

The wrap key is used once, because the ephemeral key is fresh, so the zero
nonce is safe. A wrapped 32-byte key is 81 bytes.

| Purpose | `artifact` | `epoch` |
| --- | --- | --- |
| `ak` | Artifact ID | The epoch |
| `ek` | The owner's user ID | `0` |

## Signatures

```text
sig = Ed25519(signingKey, enc("cairn/v1/sig", purpose, body))
```

A signed record travels as an envelope, and verification runs over the exact
body bytes, so no JSON canonicalization is needed:

```json
{"body": "b64(JSON bytes)", "sig": "b64(64 bytes)", "signer": "user ID"}
```

A verifier checks the signature first, then parses the body, then checks that
every field in the body matches the context it expected, such as the artifact
ID and the epoch. It refuses a body with `v` other than 1.

| Purpose | Signed by | Body |
| --- | --- | --- |
| `membership` | The owner | `{"v":1,"artifact","epoch","owner","members":[{"user","role","fp"}],"team","public","publicWrites","prev"}` |
| `manifest` | Whoever pushed | `{"v":1,"artifact","version","epoch","files":[{"path","blob","size","sha256"}]}` |
| `revision` | Whoever wrote the database | `{"v":1,"artifact","version","revision","epoch","sha256"}` |
| `vouch` | The owner | `{"v":1,"artifact","version","manifest"}` |
| `rotation` | The old signing key | `{"v":1,"user","old":{"x25519","ed25519"},"new":{"x25519","ed25519"}}` |
| `successor` | The user | `{"v":1,"user","successor","action"}` |
| `reset` | The user, with their existing key | `{"v":1,"user","token"}` |

- In a membership record, `role` is `viewer` or `editor`, `team` is `none`,
  `viewer`, or `editor`, and `prev` is `hex(SHA-256)` of the previous
  record's body, or empty for the first. Members are sorted by user ID.
- In a manifest, `blob` is the blob ID the server stores the file under,
  `size` is the plaintext size, and `sha256` is `hex(SHA-256)` of the
  encrypted blob, so a viewer, who holds `AK`, cannot swap a file.
- In a revision, `sha256` is `hex(SHA-256)` of the encrypted database blob.
- A vouch's `manifest` is `hex(SHA-256)` of the manifest envelope's body.
- A reset's `token` is `hex(SHA-256)` of the reset token from the emailed
  link, so the proof cannot be replayed with another link.
- Public keys inside bodies are `b64`; fingerprints are `hex`.

## Fingerprints

```text
fingerprint = SHA-256(enc("cairn/v1/fingerprint", x25519Public, ed25519Public))
```

Shown to people as the first 20 bytes in `hex`, in ten groups of four
characters separated by spaces.

## Public links, file addresses, and blind indexes

- **Public link.** `/shared/<artifact>#k=<b64(AK)>&e=<epoch>`.
- **Link token.** Sent as the `X-Cairn-Link-Token` header, `b64(linkToken)`.
  The server stores `hex(SHA-256(linkToken))` and compares in constant time.
- **File address.** `hex(HMAC-SHA256(fileKey, path))`.
- **Blind index.** `hex(HMAC-SHA256(indexKey, enc("cairn/v1/blind", type,
  value)))`.

## Test vectors

`internal/e2e/testdata/vectors.json` is generated by Go from a seeded random
source, and checked by a Go test and a Node test. Each entry has its inputs,
its expected output, and negative cases that must fail: a flipped bit, a
truncated or reordered stream, and a blob or wrap moved to another context.
Each side also produces fresh output with real randomness for the other to
read, so agreement is tested in both directions.
