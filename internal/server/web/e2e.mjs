// e2e.mjs — the browser half of Cairn's end-to-end encryption crypto core.
// Built only on WebCrypto (globalThis.crypto.subtle, crypto.getRandomValues),
// so it runs under Node 22 and in every modern browser with no npm
// dependency. Every byte this module produces or accepts is fixed in
// design/e2e-wire-formats.md, so it agrees with the Go package internal/e2e
// byte for byte; see internal/e2e/testdata/vectors.json and e2e_test.mjs.
//
// All parsing and decryption failures throw an Error with a stable `name`
// (DecryptError, FormatError, FloorError) rather than returning garbage.
// verify() is the one exception: it returns a boolean, matching Go's
// Verify.

const subtle = globalThis.crypto.subtle;

export class DecryptError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DecryptError';
  }
}

export class FormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FormatError';
  }
}

export class FloorError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FloorError';
  }
}

const textEncoder = new TextEncoder();

// toBytes accepts a Uint8Array as-is, or UTF-8 encodes a string. Used
// everywhere a field is naturally a string (an artifact ID, a decimal
// epoch) as well as everywhere it is already raw bytes.
function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string') return textEncoder.encode(value);
  throw new TypeError('expected a string or Uint8Array');
}

function concatBytes(arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function toHex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex) {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new FormatError(`bad hex: ${hex}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// b64/unb64: base64url without padding, matching Go's base64.RawURLEncoding.
export function b64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64(str) {
  if (str.length % 4 === 1) throw new FormatError(`bad base64url length: ${str.length}`);
  const standard = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new FormatError(`bad base64url: ${str}`);
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// enc is the canonical encoding of a list of byte strings: each field as a
// 4-byte big-endian length followed by its bytes. Used for every HKDF info,
// every associated-data value, and every signed or hashed input.
export function enc(...fields) {
  const parts = fields.map(toBytes);
  let total = 0;
  for (const f of parts) total += 4 + f.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const f of parts) {
    view.setUint32(offset, f.length, false);
    offset += 4;
    out.set(f, offset);
    offset += f.length;
  }
  return out;
}

// LABELS: every derivation and every domain-separated input starts with one
// of these. No two are equal.
export const LABELS = {
  auth: 'cairn/v1/auth',
  kek: 'cairn/v1/kek',
  recovery: 'cairn/v1/recovery',
  apiKey: 'cairn/v1/api-key',
  mkSeal: 'cairn/v1/mk-seal',
  index: 'cairn/v1/index',
  ekSeal: 'cairn/v1/ek-seal',
  linkToken: 'cairn/v1/link-token',
  fileKey: 'cairn/v1/file-key',
  blob: 'cairn/v1/blob',
  wrap: 'cairn/v1/wrap',
  seal: 'cairn/v1/seal',
  sig: 'cairn/v1/sig',
  fingerprint: 'cairn/v1/fingerprint',
  blind: 'cairn/v1/blind',
  prelogin: 'cairn/v1/prelogin',
  salt: 'cairn/v1/salt',
  akCommit: 'cairn/v1/ak-commit',
};

// KEY_LEN is the length every raw symmetric key (MK, EK, AK, and keys
// derived from them) must be. A wrong length is refused before it reaches a
// cipher, rather than silently accepted or rejected only by a cipher's own
// error.
const KEY_LEN = 32;

function checkKeyLen(key) {
  if (key.length !== KEY_LEN) throw new FormatError(`key length ${key.length}, want ${KEY_LEN}`);
}

const DERIVED_KEY_BITS = 256;

// derive is HKDF-SHA256: ikm is a Uint8Array, or a non-extractable HKDF
// CryptoKey (so a caller can keep a master key non-extractable end to end),
// salt is a Uint8Array or absent, and info = enc(label, fields...).
export async function derive(ikm, salt, label, ...fields) {
  const info = enc(label, ...fields);
  const key =
    ikm instanceof CryptoKey
      ? ikm
      : await subtle.importKey('raw', toBytes(ikm), 'HKDF', false, ['deriveBits']);
  const saltBytes = salt ? toBytes(salt) : new Uint8Array(0);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info },
    key,
    DERIVED_KEY_BITS,
  );
  return new Uint8Array(bits);
}

// Argon2id floor and ceiling. Clients refuse parameters below the floor, so
// the server can raise them later without breaking existing accounts, but
// never lower them. The ceiling catches a server (malicious or broken)
// trying to force a client into a denial-of-service-sized Argon2id run.
const FLOOR_MEMORY = 65536; // KiB
const FLOOR_TIME = 3;
const FLOOR_SALT_MIN = 16;
const FLOOR_SALT_MAX = 64;
const CEILING_MEMORY = 1048576; // KiB
const CEILING_TIME = 10;

// checkFloor refuses alg other than argon2id, m below 65536 or above
// 1048576, t below 3 or above 10, p outside 1 to 4, or a salt shorter than
// 16 bytes or longer than 64. params is {alg, m, t, p, salt}, with salt a
// Uint8Array.
export function checkFloor(params) {
  if (!params || params.alg !== 'argon2id') {
    throw new FloorError(`alg ${params && params.alg}`);
  }
  if (params.m < FLOOR_MEMORY) throw new FloorError(`memory ${params.m} below floor`);
  if (params.m > CEILING_MEMORY) throw new FloorError(`memory ${params.m} above ceiling`);
  if (params.t < FLOOR_TIME) throw new FloorError(`time ${params.t} below floor`);
  if (params.t > CEILING_TIME) throw new FloorError(`time ${params.t} above ceiling`);
  if (params.p < 1 || params.p > 4) throw new FloorError(`threads ${params.p} out of range`);
  const saltLen = params.salt ? params.salt.length : 0;
  if (saltLen < FLOOR_SALT_MIN || saltLen > FLOOR_SALT_MAX) {
    throw new FloorError(`salt length ${saltLen} out of range`);
  }
}

const ASCII_WHITESPACE = ' \t\n\r\f\v';

// normalizeEmail trims ASCII whitespace and lowercases ASCII letters only.
// It deliberately does not use String.toLowerCase: Unicode case mapping can
// map different source characters to the same lowercase form in ways that
// diverge between the browser's JavaScript and Go, which would let two
// different addresses collide on one salt. Only plain ASCII folding is
// guaranteed to agree on both sides.
export function normalizeEmail(s) {
  let start = 0;
  let end = s.length;
  while (start < end && ASCII_WHITESPACE.includes(s[start])) start++;
  while (end > start && ASCII_WHITESPACE.includes(s[end - 1])) end--;
  let out = '';
  for (let i = start; i < end; i++) {
    const code = s.charCodeAt(i);
    out += code >= 65 && code <= 90 ? String.fromCharCode(code + 32) : s[i];
  }
  return out;
}

// argonSalt derives the Argon2id salt actually used to stretch a password,
// binding it to the account's normalized email as well as the
// server-issued serverSalt. This stops a server from handing two different
// users the same salt, which would let it test one user's password against
// another's hash.
export async function argonSalt(email, serverSalt) {
  const digest = await subtle.digest('SHA-256', enc(LABELS.salt, normalizeEmail(email), serverSalt));
  return new Uint8Array(digest);
}

// stretch runs Argon2id over the password, after checking params against the
// floor and ceiling, using the identity-bound salt derived from email and
// params.salt, producing 32 bytes. argon2id is the function loadArgon2
// (argon2.mjs) returns: (password, salt, t, m, p) => Promise<Uint8Array>.
export async function stretch(password, email, params, argon2id) {
  checkFloor(params);
  const salt = await argonSalt(email, params.salt);
  return argon2id(toBytes(password), salt, params.t, params.m, params.p);
}

// passwordKeys derives authKey, sent to the server, and kek, which never
// leaves the client, from the stretched password.
export async function passwordKeys(stretched) {
  const authKey = await derive(stretched, null, LABELS.auth);
  const kek = await derive(stretched, null, LABELS.kek);
  return { authKey, kek };
}

// Recovery codes: 16 random bytes shown as uppercase base32 in groups of
// four, split into groups with hyphens.
const RECOVERY_CODE_BYTES = 16;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return out;
}

function base32Decode(s) {
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new FormatError(`invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

// isRecoveryCodeByte reports whether ch is a character parseRecoveryCode
// accepts: ASCII letters, the digits 2-7, a space, or a hyphen. Checking
// this before any case folding means a non-ASCII letter that some locale's
// uppercasing would otherwise fold onto an allowed letter (the long s "ſ",
// Turkish dotless "ı", German "ß", or the Kelvin sign "K") is rejected
// outright instead of silently accepted.
function isRecoveryCodeByte(ch) {
  return (
    (ch >= 'A' && ch <= 'Z') ||
    (ch >= 'a' && ch <= 'z') ||
    (ch >= '2' && ch <= '7') ||
    ch === '-' ||
    ch === ' '
  );
}

// base32Value returns the 5-bit value of a base32 alphabet character, or
// null if ch isn't one.
function base32Value(ch) {
  if (ch >= 'A' && ch <= 'Z') return ch.charCodeAt(0) - 65;
  if (ch >= '2' && ch <= '7') return ch.charCodeAt(0) - 50 + 26;
  return null;
}

// newRecoveryCode generates a recovery code and its display form.
export function newRecoveryCode() {
  const code = new Uint8Array(RECOVERY_CODE_BYTES);
  crypto.getRandomValues(code);
  return { code, display: formatRecoveryCode(code) };
}

// formatRecoveryCode renders a recovery code as uppercase base32 in groups
// of four separated by hyphens.
export function formatRecoveryCode(code) {
  const encoded = base32Encode(code);
  const groups = [];
  for (let i = 0; i < encoded.length; i += 4) groups.push(encoded.slice(i, i + 4));
  return groups.join('-');
}

// parseRecoveryCode parses a displayed recovery code. It first refuses any
// character outside A-Z, a-z, 2-7, space, and hyphen, then ignores case,
// spaces, and hyphens. It also refuses a final character whose two unused
// low bits are not zero: 16 bytes is 128 bits, which base32 spreads over 26
// characters (130 bits), so the last character's low 2 bits carry no data,
// and a non-zero value there is not a code this module ever produced.
export function parseRecoveryCode(s) {
  for (let i = 0; i < s.length; i++) {
    if (!isRecoveryCodeByte(s[i])) throw new FormatError(`invalid character at ${i}`);
  }
  const cleaned = s.toUpperCase().replace(/[- ]/g, '');
  const wantLen = Math.ceil((RECOVERY_CODE_BYTES * 8) / 5);
  if (cleaned.length !== wantLen) throw new FormatError('wrong length');
  const last = base32Value(cleaned[cleaned.length - 1]);
  if (last === null || (last & 0x03) !== 0) throw new FormatError('non-zero trailing bits');
  const code = base32Decode(cleaned);
  if (code.length !== RECOVERY_CODE_BYTES) throw new FormatError('wrong decoded length');
  return code;
}

// recoveryKek derives the key that seals MK under the recovery code.
export async function recoveryKek(code) {
  return derive(code, null, LABELS.recovery);
}

// API keys: cairn_<keyid>_<authSecret>_<keySecret>, each part in hex, so the
// underscore separator never appears inside a part.
const API_KEY_PREFIX = 'cairn_';
const API_KEY_ID_BYTES = 8;
const API_KEY_AUTH_BYTES = 16;
const API_KEY_SECRET_BYTES = 32;

// newApiKey generates a fresh API key.
export function newApiKey() {
  const idBytes = new Uint8Array(API_KEY_ID_BYTES);
  const authBytes = new Uint8Array(API_KEY_AUTH_BYTES);
  const keyBytes = new Uint8Array(API_KEY_SECRET_BYTES);
  crypto.getRandomValues(idBytes);
  crypto.getRandomValues(authBytes);
  crypto.getRandomValues(keyBytes);
  const keyId = toHex(idBytes);
  const authSecret = toHex(authBytes);
  const keySecretHex = toHex(keyBytes);
  const full = `${API_KEY_PREFIX}${keyId}_${authSecret}_${keySecretHex}`;
  return { full, keyId, authSecret, keySecret: keyBytes };
}

// isLowerHex reports whether s is non-empty and every character is a
// lowercase hex digit. fromHex accepts uppercase too, which would let two
// different-looking strings decode to the same bytes; API keys must have
// one canonical form.
function isLowerHex(s) {
  if (s.length === 0) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

// parseApiKey splits a presented full API key into its parts. Parsing
// refuses uppercase hexadecimal.
export function parseApiKey(full) {
  if (!full.startsWith(API_KEY_PREFIX)) throw new FormatError('missing prefix');
  const parts = full.slice(API_KEY_PREFIX.length).split('_');
  if (parts.length !== 3) throw new FormatError('wrong number of parts');
  const [keyId, authSecret, keySecretHex] = parts;
  if (
    keyId.length !== API_KEY_ID_BYTES * 2 ||
    authSecret.length !== API_KEY_AUTH_BYTES * 2 ||
    keySecretHex.length !== API_KEY_SECRET_BYTES * 2
  ) {
    throw new FormatError('wrong part length');
  }
  if (!isLowerHex(keyId) || !isLowerHex(authSecret) || !isLowerHex(keySecretHex)) {
    throw new FormatError('not lowercase hex');
  }
  const keySecret = fromHex(keySecretHex);
  return { full, keyId, authSecret, keySecret };
}

// apiKeyKek derives the key that seals the API key's copy of MK.
export async function apiKeyKek(keySecret, keyId) {
  return derive(keySecret, null, LABELS.apiKey, keyId);
}

// apiKeyAuthHash is what the server stores for authSecret: the hash of the
// hex string itself, not of the bytes it decodes to, matching the wire
// format.
export async function apiKeyAuthHash(authSecretHex) {
  const digest = await subtle.digest('SHA-256', textEncoder.encode(authSecretHex));
  return toHex(new Uint8Array(digest));
}

// Keys derived from MK, EK, and AK. Each requires a 32-byte input key, the
// length every MK, EK, and AK is fixed at; a wrong length throws rather than
// silently deriving from the wrong material.
export async function mkSealKey(mk) {
  checkKeyLen(mk);
  return derive(mk, null, LABELS.mkSeal);
}
export async function indexKey(mk) {
  checkKeyLen(mk);
  return derive(mk, null, LABELS.index);
}
export async function ekSealKey(ek) {
  checkKeyLen(ek);
  return derive(ek, null, LABELS.ekSeal);
}
export async function linkToken(ak, artifact, epoch) {
  checkKeyLen(ak);
  return derive(ak, null, LABELS.linkToken, artifact, String(epoch));
}
export async function fileKey(ak, artifact, epoch) {
  checkKeyLen(ak);
  return derive(ak, null, LABELS.fileKey, artifact, String(epoch));
}

// akCommit is a public commitment to an artifact's AK at a given epoch, so a
// party without AK can confirm two sources agree on it without learning it.
export async function akCommit(ak, artifact, epoch) {
  checkKeyLen(ak);
  const commit = await derive(ak, null, LABELS.akCommit, artifact, String(epoch));
  return toHex(commit);
}

async function hmacSha256(key, message) {
  const hmacKey = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const mac = await subtle.sign('HMAC', hmacKey, message);
  return new Uint8Array(mac);
}

// linkTokenHash is what the server stores for a public link's token.
export async function linkTokenHash(token) {
  const digest = await subtle.digest('SHA-256', token);
  return toHex(new Uint8Array(digest));
}

// fileAddress addresses a stored file by its path under fileKey.
export async function fileAddress(theFileKey, path) {
  return toHex(await hmacSha256(theFileKey, toBytes(path)));
}

// blindIndex is the lookup hash for a resource value of the given type.
export async function blindIndex(theIndexKey, type, value) {
  return toHex(await hmacSha256(theIndexKey, enc(LABELS.blind, type, value)));
}

// Sealed values: a small secret under AES-256-GCM, bound to its field list.
//
//   seal(key, fields, pt) = 0x01 ‖ nonce(12) ‖ AES-GCM(key, nonce, pt, ad)
//   ad = enc("cairn/v1/seal", fields…)
const SEAL_VERSION = 0x01;
const GCM_NONCE_SIZE = 12;

function sealAD(fields) {
  return enc(LABELS.seal, ...fields);
}

// importAesGcmKey always checks the key is exactly 32 bytes before handing
// it to WebCrypto, which would otherwise happily treat a 16- or 24-byte key
// as AES-128 or AES-192: this module only ever uses AES-256-GCM.
async function importAesGcmKey(key, usage) {
  checkKeyLen(key);
  return subtle.importKey('raw', key, 'AES-GCM', false, [usage]);
}

// seal encrypts pt under key, bound to fields, with a fresh random nonce.
export async function seal(key, fields, pt) {
  const aesKey = await importAesGcmKey(key, 'encrypt');
  const nonce = new Uint8Array(GCM_NONCE_SIZE);
  crypto.getRandomValues(nonce);
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: sealAD(fields) }, aesKey, toBytes(pt)),
  );
  return concatBytes([new Uint8Array([SEAL_VERSION]), nonce, ct]);
}

// open decrypts a value sealed with seal, checking the version byte and
// failing on any authentication error — including a key of the wrong
// length, which must not tell an attacker anything a bad ciphertext wouldn't.
export async function open(key, fields, sealed) {
  if (sealed.length < 1 + GCM_NONCE_SIZE || sealed[0] !== SEAL_VERSION) {
    throw new DecryptError('bad header');
  }
  const nonce = sealed.slice(1, 1 + GCM_NONCE_SIZE);
  const ct = sealed.slice(1 + GCM_NONCE_SIZE);
  try {
    const aesKey = await importAesGcmKey(key, 'decrypt');
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: sealAD(fields) },
      aesKey,
      ct,
    );
    return new Uint8Array(pt);
  } catch {
    throw new DecryptError('authentication failed');
  }
}

// Blobs are a header followed by STREAM chunks:
//
//   header = "CRNB" ‖ 0x01 ‖ salt(32)                       37 bytes
//   key    = derive(AK, salt, "cairn/v1/blob", artifact, version, kind, name)
//   chunk  = AES-GCM(key, nonce_i, plaintext_i, ad = header)
//   nonce_i = i as 11 bytes big-endian ‖ last-chunk flag (0x01 last, 0x00 not)
//   blob   = header ‖ chunk_0 ‖ … ‖ chunk_(n-1)
const BLOB_MAGIC = textEncoder.encode('CRNB');
const BLOB_VERSION = 0x01;
const BLOB_SALT_SIZE = 32;
const BLOB_HEADER_SIZE = BLOB_MAGIC.length + 1 + BLOB_SALT_SIZE; // 37

export const BLOB_CHUNK_SIZE = 65536; // plaintext size of every chunk but the last
const BLOB_TAG_SIZE = 16;
const BLOB_FULL_CHUNK_SIZE = BLOB_CHUNK_SIZE + BLOB_TAG_SIZE;

function blobHeader(salt) {
  const h = new Uint8Array(BLOB_HEADER_SIZE);
  h.set(BLOB_MAGIC, 0);
  h[BLOB_MAGIC.length] = BLOB_VERSION;
  h.set(salt, BLOB_MAGIC.length + 1);
  return h;
}

async function blobKey(ak, salt, ctx) {
  return derive(ak, salt, LABELS.blob, ctx.artifact, ctx.version, ctx.kind, ctx.name);
}

// chunkNonce builds the STREAM nonce: an 11-byte big-endian chunk counter
// followed by a 1-byte last-chunk flag.
function chunkNonce(i, last) {
  const nonce = new Uint8Array(GCM_NONCE_SIZE);
  const view = new DataView(nonce.buffer);
  view.setUint32(3, Math.floor(i / 0x100000000), false);
  view.setUint32(7, i >>> 0, false);
  if (last) nonce[11] = 0x01;
  return nonce;
}

// sealBlob encrypts pt as a fresh blob under ak and ctx ({artifact, version,
// kind, name}), with a random 32-byte salt.
export async function sealBlob(ak, ctx, pt) {
  checkKeyLen(ak);
  const salt = new Uint8Array(BLOB_SALT_SIZE);
  crypto.getRandomValues(salt);
  const header = blobHeader(salt);
  const aesKey = await importAesGcmKey(await blobKey(ak, salt, ctx), 'encrypt');

  const n = pt.length;
  let chunks = Math.floor(n / BLOB_CHUNK_SIZE);
  if (n % BLOB_CHUNK_SIZE !== 0 || n === 0) chunks++;

  const parts = [header];
  for (let i = 0; i < chunks; i++) {
    const start = i * BLOB_CHUNK_SIZE;
    const end = Math.min(start + BLOB_CHUNK_SIZE, n);
    const last = i === chunks - 1;
    const ct = await subtle.encrypt(
      { name: 'AES-GCM', iv: chunkNonce(i, last), additionalData: header },
      aesKey,
      pt.slice(start, end),
    );
    parts.push(new Uint8Array(ct));
  }
  return concatBytes(parts);
}

function hasMagic(blob) {
  for (let i = 0; i < BLOB_MAGIC.length; i++) {
    if (blob[i] !== BLOB_MAGIC[i]) return false;
  }
  return true;
}

// openBlob decrypts a blob sealed with sealBlob, checking the header, the
// context, and every chunk's authentication tag and position. Decryption
// reads 65,552-byte chunks with flag 0x00 while more than 65,552 bytes
// remain, and treats the rest as the last chunk, with flag 0x01 — so a
// dropped or reordered chunk, a changed header, truncation at a chunk
// boundary, and a blob moved to another context all fail.
export async function openBlob(ak, ctx, blob) {
  checkKeyLen(ak);
  if (blob.length < BLOB_HEADER_SIZE || !hasMagic(blob) || blob[BLOB_MAGIC.length] !== BLOB_VERSION) {
    throw new FormatError('bad header');
  }
  const header = blob.slice(0, BLOB_HEADER_SIZE);
  const salt = blob.slice(BLOB_MAGIC.length + 1, BLOB_HEADER_SIZE);
  let rest = blob.slice(BLOB_HEADER_SIZE);
  if (rest.length === 0) {
    // A valid blob always has at least one chunk, even an empty one.
    throw new DecryptError('no chunks');
  }

  const aesKey = await importAesGcmKey(await blobKey(ak, salt, ctx), 'decrypt');

  const parts = [];
  let i = 0;
  while (rest.length > 0) {
    const last = rest.length <= BLOB_FULL_CHUNK_SIZE;
    const chunkCT = last ? rest : rest.slice(0, BLOB_FULL_CHUNK_SIZE);
    rest = last ? new Uint8Array(0) : rest.slice(BLOB_FULL_CHUNK_SIZE);
    try {
      const pt = await subtle.decrypt(
        { name: 'AES-GCM', iv: chunkNonce(i, last), additionalData: header },
        aesKey,
        chunkCT,
      );
      parts.push(new Uint8Array(pt));
    } catch {
      throw new DecryptError('chunk authentication failed');
    }
    i++;
  }
  return concatBytes(parts);
}

// PKCS#8/SPKI DER prefixes for a raw 32-byte X25519 or Ed25519 key, so a
// private scalar/seed or a public key can be imported directly by WebCrypto.
const X25519_PKCS8_PREFIX = fromHex('302e020100300506032b656e04220420');
const X25519_SPKI_PREFIX = fromHex('302a300506032b656e032100');
const ED25519_PKCS8_PREFIX = fromHex('302e020100300506032b657004220420');
const ED25519_SPKI_PREFIX = fromHex('302a300506032b6570032100');

async function importX25519Priv(raw, extractable, usages) {
  return subtle.importKey('pkcs8', concatBytes([X25519_PKCS8_PREFIX, raw]), 'X25519', extractable, usages);
}

async function importX25519Pub(raw) {
  return subtle.importKey('spki', concatBytes([X25519_SPKI_PREFIX, raw]), 'X25519', false, []);
}

// x25519PublicFromPrivate derives the public key for a raw private scalar by
// importing it as extractable and reading the "x" coordinate back out of its
// JWK form, which WebCrypto computes for us.
async function x25519PublicFromPrivate(raw) {
  const key = await importX25519Priv(raw, true, ['deriveBits']);
  const jwk = await subtle.exportKey('jwk', key);
  return unb64(jwk.x);
}

function isAllZero(bytes) {
  return bytes.every((b) => b === 0);
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((v, i) => v === b[i]);
}

// generateX25519 reads a fresh 32-byte seed and uses it as an X25519 private
// scalar, matching Go's GenerateX25519.
export async function generateX25519() {
  const priv = new Uint8Array(32);
  crypto.getRandomValues(priv);
  const pub = await x25519PublicFromPrivate(priv);
  return { priv, pub };
}

const WRAP_VERSION = 0x01;
const WRAP_PUB_SIZE = 32;
const WRAP_TAG_SIZE = 16;
// WRAP_SIZE is the only valid length of a wrapped value: every key this
// module wraps is 32 bytes, so the ciphertext is always
// version(1) + ephPub(32) + plaintext(32) + tag(16).
const WRAP_SIZE = 1 + WRAP_PUB_SIZE + KEY_LEN + WRAP_TAG_SIZE;

async function wrapKeyDerive(shared, ctx, ephPub) {
  return derive(
    shared,
    null,
    LABELS.wrap,
    ctx.purpose,
    ctx.artifact,
    String(ctx.epoch),
    ctx.recipientId,
    ctx.recipientPub,
    ephPub,
  );
}

// x25519Shared computes the X25519 shared secret, refusing the all-zero
// result that a crafted (low-order) public key can force. A WebCrypto throw
// on a bad point is treated the same way by the caller.
async function x25519Shared(privKey, pubKey) {
  const bits = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pubKey }, privKey, 256));
  if (isAllZero(bits)) return null;
  return bits;
}

// wrap encrypts key to ctx.recipientPub ({purpose, artifact, epoch,
// recipientId, recipientPub}) with a fresh ephemeral X25519 key pair:
// eph ‖ AES-GCM(wrapKey, zero-nonce, key).
export async function wrap(ctx, key) {
  if (ctx.recipientPub.length !== WRAP_PUB_SIZE) throw new FormatError('bad recipient public key length');
  checkKeyLen(key);
  const { priv: ephPriv, pub: ephPub } = await generateX25519();
  const ephPrivKey = await importX25519Priv(ephPriv, false, ['deriveBits']);
  let recipientPubKey;
  let shared;
  try {
    recipientPubKey = await importX25519Pub(ctx.recipientPub);
    shared = await x25519Shared(ephPrivKey, recipientPubKey);
  } catch {
    throw new FormatError('bad recipient public key');
  }
  if (shared === null) throw new FormatError('all-zero shared secret');

  const aesKey = await importAesGcmKey(await wrapKeyDerive(shared, ctx, ephPub), 'encrypt');
  const zeroNonce = new Uint8Array(GCM_NONCE_SIZE);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: zeroNonce }, aesKey, key));
  return concatBytes([new Uint8Array([WRAP_VERSION]), ephPub, ct]);
}

// unwrap decrypts a key wrapped with wrap. The recipient's public key is
// derived from priv rather than trusted from ctx.recipientPub, so a caller
// who passes a priv/ctx pair that don't match fails closed instead of
// deriving a wrap key under the wrong public key.
export async function unwrap(priv, ctx, wrapped) {
  if (wrapped.length !== WRAP_SIZE || wrapped[0] !== WRAP_VERSION || priv.length !== WRAP_PUB_SIZE) {
    throw new DecryptError('bad wrapped value');
  }
  let recipientPub;
  try {
    recipientPub = await x25519PublicFromPrivate(priv);
  } catch {
    throw new DecryptError('bad private key');
  }
  if (!bytesEqual(recipientPub, ctx.recipientPub)) throw new DecryptError('recipientPub does not match priv');

  const ephPub = wrapped.slice(1, 1 + WRAP_PUB_SIZE);
  const ct = wrapped.slice(1 + WRAP_PUB_SIZE);

  const privKey = await importX25519Priv(priv, false, ['deriveBits']);
  let shared;
  try {
    const ephPubKey = await importX25519Pub(ephPub);
    shared = await x25519Shared(privKey, ephPubKey);
  } catch {
    throw new DecryptError('bad ephemeral public key');
  }
  if (shared === null) throw new DecryptError('all-zero shared secret');

  // ctx is bound into the derivation here, so a wrap moved to another
  // purpose, artifact, epoch, or recipient fails to decrypt.
  const aesKey = await importAesGcmKey(await wrapKeyDerive(shared, ctx, ephPub), 'decrypt');
  const zeroNonce = new Uint8Array(GCM_NONCE_SIZE);
  let pt;
  try {
    pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: zeroNonce }, aesKey, ct));
  } catch {
    throw new DecryptError('authentication failed');
  }
  if (pt.length !== KEY_LEN) throw new DecryptError('wrapped plaintext has the wrong length');
  return pt;
}

async function importEd25519Priv(seed, extractable, usages) {
  return subtle.importKey('pkcs8', concatBytes([ED25519_PKCS8_PREFIX, seed]), 'Ed25519', extractable, usages);
}

async function importEd25519Pub(raw) {
  return subtle.importKey('spki', concatBytes([ED25519_SPKI_PREFIX, raw]), 'Ed25519', false, ['verify']);
}

// generateEd25519 reads a fresh 32-byte seed and derives an Ed25519 key pair
// from it.
export async function generateEd25519() {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const privKey = await importEd25519Priv(seed, true, ['sign']);
  const jwk = await subtle.exportKey('jwk', privKey);
  return { seed, pub: unb64(jwk.x) };
}

function sigMessage(purpose, body) {
  return enc(LABELS.sig, purpose, body);
}

const ED25519_SEED_SIZE = 32;

// sign signs body over sig = Ed25519(signingKey, enc("cairn/v1/sig", purpose, body)).
export async function sign(seed, purpose, body) {
  if (seed.length !== ED25519_SEED_SIZE) {
    throw new FormatError(`seed length ${seed.length}, want ${ED25519_SEED_SIZE}`);
  }
  const privKey = await importEd25519Priv(seed, false, ['sign']);
  const sig = await subtle.sign('Ed25519', privKey, sigMessage(purpose, body));
  return new Uint8Array(sig);
}

// SMALL_ORDER_ED25519 is the well-known list of Ed25519 public key encodings
// whose decoded point has order dividing 8: the four points of the curve's
// torsion subgroup that aren't the identity, plus the non-canonical
// encodings of those with y < 19 (y+p is still < 2^255 and so still
// decodes, to the same point, on a decoder that doesn't reject y >= p). This
// is the same list, verbatim, as internal/e2e/sign.go's smallOrderEd25519 —
// see that file's comment for how it was derived and confirmed; it is not
// reinvented here.
const SMALL_ORDER_ED25519 = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
].map((h) => fromHex(h));

function isSmallOrderEd25519(pub) {
  if (pub.length !== 32) return false;
  return SMALL_ORDER_ED25519.some((p) => bytesEqual(p, pub));
}

// checkPublicKeys rejects a malformed or low-order X25519 or Ed25519 public
// key, so a user's keyring can never be made to hold a key an attacker chose
// to force a predictable shared secret or a universally-valid signature.
//
// An X25519 key is checked by attempting ECDH with a fresh ephemeral key:
// WebCrypto refuses the all-zero output RFC 7748 requires implementations to
// reject, which is what every low-order point produces. An Ed25519 key is
// checked against the hardcoded small-order list.
export async function checkPublicKeys(x25519Pub, ed25519Pub) {
  if (x25519Pub.length !== 32) throw new FormatError('x25519 public key length, want 32');
  if (ed25519Pub.length !== 32) throw new FormatError('ed25519 public key length, want 32');
  let shared;
  try {
    const pubKey = await importX25519Pub(x25519Pub);
    const { priv: freshPriv } = await generateX25519();
    const freshPrivKey = await importX25519Priv(freshPriv, false, ['deriveBits']);
    shared = await x25519Shared(freshPrivKey, pubKey);
  } catch {
    throw new FormatError('x25519 public key is malformed');
  }
  if (shared === null) throw new FormatError('x25519 public key is low-order');
  if (isSmallOrderEd25519(ed25519Pub)) throw new FormatError('ed25519 public key is low-order');
}

// verify checks a signature produced by sign. It refuses a public key of the
// wrong length and a public key that is one of the small-order Ed25519
// encodings, which would let a forged "signature" verify against more than
// one message under a cofactored verifier. Unlike every other failure in
// this module, a bad signature is reported as false, matching Go's Verify.
export async function verify(pub, purpose, body, sig) {
  if (pub.length !== 32 || isSmallOrderEd25519(pub)) return false;
  try {
    const pubKey = await importEd25519Pub(pub);
    return await subtle.verify('Ed25519', pubKey, sig, sigMessage(purpose, body));
  } catch {
    return false;
  }
}

// newEnvelope signs body with seed and returns the envelope's b64 JSON form:
// {body, sig, signer}.
export async function newEnvelope(seed, signer, purpose, body) {
  const sig = await sign(seed, purpose, body);
  return { body: b64(body), sig: b64(sig), signer };
}

// verifyEnvelope checks an envelope's signature against pub for purpose. It
// does not interpret the body. envelope is the {body, sig, signer} b64 JSON
// form; malformed base64 throws FormatError, a bad signature returns false.
export async function verifyEnvelope(pub, purpose, envelope) {
  const body = unb64(envelope.body);
  const sig = unb64(envelope.sig);
  return verify(pub, purpose, body, sig);
}

// signRotation signs a rotation body with the old signing key, and again
// with the new one, producing the envelope and newSig the wire format
// requires.
export async function signRotation(oldSeed, newSeed, signer, body) {
  const env = await newEnvelope(oldSeed, signer, 'rotation', body);
  const newSig = await sign(newSeed, 'rotation', body);
  return { ...env, newSig: b64(newSig) };
}

// checkNoDuplicateKeys walks text character by character, tracking just
// enough JSON structure (object/array nesting, and whether the next token in
// an object is a key or a value) to fail if any JSON object, at any depth,
// repeats a key — the one thing JSON.parse resolves silently instead of
// rejecting. It does not otherwise validate JSON grammar; JSON.parse does
// that afterward. Mirrors checkNoDuplicateKeys in internal/e2e/envelope.go,
// adapted from Go's token-based walk to a hand-rolled one, since JavaScript
// has no streaming JSON tokenizer.
function checkNoDuplicateKeys(text) {
  const n = text.length;
  let i = 0;
  const stack = [];

  function readString() {
    let j = i + 1;
    while (j < n) {
      if (text[j] === '\\') {
        j += text[j + 1] === 'u' ? 6 : 2;
        continue;
      }
      if (text[j] === '"') {
        const s = text.slice(i + 1, j);
        i = j + 1;
        return s;
      }
      j++;
    }
    throw new FormatError('unterminated string');
  }

  // afterValue runs once a complete value (of any kind) has been consumed
  // outside of key position: if the enclosing frame is an object, that value
  // was the second half of a key/value pair, so the next token is a key.
  function afterValue() {
    const top = stack[stack.length - 1];
    if (top && top.isObject) top.expectKey = true;
  }

  while (i < n) {
    const c = text[i];
    if (' \t\n\r'.includes(c)) {
      i++;
      continue;
    }
    if (c === '{') {
      stack.push({ isObject: true, expectKey: true, seen: new Set() });
      i++;
      continue;
    }
    if (c === '[') {
      stack.push({ isObject: false });
      i++;
      continue;
    }
    if (c === '}' || c === ']') {
      stack.pop();
      i++;
      afterValue();
      continue;
    }
    if (c === ':' || c === ',') {
      i++;
      continue;
    }
    if (c === '"') {
      const top = stack[stack.length - 1];
      const keyPosition = Boolean(top && top.isObject && top.expectKey);
      const s = readString();
      if (keyPosition) {
        if (top.seen.has(s)) throw new FormatError(`duplicate key "${s}"`);
        top.seen.add(s);
        top.expectKey = false;
      } else {
        afterValue();
      }
      continue;
    }
    // A number, or true/false/null: consume up to the next structural
    // character or whitespace. JSON.parse checks the shape is actually
    // valid; this pass only needs to know a value went by.
    const start = i;
    while (i < n && !',}] \t\n\r:'.includes(text[i])) i++;
    if (i === start) throw new FormatError(`unexpected character ${JSON.stringify(c)}`);
    afterValue();
  }
}

// fingerprint is a SHA-256 hash over a user's public keys, for comparing
// aloud in short groups.
export async function fingerprint(x25519Pub, ed25519Pub) {
  const digest = await subtle.digest('SHA-256', enc(LABELS.fingerprint, x25519Pub, ed25519Pub));
  return new Uint8Array(digest);
}

// formatFingerprint renders the first 20 bytes of a fingerprint as hex, in
// groups of four characters separated by spaces.
export function formatFingerprint(fp) {
  const h = toHex(fp.slice(0, Math.min(fp.length, 20)));
  const groups = [];
  for (let i = 0; i < h.length; i += 4) groups.push(h.slice(i, i + 4));
  return groups.join(' ');
}

// Purpose bodies. A schema is a plain object of {fieldName: fieldDescriptor},
// field() below. Every field a verifier doesn't recognize, every duplicate
// key, and every field missing from the JSON a schema declares is a
// rejection: see decodeStrict. No field is optional, because a field that's
// absent from the input and therefore takes its zero value is exactly how a
// missing field is caught on round trip.
function field(type, opts) {
  return { type, ...opts };
}

const KEY_PAIR_SCHEMA = {
  x25519: field('string'),
  ed25519: field('string'),
};

const MEMBER_SCHEMA = {
  user: field('string'),
  role: field('string'),
  fp: field('string'),
};

const MANIFEST_FILE_SCHEMA = {
  path: field('string'),
  blob: field('string'),
  size: field('number'),
  sha256: field('string'),
};

// BODY_SCHEMAS: one entry per purpose in the wire-format spec's signature
// table.
export const BODY_SCHEMAS = {
  membership: {
    v: field('number'),
    artifact: field('string'),
    epoch: field('number'),
    owner: field('string'),
    akCommit: field('string'),
    members: field('array', { item: MEMBER_SCHEMA }),
    team: field('string'),
    public: field('boolean'),
    publicWrites: field('boolean'),
    prev: field('string'),
  },
  manifest: {
    v: field('number'),
    artifact: field('string'),
    version: field('string'),
    epoch: field('number'),
    files: field('array', { item: MANIFEST_FILE_SCHEMA }),
  },
  revision: {
    v: field('number'),
    artifact: field('string'),
    version: field('string'),
    revision: field('number'),
    epoch: field('number'),
    sha256: field('string'),
  },
  vouch: {
    v: field('number'),
    artifact: field('string'),
    version: field('string'),
    manifest: field('string'),
  },
  record: {
    v: field('number'),
    artifact: field('string'),
    version: field('string'),
    kind: field('string'),
    name: field('string'),
    epoch: field('number'),
    sha256: field('string'),
  },
  rotation: {
    v: field('number'),
    user: field('string'),
    seq: field('number'),
    old: field('object', { fields: KEY_PAIR_SCHEMA }),
    new: field('object', { fields: KEY_PAIR_SCHEMA }),
  },
  successor: {
    v: field('number'),
    user: field('string'),
    seq: field('number'),
    successor: field('string'),
    action: field('string'),
  },
  reset: {
    v: field('number'),
    user: field('string'),
    token: field('string'),
  },
};

// zeroValue is what a field decodes to when it's absent from the input,
// matching the zero value Go gives an unset struct field: "" for a string,
// 0 for a number, false for a boolean, a nested object of its own zero
// fields for a value-typed nested struct, and null — not [] — for a slice,
// since an unset Go slice is nil and marshals as null.
function zeroValue(f) {
  switch (f.type) {
    case 'string':
      return '';
    case 'number':
      return 0;
    case 'boolean':
      return false;
    case 'object':
      return decodeObject({}, f.fields);
    case 'array':
      return null;
    default:
      throw new TypeError(`unknown field type ${f.type}`);
  }
}

// findKey looks up name in obj case-insensitively, preferring an exact match
// over a case-variant one, matching Go's default json.Unmarshal field
// matching. Returns null if nothing matches. When more than one case variant
// is present and none is exact — not a shape produced by this module, and
// not exercised by any vector — the last one in the object's own key order
// wins, an arbitrary but deterministic tie-break.
function findKey(obj, name) {
  if (Object.prototype.hasOwnProperty.call(obj, name)) return name;
  const lower = name.toLowerCase();
  let found = null;
  for (const k of Object.keys(obj)) {
    if (k.toLowerCase() === lower) found = k;
  }
  return found;
}

function decodeValue(value, f) {
  switch (f.type) {
    case 'string':
      if (typeof value !== 'string') throw new FormatError(`expected a string`);
      return value;
    case 'number':
      if (typeof value !== 'number') throw new FormatError(`expected a number`);
      return value;
    case 'boolean':
      if (typeof value !== 'boolean') throw new FormatError(`expected a boolean`);
      return value;
    case 'object':
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new FormatError('expected an object');
      }
      return decodeObject(value, f.fields);
    case 'array':
      if (value === null) return null;
      if (!Array.isArray(value)) throw new FormatError('expected an array');
      return value.map((item) => decodeObject(item, f.item));
    default:
      throw new TypeError(`unknown field type ${f.type}`);
  }
}

// decodeObject builds a plain object with exactly schema's fields, each
// looked up case-insensitively in obj (preferring an exact match) or given
// its zero value when absent.
function decodeObject(obj, schema) {
  const out = {};
  for (const [name, f] of Object.entries(schema)) {
    const key = findKey(obj, name);
    out[name] = key === null ? zeroValue(f) : decodeValue(obj[key], f);
  }
  return out;
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (typeof a !== 'object') return false;
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  if (aKeys.length !== bKeys.length) return false;
  return aKeys.every((k) => Object.prototype.hasOwnProperty.call(b, k) && deepEqual(a[k], b[k]));
}

// decodeStrict decodes bytes against schema, refusing anything a lenient
// JSON.parse would silently accept: a duplicate key at any depth, a field
// schema doesn't declare, trailing data after the JSON value, a field
// missing from the input, and — the one none of the above catches on its
// own — a key that differs from a declared field only in case (such as
// "Files" next to "files"). Case-insensitive field matching resolves that
// onto the same field, so it isn't "unknown" by itself; it's caught here by
// re-encoding the decoded value and comparing it, as a generic JSON value,
// against the original: a case variant (or any other field) consumed by one
// side and not reproduced by the other makes the two values differ. Mirrors
// DecodeStrict in internal/e2e/envelope.go.
export function decodeStrict(bytes, schema) {
  const text = typeof bytes === 'string' ? bytes : new TextDecoder().decode(bytes);
  checkNoDuplicateKeys(text);
  let original;
  try {
    original = JSON.parse(text);
  } catch {
    throw new FormatError('invalid JSON');
  }
  if (typeof original !== 'object' || original === null || Array.isArray(original)) {
    throw new FormatError('expected a JSON object');
  }
  const decoded = decodeObject(original, schema);
  const roundTripped = JSON.parse(JSON.stringify(decoded));
  if (!deepEqual(original, roundTripped)) {
    throw new FormatError('decoded value does not round-trip (case-variant or extra field)');
  }
  return decoded;
}

// openEnvelope verifies env's signature against pub for purpose, strictly
// decodes its body against BODY_SCHEMAS[purpose], and requires the body's
// "v" field to be 1.
export async function openEnvelope(env, pub, purpose) {
  const schema = BODY_SCHEMAS[purpose];
  if (!schema) throw new FormatError(`unknown purpose: ${purpose}`);
  if (!(await verifyEnvelope(pub, purpose, env))) throw new DecryptError('bad envelope signature');
  const body = decodeStrict(unb64(env.body), schema);
  if (body.v !== 1) throw new FormatError(`body version ${body.v}, want 1`);
  return body;
}

// openRotation verifies both of a rotation envelope's signatures: env.sig
// against oldPub, and env.newSig against the new Ed25519 key named inside
// the body itself, so a rotation can't be accepted without proof of control
// over both the key it moves from and the key it moves to.
export async function openRotation(env, oldPub) {
  const body = await openEnvelope(env, oldPub, 'rotation');
  if (!env.newSig) throw new FormatError('rotation envelope missing newSig');
  const newPub = unb64(body.new.ed25519);
  const newSig = unb64(env.newSig);
  const bodyBytes = unb64(env.body);
  if (!(await verify(newPub, 'rotation', bodyBytes, newSig))) throw new DecryptError('bad newSig');
  return body;
}
