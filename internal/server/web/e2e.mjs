// e2e.mjs — the browser half of Cairn's end-to-end encryption crypto core.
// Built only on WebCrypto (globalThis.crypto.subtle, crypto.getRandomValues),
// so it runs under Node 22 and in every modern browser with no npm
// dependency. Every byte this module produces or accepts is fixed in
// design/e2e-wire-formats.md, so it agrees with the Go package internal/e2e
// byte for byte; see internal/e2e/testdata/vectors.json and e2e_test.mjs.
//
// All parsing and decryption failures throw an Error with a stable `name`
// (DecryptError, FormatError, FloorError, and the chain errors) rather than
// returning garbage. verify() is the one exception: it returns a boolean,
// matching Go's Verify.

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

// The membership chain errors, matching Go's ErrChain, ErrRollback,
// ErrFork, ErrStaleEpoch, and ErrReusedAK. See verifyChain.
export class ChainError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ChainError';
  }
}

export class RollbackError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RollbackError';
  }
}

export class ForkError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ForkError';
  }
}

export class StaleEpochError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StaleEpochError';
  }
}

export class ReusedAkError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ReusedAkError';
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

// fromHex and unb64 never echo the input in their error messages: both take
// attacker-influenced wire data, and an error message is a place that data
// could otherwise leak into a log line.
export function fromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new FormatError('bad hex');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// b64/unb64: base64url without padding, matching Go's
// base64.RawURLEncoding.Strict(). unb64 accepts only the URL-safe alphabet
// (no "+", "/", or "="), no padding, and zero unused bits in a partial
// group's last character: decoding, then re-encoding and comparing, catches
// non-zero trailing bits without a separate bit-level check.
const BASE64URL_RE = /^[A-Za-z0-9_-]*$/;

export function b64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64(str) {
  if (typeof str !== 'string' || !BASE64URL_RE.test(str)) throw new FormatError('bad base64url: invalid character');
  if (str.length % 4 === 1) throw new FormatError('bad base64url: invalid length');
  const standard = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new FormatError('bad base64url');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  if (b64(bytes) !== str) throw new FormatError('bad base64url: non-canonical encoding');
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

// checkKeyLen skips the length check for a CryptoKey, which has no .length
// to read (and an HKDF CryptoKey exposes no length at all). Its length is
// not fixed by its algorithm: HKDF and HMAC import raw keys of any length.
// So a CryptoKey is the right length only because this module's importers
// and derivers produce it that way — importHKDFKey checks KEY_LEN, and the
// *CryptoKey derivers output 256-bit keys. One built elsewhere with
// subtle.importKey is unchecked here.
function checkKeyLen(key) {
  if (key instanceof CryptoKey) return;
  if (key.length !== KEY_LEN) throw new FormatError(`key length ${key.length}, want ${KEY_LEN}`);
}

// checkEpoch requires a safe non-negative integer, matching Go's uint64
// epoch and the decimal-ASCII-no-leading-zeros rule the wire format uses: a
// float, a negative number, or a value too large to round-trip exactly in a
// float64 would silently encode the wrong decimal string.
function checkEpoch(epoch) {
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new FormatError('epoch must be a safe non-negative integer');
  }
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

// importHKDFKey imports raw key bytes as a non-extractable HKDF CryptoKey
// usable by both derive (deriveBits) and deriveKey (deriveKey) below, so a
// master, estate, or artifact key can be held and derived from without ever
// being extractable again after this call. The key must be KEY_LEN bytes:
// the resulting CryptoKey exposes no length, so this is the only point at
// which it can be checked.
export async function importHKDFKey(raw) {
  const bytes = toBytes(raw);
  checkKeyLen(bytes);
  return importHKDFKeyUnchecked(bytes);
}

// importHKDFKeyUnchecked is importHKDFKey without the length check, for
// deriveKey, whose callers check the length themselves (or, for a recovery
// code or API key secret, deliberately derive from input of another length).
async function importHKDFKeyUnchecked(raw) {
  return subtle.importKey('raw', toBytes(raw), 'HKDF', false, ['deriveBits', 'deriveKey']);
}

// deriveKey derives a non-extractable key of the given algorithm directly
// via HKDF: unlike derive, the derived key material never exists as a plain
// Uint8Array in JS memory. ikm is raw bytes or a non-extractable HKDF
// CryptoKey (see importHKDFKey).
async function deriveKey(ikm, salt, label, fields, algorithm, usages) {
  const info = enc(label, ...fields);
  const key = ikm instanceof CryptoKey ? ikm : await importHKDFKeyUnchecked(ikm);
  const saltBytes = salt ? toBytes(salt) : new Uint8Array(0);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info }, key, algorithm, false, usages);
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
  if (!Number.isInteger(params.m) || !Number.isInteger(params.t) || !Number.isInteger(params.p)) {
    throw new FloorError('m, t, and p must be integers');
  }
  if (!(params.salt instanceof Uint8Array)) throw new FloorError('salt must be a Uint8Array');
  if (params.m < FLOOR_MEMORY) throw new FloorError(`memory ${params.m} below floor`);
  if (params.m > CEILING_MEMORY) throw new FloorError(`memory ${params.m} above ceiling`);
  if (params.t < FLOOR_TIME) throw new FloorError(`time ${params.t} below floor`);
  if (params.t > CEILING_TIME) throw new FloorError(`time ${params.t} above ceiling`);
  if (params.p < 1 || params.p > 4) throw new FloorError(`threads ${params.p} out of range`);
  const saltLen = params.salt.length;
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

// passwordCryptoKeys is passwordKeys with kek as a non-extractable AES-GCM
// CryptoKey for one purpose (see kekUsages), so the raw kek never exists in
// JS memory. authKey stays raw bytes: it is sent to the server.
export async function passwordCryptoKeys(stretched, purpose) {
  const usages = kekUsages(purpose);
  const authKey = await derive(stretched, null, LABELS.auth);
  const kek = await deriveKey(stretched, null, LABELS.kek, [], AES_GCM_256_ALG, usages);
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

// recoveryKekCryptoKey is recoveryKek as a non-extractable AES-GCM CryptoKey
// for one purpose (see kekUsages).
export async function recoveryKekCryptoKey(code, purpose) {
  return deriveKey(code, null, LABELS.recovery, [], AES_GCM_256_ALG, kekUsages(purpose));
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

// apiKeyKekCryptoKey is apiKeyKek as a non-extractable AES-GCM CryptoKey
// for one purpose (see kekUsages).
export async function apiKeyKekCryptoKey(keySecret, keyId, purpose) {
  return deriveKey(keySecret, null, LABELS.apiKey, [keyId], AES_GCM_256_ALG, kekUsages(purpose));
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
  checkEpoch(epoch);
  return derive(ak, null, LABELS.linkToken, artifact, String(epoch));
}
export async function fileKey(ak, artifact, epoch) {
  checkKeyLen(ak);
  checkEpoch(epoch);
  return derive(ak, null, LABELS.fileKey, artifact, String(epoch));
}

// mkSealCryptoKey, ekSealCryptoKey, indexCryptoKey, and fileCryptoKey are the
// non-extractable-CryptoKey counterparts of mkSealKey, ekSealKey, indexKey,
// and fileKey: mk/ek/ak may be raw bytes or a non-extractable HKDF CryptoKey
// (see importHKDFKey), and the result is a non-extractable CryptoKey of the
// right algorithm for seal/open (AES-GCM) or the HMAC helpers, never a raw
// Uint8Array.
const HMAC_SHA256_ALG = { name: 'HMAC', hash: 'SHA-256' };
// HMAC_SHA256_DERIVE_ALG fixes the derived key at 256 bits, matching
// DERIVED_KEY_BITS: HMAC's own default derived-key length is the hash's
// block size (512 bits for SHA-256), not its output size, which would
// silently derive a different key than derive()'s deriveBits call does for
// the same ikm/salt/info.
const HMAC_SHA256_DERIVE_ALG = { name: 'HMAC', hash: 'SHA-256', length: DERIVED_KEY_BITS };
const AES_GCM_256_ALG = { name: 'AES-GCM', length: 256 };
// KEK_USAGES are the usages of mkSealCryptoKey and ekSealCryptoKey: seal and
// open take encrypt/decrypt, and openKey takes unwrapKey.
const KEK_USAGES = ['encrypt', 'decrypt', 'unwrapKey'];

// kekUsages maps a KEK CryptoKey's purpose to its one usage. A KEK (kek,
// recoveryKek, apiKeyKek) seals only the 32-byte MK: 'seal' encrypts it, and
// 'open' unwraps it through openKey, so no KEK can decrypt MK into JS memory.
// There is no default: anything else is a FormatError.
function kekUsages(purpose) {
  if (purpose === 'seal') return ['encrypt'];
  if (purpose === 'open') return ['unwrapKey'];
  throw new FormatError(`KEK purpose must be 'seal' or 'open', got ${String(purpose)}`);
}

// These keep decrypt: they seal X25519/Ed25519 private keys, which WebCrypto can't unwrap raw.
export async function mkSealCryptoKey(mk) {
  checkKeyLen(mk);
  return deriveKey(mk, null, LABELS.mkSeal, [], AES_GCM_256_ALG, KEK_USAGES);
}
export async function ekSealCryptoKey(ek) {
  checkKeyLen(ek);
  return deriveKey(ek, null, LABELS.ekSeal, [], AES_GCM_256_ALG, KEK_USAGES);
}
export async function indexCryptoKey(mk) {
  checkKeyLen(mk);
  return deriveKey(mk, null, LABELS.index, [], HMAC_SHA256_DERIVE_ALG, ['sign']);
}
export async function fileCryptoKey(ak, artifact, epoch) {
  checkKeyLen(ak);
  checkEpoch(epoch);
  return deriveKey(ak, null, LABELS.fileKey, [artifact, String(epoch)], HMAC_SHA256_DERIVE_ALG, ['sign']);
}

// akCommit is a public commitment to an artifact's AK at a given epoch, so a
// party without AK can confirm two sources agree on it without learning it.
export async function akCommit(ak, artifact, epoch) {
  checkKeyLen(ak);
  checkEpoch(epoch);
  const commit = await derive(ak, null, LABELS.akCommit, artifact, String(epoch));
  return toHex(commit);
}

// hmacSha256 accepts either a raw KEY_LEN-byte key or a non-extractable
// HMAC-SHA256 CryptoKey (see indexCryptoKey/fileCryptoKey).
async function hmacSha256(key, message) {
  let hmacKey = key;
  if (!(key instanceof CryptoKey)) {
    const raw = toBytes(key);
    checkKeyLen(raw);
    hmacKey = await subtle.importKey('raw', raw, HMAC_SHA256_ALG, false, ['sign']);
  }
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

// importAesGcmKey accepts either a raw 32-byte key or an already-imported
// non-extractable AES-GCM CryptoKey (see mkSealCryptoKey/ekSealCryptoKey),
// always checking the key is exactly 32 bytes before handing a raw one to
// WebCrypto, which would otherwise happily treat a 16- or 24-byte key as
// AES-128 or AES-192: this module only ever uses AES-256-GCM.
async function importAesGcmKey(key, usage) {
  if (key instanceof CryptoKey) return key;
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
  if (!(sealed instanceof Uint8Array)) throw new FormatError('sealed value must be a Uint8Array');
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

// SEALED_KEY_SIZE is the only length of a sealed KEY_LEN-byte key:
// version(1) + nonce(12) + key(32) + tag(16). An HKDF CryptoKey exposes no
// length, so this is how openKey knows the key it imports is 32 bytes.
const SEALED_KEY_SIZE = 1 + GCM_NONCE_SIZE + KEY_LEN + 16;

// openKey opens a sealed 32-byte key (MK, EK, or an AK: anything sealed with
// seal and later used as HKDF input) straight into a non-extractable HKDF
// CryptoKey via subtle.unwrapKey, so the opened key never exists as raw bytes
// in JS memory. key is raw bytes or an AES-GCM CryptoKey with the unwrapKey
// usage (the *CryptoKey KEKs and sealing keys). Same format, AD, and errors as
// open, plus DecryptError for a sealed value of any other length.
export async function openKey(key, fields, sealed) {
  if (!(sealed instanceof Uint8Array)) throw new FormatError('sealed value must be a Uint8Array');
  if (sealed.length !== SEALED_KEY_SIZE || sealed[0] !== SEAL_VERSION) {
    throw new DecryptError('bad header or length');
  }
  const nonce = sealed.slice(1, 1 + GCM_NONCE_SIZE);
  const ct = sealed.slice(1 + GCM_NONCE_SIZE);
  try {
    const aesKey = await importAesGcmKey(key, 'unwrapKey');
    return await subtle.unwrapKey(
      'raw',
      ct,
      aesKey,
      { name: 'AES-GCM', iv: nonce, additionalData: sealAD(fields) },
      'HKDF',
      false,
      ['deriveBits', 'deriveKey'],
    );
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

// blobKey derives the blob's AES-GCM key straight to a non-extractable
// CryptoKey, so the derived key never exists as raw bytes in JS memory.
async function blobKey(ak, salt, ctx, usage) {
  const fields = [ctx.artifact, ctx.version, ctx.kind, ctx.name];
  return deriveKey(ak, salt, LABELS.blob, fields, AES_GCM_256_ALG, [usage]);
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
  const aesKey = await blobKey(ak, salt, ctx, 'encrypt');

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
  if (blob.length === BLOB_HEADER_SIZE) {
    // A valid blob always has at least one chunk, even an empty one.
    throw new DecryptError('no chunks');
  }

  const aesKey = await blobKey(ak, salt, ctx, 'decrypt');

  const parts = [];
  let offset = BLOB_HEADER_SIZE;
  let i = 0;
  // subarray, not slice: a view into blob rather than a copy of everything
  // from offset onward, so decrypting n chunks does O(n) work total instead
  // of O(n^2) from re-copying a shrinking remainder on every iteration.
  while (offset < blob.length) {
    const remaining = blob.length - offset;
    const last = remaining <= BLOB_FULL_CHUNK_SIZE;
    const chunkSize = last ? remaining : BLOB_FULL_CHUNK_SIZE;
    const chunkCT = blob.subarray(offset, offset + chunkSize);
    offset += chunkSize;
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
// JWK form, which WebCrypto computes for us. The extractable import is
// transient: its only use is this one export, and the key is discarded
// immediately afterward.
async function x25519PublicFromPrivate(raw) {
  const key = await importX25519Priv(raw, true, ['deriveBits']);
  const jwk = await subtle.exportKey('jwk', key);
  return unb64(jwk.x);
}

// importX25519PrivateKey imports a 32-byte private scalar as a non-
// extractable X25519 CryptoKey, computing its public key once here (the only
// time it can be read back out) rather than leaving the caller to try later,
// when the returned privateKey is no longer extractable. The result is
// accepted directly by unwrap.
export async function importX25519PrivateKey(raw) {
  if (raw.length !== 32) throw new FormatError('x25519 private key length, want 32');
  const publicKey = await x25519PublicFromPrivate(raw);
  const privateKey = await importX25519Priv(raw, false, ['deriveBits']);
  return { privateKey, publicKey };
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

// wrapKey derives the wrap key straight to a non-extractable AES-GCM
// CryptoKey, so the derived key never exists as raw bytes in JS memory.
async function wrapKey(shared, ctx, ephPub, usage) {
  checkEpoch(ctx.epoch);
  const fields = [ctx.purpose, ctx.artifact, String(ctx.epoch), ctx.recipientId, ctx.recipientPub, ephPub];
  return deriveKey(shared, null, LABELS.wrap, fields, AES_GCM_256_ALG, [usage]);
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
  if (!(ctx.recipientPub instanceof Uint8Array) || ctx.recipientPub.length !== WRAP_PUB_SIZE) {
    throw new FormatError('bad recipient public key length');
  }
  checkKeyLen(key);
  const { priv: ephPriv, pub: ephPub } = await generateX25519();
  const ephPrivKey = await importX25519Priv(ephPriv, false, ['deriveBits']);
  ephPriv.fill(0); // best-effort zeroing: the raw scalar is no longer needed once imported
  let recipientPubKey;
  let shared;
  try {
    recipientPubKey = await importX25519Pub(ctx.recipientPub);
    shared = await x25519Shared(ephPrivKey, recipientPubKey);
  } catch {
    throw new FormatError('bad recipient public key');
  }
  if (shared === null) throw new FormatError('all-zero shared secret');

  let aesKey;
  try {
    aesKey = await wrapKey(shared, ctx, ephPub, 'encrypt');
  } finally {
    shared.fill(0); // best-effort zeroing: the shared secret is no longer needed
  }
  const zeroNonce = new Uint8Array(GCM_NONCE_SIZE);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: zeroNonce }, aesKey, key));
  return concatBytes([new Uint8Array([WRAP_VERSION]), ephPub, ct]);
}

// unwrap decrypts a key wrapped with wrap. privOrKeyObj is either a raw
// 32-byte private scalar (as before, for tests and vectors) or the
// {privateKey, publicKey} object importX25519PrivateKey returns. Either way,
// the recipient's public key comes from priv itself rather than from
// ctx.recipientPub — recomputed from the raw scalar, or taken from the
// precomputed value a non-extractable CryptoKey can't be read back out to
// recompute — so a caller who passes a priv/ctx pair that don't match fails
// closed instead of deriving a wrap key under the wrong public key.
export async function unwrap(privOrKeyObj, ctx, wrapped) {
  if (wrapped.length !== WRAP_SIZE || wrapped[0] !== WRAP_VERSION) {
    throw new DecryptError('bad wrapped value');
  }
  let privKey, recipientPub;
  if (privOrKeyObj instanceof Uint8Array) {
    if (privOrKeyObj.length !== WRAP_PUB_SIZE) throw new DecryptError('bad wrapped value');
    try {
      recipientPub = await x25519PublicFromPrivate(privOrKeyObj);
    } catch {
      throw new DecryptError('bad private key');
    }
    privKey = await importX25519Priv(privOrKeyObj, false, ['deriveBits']);
  } else {
    if (
      typeof privOrKeyObj !== 'object' || privOrKeyObj === null ||
      !(privOrKeyObj.privateKey instanceof CryptoKey) || !(privOrKeyObj.publicKey instanceof Uint8Array)
    ) {
      throw new FormatError('want a 32-byte private key or the object importX25519PrivateKey returns');
    }
    ({ privateKey: privKey, publicKey: recipientPub } = privOrKeyObj);
  }
  if (!(ctx.recipientPub instanceof Uint8Array)) throw new FormatError('recipientPub must be a Uint8Array');
  if (!bytesEqual(recipientPub, ctx.recipientPub)) throw new DecryptError('recipientPub does not match priv');

  const ephPub = wrapped.slice(1, 1 + WRAP_PUB_SIZE);
  const ct = wrapped.slice(1 + WRAP_PUB_SIZE);
  // X25519 masks the high bit and reduces mod p, so a non-canonical
  // spelling of ephPub gives the same shared secret; refuse it, so each
  // wrap has exactly one valid encoding.
  if (isNonCanonicalX25519(ephPub)) throw new DecryptError('non-canonical ephemeral public key');

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
  let aesKey;
  try {
    aesKey = await wrapKey(shared, ctx, ephPub, 'decrypt');
  } finally {
    shared.fill(0); // best-effort zeroing: the shared secret is no longer needed
  }
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

// importEd25519SigningKey imports a 32-byte seed as a non-extractable
// Ed25519 signing CryptoKey, so a long-term signing key can be held without
// ever being extractable again after this call. Its result is accepted
// directly by sign.
export async function importEd25519SigningKey(seed) {
  if (seed.length !== ED25519_SEED_SIZE) {
    throw new FormatError(`seed length ${seed.length}, want ${ED25519_SEED_SIZE}`);
  }
  return importEd25519Priv(seed, false, ['sign']);
}

// sign signs body over sig = Ed25519(signingKey, enc("cairn/v1/sig", purpose, body)).
// seedOrKey is either a 32-byte seed (as before, for tests and vectors) or a
// non-extractable Ed25519 CryptoKey from importEd25519SigningKey.
export async function sign(seedOrKey, purpose, body) {
  const privKey = seedOrKey instanceof CryptoKey ? seedOrKey : await importEd25519SigningKey(seedOrKey);
  const sig = await subtle.sign('Ed25519', privKey, sigMessage(purpose, body));
  return new Uint8Array(sig);
}

// ED25519_P is the field prime shared by Curve25519 and Ed25519: 2^255-19.
const ED25519_P = (1n << 255n) - 19n;
const ED25519_P_MINUS_1 = ED25519_P - 1n;
// ED25519_L is the prime order of the Ed25519 base point (RFC 8032), used to
// refuse a non-canonical signature (S >= L) explicitly: Go's crypto/ed25519
// already refuses one, but WebCrypto implementations vary.
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

// leBytesToBigInt interprets bytes as a little-endian unsigned integer, the
// byte order every key and coordinate in this module uses.
function leBytesToBigInt(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

// CANONICAL_SMALL_ORDER_ED25519 is the 8 canonical Ed25519 public key
// encodings whose decoded point has order dividing 8: the identity, the
// order-2 point, the two order-4 points, and the four order-8 points. This
// is the same list, verbatim, as internal/e2e/sign.go's smallOrderEd25519 —
// see that file's comment for how it was derived and confirmed; it is not
// reinvented here.
//
// Every other invalid or non-canonical encoding — a y coordinate >= p, or
// the impossible combination x=0 with the sign bit set — is rejected
// structurally by isSmallOrderEd25519 below instead of by a longer list; see
// that function's comment.
const CANONICAL_SMALL_ORDER_ED25519 = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
].map((h) => fromHex(h));

// isSmallOrderEd25519 rejects a public key encoding a verifier must never
// accept: a non-canonical y coordinate (the low 255 bits, little-endian, >=
// p), the impossible combination x=0 with the sign bit set (only y=1 or
// y=p-1 give x=0, so a set sign bit there is not an encoding this curve ever
// produces), or one of the 8 canonical small-order points. Mirrors
// isSmallOrderEd25519 in internal/e2e/sign.go.
function isSmallOrderEd25519(pub) {
  if (pub.length !== 32) return false;
  const signSet = (pub[31] & 0x80) !== 0;
  const yBytes = pub.slice();
  yBytes[31] &= 0x7f;
  const y = leBytesToBigInt(yBytes);
  if (y >= ED25519_P) return true;
  if (signSet && (y === 1n || y === ED25519_P_MINUS_1)) return true;
  return CANONICAL_SMALL_ORDER_ED25519.some((p) => bytesEqual(p, pub));
}

// isNonCanonicalX25519 rejects an X25519 public key that isn't the unique
// canonical encoding of its u-coordinate: the high bit of the last byte set,
// or the full 32-byte little-endian value >= p. Checking the raw, unmasked
// value catches both cases in one comparison, since a set high bit alone
// already puts the value at or above 2^255 > p. Mirrors isNonCanonicalX25519
// in internal/e2e/sign.go.
function isNonCanonicalX25519(pub) {
  return leBytesToBigInt(pub) >= ED25519_P;
}

// --- Minimal edwards25519 arithmetic, for the torsion check only. ---
//
// WebCrypto exposes no point operations, so deciding whether a key or a
// signature's R is torsion-free needs this. It runs only on public values,
// so it makes no attempt at constant time. The curve is -x^2 + y^2 = 1 +
// d x^2 y^2 over GF(p), and points are in extended coordinates (X:Y:Z:T)
// with x = X/Z, y = Y/Z, xy = T/Z (Hisil, Wong, Carter, Dawson 2008).

// fmod reduces a mod p into [0, p); BigInt % keeps the sign of a.
function fmod(a) {
  const r = a % ED25519_P;
  return r < 0n ? r + ED25519_P : r;
}

// fpow is base^exp mod p, by square-and-multiply.
function fpow(base, exp) {
  let result = 1n;
  let b = fmod(base);
  for (let e = exp; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * b) % ED25519_P;
    b = (b * b) % ED25519_P;
  }
  return result;
}

// ED25519_D is the curve constant d = -121665/121666 mod p, and
// ED25519_SQRT_M1 a square root of -1 mod p, 2^((p-1)/4); both from RFC 8032.
const ED25519_D = fmod(-121665n * fpow(121666n, ED25519_P - 2n));
const ED25519_D2 = (2n * ED25519_D) % ED25519_P;
const ED25519_SQRT_M1 = fpow(2n, (ED25519_P - 1n) / 4n);

// decodeEd25519Point decodes a 32-byte point encoding per RFC 8032 section
// 5.1.3, up to sign, or returns null if no curve point has it. The caller
// has already refused y >= p and x = 0 with the sign bit set
// (isSmallOrderEd25519). The sign bit only chooses between x and -x, and is
// ignored: P is torsion-free exactly when -P is.
function decodeEd25519Point(bytes) {
  const y = leBytesToBigInt(bytes) & ((1n << 255n) - 1n);
  // x^2 = u/v with u = y^2 - 1 and v = d y^2 + 1. The candidate root is
  // x = u v^3 (u v^7)^((p-5)/8); it is right if v x^2 = u, off by a factor
  // of sqrt(-1) if v x^2 = -u, and otherwise u/v has no square root.
  const y2 = (y * y) % ED25519_P;
  const u = fmod(y2 - 1n);
  const v = fmod(ED25519_D * y2 + 1n);
  const v3 = (((v * v) % ED25519_P) * v) % ED25519_P;
  const v7 = (((v3 * v3) % ED25519_P) * v) % ED25519_P;
  let x = (((u * v3) % ED25519_P) * fpow(u * v7, (ED25519_P - 5n) / 8n)) % ED25519_P;
  const vx2 = (((v * x) % ED25519_P) * x) % ED25519_P;
  if (vx2 === fmod(-u)) x = (x * ED25519_SQRT_M1) % ED25519_P;
  else if (vx2 !== u) return null;
  return { X: x, Y: y, Z: 1n, T: (x * y) % ED25519_P };
}

// edAdd is add-2008-hwcd-3 for a = -1. It is complete on this curve (d is
// not a square), so it is also correct when P = Q or either is the identity.
function edAdd(P, Q) {
  const A = fmod((P.Y - P.X) * (Q.Y - Q.X));
  const B = ((P.Y + P.X) * (Q.Y + Q.X)) % ED25519_P;
  const C = (((P.T * ED25519_D2) % ED25519_P) * Q.T) % ED25519_P;
  const D = (2n * P.Z * Q.Z) % ED25519_P;
  const E = fmod(B - A);
  const F = fmod(D - C);
  const G = (D + C) % ED25519_P;
  const H = (B + A) % ED25519_P;
  return { X: (E * F) % ED25519_P, Y: (G * H) % ED25519_P, Z: (F * G) % ED25519_P, T: (E * H) % ED25519_P };
}

// edDouble is dbl-2008-hwcd for a = -1: cheaper than edAdd(P, P).
function edDouble(P) {
  const A = (P.X * P.X) % ED25519_P;
  const B = (P.Y * P.Y) % ED25519_P;
  const C = (2n * P.Z * P.Z) % ED25519_P;
  const E = fmod((P.X + P.Y) * (P.X + P.Y) - A - B);
  const G = fmod(B - A); // D + B with D = -A
  const F = fmod(G - C);
  const H = fmod(-A - B); // D - B
  return { X: (E * F) % ED25519_P, Y: (G * H) % ED25519_P, Z: (F * G) % ED25519_P, T: (E * H) % ED25519_P };
}

// edMul is [n]P by left-to-right double-and-add; n is public.
function edMul(n, P) {
  let R = { X: 0n, Y: 1n, Z: 1n, T: 0n };
  for (let i = BigInt(n.toString(2).length) - 1n; i >= 0n; i--) {
    R = edDouble(R);
    if ((n >> i) & 1n) R = edAdd(R, P);
  }
  return R;
}

// isPrimeOrderEd25519 reports whether enc is the canonical encoding of a
// curve point in the prime-order subgroup other than the identity: not
// refused by isSmallOrderEd25519, on the curve, and torsion-free, that is
// [L]P is the identity (X = 0 and Y = Z). A mixed-order point (a
// prime-order point plus a small-order one) passes the first two, so it
// needs the third. Mirrors isPrimeOrderEd25519 in internal/e2e/sign.go.
function isPrimeOrderEd25519(enc) {
  if (enc.length !== 32 || isSmallOrderEd25519(enc)) return false;
  const P = decodeEd25519Point(enc);
  if (P === null) return false;
  const Q = edMul(ED25519_L, P);
  return Q.X === 0n && Q.Y === Q.Z;
}

// ed25519KeyChecks caches isPrimeOrderEd25519 for public keys, which repeat
// (one signer, many signatures); R never does. Bounded, oldest out first.
const ed25519KeyChecks = new Map();
const ED25519_KEY_CHECKS_MAX = 256;

function isPrimeOrderEd25519Key(pub) {
  const k = toHex(pub);
  let ok = ed25519KeyChecks.get(k);
  if (ok === undefined) {
    ok = isPrimeOrderEd25519(pub);
    if (ed25519KeyChecks.size >= ED25519_KEY_CHECKS_MAX) {
      ed25519KeyChecks.delete(ed25519KeyChecks.keys().next().value);
    }
    ed25519KeyChecks.set(k, ok);
  }
  return ok;
}

// checkPublicKeys rejects a malformed, non-canonical, or low-order X25519 or
// Ed25519 public key, so a user's keyring can never be made to hold a key an
// attacker chose to force a predictable shared secret or a universally-valid
// signature.
//
// An X25519 key is checked for canonical form, then by attempting ECDH with
// a fresh ephemeral key: WebCrypto refuses the all-zero output RFC 7748
// requires implementations to reject, which is what every low-order point
// produces. An Ed25519 key must be a canonical, on-curve, torsion-free
// point; see isPrimeOrderEd25519. X25519 needs no torsion check: a clamped
// scalar is a multiple of 8, so the torsion component of a mixed-order key
// never reaches the shared secret.
export async function checkPublicKeys(x25519Pub, ed25519Pub) {
  if (x25519Pub.length !== 32) throw new FormatError('x25519 public key length, want 32');
  if (ed25519Pub.length !== 32) throw new FormatError('ed25519 public key length, want 32');
  if (isNonCanonicalX25519(x25519Pub)) {
    throw new FormatError('x25519 public key is not canonically encoded');
  }
  let shared;
  try {
    const pubKey = await importX25519Pub(x25519Pub);
    const { priv: freshPriv } = await generateX25519();
    const freshPrivKey = await importX25519Priv(freshPriv, false, ['deriveBits']);
    freshPriv.fill(0); // best-effort zeroing: the raw scalar is no longer needed once imported
    shared = await x25519Shared(freshPrivKey, pubKey);
  } catch {
    throw new FormatError('x25519 public key is malformed');
  }
  if (shared) shared.fill(0); // best-effort zeroing: only used to test for the all-zero result
  if (shared === null) throw new FormatError('x25519 public key is low-order');
  if (!isPrimeOrderEd25519Key(ed25519Pub)) {
    throw new FormatError('ed25519 public key is not a canonical point of prime order');
  }
}

// verify checks a signature produced by sign. Before the curve equation it
// requires the public key A and the signature's R (its first 32 bytes) each
// to be the canonical encoding of a point of prime order (see
// isPrimeOrderEd25519), and S (its last 32 bytes) to be below L. WebCrypto
// implementations differ: a cofactored one accepts a small-order or
// mixed-order R or A that a cofactorless one refuses, and not all refuse
// S >= L. These checks make the result the same under every one, and the
// same as Go's Verify (signatureEncodingOK). Unlike every other failure in
// this module, a bad signature is reported as false, matching Go's Verify.
// verify works on copies of pub and sig, so a caller reusing its buffers
// mid-call cannot change what was checked, and runs the cheap checks before
// the torsion checks' point multiplications.
export async function verify(pub, purpose, body, sig) {
  if (!(pub instanceof Uint8Array) || pub.length !== 32) return false;
  if (!(sig instanceof Uint8Array) || sig.length !== 64) return false;
  pub = new Uint8Array(pub);
  sig = new Uint8Array(sig);
  const R = sig.subarray(0, 32);
  if (leBytesToBigInt(sig.subarray(32)) >= ED25519_L) return false;
  if (isSmallOrderEd25519(pub) || isSmallOrderEd25519(R)) return false;
  if (!isPrimeOrderEd25519Key(pub) || !isPrimeOrderEd25519(R)) return false;
  try {
    // sigMessage copies body, so it must run before the first await.
    const message = sigMessage(purpose, body);
    const pubKey = await importEd25519Pub(pub);
    return await subtle.verify('Ed25519', pubKey, sig, message);
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

// decodeTextStrict decodes bytesOrText into a JSON text string, refusing a
// leading UTF-8 BOM, invalid UTF-8, and an unpaired UTF-16 surrogate escape —
// none of which JSON.parse itself rejects: a BOM is a valid-but-unexpected
// character, invalid UTF-8 is impossible to produce from a JS string input
// but must be refused when decoding bytes, and an unpaired \uD800-\uDFFF
// escape is silently turned into an actual lone surrogate code unit by
// JSON.parse rather than rejected, any of which would let two different
// inputs decode to the same value. Mirrors checkStrictBytes in
// internal/e2e/envelope.go.
function decodeTextStrict(bytesOrText) {
  let text;
  if (typeof bytesOrText === 'string') {
    // A JS string can hold a lone surrogate code unit outright, which no
    // UTF-8 byte input can; refuse it as the bytes path refuses invalid UTF-8.
    if (!bytesOrText.isWellFormed()) throw new FormatError('lone surrogate code unit');
    text = bytesOrText;
  } else {
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    try {
      text = decoder.decode(bytesOrText);
    } catch {
      throw new FormatError('invalid UTF-8');
    }
  }
  if (text.charCodeAt(0) === 0xfeff) throw new FormatError('UTF-8 BOM');
  checkNoLoneSurrogates(text);
  return text;
}

// checkNoLoneSurrogates scans text for \uXXXX escapes and refuses a high
// surrogate (D800-DBFF) not immediately followed by a low surrogate
// (DC00-DFFF) escape, or a low surrogate not immediately preceded by one.
// Mirrors checkNoLoneSurrogates in internal/e2e/envelope.go.
function checkNoLoneSurrogates(text) {
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (text[i] !== '\\') {
      i++;
      continue;
    }
    if (text[i + 1] !== 'u') {
      i += 2;
      continue;
    }
    const hi = parseInt(text.slice(i + 2, i + 6), 16);
    if (Number.isNaN(hi)) throw new FormatError('bad unicode escape');
    i += 6;
    if (hi >= 0xd800 && hi <= 0xdbff) {
      if (text[i] === '\\' && text[i + 1] === 'u') {
        const lo = parseInt(text.slice(i + 2, i + 6), 16);
        if (!Number.isNaN(lo) && lo >= 0xdc00 && lo <= 0xdfff) {
          i += 6;
          continue;
        }
      }
      throw new FormatError('unpaired high surrogate');
    }
    if (hi >= 0xdc00 && hi <= 0xdfff) throw new FormatError('unpaired low surrogate');
  }
}

// STRICT_NUMBER_RE matches the only JSON number lexemes this package
// accepts: zero, or a non-zero digit followed by more digits. No sign, no
// fraction, and no exponent — those are all syntactically valid JSON
// numbers, so JSON.parse itself doesn't reject them, but none of this
// package's wire format ever needs one.
const STRICT_NUMBER_RE = /^(0|[1-9][0-9]*)$/;

// MAX_SAFE_INTEGER_WIRE is 2^53-1, the largest integer a float64 represents
// exactly. A wire format number above it could round-trip differently
// between Go and the browser.
const MAX_SAFE_INTEGER_WIRE = BigInt(Number.MAX_SAFE_INTEGER);

function checkStrictNumber(lexeme) {
  if (!STRICT_NUMBER_RE.test(lexeme)) {
    throw new FormatError('number is not a non-negative integer literal');
  }
  if (BigInt(lexeme) > MAX_SAFE_INTEGER_WIRE) {
    throw new FormatError('number exceeds 2^53-1');
  }
}

// decodeJSONString decodes a JSON string literal's escapes (raw is the text
// between the quotes) the same way JSON.parse would, so two differently
// escaped spellings of the same key compare equal: the duplicate-key walk
// below must not be fooled by, say, "manifest" and "ma" + "n" + "ifest"
// (the second spelled with a unicode escape) looking different in the raw
// bytes but decoding to the same key.
function decodeJSONString(raw) {
  try {
    return JSON.parse(`"${raw}"`);
  } catch {
    throw new FormatError('bad string escape');
  }
}

// checkNoDuplicateKeys walks text character by character, tracking just
// enough JSON structure (object/array nesting, and whether the next token in
// an object is a key or a value) to fail if any JSON object, at any depth,
// repeats a key — the one thing JSON.parse resolves silently instead of
// rejecting — or if any JSON number isn't a non-negative integer lexeme at
// most 2^53-1 (see checkStrictNumber). It does not otherwise validate JSON
// grammar; JSON.parse does that afterward. Mirrors checkNoDuplicateKeys in
// internal/e2e/envelope.go, adapted from Go's token-based walk to a
// hand-rolled one, since JavaScript has no streaming JSON tokenizer.
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
        const s = decodeJSONString(text.slice(i + 1, j));
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
    // valid; this pass only needs to know a value went by, except for a
    // number, whose lexeme must also pass the wire format's own stricter
    // rule (see checkStrictNumber).
    const start = i;
    while (i < n && !',}] \t\n\r:'.includes(text[i])) i++;
    if (i === start) throw new FormatError(`unexpected character ${JSON.stringify(c)}`);
    if (c === '-' || (c >= '0' && c <= '9')) checkStrictNumber(text.slice(start, i));
    afterValue();
  }
}

// fingerprint is a SHA-256 hash over a user's public keys, for comparing
// aloud in short groups.
export async function fingerprint(x25519Pub, ed25519Pub) {
  const digest = await subtle.digest('SHA-256', enc(LABELS.fingerprint, x25519Pub, ed25519Pub));
  return new Uint8Array(digest);
}

// bodyHash returns the lowercase hex SHA-256 of a signed body, the form the
// spec's prev, transfer, and manifest fields take.
export async function bodyHash(body) {
  return toHex(new Uint8Array(await subtle.digest('SHA-256', body)));
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

const EXCLUDED_SCHEMA = {
  user: field('string'),
  fp: field('string'),
  email: field('string'),
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
    seq: field('number'),
    owner: field('string'),
    ownerFp: field('string'),
    akCommit: field('string'),
    members: field('array', { item: MEMBER_SCHEMA }),
    excluded: field('array', { item: EXCLUDED_SCHEMA }),
    team: field('string'),
    public: field('boolean'),
    publicWrites: field('boolean'),
    prev: field('string'),
    transfer: field('string'),
    handover: field('string'),
  },
  transfer: {
    v: field('number'),
    artifact: field('string'),
    from: field('string'),
    to: field('string'),
    toFp: field('string'),
    prev: field('string'),
  },
  approval: {
    v: field('number'),
    artifact: field('string'),
    epoch: field('number'),
    user: field('string'),
    fp: field('string'),
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
    successorFp: field('string'),
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
      return value.map((item) => {
        if (typeof item !== 'object' || item === null || Array.isArray(item)) {
          throw new FormatError('expected an object');
        }
        return decodeObject(item, f.item);
      });
    default:
      throw new TypeError(`unknown field type ${f.type}`);
  }
}

// decodeObject builds a plain object with exactly schema's fields, each
// looked up case-insensitively in obj (preferring an exact match) or given
// its zero value when absent. A field marked omitEmpty (used only by
// ENVELOPE_SCHEMA's newSig, matching Go's envelopeJSON) is left out of the
// result entirely when its decoded value is the zero value, mirroring Go's
// `json:",omitempty"`, which drops a zero value on marshal. An absent field
// therefore round-trips; one present with the zero value explicitly (such
// as "newSig":"") does not, because the original still has it, so
// decodeStrict refuses it — as Go's DecodeStrict does, by the same
// comparison (see the newSig-empty envelope vector).
function decodeObject(obj, schema) {
  const out = {};
  for (const [name, f] of Object.entries(schema)) {
    const key = findKey(obj, name);
    const value = key === null ? zeroValue(f) : decodeValue(obj[key], f);
    if (f.omitEmpty && deepEqual(value, zeroValue(f))) continue;
    out[name] = value;
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
  const text = decodeTextStrict(bytes);
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

// ENVELOPE_SCHEMA is the raw envelope wrapper's own shape:
// {body,sig,signer[,newSig]}. newSig is omitEmpty, matching Go's
// envelopeJSON struct tag, since it's only present on a rotation envelope;
// it may be absent but never present and empty.
const ENVELOPE_SCHEMA = {
  body: field('string'),
  sig: field('string'),
  signer: field('string'),
  newSig: field('string', { omitEmpty: true }),
};

// decodeEnvelope strictly decodes a raw envelope's JSON bytes or text:
// {body,sig,signer[,newSig]}, nothing else, no duplicate keys, no case
// variants, and no trailing data — mirroring Go's
// Envelope.UnmarshalJSON/DecodeStrict (see TestOpenEnvelopeJSONItselfIsStrict
// in internal/e2e/envelope_test.go for the cases this refuses). The result
// is the same {body,sig,signer[,newSig]} b64-string shape openEnvelope and
// openRotation already accept; body/sig/newSig are also checked for valid
// base64url here, so a malformed one is caught at this point rather than
// later inside verify.
export function decodeEnvelope(bytesOrText) {
  const env = decodeStrict(bytesOrText, ENVELOPE_SCHEMA);
  unb64(env.body);
  unb64(env.sig);
  if (env.newSig) unb64(env.newSig);
  return env;
}

// openEnvelope and openRotation verify a signature and decode a body; that
// is all they do. Neither binds signer to pub, binds a membership record's
// owner to the signer, binds a rotation's user/old to the key being rotated
// away from, or enforces a monotonic seq. The caller must do all of that —
// signer is untrusted wire data, never a key lookup by itself — and must run
// checkPublicKeys/CheckPublicKeys on any wrap recipient before trusting it.
// openRotation itself runs checkPublicKeys on the new key pair (FormatError).

// openEnvelope verifies env's signature against pub for purpose, strictly
// decodes its body against BODY_SCHEMAS[purpose], and requires the body's
// "v" field to be 1. It refuses purpose 'rotation' with FormatError: a
// rotation also needs newSig, which only openRotation checks.
export async function openEnvelope(env, pub, purpose) {
  if (purpose === 'rotation') throw new FormatError('open a rotation envelope with openRotation');
  return openEnvelopeBody(env, pub, purpose);
}

async function openEnvelopeBody(env, pub, purpose) {
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
  const body = await openEnvelopeBody(env, oldPub, 'rotation');
  if (!env.newSig) throw new FormatError('rotation envelope missing newSig');
  const newX25519 = unb64(body.new.x25519);
  const newPub = unb64(body.new.ed25519);
  await checkPublicKeys(newX25519, newPub);
  const newSig = unb64(env.newSig);
  const bodyBytes = unb64(env.body);
  if (!(await verify(newPub, 'rotation', bodyBytes, newSig))) throw new DecryptError('bad newSig');
  return body;
}

// compareUtf8 orders two strings by their UTF-8 bytes, as Go compares
// strings. JavaScript's < compares UTF-16 code units instead, which puts a
// character above U+FFFF before one in U+E000 to U+FFFF.
function compareUtf8(a, b) {
  const x = textEncoder.encode(a);
  const y = textEncoder.encode(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    if (x[i] !== y[i]) return x[i] - y[i];
  }
  return x.length - y.length;
}

function hasOwn(obj, key) {
  return obj != null && Object.prototype.hasOwnProperty.call(obj, key);
}

// ownerKeys keeps the Ed25519 key of each pair that hashes to its
// fingerprint, and drops the rest.
async function ownerKeys(pairs) {
  const keys = new Map();
  for (const [fp, kp] of Object.entries(pairs ?? {})) {
    try {
      const x = unb64(kp.x25519);
      const ed = unb64(kp.ed25519);
      if (toHex(await fingerprint(x, ed)) === fp) keys.set(fp, ed);
    } catch {
      // A pair that does not decode cannot hash to its fingerprint.
    }
  }
  return keys;
}

// openRecord verifies one record under the key its ownerFp names, and
// checks the fields that do not depend on the record before it. The body is
// decoded strictly before the signature is checked, only to read ownerFp;
// openEnvelope then decodes the same bytes the same way, so the ownerFp it
// returns is the one whose key verified the record. Mirrors openRecord in
// internal/e2e/chain.go.
async function openRecord(env, artifact, owners) {
  const pre = decodeStrict(unb64(env.body), BODY_SCHEMAS.membership);
  if (!owners.has(pre.ownerFp)) throw new ChainError(`no owner key for ownerFp ${pre.ownerFp}`);
  const b = await openEnvelope(env, owners.get(pre.ownerFp), 'membership');
  if (b.artifact !== artifact) throw new ChainError(`record for artifact ${b.artifact}`);
  if (b.members === null || b.excluded === null) {
    throw new ChainError('members and excluded must be arrays');
  }
  if (b.team !== 'none' && b.team !== 'viewer' && b.team !== 'editor') throw new ChainError(`team ${b.team}`);
  if (!isHex64(b.akCommit)) throw new ChainError('akCommit is not 64 lowercase hex digits');
  for (let i = 1; i < b.members.length; i++) {
    if (compareUtf8(b.members[i - 1].user, b.members[i].user) >= 0) {
      throw new ChainError('members not sorted by user ID, or duplicated');
    }
  }
  for (let i = 1; i < b.excluded.length; i++) {
    if (compareUtf8(b.excluded[i - 1].user, b.excluded[i].user) >= 0) {
      throw new ChainError('excluded not sorted by user ID, or duplicated');
    }
  }
  for (const m of b.members) {
    if (m.user === b.owner) throw new ChainError('the owner is listed as a member');
    if (m.role !== 'viewer' && m.role !== 'editor') throw new ChainError(`member ${m.user} has role ${m.role}`);
    if (!isHex64(m.fp)) throw new ChainError(`member ${m.user} fp is not 64 lowercase hex digits`);
    for (const e of b.excluded) {
      if (e.user === m.user || e.fp === m.fp) {
        throw new ChainError(`excluded entry ${e.user} matches member ${m.user}`);
      }
    }
  }
  for (const e of b.excluded) {
    if (e.user === b.owner) throw new ChainError('the owner is excluded');
  }
  return b;
}

// isHex64 reports whether s is 64 lowercase hex digits: a SHA-256 hash or
// fingerprint in its one canonical form.
function isHex64(s) {
  return s.length === 64 && isLowerHex(s);
}

function checkFirstRecord(b, anchor, linked) {
  if (b.seq !== 1) throw new ChainError(`first record has seq ${b.seq}`);
  if (b.prev !== '') throw new ChainError('first record has a prev');
  if (b.epoch !== 1) throw new ChainError(`first record has epoch ${b.epoch}`);
  if (b.transfer !== '' || b.handover !== '') {
    throw new ChainError('first record sets transfer or handover');
  }
  if (!linked(b.owner, anchor, b.ownerFp)) {
    throw new ChainError("first record's ownerFp does not reach the anchor");
  }
}

// checkNextRecord checks b against prev, the record before it, whose body
// bytes hash to prevHash, and notes an administrator's handover in
// handovers.
async function checkNextRecord(input, owners, linked, prev, prevHash, b, handovers) {
  if (b.seq !== prev.seq + 1) throw new ChainError(`seq ${b.seq} follows ${prev.seq}`);
  if (b.prev !== prevHash) throw new ChainError("prev is not the previous record's hash");
  if (b.epoch === prev.epoch) {
    if (b.akCommit !== prev.akCommit) throw new ChainError(`akCommit changed within epoch ${b.epoch}`);
  } else if (b.epoch === prev.epoch + 1) {
    if (b.akCommit === prev.akCommit) throw new ChainError(`epoch ${b.epoch} keeps the previous akCommit`);
  } else {
    throw new ChainError(`epoch ${b.epoch} follows ${prev.epoch}`);
  }

  if (b.owner === prev.owner) {
    if (b.transfer !== '' || b.handover !== '') {
      throw new ChainError('transfer or handover set without a change of owner');
    }
    if (!linked(b.owner, prev.ownerFp, b.ownerFp)) {
      throw new ChainError("ownerFp does not follow from the previous record's");
    }
    return;
  }

  if ((b.transfer === '') === (b.handover === '')) {
    throw new ChainError('a change of owner sets exactly one of transfer and handover');
  }
  if (b.handover !== '' && b.handover !== 'admin') throw new ChainError(`handover ${b.handover}`);
  const listed = prev.members.find((m) => m.user === b.owner);
  if (!listed) {
    if (b.handover !== '') {
      throw new ChainError(
        'a handover to a user the previous record does not list needs a successor record, which this client does not check yet',
      );
    }
    throw new ChainError('the new owner is not listed in the previous record');
  }
  if (listed.role !== 'editor') throw new ChainError(`the new owner is listed as ${listed.role}, not editor`);
  if (!linked(b.owner, listed.fp, b.ownerFp)) {
    throw new ChainError('ownerFp does not follow from the fp the previous record lists for the new owner');
  }
  if (b.handover !== '') {
    handovers.push(b.seq);
    return;
  }

  const offer = hasOwn(input.offers, b.transfer) ? input.offers[b.transfer] : null;
  if (!offer || (await bodyHash(unb64(offer.body))) !== b.transfer) {
    throw new ChainError(`no offer hashes to transfer ${b.transfer}`);
  }
  const t = await openEnvelope(offer, owners.get(prev.ownerFp), 'transfer');
  if (t.artifact !== input.artifact) throw new ChainError(`offer for artifact ${t.artifact}`);
  if (t.from !== prev.owner) throw new ChainError(`offer from ${t.from}, not the previous owner`);
  if (t.to !== b.owner) throw new ChainError(`offer to ${t.to}, not the new owner`);
  if (t.toFp !== listed.fp) throw new ChainError("offer's toFp is not the fp listed for the new owner");
  if (t.prev !== prevHash) throw new ChainError("offer's prev is not the previous record's hash");
}

// verifyChain checks every record of a membership chain, as the client
// rules in design/e2e-api.md ("Membership records" and "Ownership
// transfer") require, and refuses the whole chain when any check fails.
// input is {artifact, records, owners, offers, anchor, currentOwnerFp, pin,
// linked}: records, owners, and offers as GET /api/artifacts/{id}/membership
// serves them; anchor the fingerprint the first record's ownerFp must
// reach; currentOwnerFp, when non-empty, the latest record's ownerFp; pin
// the keyring's {epoch, seq, head}, or null on first sight; and linked an
// optional (user, fromFp, toFp) => boolean rotation chain hook, which
// defaults to fromFp === toFp. Returns {bodies, latest, head, handovers}.
// A record that fails to parse throws FormatError, and one whose signature
// fails DecryptError; every other broken rule throws ChainError,
// RollbackError, ForkError, or StaleEpochError. Mirrors VerifyChain in
// internal/e2e/chain.go.
export async function verifyChain(input) {
  const records = input.records ?? [];
  if (records.length === 0) throw new ChainError('no records');
  const linked = input.linked ?? ((_user, fromFp, toFp) => fromFp === toFp);
  const owners = await ownerKeys(input.owners);
  const bodies = [];
  const handovers = [];
  let prevHash = '';
  for (let i = 0; i < records.length; i++) {
    const b = await openRecord(records[i], input.artifact, owners);
    if (i === 0) {
      checkFirstRecord(b, input.anchor, linked);
    } else {
      await checkNextRecord(input, owners, linked, bodies[i - 1], prevHash, b, handovers);
    }
    bodies.push(b);
    prevHash = await bodyHash(unb64(records[i].body));
  }
  const latest = bodies[bodies.length - 1];
  if (input.currentOwnerFp && latest.ownerFp !== input.currentOwnerFp) {
    throw new ChainError("the latest record is not signed by the current owner's key");
  }
  const pin = input.pin;
  if (pin) {
    if (!Number.isInteger(pin.epoch) || pin.epoch < 1) throw new FormatError(`pinned epoch ${pin.epoch}`);
    if (!Number.isInteger(pin.seq) || pin.seq < 1) throw new FormatError(`pinned seq ${pin.seq}`);
    if (typeof pin.head !== 'string') throw new FormatError('pinned head is not a string');
    if (records.length < pin.seq) throw new RollbackError(`${records.length} records, pinned seq ${pin.seq}`);
    if ((await bodyHash(unb64(records[pin.seq - 1].body))) !== pin.head) {
      throw new ForkError(`record ${pin.seq}`);
    }
    if (latest.epoch < pin.epoch) throw new StaleEpochError(`latest epoch ${latest.epoch}, pinned ${pin.epoch}`);
  }
  return { bodies, latest, head: prevHash, handovers };
}

// checkEncryptEpoch refuses to encrypt under an epoch older than the
// highest one the keyring pins. A null pin allows any epoch.
export function checkEncryptEpoch(pin, epoch) {
  if (pin && epoch < pin.epoch) throw new StaleEpochError(`epoch ${epoch}, pinned ${pin.epoch}`);
}

// constantTimeEqual compares two byte arrays without stopping at the first
// difference, as Go's subtle.ConstantTimeCompare does.
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// checkNewAk refuses a new epoch's AK that equals the AK of any earlier
// epoch. The akCommit check cannot show this, because the commitment
// includes the epoch. Both are raw bytes, not CryptoKeys.
export function checkNewAk(ak, earlier) {
  if (!(ak instanceof Uint8Array)) throw new FormatError('ak must be raw bytes');
  checkKeyLen(ak);
  for (const e of earlier) {
    if (constantTimeEqual(ak, e)) throw new ReusedAkError('AK reused from an earlier epoch');
  }
}
