// Tests for e2e.mjs against internal/e2e/testdata/vectors.json: every
// positive entry in every section, and every negative case. Run with:
// node --test internal/server/web/*_test.mjs
//
// Every negative entry carries a `why` and zero or more overrides — input,
// ctx, key, fields, purpose, pub, params, newSig, transform — each replacing
// one field of the positive entry; see testdata/README.md for the full
// schema and which primitives read which override. No negative case here
// relies on logic of its own: applyOverrides merges generically, and each
// section's loop below reads only the fields that primitive's operation
// takes.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as e2e from './e2e.mjs';
import { loadArgon2 } from './argon2.mjs';
import './vendor/wasm_exec.js'; // Side effect: defines globalThis.Go.

const { fromHex: hex, toHex } = e2e;

const vf = JSON.parse(readFileSync(new URL('../../e2e/testdata/vectors.json', import.meta.url)));

const wasmBytes = readFileSync(new URL('./vendor/argon2.wasm', import.meta.url));
const argon2id = await loadArgon2({ wasmBytes, goClass: globalThis.Go });

// applyOverrides merges a negative entry's overrides onto the positive
// entry's own inputs. ctx is merged shallowly; every other field, when
// present, replaces outright.
function applyOverrides(base, neg) {
  const out = { ...base };
  for (const k of ['input', 'key', 'fields', 'purpose', 'pub']) {
    if (k in neg) out[k] = neg[k];
  }
  if ('ctx' in neg) out.ctx = { ...base.ctx, ...neg.ctx };
  return out;
}

async function assertThrows(fn, errorClass) {
  await assert.rejects(fn, errorClass ?? Error);
}

// testKeyBytes returns a deterministic, distinct 32-byte key for test n, so
// tests don't need real randomness for inputs whose exact value doesn't
// matter.
function testKeyBytes(n) {
  return new Uint8Array(32).fill(n);
}

test('enc', () => {
  for (const v of vf.enc) {
    const fields = (v.fields ?? []).map(hex);
    assert.equal(toHex(e2e.enc(...fields)), v.want, v.name);
  }
});

test('derive', async () => {
  for (const v of vf.derive) {
    const fields = (v.fields ?? []).map(hex);
    const got = await e2e.derive(hex(v.ikm), hex(v.salt), v.label, ...fields);
    assert.equal(toHex(got), v.want, v.label);
  }
});

test('argon2', async () => {
  for (const v of vf.argon2) {
    const params = {
      alg: v.params.alg,
      m: v.params.m,
      t: v.params.t,
      p: v.params.p,
      salt: hex(v.params.salt),
    };
    assert.equal(toHex(await e2e.argonSalt(v.email, params.salt)), v.argonSalt, `${v.name}: argonSalt`);
    const stretched = await e2e.stretch(hex(v.password), v.email, params, argon2id);
    assert.equal(toHex(stretched), v.stretched, `${v.name}: stretched`);
    const { authKey, kek } = await e2e.passwordKeys(stretched);
    assert.equal(toHex(authKey), v.authKey, `${v.name}: authKey`);
    assert.equal(toHex(kek), v.kek, `${v.name}: kek`);

    // Every negative carries its own complete, standalone params object
    // (its own salt too), not a partial override merged over the positive.
    for (const neg of v.negative) {
      assert.ok(neg.params, `${v.name}: ${neg.why}: missing params`);
      const np = {
        alg: neg.params.alg, m: neg.params.m, t: neg.params.t, p: neg.params.p,
        salt: hex(neg.params.salt),
      };
      assert.throws(() => e2e.checkFloor(np), e2e.FloorError, `${v.name}: ${neg.why}`);
    }
  }
});

test('akCommit', async () => {
  for (const v of vf.akCommit) {
    const got = await e2e.akCommit(hex(v.ak), v.artifact, v.epoch);
    assert.equal(got, v.want, v.name);
  }
});

test('recoveryCode', async () => {
  for (const v of vf.recoveryCode) {
    const code = hex(v.code);
    assert.equal(e2e.formatRecoveryCode(code), v.display, v.name);
    assert.equal(toHex(e2e.parseRecoveryCode(v.display)), v.code, v.name);
    for (const variant of v.variants) {
      assert.equal(toHex(e2e.parseRecoveryCode(variant)), v.code, `${v.name}: variant ${variant}`);
    }
    assert.equal(toHex(await e2e.recoveryKek(code)), v.kek, `${v.name}: kek`);
    // Go's Input field is plain string, so an omitted override ("empty")
    // decodes to "", not absence — there's no "positive ciphertext" to fall
    // back to for a parse-only operation like this one.
    for (const neg of v.negative) {
      assert.throws(
        () => e2e.parseRecoveryCode(neg.input ?? ''),
        e2e.FormatError,
        `${v.name}: ${neg.why}`,
      );
    }
  }
});

// The Go side checks the same vector: fingerprint bytes 0..31.
test('successorCode', () => {
  const fp = Uint8Array.from({ length: 32 }, (_, i) => i);
  assert.equal(e2e.successorCode(fp), 'AAAQ-EAYE-AUDA-OCAJ');
  for (const s of ['aaaq-eaye-auda-ocaj', 'AAAQ EAYE AUDA OCAJ', 'AAAQEAYEAUDAOCAJ', ' aaaq-EAYE auda-OCAJ ']) {
    assert.equal(toHex(e2e.parseSuccessorCode(s)), toHex(fp.slice(0, 10)), s);
  }
  for (const s of [
    '',
    'AAAQ-EAYE-AUDA-OCA', // 15 characters
    'AAAQ-EAYE-AUDA-OCAJA', // 17 characters
    'AAAQ-EAYE-AUDA-OCA1', // outside the alphabet
    'AAAQ-EAYE-AUDA-OCA!', // outside the character set
    'AAAQ_EAYE_AUDA_OCAJ', // wrong separator
    'ſAAQ-EAYE-AUDA-OCAJ', // would fold onto S under some locales
    'AAAQ-EAYE-AUDA-OCAJ\x00', // control character
    'AAAQ-EAYE-AUDA-OCAJ-AAAA', // a recovery-code-sized tail
  ]) {
    assert.throws(() => e2e.parseSuccessorCode(s), e2e.FormatError, JSON.stringify(s));
  }
});

test('refusal body schema', () => {
  const body = { v: 1, user: 'u1', requestedAt: '2026-10-05T12:00:00Z' };
  const bytes = new TextEncoder().encode(JSON.stringify(body));
  assert.deepEqual(e2e.decodeStrict(bytes, e2e.BODY_SCHEMAS.refusal), body);
  const extra = new TextEncoder().encode(JSON.stringify({ ...body, seq: 1 }));
  assert.throws(() => e2e.decodeStrict(extra, e2e.BODY_SCHEMAS.refusal), e2e.FormatError);
});

test('apiKey', async () => {
  for (const v of vf.apiKey) {
    const parsed = e2e.parseApiKey(v.full);
    assert.equal(parsed.keyId, v.keyId, v.name);
    assert.equal(parsed.authSecret, v.authSecret, v.name);
    assert.equal(toHex(parsed.keySecret), v.keySecret, v.name);
    assert.equal(
      toHex(await e2e.apiKeyKek(parsed.keySecret, parsed.keyId)),
      v.kek,
      `${v.name}: kek`,
    );
    assert.equal(await e2e.apiKeyAuthHash(parsed.authSecret), v.authHash, `${v.name}: authHash`);
    // Same reasoning as recoveryCode: an omitted override is Go's zero
    // value "", not "no override".
    for (const neg of v.negative) {
      assert.throws(
        () => e2e.parseApiKey(neg.input ?? ''),
        e2e.FormatError,
        `${v.name}: ${neg.why}`,
      );
    }
  }
});

test('apiKey: rejects each part with the wrong individual length', () => {
  const full = vf.apiKey[0].full;
  const [, keyId, authSecret, keySecret] = full.match(/^cairn_([0-9a-f]+)_([0-9a-f]+)_([0-9a-f]+)$/);
  const cases = [
    `cairn_${keyId.slice(1)}_${authSecret}_${keySecret}`, // keyId one hex digit short
    `cairn_${keyId}a_${authSecret}_${keySecret}`, // keyId one hex digit long
    `cairn_${keyId}_${authSecret.slice(1)}_${keySecret}`, // authSecret one short
    `cairn_${keyId}_${authSecret}a_${keySecret}`, // authSecret one long
    `cairn_${keyId}_${authSecret}_${keySecret.slice(1)}`, // keySecret one short
    `cairn_${keyId}_${authSecret}_${keySecret}a`, // keySecret one long
  ];
  for (const c of cases) {
    assert.throws(() => e2e.parseApiKey(c), e2e.FormatError, c);
  }
});

test('seal', async () => {
  for (const v of vf.seal) {
    const key = hex(v.key);
    const fields = v.fields.map(hex);
    const sealed = hex(v.want);
    const pt = await e2e.open(key, fields, sealed);
    assert.equal(toHex(pt), v.pt ?? '', v.name);

    for (const neg of v.negative) {
      const n = applyOverrides({ input: v.want, key: v.key, fields: v.fields }, neg);
      const useKey = hex(n.key);
      const useFields = n.fields.map(hex);
      await assertThrows(() => e2e.open(useKey, useFields, hex(n.input)), e2e.DecryptError);
    }
  }
});

// A wrong-length key (16 and 24 bytes, AES-128 and AES-192 sizes WebCrypto
// would otherwise happily accept) must be refused by every function this
// module guards with checkKeyLen, mirroring internal/e2e's
// TestNewGCMRejectsWrongKeyLength, TestAKCommitRejectsWrongKeyLength, the
// derive loop in seal_test.go, TestSealBlobRejectsWrongKeyLength,
// TestOpenBlobRejectsWrongKeyLength, and TestWrapRejectsWrongKeyLength.
test('wrong-length keys are rejected everywhere checkKeyLen guards', async () => {
  const sealed = hex(vf.seal[0].want);
  const fields = vf.seal[0].fields.map(hex);
  const blob = hex(vf.blob[0].want);
  const ctx = vf.blob[0].ctx;
  const wrapCtx = wrapCtxFromVec(vf.wrap[0].ctx);

  for (const n of [16, 24]) {
    const badKey = new Uint8Array(n);
    await assertThrows(() => e2e.seal(badKey, fields, new Uint8Array(1)), e2e.FormatError);
    // open wraps every decrypt-path error, including a bad key length, into
    // DecryptError -- matching Go's Open, which returns ErrDecrypt here too.
    await assertThrows(() => e2e.open(badKey, fields, sealed), e2e.DecryptError);
    await assertThrows(() => e2e.sealBlob(badKey, ctx, new Uint8Array(1)), e2e.FormatError);
    await assertThrows(() => e2e.openBlob(badKey, ctx, blob), e2e.FormatError);
    await assertThrows(() => e2e.wrap(wrapCtx, badKey), e2e.FormatError);
    await assertThrows(() => e2e.mkSealKey(badKey), e2e.FormatError);
    await assertThrows(() => e2e.indexKey(badKey), e2e.FormatError);
    await assertThrows(() => e2e.ekSealKey(badKey), e2e.FormatError);
    await assertThrows(() => e2e.linkToken(badKey, 'artifact-1', 3), e2e.FormatError);
    await assertThrows(() => e2e.fileKey(badKey, 'artifact-1', 3), e2e.FormatError);
    await assertThrows(() => e2e.akCommit(badKey, 'artifact-1', 3), e2e.FormatError);
  }
});

test('open rejects a truncated sealed value', async () => {
  const sealed = hex(vf.seal[0].want);
  const key = hex(vf.seal[0].key);
  const fields = vf.seal[0].fields.map(hex);
  await assertThrows(() => e2e.open(key, fields, sealed.slice(0, 5)), e2e.DecryptError);
});

test('open rejects a wrong-version sealed value', async () => {
  const sealed = hex(vf.seal[0].want).slice();
  sealed[0] = 0x02;
  const key = hex(vf.seal[0].key);
  const fields = vf.seal[0].fields.map(hex);
  await assertThrows(() => e2e.open(key, fields, sealed), e2e.DecryptError);
});

// applyBlobTransform implements the blob negative `transform` ops documented
// in testdata/README.md, mutating a valid blob's bytes without ever
// producing one openBlob would accept. Go's `chunk` and `offset` fields are
// plain ints with `omitempty`, so a genuine 0 is indistinguishable from
// absent in the JSON; both default to 0 here to match.
function applyBlobTransform(blob, transform, headerSize, fullChunkSize) {
  switch (transform.op) {
    case 'truncate':
      return blob.slice(0, headerSize + (transform.chunks ?? 0) * fullChunkSize);
    case 'drop': {
      const start = headerSize + (transform.chunk ?? 0) * fullChunkSize;
      return concatSlices([blob.slice(0, start), blob.slice(start + fullChunkSize)]);
    }
    case 'swap': {
      const [i, j] = transform.chunks;
      const chunkAt = (k) => blob.slice(headerSize + k * fullChunkSize, headerSize + (k + 1) * fullChunkSize);
      const lo = Math.min(i, j);
      const hi = Math.max(i, j);
      return concatSlices([
        blob.slice(0, headerSize + lo * fullChunkSize),
        chunkAt(hi),
        blob.slice(headerSize + (lo + 1) * fullChunkSize, headerSize + hi * fullChunkSize),
        chunkAt(lo),
        blob.slice(headerSize + (hi + 1) * fullChunkSize),
      ]);
    }
    case 'append':
      return concatSlices([blob, hex(transform.bytes)]);
    case 'flip': {
      const out = blob.slice();
      out[transform.offset ?? 0] ^= 0x01;
      return out;
    }
    default:
      throw new Error(`unknown blob transform op: ${transform.op}`);
  }
}

function concatSlices(arrays) {
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

test('blob', async () => {
  const headerSize = 37;
  const fullChunkSize = 65536 + 16;
  for (const v of vf.blob) {
    const ak = hex(v.ak);
    const blob = hex(v.want);
    const pt = await e2e.openBlob(ak, v.ctx, blob);
    if (v.ptRule) {
      assert.equal(pt.length, v.ptRule.len, v.name);
    } else {
      assert.equal(toHex(pt), v.pt ?? '', v.name);
    }

    for (const neg of v.negative ?? []) {
      const n = applyOverrides({ ctx: v.ctx }, neg);
      let input = blob;
      if (neg.transform) input = applyBlobTransform(blob, neg.transform, headerSize, fullChunkSize);
      else if (neg.input !== undefined) input = hex(neg.input);
      await assertThrows(() => e2e.openBlob(ak, n.ctx, input));
    }
  }
});

function wrapCtxFromVec(c) {
  return { purpose: c.purpose, artifact: c.artifact, epoch: c.epoch, recipientId: c.recipientId, recipientPub: hex(c.recipientPub) };
}

test('wrap', async () => {
  for (const v of vf.wrap) {
    const ctx = wrapCtxFromVec(v.ctx);
    const priv = hex(v.recipientPriv);
    const got = await e2e.unwrap(priv, ctx, hex(v.want));
    assert.equal(toHex(got), v.key, v.name);

    for (const neg of v.negative) {
      const n = applyOverrides({ ctx: v.ctx, key: v.recipientPriv }, neg);
      const useCtx = wrapCtxFromVec(n.ctx);
      const usePriv = hex(n.key);
      const input = n.input !== undefined ? hex(n.input) : hex(v.want);
      await assertThrows(() => e2e.unwrap(usePriv, useCtx, input), e2e.DecryptError);
    }
  }
});

test('unwrap rejects a wrong-length wrapped value', async () => {
  const v = vf.wrap[0];
  const ctx = wrapCtxFromVec(v.ctx);
  const priv = hex(v.recipientPriv);
  const wrapped = hex(v.want);
  await assertThrows(() => e2e.unwrap(priv, ctx, wrapped.slice(0, -1)), e2e.DecryptError);
  await assertThrows(
    () => e2e.unwrap(priv, ctx, new Uint8Array([...wrapped, 0])),
    e2e.DecryptError,
  );
});

test('unwrap rejects a wrong-version wrapped value', async () => {
  const v = vf.wrap[0];
  const ctx = wrapCtxFromVec(v.ctx);
  const priv = hex(v.recipientPriv);
  const wrapped = hex(v.want).slice();
  wrapped[0] = 0x02;
  await assertThrows(() => e2e.unwrap(priv, ctx, wrapped), e2e.DecryptError);
});

test('unwrap rejects a wrong-length private key', async () => {
  const v = vf.wrap[0];
  const ctx = wrapCtxFromVec(v.ctx);
  const wrapped = hex(v.want);
  for (const n of [16, 24, 31, 33]) {
    await assertThrows(() => e2e.unwrap(new Uint8Array(n), ctx, wrapped), e2e.DecryptError);
  }
});

// Isolates the recipientPub check: the correct private key, but a ctx whose
// recipientPub has been overridden to something else, must still fail —
// proving the comparison actually runs rather than trivially passing because
// priv and ctx.recipientPub usually agree.
test('unwrap rejects the correct private key with recipientPub overridden', async () => {
  const v = vf.wrap[0];
  const ctx = { ...wrapCtxFromVec(v.ctx), recipientPub: testKeyBytes(9) };
  const priv = hex(v.recipientPriv);
  const wrapped = hex(v.want);
  await assertThrows(() => e2e.unwrap(priv, ctx, wrapped), e2e.DecryptError);
});

// A wrongly typed argument is a caller bug, so it's a FormatError -- never a
// TypeError, and never a DecryptError that reads as tampering. Go's []byte
// parameters can't be given any of these. A wrong-length Uint8Array stays a
// DecryptError, as in Go (see the tests above).
test('unwrap and open refuse wrongly typed arguments as FormatError', async () => {
  const v = vf.wrap[0];
  const ctx = wrapCtxFromVec(v.ctx);
  const priv = hex(v.recipientPriv);
  const wrapped = hex(v.want);
  const keyObj = await e2e.importX25519PrivateKey(priv);
  assert.equal(toHex(await e2e.unwrap(keyObj, ctx, wrapped)), v.key); // positive control
  const badKeyObjs = [
    keyObj.privateKey, null, undefined, {}, { privateKey: keyObj.privateKey },
    { privateKey: keyObj.privateKey, publicKey: e2e.b64(keyObj.publicKey) },
    { privateKey: priv, publicKey: keyObj.publicKey },
  ];
  for (const bad of badKeyObjs) {
    await assertThrows(() => e2e.unwrap(bad, ctx, wrapped), e2e.FormatError);
  }
  for (const pub of [v.ctx.recipientPub, e2e.b64(ctx.recipientPub), Array.from(ctx.recipientPub), null, undefined]) {
    await assertThrows(() => e2e.unwrap(priv, { ...ctx, recipientPub: pub }, wrapped), e2e.FormatError);
    await assertThrows(() => e2e.unwrap(keyObj, { ...ctx, recipientPub: pub }, wrapped), e2e.FormatError);
    await assertThrows(() => e2e.wrap({ ...ctx, recipientPub: pub }, testKeyBytes(4)), e2e.FormatError);
  }
  const s = vf.seal[0];
  assert.equal(toHex(await e2e.open(hex(s.key), s.fields.map(hex), hex(s.want))), s.pt); // positive control
  for (const sealed of [s.want, Array.from(hex(s.want)), hex(s.want).buffer, null, undefined]) {
    await assertThrows(() => e2e.open(hex(s.key), s.fields.map(hex), sealed), e2e.FormatError);
  }
});

// checkEpoch: every function taking an epoch refuses anything but a safe
// non-negative integer, before it derives anything.
test('epoch must be a safe non-negative integer everywhere', async () => {
  const ak = testKeyBytes(1);
  const key = testKeyBytes(2);
  const recipient = await e2e.generateX25519();
  const ctx = { purpose: 'ak', artifact: 'artifact-1', epoch: 0, recipientId: 'user-1', recipientPub: recipient.pub };
  // positive controls: epoch 0 and 2^53-1 are accepted.
  for (const epoch of [0, Number.MAX_SAFE_INTEGER]) {
    await e2e.linkToken(ak, 'artifact-1', epoch);
    await e2e.fileKey(ak, 'artifact-1', epoch);
    await e2e.akCommit(ak, 'artifact-1', epoch);
    const w = await e2e.wrap({ ...ctx, epoch }, key);
    assert.equal(toHex(await e2e.unwrap(recipient.priv, { ...ctx, epoch }, w)), toHex(key));
  }
  const good = await e2e.wrap(ctx, key);
  for (const epoch of [-1, 1.5, 2 ** 53, NaN, Infinity, '1', null, undefined, 1n]) {
    await assertThrows(() => e2e.linkToken(ak, 'artifact-1', epoch), e2e.FormatError);
    await assertThrows(() => e2e.fileKey(ak, 'artifact-1', epoch), e2e.FormatError);
    await assertThrows(() => e2e.akCommit(ak, 'artifact-1', epoch), e2e.FormatError);
    await assertThrows(() => e2e.wrap({ ...ctx, epoch }, key), e2e.FormatError);
    await assertThrows(() => e2e.unwrap(recipient.priv, { ...ctx, epoch }, good), e2e.FormatError);
  }
});

// Length guards on public keys, private keys and seeds: each refuses one
// byte short and one byte long.
test('length guards: X25519 and Ed25519 keys and seeds', async () => {
  const x = await e2e.generateX25519();
  const ed = await e2e.generateEd25519();
  const key = testKeyBytes(3);
  const ctx = { purpose: 'ak', artifact: 'artifact-1', epoch: 1, recipientId: 'user-1', recipientPub: x.pub };
  // positive controls
  await e2e.importX25519PrivateKey(x.priv);
  await e2e.wrap(ctx, key);
  await e2e.checkPublicKeys(x.pub, ed.pub);
  await e2e.importEd25519SigningKey(ed.seed);
  for (const n of [0, 31, 33]) {
    const b = new Uint8Array(n).fill(9);
    await assertThrows(() => e2e.importX25519PrivateKey(b), e2e.FormatError);
    await assertThrows(() => e2e.wrap({ ...ctx, recipientPub: b }, key), e2e.FormatError);
    await assertThrows(() => e2e.checkPublicKeys(b, ed.pub), e2e.FormatError);
    await assertThrows(() => e2e.checkPublicKeys(x.pub, b), e2e.FormatError);
    await assertThrows(() => e2e.importEd25519SigningKey(b), e2e.FormatError);
    await assertThrows(() => e2e.sign(b, 'reset', new Uint8Array(1)), e2e.FormatError);
  }
});

// non-extractable keys: the importers return CryptoKey objects that cannot
// be read back out to raw bytes, and every function that accepts one gives
// the identical result it would for the equivalent raw bytes.
test('non-extractable keys: importer outputs are non-extractable', async () => {
  const { seed } = await e2e.generateEd25519();
  const signingKey = await e2e.importEd25519SigningKey(seed);
  assert.equal(signingKey.extractable, false);

  const { priv } = await e2e.generateX25519();
  const { privateKey } = await e2e.importX25519PrivateKey(priv);
  assert.equal(privateKey.extractable, false);

  const mk = testKeyBytes(1);
  assert.equal((await e2e.mkSealCryptoKey(mk)).extractable, false);
  assert.equal((await e2e.ekSealCryptoKey(mk)).extractable, false);
  assert.equal((await e2e.indexCryptoKey(mk)).extractable, false);
  assert.equal((await e2e.fileCryptoKey(mk, 'artifact-1', 3)).extractable, false);
  assert.equal((await e2e.importHKDFKey(mk)).extractable, false);
});

test('non-extractable keys: sign with a CryptoKey matches sign with the seed', async () => {
  const { seed } = await e2e.generateEd25519();
  const signingKey = await e2e.importEd25519SigningKey(seed);
  const body = new TextEncoder().encode('body');
  const viaSeed = await e2e.sign(seed, 'manifest', body);
  const viaKey = await e2e.sign(signingKey, 'manifest', body);
  assert.equal(toHex(viaKey), toHex(viaSeed));
});

test('non-extractable keys: unwrap with a CryptoKey matches unwrap with raw bytes', async () => {
  const v = vf.wrap[0];
  const ctx = wrapCtxFromVec(v.ctx);
  const viaBytes = await e2e.unwrap(hex(v.recipientPriv), ctx, hex(v.want));
  const keyObj = await e2e.importX25519PrivateKey(hex(v.recipientPriv));
  const viaKey = await e2e.unwrap(keyObj, ctx, hex(v.want));
  assert.equal(toHex(viaKey), toHex(viaBytes));
  assert.equal(toHex(viaKey), v.key);
});

test('non-extractable keys: seal/open with mkSealCryptoKey matches raw mkSealKey', async () => {
  const mk = testKeyBytes(2);
  const fields = [new TextEncoder().encode('mk')];
  const pt = new TextEncoder().encode('thirty-two-byte-master-key-material');
  const rawKey = await e2e.mkSealKey(mk);
  const cryptoKey = await e2e.mkSealCryptoKey(mk);
  const sealedViaKey = await e2e.seal(cryptoKey, fields, pt);
  const openedViaRaw = await e2e.open(rawKey, fields, sealedViaKey);
  assert.equal(toHex(openedViaRaw), toHex(pt));
  const sealedViaRaw = await e2e.seal(rawKey, fields, pt);
  const openedViaKey = await e2e.open(cryptoKey, fields, sealedViaRaw);
  assert.equal(toHex(openedViaKey), toHex(pt));
});

// assertKekPurposes proves a KEK's 'seal' and 'open' CryptoKeys are the raw
// KEK, each limited to its one job. A KEK seals only the 32-byte MK, so
// 'seal' can only encrypt and 'open' can only unwrap through openKey: neither
// can decrypt, so neither can read a sealed value back into JS memory.
async function assertKekPurposes(sealKey, openWith, rawKey, label) {
  for (const [k, usages] of [[sealKey, ['encrypt']], [openWith, ['unwrapKey']]]) {
    assert.equal(k.extractable, false, label);
    assert.equal(k.algorithm.name, 'AES-GCM', label);
    assert.deepEqual([...k.usages].sort(), usages, label);
  }
  const fields = [new TextEncoder().encode(label)];
  const mk = testKeyBytes(6);
  assert.equal(toHex(await e2e.open(rawKey, fields, await e2e.seal(sealKey, fields, mk))), toHex(mk), label);
  const sealed = await e2e.seal(rawKey, fields, mk);
  const opened = await e2e.openKey(openWith, fields, sealed);
  assert.equal(toHex(await e2e.mkSealKey(opened)), toHex(await e2e.mkSealKey(mk)), label);
  await assertThrows(() => e2e.open(openWith, fields, sealed), e2e.DecryptError);
  await assertThrows(() => e2e.openKey(sealKey, fields, sealed), e2e.DecryptError);
  await assertThrows(() => e2e.open(sealKey, fields, sealed), e2e.DecryptError);
  // WebCrypto refuses the key for want of 'encrypt', before seal touches mk.
  await assertThrows(() => e2e.seal(openWith, fields, mk), { name: 'InvalidAccessError' });
}

test('non-extractable keys: KEK CryptoKey variants match the raw KEKs, one purpose each', async () => {
  const stretched = testKeyBytes(7);
  const raw = await e2e.passwordKeys(stretched);
  const forSeal = await e2e.passwordCryptoKeys(stretched, 'seal');
  const forOpen = await e2e.passwordCryptoKeys(stretched, 'open');
  assert.equal(toHex(forSeal.authKey), toHex(raw.authKey));
  assert.equal(toHex(forOpen.authKey), toHex(raw.authKey));
  await assertKekPurposes(forSeal.kek, forOpen.kek, raw.kek, 'kek');

  const code = e2e.newRecoveryCode().code;
  assert.equal(code.length, 16);
  await assertKekPurposes(
    await e2e.recoveryKekCryptoKey(code, 'seal'),
    await e2e.recoveryKekCryptoKey(code, 'open'),
    await e2e.recoveryKek(code),
    'recoveryKek',
  );

  const { keyId, keySecret } = e2e.newApiKey();
  await assertKekPurposes(
    await e2e.apiKeyKekCryptoKey(keySecret, keyId, 'seal'),
    await e2e.apiKeyKekCryptoKey(keySecret, keyId, 'open'),
    await e2e.apiKeyKek(keySecret, keyId),
    'apiKeyKek',
  );
});

// No KEK CryptoKey has a default purpose: leaving it out, or naming any
// other, is a FormatError rather than a key with every usage.
test('non-extractable keys: KEK CryptoKeys require a purpose', async () => {
  const code = e2e.newRecoveryCode().code;
  const { keyId, keySecret } = e2e.newApiKey();
  for (const purpose of [undefined, '', 'both', 'decrypt', 'Open']) {
    await assertThrows(async () => e2e.passwordCryptoKeys(testKeyBytes(7), purpose), e2e.FormatError);
    await assertThrows(async () => e2e.recoveryKekCryptoKey(code, purpose), e2e.FormatError);
    await assertThrows(async () => e2e.apiKeyKekCryptoKey(keySecret, keyId, purpose), e2e.FormatError);
  }
});

// openKey opens a sealed 32-byte key straight into a non-extractable HKDF
// CryptoKey: the opened key must derive exactly what the raw key derives, and
// it must work under every key that seals a key (the KEKs, mkSealKey for EK,
// ekSealKey for an estate AK).
test('non-extractable keys: openKey matches open, under every sealing key', async () => {
  const mk = testKeyBytes(8);
  const ek = testKeyBytes(9);
  const fields = [new TextEncoder().encode('mk')];
  const { kek: rawKek } = await e2e.passwordKeys(testKeyBytes(7));
  const { kek } = await e2e.passwordCryptoKeys(testKeyBytes(7), 'open');
  // The last column says whether open works with the same key: the 'open'
  // KEK CryptoKey has no decrypt usage, so it opens only through openKey.
  const sealers = [
    ['raw kek', rawKek, rawKek, mk, true],
    ['kek CryptoKey', rawKek, kek, mk, false],
    ['mkSealCryptoKey', await e2e.mkSealKey(mk), await e2e.mkSealCryptoKey(mk), ek, true],
    ['ekSealCryptoKey', await e2e.ekSealKey(ek), await e2e.ekSealCryptoKey(ek), mk, true],
  ];
  for (const [label, sealWith, openWith, secret, opensRaw] of sealers) {
    const sealed = await e2e.seal(sealWith, fields, secret);
    const opened = await e2e.openKey(openWith, fields, sealed);
    assert.equal(opened.extractable, false, label);
    assert.equal(opened.algorithm.name, 'HKDF', label);
    assert.equal(toHex(await e2e.mkSealKey(opened)), toHex(await e2e.mkSealKey(secret)), label);
    if (opensRaw) {
      assert.equal(toHex(await e2e.open(openWith, fields, sealed)), toHex(secret), label);
    } else {
      await assertThrows(() => e2e.open(openWith, fields, sealed), e2e.DecryptError);
    }
  }
});

// Every seal vector but the keyring seals a 32-byte key, so openKey opens it
// into a CryptoKey that derives exactly what the vector's plaintext derives.
// The keyring is not a key, and openKey refuses it on length alone.
test('seal: openKey over every sealed-key vector', async () => {
  let keys = 0;
  for (const v of vf.seal) {
    const args = [hex(v.key), v.fields.map(hex), hex(v.want)];
    const pt = hex(v.pt ?? '');
    if (new TextDecoder().decode(hex(v.fields[0])) === 'keyring') {
      await assertThrows(() => e2e.openKey(...args), e2e.DecryptError);
      continue;
    }
    assert.equal(pt.length, 32, `${v.name}: a sealed key's plaintext is 32 bytes`);
    const opened = await e2e.openKey(...args);
    assert.equal(toHex(await e2e.mkSealKey(opened)), toHex(await e2e.mkSealKey(pt)), v.name);
    keys++;
  }
  assert.ok(keys > 0, 'no sealed-key vectors');
});

test('openKey refuses what open refuses, and any plaintext but 32 bytes', async () => {
  const key = testKeyBytes(10);
  const fields = [new TextEncoder().encode('mk')];
  const sealed = await e2e.seal(key, fields, testKeyBytes(11));
  await e2e.openKey(key, fields, sealed); // positive control
  await assertThrows(() => e2e.openKey(testKeyBytes(12), fields, sealed), e2e.DecryptError);
  await assertThrows(() => e2e.openKey(key, [new TextEncoder().encode('ek')], sealed), e2e.DecryptError);
  const tampered = sealed.slice();
  tampered[20] ^= 1;
  await assertThrows(() => e2e.openKey(key, fields, tampered), e2e.DecryptError);
  // The version byte is outside the AEAD, so only the header check refuses it.
  const badVersion = sealed.slice();
  badVersion[0] = 0x02;
  await assertThrows(() => e2e.openKey(key, fields, badVersion), e2e.DecryptError);
  await assertThrows(() => e2e.open(key, fields, badVersion), e2e.DecryptError);
  await assertThrows(() => e2e.openKey(new Uint8Array(16), fields, sealed), e2e.DecryptError);
  for (const n of [0, 16, 31, 33, 64]) {
    const other = await e2e.seal(key, fields, new Uint8Array(n).fill(1));
    await assertThrows(() => e2e.openKey(key, fields, other), e2e.DecryptError);
  }
  await assertThrows(() => e2e.openKey(key, fields, Array.from(sealed)), e2e.FormatError);
});

// sealBlob/openBlob take ak as raw bytes or as an HKDF CryptoKey, and the two
// are interchangeable (the blob vectors pin the raw path).
test('non-extractable keys: sealBlob/openBlob with an HKDF CryptoKey ak match raw ak', async () => {
  const ak = testKeyBytes(13);
  const akKey = await e2e.importHKDFKey(ak);
  const ctx = { artifact: 'artifact-1', version: 'v1', kind: 'file', name: 'a.txt' };
  const pt = new TextEncoder().encode('blob body');
  assert.equal(toHex(await e2e.openBlob(ak, ctx, await e2e.sealBlob(akKey, ctx, pt))), toHex(pt));
  assert.equal(toHex(await e2e.openBlob(akKey, ctx, await e2e.sealBlob(ak, ctx, pt))), toHex(pt));
});

test('non-extractable keys: fileAddress with fileCryptoKey matches raw fileKey', async () => {
  const ak = testKeyBytes(3);
  const rawKey = await e2e.fileKey(ak, 'artifact-1', 3);
  const cryptoKey = await e2e.fileCryptoKey(ak, 'artifact-1', 3);
  const viaRaw = await e2e.fileAddress(rawKey, '/images/logo.png');
  const viaKey = await e2e.fileAddress(cryptoKey, '/images/logo.png');
  assert.equal(viaKey, viaRaw);
});

test('non-extractable keys: blindIndex with indexCryptoKey matches raw indexKey', async () => {
  const mk = testKeyBytes(4);
  const rawKey = await e2e.indexKey(mk);
  const cryptoKey = await e2e.indexCryptoKey(mk);
  const viaRaw = await e2e.blindIndex(rawKey, 'session', 'abc123');
  const viaKey = await e2e.blindIndex(cryptoKey, 'session', 'abc123');
  assert.equal(viaKey, viaRaw);
});

test('signature', async () => {
  for (const v of vf.signature) {
    const pub = hex(v.pub);
    const body = hex(v.body);
    const sig = hex(v.want);
    assert.ok(await e2e.verify(pub, v.purpose, body, sig), v.name);

    const env = { body: e2e.b64(body), sig: e2e.b64(sig), signer: v.signer };
    assert.ok(await e2e.verifyEnvelope(pub, v.purpose, env), `${v.name}: envelope`);

    for (const neg of v.negative) {
      const n = applyOverrides({ purpose: v.purpose, pub: v.pub }, neg);
      const useBody = n.input !== undefined ? hex(n.input) : body;
      const usePub = hex(n.pub);
      assert.equal(
        await e2e.verify(usePub, n.purpose, useBody, sig),
        false,
        `${v.name}: ${neg.why}`,
      );
    }
  }
});

// Envelope strictness isn't covered by vectors.json's own cases (which are
// all valid JSON), so these mirror internal/e2e/envelope_test.go directly:
// hand-written bodies exercising decodeStrict's duplicate-key, case-variant,
// unknown-key, missing-key, and trailing-data rejections through
// openEnvelope. Split into one test per case (rather than one long test
// asserting all of them) so a regression in one doesn't hide a regression in
// the rest.
const textEncoder = new TextEncoder();
const { seed: envSeed, pub: envPub } = await e2e.generateEd25519();

async function envelopeFor(purpose, body) {
  return e2e.newEnvelope(envSeed, 'user-1', purpose, textEncoder.encode(body));
}

// The signature table's membership, transfer, approval, and successor
// bodies: a full body opens, and dropping any field the table added is a
// FormatError. Mirrors TestOpenEnvelopeSigTableBodies in
// internal/e2e/envelope_test.go.
const sigTableFp = `"${'aa'.repeat(32)}"`;
const sigTableCases = [
  [
    'membership',
    [
      ['v', '1'], ['artifact', '"artifact-1"'], ['epoch', '3'], ['seq', '2'],
      ['owner', '"user-1"'], ['ownerFp', sigTableFp], ['akCommit', sigTableFp],
      ['members', `[{"user":"user-1","role":"editor","fp":${sigTableFp}}]`],
      ['excluded', `[{"user":"user-2","fp":${sigTableFp},"email":"b@example.com"}]`],
      ['team', '"none"'], ['public', 'false'], ['publicWrites', 'false'],
      ['prev', '""'], ['transfer', '""'], ['handover', '""'],
    ],
    ['seq', 'ownerFp', 'excluded', 'transfer', 'handover'],
  ],
  [
    'transfer',
    [
      ['v', '1'], ['artifact', '"artifact-1"'], ['from', '"user-1"'],
      ['to', '"user-2"'], ['toFp', sigTableFp], ['prev', sigTableFp],
    ],
    ['artifact', 'from', 'to', 'toFp', 'prev'],
  ],
  [
    'approval',
    [
      ['v', '1'], ['artifact', '"artifact-1"'], ['epoch', '3'],
      ['user', '"user-2"'], ['fp', sigTableFp],
    ],
    ['artifact', 'epoch', 'user', 'fp'],
  ],
  [
    'successor',
    [
      ['v', '1'], ['user', '"user-1"'], ['seq', '2'], ['successor', '"user-2"'],
      ['successorFp', sigTableFp], ['action', '"nominate"'],
    ],
    ['successorFp'],
  ],
];

function sigTableJSON(fields, skip) {
  return `{${fields.filter(([k]) => k !== skip).map(([k, v]) => `"${k}":${v}`).join(',')}}`;
}

for (const [purpose, fields, dropped] of sigTableCases) {
  test(`signature table: ${purpose} body`, async () => {
    const body = await e2e.openEnvelope(await envelopeFor(purpose, sigTableJSON(fields, '')), envPub, purpose);
    assert.equal(body.v, 1);
    for (const key of dropped) {
      const env = await envelopeFor(purpose, sigTableJSON(fields, key));
      await assertThrows(() => e2e.openEnvelope(env, envPub, purpose), e2e.FormatError);
    }
  });
}

test('bodyHash is the lowercase hex SHA-256 of the body', async () => {
  assert.equal(
    await e2e.bodyHash(textEncoder.encode('abc')),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
});

test('envelope strictness: valid body decodes', async () => {
  const env = await envelopeFor('vouch', `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef"}`);
  const body = await e2e.openEnvelope(env, envPub, 'vouch');
  assert.equal(body.artifact, 'a1');
});

test('envelope strictness: duplicate key', async () => {
  const env = await envelopeFor(
    'vouch',
    `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef","manifest":"beefdead"}`,
  );
  await assertThrows(() => e2e.openEnvelope(env, envPub, 'vouch'), e2e.FormatError);
});

test('envelope strictness: case-variant key', async () => {
  const env = await envelopeFor(
    'manifest',
    `{"v":1,"artifact":"a1","version":"v1","epoch":3,"Files":[],"files":[]}`,
  );
  await assertThrows(() => e2e.openEnvelope(env, envPub, 'manifest'), e2e.FormatError);
});

test('envelope strictness: unknown key', async () => {
  const env = await envelopeFor(
    'vouch',
    `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef","extra":"nope"}`,
  );
  await assertThrows(() => e2e.openEnvelope(env, envPub, 'vouch'), e2e.FormatError);
});

test('envelope strictness: missing key', async () => {
  const env = await envelopeFor('vouch', `{"v":1,"artifact":"a1","version":"v1"}`);
  await assertThrows(() => e2e.openEnvelope(env, envPub, 'vouch'), e2e.FormatError);
});

test('envelope strictness: trailing garbage', async () => {
  const env = await envelopeFor(
    'vouch',
    `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef"} garbage`,
  );
  await assertThrows(() => e2e.openEnvelope(env, envPub, 'vouch'), e2e.FormatError);
});

test('envelope strictness: wrong version', async () => {
  const env = await envelopeFor(
    'vouch',
    `{"v":2,"artifact":"a1","version":"v1","manifest":"deadbeef"}`,
  );
  await assertThrows(() => e2e.openEnvelope(env, envPub, 'vouch'), e2e.FormatError);
});

test('envelope strictness: wrong purpose', async () => {
  const env = await envelopeFor('vouch', `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef"}`);
  await assertThrows(() => e2e.openEnvelope(env, envPub, 'manifest'), e2e.DecryptError);
});

test('envelope strictness: bad signature', async () => {
  const env = await envelopeFor('vouch', `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef"}`);
  const badSig = { ...env, sig: e2e.b64(e2e.fromHex('00'.repeat(64))) };
  await assertThrows(() => e2e.openEnvelope(badSig, envPub, 'vouch'), e2e.DecryptError);
});

test('envelope strictness: rotation missing newSig', async () => {
  // The new key's seed is deliberately unused: this envelope is never
  // signed with it, which is exactly the "missing newSig" condition.
  const { pub: newPub } = await e2e.generateEd25519();
  const { pub: x25519Pub } = await e2e.generateX25519();
  const rotationBody = JSON.stringify({
    v: 1, user: 'user-1', seq: 1,
    old: { x25519: e2e.b64(x25519Pub), ed25519: e2e.b64(envPub) },
    new: { x25519: e2e.b64(x25519Pub), ed25519: e2e.b64(newPub) },
  });
  const noNewSig = await envelopeFor('rotation', rotationBody);
  await assertThrows(() => e2e.openRotation(noNewSig, envPub), e2e.FormatError);
});

// signedRotation is a rotation from envPub that openRotation accepts.
async function signedRotation() {
  const { seed: newSeed, pub: newPub } = await e2e.generateEd25519();
  const { pub: x25519Pub } = await e2e.generateX25519();
  const body = textEncoder.encode(JSON.stringify({
    v: 1, user: 'user-1', seq: 1,
    old: { x25519: e2e.b64(x25519Pub), ed25519: e2e.b64(envPub) },
    new: { x25519: e2e.b64(x25519Pub), ed25519: e2e.b64(newPub) },
  }));
  const env = await e2e.signRotation(envSeed, newSeed, 'user-1', body);
  await e2e.openRotation(env, envPub); // positive control
  return env;
}

// An empty or null newSig is missing, and is refused as such: "" would
// otherwise reach verify as a zero-length signature (DecryptError), and null
// would fail inside unb64 for an unrelated reason.
test('envelope strictness: rotation with an empty or null newSig', async () => {
  const env = await signedRotation();
  for (const newSig of ['', null]) {
    await assert.rejects(
      () => e2e.openRotation({ ...env, newSig }, envPub),
      { name: 'FormatError', message: /newSig/ },
      `newSig ${JSON.stringify(newSig)}`,
    );
  }
});

// openEnvelope never checks newSig, so it must refuse the rotation purpose
// outright rather than accept a rotation on the old key's signature alone.
test('envelope strictness: openEnvelope refuses rotation', async () => {
  const env = await signedRotation();
  await assertThrows(() => e2e.openEnvelope(env, envPub, 'rotation'), e2e.FormatError);
  const withoutNewSig = { ...env };
  delete withoutNewSig.newSig;
  await assertThrows(() => e2e.openEnvelope(withoutNewSig, envPub, 'rotation'), e2e.FormatError);
});

// verify works on its own copy of sig: a caller that reuses its buffer while
// verification is in flight does not change the outcome.
test('verify copies sig on entry', async () => {
  const v = vf.signature[0];
  const pub = hex(v.pub);
  const sig = hex(v.want);
  const pending = e2e.verify(pub, v.purpose, hex(v.body), sig);
  sig.fill(0);
  assert.equal(await pending, true);
});

test('verify copies body on entry', async () => {
  const v = vf.signature[0];
  const body = hex(v.body);
  const pending = e2e.verify(hex(v.pub), v.purpose, body, hex(v.want));
  body.fill(0);
  assert.equal(await pending, true);
});

// envelope wrapper strictness mirrors TestOpenEnvelopeJSONItselfIsStrict in
// internal/e2e/envelope_test.go: decodeEnvelope (not openEnvelope, which
// takes an already-parsed object) must refuse a case-variant key, an unknown
// key, and a missing field in the raw envelope JSON itself.
test('envelope wrapper strictness', async () => {
  const env = await envelopeFor('vouch', `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef"}`);
  const good = JSON.stringify(env);
  const cases = [
    good.slice(0, -1) + `,"Body":"AA"}`, // case-variant key
    good.slice(0, -1) + `,"extra":1}`, // unknown key
    `{"sig":"AA","signer":"user-1"}`, // missing body
  ];
  for (const c of cases) {
    assert.throws(() => e2e.decodeEnvelope(c), e2e.FormatError, c);
  }
  // decodeEnvelope's output is exactly what openEnvelope already accepts.
  const decoded = e2e.decodeEnvelope(good);
  const body = await e2e.openEnvelope(decoded, envPub, 'vouch');
  assert.equal(body.artifact, 'a1');
});

test('rotation', async () => {
  for (const v of vf.rotation) {
    const env = {
      body: e2e.b64(hex(v.body)), sig: e2e.b64(hex(v.sig)), signer: v.signer,
      newSig: e2e.b64(hex(v.newSig)),
    };
    if (v.refuse) {
      await assertThrows(() => e2e.openRotation(env, hex(v.oldPub)), e2e.FormatError);
      continue;
    }
    const body = await e2e.openRotation(env, hex(v.oldPub));
    assert.equal(body.user, 'user-1', v.name);

    for (const neg of v.negative) {
      const useEnv = { ...env };
      if (neg.newSig !== undefined) useEnv.newSig = e2e.b64(hex(neg.newSig));
      await assertThrows(() => e2e.openRotation(useEnv, hex(v.oldPub)));
    }
  }
});

// edwards25519BasePoint is the standard compressed encoding of the Ed25519
// base point B (y = 4/5 mod p, x even). Paired with S=1, R=B satisfies the
// cofactored verification equation for ANY message whenever the public key
// has order dividing 8 — a universal forgery against any verifier that
// doesn't itself refuse a small-order or non-canonical key first.
const edwards25519BasePoint = hex(
  '5866666666666666666666666666666666666666666666666666666666666666',
);
const forgedS = new Uint8Array(32);
forgedS[0] = 1;
const forgedSig = new Uint8Array([...edwards25519BasePoint, ...forgedS]);

// withEquationStubbed runs fn with WebCrypto's Ed25519 verification replaced
// by one that always succeeds, so verify's result is decided by its own
// encoding checks alone. Node's verifier is cofactorless and already fails
// several ed25519Strict signatures through the curve equation; a cofactored
// browser verifier would not, so each must be refused before it.
async function withEquationStubbed(fn) {
  const subtle = globalThis.crypto.subtle;
  subtle.verify = async () => true;
  try {
    return await fn();
  } finally {
    delete subtle.verify;
  }
}

test('ed25519Strict: the stub isolates verify\'s own checks', async () => {
  const v = vf.signature[0];
  const otherBody = new TextEncoder().encode('not the signed body');
  assert.equal(await e2e.verify(hex(v.pub), v.purpose, otherBody, hex(v.want)), false);
  await withEquationStubbed(async () => {
    assert.equal(await e2e.verify(hex(v.pub), v.purpose, otherBody, hex(v.want)), true);
  });
  assert.equal(await e2e.verify(hex(v.pub), v.purpose, otherBody, hex(v.want)), false);
});

test('ed25519Strict', async () => {
  for (const v of vf.ed25519Strict) {
    const pub = hex(v.pub);
    assert.equal(pub.length, 32, v.name);
    if (v.sig) {
      // A signature some verifier accepts, which verify must refuse, and
      // must refuse before the curve equation runs.
      const args = [pub, v.purpose, hex(v.body), hex(v.sig)];
      assert.equal(await e2e.verify(...args), false, `${v.name}: ${v.why}`);
      await withEquationStubbed(async () => {
        assert.equal(await e2e.verify(...args), false, `${v.name} (equation stubbed): ${v.why}`);
      });
      continue;
    }
    // A small-order or non-canonical key must fail on its own, for any
    // purpose, body, and signature — including the R=B,S=1 forgery.
    await assertThrows(
      () => e2e.checkPublicKeys(new Uint8Array(32).fill(1), pub),
      e2e.FormatError,
    );
    for (const body of ['body', 'a different message']) {
      const ok = await e2e.verify(pub, 'manifest', new TextEncoder().encode(body), forgedSig);
      assert.equal(ok, false, `${v.name}: ${v.why}`);
    }
  }
});

test('x25519Strict', async () => {
  // A real key: checkPublicKeys refuses an arbitrary 32-byte value as an
  // Ed25519 key, which would make every case here pass for the wrong reason.
  const { pub: genuineEd25519Pub } = await e2e.generateEd25519();
  for (const v of vf.x25519Strict) {
    if (v.accept) {
      await e2e.checkPublicKeys(hex(v.pub), genuineEd25519Pub);
      continue;
    }
    await assertThrows(
      () => e2e.checkPublicKeys(hex(v.pub), genuineEd25519Pub),
      e2e.FormatError,
      `${v.name}: ${v.why}`,
    );
  }
});

// envelope mirrors the Go envelope vector check: decodeEnvelope must accept
// or refuse each raw wrapper exactly as Envelope.UnmarshalJSON does, and an
// accepted one must re-encode to exactly the input.
test('envelope', () => {
  for (const v of vf.envelope) {
    if (!v.accept) {
      assert.throws(() => e2e.decodeEnvelope(v.json), e2e.FormatError, `${v.name}: ${v.why}`);
      continue;
    }
    assert.equal(JSON.stringify(e2e.decodeEnvelope(v.json)), v.json, v.name);
  }
});

// A JS string can hold a lone surrogate code unit outright, not only as a
// \uD800 escape; Go's input is bytes, where it can't exist as valid UTF-8.
test('decodeEnvelope refuses a string holding a lone surrogate code unit', () => {
  const text = '{"body":"eyJ2IjoxfQ","sig":"AAAA","signer":"u\uD800"}';
  assert.equal(text.isWellFormed(), false);
  assert.throws(() => e2e.decodeEnvelope(text), e2e.FormatError);
});

// A leading BOM is refused for string input as well as for bytes (the bytes
// case is the utf8-bom strictJSON vector); U+FEFF inside a string is fine.
test('decodeEnvelope refuses a leading BOM in string input', () => {
  const good = '{"body":"eyJ2IjoxfQ","sig":"AAAA","signer":"u\uFEFF"}';
  assert.equal(e2e.decodeEnvelope(good).signer, 'u\uFEFF');
  assert.throws(() => e2e.decodeEnvelope('\uFEFF' + good), e2e.FormatError);
});

test('strictJSON', () => {
  for (const v of vf.strictJSON) {
    const schema = e2e.BODY_SCHEMAS[v.purpose];
    assert.throws(
      () => e2e.decodeStrict(hex(v.body), schema),
      e2e.FormatError,
      `${v.name}: ${v.why}`,
    );
  }
});

test('base64url', () => {
  for (const v of vf.base64url) {
    assert.equal(toHex(e2e.unb64(v.encoded)), v.bytes, v.name);
    for (const neg of v.negative) {
      assert.throws(() => e2e.unb64(neg.input), e2e.FormatError, `${v.name}: ${neg.why}`);
    }
  }
});

test('fingerprint', async () => {
  for (const v of vf.fingerprint) {
    const got = await e2e.fingerprint(hex(v.x25519Pub), hex(v.ed25519Pub));
    assert.equal(toHex(got), v.want, v.name);
    assert.equal(e2e.formatFingerprint(got), v.display, v.name);
  }
});

test('linkToken', async () => {
  for (const v of vf.linkToken) {
    const got = await e2e.linkToken(hex(v.ak), v.artifact, v.epoch);
    assert.equal(toHex(got), v.want, v.name);
    assert.equal(await e2e.linkTokenHash(got), v.hash, v.name);
  }
});

test('fileAddress', async () => {
  for (const v of vf.fileAddress) {
    assert.equal(await e2e.fileAddress(hex(v.fileKey), v.path), v.want, v.name);
    for (const neg of v.negative) {
      await assertThrows(() => e2e.fileAddress(hex(neg.key), v.path), e2e.FormatError);
    }
  }
});

test('blindIndex', async () => {
  for (const v of vf.blindIndex) {
    assert.equal(await e2e.blindIndex(hex(v.indexKey), v.type, v.value), v.want, v.name);
    for (const neg of v.negative) {
      await assertThrows(() => e2e.blindIndex(hex(neg.key), v.type, v.value), e2e.FormatError);
    }
  }
});

// importHKDFKey holds a master, estate or artifact key, all of which are 32
// bytes; it refuses any other length rather than importing it.
test('importHKDFKey refuses a key that is not 32 bytes', async () => {
  await e2e.importHKDFKey(testKeyBytes(5)); // positive control
  for (const n of [0, 16, 31, 33]) {
    await assertThrows(() => e2e.importHKDFKey(new Uint8Array(n)), e2e.FormatError);
  }
});

// chainErrors maps each chain entry's error kind to the class verifyChain
// throws for it; see testdata/README.md.
const chainErrors = {
  chain: e2e.ChainError,
  rollback: e2e.RollbackError,
  fork: e2e.ForkError,
  staleEpoch: e2e.StaleEpochError,
  format: e2e.FormatError,
  decrypt: e2e.DecryptError,
};

function chainInput(v) {
  return {
    artifact: v.artifact,
    records: v.records,
    owners: v.owners,
    offers: v.offers,
    successors: v.successors,
    anchor: v.anchor,
    currentOwnerFp: v.currentOwnerFp,
    pin: v.pin,
  };
}

// chain mirrors the Go chain vector check: verifyChain must accept each
// valid chain with the same result, and refuse each other one with the
// class for its error kind.
describe('chain', () => {
  for (const v of vf.chain) {
    test(v.name, async () => {
      if (v.error) {
        assert.ok(chainErrors[v.error], `${v.name}: unknown error kind ${v.error}`);
        await assert.rejects(() => e2e.verifyChain(chainInput(v)), chainErrors[v.error], `${v.name}: ${v.why}`);
        return;
      }
      const got = await e2e.verifyChain(chainInput(v));
      assert.deepEqual(
        { head: got.head, seq: got.latest.seq, epoch: got.latest.epoch, handovers: got.handovers },
        v.want,
        v.name,
      );
      assert.equal(got.bodies.length, v.records.length, v.name);
    });
  }
});

// A pin that is not {epoch >= 1, seq >= 1, head string} is refused as a
// format error before it is compared with anything; null or undefined is no
// pin at all.
test('verifyChain: a malformed pin is a format error', async () => {
  const v = vf.chain.find((c) => !c.error);
  const good = { epoch: 1, seq: 1, head: 'h' };
  for (const bad of [
    { seq: 1, head: 'h' },
    { ...good, epoch: '1' },
    { ...good, epoch: 0 },
    { ...good, seq: 1.5 },
    { ...good, seq: 0 },
    { ...good, head: 7 },
    { epoch: 1, seq: 1 },
  ]) {
    await assert.rejects(() => e2e.verifyChain({ ...chainInput(v), pin: bad }), e2e.FormatError, JSON.stringify(bad));
  }
  for (const none of [null, undefined]) {
    await e2e.verifyChain({ ...chainInput(v), pin: none });
  }
});

// An administrator's handover to an unlisted user names the successor
// record it needs, rather than reading like any other unlisted new owner.
test('verifyChain: a handover to an unlisted user names the successor record', async () => {
  const v = vf.chain.find((c) => c.name === 'handover-to-unlisted');
  await assert.rejects(
    () => e2e.verifyChain(chainInput(v)),
    (err) => err instanceof e2e.ChainError && /successor record/.test(err.message),
  );
});

// The rotation chain hook stands in for fingerprint equality at the anchor
// and at each record; without it, a changed ownerFp is refused.
test('verifyChain: linked replaces fingerprint equality', async () => {
  const v = vf.chain.find((c) => c.name === 'owner-fp-changed');
  const input = { ...chainInput(v), anchor: 'anchor-fp' };
  await assert.rejects(() => e2e.verifyChain(input), e2e.ChainError);
  const calls = [];
  input.linked = (user, from, to) => {
    calls.push([user, from, to]);
    return true;
  };
  await e2e.verifyChain(input);
  const fps = v.records.map((r) => JSON.parse(new TextDecoder().decode(e2e.unb64(r.body))).ownerFp);
  assert.deepEqual(calls, [
    ['u-alice', 'anchor-fp', fps[0]],
    ['u-alice', fps[0], fps[1]],
  ]);
});

// rotationLinker is async, since checking a rotation signature is, so
// verifyChain must wait for the hook: an unawaited Promise is always truthy.
test('verifyChain: an async linked that says no refuses the chain', async () => {
  const v = vf.chain.find((c) => c.name === 'owner-fp-changed');
  const input = { ...chainInput(v), anchor: 'anchor-fp' };
  input.linked = async (_user, from) => from !== 'anchor-fp'; // refuses only the anchor
  await assert.rejects(() => e2e.verifyChain(input), e2e.ChainError);
  input.linked = async (_user, from) => from === 'anchor-fp'; // refuses only the later record
  await assert.rejects(() => e2e.verifyChain(input), e2e.ChainError);
  input.linked = async () => true;
  await e2e.verifyChain(input);
});

// The owner-change path asks linked about the fp the previous record lists for
// the new owner. The first call for anyone but the creator is that one, so
// refusing it kills an unawaited Promise there, which the same-owner test
// above does not reach.
test('verifyChain: an async linked that says no refuses an owner change', async () => {
  for (const name of ['admin-handover', 'transfer']) {
    const v = vf.chain.find((c) => c.name === name);
    const creator = JSON.parse(new TextDecoder().decode(e2e.unb64(v.records[0].body))).owner;
    const input = chainInput(v);
    input.linked = async (user, from, to) => user === creator && from === to;
    await assert.rejects(() => e2e.verifyChain(input), e2e.ChainError, name);
    input.linked = async (_user, from, to) => from === to;
    await e2e.verifyChain(input); // positive control
  }
});

// approvalErrors maps each approval entry's error kind to the class
// checkApproval throws for it; see testdata/README.md.
const approvalErrors = {
  missing: e2e.ApprovalMissingError,
  signer: e2e.ApprovalSignerError,
  decrypt: e2e.DecryptError,
  format: e2e.FormatError,
  mismatch: e2e.ApprovalMismatchError,
  excluded: e2e.ApprovalExcludedError,
  duplicate: e2e.ApprovalDuplicateError,
};

// approval mirrors the Go approval vector check: checkApproval must accept
// each approval that passes all four checks, and refuse each other one with
// the class for its error kind.
describe('approval', () => {
  for (const v of vf.approval) {
    test(v.name, async () => {
      const input = {
        artifact: v.artifact,
        latest: v.latest,
        approval: v.approval,
        signerKeys: v.signerKeys,
        user: v.user,
        directory: v.directory,
        rotations: v.rotations,
      };
      if (v.error) {
        assert.ok(approvalErrors[v.error], `${v.name}: unknown error kind ${v.error}`);
        await assert.rejects(() => e2e.checkApproval(input), approvalErrors[v.error], `${v.name}: ${v.why}`);
        return;
      }
      await e2e.checkApproval(input);
    });
  }
});

test('approval vectors cover every error kind', () => {
  const kinds = new Set(vf.approval.map((v) => v.error ?? ''));
  for (const k of Object.keys(approvalErrors)) assert.ok(kinds.has(k), `no approval vector for ${k}`);
});

// signApproval builds the approval body the way Go marshals it, and the
// result opens under the signer's key as an approval, and under no other
// purpose.
test('signApproval builds a body openEnvelope accepts', async () => {
  const { seed, pub } = await e2e.generateEd25519();
  const env = await e2e.signApproval(seed, 'u-bob', { artifact: 'art-1', epoch: 2, user: 'u-dave', fp: 'ab'.repeat(32) });
  assert.equal(env.signer, 'u-bob');
  assert.equal(
    new TextDecoder().decode(e2e.unb64(env.body)),
    `{"v":1,"artifact":"art-1","epoch":2,"user":"u-dave","fp":"${'ab'.repeat(32)}"}`,
  );
  const body = await e2e.openEnvelope(env, pub, 'approval');
  assert.deepEqual(body, { v: 1, artifact: 'art-1', epoch: 2, user: 'u-dave', fp: 'ab'.repeat(32) });
  await assertThrows(() => e2e.openEnvelope(env, pub, 'vouch'), e2e.DecryptError);
});

test('excludedMatch matches by ID, fingerprint, and normalized email', () => {
  const x = [{ user: 'u-1', fp: 'aa', email: 'a@example.com' }];
  assert.equal(e2e.excludedMatch(x, 'u-1', 'bb', 'b@example.com'), x[0]);
  assert.equal(e2e.excludedMatch(x, 'u-2', 'aa', 'b@example.com'), x[0]);
  assert.equal(e2e.excludedMatch(x, 'u-2', 'bb', ' A@Example.com'), x[0]);
  assert.equal(e2e.excludedMatch(x, 'u-2', 'bb', 'b@example.com'), null);
  const stored = [{ user: 'u-1', fp: 'aa', email: ' A@Example.COM' }];
  assert.equal(e2e.excludedMatch(stored, 'u-2', 'bb', 'a@example.com'), stored[0]);
});

test('checkEncryptEpoch refuses an epoch below the pinned one', () => {
  const pin = { epoch: 3, seq: 5, head: 'h' };
  e2e.checkEncryptEpoch(pin, 3);
  e2e.checkEncryptEpoch(pin, 4);
  e2e.checkEncryptEpoch(null, 1);
  assert.throws(() => e2e.checkEncryptEpoch(pin, 2), e2e.StaleEpochError);
});

test('checkNewAk refuses an earlier epoch\'s AK', () => {
  const earlier = [testKeyBytes(1), testKeyBytes(2)];
  e2e.checkNewAk(testKeyBytes(3), earlier);
  e2e.checkNewAk(testKeyBytes(3), []);
  for (const ak of earlier) {
    assert.throws(() => e2e.checkNewAk(new Uint8Array(ak), earlier), e2e.ReusedAkError);
  }
  // Equal in every byte the shorter one has, so only the length differs.
  e2e.checkNewAk(testKeyBytes(1), [new Uint8Array(31).fill(1), new Uint8Array(33).fill(1)]);
  assert.throws(() => e2e.checkNewAk(new Uint8Array(16), earlier), e2e.FormatError);
  assert.throws(() => e2e.checkNewAk(Array.from(testKeyBytes(3)), earlier), e2e.FormatError);
});

// keyringErrors maps each keyring entry's error kind to the class
// openKeyring must throw; see testdata/README.md.
const keyringErrors = {
  rev: e2e.KeyringRevError,
  rollback: e2e.KeyringRollbackError,
  fork: e2e.KeyringForkError,
  format: e2e.FormatError,
  decrypt: e2e.DecryptError,
};

// keyring mirrors the Go keyring vector check: openKeyring must open each
// valid answer to the same keyring and anchor, and refuse each other one
// with the same error kind.
describe('keyring', () => {
  for (const v of vf.keyring) {
    test(v.name, async () => {
      const run = () => e2e.openKeyring(hex(v.key), v.rev, hex(v.sealed), v.anchor);
      if (v.error) {
        assert.ok(keyringErrors[v.error], `${v.name}: unknown error kind ${v.error}`);
        await assert.rejects(run, keyringErrors[v.error], `${v.name}: ${v.why}`);
        return;
      }
      const got = await run();
      assert.deepEqual(got, v.want, `${v.name}: ${v.why}`);
    });
  }
});

test('the keyring errors are distinct classes', () => {
  const classes = [e2e.KeyringRevError, e2e.KeyringRollbackError, e2e.KeyringForkError];
  for (const a of classes) {
    for (const b of classes) {
      if (a !== b) assert.ok(!(new a('x') instanceof b), `${a.name} is a ${b.name}`);
    }
  }
});

test('sealKeyring round-trips and refuses an invalid keyring', async () => {
  const key = await e2e.mkSealKey(testKeyBytes(7));
  const k = e2e.newKeyring();
  k.rev = 2;
  k.pins['u-bob'] = { fp: 'a'.repeat(64), state: e2e.PIN_VERIFIED, rotSeq: 0, rotHead: '' };
  k.epochs['a-1'] = { epoch: 1, seq: 3, head: 'b'.repeat(64), ack: 0 };
  const sealed = await e2e.sealKeyring(key, k);
  const got = await e2e.openKeyring(key, 2, sealed, null);
  assert.deepEqual(got.keyring, k);
  assert.deepEqual(got.anchor, { rev: 2, hash: await e2e.bodyHash(sealed) });
  // Opening under the mk field, not keyring, fails.
  await assert.rejects(() => e2e.open(key, [new TextEncoder().encode('mk')], sealed), e2e.DecryptError);

  const bad = structuredClone(k);
  bad.pins['u-bob'].state = e2e.PIN_NEW;
  await assert.rejects(() => e2e.sealKeyring(key, bad), e2e.FormatError);
  for (const rev of [-1, 1.5]) {
    await assert.rejects(() => e2e.sealKeyring(key, { ...k, rev }), e2e.FormatError, `rev ${rev}`);
  }
});

test('openKeyring refuses a malformed anchor before comparing', async () => {
  const key = await e2e.mkSealKey(testKeyBytes(7));
  const k = e2e.newKeyring();
  k.rev = 2;
  const sealed = await e2e.sealKeyring(key, k);
  const hash = await e2e.bodyHash(sealed);
  for (const anchor of [{ rev: -1, hash }, { rev: 1, hash: 'X'.repeat(64) }, { rev: 1.5, hash }]) {
    await assert.rejects(() => e2e.openKeyring(key, 2, sealed, anchor), e2e.FormatError, JSON.stringify(anchor));
  }
});

test('pinState reports new, the pinned state, or changed', async () => {
  const x = new Uint8Array(32).fill(1);
  const ed = new Uint8Array(32).fill(2);
  const fp = toHex(await e2e.fingerprint(x, ed));
  const other = 'c'.repeat(64);
  const cases = [
    [null, e2e.PIN_NEW],
    [{ fp, state: e2e.PIN_UNVERIFIED }, e2e.PIN_UNVERIFIED],
    [{ fp, state: e2e.PIN_VERIFIED }, e2e.PIN_VERIFIED],
    [{ fp: other, state: e2e.PIN_VERIFIED }, e2e.PIN_CHANGED],
    [{ fp: other, state: e2e.PIN_UNVERIFIED }, e2e.PIN_CHANGED],
  ];
  for (const [pin, want] of cases) {
    assert.deepEqual(await e2e.pinState(pin, x, ed), { state: want, fp }, JSON.stringify(pin));
  }
});

// fakeStorage is the part of the Storage interface the anchor helpers use.
function fakeStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    keys: () => [...m.keys()],
  };
}

const FP_A = 'a'.repeat(64);
const FP_B = 'b'.repeat(64);

test('the keyring anchor is kept per user and fingerprint and survives signing out', async () => {
  const storage = fakeStorage();
  const key = await e2e.mkSealKey(testKeyBytes(8));
  const k = e2e.newKeyring();
  k.rev = 1;
  const sealed1 = await e2e.sealKeyring(key, k);
  k.rev = 2;
  const sealed2 = await e2e.sealKeyring(key, k);

  assert.equal(e2e.loadKeyringAnchor(storage, 'u-ada', FP_A), null);
  const read2 = await e2e.openKeyring(key, 2, sealed2, null);
  e2e.saveKeyringAnchor(storage, 'u-ada', FP_A, read2.anchor);
  storage.setItem('cairn.session', 'token');

  // Signing out drops the session; the anchor is a separate key.
  storage.removeItem('cairn.session');
  assert.deepEqual(storage.keys(), [`cairn.keyringAnchor.u-ada.${FP_A}`]);

  // Signing in again reads the anchor back, and it refuses the rev 1
  // keyring a server rolled back to.
  const anchor = e2e.loadKeyringAnchor(storage, 'u-ada', FP_A);
  assert.deepEqual(anchor, read2.anchor);
  await assert.rejects(() => e2e.openKeyring(key, 1, sealed1, anchor), e2e.KeyringRollbackError);
  await e2e.openKeyring(key, 2, sealed2, anchor);

  // Another user on the same browser has no anchor of their own yet.
  assert.equal(e2e.loadKeyringAnchor(storage, 'u-bob', FP_A), null);

  // The same user under another fingerprint, as after a reset without the
  // recovery code, has none either; the old anchor stays where it was.
  assert.equal(e2e.loadKeyringAnchor(storage, 'u-ada', FP_B), null);
  e2e.saveKeyringAnchor(storage, 'u-ada', FP_B, (await e2e.openKeyring(key, 1, sealed1, null)).anchor);
  assert.equal(e2e.loadKeyringAnchor(storage, 'u-ada', FP_B).rev, 1);
  assert.deepEqual(e2e.loadKeyringAnchor(storage, 'u-ada', FP_A), anchor);
  storage.removeItem(`cairn.keyringAnchor.u-ada.${FP_B}`);

  // A malformed stored anchor is an error, never "no anchor".
  for (const raw of ['not json', '{"rev":-1,"hash":"' + 'a'.repeat(64) + '"}', '{"rev":1,"hash":"zz"}', 'null']) {
    storage.setItem(`cairn.keyringAnchor.u-ada.${FP_A}`, raw);
    assert.throws(() => e2e.loadKeyringAnchor(storage, 'u-ada', FP_A), e2e.FormatError, raw);
  }
  assert.throws(() => e2e.loadKeyringAnchor(storage, '', FP_A), e2e.FormatError);
  assert.throws(() => e2e.loadKeyringAnchor(storage, 'u-ada', ''), e2e.FormatError);
  assert.throws(() => e2e.saveKeyringAnchor(storage, 'u-ada', '', anchor), e2e.FormatError);
  assert.throws(() => e2e.saveKeyringAnchor(storage, 'u-ada', FP_A, { rev: 1, hash: 'nope' }), e2e.FormatError);
});

test('saving a keyring anchor never lowers the rev or replaces the hash at it', async () => {
  const storage = fakeStorage();
  const key = await e2e.mkSealKey(testKeyBytes(8));
  const k = e2e.newKeyring();
  const anchors = [];
  for (const rev of [1, 2]) {
    k.rev = rev;
    anchors.push((await e2e.openKeyring(key, rev, await e2e.sealKeyring(key, k), null)).anchor);
  }
  const other = { rev: 2, hash: 'c'.repeat(64) };

  e2e.saveKeyringAnchor(storage, 'u-ada', FP_A, anchors[1]);
  e2e.saveKeyringAnchor(storage, 'u-ada', FP_A, anchors[1]); // the same anchor again is fine
  assert.throws(() => e2e.saveKeyringAnchor(storage, 'u-ada', FP_A, anchors[0]), e2e.KeyringRollbackError);
  assert.throws(() => e2e.saveKeyringAnchor(storage, 'u-ada', FP_A, other), e2e.KeyringForkError);
  assert.deepEqual(e2e.loadKeyringAnchor(storage, 'u-ada', FP_A), anchors[1]);
  e2e.saveKeyringAnchor(storage, 'u-ada', FP_A, { rev: 3, hash: 'd'.repeat(64) });
  assert.equal(e2e.loadKeyringAnchor(storage, 'u-ada', FP_A).rev, 3);
});

// linkChainErrors maps each linkChain entry's error kind to the class
// verifyLinkChain throws for it; see testdata/README.md.
const linkChainErrors = { ...chainErrors, staleLink: e2e.StaleLinkError };

// link mirrors the Go link vector check: publicLink builds each link,
// parseLink reads it back, and parseLink refuses every negative input.
describe('link', () => {
  for (const v of vf.link) {
    test(v.name, () => {
      assert.equal(e2e.publicLink(v.host, v.artifact, hex(v.ak), v.epoch, v.o), v.want);
      const l = e2e.parseLink(v.want);
      assert.deepEqual(
        { host: l.host, artifact: l.artifact, ak: toHex(l.ak), epoch: l.epoch, o: l.o },
        { host: v.host, artifact: v.artifact, ak: v.ak, epoch: v.epoch, o: v.o },
      );
      for (const n of v.negative ?? []) {
        assert.throws(() => e2e.parseLink(n.input), e2e.FormatError, `${n.why}: ${JSON.stringify(n.input)}`);
      }
    });
  }

  test('publicLink refuses what parseLink would', () => {
    const ak = new Uint8Array(32);
    const o = 'a'.repeat(64);
    const id = vf.link[0].artifact;
    assert.throws(() => e2e.publicLink('https://h', id, ak.slice(1), 1, o), e2e.FormatError);
    assert.throws(() => e2e.publicLink('https://h', id, ak, 0, o), e2e.FormatError);
    assert.throws(() => e2e.publicLink('https://h', 'nope', ak, 1, o), e2e.FormatError);
    assert.throws(() => e2e.publicLink('https://h', id, ak, 1, 'AB'), e2e.FormatError);
    assert.throws(() => e2e.publicLink('https://h/x', id, ak, 1, o), e2e.FormatError);
    assert.ok(e2e.publicLink('https://h/', id, ak, 1, o).startsWith('https://h/shared/'));
  });
});

// linkChain mirrors the Go linkChain vector check: verifyLinkChain must
// accept each valid answer with the same result, and refuse each other one
// with the class for its error kind.
describe('linkChain', () => {
  for (const v of vf.linkChain) {
    test(v.name, async () => {
      const input = {
        link: { artifact: v.artifact, ak: hex(v.ak), epoch: v.epoch, o: v.o },
        records: v.records,
        owners: v.owners,
        offers: v.offers,
        successors: v.successors,
        keys: v.keys,
        rotations: v.rotations,
      };
      if (v.error) {
        assert.ok(linkChainErrors[v.error], `${v.name}: unknown error kind ${v.error}`);
        await assert.rejects(() => e2e.verifyLinkChain(input), linkChainErrors[v.error], `${v.name}: ${v.why}`);
        return;
      }
      const got = await e2e.verifyLinkChain(input);
      assert.deepEqual(
        { head: got.chain.head, seq: got.chain.latest.seq, epoch: got.chain.latest.epoch },
        { head: v.want.head, seq: v.want.seq, epoch: v.want.epoch },
        v.name,
      );
      assert.deepEqual(Object.keys(got.editors).sort(), v.want.editors, `${v.name}: ${v.why}`);
      for (const id of v.want.editors) assert.deepEqual(got.editors[id], v.keys[id], `${v.name}: keys of ${id}`);
    });
  }
});

// rotationErrors maps each rotationChain entry's error kind to the class
// followRotations throws for it; see testdata/README.md.
const rotationErrors = { ...chainErrors, rotationFork: e2e.RotationForkError, rollback: e2e.RollbackError };

// rotationChain mirrors the Go rotationChain vector check: followRotations
// must accept each valid chain with the same result, and refuse each other
// one with the class for its error kind.
describe('rotationChain', () => {
  for (const v of vf.rotationChain) {
    test(v.name, async () => {
      if (v.error) {
        assert.ok(rotationErrors[v.error], `${v.name}: unknown error kind ${v.error}`);
        await assert.rejects(
          () => e2e.followRotations(v.user, v.records, v.pin),
          rotationErrors[v.error],
          `${v.name}: ${v.why}`,
        );
        return;
      }
      const got = await e2e.followRotations(v.user, v.records, v.pin);
      assert.deepEqual(got, v.want, `${v.name}: ${v.why}`);
    });
  }

  test('a fork is not a chain error', async () => {
    const v = vf.rotationChain.find((c) => c.name === 'fork-against-rotHead');
    await assert.rejects(() => e2e.followRotations(v.user, v.records, v.pin), (err) => {
      assert.ok(err instanceof e2e.RotationForkError);
      assert.ok(!(err instanceof e2e.ChainError));
      return true;
    });
  });
});

// rotationLink mirrors the Go rotationLink vector check: rotationLinker
// must answer each question as the vector does.
describe('rotationLink', () => {
  for (const v of vf.rotationLink) {
    test(v.name, async () => {
      const linked = e2e.rotationLinker(v.rotations);
      assert.equal(await linked(v.user, v.from, v.to), v.want, `${v.name}: ${v.why}`);
    });
  }
});

// followPin mirrors the Go followPin vector check: followPin must answer
// each entry with the state and next pin the vector holds. A fork or rollback
// throws the error, with the state and next pin attached to it.
describe('followPin', () => {
  for (const v of vf.followPin) {
    test(v.name, async () => {
      const keys = [e2e.unb64(v.keys.x25519), e2e.unb64(v.keys.ed25519)];
      if (v.want.error) {
        assert.ok(rotationErrors[v.want.error], `${v.name}: unknown error kind ${v.want.error}`);
        await assert.rejects(() => e2e.followPin(v.user, v.pin, v.records, ...keys), (err) => {
          assert.ok(err instanceof rotationErrors[v.want.error], `${v.name}: ${v.why}: ${err}`);
          assert.equal(err.state, v.want.state, `${v.name}: ${v.why}`);
          assert.deepEqual(err.next, v.want.next, `${v.name}: ${v.why}`);
          return true;
        });
        return;
      }
      const got = await e2e.followPin(v.user, v.pin, v.records, ...keys);
      assert.deepEqual(got, { state: v.want.state, next: v.want.next }, `${v.name}: ${v.why}`);
    });
  }

  test('a fork is not a chain error', async () => {
    const v = vf.followPin.find((c) => c.name === 'fork');
    const keys = [e2e.unb64(v.keys.x25519), e2e.unb64(v.keys.ed25519)];
    await assert.rejects(() => e2e.followPin(v.user, v.pin, v.records, ...keys), (err) => {
      assert.ok(err instanceof e2e.RotationForkError);
      assert.ok(!(err instanceof e2e.ChainError));
      return true;
    });
  });

  test('the pin passed in is not edited', async () => {
    const v = vf.followPin.find((c) => c.name === 'rotated-verified-drops');
    const keys = [e2e.unb64(v.keys.x25519), e2e.unb64(v.keys.ed25519)];
    const before = structuredClone(v.pin);
    await e2e.followPin(v.user, v.pin, v.records, ...keys);
    assert.deepEqual(v.pin, before);
  });
});

// A user ID is untrusted input, and an object lookup finds "__proto__" and
// "constructor" on every map, so the linker must not read them as records.
test('rotationLinker: user IDs that name Object properties link nothing', async () => {
  const linked = e2e.rotationLinker({});
  for (const user of ['__proto__', 'constructor']) {
    assert.equal(await linked(user, 'a'.repeat(64), 'b'.repeat(64)), false, user);
  }
});

test('vectors.json has no section this file does not check', () => {
  const handled = [
    'enc', 'derive', 'argon2', 'recoveryCode', 'apiKey', 'akCommit', 'seal',
    'blob', 'wrap', 'signature', 'rotation', 'ed25519Strict', 'x25519Strict',
    'fingerprint', 'linkToken', 'fileAddress', 'blindIndex', 'strictJSON',
    'base64url', 'envelope', 'chain', 'approval', 'keyring', 'link', 'linkChain',
    'rotationChain', 'rotationLink', 'followPin',
  ];
  const unhandled = Object.keys(vf).filter((k) => !handled.includes(k));
  assert.deepEqual(unhandled, []);
});

// Keys with a leading zero byte. Linux WebKit runs WebCrypto on libgcrypt,
// which refuses such a key from PKCS#8 or SPKI (see the comment above
// X25519_PKCS8_PREFIX in e2e.mjs). Node does not, so withGcryptQuirks makes it,
// and these tests reach the fallbacks; browser/crypto.spec.mjs runs the same
// keys on the real thing. Pairs and wrap as in that spec.
const LZ = {
  xPriv: '00fcb6c425cf330f7482945ff7882232ebb875c68eb1d3212f068c7df365a938',
  xPub: '00ddfa1d09ac3b45b3f0323f51dc5cd11d0a604551dd0885de0041ddb0b68e1f',
  edSeed: '002e61831ef4b83516a1de4106753b70b72c99c8c0951722708d7e8a13aec83d',
  edPub: '00fc0255ade803b0bb62f60ce48c78cd3d7f5ee8b5bb29567635e23317ea0e97',
  wrapped:
    '0100714df6c3410642fc546607af242187ffab4ba37721f2db639f0af981aade463c8a335112a04f4d9218be80f9944d85970993738258eed140a6791180c36f392cb6230ba6d2723ac82c36c3d07c9ddb',
  sig: '3f07dc63e78a017338eccad4b772ae58ad45b7a3c6c5a74cbfc670e426bc8d3759148e098669a2900d8904a11ae2dabcbd911530d34633d5fd4d992a7e9a530e',
  key: '07'.repeat(32),
  ctx: { purpose: 'test', artifact: 'a1', epoch: 1, recipientId: 'u1' },
};
const X25519_PKCS8_PREFIX = '302e020100300506032b656e04220420';

// withGcryptQuirks runs fn with Node's WebCrypto refusing a PKCS#8 or SPKI
// import whose key starts with a zero byte. failPkcs8, when set, refuses every
// PKCS#8 import with that error instead. emptyX, when set, exports every
// Ed25519 JWK with an empty x, as WebKit does when it cannot derive the
// public key.
async function withGcryptQuirks(fn, { failPkcs8, emptyX } = {}) {
  const { subtle } = crypto;
  const realImport = subtle.importKey.bind(subtle);
  const realExport = subtle.exportKey.bind(subtle);
  const formats = [];
  subtle.importKey = async (format, data, ...rest) => {
    formats.push(format);
    if (format === 'pkcs8' && failPkcs8) throw failPkcs8;
    if ((format === 'pkcs8' || format === 'spki') && new Uint8Array(data).at(-32) === 0) {
      throw new DOMException('Data provided to an operation does not meet requirements', 'DataError');
    }
    return realImport(format, data, ...rest);
  };
  subtle.exportKey = async (format, key) => {
    const out = await realExport(format, key);
    if (format === 'jwk' && out.crv === 'Ed25519' && emptyX) out.x = '';
    return out;
  };
  try {
    return await fn(formats);
  } finally {
    delete subtle.importKey;
    delete subtle.exportKey;
  }
}

describe('leading zero bytes', () => {
  const ctx = { ...LZ.ctx, recipientPub: hex(LZ.xPub) };
  const body = new TextEncoder().encode('body');

  test('x25519Pkcs8 sets the low bit of the first scalar byte, and changes nothing else', async () => {
    for (const first of [0x00, 0x01, 0xf8, 0xff]) {
      const raw = hex(LZ.xPriv);
      raw[0] = first;
      const before = toHex(raw);
      const der = e2e.x25519Pkcs8(raw);
      assert.equal(toHex(raw), before, 'the input is not edited');
      assert.equal(toHex(der), X25519_PKCS8_PREFIX + toHex([first | 1]) + before.slice(2));
      // X25519 clears that bit before use, so the key is the same key.
      const plain = await crypto.subtle.importKey('pkcs8', hex(X25519_PKCS8_PREFIX + before), 'X25519', true, ['deriveBits']);
      const { x } = await crypto.subtle.exportKey('jwk', plain);
      assert.equal(toHex((await e2e.importX25519PrivateKey(raw)).publicKey), toHex(e2e.unb64(x)));
    }
  });

  test('the keys and the wrap check out on Node as they are', async () => {
    assert.equal(toHex((await e2e.importX25519PrivateKey(hex(LZ.xPriv))).publicKey), LZ.xPub);
    assert.equal(toHex(await e2e.unwrap(hex(LZ.xPriv), ctx, hex(LZ.wrapped))), LZ.key);
    assert.equal(toHex(await e2e.ed25519PublicKey(hex(LZ.edSeed))), LZ.edPub);
    assert.equal(toHex(await e2e.sign(hex(LZ.edSeed), 'test', body)), LZ.sig);
  });

  test('X25519: under the quirks, the private key imports, and wraps to and from it open', async () => {
    await withGcryptQuirks(async () => {
      const priv = hex(LZ.xPriv);
      const imported = await e2e.importX25519PrivateKey(priv);
      assert.equal(toHex(imported.publicKey), LZ.xPub);
      assert.equal(toHex(await e2e.unwrap(imported, ctx, hex(LZ.wrapped))), LZ.key);
      assert.equal(toHex(await e2e.unwrap(priv, ctx, hex(LZ.wrapped))), LZ.key);
      assert.equal(toHex(await e2e.unwrap(priv, ctx, await e2e.wrap(ctx, hex(LZ.key)))), LZ.key);
      await e2e.checkPublicKeys(hex(LZ.xPub), hex(LZ.edPub));
    });
  });

  test('Ed25519: under the quirks, the seed signs, verifies, and derives its public key', async () => {
    await withGcryptQuirks(async () => {
      const seed = hex(LZ.edSeed);
      const key = await e2e.importEd25519SigningKey(seed);
      assert.equal(key.extractable, false);
      assert.deepEqual(key.usages, ['sign']);
      assert.equal(toHex(await e2e.sign(key, 'test', body)), LZ.sig);
      assert.equal(toHex(await e2e.sign(seed, 'test', body)), LZ.sig);
      assert.equal(await e2e.verify(hex(LZ.edPub), 'test', body, hex(LZ.sig)), true);
      assert.equal(toHex(await e2e.ed25519PublicKey(seed)), LZ.edPub);
    });
  });

  test('Ed25519: a seed with no leading zero takes PKCS#8, and its failure is not hidden', async () => {
    const seed = hex(LZ.edSeed);
    seed[0] = 1;
    const formats = await withGcryptQuirks(async (f) => {
      await e2e.importEd25519SigningKey(seed);
      return f;
    });
    assert.deepEqual(formats, ['pkcs8']);
    const injected = new Error('injected pkcs8 failure');
    await withGcryptQuirks(async (f) => {
      await assert.rejects(e2e.importEd25519SigningKey(seed), (err) => err === injected);
      assert.deepEqual(f, ['pkcs8'], 'and no fallback is tried');
      await assert.rejects(e2e.ed25519PublicKey(seed), (err) => err === injected, 'nor by the slow fallback');
    }, { failPkcs8: injected });
  });

  // RFC 8032 section 7.1, tests 1 to 3, and the zero-led pair: with no x from
  // WebCrypto, the public key comes from ed25519PublicKeyFromSeed alone.
  test('ed25519PublicKey: the fallback gives the RFC 8032 public keys', async () => {
    const cases = [
      ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'],
      ['4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'],
      ['c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7', 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025'],
      [LZ.edSeed, LZ.edPub],
    ];
    await withGcryptQuirks(async () => {
      for (const [seed, pub] of cases) assert.equal(toHex(await e2e.ed25519PublicKey(hex(seed))), pub, seed);
    }, { emptyX: true });
  });

  test('ed25519PublicKey: the fallback agrees with WebCrypto on random seeds', async () => {
    const seeds = Array.from({ length: 32 }, () => crypto.getRandomValues(new Uint8Array(32)));
    const want = await Promise.all(seeds.map((s) => e2e.ed25519PublicKey(s).then(toHex)));
    await withGcryptQuirks(async () => {
      for (const [i, s] of seeds.entries()) assert.equal(toHex(await e2e.ed25519PublicKey(s)), want[i], toHex(s));
    }, { emptyX: true });
  });

  // The seed imports and the export succeeds, so this reaches the length
  // check, not the catch.
  test('ed25519PublicKey: an empty x from WebCrypto is not taken as the key', async () => {
    const seed = hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    await withGcryptQuirks(async () => {
      assert.equal(toHex(await e2e.ed25519PublicKey(seed)), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    }, { emptyX: true });
  });
});
