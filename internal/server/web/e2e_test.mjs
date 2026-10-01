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
import { test } from 'node:test';
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
// openEnvelope.
test('envelope strictness', async () => {
  const textEncoder = new TextEncoder();
  const { seed, pub } = await e2e.generateEd25519();

  async function envelopeFor(purpose, body) {
    return e2e.newEnvelope(seed, 'user-1', purpose, textEncoder.encode(body));
  }

  const vouchBody = `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef"}`;
  const env = await envelopeFor('vouch', vouchBody);
  const body = await e2e.openEnvelope(env, pub, 'vouch');
  assert.equal(body.artifact, 'a1');

  const duplicate = await envelopeFor(
    'vouch',
    `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef","manifest":"beefdead"}`,
  );
  await assertThrows(() => e2e.openEnvelope(duplicate, pub, 'vouch'), e2e.FormatError);

  const caseVariant = await envelopeFor(
    'manifest',
    `{"v":1,"artifact":"a1","version":"v1","epoch":3,"Files":[],"files":[]}`,
  );
  await assertThrows(() => e2e.openEnvelope(caseVariant, pub, 'manifest'), e2e.FormatError);

  const unknown = await envelopeFor(
    'vouch',
    `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef","extra":"nope"}`,
  );
  await assertThrows(() => e2e.openEnvelope(unknown, pub, 'vouch'), e2e.FormatError);

  const missing = await envelopeFor('vouch', `{"v":1,"artifact":"a1","version":"v1"}`);
  await assertThrows(() => e2e.openEnvelope(missing, pub, 'vouch'), e2e.FormatError);

  const trailing = await envelopeFor(
    'vouch',
    `{"v":1,"artifact":"a1","version":"v1","manifest":"deadbeef"} garbage`,
  );
  await assertThrows(() => e2e.openEnvelope(trailing, pub, 'vouch'), e2e.FormatError);

  const wrongVersion = await envelopeFor(
    'vouch',
    `{"v":2,"artifact":"a1","version":"v1","manifest":"deadbeef"}`,
  );
  await assertThrows(() => e2e.openEnvelope(wrongVersion, pub, 'vouch'), e2e.FormatError);

  await assertThrows(() => e2e.openEnvelope(env, pub, 'manifest'), e2e.DecryptError);

  const badSig = { ...env, sig: e2e.b64(e2e.fromHex('00'.repeat(64))) };
  await assertThrows(() => e2e.openEnvelope(badSig, pub, 'vouch'), e2e.DecryptError);

  // A rotation envelope with no newSig at all.
  // The new key's seed is deliberately unused: this envelope is never
  // signed with it, which is exactly the "missing newSig" condition.
  const { pub: newPub } = await e2e.generateEd25519();
  const { pub: x25519Pub } = await e2e.generateX25519();
  const rotationBody = JSON.stringify({
    v: 1, user: 'user-1', seq: 1,
    old: { x25519: e2e.b64(x25519Pub), ed25519: e2e.b64(pub) },
    new: { x25519: e2e.b64(x25519Pub), ed25519: e2e.b64(newPub) },
  });
  const noNewSig = await envelopeFor('rotation', rotationBody);
  await assertThrows(() => e2e.openRotation(noNewSig, pub), e2e.FormatError);
});

test('rotation', async () => {
  for (const v of vf.rotation) {
    const env = {
      body: e2e.b64(hex(v.body)), sig: e2e.b64(hex(v.sig)), signer: v.signer,
      newSig: e2e.b64(hex(v.newSig)),
    };
    const body = await e2e.openRotation(env, hex(v.oldPub));
    assert.equal(body.user, 'user-1', v.name);

    for (const neg of v.negative) {
      const useEnv = { ...env };
      if (neg.newSig !== undefined) useEnv.newSig = e2e.b64(hex(neg.newSig));
      await assertThrows(() => e2e.openRotation(useEnv, hex(v.oldPub)));
    }
  }
});

test('ed25519Strict', async () => {
  for (const v of vf.ed25519Strict) {
    const pub = hex(v.pub);
    assert.equal(pub.length, 32, v.name);
    if (v.sig) {
      // A genuine key, with a non-canonical signature.
      const ok = await e2e.verify(pub, v.purpose, hex(v.body), hex(v.sig));
      assert.equal(ok, false, `${v.name}: ${v.why}`);
      continue;
    }
    // A small-order key must fail on its own, for any purpose, body, and
    // signature.
    await assertThrows(
      () => e2e.checkPublicKeys(new Uint8Array(32).fill(1), pub),
      e2e.FormatError,
    );
    const sig = new Uint8Array(64);
    const ok = await e2e.verify(pub, 'manifest', new TextEncoder().encode('body'), sig);
    assert.equal(ok, false, `${v.name}: ${v.why}`);
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
  }
});

test('blindIndex', async () => {
  for (const v of vf.blindIndex) {
    assert.equal(await e2e.blindIndex(hex(v.indexKey), v.type, v.value), v.want, v.name);
  }
});

test('vectors.json has no section this file does not check', () => {
  const handled = [
    'enc', 'derive', 'argon2', 'recoveryCode', 'apiKey', 'akCommit', 'seal',
    'blob', 'wrap', 'signature', 'rotation', 'ed25519Strict', 'fingerprint',
    'linkToken', 'fileAddress', 'blindIndex',
  ];
  const unhandled = Object.keys(vf).filter((k) => !handled.includes(k));
  assert.deepEqual(unhandled, []);
});
