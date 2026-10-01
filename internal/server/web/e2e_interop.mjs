#!/usr/bin/env node
// e2e_interop.mjs — cross-language agreement check with real randomness, run
// from internal/e2e/interop_test.go in both directions:
//
//   node e2e_interop.mjs emit        prints fresh JSON made with this module
//   node e2e_interop.mjs check FILE  verifies/opens every item in FILE,
//                                    which may have been emitted by Go
//
// The JSON shape is documented in internal/e2e/testdata/README.md. Every
// byte value is hex, matching vectors.json's convention.
import { readFileSync } from 'node:fs';
import * as e2e from './e2e.mjs';
import { loadArgon2 } from './argon2.mjs';
import './vendor/wasm_exec.js'; // Side effect: defines globalThis.Go.

const { toHex: hex, fromHex: unhex } = e2e;

const wasmBytes = readFileSync(new URL('./vendor/argon2.wasm', import.meta.url));
const argon2id = await loadArgon2({ wasmBytes, goClass: globalThis.Go });

const BLOB_CTX = { artifact: 'interop-artifact', version: 'interop-version', kind: 'content', name: 'interop.txt' };
const WRAP_CTX_BASE = { purpose: 'ak', artifact: 'interop-artifact', epoch: 7, recipientId: 'interop-user' };

// randomBytes fills n bytes in chunks, since getRandomValues refuses more
// than 65,536 bytes per call — relevant here because interop exercises a
// multi-chunk blob plaintext larger than that.
function randomBytes(n) {
  const b = new Uint8Array(n);
  for (let offset = 0; offset < n; offset += 65536) {
    crypto.getRandomValues(b.subarray(offset, Math.min(offset + 65536, n)));
  }
  return b;
}

const textEncoder = new TextEncoder();

async function emit() {
  const sealKey = randomBytes(32);
  const sealFields = ['mk'];
  const sealPt = randomBytes(40);
  const sealed = await e2e.seal(sealKey, sealFields, sealPt);

  const blobAk = randomBytes(32);
  const blobPt = randomBytes(200);
  const blob = await e2e.sealBlob(blobAk, BLOB_CTX, blobPt);

  const multiAk = randomBytes(32);
  const multiPt = randomBytes(2 * e2e.BLOB_CHUNK_SIZE + 1000); // several chunks
  const multiBlob = await e2e.sealBlob(multiAk, BLOB_CTX, multiPt);

  const { priv: recipientPriv, pub: recipientPub } = await e2e.generateX25519();
  const wrapKey = randomBytes(32);
  const wrapCtx = { ...WRAP_CTX_BASE, recipientPub: hex(recipientPub) };
  const wrapped = await e2e.wrap({ ...WRAP_CTX_BASE, recipientPub }, wrapKey);

  const { seed, pub } = await e2e.generateEd25519();
  const sigBody = textEncoder.encode('{"v":1,"artifact":"interop-artifact"}');
  const sigPurpose = 'manifest';
  const sig = await e2e.sign(seed, sigPurpose, sigBody);
  const envelope = await e2e.newEnvelope(seed, 'interop-user', sigPurpose, sigBody);

  const { code, display } = e2e.newRecoveryCode();
  const recoveryKek = await e2e.recoveryKek(code);

  const apiKey = e2e.newApiKey();
  const apiKeyKek = await e2e.apiKeyKek(apiKey.keySecret, apiKey.keyId);

  const akCommitAk = randomBytes(32);
  const akCommit = await e2e.akCommit(akCommitAk, 'interop-artifact', 9);

  const rotation = await emitRotation();

  const email = '  Interop@Example.COM ';
  const stretchParams = { alg: 'argon2id', m: 65536, t: 3, p: 1, salt: randomBytes(16) };
  const argonSalt = await e2e.argonSalt(email, stretchParams.salt);
  const password = textEncoder.encode('correct horse battery staple');
  const stretched = await e2e.stretch(password, email, stretchParams, argon2id);
  const { authKey, kek } = await e2e.passwordKeys(stretched);

  return {
    seal: { key: hex(sealKey), fields: sealFields.map((f) => hex(textEncoder.encode(f))), pt: hex(sealPt), sealed: hex(sealed) },
    blob: { ak: hex(blobAk), ctx: BLOB_CTX, pt: hex(blobPt), blob: hex(blob) },
    blobMultiChunk: { ak: hex(multiAk), ctx: BLOB_CTX, pt: hex(multiPt), blob: hex(multiBlob) },
    wrap: { ctx: wrapCtx, recipientPriv: hex(recipientPriv), key: hex(wrapKey), wrapped: hex(wrapped) },
    signature: { purpose: sigPurpose, seed: hex(seed), pub: hex(pub), body: hex(sigBody), signer: 'interop-user', sig: hex(sig), envelope },
    recoveryCode: { code: hex(code), display, kek: hex(recoveryKek) },
    apiKey: { full: apiKey.full, keyId: apiKey.keyId, authSecret: apiKey.authSecret, keySecret: hex(apiKey.keySecret), kek: hex(apiKeyKek) },
    akCommit: { ak: hex(akCommitAk), artifact: 'interop-artifact', epoch: 9, want: akCommit },
    rotation,
    stretch: {
      email, password: hex(password),
      params: { alg: stretchParams.alg, m: stretchParams.m, t: stretchParams.t, p: stretchParams.p, salt: hex(stretchParams.salt) },
      argonSalt: hex(argonSalt), stretched: hex(stretched), authKey: hex(authKey), kek: hex(kek),
    },
  };
}

// emitRotation builds a rotation envelope signed by a fresh old key and a
// fresh new key, matching RotationBody in internal/e2e/envelope.go.
async function emitRotation() {
  const old = await e2e.generateEd25519();
  const next = await e2e.generateEd25519();
  const { pub: x25519Pub } = await e2e.generateX25519();
  const body = {
    v: 1, user: 'interop-user', seq: 3,
    old: { x25519: e2e.b64(x25519Pub), ed25519: e2e.b64(old.pub) },
    new: { x25519: e2e.b64(x25519Pub), ed25519: e2e.b64(next.pub) },
  };
  const bodyBytes = textEncoder.encode(JSON.stringify(body));
  const env = await e2e.signRotation(old.seed, next.seed, 'interop-user', bodyBytes);
  return {
    oldSeed: hex(old.seed), oldPub: hex(old.pub), newSeed: hex(next.seed), newPub: hex(next.pub),
    signer: 'interop-user', body: hex(bodyBytes), sig: hex(e2e.unb64(env.sig)), newSig: hex(e2e.unb64(env.newSig)),
  };
}

// check verifies/opens every item in data (the shape emit() produces,
// whichever language made it), collecting every failure rather than
// stopping at the first.
async function check(data) {
  const failures = [];
  async function expect(name, fn) {
    try {
      if (!(await fn())) failures.push(`${name}: result did not match`);
    } catch (err) {
      failures.push(`${name}: ${err.name ?? 'Error'}: ${err.message}`);
    }
  }

  await expect('seal', async () => {
    const pt = await e2e.open(unhex(data.seal.key), data.seal.fields.map(unhex), unhex(data.seal.sealed));
    return hex(pt) === data.seal.pt;
  });

  for (const key of ['blob', 'blobMultiChunk']) {
    await expect(key, async () => {
      const v = data[key];
      const pt = await e2e.openBlob(unhex(v.ak), v.ctx, unhex(v.blob));
      return hex(pt) === v.pt;
    });
  }

  await expect('wrap', async () => {
    const ctx = { ...data.wrap.ctx, recipientPub: unhex(data.wrap.ctx.recipientPub) };
    const key = await e2e.unwrap(unhex(data.wrap.recipientPriv), ctx, unhex(data.wrap.wrapped));
    return hex(key) === data.wrap.key;
  });

  await expect('signature: verify', async () => {
    const v = data.signature;
    return e2e.verify(unhex(v.pub), v.purpose, unhex(v.body), unhex(v.sig));
  });
  await expect('signature: envelope', async () => {
    const v = data.signature;
    return e2e.verifyEnvelope(unhex(v.pub), v.purpose, v.envelope);
  });

  await expect('recoveryCode', async () => {
    const v = data.recoveryCode;
    const code = e2e.parseRecoveryCode(v.display);
    if (hex(code) !== v.code) return false;
    return hex(await e2e.recoveryKek(code)) === v.kek;
  });

  await expect('apiKey', async () => {
    const v = data.apiKey;
    const parsed = e2e.parseApiKey(v.full);
    if (parsed.keyId !== v.keyId || parsed.authSecret !== v.authSecret || hex(parsed.keySecret) !== v.keySecret) {
      return false;
    }
    return hex(await e2e.apiKeyKek(parsed.keySecret, parsed.keyId)) === v.kek;
  });

  await expect('akCommit', async () => {
    const v = data.akCommit;
    return (await e2e.akCommit(unhex(v.ak), v.artifact, v.epoch)) === v.want;
  });

  await expect('rotation', async () => {
    const v = data.rotation;
    const env = {
      body: e2e.b64(unhex(v.body)), sig: e2e.b64(unhex(v.sig)), signer: v.signer,
      newSig: e2e.b64(unhex(v.newSig)),
    };
    const body = await e2e.openRotation(env, unhex(v.oldPub));
    return body.user === v.signer;
  });

  await expect('stretch', async () => {
    const v = data.stretch;
    const params = {
      alg: v.params.alg, m: v.params.m, t: v.params.t, p: v.params.p, salt: unhex(v.params.salt),
    };
    const argonSalt = await e2e.argonSalt(v.email, params.salt);
    if (hex(argonSalt) !== v.argonSalt) return false;
    const stretched = await e2e.stretch(unhex(v.password), v.email, params, argon2id);
    if (hex(stretched) !== v.stretched) return false;
    const { authKey, kek } = await e2e.passwordKeys(stretched);
    return hex(authKey) === v.authKey && hex(kek) === v.kek;
  });

  return failures;
}

async function main() {
  const [, , cmd, arg] = process.argv;
  if (cmd === 'emit') {
    process.stdout.write(JSON.stringify(await emit(), null, 2) + '\n');
    return;
  }
  if (cmd === 'check' && arg) {
    const data = JSON.parse(readFileSync(arg, 'utf8'));
    const failures = await check(data);
    for (const f of failures) console.error(f);
    if (failures.length > 0) process.exitCode = 1;
    return;
  }
  console.error('usage: e2e_interop.mjs emit | check FILE');
  process.exitCode = 2;
}

await main();
