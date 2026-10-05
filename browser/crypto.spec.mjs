// Keys whose first byte is zero. Linux WebKit's WebCrypto runs on libgcrypt,
// which reads an X25519 or Ed25519 key from SPKI or PKCS#8 as a big number and
// writes it back without its leading zero bytes; the 31-byte key that is left
// is then refused, and deriveBits or sign fails. One random key in 256 starts
// with a zero byte, so these tests fix keys that do. They fail on Linux WebKit,
// which CI runs, if a key goes into WebCrypto in one of those forms; macOS
// WebKit uses CryptoKit, and passes either way.
//
// The page is served by page.route from the source tree, not by the server, so
// the tests reach e2e.mjs and keystore.mjs directly.
import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';

const WEB = new URL('../internal/server/web/', import.meta.url);
const ORIGIN = 'https://crypto.test';

// From Node's WebCrypto, by drawing keys until one fit. xPriv and xPub, and
// edSeed and edPub, are key pairs whose private and public halves both start
// with a zero byte; wrapped wraps key to xPub under ctx with an ephemeral
// public key (its bytes 1 to 32) that starts with one too; sig is edSeed's
// signature of body. edSeed2 does not start with a zero byte, but its public
// key edPub2 does.
const V = {
  xPriv: '00fcb6c425cf330f7482945ff7882232ebb875c68eb1d3212f068c7df365a938',
  xPub: '00ddfa1d09ac3b45b3f0323f51dc5cd11d0a604551dd0885de0041ddb0b68e1f',
  edSeed: '002e61831ef4b83516a1de4106753b70b72c99c8c0951722708d7e8a13aec83d',
  edPub: '00fc0255ade803b0bb62f60ce48c78cd3d7f5ee8b5bb29567635e23317ea0e97',
  edSeed2: 'e5f6327bac6ba5ae2bc161de0acf1d98ea38c3ba036a442bbf7e5a7e0a760ab2',
  edPub2: '004a9f25cddebb0868870ddd3b5c5e8c46869634b06bc515fbc35ebfaa8ed64c',
  wrapped:
    '0100714df6c3410642fc546607af242187ffab4ba37721f2db639f0af981aade463c8a335112a04f4d9218be80f9944d85970993738258eed140a6791180c36f392cb6230ba6d2723ac82c36c3d07c9ddb',
  sig: '3f07dc63e78a017338eccad4b772ae58ad45b7a3c6c5a74cbfc670e426bc8d3759148e098669a2900d8904a11ae2dabcbd911530d34633d5fd4d992a7e9a530e',
  key: '0707070707070707070707070707070707070707070707070707070707070707',
  ctx: { purpose: 'test', artifact: 'a1', epoch: 1, recipientId: 'u1' },
  body: 'body',
};

test.beforeEach(async ({ page }) => {
  await page.route(`${ORIGIN}/**`, (route) => {
    const name = new URL(route.request().url()).pathname.slice(1);
    if (name === '') return route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>crypto</title>' });
    return route.fulfill({ contentType: 'text/javascript', body: readFileSync(new URL(name, WEB)) });
  });
  await page.goto(`${ORIGIN}/`);
});

test('crypto: an X25519 key pair with leading zero bytes imports, and a wrap to it unwraps', async ({ page }) => {
  const got = await page.evaluate(async (V) => {
    const e2e = await import('/e2e.mjs');
    const ctx = { ...V.ctx, recipientPub: e2e.fromHex(V.xPub) };
    const priv = e2e.fromHex(V.xPriv);
    const imported = await e2e.importX25519PrivateKey(priv);
    const generated = await e2e.wrap(ctx, e2e.fromHex(V.key));
    return {
      pub: e2e.toHex(imported.publicKey),
      // The ephemeral key of a fixed wrap starts with a zero byte.
      fixed: e2e.toHex(await e2e.unwrap(imported, ctx, e2e.fromHex(V.wrapped))),
      // A fresh wrap to xPub, opened with the raw scalar.
      fresh: e2e.toHex(await e2e.unwrap(priv, ctx, generated)),
    };
  }, V);
  expect(got).toEqual({ pub: V.xPub, fixed: V.key, fresh: V.key });
});

test('crypto: the wrapped X25519 key store holds a private key with a leading zero byte', async ({ page }) => {
  const got = await page.evaluate(async (V) => {
    const e2e = await import('/e2e.mjs');
    const { wrapX25519, openX25519 } = await import('/keystore.mjs');
    const ctx = { ...V.ctx, recipientPub: e2e.fromHex(V.xPub) };
    const opened = await openX25519(await wrapX25519(e2e.fromHex(V.xPriv)));
    return e2e.toHex(await e2e.unwrap(opened, ctx, e2e.fromHex(V.wrapped)));
  }, V);
  expect(got).toBe(V.key);
});

test('crypto: an Ed25519 key pair with leading zero bytes signs, verifies, and derives its public key', async ({ page }) => {
  const got = await page.evaluate(async (V) => {
    const e2e = await import('/e2e.mjs');
    const body = new TextEncoder().encode(V.body);
    const seed = e2e.fromHex(V.edSeed);
    const pub = e2e.fromHex(V.edPub);
    const sig = await e2e.sign(await e2e.importEd25519SigningKey(seed), 'test', body);
    return {
      pub: e2e.toHex(await e2e.ed25519PublicKey(seed)),
      // Not compared with the fixed signature: macOS WebKit signs through
      // CryptoKit, whose Ed25519 signatures are randomized.
      fresh: await e2e.verify(pub, 'test', body, sig),
      fixed: await e2e.verify(pub, 'test', body, e2e.fromHex(V.sig)),
    };
  }, V);
  expect(got).toEqual({ pub: V.edPub, fresh: true, fixed: true });
});

// The seed imports from PKCS#8, and its public key starts with a zero byte.
test('crypto: an Ed25519 seed whose public key starts with a zero byte derives that key, and signs', async ({ page }) => {
  const got = await page.evaluate(async (V) => {
    const e2e = await import('/e2e.mjs');
    const body = new TextEncoder().encode(V.body);
    const seed = e2e.fromHex(V.edSeed2);
    const sig = await e2e.sign(await e2e.importEd25519SigningKey(seed), 'test', body);
    return {
      pub: e2e.toHex(await e2e.ed25519PublicKey(seed)),
      verified: await e2e.verify(e2e.fromHex(V.edPub2), 'test', body, sig),
    };
  }, V);
  expect(got).toEqual({ pub: V.edPub2, verified: true });
});
