// Fixtures shared by content_test.mjs and sw_test.mjs: file blobs sealed and
// a manifest signed by e2e.mjs itself, with overrides for each refusal.
import * as e2e from './e2e.mjs';

export const enc = new TextEncoder();

export const ARTIFACT = '11111111-1111-4111-8111-111111111111';
export const VERSION = '22222222-2222-4222-8222-222222222222';
export const USER = '33333333-3333-4333-8333-333333333333';
export const OTHER = '44444444-4444-4444-8444-444444444444';
export const APP = 'http://localhost:8080';

export function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export async function sha256Hex(bytes) {
  return e2e.toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

// fixture builds a version: file blobs sealed under a random AK and a
// manifest signed by a fresh key, with overrides for each refusal.
export async function fixture({ files, manifest = {}, signerUser = USER, ctx = {}, version = VERSION } = {}) {
  const ak = randomBytes(32);
  const key = await e2e.generateEd25519();
  const contents = files ?? {
    'index.html': '<html>hi</html>',
    'app/main.js': 'console.log(1)',
    'empty.txt': '',
  };
  const blobs = {};
  const entries = [];
  for (const [path, text] of Object.entries(contents)) {
    const blobId = e2e.toHex(randomBytes(16));
    const plain = enc.encode(text);
    const blob = await e2e.sealBlob(ak, { artifact: ARTIFACT, version, kind: 'content', name: path }, plain);
    blobs[blobId] = blob;
    entries.push({ path, blob: blobId, size: plain.length, sha256: await sha256Hex(blob) });
  }
  const body = enc.encode(
    JSON.stringify({ v: 1, artifact: ARTIFACT, version, epoch: 3, files: entries, ...manifest }),
  );
  const env = await e2e.newEnvelope(key.seed, signerUser, 'manifest', body);
  const manifestBlob = await e2e.sealBlob(
    ak,
    { artifact: ARTIFACT, version, kind: 'manifest', name: '', ...ctx },
    enc.encode(JSON.stringify(env)),
  );
  return {
    ak,
    key,
    entries,
    blobs,
    manifestBlob,
    args: {
      ak,
      artifact: ARTIFACT,
      version,
      epoch: 3,
      signer: { user: USER, ed25519: key.pub },
      manifestHash: await e2e.bodyHash(body),
      blob: manifestBlob,
    },
  };
}
