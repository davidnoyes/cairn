// Tests for successor.mjs: the browser's side of the successor, against a
// fake of the server's routes and the real e2e.mjs crypto. They mirror the Go
// client's (internal/client/successor.go). Run with:
// node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { ApiError } from './account.mjs';
import { makeUser, keyStoreRecord, fakeKeyStore } from './viewer_fixture.mjs';
import * as successor from './successor.mjs';

const enc = new TextEncoder();
const dec = new TextDecoder();
const PASSWORD = 'correct horse battery staple';
const ORIGIN = 'http://localhost:8080';

const U = {};
for (const name of ['owner', 'editor', 'viewer']) U[name] = await makeUser(name);
const record = await keyStoreRecord(U.owner);
const emailOf = (u) => `${u.name}@example.com`;
const wireUser = (u) => ({ id: u.id, name: u.name, email: emailOf(u), x25519Pub: u.pair.x25519, ed25519Pub: u.pair.ed25519 });
const codeOf = (u) => e2e.successorCode(e2e.fromHex(u.fp));

// keptDecrypts records every buffer SubtleCrypto decrypt returns, with a copy
// of its bytes as returned, so a test can find a secret by value and check it
// was zeroed afterwards. restore() removes the patch.
function keptDecrypts() {
  const { subtle } = crypto;
  const realDecrypt = subtle.decrypt.bind(subtle);
  const kept = [];
  subtle.decrypt = async (...args) => {
    const pt = await realDecrypt(...args);
    kept.push({ pt, copy: new Uint8Array(pt).slice() });
    return pt;
  };
  kept.restore = () => { delete subtle.decrypt; };
  return kept;
}

const isZero = (b) => new Uint8Array(b).every((x) => x === 0);
const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// fakeStretch stands in for Argon2id: deterministic and instant.
async function fakeStretch(password, email, params) {
  const data = new Uint8Array([...enc.encode(password), 0, ...enc.encode(email), 0, ...params.salt]);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

// bundleOf is the owner's key bundle as the server holds it: MK sealed under
// the password, and EK sealed under MK.
async function bundleOf(u, password) {
  const params = { alg: 'argon2id', m: 65536, t: 3, p: 1, salt: new Uint8Array(16).fill(7) };
  const { authKey, kek } = await e2e.passwordCryptoKeys(await fakeStretch(password, emailOf(u), params), 'seal');
  const seal = await e2e.mkSealCryptoKey(u.mk);
  return {
    authKey: e2e.b64(authKey),
    bundle: {
      kdf: { alg: params.alg, m: params.m, t: params.t, p: params.p, salt: e2e.b64(params.salt) },
      mkPassword: e2e.b64(await e2e.seal(kek, ['mk'], u.mk)),
      ek: e2e.b64(await e2e.seal(seal, ['ek'], u.ek)),
    },
  };
}
const account = await bundleOf(U.owner, PASSWORD);

const reply = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

// scene is the owner signed in. s.calls holds every request with its JSON
// body; s.state is what GET /api/me/successor answers; s.fail makes a route
// answer an error instead.
function scene({ seq = 0, users = [U.editor, U.viewer], succession = null } = {}) {
  const s = { calls: [], state: { successor: null, record: null, nominatedAt: '', seq, request: null }, fail: {}, successions: succession ?? [] };
  s.fetch = async (path, init = {}) => {
    const method = init.method ?? 'GET';
    const body = init.body ? JSON.parse(init.body) : undefined;
    s.calls.push({ method, path, body });
    const failed = s.fail[`${method} ${path}`];
    if (failed) return reply(failed.status, { error: failed.error });
    switch (`${method} ${path}`) {
      case 'GET /api/me': return reply(200, { id: U.owner.id, email: emailOf(U.owner), name: 'owner' });
      case 'GET /api/me/bundle': return reply(200, account.bundle);
      case 'GET /api/users': return reply(200, [U.owner, ...users].map(wireUser));
      case 'GET /api/me/successor': return reply(200, s.state);
      case 'PUT /api/me/successor': return reply(200, { seq: s.state.seq + 1 });
      case 'DELETE /api/me/successor': return reply(200, { seq: s.state.seq + 1 });
      case 'DELETE /api/me/successor/request': return reply(200, { ok: true });
      case 'PUT /api/me/notice-email': return body.email === '' ? reply(200, { ok: true }) : reply(202, { status: 'check-email' });
      case 'GET /api/successions': return reply(200, s.successions);
      default:
        if (/^POST \/api\/successions\/[^/]+\/request$/.test(`${method} ${path}`)) return reply(200, { requestedAt: '2026-10-05T10:00:00Z', releaseAt: '2026-10-19T10:00:00Z' });
        return reply(404, { error: `no route ${method} ${path}` });
    }
  };
  s.deps = { fetch: s.fetch, keyStore: fakeKeyStore(record), stretch: fakeStretch, origin: ORIGIN };
  s.writes = () => s.calls.filter((c) => c.method !== 'GET');
  return s;
}

const bodyOf = (env) => JSON.parse(dec.decode(e2e.unb64(env.body)));
const put = (s) => s.calls.find((c) => c.method === 'PUT' && c.path === '/api/me/successor');

test('myCode is the code of the fingerprint of the user\'s own keys', async () => {
  assert.equal(await successor.myCode(record), codeOf(U.owner));
});

test('status reads the successor, the record, the seq and any request', async () => {
  const s = scene({ seq: 3 });
  assert.deepEqual(await successor.status(s.deps), s.state);
  assert.deepEqual(s.calls.map((c) => `${c.method} ${c.path}`), ['GET /api/me/successor']);
});

test('nominate signs a nominate record one seq on, wraps EK to the successor, and sends both', async () => {
  const s = scene({ seq: 4 });
  const out = await successor.nominate(s.deps, { who: 'Editor@Example.com', code: codeOf(U.editor), password: PASSWORD });
  assert.equal(out.seq, 5);
  assert.equal(out.user.id, U.editor.id);
  const sent = put(s).body;
  assert.equal(sent.authKey, account.authKey);
  assert.equal(sent.successor, U.editor.id);
  assert.equal(sent.record.signer, U.owner.id);
  assert.equal(await e2e.verifyEnvelope(U.owner.ed.pub, 'successor', sent.record), true);
  assert.deepEqual(bodyOf(sent.record), { v: 1, seq: 5, user: U.owner.id, successor: U.editor.id, successorFp: U.editor.fp, action: 'nominate' });
  const wrapped = e2e.unb64(sent.wrapped);
  assert.equal(wrapped.length, 81);
  const ctx = { purpose: 'ek', artifact: U.owner.id, epoch: 0, recipientId: U.editor.id, recipientPub: U.editor.x.pub };
  const ek = await e2e.unwrap(await e2e.importX25519PrivateKey(U.editor.x.priv), ctx, wrapped);
  assert.deepEqual(ek, U.owner.ek);
});

test('nominate zeroes MK and EK once it has wrapped EK', async () => {
  const s = scene();
  const kept = keptDecrypts();
  try {
    await successor.nominate(s.deps, { who: emailOf(U.editor), code: codeOf(U.editor), password: PASSWORD });
  } finally {
    kept.restore();
  }
  assert.ok(kept.some((k) => sameBytes(k.copy, U.owner.ek)), 'EK was never decrypted');
  for (const k of kept) assert.ok(isZero(k.pt), 'a decrypted secret was left in memory');
});

test('nominate finds the successor by ID too', async () => {
  const s = scene();
  const out = await successor.nominate(s.deps, { who: U.viewer.id, code: codeOf(U.viewer), password: PASSWORD });
  assert.equal(out.user.email, emailOf(U.viewer));
  assert.equal(put(s).body.successor, U.viewer.id);
});

test('nominate refuses a code the served keys do not produce, and sends nothing', async () => {
  const s = scene();
  await assert.rejects(
    successor.nominate(s.deps, { who: emailOf(U.editor), code: codeOf(U.viewer), password: PASSWORD }),
    /The code does not match the keys the server lists for editor@example\.com/,
  );
  assert.deepEqual(s.writes(), []);
  assert.equal(s.calls.some((c) => c.path === '/api/me/bundle'), false);
});

test('nominate refuses a code that differs in the last byte it names', async () => {
  const s = scene();
  const fp = e2e.fromHex(U.editor.fp);
  fp[9] ^= 1;
  await assert.rejects(
    successor.nominate(s.deps, { who: emailOf(U.editor), code: e2e.successorCode(fp), password: PASSWORD }),
    /does not match/,
  );
  assert.deepEqual(s.writes(), []);
});

test('nominate refuses a malformed code in plain words, before any request', async () => {
  const s = scene();
  await assert.rejects(successor.nominate(s.deps, { who: emailOf(U.editor), code: 'not a code', password: PASSWORD }), /not a successor code/);
  assert.deepEqual(s.calls, []);
});

test('nominate refuses the user themselves, and a user the directory does not list', async () => {
  const s = scene();
  await assert.rejects(successor.nominate(s.deps, { who: emailOf(U.owner), code: codeOf(U.owner), password: PASSWORD }), /your own successor/);
  await assert.rejects(successor.nominate(s.deps, { who: 'nobody@example.com', code: codeOf(U.editor), password: PASSWORD }), /No user with that email/);
  assert.deepEqual(s.writes(), []);
});

test('nominate with a wrong password sends nothing', async () => {
  const s = scene();
  await assert.rejects(successor.nominate(s.deps, { who: emailOf(U.editor), code: codeOf(U.editor), password: 'not it' }), /password is wrong/);
  assert.deepEqual(s.writes(), []);
});

test('nominate says another device changed the successor on a stale seq, and passes other refusals on', async () => {
  const s = scene();
  s.fail['PUT /api/me/successor'] = { status: 409, error: 'seq must be 3' };
  await assert.rejects(
    successor.nominate(s.deps, { who: emailOf(U.editor), code: codeOf(U.editor), password: PASSWORD }),
    /another device changed your successor.*try again/i,
  );
  s.fail['PUT /api/me/successor'] = { status: 409, error: 'your successor was released' };
  await assert.rejects(
    successor.nominate(s.deps, { who: emailOf(U.editor), code: codeOf(U.editor), password: PASSWORD }),
    (e) => e instanceof ApiError && e.status === 409 && /released/.test(e.message),
  );
});

test('remove signs a remove record for the current successor with an empty fingerprint', async () => {
  const s = scene({ seq: 2 });
  s.state.successor = wireUser(U.editor);
  const gone = await successor.remove(s.deps);
  assert.equal(gone.id, U.editor.id);
  const del = s.calls.find((c) => c.method === 'DELETE' && c.path === '/api/me/successor');
  assert.equal(await e2e.verifyEnvelope(U.owner.ed.pub, 'successor', del.body.record), true);
  assert.deepEqual(bodyOf(del.body.record), { v: 1, seq: 3, user: U.owner.id, successor: U.editor.id, successorFp: '', action: 'remove' });
});

test('remove with no successor says so and sends nothing; a stale seq is mapped', async () => {
  const s = scene();
  await assert.rejects(successor.remove(s.deps), /no successor/);
  assert.deepEqual(s.writes(), []);
  s.state.successor = wireUser(U.editor);
  s.fail['DELETE /api/me/successor'] = { status: 409, error: 'seq must be 1' };
  await assert.rejects(successor.remove(s.deps), /another device changed your successor/i);
});

test('refuse, setNoticeEmail, successions and requestAccess call their routes', async () => {
  const s = scene({ succession: [{ user: wireUser(U.editor), requestedAt: '', releaseAt: '', released: false }] });
  await successor.refuse(s.deps);
  assert.equal(await successor.setNoticeEmail(s.deps, 'me@home.example'), true);
  assert.equal(await successor.setNoticeEmail(s.deps, ''), false);
  assert.equal((await successor.successions(s.deps)).length, 1);
  const out = await successor.requestAccess(s.deps, U.editor.id);
  assert.equal(out.releaseAt, '2026-10-19T10:00:00Z');
  assert.deepEqual(s.calls.map((c) => [c.method, c.path, c.body]), [
    ['DELETE', '/api/me/successor/request', undefined],
    ['PUT', '/api/me/notice-email', { email: 'me@home.example' }],
    ['PUT', '/api/me/notice-email', { email: '' }],
    ['GET', '/api/successions', undefined],
    ['POST', `/api/successions/${U.editor.id}/request`, undefined],
  ]);
});

test('bannerView shows nothing with no request, and the rotate banner alone once the user must rotate', () => {
  assert.deepEqual(successor.bannerView({ succession: null, mustRotate: false }), { banner: false, refuse: false, rotate: false, text: '' });
  assert.deepEqual(successor.bannerView({ succession: null, mustRotate: true }), { banner: false, refuse: false, rotate: true, text: '' });
});

test('bannerView offers Refuse on a pending request, and names the deactivation when there is one', () => {
  const pending = { successor: { name: 'Heir', email: 'heir@example.com' }, requestedAt: '2026-10-01T10:00:00Z', releaseAt: '2026-10-15T10:00:00Z', released: false };
  assert.deepEqual(successor.bannerView({ succession: pending, mustRotate: false }), {
    banner: true, refuse: true, rotate: false,
    text: 'Heir (heir@example.com) asked for access to your artifacts on 2026-10-01. They get it on 2026-10-15 unless you refuse.',
  });
  const dead = successor.bannerView({ succession: { ...pending, successor: { email: 'heir@example.com' }, deactivatedAt: '2026-10-02T09:00:00Z' } });
  assert.equal(dead.text, 'heir@example.com asked for access to your artifacts on 2026-10-01. They get it on 2026-10-15 unless you refuse. An administrator deactivated your account on 2026-10-02.');
});

test('bannerView offers no Refuse once released, and says the successor can read', () => {
  const released = { successor: { email: 'heir@example.com' }, requestedAt: '2026-10-01T10:00:00Z', releaseAt: '2026-10-15T10:00:00Z', released: true };
  assert.deepEqual(successor.bannerView({ succession: released, mustRotate: true }), {
    banner: true, refuse: false, rotate: true, text: 'heir@example.com can now read your artifacts.',
  });
});

test('refusalView names who asked and when, and the deactivation only when there was one', () => {
  const answer = { successor: { name: 'Heir', email: 'heir@example.com' }, requestedAt: '2026-10-01T10:00:00Z' };
  assert.deepEqual(successor.refusalView(answer), {
    done: 'You refused the request that Heir (heir@example.com) made on 2026-10-01. They stay your successor; to remove them, use the Successor tab or run cairn successor remove.',
    deactivated: '',
  });
  const dead = successor.refusalView({ ...answer, successor: { email: 'heir@example.com' }, deactivatedAt: '2026-10-02T09:00:00Z' });
  assert.match(dead.done, /^You refused the request that heir@example\.com made on 2026-10-01\. /);
  assert.equal(dead.deactivated, 'An administrator deactivated your account on 2026-10-02, while the request was pending.');
});
