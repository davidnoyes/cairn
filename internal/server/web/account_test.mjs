// Tests for account.mjs: the browser account flows, against a fake server
// that stores what sign-up sends and answers the way Cairn's handlers do, a
// fast fake stretch function, and the real e2e.mjs crypto. Run with:
// node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import * as account from './account.mjs';
import { openX25519 } from './keystore.mjs';

const enc = new TextEncoder();
const STRONG = 'correct horse battery staple';
const NEW_STRONG = 'a different long passphrase 42';

// fakeStretch stands in for Argon2id: deterministic and instant. It still
// binds the email and salt, so a wrong email or password changes the result.
async function fakeStretch(password, email, params) {
  const data = new Uint8Array([...enc.encode(password), 0, ...enc.encode(email), 0, ...params.salt]);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

// fakeStrength scores by length: under 12 characters is 2, else 3.
function fakeStrength(password, userInputs) {
  fakeStrength.calls.push({ password, userInputs });
  return { score: password.length < 12 ? 2 : 3, feedback: { warning: 'too short', suggestions: ['add words'] } };
}
fakeStrength.calls = [];

function fakeKeyStore() {
  return {
    saved: [],
    cleared: 0,
    async save(record) { this.saved.push(record); },
    async clear() { this.cleared++; },
  };
}

const json = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

// fakeServer records every request in server.log and answers each endpoint
// from an in-memory account table.
function fakeServer({ signupStatus = 202 } = {}) {
  const server = { log: [], accounts: new Map(), tokens: new Map(), requests: new Map(), tamperMKPassword: false };
  server.fetch = async (path, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : null;
    server.log.push({ path, method: options.method, headers: options.headers, body });
    switch (path) {
      case '/api/auth/signup':
        if (signupStatus !== 202) return json(signupStatus, { error: 'sign-up is not open for this address' });
        server.accounts.set(body.email, { id: 'u-' + body.email, name: body.name, authKey: body.authKey, bundle: body.bundle });
        server.current = body.email;
        return json(202, { status: 'check-email' });
      case '/api/auth/prelogin': {
        const a = server.accounts.get(body.email);
        return json(200, a ? a.bundle.kdf : { alg: 'argon2id', m: 65536, t: 3, p: 1, salt: e2e.b64(new Uint8Array(16)) });
      }
      case '/api/auth/login': {
        const a = server.accounts.get(body.email);
        if (!a || a.authKey !== body.authKey) return json(401, { error: 'invalid email or password' });
        const bundle = { ...a.bundle };
        if (server.tamperMKPassword) bundle.mkPassword = bundle.mkRecovery;
        return json(200, { user: { id: a.id, email: body.email, name: a.name, isAdmin: false }, bundle });
      }
      case '/api/auth/logout':
        return json(200, { ok: true });
      case '/api/auth/verify':
        return body.token === 'good-token' ? json(200, { ok: true }) : json(400, { error: 'invalid or expired token' });
      case '/api/auth/forgot':
        return json(202, { status: 'check-email' });
      case '/api/auth/reset/begin': {
        const a = [...server.accounts.values()].find((x) => x.id === server.tokens.get(body.token));
        if (!a) return json(400, { error: 'invalid or expired token' });
        const { mkRecovery, x25519Pub, ed25519Pub, ed25519Priv } = a.bundle;
        return json(200, { id: a.id, email: [...server.accounts.keys()].find((k) => server.accounts.get(k) === a), mkRecovery, x25519Pub, ed25519Pub, ed25519Priv });
      }
      case '/api/auth/reset/complete': {
        const id = server.tokens.get(body.token);
        const email = [...server.accounts.keys()].find((k) => server.accounts.get(k).id === id);
        if (!email) return json(400, { error: 'invalid or expired token' });
        const a = server.accounts.get(email);
        if (body.mode === 'new') {
          server.accounts.set(email, { ...a, authKey: body.authKey, bundle: body.bundle });
        } else {
          const proofBody = enc.encode(JSON.stringify({ v: 1, user: a.id, token: await tokenHash(body.token) }));
          const ok = await e2e.verify(e2e.unb64(a.bundle.ed25519Pub), 'reset', proofBody, e2e.unb64(body.proof));
          if (!ok) return json(403, { error: 'invalid proof' });
          server.accounts.set(email, { ...a, authKey: body.authKey, bundle: { ...a.bundle, kdf: body.kdf, mkPassword: body.mkPassword } });
        }
        return json(200, { ok: true });
      }
      // A refusal is pending for an account when server.requests holds its
      // requestedAt. The proof is checked as refusalProof does; the key path
      // as handleRefuse does, with a 409 when nothing is pending.
      case '/api/auth/refuse/begin': {
        const a = server.accounts.get(body.email);
        const requestedAt = server.requests.get(body.email);
        if (!a || !requestedAt) return json(200, { id: 'fake', mkRecovery: e2e.b64(new Uint8Array(60)), ed25519Priv: e2e.b64(new Uint8Array(60)), requestedAt: '2026-01-01T00:00:00Z' });
        return json(200, { id: a.id, mkRecovery: a.bundle.mkRecovery, ed25519Priv: a.bundle.ed25519Priv, requestedAt });
      }
      case '/api/auth/refuse': {
        const a = server.accounts.get(body.email);
        if (!a) return json(401, { error: 'invalid email or password' });
        if (body.proof) {
          const parsed = body.proof.body && JSON.parse(new TextDecoder().decode(e2e.unb64(body.proof.body)));
          const ok = body.proof.signer === a.id && await e2e.verifyEnvelope(e2e.unb64(a.bundle.ed25519Pub), 'refusal', body.proof)
            && parsed.user === a.id && (!server.requests.get(body.email) || parsed.requestedAt === server.requests.get(body.email));
          if (!ok) return json(401, { error: 'invalid email or password' });
        } else if (body.authKey !== a.authKey) {
          return json(401, { error: 'invalid email or password' });
        }
        const requestedAt = server.requests.get(body.email);
        if (!requestedAt) return json(409, { error: 'no succession request is pending' });
        return json(200, { refused: true, successor: { name: 'Bea', email: 'bea@example.com' }, requestedAt, deactivatedAt: '' });
      }
      // The signed-in account's endpoints act on server.current, the last
      // account to sign up. Each fresh-password check answers as
      // requireFreshAuthKey does.
      case '/api/me': {
        const a = server.accounts.get(server.current);
        return json(200, { id: a.id, email: server.current, name: a.name, isAdmin: false });
      }
      case '/api/me/bundle':
        return json(200, server.accounts.get(server.current).bundle);
      case '/api/keys':
      case '/api/me/password':
      case '/api/me/recovery': {
        const a = server.accounts.get(server.current);
        if (body.authKey !== a.authKey) return json(401, { error: 'invalid password' });
        if (path === '/api/keys') return json(201, { id: body.keyId, name: body.name, device: body.device, createdAt: 'now' });
        if (path === '/api/me/password') {
          server.accounts.set(server.current, { ...a, authKey: body.newAuthKey, bundle: { ...a.bundle, kdf: body.kdf, mkPassword: body.mkPassword } });
        } else {
          server.accounts.set(server.current, { ...a, bundle: { ...a.bundle, mkRecovery: body.mkRecovery } });
        }
        return json(200, { ok: true });
      }
      default:
        return json(404, { error: 'not found ' + path });
    }
  };
  return server;
}

async function tokenHash(tokenB64) {
  return e2e.toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', e2e.unb64(tokenB64))));
}

function makeDeps(server, overrides = {}) {
  return { fetch: server.fetch, stretch: fakeStretch, strength: fakeStrength, keyStore: fakeKeyStore(), ...overrides };
}

async function signedUp(server, email = 'ada@example.com', password = STRONG) {
  const deps = makeDeps(server);
  const { recoveryCode } = await account.signUp(deps, { email, name: 'Ada', password, confirm: password });
  return { deps, recoveryCode };
}

// resetToken makes a reset token the fake server accepts for an account.
function resetToken(server, email) {
  const token = e2e.b64(crypto.getRandomValues(new Uint8Array(32)));
  server.tokens.set(token, server.accounts.get(email).id);
  return token;
}

const call = (server, path) => server.log.filter((e) => e.path === path);

// ---------------------------------------------------------------- sign-up

test('signUp posts a normalized email, the name, an authKey, and a well-formed bundle', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server, '  Ada@Example.COM ');
  assert.equal(server.log.length, 1);
  const req = server.log[0];
  assert.equal(req.path, '/api/auth/signup');
  assert.equal(req.method, 'POST');
  assert.equal(req.headers['Content-Type'], 'application/json');
  assert.deepEqual(Object.keys(req.body).sort(), ['authKey', 'bundle', 'email', 'name']);
  assert.equal(req.body.email, 'ada@example.com');
  assert.equal(req.body.name, 'Ada');
  assert.equal(e2e.unb64(req.body.authKey).length, 32);
  const b = req.body.bundle;
  assert.deepEqual(Object.keys(b).sort(), ['ed25519Priv', 'ed25519Pub', 'ek', 'kdf', 'mkPassword', 'mkRecovery', 'x25519Priv', 'x25519Pub']);
  assert.deepEqual({ ...b.kdf, salt: undefined }, { alg: 'argon2id', m: 65536, t: 3, p: 1, salt: undefined });
  assert.equal(e2e.unb64(b.kdf.salt).length, 16);
  for (const f of ['mkPassword', 'mkRecovery', 'x25519Priv', 'ed25519Priv', 'ek']) {
    assert.equal(e2e.unb64(b[f]).length, 61, f);
  }
  for (const f of ['x25519Pub', 'ed25519Pub']) assert.equal(e2e.unb64(b[f]).length, 32, f);
  assert.match(recoveryCode, /^([A-Z2-7]{4}-){6}[A-Z2-7]{2}$/);
});

test('signUp: the recovery code and the password open the same MK, which seals the private keys', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  const b = server.accounts.get('ada@example.com').bundle;

  const mkRecovery = await e2e.open(await e2e.recoveryKek(e2e.parseRecoveryCode(recoveryCode)), ['mk'], e2e.unb64(b.mkRecovery));
  const stretched = await fakeStretch(STRONG, 'ada@example.com', { salt: e2e.unb64(b.kdf.salt) });
  const { kek } = await e2e.passwordKeys(stretched);
  const mkPassword = await e2e.open(kek, ['mk'], e2e.unb64(b.mkPassword));
  assert.deepEqual(mkRecovery, mkPassword);

  const sealKey = await e2e.mkSealKey(mkPassword);
  const x = await e2e.open(sealKey, ['x25519'], e2e.unb64(b.x25519Priv));
  const { publicKey } = await e2e.importX25519PrivateKey(x);
  assert.deepEqual(publicKey, e2e.unb64(b.x25519Pub));
  const seed = await e2e.open(sealKey, ['ed25519'], e2e.unb64(b.ed25519Priv));
  const sig = await e2e.sign(seed, 'probe', enc.encode('x'));
  assert.equal(await e2e.verify(e2e.unb64(b.ed25519Pub), 'probe', enc.encode('x'), sig), true);
});

test('signUp refuses a password scored below 3, and accepts one scored 3', async () => {
  const server = fakeServer();
  const deps = makeDeps(server);
  await assert.rejects(
    account.signUp(deps, { email: 'a@example.com', name: 'A', password: 'short-one', confirm: 'short-one' }),
    (err) => err.name === 'WeakPasswordError' && err.feedback.warning === 'too short' && /too weak/.test(err.message),
  );
  assert.equal(server.log.length, 0, 'no request for a weak password');
  await account.signUp(deps, { email: 'a@example.com', name: 'A', password: 'exactly twelve', confirm: 'exactly twelve' });
  assert.equal(server.log.length, 1);
});

test('signUp gives the strength estimator the email and name as dictionary context', async () => {
  fakeStrength.calls.length = 0;
  const server = fakeServer();
  await signedUp(server);
  assert.deepEqual(fakeStrength.calls[0].userInputs, ['ada@example.com', 'Ada']);
});

test('signUp refuses an empty password and a mismatched confirmation without a request', async () => {
  const server = fakeServer();
  const deps = makeDeps(server);
  await assert.rejects(account.signUp(deps, { email: 'a@example.com', name: '', password: '', confirm: '' }), /empty/);
  await assert.rejects(account.signUp(deps, { email: 'a@example.com', name: '', password: STRONG, confirm: STRONG + 'x' }), /do not match/);
  assert.equal(server.log.length, 0);
});

test("signUp surfaces the server's refusal and returns no recovery code", async () => {
  const server = fakeServer({ signupStatus: 403 });
  const deps = makeDeps(server);
  await assert.rejects(
    account.signUp(deps, { email: 'a@other.test', name: '', password: STRONG, confirm: STRONG }),
    (err) => err.status === 403 && err.message === 'sign-up is not open for this address',
  );
});

// ---------------------------------------------------------------- sign-in

test('signIn runs prelogin, then login with client "web", then stores non-extractable keys', async () => {
  const server = fakeServer();
  await signedUp(server);
  server.log.length = 0;
  const deps = makeDeps(server);
  const user = await account.signIn(deps, { email: ' ADA@example.com', password: STRONG });

  assert.deepEqual(server.log.map((e) => e.path), ['/api/auth/prelogin', '/api/auth/login']);
  assert.deepEqual(server.log[0].body, { email: 'ada@example.com' });
  const login = server.log[1].body;
  assert.deepEqual(Object.keys(login).sort(), ['authKey', 'client', 'email']);
  assert.equal(login.client, 'web');
  assert.equal(user.email, 'ada@example.com');

  assert.equal(deps.keyStore.saved.length, 1);
  const rec = deps.keyStore.saved[0];
  const b = server.accounts.get('ada@example.com').bundle;
  assert.equal(rec.userId, 'u-ada@example.com');
  assert.equal(rec.email, 'ada@example.com');
  const keys = [
    ['mk', rec.mk], ['mkSeal', rec.mkSeal], ['ek', rec.ek], ['x25519', rec.x25519.privateKey],
    ['x25519 wrapping key', rec.x25519Wrapped.wrapKey], ['ed25519', rec.ed25519],
  ];
  for (const [name, key] of keys) {
    assert.ok(key instanceof CryptoKey, name);
    assert.equal(key.extractable, false, `${name} must not be extractable`);
  }
  // The X25519 key comes both as a CryptoKey and wrapped, for a browser that
  // drops a record holding an X25519 CryptoKey (see keystore.mjs). Both are
  // the account key.
  assert.deepEqual(rec.x25519.publicKey, e2e.unb64(b.x25519Pub));
  assert.deepEqual(rec.x25519Wrapped.publicKey, e2e.unb64(b.x25519Pub));
  for (const [name, x] of [['x25519', rec.x25519], ['x25519Wrapped', await openX25519(rec.x25519Wrapped)]]) {
    const info = { purpose: 'ak', artifact: 'a1', epoch: 1, recipientId: rec.userId, recipientPub: x.publicKey };
    const secret = crypto.getRandomValues(new Uint8Array(32));
    assert.deepEqual(await e2e.unwrap(x, info, await e2e.wrap(info, secret)), secret, `${name} is the account key`);
  }
  // The record carries the Ed25519 public key too, derived from the seed, as
  // bytes, so the shell can compute the caller's own fingerprint.
  assert.ok(rec.ed25519Pub instanceof Uint8Array);
  assert.deepEqual(rec.ed25519Pub, e2e.unb64(b.ed25519Pub));
  // The stored signing key is the account's: a signature verifies under the bundle's public key.
  const sig = await e2e.sign(rec.ed25519, 'probe', enc.encode('y'));
  assert.equal(await e2e.verify(e2e.unb64(b.ed25519Pub), 'probe', enc.encode('y'), sig), true);
  // The stored mkSeal key opens a sealed key from the bundle.
  assert.equal((await e2e.open(rec.mkSeal, ['ek'], e2e.unb64(b.ek))).length, 32);
});

test('signIn refuses prelogin parameters below the floor before stretching or logging in', async () => {
  const server = fakeServer();
  await signedUp(server);
  server.accounts.get('ada@example.com').bundle.kdf.m = 1024;
  server.log.length = 0;
  let stretched = 0;
  const deps = makeDeps(server, { stretch: (...a) => { stretched++; return fakeStretch(...a); } });
  await assert.rejects(account.signIn(deps, { email: 'ada@example.com', password: STRONG }), (err) => err.name === 'FloorError');
  assert.equal(stretched, 0);
  assert.deepEqual(server.log.map((e) => e.path), ['/api/auth/prelogin']);
  assert.equal(deps.keyStore.saved.length, 0);
});

test('signIn with a wrong password stores nothing and shows the server message', async () => {
  const server = fakeServer();
  await signedUp(server);
  const deps = makeDeps(server);
  await assert.rejects(account.signIn(deps, { email: 'ada@example.com', password: 'not the password' }), /invalid email or password/);
  assert.equal(deps.keyStore.saved.length, 0);
});

test('signIn does not apply the strength check (an existing password may be weak)', async () => {
  const server = fakeServer();
  await signedUp(server, 'weak@example.com', 'exactly twelve');
  fakeStrength.calls.length = 0;
  await account.signIn(makeDeps(server), { email: 'weak@example.com', password: 'exactly twelve' });
  assert.equal(fakeStrength.calls.length, 0);
});

test('signIn refuses an empty password without a request', async () => {
  const server = fakeServer();
  await assert.rejects(account.signIn(makeDeps(server), { email: 'a@example.com', password: '' }), /empty/);
  assert.equal(server.log.length, 0);
});

test('signIn signs out again and stores nothing when MK will not open', async () => {
  const server = fakeServer();
  await signedUp(server);
  server.tamperMKPassword = true;
  server.log.length = 0;
  const deps = makeDeps(server);
  await assert.rejects(account.signIn(deps, { email: 'ada@example.com', password: STRONG }));
  assert.equal(deps.keyStore.saved.length, 0);
  assert.equal(call(server, '/api/auth/logout').length, 1);
});

// ---------------------------------------------------------------- verify

function fakePage(hash) {
  const events = [];
  return {
    events,
    location: { hash, pathname: '/verify', search: '' },
    history: { replaceState: (state, title, url) => events.push(['replaceState', url]) },
  };
}

test('takeToken reads the fragment token and strips the fragment', () => {
  const page = fakePage('#token=abc_DEF-123');
  assert.equal(account.takeToken(page.location, page.history), 'abc_DEF-123');
  assert.deepEqual(page.events, [['replaceState', '/verify']]);
});

test('takeToken accepts only a fragment that is exactly #token=<token>', () => {
  for (const hash of ['#token=abc&x=y', '#foo#token=abc', '#x=1&token=abc', '#token=', '#token=a b', '']) {
    const page = fakePage(hash);
    assert.throws(() => account.takeToken(page.location, page.history), /incomplete/, hash);
    assert.equal(page.events.length, 1, 'the fragment is stripped even when refused');
  }
});

test('takeToken strips the fragment even when it holds no token, then refuses', () => {
  const page = fakePage('#other=1');
  assert.throws(() => account.takeToken(page.location, page.history), /incomplete/);
  assert.equal(page.events.length, 1);
});

test('verifyFromLink removes the token from the address bar before the request', async () => {
  const page = fakePage('#token=good-token');
  const order = [];
  const deps = { fetch: async () => { order.push(...page.events.map((e) => e[0]), 'fetch'); return json(200, { ok: true }); } };
  await account.verifyFromLink(deps, page);
  assert.deepEqual(order, ['replaceState', 'fetch']);
});

test('verifyFromLink posts the token and reports a refused token', async () => {
  const server = fakeServer();
  await account.verifyFromLink(makeDeps(server), fakePage('#token=good-token'));
  assert.deepEqual(server.log[0].body, { token: 'good-token' });
  assert.equal(server.log[0].path, '/api/auth/verify');
  await assert.rejects(account.verifyFromLink(makeDeps(server), fakePage('#token=bad-token')), /invalid or expired token/);
});

// ---------------------------------------------------------------- forgot

test('forgot posts the normalized email and resolves the same for any address', async () => {
  const server = fakeServer();
  await account.forgot(makeDeps(server), { email: ' Nobody@Example.COM ' });
  assert.deepEqual(server.log[0], { path: '/api/auth/forgot', method: 'POST', headers: { 'Content-Type': 'application/json' }, body: { email: 'nobody@example.com' } });
  assert.equal(await account.forgot(makeDeps(server), { email: 'ada@example.com' }), account.FORGOT_MESSAGE);
  assert.equal(await account.forgot(makeDeps(server), { email: 'nobody@example.com' }), account.FORGOT_MESSAGE);
});

// ----------------------------------------------------------------- reset

test('resetBeginFromLink strips the fragment before reset/begin and returns what the page needs', async () => {
  const server = fakeServer();
  await signedUp(server);
  const token = resetToken(server, 'ada@example.com');
  const page = fakePage('#token=' + token);
  server.log.length = 0;
  const order = [];
  const fetch = async (path, options) => { order.push(page.events.length ? 'stripped' : 'not stripped'); return server.fetch(path, options); };
  const { info, token: got } = await account.resetBeginFromLink(makeDeps(server, { fetch }), page);
  assert.deepEqual(order, ['stripped']);
  assert.equal(got, token);
  assert.equal(info.email, 'ada@example.com');
  assert.deepEqual(server.log[0].body, { token });
});

test('reset with the recovery code keeps the keys: same public keys, new password signs in', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  const before = server.accounts.get('ada@example.com').bundle;
  const token = resetToken(server, 'ada@example.com');
  server.log.length = 0;
  const deps = makeDeps(server);
  const { info } = await account.resetBeginFromLink(deps, fakePage('#token=' + token));
  await account.resetWithRecovery(deps, { token, info, recoveryCode: recoveryCode.toLowerCase(), password: NEW_STRONG, confirm: NEW_STRONG });

  assert.deepEqual(server.log.map((e) => e.path), ['/api/auth/reset/begin', '/api/auth/reset/complete']);
  const done = server.log[1].body;
  assert.deepEqual(Object.keys(done).sort(), ['authKey', 'kdf', 'mkPassword', 'mode', 'proof', 'token']);
  assert.equal(done.mode, 'recovery');
  const after = server.accounts.get('ada@example.com').bundle;
  assert.equal(after.x25519Pub, before.x25519Pub);
  assert.equal(after.ed25519Pub, before.ed25519Pub);
  assert.equal(after.mkRecovery, before.mkRecovery);
  assert.notEqual(after.kdf.salt, before.kdf.salt);

  const signIn = makeDeps(server);
  await assert.rejects(account.signIn(signIn, { email: 'ada@example.com', password: STRONG }), /invalid email or password/);
  await account.signIn(signIn, { email: 'ada@example.com', password: NEW_STRONG });
  assert.deepEqual(signIn.keyStore.saved[0].x25519Wrapped.publicKey, e2e.unb64(before.x25519Pub));
});

test('reset with a wrong recovery code sends no complete request', async () => {
  const server = fakeServer();
  await signedUp(server);
  const token = resetToken(server, 'ada@example.com');
  const deps = makeDeps(server);
  const { info } = await account.resetBeginFromLink(deps, fakePage('#token=' + token));
  const wrong = e2e.formatRecoveryCode(new Uint8Array(16));
  await assert.rejects(account.resetWithRecovery(deps, { token, info, recoveryCode: wrong, password: NEW_STRONG, confirm: NEW_STRONG }), /26 characters.*groups of four.*Start with new keys/);
  await assert.rejects(account.resetWithRecovery(deps, { token, info, recoveryCode: 'not a code', password: NEW_STRONG, confirm: NEW_STRONG }));
  assert.equal(call(server, '/api/auth/reset/complete').length, 0);
});

test('reset refuses a weak password, with or without the code, before any complete request', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  const token = resetToken(server, 'ada@example.com');
  const deps = makeDeps(server);
  const { info } = await account.resetBeginFromLink(deps, fakePage('#token=' + token));
  await assert.rejects(account.resetWithRecovery(deps, { token, info, recoveryCode, password: 'weak-pw', confirm: 'weak-pw' }), (e) => e.name === 'WeakPasswordError');
  await assert.rejects(account.resetWithoutRecovery(deps, { token, info, password: 'weak-pw', confirm: 'weak-pw' }), (e) => e.name === 'WeakPasswordError');
  await assert.rejects(account.resetWithRecovery(deps, { token, info, recoveryCode, password: NEW_STRONG, confirm: 'other' }), /do not match/);
  assert.equal(call(server, '/api/auth/reset/complete').length, 0);
});

test('reset without the recovery code sends a fresh bundle and returns the new recovery code', async () => {
  const server = fakeServer();
  const { recoveryCode: oldCode } = await signedUp(server);
  const before = server.accounts.get('ada@example.com').bundle;
  const token = resetToken(server, 'ada@example.com');
  const deps = makeDeps(server);
  const { info } = await account.resetBeginFromLink(deps, fakePage('#token=' + token));
  const { recoveryCode } = await account.resetWithoutRecovery(deps, { token, info, password: NEW_STRONG, confirm: NEW_STRONG });

  const done = call(server, '/api/auth/reset/complete')[0].body;
  assert.deepEqual(Object.keys(done).sort(), ['authKey', 'bundle', 'mode', 'token']);
  assert.equal(done.mode, 'new');
  assert.match(recoveryCode, /^([A-Z2-7]{4}-){6}[A-Z2-7]{2}$/);
  assert.notEqual(recoveryCode, oldCode);
  const after = server.accounts.get('ada@example.com').bundle;
  assert.notEqual(after.x25519Pub, before.x25519Pub);
  assert.notEqual(after.ed25519Pub, before.ed25519Pub);
  // The new recovery code opens the new bundle.
  await e2e.open(await e2e.recoveryKek(e2e.parseRecoveryCode(recoveryCode)), ['mk'], e2e.unb64(after.mkRecovery));
  await account.signIn(makeDeps(server), { email: 'ada@example.com', password: NEW_STRONG });
});

// ------------------------------------------------- recovery-code confirm

// pendingRequest gives an account a pending succession request for the fake
// refusal endpoints.
function pendingRequest(server, email, requestedAt = '2026-09-20T10:11:12Z') {
  server.requests.set(email, requestedAt);
  return requestedAt;
}

test('refuseWithPassword posts the normalized email and authKey after a prelogin, and returns the answer', async () => {
  const server = fakeServer();
  await signedUp(server);
  const requestedAt = pendingRequest(server, 'ada@example.com');
  server.log.length = 0;
  const answer = await account.refuseWithPassword(makeDeps(server), { email: '  Ada@Example.COM ', password: STRONG });

  assert.deepEqual(server.log.map((e) => e.path), ['/api/auth/prelogin', '/api/auth/refuse']);
  assert.equal(server.log[0].body.email, 'ada@example.com');
  const sent = server.log[1].body;
  assert.deepEqual(Object.keys(sent).sort(), ['authKey', 'email']);
  assert.equal(sent.email, 'ada@example.com');
  assert.equal(sent.authKey, server.accounts.get('ada@example.com').authKey);
  assert.deepEqual(answer, { refused: true, successor: { name: 'Bea', email: 'bea@example.com' }, requestedAt, deactivatedAt: '' });
});

test('refuseWithPassword surfaces a 401 for a wrong password and a 409 for no pending request', async () => {
  const server = fakeServer();
  await signedUp(server);
  pendingRequest(server, 'ada@example.com');
  await assert.rejects(account.refuseWithPassword(makeDeps(server), { email: 'ada@example.com', password: 'wrong password here' }),
    (e) => e instanceof account.ApiError && e.status === 401 && /invalid email or password/.test(e.message));
  server.requests.clear();
  await assert.rejects(account.refuseWithPassword(makeDeps(server), { email: 'ada@example.com', password: STRONG }),
    (e) => e instanceof account.ApiError && e.status === 409 && /no succession request is pending/.test(e.message));
});

test('refuseWithPassword refuses an empty password without a request', async () => {
  const server = fakeServer();
  await assert.rejects(account.refuseWithPassword(makeDeps(server), { email: 'ada@example.com', password: '' }), /must not be empty/);
  assert.equal(server.log.length, 0);
});

test('refuseWithRecovery makes begin then refuse requests, and returns the answer', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  const requestedAt = pendingRequest(server, 'ada@example.com');
  server.log.length = 0;
  const answer = await account.refuseWithRecovery(makeDeps(server), { email: ' ADA@example.com', recoveryCode: recoveryCode.toLowerCase() });

  assert.deepEqual(server.log.map((e) => e.path), ['/api/auth/refuse/begin', '/api/auth/refuse']);
  assert.deepEqual(server.log[0].body, { email: 'ada@example.com' });
  assert.deepEqual(Object.keys(server.log[1].body).sort(), ['email', 'proof']);
  assert.equal(server.log[1].body.email, 'ada@example.com');
  assert.equal(answer.refused, true);
  assert.equal(answer.requestedAt, requestedAt);
});

test('refuseWithRecovery proof verifies under the account key for refusal, and names user and requestedAt from begin', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  const requestedAt = pendingRequest(server, 'ada@example.com', '2026-09-21T01:02:03Z');
  await account.refuseWithRecovery(makeDeps(server), { email: 'ada@example.com', recoveryCode });

  const a = server.accounts.get('ada@example.com');
  const proof = call(server, '/api/auth/refuse')[0].body.proof;
  assert.deepEqual(Object.keys(proof).sort(), ['body', 'sig', 'signer']);
  assert.equal(proof.signer, a.id);
  const pub = e2e.unb64(a.bundle.ed25519Pub);
  assert.equal(await e2e.verifyEnvelope(pub, 'refusal', proof), true);
  assert.equal(await e2e.verifyEnvelope(pub, 'reset', proof), false);
  const body = JSON.parse(new TextDecoder().decode(e2e.unb64(proof.body)));
  assert.deepEqual(body, { v: 1, user: a.id, requestedAt });
});

test('refuseWithRecovery with a wrong code says it does not open the account, without reset advice, and sends no refusal', async () => {
  const server = fakeServer();
  await signedUp(server);
  pendingRequest(server, 'ada@example.com');
  const wrong = e2e.formatRecoveryCode(new Uint8Array(16));
  await assert.rejects(account.refuseWithRecovery(makeDeps(server), { email: 'ada@example.com', recoveryCode: wrong }),
    (e) => /That recovery code does not open this account/.test(e.message) && !/Start with new keys/.test(e.message));
  assert.equal(call(server, '/api/auth/refuse').length, 0);
});

test('refuseWithRecovery refuses a malformed code before any request', async () => {
  const server = fakeServer();
  await assert.rejects(account.refuseWithRecovery(makeDeps(server), { email: 'ada@example.com', recoveryCode: 'not a code' }),
    /That is not a recovery code\. It has 26 letters and digits in groups of four\./);
  assert.equal(server.log.length, 0);
});

test('refuseWithRecovery against an address with no request gets a fake, which fails as a wrong code', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  await assert.rejects(account.refuseWithRecovery(makeDeps(server), { email: 'ada@example.com', recoveryCode }), /does not open this account/);
  assert.equal(call(server, '/api/auth/refuse').length, 0);
});

test('refuseWithRecovery surfaces a 409 for a request that is no longer pending', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  pendingRequest(server, 'ada@example.com');
  const deps = makeDeps(server, {
    fetch: async (path, options) => {
      if (path === '/api/auth/refuse') server.requests.set('ada@example.com', '');
      return server.fetch(path, options);
    },
  });
  await assert.rejects(account.refuseWithRecovery(deps, { email: 'ada@example.com', recoveryCode }),
    (e) => e instanceof account.ApiError && e.status === 409 && /no succession request is pending/.test(e.message));
});

test('refuseWithRecovery surfaces a 401 for a proof the server rejects', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  pendingRequest(server, 'ada@example.com');
  const deps = makeDeps(server, {
    fetch: async (path, options) => {
      if (path === '/api/auth/refuse') server.requests.set('ada@example.com', '2030-01-01T00:00:00Z'); // a newer request
      return server.fetch(path, options);
    },
  });
  await assert.rejects(account.refuseWithRecovery(deps, { email: 'ada@example.com', recoveryCode }),
    (e) => e instanceof account.ApiError && e.status === 401 && /invalid email or password/.test(e.message));
});

test('refuseWithRecovery zeroes the code, its key, MK, and the seed, even when the refusal fails', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  pendingRequest(server, 'ada@example.com');
  const spy = spyCrypto();
  try {
    const deps = makeDeps(server, {
      fetch: async (path, options) => (path === '/api/auth/refuse' ? json(401, { error: 'invalid email or password' }) : server.fetch(path, options)),
    });
    await assert.rejects(account.refuseWithRecovery(deps, { email: 'ada@example.com', recoveryCode }), /invalid email or password/);
  } finally {
    spy.restore();
  }
  assert.ok(spy.decrypted.length >= 2, 'MK and the seed were opened');
  for (const secret of [...spy.decrypted, ...spy.raws]) assert.ok(isZero(secret), 'a secret was left in memory');
});

test('the recovery confirmation picks a group, and accepts only that group, in any case', () => {
  const display = 'ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ';
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const index = account.recoveryGroupIndex(display);
    assert.ok(Number.isInteger(index) && index >= 0 && index < 7);
    seen.add(index);
  }
  assert.ok(seen.size > 1, 'the group is random');
  assert.equal(account.recoveryGroupMatches(display, 2, ' ijkl '), true);
  assert.equal(account.recoveryGroupMatches(display, 2, 'EFGH'), false);
  assert.equal(account.recoveryGroupMatches(display, 6, 'yz'), true);
  assert.equal(account.recoveryGroupMatches(display, 2, ''), false);
});

// -------------------------------------------------------------- sign-out

test('signOut clears the stored keys', async () => {
  const deps = makeDeps(fakeServer());
  await account.signOut(deps);
  assert.equal(deps.keyStore.cleared, 1);
});

test('signOut leaves the keyring anchor in localStorage', async () => {
  const anchor = new Map([['cairn.keyringAnchor', '{"rev":12}']]);
  const localStorage = {
    getItem: (k) => anchor.get(k) ?? null,
    setItem: (k, v) => anchor.set(k, v),
    removeItem: () => assert.fail('sign-out must not remove from localStorage'),
    clear: () => assert.fail('sign-out must not clear localStorage'),
  };
  const deps = { ...makeDeps(fakeServer()), localStorage };
  await account.signOut(deps);
  assert.equal(deps.keyStore.cleared, 1);
  assert.equal(localStorage.getItem('cairn.keyringAnchor'), '{"rev":12}');
});

test('signOut leaves a real-format keyring anchor readable by loadKeyringAnchor', async () => {
  const store = new Map();
  const localStorage = {
    getItem: (k) => store.get(k) ?? null,
    setItem: (k, v) => store.set(k, v),
    removeItem: () => assert.fail('sign-out must not remove from localStorage'),
    clear: () => assert.fail('sign-out must not clear localStorage'),
  };
  const fp = 'a'.repeat(64);
  const anchor = { rev: 12, hash: 'b'.repeat(64) };
  e2e.saveKeyringAnchor(localStorage, 'u-ada', fp, anchor);
  assert.deepEqual([...store.keys()], [`cairn.keyringAnchor.u-ada.${fp}`]);
  const deps = { ...makeDeps(fakeServer()), localStorage };
  await account.signOut(deps);
  assert.equal(deps.keyStore.cleared, 1);
  assert.deepEqual(e2e.loadKeyringAnchor(localStorage, 'u-ada', fp), anchor);
});

// ------------------------------------------------- raw key bytes are zeroed

// spyCrypto records every raw key an importKey call receives, every 32-byte
// array getRandomValues fills, and every buffer decrypt returns, so a test can
// check afterwards that none of those secrets is left in memory. It also lets
// a test make one SubtleCrypto method throw. The patches sit on the instances
// and are removed by restore().
function spyCrypto() {
  const spy = { raws: [], randoms: [], decrypted: [], failing: new Set() };
  const { subtle } = crypto;
  const realImport = subtle.importKey.bind(subtle);
  const realDecrypt = subtle.decrypt.bind(subtle);
  const realRandom = crypto.getRandomValues.bind(crypto);
  const maybeFail = (name) => { if (spy.failing.has(name)) throw new Error(`injected ${name} failure`); };
  subtle.importKey = (format, data, ...rest) => {
    if (format === 'raw') spy.raws.push(data);
    return realImport(format, data, ...rest);
  };
  subtle.decrypt = async (...args) => {
    const pt = await realDecrypt(...args);
    spy.decrypted.push(pt);
    return pt;
  };
  subtle.deriveBits = (...args) => { maybeFail('deriveBits'); return Object.getPrototypeOf(subtle).deriveBits.apply(subtle, args); };
  subtle.encrypt = (...args) => { maybeFail('encrypt'); return Object.getPrototypeOf(subtle).encrypt.apply(subtle, args); };
  crypto.getRandomValues = (a) => {
    if (a.length === 32) spy.randoms.push(a);
    return realRandom(a);
  };
  spy.restore = () => {
    for (const name of ['importKey', 'decrypt', 'deriveBits', 'encrypt']) delete subtle[name];
    delete crypto.getRandomValues;
  };
  return spy;
}

const isZero = (b) => new Uint8Array(b.buffer ?? b).every((x) => x === 0);

// stretchKeeping returns a stretch dep that hands out buffers it remembers,
// and runs onStretch (to arm an injected failure) once it has answered.
function stretchKeeping(kept, onStretch = () => {}) {
  return async (password, email, params) => {
    const out = await fakeStretch(password, email, params);
    kept.push(out);
    onStretch();
    return out;
  };
}

test('signUp zeroes the stretched key when deriving from it throws', async () => {
  const kept = [];
  const spy = spyCrypto();
  try {
    const deps = makeDeps(fakeServer(), { stretch: stretchKeeping(kept, () => spy.failing.add('deriveBits')) });
    await assert.rejects(account.signUp(deps, { email: 'a@example.com', name: 'A', password: STRONG, confirm: STRONG }), /injected deriveBits/);
  } finally {
    spy.restore();
  }
  assert.equal(kept.length, 1);
  assert.ok(isZero(kept[0]), 'the stretched key was left in memory');
});

test('signUp zeroes MK, EK, the key seeds, and the recovery code when sealing throws', async () => {
  const kept = [];
  const spy = spyCrypto();
  try {
    const deps = makeDeps(fakeServer(), { stretch: stretchKeeping(kept, () => {}) });
    spy.failing.add('encrypt');
    await assert.rejects(account.signUp(deps, { email: 'a@example.com', name: 'A', password: STRONG, confirm: STRONG }), /injected encrypt/);
  } finally {
    spy.restore();
  }
  assert.ok(spy.randoms.length >= 4, 'MK, EK, and both key seeds are read at random');
  for (const secret of [...spy.randoms, ...spy.raws, ...kept]) assert.ok(isZero(secret), 'a secret was left in memory');
});

test('signIn zeroes the stretched key when deriving from it throws', async () => {
  const server = fakeServer();
  await signedUp(server);
  const kept = [];
  const spy = spyCrypto();
  try {
    const deps = makeDeps(server, { stretch: stretchKeeping(kept, () => spy.failing.add('deriveBits')) });
    await assert.rejects(account.signIn(deps, { email: 'ada@example.com', password: STRONG }), /injected deriveBits/);
  } finally {
    spy.restore();
  }
  assert.equal(kept.length, 1);
  assert.ok(isZero(kept[0]), 'the stretched key was left in memory');
});

test('signIn zeroes the decrypted private keys when opening the bundle fails after them', async () => {
  const server = fakeServer();
  await signedUp(server);
  // A truncated EK fails to open after both private keys were decrypted.
  const stored = server.accounts.get('ada@example.com').bundle;
  stored.ek = e2e.b64(e2e.unb64(stored.ek).slice(1));
  const spy = spyCrypto();
  try {
    await assert.rejects(account.signIn(makeDeps(server), { email: 'ada@example.com', password: STRONG }), (e) => e.name === 'DecryptError');
  } finally {
    spy.restore();
  }
  assert.ok(spy.decrypted.length >= 2, 'both private keys were decrypted');
  for (const secret of spy.decrypted) assert.ok(isZero(secret), 'a decrypted private key was left in memory');
});

test('reset with the recovery code zeroes the code, its key, MK, and the seed when the stretch throws', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  const token = resetToken(server, 'ada@example.com');
  const { info } = await account.resetBeginFromLink(makeDeps(server), fakePage('#token=' + token));
  const spy = spyCrypto();
  try {
    const deps = makeDeps(server, { stretch: async () => { throw new Error('stretch failed'); } });
    await assert.rejects(account.resetWithRecovery(deps, { token, info, recoveryCode, password: NEW_STRONG, confirm: NEW_STRONG }), /stretch failed/);
  } finally {
    spy.restore();
  }
  assert.ok(spy.decrypted.length >= 2, 'MK and the seed were opened');
  for (const secret of [...spy.decrypted, ...spy.raws]) assert.ok(isZero(secret), 'a secret was left in memory');
  assert.equal(call(server, '/api/auth/reset/complete').length, 0);
});

test('reset with the recovery code reports a crypto failure as itself, not as a wrong code', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  const token = resetToken(server, 'ada@example.com');
  const { info } = await account.resetBeginFromLink(makeDeps(server), fakePage('#token=' + token));
  const spy = spyCrypto();
  spy.failing.add('deriveBits');
  try {
    await assert.rejects(
      account.resetWithRecovery(makeDeps(server), { token, info, recoveryCode, password: NEW_STRONG, confirm: NEW_STRONG }),
      (e) => /injected deriveBits/.test(e.message) && !/Start with new keys/.test(e.message));
  } finally {
    spy.restore();
  }
  assert.equal(call(server, '/api/auth/reset/complete').length, 0);
});

test('reset with the recovery code reports a malformed sealed MK as itself, not as a wrong code', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  const token = resetToken(server, 'ada@example.com');
  const { info } = await account.resetBeginFromLink(makeDeps(server), fakePage('#token=' + token));
  await assert.rejects(
    account.resetWithRecovery(makeDeps(server), { token, info: { ...info, mkRecovery: '@@@' }, recoveryCode, password: NEW_STRONG, confirm: NEW_STRONG }),
    (e) => e instanceof e2e.FormatError && !/Start with new keys/.test(e.message));
  assert.equal(call(server, '/api/auth/reset/complete').length, 0);
});

test('reset with the recovery code zeroes the stretched key when deriving from it throws', async () => {
  const server = fakeServer();
  const { recoveryCode } = await signedUp(server);
  const token = resetToken(server, 'ada@example.com');
  const { info } = await account.resetBeginFromLink(makeDeps(server), fakePage('#token=' + token));
  const kept = [];
  const spy = spyCrypto();
  try {
    const deps = makeDeps(server, { stretch: stretchKeeping(kept, () => spy.failing.add('deriveBits')) });
    await assert.rejects(account.resetWithRecovery(deps, { token, info, recoveryCode, password: NEW_STRONG, confirm: NEW_STRONG }), /injected deriveBits/);
  } finally {
    spy.restore();
  }
  for (const secret of [...kept, ...spy.decrypted, ...spy.raws]) assert.ok(isZero(secret), 'a secret was left in memory');
});

// ------------------------------------------------- signed-in account changes

// mkOf opens the account's MK with its password, as sign-in does.
async function mkOf(server, password, email = 'ada@example.com') {
  const b = server.accounts.get(email).bundle;
  const stretched = await fakeStretch(password, email, { salt: e2e.unb64(b.kdf.salt) });
  const { kek } = await e2e.passwordKeys(stretched);
  return e2e.open(kek, ['mk'], e2e.unb64(b.mkPassword));
}

test('createApiKey seals MK under the new key, sends only its public parts, and returns the full key once', async () => {
  const server = fakeServer();
  const { deps } = await signedUp(server);
  const authKey = server.accounts.get('ada@example.com').authKey;
  const out = await account.createApiKey(deps, { name: ' laptop ', password: STRONG });
  const [req] = call(server, '/api/keys');
  assert.equal(req.method, 'POST');
  assert.deepEqual(Object.keys(req.body).sort(), ['authKey', 'authSecret', 'device', 'keyId', 'mk', 'name']);
  assert.equal(req.body.authKey, authKey);
  assert.equal(req.body.name, 'laptop');
  assert.equal(req.body.device, false);
  const parsed = e2e.parseApiKey(out.key);
  assert.equal(req.body.keyId, parsed.keyId);
  assert.equal(req.body.authSecret, parsed.authSecret);
  assert.ok(!JSON.stringify(server.log).includes(e2e.toHex(parsed.keySecret)), 'the key secret never reaches the server');
  const mk = await e2e.open(await e2e.apiKeyKek(parsed.keySecret, parsed.keyId), ['mk', parsed.keyId], e2e.unb64(req.body.mk));
  assert.deepEqual(mk, await mkOf(server, STRONG));
  assert.equal(out.id, parsed.keyId);
});

test('createApiKey refuses a wrong or empty password and an empty name without creating a key', async () => {
  const server = fakeServer();
  const { deps } = await signedUp(server);
  await assert.rejects(account.createApiKey(deps, { name: 'k', password: 'not it' }), /password is wrong/);
  await assert.rejects(account.createApiKey(deps, { name: 'k', password: '' }), /password/);
  await assert.rejects(account.createApiKey(deps, { name: '  ', password: STRONG }), /name/);
  assert.equal(call(server, '/api/keys').length, 0);
});

test("createApiKey surfaces the server's refusal of the password", async () => {
  const server = fakeServer();
  const { deps } = await signedUp(server);
  server.accounts.get('ada@example.com').authKey = 'stale';
  await assert.rejects(account.createApiKey(deps, { name: 'k', password: STRONG }), (e) => e.status === 401 && /password/.test(e.message));
});

test('changePassword re-seals the same MK under a fresh salt, and only the new password signs in', async () => {
  const server = fakeServer();
  const { deps } = await signedUp(server);
  const mk = await mkOf(server, STRONG);
  const before = server.accounts.get('ada@example.com');
  await account.changePassword(deps, { current: STRONG, next: NEW_STRONG, confirm: NEW_STRONG });
  const [req] = call(server, '/api/me/password');
  assert.equal(req.method, 'PUT');
  assert.deepEqual(Object.keys(req.body).sort(), ['authKey', 'kdf', 'mkPassword', 'newAuthKey']);
  assert.equal(req.body.authKey, before.authKey);
  assert.deepEqual({ ...req.body.kdf, salt: undefined }, { alg: 'argon2id', m: 65536, t: 3, p: 1, salt: undefined });
  assert.notEqual(req.body.kdf.salt, before.bundle.kdf.salt);
  assert.deepEqual(await mkOf(server, NEW_STRONG), mk);

  await assert.rejects(account.signIn(makeDeps(server), { email: 'ada@example.com', password: STRONG }), /invalid email or password/);
  await account.signIn(makeDeps(server), { email: 'ada@example.com', password: NEW_STRONG });
});

test('changePassword checks the new password before anything, and refuses a wrong current one', async () => {
  const server = fakeServer();
  const { deps } = await signedUp(server);
  const sent = server.log.length;
  await assert.rejects(account.changePassword(deps, { current: STRONG, next: NEW_STRONG, confirm: NEW_STRONG + 'x' }), /do not match/);
  await assert.rejects(account.changePassword(deps, { current: STRONG, next: 'short-one', confirm: 'short-one' }), (e) => e.name === 'WeakPasswordError');
  assert.deepEqual(server.log.slice(sent).map((e) => e.path), ['/api/me'], 'nothing past the account lookup for a bad new password');
  await assert.rejects(account.changePassword(deps, { current: 'not it', next: NEW_STRONG, confirm: NEW_STRONG }), /password is wrong/);
  assert.equal(call(server, '/api/me/password').length, 0);
});

test('changePassword gives the strength estimator the email and name', async () => {
  const server = fakeServer();
  const { deps } = await signedUp(server);
  fakeStrength.calls.length = 0;
  await account.changePassword(deps, { current: STRONG, next: NEW_STRONG, confirm: NEW_STRONG });
  assert.deepEqual(fakeStrength.calls[0].userInputs, ['ada@example.com', 'Ada']);
});

test('newRecoveryCode seals MK under a new code that the old one no longer opens', async () => {
  const server = fakeServer();
  const { deps, recoveryCode: old } = await signedUp(server);
  const authKey = server.accounts.get('ada@example.com').authKey;
  const { recoveryCode } = await account.newRecoveryCode(deps, { password: STRONG });
  assert.match(recoveryCode, /^([A-Z2-7]{4}-){6}[A-Z2-7]{2}$/);
  const [req] = call(server, '/api/me/recovery');
  assert.equal(req.method, 'PUT');
  assert.deepEqual(Object.keys(req.body).sort(), ['authKey', 'mkRecovery']);
  assert.equal(req.body.authKey, authKey);
  const sealed = e2e.unb64(req.body.mkRecovery);
  const mk = await e2e.open(await e2e.recoveryKek(e2e.parseRecoveryCode(recoveryCode)), ['mk'], sealed);
  assert.deepEqual(mk, await mkOf(server, STRONG));
  await assert.rejects(e2e.open(await e2e.recoveryKek(e2e.parseRecoveryCode(old)), ['mk'], sealed), e2e.DecryptError);
});

test('newRecoveryCode refuses a wrong password without a request', async () => {
  const server = fakeServer();
  const { deps } = await signedUp(server);
  await assert.rejects(account.newRecoveryCode(deps, { password: 'not it' }), /password is wrong/);
  assert.equal(call(server, '/api/me/recovery').length, 0);
});

test('every password check refuses bundle parameters below the floor before stretching or writing', async () => {
  const actions = {
    createApiKey: (deps) => account.createApiKey(deps, { name: 'k', password: STRONG }),
    changePassword: (deps) => account.changePassword(deps, { current: STRONG, next: NEW_STRONG, confirm: NEW_STRONG }),
    newRecoveryCode: (deps) => account.newRecoveryCode(deps, { password: STRONG }),
  };
  for (const [name, run] of Object.entries(actions)) {
    const server = fakeServer();
    const { deps } = await signedUp(server);
    server.accounts.get('ada@example.com').bundle.kdf.m = 1024;
    let stretched = 0;
    deps.stretch = (...a) => { stretched++; return fakeStretch(...a); };
    const sent = server.log.length;
    await assert.rejects(run(deps), (err) => err.name === 'FloorError', name);
    assert.equal(stretched, 0, `${name} stretched the password`);
    const writes = server.log.slice(sent).filter((e) => ['POST', 'PUT', 'DELETE'].includes(e.method));
    assert.deepEqual(writes, [], `${name} wrote`);
  }
});

test('the account changes zero MK, the stretched password, and the key secret', async () => {
  const server = fakeServer();
  const { deps } = await signedUp(server);
  const kept = [];
  const spy = spyCrypto();
  try {
    const d = { ...deps, stretch: stretchKeeping(kept) };
    await account.createApiKey(d, { name: 'k', password: STRONG });
    await account.newRecoveryCode(d, { password: STRONG });
    await account.changePassword(d, { current: STRONG, next: NEW_STRONG, confirm: NEW_STRONG });
  } finally {
    spy.restore();
  }
  for (const secret of [...kept, ...spy.decrypted, ...spy.raws]) assert.ok(isZero(secret), 'a secret was left in memory');
});
