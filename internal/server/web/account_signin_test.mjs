// Tests for the passkey and Google flows of account.mjs, against a fake
// server that answers the way Cairn's handlers do, a fake authenticator in
// place of navigator.credentials, a fast fake stretch, and the real e2e.mjs
// crypto. Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import * as account from './account.mjs';

const enc = new TextEncoder();
const STRONG = 'correct horse battery staple';

async function fakeStretch(password, email, params) {
  const data = new Uint8Array([...enc.encode(password), 0, ...enc.encode(email), 0, ...params.salt]);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

const fakeStrength = (password) => ({ score: password.length < 12 ? 2 : 3, feedback: {} });

function fakeKeyStore() {
  return {
    saved: [],
    cleared: 0,
    async save(record) { this.saved.push(record); },
    async clear() { this.cleared++; },
  };
}

const json = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

// fakeServer keeps one account table and the passkeys enrolled for it. The
// passkey endpoints answer as the handlers do once the assertion checks out:
// the server's own signature checks are Go's to test, not this file's.
function fakeServer({ google = null, signupStatus = 202 } = {}) {
  const server = { log: [], accounts: new Map(), passkeys: new Map(), google };
  server.fetch = async (path, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : null;
    server.log.push({ path, method: options.method || 'GET', body });
    const a = server.accounts.get(server.current);
    switch (path) {
      case '/api/auth/signup':
        server.accounts.set(body.email, { id: 'u-' + body.email, name: body.name, authKey: body.authKey, bundle: body.bundle });
        server.current = body.email;
        return signupStatus === 201 ? json(201, { status: 'active' }) : json(202, { status: 'check-email' });
      case '/api/auth/prelogin':
        return json(200, server.accounts.get(body.email).bundle.kdf);
      case '/api/auth/login': {
        const acct = server.accounts.get(body.email);
        if (!acct || acct.authKey !== body.authKey) return json(401, { error: 'invalid email or password' });
        return json(200, { user: { id: acct.id, email: body.email, name: acct.name, isAdmin: false }, bundle: acct.bundle });
      }
      case '/api/auth/logout':
        return json(200, { ok: true });
      case '/api/me':
        return json(200, { id: a.id, email: server.current, name: a.name, isAdmin: false });
      case '/api/me/bundle':
        return json(200, a.bundle);
      case '/api/me/passkeys':
        if (options.method === 'POST') {
          if (body.authKey !== a.authKey) return json(401, { error: 'wrong password' });
          server.passkeys.set(body.id, { ...body, user: server.current });
          return json(201, { id: body.id, name: body.name, createdAt: '2026-10-19T00:00:00Z' });
        }
        return json(200, [...server.passkeys.values()].map((p) => ({ id: p.id, name: p.name })));
      case '/api/auth/passkey/begin':
        server.challenge = crypto.getRandomValues(new Uint8Array(32));
        return json(200, { challenge: e2e.b64(server.challenge), rpId: 'cairn.test' });
      case '/api/auth/passkey/finish': {
        const p = server.passkeys.get(body.credentialId);
        if (!p) return json(401, { error: 'unknown passkey' });
        const acct = server.accounts.get(p.user);
        return json(200, {
          user: { id: acct.id, email: p.user, name: acct.name, isAdmin: false },
          bundle: acct.bundle,
          passkeyMk: server.tamperPasskeyMk ? acct.bundle.mkRecovery : p.mk,
        });
      }
      case '/api/auth/google':
        return server.google ? json(200, server.google) : json(401, { error: 'sign in with Google first' });
      case '/api/auth/forgot':
        return server.google ? json(200, { token: 'reset-token' }) : json(403, { error: 'sign in with Google first' });
      default:
        if (path.startsWith('/api/me/passkeys/') && options.method === 'DELETE') {
          server.passkeys.delete(decodeURIComponent(path.slice('/api/me/passkeys/'.length)));
          return json(200, { ok: true });
        }
        return json(404, { error: 'not found: ' + path });
    }
  };
  return server;
}

// fakeAuthenticator stands in for navigator.credentials. Each credential has
// a secret, and its PRF output is SHA-256(secret || input), so it is fixed
// per credential and differs between credentials, as a real one's is.
function fakeAuthenticator({ prf = true, prfAtCreate = true } = {}) {
  const auth = { creds: [], calls: [] };
  const toBuf = (u8) => u8.slice().buffer;
  const prfOf = async (cred, input) =>
    new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([...cred.secret, ...new Uint8Array(input)])));
  auth.create = async (options) => {
    auth.calls.push({ kind: 'create', options });
    const cred = { rawId: crypto.getRandomValues(new Uint8Array(16)), secret: crypto.getRandomValues(new Uint8Array(32)) };
    auth.creds.push(cred);
    const evalFirst = options.publicKey.extensions?.prf?.eval?.first;
    const results = prf && prfAtCreate && evalFirst ? { first: toBuf(await prfOf(cred, evalFirst)) } : undefined;
    return {
      rawId: toBuf(cred.rawId),
      response: {
        getPublicKey: () => toBuf(new Uint8Array([0x30, 1, 2, 3])),
        getPublicKeyAlgorithm: () => -7,
      },
      getClientExtensionResults: () => ({ prf: { enabled: prf, ...(results ? { results } : {}) } }),
    };
  };
  auth.get = async (options) => {
    auth.calls.push({ kind: 'get', options });
    const allow = options.publicKey.allowCredentials ?? [];
    const cred = allow.length
      ? auth.creds.find((c) => e2e.b64(c.rawId) === e2e.b64(new Uint8Array(allow[0].id)))
      : auth.creds[auth.creds.length - 1];
    const evalFirst = options.publicKey.extensions?.prf?.eval?.first;
    const results = prf && evalFirst ? { first: toBuf(await prfOf(cred, evalFirst)) } : undefined;
    return {
      rawId: toBuf(cred.rawId),
      response: {
        clientDataJSON: toBuf(enc.encode('{"type":"webauthn.get"}')),
        authenticatorData: toBuf(new Uint8Array(37)),
        signature: toBuf(new Uint8Array([9, 9])),
        userHandle: toBuf(enc.encode('user-handle')),
      },
      getClientExtensionResults: () => ({ prf: results ? { results } : {} }),
    };
  };
  return auth;
}

function makeDeps(server, credentials = fakeAuthenticator()) {
  return { fetch: server.fetch, stretch: fakeStretch, strength: fakeStrength, keyStore: fakeKeyStore(), credentials };
}

async function signedUp(opts) {
  const server = fakeServer(opts);
  const deps = makeDeps(server);
  await account.signUp(deps, { email: 'ada@example.com', name: 'Ada', password: STRONG, confirm: STRONG });
  return { server, deps };
}

// passwordMK opens MK with the password, the way sign-in does, for comparing.
async function passwordMK(server, email = 'ada@example.com') {
  const a = server.accounts.get(email);
  const stretched = await fakeStretch(STRONG, email, { salt: e2e.unb64(a.bundle.kdf.salt) });
  const { kek } = await e2e.passwordKeys(stretched);
  return e2e.open(kek, ['mk'], e2e.unb64(a.bundle.mkPassword));
}

test('enrollPasskey asks the authenticator for a discoverable, verified credential that evaluates the PRF input', async () => {
  const { server, deps } = await signedUp();
  await account.enrollPasskey(deps, { name: 'laptop', password: STRONG });
  const create = deps.credentials.calls.find((c) => c.kind === 'create').options.publicKey;
  assert.equal(create.authenticatorSelection.residentKey, 'required');
  assert.equal(create.authenticatorSelection.userVerification, 'required');
  assert.equal(create.attestation, 'none');
  assert.deepEqual(new Uint8Array(create.extensions.prf.eval.first), e2e.PASSKEY_PRF_INPUT);
  assert.equal(new TextDecoder().decode(create.user.id), server.accounts.get('ada@example.com').id);
  assert.equal(create.user.name, 'ada@example.com');
  assert.deepEqual(create.pubKeyCredParams.map((p) => p.alg), [-8, -7, -257]);
});

test('enrollPasskey seals the same MK the password opens, under passkeyKek, and sends a fresh authKey', async () => {
  const { server, deps } = await signedUp();
  const created = await account.enrollPasskey(deps, { name: 'laptop', password: STRONG });
  const [stored] = server.passkeys.values();
  assert.equal(created.id, stored.id);
  assert.equal(stored.name, 'laptop');
  assert.equal(stored.alg, -7);
  assert.equal(stored.publicKey, e2e.b64(new Uint8Array([0x30, 1, 2, 3])));
  assert.equal(stored.authKey, server.accounts.get('ada@example.com').authKey);

  const cred = deps.credentials.creds[0];
  const prf = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([...cred.secret, ...e2e.PASSKEY_PRF_INPUT])));
  const userId = server.accounts.get('ada@example.com').id;
  const kek = await e2e.passkeyKek(prf, userId, stored.id);
  const mk = await e2e.open(kek, ['mk', stored.id], e2e.unb64(stored.mk));
  assert.deepEqual(mk, await passwordMK(server));
});

test('enrollPasskey refuses a passkey without PRF, and stores nothing', async () => {
  const server = fakeServer();
  const deps = makeDeps(server, fakeAuthenticator({ prf: false }));
  await account.signUp(deps, { email: 'ada@example.com', name: 'Ada', password: STRONG, confirm: STRONG });
  await assert.rejects(account.enrollPasskey(deps, { name: 'key', password: STRONG }), account.PasskeyUnsupportedError);
  assert.equal(server.passkeys.size, 0);
  assert.ok(!server.log.some((r) => r.path === '/api/me/passkeys' && r.method === 'POST'));
  // It stops at create, rather than asking the user to touch the key again.
  assert.ok(!deps.credentials.calls.some((c) => c.kind === 'get'));
});

test('enrollPasskey gets the PRF output with an assertion when create returns none', async () => {
  const server = fakeServer();
  const deps = makeDeps(server, fakeAuthenticator({ prfAtCreate: false }));
  await account.signUp(deps, { email: 'ada@example.com', name: 'Ada', password: STRONG, confirm: STRONG });
  await account.enrollPasskey(deps, { name: 'key', password: STRONG });
  const get = deps.credentials.calls.find((c) => c.kind === 'get').options.publicKey;
  assert.equal(get.userVerification, 'required');
  assert.equal(get.allowCredentials.length, 1);
  assert.equal(e2e.b64(new Uint8Array(get.allowCredentials[0].id)), [...server.passkeys.keys()][0]);
  // The sealed MK opens with what a later sign-in derives.
  const signIn = makeDeps(server, deps.credentials);
  await account.signInWithPasskey(signIn);
  assert.equal(signIn.keyStore.saved.length, 1);
});

test('enrollPasskey checks the password before touching the authenticator', async () => {
  const { server, deps } = await signedUp();
  await assert.rejects(account.enrollPasskey(deps, { name: 'key', password: 'wrong password entirely' }), /password is wrong/);
  assert.equal(deps.credentials.calls.length, 0);
  assert.equal(server.passkeys.size, 0);
});

test('enrollPasskey excludes the passkeys already enrolled', async () => {
  const { server, deps } = await signedUp();
  await account.enrollPasskey(deps, { name: 'one', password: STRONG });
  await account.enrollPasskey(deps, { name: 'two', password: STRONG });
  const second = deps.credentials.calls.filter((c) => c.kind === 'create')[1].options.publicKey;
  assert.deepEqual(second.excludeCredentials.map((c) => e2e.b64(new Uint8Array(c.id))), [[...server.passkeys.keys()][0]]);
});

test('signInWithPasskey opens the same keys a password sign-in does', async () => {
  const { server, deps } = await signedUp();
  await account.enrollPasskey(deps, { name: 'laptop', password: STRONG });

  const byPasskey = makeDeps(server, deps.credentials);
  const user = await account.signInWithPasskey(byPasskey);
  const byPassword = makeDeps(server);
  await account.signIn(byPassword, { email: 'ada@example.com', password: STRONG });

  assert.equal(user.email, 'ada@example.com');
  const [a] = byPasskey.keyStore.saved;
  const [b] = byPassword.keyStore.saved;
  assert.equal(a.userId, b.userId);
  assert.deepEqual(a.ed25519Pub, b.ed25519Pub);
  // Both opened the same MK: what one mkSealKey seals, the other opens.
  const probe = enc.encode('probe');
  assert.deepEqual(await e2e.open(b.mkSeal, ['probe'], await e2e.seal(a.mkSeal, ['probe'], probe)), probe);
});

test('signInWithPasskey asks for any discoverable credential, verified, with the challenge and the PRF input', async () => {
  const { server, deps } = await signedUp();
  await account.enrollPasskey(deps, { name: 'laptop', password: STRONG });
  const signIn = makeDeps(server, deps.credentials);
  await account.signInWithPasskey(signIn);
  const get = signIn.credentials.calls.filter((c) => c.kind === 'get').at(-1).options.publicKey;
  assert.deepEqual(new Uint8Array(get.challenge), server.challenge);
  assert.equal(get.rpId, 'cairn.test');
  assert.equal(get.userVerification, 'required');
  assert.deepEqual(get.allowCredentials, []);
  assert.deepEqual(new Uint8Array(get.extensions.prf.eval.first), e2e.PASSKEY_PRF_INPUT);

  const finish = server.log.find((r) => r.path === '/api/auth/passkey/finish').body;
  assert.deepEqual(Object.keys(finish).sort(), ['authenticatorData', 'clientDataJSON', 'credentialId', 'signature', 'userHandle']);
  assert.equal(finish.credentialId, [...server.passkeys.keys()][0]);
  assert.equal(new TextDecoder().decode(e2e.unb64(finish.clientDataJSON)), '{"type":"webauthn.get"}');
});

test('signInWithPasskey without a PRF result never asks the server for a session', async () => {
  const { server, deps } = await signedUp();
  await account.enrollPasskey(deps, { name: 'laptop', password: STRONG });
  const noPrf = fakeAuthenticator({ prf: false });
  noPrf.creds = deps.credentials.creds;
  const signIn = makeDeps(server, noPrf);
  await assert.rejects(account.signInWithPasskey(signIn), account.PasskeyUnsupportedError);
  assert.ok(!server.log.some((r) => r.path === '/api/auth/passkey/finish'));
  assert.equal(signIn.keyStore.saved.length, 0);
});

test('signInWithPasskey signs out again and stores nothing when the sealed MK will not open', async () => {
  const { server, deps } = await signedUp();
  await account.enrollPasskey(deps, { name: 'laptop', password: STRONG });
  server.tamperPasskeyMk = true;
  const signIn = makeDeps(server, deps.credentials);
  await assert.rejects(account.signInWithPasskey(signIn));
  assert.equal(signIn.keyStore.saved.length, 0);
  assert.equal(server.log.at(-1).path, '/api/auth/logout');
});

test('signInWithPasskey zeroes the PRF output', async () => {
  const { server, deps } = await signedUp();
  await account.enrollPasskey(deps, { name: 'laptop', password: STRONG });
  const seen = [];
  const watching = {
    ...deps.credentials,
    get: async (options) => {
      const cred = await deps.credentials.get(options);
      const results = cred.getClientExtensionResults();
      seen.push(results.prf.results.first);
      return { ...cred, getClientExtensionResults: () => results };
    },
  };
  await account.signInWithPasskey(makeDeps(server, watching));
  assert.ok(new Uint8Array(seen[0]).every((b) => b === 0));
});

test('listPasskeys and removePasskey use the account endpoints', async () => {
  const { server, deps } = await signedUp();
  const { id } = await account.enrollPasskey(deps, { name: 'laptop', password: STRONG });
  assert.deepEqual(await account.listPasskeys(deps), [{ id, name: 'laptop' }]);
  await account.removePasskey(deps, id);
  const del = server.log.at(-1);
  assert.equal(del.method, 'DELETE');
  assert.equal(del.path, '/api/me/passkeys/' + encodeURIComponent(id));
  assert.equal(server.passkeys.size, 0);
});

test('googleIdentity returns the proof address, or null without a proof', async () => {
  const signedIn = fakeServer({ google: { email: 'ada@example.com', name: 'Ada L' } });
  assert.deepEqual(await account.googleIdentity(makeDeps(signedIn)), { email: 'ada@example.com', name: 'Ada L' });
  assert.equal(await account.googleIdentity(makeDeps(fakeServer())), null);
});

test('signUp reports an account that is active at once, as a Google sign-up is', async () => {
  const google = fakeServer({ google: { email: 'ada@example.com', name: 'Ada' }, signupStatus: 201 });
  const out = await account.signUp(makeDeps(google), { email: 'ada@example.com', name: 'Ada', password: STRONG, confirm: STRONG });
  assert.equal(out.active, true);
  const mailed = fakeServer();
  assert.equal((await account.signUp(makeDeps(mailed), { email: 'ada@example.com', name: 'Ada', password: STRONG, confirm: STRONG })).active, false);
});

test('forgotWithGoogle posts no address and returns the reset token', async () => {
  const server = fakeServer({ google: { email: 'ada@example.com', name: 'Ada' } });
  assert.equal(await account.forgotWithGoogle(makeDeps(server)), 'reset-token');
  const req = server.log.at(-1);
  assert.equal(req.path, '/api/auth/forgot');
  assert.deepEqual(req.body, {});
  await assert.rejects(account.forgotWithGoogle(makeDeps(fakeServer())), /sign in with Google first/);
});
