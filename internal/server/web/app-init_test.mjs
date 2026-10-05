// Tests for app-init.mjs: how the app page starts, and which errors it shows.
// api, the key store, and the list loaders are injected, so no DOM is needed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UnauthenticatedError, startApp } from './app-init.mjs';

const ME = { id: 'u1', email: 'a@example.com', isAdmin: false };
const KEYS = { userId: 'u1', email: 'a@example.com' };

function harness(opts) {
  const { api = async () => ME, lists } = opts;
  const keys = 'keys' in opts ? opts.keys : KEYS; // an explicit undefined is a case under test
  const seen = { user: [], failed: [], loaded: [], login: 0 };
  const wrapped = lists.map(({ name, load, admin }) => ({
    name,
    admin,
    load: async (ctx) => { seen.loaded.push([name, ctx.me.id, ctx.keys.userId]); return load(); },
  }));
  return {
    seen,
    run: () => startApp({
      api,
      keyStore: { load: async () => { if (keys instanceof Error) throw keys; return keys; } },
      toLogin: () => { seen.login++; },
      lists: wrapped,
      setUser: (me) => seen.user.push(me.email),
      listFailed: (name, err) => seen.failed.push([name, err.message]),
      fail: (err) => seen.failed.push(['init', err.message]),
    }),
  };
}

const ok = async () => {};

test('startApp shows who is signed in, then loads every list with the account and its keys', async () => {
  const h = harness({ lists: [{ name: 'artifacts', load: ok }, { name: 'keys', load: ok }] });
  const ctx = await h.run();
  assert.deepEqual(h.seen.user, ['a@example.com']);
  assert.deepEqual(h.seen.loaded, [['artifacts', 'u1', 'u1'], ['keys', 'u1', 'u1']]);
  assert.deepEqual(h.seen.failed, []);
  assert.deepEqual(ctx, { me: ME, keys: KEYS });
});

test('startApp loads the administrator lists only for an administrator', async () => {
  const lists = [{ name: 'artifacts', load: ok }, { name: 'users', load: ok, admin: true }];
  const user = harness({ lists });
  await user.run();
  assert.deepEqual(user.seen.loaded.map(([n]) => n), ['artifacts']);
  const admin = harness({ api: async () => ({ ...ME, isAdmin: true }), lists });
  await admin.run();
  assert.deepEqual(admin.seen.loaded.map(([n]) => n), ['artifacts', 'users']);
});

test('startApp sends a session with no unlocked keys to sign in, and loads nothing', async () => {
  for (const keys of [undefined, null]) {
    const h = harness({ keys, lists: [{ name: 'artifacts', load: ok }] });
    assert.equal(await h.run(), null);
    assert.equal(h.seen.login, 1);
    assert.deepEqual(h.seen.loaded, []);
    assert.deepEqual(h.seen.user, []);
  }
});

test("startApp never uses another account's keys left in the browser", async () => {
  const h = harness({ keys: { userId: 'someone-else' }, lists: [{ name: 'artifacts', load: ok }] });
  assert.equal(await h.run(), null);
  assert.equal(h.seen.login, 1);
  assert.deepEqual(h.seen.loaded, []);
});

test('startApp sends the visitor to sign in when the key store cannot be read', async () => {
  const h = harness({ keys: new Error('IndexedDB is gone'), lists: [{ name: 'artifacts', load: ok }] });
  assert.equal(await h.run(), null);
  assert.equal(h.seen.login, 1);
  assert.deepEqual(h.seen.loaded, []);
});

test('startApp stays quiet for the unauthenticated redirect, and loads nothing', async () => {
  const h = harness({ api: async () => { throw new UnauthenticatedError(); }, lists: [{ name: 'artifacts', load: ok }] });
  assert.equal(await h.run(), null);
  assert.deepEqual(h.seen.failed, []);
  assert.deepEqual(h.seen.loaded, []);
  assert.equal(h.seen.login, 0);
});

test('startApp shows any other failure of /api/me in the flash and every list', async () => {
  const h = harness({ api: async () => { throw new Error('HTTP 500'); }, lists: [{ name: 'artifacts', load: ok }, { name: 'keys', load: ok }] });
  assert.equal(await h.run(), null);
  assert.deepEqual(h.seen.failed, [['init', 'HTTP 500'], ['artifacts', 'HTTP 500'], ['keys', 'HTTP 500']]);
  assert.deepEqual(h.seen.loaded, []);
});

test('one list failing does not hide the others, and its error is shown', async () => {
  const h = harness({
    lists: [
      { name: 'artifacts', load: async () => { throw new Error('artifact store is down'); } },
      { name: 'account', load: ok },
      { name: 'keys', load: async () => { throw new Error('keys are down'); } },
    ],
  });
  await h.run();
  assert.deepEqual(h.seen.loaded.map(([n]) => n), ['artifacts', 'account', 'keys']);
  assert.deepEqual(h.seen.failed, [['artifacts', 'artifact store is down'], ['keys', 'keys are down']]);
});

test('a list that hits the unauthenticated redirect is not reported', async () => {
  const h = harness({ lists: [{ name: 'keys', load: async () => { throw new UnauthenticatedError(); } }] });
  await h.run();
  assert.deepEqual(h.seen.failed, []);
});
