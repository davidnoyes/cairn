// Tests for admin-init.mjs: how the admin page starts, and which errors it
// shows. api and the list loaders are injected, so no DOM is needed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UnauthenticatedError, startAdmin } from './admin-init.mjs';

function harness({ api, lists }) {
  const seen = { who: [], failed: [], loaded: [] };
  const wrapped = lists.map(({ name, load }) => ({
    name,
    load: async () => { seen.loaded.push(name); return load(); },
  }));
  return {
    seen,
    run: () => startAdmin({
      api,
      lists: wrapped,
      setWho: (email) => seen.who.push(email),
      listFailed: (name, err) => seen.failed.push([name, err.message]),
      fail: (err) => seen.failed.push(['init', err.message]),
    }),
  };
}

const ok = async () => {};

test('startAdmin shows who is signed in, then loads every list', async () => {
  const h = harness({ api: async () => ({ email: 'a@example.com' }), lists: [{ name: 'artifacts', load: ok }, { name: 'users', load: ok }] });
  await h.run();
  assert.deepEqual(h.seen.who, ['a@example.com']);
  assert.deepEqual(h.seen.loaded, ['artifacts', 'users']);
  assert.deepEqual(h.seen.failed, []);
});

test('startAdmin stays quiet for the unauthenticated redirect, and loads nothing', async () => {
  const h = harness({ api: async () => { throw new UnauthenticatedError(); }, lists: [{ name: 'artifacts', load: ok }] });
  await h.run();
  assert.deepEqual(h.seen.failed, []);
  assert.deepEqual(h.seen.loaded, []);
});

test('startAdmin shows any other failure of /api/me instead of assuming a sign-in redirect', async () => {
  const h = harness({ api: async () => { throw new Error('HTTP 500'); }, lists: [{ name: 'artifacts', load: ok }] });
  await h.run();
  assert.deepEqual(h.seen.failed, [['init', 'HTTP 500']]);
  assert.deepEqual(h.seen.loaded, []);
});

test('one list failing does not hide the others, and its error is shown', async () => {
  const h = harness({
    api: async () => ({ email: 'a@example.com' }),
    lists: [
      { name: 'artifacts', load: async () => { throw new Error('artifact store is down'); } },
      { name: 'users', load: ok },
      { name: 'keys', load: async () => { throw new Error('keys are down'); } },
    ],
  });
  await h.run();
  assert.deepEqual(h.seen.loaded, ['artifacts', 'users', 'keys']);
  assert.deepEqual(h.seen.failed, [['artifacts', 'artifact store is down'], ['keys', 'keys are down']]);
});

test('a list that hits the unauthenticated redirect is not reported', async () => {
  const h = harness({
    api: async () => ({ email: 'a@example.com' }),
    lists: [{ name: 'users', load: async () => { throw new UnauthenticatedError(); } }],
  });
  await h.run();
  assert.deepEqual(h.seen.failed, []);
});
