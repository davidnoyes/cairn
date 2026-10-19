// Tests for cli.mjs, the logic of the command-line sign-in page, against a
// fake fetch. Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { googleSignInURL, handOver, isLoopbackRedirect } from './cli.mjs';

const STATE = 'abcdefghijklmnop0123456789';
const json = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

test('googleSignInURL returns to this page, query included', () => {
  const url = googleSignInURL({ pathname: '/auth/cli', search: `?port=40000&state=${STATE}` });
  assert.equal(url, '/auth/google?next=' + encodeURIComponent(`/auth/cli?port=40000&state=${STATE}`));
});

test('isLoopbackRedirect accepts only the tool callback on the same port', () => {
  const good = `http://127.0.0.1:40000/callback?state=${STATE}&email=a%40b.c&proof=p`;
  assert.equal(isLoopbackRedirect(good, 40000), true);
  for (const bad of [
    good.replace('40000', '40001'),
    good.replace('127.0.0.1', 'localhost'),
    good.replace('http:', 'https:'),
    good.replace('/callback?', '/other?'),
    good.replace('/callback?', '/callback'),
    'http://127.0.0.1:40000@evil.example/callback?x=1',
    `http://evil.example/?http://127.0.0.1:40000/callback?${STATE}`,
    '',
    undefined,
    null,
    { toString: () => good },
  ]) {
    assert.equal(isLoopbackRedirect(bad, 40000), false, String(bad));
  }
});

test('handOver posts the port as a number and returns the redirect', async () => {
  const redirect = `http://127.0.0.1:40000/callback?state=${STATE}&email=a%40b.c&proof=p`;
  const calls = [];
  const deps = { fetch: async (path, options) => { calls.push({ path, options }); return json(200, { redirect }); } };
  assert.equal(await handOver(deps, { port: 40000, state: STATE }), redirect);
  assert.equal(calls[0].path, '/api/auth/cli');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.headers['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(calls[0].options.body), { port: 40000, state: STATE });
});

test('handOver refuses a redirect that is not the tool', async () => {
  const deps = { fetch: async () => json(200, { redirect: 'https://evil.example/callback?proof=p' }) };
  await assert.rejects(handOver(deps, { port: 40000, state: STATE }), /not the command-line tool/);
});

test('handOver reports the server error', async () => {
  const deps = { fetch: async () => json(403, { error: 'sign in with Google first' }) };
  await assert.rejects(handOver(deps, { port: 40000, state: STATE }), (err) => err.status === 403 && /sign in with Google first/.test(err.message));
});
