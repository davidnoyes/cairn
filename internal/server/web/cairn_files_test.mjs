// Checks that cairn.js sends file writes with a Content-Type the server's
// cross-site request protection accepts, and finds its artifact and version
// on a content origin.
// Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('./cairn.js', import.meta.url), 'utf8');

// load runs cairn.js as a page served by Cairn, recording every fetch.
function load(location = { protocol: 'https:', hostname: 'cairn.example', pathname: '/artifacts/a1/v1/index.html' }) {
  const calls = [];
  const window = {};
  const ctx = {
    window,
    location,
    fetch: (url, opts = {}) => {
      calls.push({ url, opts });
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) });
    },
  };
  vm.runInNewContext(source, ctx);
  return { cairn: window.cairn, calls };
}

test('files.upload sends application/octet-stream whatever the data type', async () => {
  const { cairn, calls } = load();
  await cairn.files.upload('photo.png', new Blob(['x'], { type: 'image/png' }));
  const put = calls.find((c) => c.opts.method === 'PUT');
  assert.ok(put, 'no PUT sent');
  assert.equal(put.opts.headers['Content-Type'], 'application/octet-stream');
});

test('files.remove sends a DELETE with no body', async () => {
  const { cairn, calls } = load();
  await cairn.files.remove('photo.png');
  const del = calls.find((c) => c.opts.method === 'DELETE');
  assert.ok(del, 'no DELETE sent');
  assert.equal(del.opts.body, undefined);
});

const A = '0123abcd-0123-4abc-8abc-0123456789ab';
const V = '89abcdef-89ab-4def-8def-89abcdef0123';
const at = (hostname, pathname) => load({ protocol: 'http:', hostname, pathname });

test('on a content origin, the artifact is the host label and the version the first path segment', async () => {
  const { cairn, calls } = at(`${A}.localhost`, `/${V}/sub/index.html`);
  assert.equal(cairn.mode, 'remote');
  assert.equal(cairn.db.downloadURL, `/api/artifacts/${A}/versions/${V}/db/download`);
  assert.equal(cairn.files.url('a b/c.txt'), `/api/artifacts/${A}/versions/${V}/files/a%20b/c.txt`);
  await cairn.db.query('SELECT 1');
  assert.equal(calls[0].url, `/api/artifacts/${A}/versions/${V}/db/query`);
});

test('anything short of a content-origin page of one version stays in debug mode', () => {
  for (const [hostname, pathname] of [
    [`${A}.localhost`, '/_cairn/boot'],
    [`${A}.localhost`, `/${V}`],
    [`${A}.localhost`, `/${V.toUpperCase()}/index.html`],
    [`${A.toUpperCase()}.localhost`, `/${V}/index.html`],
    [`x${A}.localhost`, `/${V}/index.html`],
    [A, `/${V}/index.html`],
    ['cairn.example', `/${V}/index.html`],
  ]) {
    const { cairn } = at(hostname, pathname);
    assert.equal(cairn.mode, 'debug', `${hostname}${pathname}`);
    assert.equal(cairn.db.downloadURL, null, `${hostname}${pathname}`);
  }
});
