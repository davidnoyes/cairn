// Checks that cairn.js sends file writes with a Content-Type the server's
// cross-site request protection accepts.
// Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('./cairn.js', import.meta.url), 'utf8');

// load runs cairn.js as a page served by Cairn, recording every fetch.
function load() {
  const calls = [];
  const window = {};
  const ctx = {
    window,
    location: { protocol: 'https:', pathname: '/artifacts/a1/v1/index.html' },
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
