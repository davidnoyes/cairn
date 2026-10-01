// Unit tests for the pure link decision function in shell.js.
// Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { linkAction } from './shell.js';

const ORIGIN = 'https://cairn.example';
const FRAME = '/artifacts/a1/v1/';
const BASE = ORIGIN + FRAME + 'index.html';

// act classifies a click on href in the artifact at FRAME.
const act = (href, target = '', baseTarget = '') => linkAction(href, target, baseTarget, BASE, ORIGIN, FRAME);

test('external http(s) link opens in a new tab', () => {
  assert.deepEqual(act('https://github.com/foo/bar'), { open: 'https://github.com/foo/bar' });
  assert.deepEqual(act('http://example.com/'), { open: 'http://example.com/' });
});

test('links inside this artifact version stay in the frame', () => {
  assert.equal(act('./other.html'), null);
  assert.equal(act('sub/page.html?x=1'), null);
  assert.equal(act(ORIGIN + FRAME + 'other.html'), null);
  assert.equal(act('#hash'), null);
});

test('other Cairn pages replace the whole page', () => {
  assert.deepEqual(act('/admin'), { navigate: ORIGIN + '/admin' });
  assert.deepEqual(act('/'), { navigate: ORIGIN + '/' });
  assert.deepEqual(act('/shared/b2'), { navigate: ORIGIN + '/shared/b2' });
  assert.deepEqual(act(ORIGIN + '/shared/b2/v9'), { navigate: ORIGIN + '/shared/b2/v9' });
});

test("an artifact's root opens in the shell, so the header and home link stay", () => {
  assert.deepEqual(act('/artifacts/b2'), { navigate: ORIGIN + '/shared/b2' });
  assert.deepEqual(act('/artifacts/b2/'), { navigate: ORIGIN + '/shared/b2' });
  assert.deepEqual(act('/artifacts/b2/v9/'), { navigate: ORIGIN + '/shared/b2/v9' });
  assert.deepEqual(act('../v2/'), { navigate: ORIGIN + '/shared/a1/v2' }, 'another version of this artifact');
});

test('deep or parameterized artifact links navigate as written', () => {
  assert.deepEqual(act('/artifacts/b2/v9/page.html'), { navigate: ORIGIN + '/artifacts/b2/v9/page.html' });
  assert.deepEqual(act('/artifacts/b2/v9/?q=1'), { navigate: ORIGIN + '/artifacts/b2/v9/?q=1' });
  assert.deepEqual(act('/artifacts/b2/#top'), { navigate: ORIGIN + '/artifacts/b2/#top' });
});

test('an explicit target other than _self is left to the browser', () => {
  for (const t of ['_blank', '_top', '_parent', 'named']) {
    assert.equal(act('https://github.com/', t), null, t);
    assert.equal(act('/shared/b2', t), null, t);
  }
});

test('base target applies unless the anchor sets its own', () => {
  assert.equal(act('https://github.com/', '', '_blank'), null);
  assert.deepEqual(act('https://github.com/', '', '_self'), { open: 'https://github.com/' });
  assert.deepEqual(act('https://github.com/', '_self', '_blank'), { open: 'https://github.com/' });
});

test('non-http(s) protocols and bad URLs are left alone', () => {
  assert.equal(act('mailto:a@b.com'), null);
  assert.equal(act('javascript:alert(1)'), null);
  assert.equal(act('http://[bad'), null);
});
