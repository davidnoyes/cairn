// Unit tests for the pure external-link decision function in shell.js.
// Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { externalLinkTarget } from './shell.js';

const ORIGIN = 'https://cairn.example';

test('external http(s) link on a different origin returns the URL', () => {
  assert.equal(
    externalLinkTarget('https://github.com/foo/bar', '', '', ORIGIN),
    'https://github.com/foo/bar'
  );
  assert.equal(
    externalLinkTarget('http://example.com/', '', '', ORIGIN),
    'http://example.com/'
  );
});

test('same-origin link returns null', () => {
  assert.equal(externalLinkTarget(ORIGIN + '/other.html', '', '', ORIGIN), null);
});

test('relative href resolves same-origin and returns null', () => {
  assert.equal(externalLinkTarget('./other.html', '', '', ORIGIN), null);
});

test('anchor with target=_blank returns null (native handling works)', () => {
  assert.equal(
    externalLinkTarget('https://github.com/', '_blank', '', ORIGIN),
    null
  );
});

test('anchor with target=_top or a named target returns null', () => {
  assert.equal(externalLinkTarget('https://github.com/', '_top', '', ORIGIN), null);
  assert.equal(externalLinkTarget('https://github.com/', '_parent', '', ORIGIN), null);
  assert.equal(externalLinkTarget('https://github.com/', 'named', '', ORIGIN), null);
});

test('base target=_blank makes native handling work, so returns null', () => {
  assert.equal(
    externalLinkTarget('https://github.com/', '', '_blank', ORIGIN),
    null
  );
});

test('base target=_self does not change the effective target', () => {
  assert.equal(
    externalLinkTarget('https://github.com/', '', '_self', ORIGIN),
    'https://github.com/'
  );
});

test('non-http(s) protocols return null', () => {
  assert.equal(externalLinkTarget('mailto:a@b.com', '', '', ORIGIN), null);
  assert.equal(externalLinkTarget('javascript:alert(1)', '', '', ORIGIN), null);
  assert.equal(externalLinkTarget('#hash', '', '', ORIGIN), null);
});
