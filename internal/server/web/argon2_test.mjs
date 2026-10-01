// Tests for argon2.mjs against the real vendored WebAssembly module: known
// Argon2id answers (one from the brief, one computed independently with
// Go's argon2.IDKey) and invalid-input handling. Run with:
// node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadArgon2 } from './argon2.mjs';
import './vendor/wasm_exec.js'; // Side effect: defines globalThis.Go.

const wasmBytes = readFileSync(new URL('./vendor/argon2.wasm', import.meta.url));
const argon2id = await loadArgon2({ wasmBytes, goClass: globalThis.Go });

function hex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function bytesOf(fill, length) {
  return new Uint8Array(length).fill(fill);
}

test('known answer: "correct horse" / salt of 0x07 / t=3 m=65536 p=1', async () => {
  const password = new TextEncoder().encode('correct horse');
  const salt = bytesOf(0x07, 16);
  const key = await argon2id(password, salt, 3, 65536, 1);
  assert.equal(
    hex(key),
    '7b985d8fa00c9eccccf918c8cb9feaa8036af381caf6f498e099b5b849b8c18a',
  );
});

// Computed independently with a throwaway Go program calling
// golang.org/x/crypto/argon2.IDKey directly (not committed).
test('known answer: "correct horse battery staple" / salt of 0x2a / t=3 m=65536 p=2', async () => {
  const password = new TextEncoder().encode('correct horse battery staple');
  const salt = bytesOf(0x2a, 16);
  const key = await argon2id(password, salt, 3, 65536, 2);
  assert.equal(
    hex(key),
    'c93b7e90b59a92b4273bcb837fb4b6d7d61a50ce892a9843dc17c1b26a79ac14',
  );
});

test('invalid salt rejects, and a later valid call still works', async () => {
  const password = new TextEncoder().encode('correct horse');
  await assert.rejects(() => argon2id(password, 'not a Uint8Array', 3, 65536, 1), Error);

  const key = await argon2id(password, bytesOf(0x07, 16), 3, 65536, 1);
  assert.equal(
    hex(key),
    '7b985d8fa00c9eccccf918c8cb9feaa8036af381caf6f498e099b5b849b8c18a',
  );
});

test('invalid password rejects', async () => {
  await assert.rejects(
    () => argon2id('not a Uint8Array', bytesOf(0x07, 16), 3, 65536, 1),
    Error,
  );
});

test('invalid parameter type rejects', async () => {
  const password = new TextEncoder().encode('correct horse');
  await assert.rejects(() => argon2id(password, bytesOf(0x07, 16), '3', 65536, 1), Error);
});

test('zero passes or too little memory rejects without killing the module', async () => {
  const password = new TextEncoder().encode('correct horse');
  await assert.rejects(() => argon2id(password, bytesOf(0x07, 16), 0, 65536, 1), Error);
  await assert.rejects(() => argon2id(password, bytesOf(0x07, 16), 3, 7, 1), Error);

  const key = await argon2id(password, bytesOf(0x07, 16), 3, 65536, 1);
  assert.equal(
    hex(key),
    '7b985d8fa00c9eccccf918c8cb9feaa8036af381caf6f498e099b5b849b8c18a',
  );
});
