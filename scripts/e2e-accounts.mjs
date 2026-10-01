#!/usr/bin/env node
// End-to-end check of the browser account flows against a real server: it
// drives internal/server/web/account.mjs, the module the account pages use,
// with real Argon2id (the vendored WebAssembly build) and the real vendored
// zxcvbn. scripts/e2e.sh runs it after the CLI part, passing the server's
// URL, the server log (where the log:// mailer writes each emailed link), and
// the email and password of an account the CLI already signed up.
//
// Usage: node scripts/e2e-accounts.mjs HOST SERVER_LOG CLI_EMAIL CLI_PASSWORD
//
// It leaves one account behind, web@e2e.test, with the password
// FINAL_PASSWORD, so the shell script can check that the CLI signs in to it.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import * as account from '../internal/server/web/account.mjs';
import * as e2e from '../internal/server/web/e2e.mjs';
import { loadArgon2 } from '../internal/server/web/argon2.mjs';
import '../internal/server/web/vendor/wasm_exec.js'; // Side effect: defines globalThis.Go.

const [host, serverLog, cliEmail, cliPassword] = process.argv.slice(2);
const EMAIL = 'web@e2e.test';
const FIRST_PASSWORD = 'browser-flow-strong-pw-1';
const FINAL_PASSWORD = 'browser-flow-even-stronger-pw-2';

const wasmBytes = readFileSync(new URL('../internal/server/web/vendor/argon2.wasm', import.meta.url));
const argon2id = await loadArgon2({ wasmBytes, goClass: globalThis.Go });
const zxcvbn = createRequire(import.meta.url)('../internal/server/web/vendor/zxcvbn.js');

// loginBundles keeps the bundle each login response carried, so the checks
// can compare public keys across a reset.
const loginBundles = [];
function makeDeps() {
  return {
    async fetch(path, options) {
      const resp = await fetch(host + path, options);
      if (path === '/api/auth/login' && resp.ok) loginBundles.push((await resp.clone().json()).bundle);
      return resp;
    },
    stretch: (password, email, params) => e2e.stretch(password, email, params, argon2id),
    strength(password, userInputs) {
      const { score, feedback } = zxcvbn(password, userInputs);
      return { score, feedback };
    },
    keyStore: { saved: [], async save(r) { this.saved.push(r); }, async clear() { this.saved.length = 0; } },
  };
}

function pass(msg) { console.log(`  \x1b[32m✓\x1b[0m ${msg}`); }

// emailedLinks returns every link of one kind ("verify" or "reset") in the log.
function emailedLinks(kind) {
  const re = new RegExp(`${host}/${kind}#token=[A-Za-z0-9_-]+`, 'g');
  return readFileSync(serverLog, 'utf8').match(re) ?? [];
}

// nextLink waits for a new link of one kind to reach the log.
async function nextLink(kind, before) {
  for (let i = 0; i < 50; i++) {
    const links = emailedLinks(kind);
    if (links.length > before) return links.at(-1);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`no new ${kind} link in the server log`);
}

// pageFor is what the verify and reset pages hand to the flows: a location
// holding the link's fragment, and a history that records the strip.
function pageFor(link) {
  const url = new URL(link);
  const stripped = [];
  return { location: { hash: url.hash, pathname: url.pathname, search: url.search }, history: { replaceState: (s, t, u) => stripped.push(u) }, stripped };
}

const verifyBefore = emailedLinks('verify').length;

// -- sign up
const deps = makeDeps();
await assert.rejects(
  account.signUp(deps, { email: EMAIL, name: 'Web', password: 'password1', confirm: 'password1' }),
  (err) => err.name === 'WeakPasswordError',
);
pass('browser sign-up refuses a weak password, with no request');

const { recoveryCode } = await account.signUp(deps, { email: EMAIL, name: 'Web', password: FIRST_PASSWORD, confirm: FIRST_PASSWORD });
assert.match(recoveryCode, /^([A-Z2-7]{4}-){6}[A-Z2-7]{2}$/);
pass('browser sign-up accepted; recovery code shown once');

// -- verify
// Prelogin answers an unverified address with a fake salt, so the key is wrong.
await assert.rejects(account.signIn(deps, { email: EMAIL, password: FIRST_PASSWORD }), /invalid email or password/);
pass('sign-in is refused before the email is verified');

const verifyPage = pageFor(await nextLink('verify', verifyBefore));
await account.verifyFromLink(deps, verifyPage);
assert.deepEqual(verifyPage.stripped, ['/verify'], 'the token left the address bar');
pass('verification link followed; token stripped from the address bar');

// -- sign in
await account.signIn(deps, { email: EMAIL, password: FIRST_PASSWORD });
assert.equal(deps.keyStore.saved.length, 1);
const before = deps.keyStore.saved[0];
for (const key of [before.mk, before.mkSeal, before.ek, before.x25519.privateKey, before.ed25519]) {
  assert.equal(key.extractable, false);
}
const bundleBefore = loginBundles.at(-1);
assert.deepEqual(before.x25519.publicKey, e2e.unb64(bundleBefore.x25519Pub));
const probe = new TextEncoder().encode('probe');
assert.ok(await e2e.verify(e2e.unb64(bundleBefore.ed25519Pub), 'probe', probe, await e2e.sign(before.ed25519, 'probe', probe)));
pass('browser sign-in opened the bundle and stored non-extractable keys');

// -- reset with the recovery code
const resetBefore = emailedLinks('reset').length;
await account.forgot(deps, { email: EMAIL });
const resetPage = pageFor(await nextLink('reset', resetBefore));
const { token, info } = await account.resetBeginFromLink(deps, resetPage);
assert.deepEqual(resetPage.stripped, ['/reset'], 'the token left the address bar');
await account.resetWithRecovery(deps, { token, info, recoveryCode, password: FINAL_PASSWORD, confirm: FINAL_PASSWORD });
pass('password reset with the recovery code');

await assert.rejects(account.signIn(makeDeps(), { email: EMAIL, password: FIRST_PASSWORD }), /invalid email or password/);
pass('the old password no longer signs in');

const afterDeps = makeDeps();
await account.signIn(afterDeps, { email: EMAIL, password: FINAL_PASSWORD });
const after = afterDeps.keyStore.saved[0];
const bundleAfter = loginBundles.at(-1);
assert.equal(bundleAfter.x25519Pub, bundleBefore.x25519Pub);
assert.equal(bundleAfter.ed25519Pub, bundleBefore.ed25519Pub);
assert.notEqual(bundleAfter.kdf.salt, bundleBefore.kdf.salt);
assert.deepEqual(after.x25519.publicKey, before.x25519.publicKey);
assert.ok(await e2e.verify(e2e.unb64(bundleBefore.ed25519Pub), 'probe', probe, await e2e.sign(after.ed25519, 'probe', probe)));
pass('after the reset the public keys are the same, and the new keys sign for them');

await assert.rejects(
  account.resetWithRecovery(afterDeps, { token, info, recoveryCode, password: FINAL_PASSWORD, confirm: FINAL_PASSWORD }),
  /invalid or expired token/,
);
pass('the reset token works once');

// -- an account the CLI created opens in the browser code
const cliDeps = makeDeps();
await account.signIn(cliDeps, { email: cliEmail, password: cliPassword });
assert.equal(cliDeps.keyStore.saved.length, 1);
pass('browser sign-in opens a bundle the CLI generated');

// -- sign out
await account.signOut(cliDeps);
assert.equal(cliDeps.keyStore.saved.length, 0);
pass('sign-out clears the stored keys');
