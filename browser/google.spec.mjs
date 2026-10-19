// Google sign-in in a real browser: a second Cairn server with Google
// configured, pointed at a fake Google that this spec runs. The binary is the
// e2egoogle build, which reads the fake's address from CAIRN_TEST_GOOGLE_URL.
// The fake signs in whoever google.as() names, checks the PKCE verifier and
// the client secret, and returns an unsigned ID token, as Google's token
// endpoint does over TLS.
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, openSync, rmSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test, expect } from '@playwright/test';
import { loadState } from './helpers.mjs';

const DOMAIN = 'google.test';
const CLIENT_ID = 'e2e-client';
const CLIENT_SECRET = 'e2e-secret';

const b64url = (buf) => Buffer.from(buf).toString('base64url');

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => { data += c; });
    req.on('end', () => resolve(data));
  });
}

// fakeGoogle answers /authorize by sending the browser straight back with a
// code, and /token by trading that code, once, for an ID token.
async function fakeGoogle() {
  const codes = new Map();
  const google = { current: null, exchanges: 0 };
  google.as = (user) => { google.current = user; };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://fake');
    if (url.pathname === '/authorize') {
      const code = randomUUID();
      codes.set(code, { user: google.current, challenge: url.searchParams.get('code_challenge') });
      const back = new URL(url.searchParams.get('redirect_uri'));
      back.searchParams.set('code', code);
      back.searchParams.set('state', url.searchParams.get('state'));
      res.writeHead(302, { Location: back.toString() });
      res.end();
      return;
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      const form = new URLSearchParams(await readBody(req));
      const grant = codes.get(form.get('code'));
      codes.delete(form.get('code'));
      const verifierOK = grant && b64url(createHash('sha256').update(form.get('code_verifier') ?? '').digest()) === grant.challenge;
      if (!grant || !verifierOK || form.get('client_secret') !== CLIENT_SECRET) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_grant' }));
        return;
      }
      google.exchanges++;
      const { email, name, hd } = grant.user;
      const claims = { iss: 'https://accounts.google.com', aud: CLIENT_ID, exp: Math.floor(Date.now() / 1000) + 300, email, email_verified: true, name, ...(hd ? { hd } : {}) };
      const idToken = `${b64url('{"alg":"RS256"}')}.${b64url(JSON.stringify(claims))}.${b64url('sig')}`;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id_token: idToken }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  google.url = `http://127.0.0.1:${server.address().port}`;
  google.close = () => new Promise((resolve) => server.close(resolve));
  return google;
}

let google;
let cairn;
let origin;
let tmp;

test.beforeAll(async () => {
  const s = loadState();
  google = await fakeGoogle();
  tmp = mkdtempSync(path.join(tmpdir(), 'cairn-google-'));
  const port = await freePort();
  origin = `http://localhost:${port}`;
  const env = { ...process.env, CAIRN_TEST_GOOGLE_URL: google.url, CAIRN_TEST_CLOCK_FILE: path.join(tmp, 'clock-offset') };
  delete env.CAIRN_HOST;
  delete env.CAIRN_API_KEY;
  const log = openSync(path.join(tmp, 'server.log'), 'a');
  cairn = spawn(s.bin, [
    'serve', '--addr', `127.0.0.1:${port}`, '--public-url', origin, '--data-dir', path.join(tmp, 'data'),
    '--smtp-url', 'log://', '--signup-domain', DOMAIN,
    '--google-client-id', CLIENT_ID, '--google-client-secret', CLIENT_SECRET,
  ], { env, stdio: ['ignore', log, log] });
  for (let i = 0; i < 300; i++) {
    try {
      if ((await fetch(`${origin}/healthz`)).ok) return;
    } catch {
      // Not listening yet.
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('the Google-mode server did not start');
});

test.afterAll(async () => {
  cairn?.kill('SIGTERM');
  await google?.close();
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

// continueWithGoogle clicks through the page's Google button and waits to
// land back on page.
async function continueWithGoogle(page, pathname) {
  await expect(page.locator('#google')).toBeVisible({ timeout: 30_000 });
  await page.locator('#google-start').click();
  await page.waitForURL((u) => u.pathname === pathname && u.origin === origin);
}

// confirmRecovery reads the code the page shows once, then fills in the
// group it blanks out. It returns the code.
async function confirmRecovery(page) {
  const panel = page.locator('#recovery');
  await expect(panel.locator('#code')).not.toHaveText('', { timeout: 60_000 });
  const code = (await panel.locator('#code').textContent()).trim();
  await panel.getByRole('button', { name: 'Next' }).click();
  const masked = (await panel.locator('#masked').textContent()).split('-');
  const missing = masked.findIndex((g) => /^_+$/.test(g));
  await panel.getByLabel('fill in the missing group from your saved copy').fill(code.split('-')[missing]);
  await panel.getByRole('button', { name: 'Confirm' }).click();
  return code;
}

test('google: sign up, sign in, and reset with the recovery code, each through Google first', async ({ browser, browserName }) => {
  const email = `ada-${browserName}@${DOMAIN}`;
  const password = `google-${browserName}-password-Qm47vz`;
  google.as({ email, name: 'Ada Lovelace', hd: DOMAIN });

  // Sign-up: the address comes from Google and cannot be changed, and the
  // account is active at once, so the page signs straight in.
  let context = await browser.newContext();
  let page = await context.newPage();
  await page.goto(`${origin}/signup`);
  await expect(page.locator('#form')).toBeHidden();
  await continueWithGoogle(page, '/signup');
  await expect(page.locator('#email')).toHaveValue(email);
  await expect(page.locator('#email')).not.toBeEditable();
  await expect(page.locator('#name')).toHaveValue('Ada Lovelace');
  await page.locator('#password').fill(password);
  await page.locator('#confirm').fill(password);
  await page.locator('#submit').click();
  const code = await confirmRecovery(page);
  await page.waitForURL(`${origin}/app`, { timeout: 60_000 });
  await expect(page.locator('#who')).toHaveText(email);
  await context.close();

  // Sign-in: no password form until Google has vouched for the address.
  context = await browser.newContext();
  page = await context.newPage();
  await page.goto(`${origin}/login`);
  await expect(page.locator('#form')).toBeHidden();
  await continueWithGoogle(page, '/login');
  await expect(page.locator('#google-email')).toHaveText(email);
  await expect(page.locator('#email')).toHaveValue(email);
  await page.locator('#password').fill(password);
  await page.locator('#submit').click();
  await page.waitForURL(`${origin}/app`, { timeout: 60_000 });
  await expect(page.locator('#who')).toHaveText(email);
  await context.close();

  // Reset: Google stands in for the mailed link, and the recovery code keeps
  // the keys.
  const reset = `${password}-reset`;
  context = await browser.newContext();
  page = await context.newPage();
  await page.goto(`${origin}/forgot`);
  await continueWithGoogle(page, '/forgot');
  await expect(page.locator('#google-email')).toHaveText(email);
  await page.locator('#google-submit').click();
  await page.waitForURL((u) => u.pathname === '/reset');
  await page.locator('#code').fill(code);
  await page.locator('#password').fill(reset);
  await page.locator('#confirm').fill(reset);
  await page.locator('#submit').click();
  await expect(page.getByText('Sign in with the new password.')).toBeVisible({ timeout: 60_000 });
  await page.goto(`${origin}/login`);
  await continueWithGoogle(page, '/login');
  await page.locator('#password').fill(reset);
  await page.locator('#submit').click();
  await page.waitForURL(`${origin}/app`, { timeout: 60_000 });
  await context.close();
});

test('google: an address in the signup domain from outside its Workspace gets no proof', async ({ page, browserName }) => {
  google.as({ email: `mallory-${browserName}@${DOMAIN}`, name: 'Mallory' });
  const before = google.exchanges;
  await page.goto(`${origin}/login`);
  await page.locator('#google-start').click();
  await page.waitForURL((u) => u.pathname === '/auth/google/callback');
  expect(google.exchanges).toBe(before + 1);
  await expect(page.locator('#error')).toHaveText('Google sign-in failed.');
  await expect(page.locator('#google')).toBeVisible();
  await expect(page.locator('#form')).toBeHidden();
});
