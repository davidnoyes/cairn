// Passkey unlock in a real browser. Chromium only: the passkey comes from a
// DevTools virtual authenticator with PRF, which only Chromium offers. The
// user is made fresh here, so no other spec's password or key changes reach
// it, and owns a private artifact the passkey has to unlock.
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { test, expect } from '@playwright/test';
import { MARKER, contentFrame, loadState, logSize, mailedLink, runCli, signIn } from './helpers.mjs';

test.skip(({ browserName }) => browserName !== 'chromium', 'virtual authenticators are a Chromium DevTools feature');

// freshUser signs up, verifies, and signs in with the command-line tool, then
// pushes a private copy of the marker fixture.
async function freshUser(name) {
  const s = loadState();
  const domain = s.users.owner.email.split('@')[1];
  const email = `${name}@${domain}`;
  const password = `e2e-${name}-password-Qm47vz`;
  const config = path.join(s.tmp, 'config', name, 'config.json');
  mkdirSync(path.dirname(config), { recursive: true });
  const before = logSize();
  runCli(s.bin, config, ['signup', '--host', s.appOrigin, '--email', email, '--password-stdin'], { input: `${password}\n` });
  runCli(s.bin, config, ['confirm-email', await mailedLink(new RegExp(`${s.appOrigin}/verify#token=[A-Za-z0-9_-]+`), before)]);
  runCli(s.bin, config, ['login', '--host', s.appOrigin, '--email', email, '--password-stdin'], { input: `${password}\n` });
  const out = JSON.parse(runCli(s.bin, config, ['push', path.join(s.fixturesDir, 'marker'), '--artifact', `${name}-doc`, '--create', '--json']));
  return { email, password, artifact: out.artifact.id };
}

// addAuthenticator gives the page a platform authenticator that keeps
// discoverable credentials, verifies the user, and supports PRF.
async function addAuthenticator(page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
      automaticPresenceSimulation: true, hasPrf: true,
    },
  });
  return { cdp, authenticatorId };
}

test('passkey: enroll on the Account tab, sign out, unlock with the passkey, and read a private artifact', async ({ page }) => {
  const s = loadState();
  const user = await freshUser(`passkey-${Date.now()}`);
  const { cdp, authenticatorId } = await addAuthenticator(page);

  await signIn(page, user.email, user.password);
  await page.getByRole('tab', { name: 'Account' }).click();
  const account = page.getByRole('tabpanel', { name: 'Account' });
  await account.locator('#passkey-name').fill('virtual');
  await account.locator('#passkey-password').fill(user.password);
  await account.getByRole('button', { name: 'Add passkey' }).click();
  await expect(account.locator('#passkeys-status')).toHaveText('Passkey added. You can sign in with it next time.', { timeout: 60_000 });
  await expect(account.locator('#passkeys tr')).toHaveCount(1);
  await expect(account.locator('#passkeys tr td').first()).toHaveText('virtual');
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  expect(credentials).toHaveLength(1);
  expect(credentials[0].isResidentCredential).toBe(true);

  // Signed out, the keys are gone from this browser; only the passkey can
  // bring them back without the password.
  await page.goto(`${s.appOrigin}/logout`);
  await page.goto(`${s.appOrigin}/login`);
  await page.locator('#passkey').click();
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 60_000 });
  await page.goto(`${s.appOrigin}/shared/${user.artifact}`);
  const frame = await contentFrame(page);
  await expect(frame.locator('#marker')).toHaveText(MARKER);

  // Removed, the passkey no longer signs in.
  await page.goto(`${s.appOrigin}/app`);
  await page.getByRole('tab', { name: 'Account' }).click();
  await account.getByRole('button', { name: 'Remove' }).click();
  await account.getByRole('button', { name: 'Remove this passkey?' }).click();
  await expect(account.locator('#passkeys tr')).toHaveCount(0);
  await page.goto(`${s.appOrigin}/logout`);
  await page.goto(`${s.appOrigin}/login`);
  await page.locator('#passkey').click();
  await expect(page.locator('#error')).toHaveText(/passkey sign-in failed/, { timeout: 30_000 });
  await expect(page).toHaveURL(/\/login/);
});

test('passkey: an authenticator without PRF is refused at enrollment, and nothing is stored', async ({ page }) => {
  const user = await freshUser(`noprf-${Date.now()}`);
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
      automaticPresenceSimulation: true, hasPrf: false,
    },
  });
  await signIn(page, user.email, user.password);
  await page.getByRole('tab', { name: 'Account' }).click();
  const account = page.getByRole('tabpanel', { name: 'Account' });
  await account.locator('#passkey-password').fill(user.password);
  await account.getByRole('button', { name: 'Add passkey' }).click();
  await expect(account.locator('#passkeys-status')).toHaveText(/cannot unlock Cairn/, { timeout: 60_000 });
  await expect(account.locator('#passkeys tr')).toHaveCount(0);
});
