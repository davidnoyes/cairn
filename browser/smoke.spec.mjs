// Passes before milestone 4 lands: proves the harness, the server, the users
// and the browser sign-in work.
import { expect, test } from '@playwright/test';
import { loadState, signIn } from './helpers.mjs';

test('smoke: the owner signs in through the UI and reaches a signed-in page', async ({ page }) => {
  const s = loadState();
  await signIn(page, s.users.owner.email, s.users.owner.password);
  expect(new URL(page.url()).origin).toBe(s.appOrigin);
  expect(new URL(page.url()).pathname).not.toMatch(/^\/login/);
  const res = await page.request.get(`${s.appOrigin}/api/me`);
  expect(res.status()).toBe(200);
});
