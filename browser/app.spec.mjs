// Milestone 6 browser tests, written before the feature: the app page, its
// lists, API keys and account settings. See design/e2e-api.md "The app page".
//
// The page's contract with these tests:
// - Tabs are role=tab: Artifacts, API keys, Account, and Users for an admin.
// - #own and #shared list artifacts as tr[data-id] rows with td.name, td.desc,
//   td.access and td.public. An owner's row has Share and Delete buttons.
// - API keys: #key-name, #key-password, a "Create key" button, #key-new for
//   the key shown once, tr[data-key] rows with a Revoke button, #keys-status.
// - Account: #pw-current, #pw-new, #pw-confirm and "Change password";
//   #rc-password, "New recovery code" and #rc-new; #account-status.
// - No page ever opens a native alert, confirm or prompt.
import { readFileSync } from 'node:fs';
import { expect, test } from './test.mjs';
import {
  MARKER, cli, cliWithKey, contentFrame, files, loadState, logSize, mailedLink, runCli, signIn, signedInContext,
} from './helpers.mjs';

// noNativeDialogs fails the test if the page opens alert, confirm or prompt:
// a hostile name that ran as markup would call alert.
function noNativeDialogs(page) {
  const seen = [];
  page.on('dialog', async (d) => {
    seen.push(`${d.type()}: ${d.message()}`);
    await d.dismiss();
  });
  return seen;
}

async function openTab(page, name) {
  const s = loadState();
  if (!page.url().startsWith(`${s.appOrigin}/app`)) await page.goto(`${s.appOrigin}/app`);
  await page.getByRole('tab', { name }).click();
}

test('app: / and /admin open /app when signed in, and /app sends a visitor with no session to /login', async ({ ownerPage, browser }) => {
  const s = loadState();
  for (const from of ['/', '/admin']) {
    await ownerPage.goto(`${s.appOrigin}${from}`);
    await expect(ownerPage).toHaveURL(`${s.appOrigin}/app`);
  }
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(`${s.appOrigin}/app`);
    await expect(page).toHaveURL(/\/login(\?|$)/);
  } finally {
    await context.close();
  }
});

test('app: the owner lists their artifacts by name, and a viewer finds the shared one under Shared with you', async ({ ownerPage, browser }) => {
  const s = loadState();
  const plain = s.artifacts['plain-doc'].id;
  await openTab(ownerPage, 'Artifacts');
  const own = ownerPage.locator(`#own tr[data-id="${plain}"]`);
  await expect(own.locator('td.name')).toHaveText('plain-doc');
  await expect(own.getByRole('button', { name: 'Share' })).toBeVisible();
  await expect(own.locator('td.public')).toHaveText(/public/i);
  await expect(ownerPage.getByRole('tab', { name: 'Users' })).toBeVisible();

  const { context, page } = await signedInContext(browser, 'viewer');
  try {
    await openTab(page, 'Artifacts');
    const shared = page.locator(`#shared tr[data-id="${plain}"]`);
    await expect(shared.locator('td.name')).toHaveText('plain-doc');
    await expect(shared.locator('td.access')).toHaveText(/viewer/i);
    await expect(shared.getByRole('button', { name: 'Share' })).toHaveCount(0);
    await expect(page.locator(`#own tr[data-id="${plain}"]`)).toHaveCount(0);
    await expect(page.getByRole('tab', { name: 'Users' })).toHaveCount(0);
  } finally {
    await context.close();
  }
});

test('app: hostile names and descriptions render as text in the list, the share dialog, and the shell', async ({ ownerPage, browserName }) => {
  const s = loadState();
  const nameMarker = `CAIRN-NAME-MARKER-${browserName}-c81e`;
  const hostile = [
    `<img src=x onerror=alert(1)>${nameMarker}`,
    '‮gnp.exe',
    'N'.repeat(10_000),
    'lone \uD800 surrogate',
  ];
  const dialogs = noNativeDialogs(ownerPage);
  const ids = hostile.map((name) => JSON.parse(cli('owner', ['artifact', 'create', '--name', name, '--description', `<b>${name}</b>`, '--json'])).id);

  await openTab(ownerPage, 'Artifacts');
  for (const [i, name] of hostile.entries()) {
    // The CLI's argument went through UTF-8, so a lone surrogate arrives as U+FFFD.
    const want = name.toWellFormed();
    const row = ownerPage.locator(`#own tr[data-id="${ids[i]}"]`);
    await expect(row.locator('td.name')).toHaveText(want);
    await expect(row.locator('td.desc')).toHaveText(`<b>${want}</b>`);
    // A right-to-left override stays inside its own cell.
    const bidi = await row.locator('td.name').evaluate((el) => getComputedStyle(el).unicodeBidi);
    expect(['isolate', 'plaintext', 'isolate-override'], 'td.name unicode-bidi').toContain(bidi);
    // A 10,000-character name does not stretch the row down the page.
    expect((await row.boundingBox()).height, 'row height').toBeLessThan(200);

    await row.getByRole('button', { name: 'Share' }).click();
    await expect(ownerPage.locator('#share-title')).toHaveText(want);
    await ownerPage.locator('dialog#share').getByRole('button', { name: 'Close' }).click();
  }
  await expect(ownerPage.locator('img[src="x"]')).toHaveCount(0);

  // The first carries a version, so the shell has something to show.
  cli('owner', ['push', `${s.fixturesDir}/marker`, '--artifact', ids[0], '--name', hostile[0], '--changelog', hostile[0]]);
  await ownerPage.goto(`${s.appOrigin}/shared/${ids[0]}`);
  await contentFrame(ownerPage);
  await expect(ownerPage.locator('#name')).toHaveText(hostile[0]);
  await expect(ownerPage.locator('#desc')).toHaveText(`<b>${hostile[0]}</b>`);
  await expect(ownerPage.locator('#version option')).toContainText([hostile[0]]);
  expect(await ownerPage.title()).toBe(hostile[0]);
  await expect(ownerPage.locator('img[src="x"]')).toHaveCount(0);
  expect(dialogs, 'native dialogs opened').toEqual([]);

  const needle = Buffer.from(nameMarker);
  const leaks = files(s.dataDir).filter((f) => readFileSync(f).includes(needle));
  expect(leaks, 'files under the data dir that hold the artifact name').toEqual([]);
});

test('shell: no password field appears over an artifact, and locked keys send the visitor to /login', async ({ ownerPage, ownerContext, browser }) => {
  const s = loadState();
  const id = s.artifacts['plain-doc'].id;
  const html = await (await ownerPage.request.get(`${s.appOrigin}/shared/${id}`)).text();
  expect(html, 'shell page markup').not.toMatch(/password/i);
  await ownerPage.goto(`${s.appOrigin}/shared/${id}`);
  await expect((await contentFrame(ownerPage)).locator('#marker')).toHaveText(MARKER);
  await expect(ownerPage.locator('input[type=password]')).toHaveCount(0);

  // The session cookie without the keys the sign-in unlocked: the shell must
  // not ask for the password itself.
  const cookiesOnly = await browser.newContext({ storageState: { cookies: (await ownerContext.storageState()).cookies, origins: [] } });
  try {
    const page = await cookiesOnly.newPage();
    await page.goto(`${s.appOrigin}/shared/${id}`);
    await expect(page).toHaveURL(/\/login(\?|$)/);
    expect(page.frames().filter((f) => f.url().includes('.localhost')), 'artifact frames').toEqual([]);
  } finally {
    await cookiesOnly.close();
  }
});

test('keys: an API key needs the password, is shown once, works for the CLI, and stops when revoked', async ({ browser, browserName }) => {
  const s = loadState();
  const user = `acct-${browserName}`;
  const { context, page } = await signedInContext(browser, user);
  try {
    await openTab(page, 'API keys');
    // The CLI's sign-in in setup left a device key, listed with the rest.
    const rows = page.locator('#keys tr[data-key]');
    await expect(rows.locator('td.name')).toContainText(['device']);
    const before = await rows.count();
    const mine = rows.filter({ has: page.locator('td.name', { hasText: `agent-${browserName}` }) });
    await page.locator('#key-name').fill('wrong-password');
    await page.locator('#key-password').fill('not-the-password');
    await page.getByRole('button', { name: 'Create key' }).click();
    await expect(page.locator('#keys-status')).toHaveText(/password/i);
    await expect(page.locator('#key-new')).toHaveText('');
    await expect(rows).toHaveCount(before);

    await page.locator('#key-name').fill(`agent-${browserName}`);
    await page.locator('#key-password').fill(s.users[user].password);
    await page.getByRole('button', { name: 'Create key' }).click();
    await expect(page.locator('#key-new')).toHaveText(/^cairn_[0-9a-f]{16}_[0-9a-f]{32}_[0-9a-f]{64}$/);
    const key = await page.locator('#key-new').textContent();
    await expect(page.locator('#key-password')).toHaveValue('');
    await expect(rows).toHaveCount(before + 1);
    await expect(mine).toHaveCount(1);

    // The key opens the user's keys, not just the API: the CLI lists the
    // artifact by its encrypted name.
    const listed = JSON.parse(cliWithKey(key, ['artifact', 'list', '--json']));
    expect(listed.map((a) => a.name)).toContain(`acct-doc-${browserName}`);

    await page.reload();
    await openTab(page, 'API keys');
    await expect(page.locator('#key-new')).toHaveText('');
    expect(await page.content(), 'page after reload').not.toContain(key.split('_')[3]);

    await mine.getByRole('button', { name: 'Revoke' }).click();
    await expect(mine).toHaveCount(0);
    await expect(rows).toHaveCount(before);
    expect(() => cliWithKey(key, ['artifact', 'list', '--json']), 'CLI with a revoked key').toThrow();
  } finally {
    await context.close();
  }
});

test('account: the password changes in the browser, and only the new one signs in', async ({ browser, browserName }) => {
  const s = loadState();
  const user = `acct-${browserName}`;
  const { email, password } = s.users[user];
  const next = `${password}-changed`;
  const change = async (page, from, to) => {
    await openTab(page, 'Account');
    await page.locator('#pw-current').fill(from);
    await page.locator('#pw-new').fill(to);
    await page.locator('#pw-confirm').fill(to);
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page.locator('#account-status')).toHaveText(/changed/i, { timeout: 60_000 });
  };

  const { context, page } = await signedInContext(browser, user);
  try {
    // A mistyped confirmation changes nothing.
    await openTab(page, 'Account');
    await page.locator('#pw-current').fill(password);
    await page.locator('#pw-new').fill(next);
    await page.locator('#pw-confirm').fill(`${next}x`);
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page.locator('#account-status')).toHaveText(/match/i);

    await change(page, password, next);
  } finally {
    await context.close();
  }

  const fresh = await browser.newContext();
  try {
    const page = await fresh.newPage();
    await expect(signIn(page, email, password)).rejects.toThrow(/did not leave \/login/);
    await signIn(page, email, next);
    await expect((await openAcctDoc(page, browserName)).locator('#marker')).toHaveText(MARKER);
    await change(page, next, password);
  } finally {
    await fresh.close();
  }
});

test('account: a new recovery code is shown once, and resets a forgotten password with the keys intact', async ({ browser, browserName }) => {
  const s = loadState();
  const user = `acct-${browserName}`;
  const { email, password, config } = s.users[user];
  const { context, page } = await signedInContext(browser, user);
  let code;
  try {
    await openTab(page, 'Account');
    await page.locator('#rc-password').fill(password);
    await page.getByRole('button', { name: 'New recovery code' }).click();
    await expect(page.locator('#rc-new')).not.toHaveText('', { timeout: 60_000 });
    code = (await page.locator('#rc-new').textContent()).trim();
    await page.reload();
    await openTab(page, 'Account');
    await expect(page.locator('#rc-new')).toHaveText('');
    expect(await page.content(), 'page after reload').not.toContain(code);
  } finally {
    await context.close();
  }

  const reset = `${password}-reset`;
  const before = logSize();
  runCli(s.bin, config, ['forgot', '--host', s.appOrigin, '--email', email]);
  const link = await mailedLink(new RegExp(`${s.appOrigin}/reset#token=[A-Za-z0-9_-]+`), before);
  runCli(s.bin, config, ['reset', link, '--recovery-code', code, '--password-stdin'], { input: `${reset}\n` });

  const fresh = await browser.newContext();
  try {
    const p = await fresh.newPage();
    await signIn(p, email, reset);
    // The recovery code brought back the same keys, so the artifact opens.
    await expect((await openAcctDoc(p, browserName)).locator('#marker')).toHaveText(MARKER);
    await openTab(p, 'Account');
    await p.locator('#pw-current').fill(reset);
    await p.locator('#pw-new').fill(password);
    await p.locator('#pw-confirm').fill(password);
    await p.getByRole('button', { name: 'Change password' }).click();
    await expect(p.locator('#account-status')).toHaveText(/changed/i, { timeout: 60_000 });
  } finally {
    await fresh.close();
  }
  runCli(s.bin, config, ['login', '--host', s.appOrigin, '--email', email, '--password-stdin'], { input: `${password}\n` });
});

async function openAcctDoc(page, browserName) {
  const s = loadState();
  await page.goto(`${s.appOrigin}/shared/${s.artifacts[`acct-doc-${browserName}`].id}`);
  return contentFrame(page);
}
