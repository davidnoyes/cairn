// Milestone 6 browser tests, written before the feature: the owner's share
// dialog. See design/e2e-api.md "The app page".
//
// The dialog's contract with these tests:
// - dialog#share opens from an owner row's Share button; #share-title holds
//   the artifact's name, and a Close button closes it.
// - #members lists tr[data-email] rows with td.name, td.email, td.role, td.fp
//   and td.pin. A member's row has select.role, and Remove, Verify, and
//   "Accept new key" buttons where they apply. "Accept new key" shows
//   #accept-warning with an Accept button before it changes anything.
// - #share-email, #share-role and a Share button add a member.
// - #public and #public-writes are checkboxes; #public-note says the link
//   carries the key; "Copy link" writes it to the clipboard and nowhere else.
// - #share-status reports each change, and what a new epoch left alone.
import { expect, test } from './test.mjs';
import { MARKER, cli, cliJson, contentFrame, loadState, logSize, mailedLink, runCli, signedInContext } from './helpers.mjs';

function members(id) {
  return Object.fromEntries(cliJson('owner', ['members', id]).members.map((m) => [m.email, m]));
}

async function openShare(page, id) {
  const s = loadState();
  await page.goto(`${s.appOrigin}/app`);
  await page.getByRole('tab', { name: 'Artifacts' }).click();
  await page.locator(`#own tr[data-id="${id}"]`).getByRole('button', { name: 'Share' }).click();
  const dialog = page.locator('dialog#share');
  await expect(dialog).toBeVisible();
  return dialog;
}

// pushDoc pushes a fresh marker artifact as the owner, one per engine.
function pushDoc(name) {
  const s = loadState();
  const out = JSON.parse(cli('owner', ['push', `${s.fixturesDir}/marker`, '--artifact', name, '--create', '--json']));
  return { id: out.artifact.id, version: out.version.id };
}

test('share: the owner shares, changes a role, verifies and removes a member, and the CLI agrees', async ({ ownerPage, browser, browserName }) => {
  const s = loadState();
  const name = `share-${browserName}`;
  const { id } = pushDoc(name);
  const peer = `peer-${browserName}`;
  const viewer = s.users[peer];
  const dialog = await openShare(ownerPage, id);
  await expect(dialog.locator('#share-title')).toHaveText(name);
  await expect(dialog.locator(`tr[data-email="${s.users.owner.email}"] td.role`)).toHaveText('owner');

  await dialog.locator('#share-email').fill(viewer.email);
  await dialog.locator('#share-role').selectOption('viewer');
  await dialog.getByRole('button', { name: 'Share', exact: true }).click();
  const row = dialog.locator(`tr[data-email="${viewer.email}"]`);
  await expect(row.locator('td.role')).toHaveText('viewer');
  let m = members(id)[viewer.email];
  expect(m.role).toBe('viewer');
  await expect(row.locator('td.fp')).toHaveText(m.fp);
  await expect(row.locator('td.pin')).toHaveText(m.state);

  const { context, page } = await signedInContext(browser, peer);
  try {
    await page.goto(`${s.appOrigin}/shared/${id}`);
    await expect((await contentFrame(page)).locator('#marker')).toHaveText(MARKER);

    await row.locator('select.role').selectOption('editor');
    await expect(row.locator('td.role')).toHaveText('editor');
    expect(members(id)[viewer.email].role).toBe('editor');

    await row.getByRole('button', { name: 'Verify' }).click();
    await expect(row.locator('td.pin')).toHaveText('verified');
    expect(members(id)[viewer.email].state).toBe('verified');

    const epoch = cliJson('owner', ['members', id]).epoch;
    await row.getByRole('button', { name: 'Remove' }).click();
    await expect(row).toHaveCount(0);
    await expect(dialog.locator('#share-status')).toHaveText(/removed/i, { timeout: 60_000 });
    m = cliJson('owner', ['members', id]);
    expect(m.members.map((x) => x.email)).not.toContain(viewer.email);
    expect(m.epoch).toBeGreaterThan(epoch);

    // The browser re-sealed the latest version and the name under the new
    // epoch, so the owner still reads both, and the CLI agrees.
    const got = cliJson('owner', ['artifact', 'show', id]);
    expect(got.artifact.name).toBe(name);
    expect(got.versions[0].epoch).toBe(m.epoch);
    await dialog.getByRole('button', { name: 'Close' }).click();
    await expect(ownerPage.locator(`#own tr[data-id="${id}"] td.name`)).toHaveText(name);
    await ownerPage.goto(`${s.appOrigin}/shared/${id}`);
    await expect((await contentFrame(ownerPage)).locator('#marker')).toHaveText(MARKER);

    // The removed member no longer opens it.
    await page.goto(`${s.appOrigin}/shared/${id}`);
    await expect(page.locator('#status')).toBeVisible();
    expect(page.frames().filter((f) => f.url().includes('.localhost')), 'artifact frames').toEqual([]);
  } finally {
    await context.close();
  }
});

test('share: the public link carries the key, is copied only on request, and stops when public is off', async ({ ownerPage, browser, browserName }) => {
  const s = loadState();
  const { id } = pushDoc(`public-${browserName}`);
  const dialog = await openShare(ownerPage, id);
  await ownerPage.evaluate(() => {
    window.copied = [];
    navigator.clipboard.writeText = async (t) => { window.copied.push(t); };
  });

  await dialog.locator('#public').check();
  await expect(dialog.locator('#share-status')).toHaveText(/anyone with the link can read it/, { timeout: 60_000 });
  await expect(dialog.locator('#public-note')).toHaveText(/key/i);
  expect(await ownerPage.content(), 'page before copying').not.toMatch(/#[^"'<\s]*k=/);
  await dialog.getByRole('button', { name: 'Copy link' }).click();
  const copied = await ownerPage.evaluate(() => window.copied);
  expect(copied).toHaveLength(1);
  const link = copied[0];
  expect(link).toMatch(new RegExp(`^${s.appOrigin}/.+#.*k=`));
  expect(await ownerPage.content(), 'page after copying').not.toContain(new URL(link).hash);
  expect(cliJson('owner', ['artifact', 'show', id]).artifact.public).toBe(true);

  await dialog.locator('#public-writes').check();
  await expect.poll(() => cliJson('owner', ['artifact', 'show', id]).artifact.publicWrites).toBe(true);
  await dialog.locator('#public-writes').uncheck();
  await expect.poll(() => cliJson('owner', ['artifact', 'show', id]).artifact.publicWrites).toBe(false);

  const anon = await browser.newContext();
  try {
    const page = await anon.newPage();
    await page.goto(link);
    await expect((await contentFrame(page)).locator('#marker')).toHaveText(MARKER);

    await dialog.locator('#public').uncheck();
    await expect(dialog.locator('#share-status')).toHaveText(/the old link no longer opens it/, { timeout: 60_000 });
    expect(cliJson('owner', ['artifact', 'show', id]).artifact.public).toBe(false);
    const again = await anon.newPage();
    await again.goto(link);
    await expect(again.locator('#status')).toBeVisible();
    expect(again.frames().filter((f) => f.url().includes('.localhost')), 'artifact frames').toEqual([]);
  } finally {
    await anon.close();
  }
  // The owner still reads the name and the content under the new epoch.
  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(ownerPage.locator(`#own tr[data-id="${id}"] td.name`)).toHaveText(`public-${browserName}`);
  await ownerPage.goto(`${s.appOrigin}/shared/${id}`);
  await expect((await contentFrame(ownerPage)).locator('#marker')).toHaveText(MARKER);
});

test('share: a member whose keys changed is flagged, and the owner accepts the new key only after a warning', async ({ ownerPage, browserName }) => {
  const s = loadState();
  const user = `drift-${browserName}`;
  const { email, password, config } = s.users[user];
  const { id } = pushDoc(`drift-${browserName}`);
  cli('owner', ['share', id, email]);
  const fp = members(id)[email].fp;

  // A reset without the recovery code makes new keys that nothing links to
  // the old ones.
  const before = logSize();
  runCli(s.bin, config, ['forgot', '--host', s.appOrigin, '--email', email]);
  const link = await mailedLink(new RegExp(`${s.appOrigin}/reset#token=[A-Za-z0-9_-]+`), before);
  runCli(s.bin, config, ['reset', link, '--no-recovery-code', '--yes', '--password-stdin'], { input: `${password}\n` });

  const dialog = await openShare(ownerPage, id);
  const row = dialog.locator(`tr[data-email="${email}"]`);
  await expect(row.locator('td.pin')).toHaveText('changed');
  await expect(row.locator('td.fp')).not.toHaveText(fp);
  await row.getByRole('button', { name: 'Accept new key' }).click();
  const warning = dialog.locator('#accept-warning');
  await expect(warning).toBeVisible();
  await expect(warning).toContainText(email);
  // Nothing has changed yet.
  expect(members(id)[email].state).toBe('changed');
  await warning.getByRole('button', { name: 'Accept' }).click();
  await expect(row.locator('td.pin')).not.toHaveText('changed');
  expect(members(id)[email].state).not.toBe('changed');
});

test('share: a change still running when the dialog closes stays with its own artifact', async ({ ownerPage, browserName }) => {
  const s = loadState();
  const first = pushDoc(`race-a-${browserName}`);
  const second = pushDoc(`race-b-${browserName}`);
  const viewer = s.users[`peer-${browserName}`];
  const dialog = await openShare(ownerPage, first.id);

  // Hold the first artifact's membership write until the dialog shows the
  // second one.
  const membership = `**/api/artifacts/${first.id}/membership`;
  let release, reached;
  const held = new Promise((resolve) => { release = resolve; });
  const arrived = new Promise((resolve) => { reached = resolve; });
  await ownerPage.route(membership, async (route) => {
    if (route.request().method() !== 'PUT') return route.fallback();
    reached();
    await held;
    return route.continue();
  });
  try {
    await dialog.locator('#share-email').fill(viewer.email);
    await dialog.locator('#share-role').selectOption('viewer');
    await dialog.getByRole('button', { name: 'Share', exact: true }).click();
    await arrived;
    await dialog.getByRole('button', { name: 'Close' }).click();
    await ownerPage.locator(`#own tr[data-id="${second.id}"]`).getByRole('button', { name: 'Share' }).click();
    await expect(dialog.locator('#share-title')).toHaveText(`race-b-${browserName}`);
    await expect(dialog.locator('#share-email')).toBeEnabled();
    await dialog.locator('#share-email').fill('typed@example.com');

    // The finished change reloads the list, because the dialog it came from
    // is gone, and leaves the second dialog as it is.
    const row = `#own tr[data-id="${first.id}"]`;
    await ownerPage.locator(row).evaluate((tr) => { tr.dataset.stale = '1'; });
    const reloaded = ownerPage.waitForResponse((r) => new URL(r.url()).pathname === '/api/artifacts' && r.request().method() === 'GET');
    release();
    await reloaded;
    expect(Object.keys(members(first.id))).toContain(viewer.email);
    expect(Object.keys(members(second.id))).not.toContain(viewer.email);
    await expect(dialog.locator('#share-email')).toHaveValue('typed@example.com');
    // A stale write would land within the same chain as the reload, so wait
    // for the rebuilt row to be named before looking.
    await expect(ownerPage.locator(`${row}:not([data-stale]) td.name`)).toContainText(`race-a-${browserName}`);
    await expect(dialog.locator('#share-status')).not.toContainText('Shared with');
    await expect(dialog.locator('#share-email')).toBeEnabled();
    await expect(dialog.locator(`tr[data-email="${viewer.email}"]`)).toHaveCount(0);
  } finally {
    release();
    await ownerPage.unroute(membership);
  }
});
