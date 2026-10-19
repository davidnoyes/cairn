// Sharing with a group and with Everyone in a real browser (R3c). The owner
// shares an artifact with a group from the share dialog, which approves its
// member; a later joiner waits until the owner approves them; a member who
// leaves the group loses access at once, shows as left, and the owner's
// Remove starts an epoch that excludes them. Everyone turns on and off.
import path from 'node:path';
import { test, expect } from './test.mjs';
import { MARKER, cli, cliJson, contentFrame, freshUser, loadState, signIn } from './helpers.mjs';

// openDialog opens the share dialog for one of the owner's artifacts.
async function openDialog(page, id) {
  const s = loadState();
  await page.goto(`${s.appOrigin}/app`);
  await page.getByRole('tab', { name: 'Artifacts' }).click();
  await expect(page.locator('#own')).not.toHaveAttribute('aria-busy', 'true', { timeout: 60_000 });
  await page.locator(`#own tr[data-id="${id}"]`).getByRole('button', { name: 'Share' }).click();
  const dialog = page.locator('dialog#share');
  await expect(dialog).toBeVisible();
  return dialog;
}

// reads opens the artifact as a member and expects its content, or not.
async function reads(browser, user, id, yes) {
  const s = loadState();
  const ctx = await browser.newContext();
  try {
    const page = await ctx.newPage();
    await signIn(page, user.email, user.password);
    await page.goto(`${s.appOrigin}/shared/${id}`);
    if (yes) {
      const frame = await contentFrame(page).catch(async (err) => {
        throw new Error(`${err.message}; the page said: ${JSON.stringify(await page.locator('#status').textContent().catch(() => ''))}`);
      });
      await expect(frame.locator('#marker')).toHaveText(MARKER);
    } else {
      await expect(page.locator('#status')).toBeVisible();
      expect(page.frames().filter((f) => f.url().includes('.localhost')), 'artifact frames').toEqual([]);
    }
  } finally {
    await ctx.close();
  }
}

test('group share: approve the members, approve a joiner, remove one who left, and Everyone', async ({ browser, ownerPage, browserName }) => {
  const s = loadState();
  const domain = s.users.owner.email.split('@')[1];
  const stamp = `${browserName}-${Date.now()}`;
  const first = await freshUser(`gs1-${stamp}`, domain);
  const later = await freshUser(`gs2-${stamp}`, domain);
  const group = `Readers ${stamp}`;
  cli('owner', ['group', 'create', group, '--member', first.email]);
  const id = JSON.parse(cli('owner', ['push', path.join(s.fixturesDir, 'marker'), '--artifact', `gs-doc-${stamp}`, '--create', '--json'])).artifact.id;

  // Sharing with the group approves its member at once.
  let dialog = await openDialog(ownerPage, id);
  await dialog.getByLabel('Share with').selectOption('group');
  await dialog.getByLabel('Group', { exact: true }).selectOption({ label: group });
  await dialog.getByLabel('Role', { exact: true }).selectOption('viewer');
  await dialog.getByRole('button', { name: 'Share' }).click();
  await expect(dialog.locator('#share-status')).toContainText(`Shared with the group ${group} as viewer`, { timeout: 60_000 });
  await expect(dialog.locator('#share-status')).toContainText(`Approved 1 person: ${first.email}`);
  await expect(dialog.locator('#members tr[data-group]')).toHaveCount(1);
  await reads(browser, first, id, true);

  // A later joiner waits until the owner approves them.
  cli('owner', ['group', 'add', group, later.email]);
  await reads(browser, later, id, false);
  dialog = await openDialog(ownerPage, id);
  const waiting = dialog.locator(`#waiting tr[data-state="new"][data-email="${later.email}"]`);
  await expect(waiting).toHaveCount(1, { timeout: 30_000 });
  await waiting.getByRole('button', { name: 'Approve' }).click();
  await expect(waiting).toHaveCount(0, { timeout: 60_000 });
  await reads(browser, later, id, true);

  // Someone who leaves the group loses access at once, then is removed.
  const epoch = cliJson('owner', ['members', id]).epoch;
  cli('owner', ['group', 'remove', group, first.email]);
  await reads(browser, first, id, false);
  dialog = await openDialog(ownerPage, id);
  const left = dialog.locator(`#waiting tr[data-state="left"][data-email="${first.email}"]`);
  await expect(left).toHaveCount(1, { timeout: 30_000 });
  await left.getByRole('button', { name: 'Remove' }).click();
  await expect(left).toHaveCount(0, { timeout: 90_000 });
  const m = cliJson('owner', ['members', id]);
  expect(m.epoch).toBeGreaterThan(epoch);
  expect(m.members.map((x) => x.email)).not.toContain(first.email);
  await reads(browser, later, id, true);

  // Everyone turns on, then off.
  await dialog.getByLabel('Share with').selectOption('everyone');
  await dialog.getByLabel('Role', { exact: true }).selectOption('viewer');
  await dialog.getByRole('button', { name: 'Share' }).click();
  const everyone = dialog.locator('#members tr[data-everyone="true"]');
  await expect(everyone).toHaveCount(1, { timeout: 60_000 });
  await everyone.getByRole('button', { name: 'Remove' }).click();
  await expect(everyone).toHaveCount(0, { timeout: 60_000 });
});

test('group share: the owner sees who waits, an editor approves from the approve-only dialog, and a deleted group shows as deleted', async ({ browser, ownerPage, browserName }) => {
  const s = loadState();
  const domain = s.users.owner.email.split('@')[1];
  const stamp = `${browserName}-${Date.now()}`;
  const editor = await freshUser(`gse-${stamp}`, domain);
  const joiner = await freshUser(`gsj-${stamp}`, domain);
  const group = `Joiners ${stamp}`;
  cli('owner', ['group', 'create', group]);
  const id = JSON.parse(cli('owner', ['push', path.join(s.fixturesDir, 'marker'), '--artifact', `gse-doc-${stamp}`, '--create', '--json'])).artifact.id;
  cli('owner', ['share', id, editor.email, '--role', 'editor']);
  cli('owner', ['share', id, group, '--role', 'viewer']);
  cli('owner', ['group', 'add', group, joiner.email]);

  // The owner's row says someone waits; the name cell holds the name alone.
  await ownerPage.goto(`${s.appOrigin}/app`);
  await ownerPage.getByRole('tab', { name: 'Artifacts' }).click();
  const ownerRow = ownerPage.locator(`#own tr[data-id="${id}"]`);
  await expect(ownerRow.locator('span.pill.waiting')).toHaveText('1 waiting for approval', { timeout: 60_000 });
  await expect(ownerRow.locator('td.name')).toHaveText(`gse-doc-${stamp}`);

  // The editor approves from the approve-only dialog, which shows nothing else.
  const ctx = await browser.newContext();
  try {
    const page = await ctx.newPage();
    await signIn(page, editor.email, editor.password);
    await page.getByRole('tab', { name: 'Artifacts' }).click();
    const row = page.locator(`#shared tr[data-id="${id}"]`);
    await expect(row.locator('span.pill.waiting')).toHaveText('1 waiting for approval', { timeout: 60_000 });
    await row.getByRole('button', { name: 'Approve' }).click();
    const dialog = page.locator('dialog#share');
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('#approve-only-note')).toBeVisible();
    await expect(dialog.locator('#share-form')).toBeHidden();
    const waiting = dialog.locator(`#waiting tr[data-state="new"][data-email="${joiner.email}"]`);
    await waiting.getByRole('button', { name: 'Approve' }).click();
    await expect(waiting).toHaveCount(0, { timeout: 60_000 });
  } finally {
    await ctx.close();
  }
  await reads(browser, joiner, id, true);
  await ownerPage.reload();
  await ownerPage.getByRole('tab', { name: 'Artifacts' }).click();
  await expect(ownerPage.locator('#own')).not.toHaveAttribute('aria-busy', 'true', { timeout: 60_000 });
  await expect(ownerRow.locator('span.pill.waiting')).toBeHidden();

  // A deleted group shows as deleted, with nothing to change.
  cli('owner', ['group', 'delete', group]);
  const dialog = await openDialog(ownerPage, id);
  const gone = dialog.locator('#members tr[data-group]');
  await expect(gone).toContainText('(deleted group)', { timeout: 30_000 });
  await expect(gone.locator('select')).toHaveCount(0);
});
