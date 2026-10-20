// Shared folders in a real browser (F2). The owner shares a folder tree from
// the share dialog; the reader browses it under Shared with you and reads a
// nested item; the owner sees the inherited entry on an item, moves another
// artifact into the folder from the page, and then unshares the folder, which
// ends the reader's access to everything inside.
import path from 'node:path';
import { test, expect } from './test.mjs';
import { MARKER, cli, cliJson, contentFrame, freshUser, loadState, signIn } from './helpers.mjs';

// settled waits until the Artifacts lists are not being loaded.
async function settled(page) {
  await expect(page.locator('#own')).not.toHaveAttribute('aria-busy', 'true', { timeout: 60_000 });
}

// item finds one of the owner's items by its decrypted name.
const item = (name) => cliJson('owner', ['artifact', 'list']).find((a) => a.name === name);

// openDialog opens the share dialog for one of the owner's items, opening
// the folder it sits in first when there is one: [id, name] of that folder.
async function openDialog(page, id, folder = null) {
  const s = loadState();
  await page.goto(`${s.appOrigin}/app`);
  await page.getByRole('tab', { name: 'Artifacts' }).click();
  await settled(page);
  if (folder) await page.locator(`#own tr[data-id="${folder[0]}"]`).getByRole('button', { name: folder[1] }).click();
  await page.locator(`#own tr[data-id="${id}"]`).getByRole('button', { name: 'Share' }).click();
  const dialog = page.locator('dialog#share');
  await expect(dialog).toBeVisible();
  return dialog;
}

// reads opens the artifact as the reader and expects its content, or not.
async function reads(page, id, yes) {
  const s = loadState();
  await page.goto(`${s.appOrigin}/shared/${id}`);
  if (yes) {
    await expect((await contentFrame(page)).locator('#marker')).toHaveText(MARKER);
  } else {
    await expect(page.locator('#status')).toBeVisible();
    expect(page.frames().filter((f) => f.url().includes('.localhost')), 'artifact frames').toEqual([]);
  }
}

test('shared folder: share a tree, browse it as the reader, move an artifact in, and unshare', async ({ browser, ownerPage, browserName }) => {
  const s = loadState();
  const domain = s.users.owner.email.split('@')[1];
  const stamp = `${browserName}-${Date.now()}`;
  const reader = await freshUser(`fs-${stamp}`, domain);
  const top = `team-${stamp}`;
  const inner = `inner-${stamp}`;
  const doc = `fs-doc-${stamp}`;
  const deep = `fs-deep-${stamp}`;
  const later = `fs-later-${stamp}`;
  const marker = path.join(s.fixturesDir, 'marker');
  cli('owner', ['folder', 'create', top]);
  cli('owner', ['folder', 'create', inner, '--in', top]);
  cli('owner', ['push', marker, '--artifact', doc, '--create', '--in', top]);
  cli('owner', ['push', marker, '--artifact', deep, '--create', '--in', inner]);
  cli('owner', ['push', marker, '--artifact', later, '--create']);
  const ids = Object.fromEntries([top, inner, doc, deep, later].map((n) => [n, item(n).id]));

  // Sharing the folder brings every item inside it up to date.
  let dialog = await openDialog(ownerPage, ids[top]);
  await expect(dialog.locator('#folder-note')).toBeVisible();
  await dialog.locator('#share-email').fill(reader.email);
  await dialog.getByLabel('Role', { exact: true }).selectOption('viewer');
  await dialog.getByRole('button', { name: 'Share' }).click();
  await expect(dialog.locator('#share-status')).toContainText('3 of 3 items up to date.', { timeout: 90_000 });

  // The reader browses the tree under Shared with you and reads the deep item.
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  try {
    await signIn(page, reader.email, reader.password);
    await page.getByRole('tab', { name: 'Artifacts' }).click();
    await settled(page);
    const sharedRow = (id) => page.locator(`#shared tr[data-id="${id}"]`);
    await sharedRow(ids[top]).getByRole('button', { name: top }).click();
    await expect(page.locator('#shared-crumbs')).toContainText(top);
    await expect(sharedRow(ids[doc])).toHaveCount(1);
    await sharedRow(ids[inner]).getByRole('button', { name: inner }).click();
    await expect(page.locator('#shared-crumbs')).toContainText(inner);
    await expect(sharedRow(ids[deep])).toHaveCount(1);
    await reads(page, ids[deep], true);

    // The owner sees the reader on an item inside, inherited from the folder.
    dialog = await openDialog(ownerPage, ids[doc], [ids[top], top]);
    const inherited = dialog.locator(`#members tr.inherited[data-via="${ids[top]}"]`).filter({ hasText: reader.email });
    await expect(inherited).toContainText(`from ${top}`, { timeout: 30_000 });
    await expect(inherited.locator('select')).toHaveCount(0);
    await expect(inherited.getByRole('button', { name: 'Remove' })).toHaveCount(0);
    await expect(dialog.locator('#share-close')).toBeEnabled({ timeout: 30_000 });
    await dialog.locator('#share-close').click();
    await expect(dialog).toBeHidden();

    // Moving an artifact into the folder from the page shares it too.
    await reads(page, ids[later], false);
    await ownerPage.locator('#crumbs').getByRole('button', { name: 'Top' }).click();
    const laterRow = ownerPage.locator(`#own tr[data-id="${ids[later]}"]`);
    await laterRow.getByRole('button', { name: 'Move to…' }).click();
    await laterRow.getByLabel(`Move ${later} to`).selectOption({ label: top });
    await expect(ownerPage.locator('#artifacts-status')).toContainText('items up to date', { timeout: 60_000 });
    await reads(page, ids[later], true);

    // A move nobody placed (as one made by another client) leaves the item
    // pending, and the reader loses it at once. Moving it there again from
    // the page places it, and the pending mark goes.
    await ownerPage.evaluate(async (id) => {
      const r = await fetch(`/api/artifacts/${id}/parent`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ parent: null }) });
      if (!r.ok) throw new Error(`move: ${r.status}`);
    }, ids[later]);
    await ownerPage.reload();
    await ownerPage.getByRole('tab', { name: 'Artifacts' }).click();
    await settled(ownerPage);
    const pendingRow = ownerPage.locator(`#own tr[data-id="${ids[later]}"]`);
    await expect(pendingRow.locator('span.pill.pending')).toBeVisible();
    await reads(page, ids[later], false);
    await pendingRow.getByRole('button', { name: 'Move to…' }).click();
    await pendingRow.getByLabel(`Move ${later} to`).selectOption({ label: 'Top level' });
    await expect(ownerPage.locator('#artifacts-status')).toContainText('items up to date', { timeout: 60_000 });
    await settled(ownerPage);
    await expect(pendingRow.locator('span.pill.pending')).toBeHidden();

    // Unsharing the folder ends the reader's access to everything inside.
    dialog = await openDialog(ownerPage, ids[top]);
    await dialog.locator('#members tr').filter({ hasText: reader.email }).getByRole('button', { name: 'Remove' }).click();
    await expect(dialog.locator('#share-status')).toContainText('items up to date', { timeout: 120_000 });
    for (const n of [deep, doc, later]) await reads(page, ids[n], false);
  } finally {
    await ctx.close();
  }
});
