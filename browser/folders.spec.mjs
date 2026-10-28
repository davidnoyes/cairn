// Folders in a real browser (F1). The owner creates a folder and one inside
// it on the Artifacts tab, moves an artifact in with Move to… and out again
// by dragging it onto the breadcrumb, renames the inner folder, and deletes
// the tree. The command-line tool reads the same tree at each step.
import path from 'node:path';
import { test, expect } from './test.mjs';
import { cli, cliJson, loadState, settle, signIn } from './helpers.mjs';

// item finds one of the owner's items by its decrypted name.
function item(name) {
  return cliJson('owner', ['artifact', 'list']).find((a) => a.name === name);
}

// settled waits until no load of the Artifacts lists is queued or running, so
// the rows a test acts on are not about to be replaced.
async function settled(page) {
  await expect(page.locator('#own')).not.toHaveAttribute('aria-busy', 'true', { timeout: 60_000 });
}

// newFolder creates a folder in the one in view and waits for its row.
async function newFolder(page, name) {
  await page.getByLabel('New folder name', { exact: true }).fill(name);
  await page.getByRole('button', { name: 'New folder' }).click();
  await expect(page.locator('#own tr').filter({ hasText: name })).toHaveCount(1, { timeout: 30_000 });
  await settled(page);
}

test('folders: create, nest, move in and out, rename, open, and delete the tree', async ({ ownerPage, browserName }) => {
  const s = loadState();
  const stamp = `${browserName}-${Date.now()}`;
  const outer = `docs-${stamp}`;
  const inner = `inner-${stamp}`;
  const doc = `doc-${stamp}`;
  cli('owner', ['push', path.join(s.fixturesDir, 'marker'), '--artifact', doc, '--create']);

  await ownerPage.goto(`${s.appOrigin}/app`);
  await ownerPage.getByRole('tab', { name: 'Artifacts' }).click();
  await settled(ownerPage);
  const crumbs = ownerPage.locator('#crumbs');

  // New folder waits for a name, and creating one says so beside the form
  // without moving the page.
  const button = ownerPage.getByRole('button', { name: 'New folder', exact: true });
  await expect(button).toBeDisabled();
  await ownerPage.getByLabel('New folder name', { exact: true }).fill('   ');
  await expect(button).toBeDisabled();
  // A window shorter than the page, so a status line at the foot would scroll it.
  await ownerPage.setViewportSize({ width: 1280, height: 320 });
  const scrolled = await ownerPage.evaluate(() => window.scrollY);
  await ownerPage.getByLabel('New folder name', { exact: true }).fill(`scroll-${stamp}`);
  await expect(button).toBeEnabled();
  await button.click();
  await expect(ownerPage.locator('#folder-status')).toHaveText('Folder created.', { timeout: 30_000 });
  await settled(ownerPage);
  await expect(button).toBeDisabled();
  expect(await ownerPage.evaluate(() => window.scrollY), 'the page did not scroll').toBe(scrolled);
  await ownerPage.setViewportSize({ width: 1280, height: 720 });
  // Typing clears what the last attempt said.
  await ownerPage.getByLabel('New folder name', { exact: true }).fill('x');
  await expect(ownerPage.locator('#folder-status')).toHaveText('');
  await ownerPage.getByLabel('New folder name', { exact: true }).fill('');

  // A folder at the top level, then one inside it.
  await newFolder(ownerPage, outer);
  const outerID = item(outer).id;
  expect(item(outer)).toMatchObject({ kind: 'folder' });
  await ownerPage.locator(`#own tr[data-id="${outerID}"]`).getByRole('button', { name: outer }).click();
  await expect(crumbs).toContainText(outer);
  await expect(ownerPage.locator('#own')).toContainText('This folder is empty.');
  await newFolder(ownerPage, inner);
  const innerID = item(inner).id;
  expect(item(inner).parent).toBe(outerID);

  // Move to… puts the artifact in the outer folder.
  await crumbs.getByRole('button', { name: 'Top' }).click();
  const docRow = ownerPage.locator(`#own tr[data-id="${item(doc).id}"]`);
  await docRow.getByRole('button', { name: 'Move to…' }).click();
  await docRow.getByLabel(`Move ${doc} to`).selectOption({ label: outer });
  await expect(ownerPage.locator('#artifacts-status')).toHaveText('Moved. 1 of 1 items up to date.', { timeout: 30_000 });
  await expect.poll(() => item(doc).parent).toBe(outerID);
  await expect(docRow).toHaveCount(0);
  await settled(ownerPage);

  // Dragging it onto Top in the breadcrumb moves it back out.
  await ownerPage.locator(`#own tr[data-id="${outerID}"]`).getByRole('button', { name: outer }).click();
  await expect(ownerPage.locator('#own')).toContainText(doc);
  await docRow.dragTo(crumbs.getByRole('button', { name: 'Top' }));
  await expect(ownerPage.locator('#artifacts-status')).toHaveText('Moved. 1 of 1 items up to date.', { timeout: 30_000 });
  await expect(docRow).toHaveCount(0);
  await expect.poll(() => item(doc).parent ?? null, { timeout: 30_000 }).toBeNull();
  await settled(ownerPage);

  // Rename the inner folder; the name is sealed, and every client reads it.
  const renamed = `${inner}-renamed`;
  const innerRow = ownerPage.locator(`#own tr[data-id="${innerID}"]`);
  await innerRow.getByRole('button', { name: 'Rename' }).click();
  await innerRow.getByLabel(`New name of ${inner}`).fill(renamed);
  await innerRow.getByRole('button', { name: 'Save' }).click();
  await expect(ownerPage.locator('#artifacts-status')).toHaveText('Folder renamed.', { timeout: 30_000 });
  await expect.poll(() => item(renamed)?.id).toBe(innerID);
  await settled(ownerPage);

  // A folder's own address says it is a folder, rather than failing.
  await ownerPage.goto(`${s.appOrigin}/shared/${outerID}`);
  await expect(ownerPage.locator('#status')).toContainText('This is a folder');

  // Deleting the outer folder states what goes, then removes both folders.
  await ownerPage.goto(`${s.appOrigin}/app`);
  await ownerPage.getByRole('tab', { name: 'Artifacts' }).click();
  await settled(ownerPage);
  const del = ownerPage.locator(`#own tr[data-id="${outerID}"]`).getByRole('button', { name: /^Delete/ });
  await del.click();
  await expect(del).toHaveText('Delete 2 folders and 0 artifacts?');
  await del.click();
  await expect(ownerPage.locator(`#own tr[data-id="${outerID}"]`)).toHaveCount(0, { timeout: 30_000 });
  expect(item(outer)).toBeUndefined();
  expect(item(renamed)).toBeUndefined();
  expect(item(doc)).toBeDefined();
});

test('folders: drag onto a folder row, move a folder, and delete a folder that holds an artifact', async ({ ownerPage, browserName }) => {
  const s = loadState();
  const stamp = `${browserName}-${Date.now()}`;
  const box = `box-${stamp}`;
  const sub = `sub-${stamp}`;
  const doc = `boxed-${stamp}`;
  cli('owner', ['push', path.join(s.fixturesDir, 'marker'), '--artifact', doc, '--create']);

  await ownerPage.goto(`${s.appOrigin}/app`);
  await ownerPage.getByRole('tab', { name: 'Artifacts' }).click();
  await settled(ownerPage);
  // Work inside a fresh folder, so the rows sit together on screen whatever
  // earlier tests left at the top level.
  const work = `work-${stamp}`;
  await newFolder(ownerPage, work);
  const workID = item(work).id;
  cli('owner', ['move', doc, '--to', work]);
  await ownerPage.locator(`#own tr[data-id="${workID}"]`).getByRole('button', { name: work }).click();
  await newFolder(ownerPage, box);
  await newFolder(ownerPage, sub);
  const boxID = item(box).id;
  const subID = item(sub).id;

  // Dragging the artifact onto a folder row files it there.
  const docRow = ownerPage.locator(`#own tr[data-id="${item(doc).id}"]`);
  const boxRow = ownerPage.locator(`#own tr[data-id="${boxID}"]`);
  await expect(docRow).toContainText(doc);
  await docRow.dragTo(boxRow);
  await expect(docRow).toHaveCount(0, { timeout: 30_000 });
  await expect.poll(() => item(doc).parent).toBe(boxID);
  await settled(ownerPage);

  // Move to… on a folder offers the other folder, and moves it whole.
  const subRow = ownerPage.locator(`#own tr[data-id="${subID}"]`);
  await subRow.getByRole('button', { name: 'Move to…' }).click();
  await subRow.getByLabel(`Move ${sub} to`).selectOption({ label: `${work} / ${box}` });
  await expect(subRow).toHaveCount(0, { timeout: 30_000 });
  await expect.poll(() => item(sub).parent).toBe(boxID);
  await settled(ownerPage);

  // Deleting the box names both folders and the artifact, then removes them.
  const del = boxRow.getByRole('button', { name: /^Delete/ });
  await del.click();
  await expect(del).toHaveText('Delete 2 folders and 1 artifact?');
  await del.click();
  await expect(boxRow).toHaveCount(0, { timeout: 30_000 });
  for (const name of [box, sub, doc]) expect(item(name)).toBeUndefined();
});

test('folders: Back and Forward step through folders, and an artifact opened in one comes back to it', async ({ ownerPage, browserName }) => {
  const s = loadState();
  const stamp = `${browserName}-${Date.now()}`;
  const outer = `back-outer-${stamp}`;
  const inner = `back-inner-${stamp}`;
  const doc = `back-doc-${stamp}`;
  cli('owner', ['folder', 'create', outer]);
  cli('owner', ['folder', 'create', inner, '--in', outer]);
  cli('owner', ['push', path.join(s.fixturesDir, 'marker'), '--artifact', doc, '--create', '--in', inner]);

  await ownerPage.goto(`${s.appOrigin}/app`);
  await ownerPage.getByRole('tab', { name: 'Artifacts' }).click();
  await settled(ownerPage);
  const here = ownerPage.locator('#crumbs [aria-current=page]');
  const row = (name) => ownerPage.locator('#own tr').filter({ hasText: name });
  await row(outer).getByRole('button', { name: outer }).click();
  await row(inner).getByRole('button', { name: inner }).click();
  await expect(here).toHaveText(inner);

  // Back from an artifact comes back to the folder it was opened from.
  await row(doc).getByRole('link', { name: doc }).click();
  await ownerPage.waitForURL(/\/shared\//);
  await ownerPage.goBack();
  await expect(here).toHaveText(inner, { timeout: 60_000 });
  await expect(row(doc)).toHaveCount(1);

  // Then out through each folder to the top level, and Forward goes in again.
  await ownerPage.goBack();
  await expect(here).toHaveText(outer);
  await ownerPage.goBack();
  await expect(here).toHaveText('Top');
  await ownerPage.goForward();
  await expect(here).toHaveText(outer);

  // Back from another tab shows the Artifacts tab, where the folder changed.
  await ownerPage.getByRole('tab', { name: 'Account' }).click();
  await ownerPage.goBack();
  await expect(ownerPage.getByRole('tab', { name: 'Artifacts' })).toHaveAttribute('aria-selected', 'true');
  await expect(here).toHaveText('Top');
  await ownerPage.goForward();
  await expect(here).toHaveText(outer);

  // A reload keeps the folder in view, and the breadcrumb is a step Back undoes.
  await ownerPage.reload();
  await expect(here).toHaveText(outer, { timeout: 60_000 });
  await settled(ownerPage);
  await ownerPage.locator('#crumbs').getByRole('button', { name: 'Top' }).click();
  await expect(here).toHaveText('Top');
  await ownerPage.goBack();
  await expect(here).toHaveText(outer);

  // A folder the address names that is not there shows the top level, and
  // the address stops naming it.
  await ownerPage.goto(`${s.appOrigin}/app?folder=00000000-0000-4000-8000-000000000000`);
  await settled(ownerPage);
  await expect(here).toHaveText('Top');
  expect(new URL(ownerPage.url()).search).toBe('');
});

test("folders: a folder's own page, and signing in again, both open the folder", async ({ browser, browserName }) => {
  const s = loadState();
  const owner = s.users.owner;
  const folder = `link-${browserName}-${Date.now()}`;
  cli('owner', ['folder', 'create', folder]);
  const id = item(folder).id;
  // A context of its own: the test ends its session, which the shared owner
  // context must keep.
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  try {
    await signIn(page, owner.email, owner.password);
    const here = page.locator('#crumbs [aria-current=page]');
    const next = () => new URL(page.url()).searchParams.get('next');

    // The folder's own address links to it on the Artifacts tab.
    await page.goto(`${s.appOrigin}/shared/${id}`);
    await page.getByRole('link', { name: 'Open it on the Artifacts tab' }).click();
    await expect(here).toHaveText(folder, { timeout: 60_000 });
    await settle(page);

    // A session that ends with the folder open goes to sign in and back to
    // the folder: from the page, when it next asks the server...
    await ctx.clearCookies();
    await page.getByRole('tab', { name: 'Groups' }).click();
    await page.waitForURL(/\/login\?/);
    expect(next()).toBe(`/app?folder=${id}`);
    // ...and from the server, when the page loads.
    await page.goto(`${s.appOrigin}/app?folder=${id}`);
    await page.waitForURL(/\/login\?/);
    expect(next()).toBe(`/app?folder=${id}`);

    await page.locator('#email').fill(owner.email);
    await page.locator('#password').fill(owner.password);
    await page.locator('#submit').click();
    await expect(here).toHaveText(folder, { timeout: 60_000 });
    await settle(page);
  } finally {
    await ctx.close();
  }
});
