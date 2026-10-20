// Folders in a real browser (F1). The owner creates a folder and one inside
// it on the Artifacts tab, moves an artifact in with Move to… and out again
// by dragging it onto the breadcrumb, renames the inner folder, and deletes
// the tree. The command-line tool reads the same tree at each step.
import path from 'node:path';
import { test, expect } from './test.mjs';
import { cli, cliJson, loadState } from './helpers.mjs';

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
  await page.getByLabel('New folder name').fill(name);
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
