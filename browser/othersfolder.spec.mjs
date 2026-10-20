// Folders holding other people's items, in a real browser (F3). An editor of
// the owner's folder puts their own artifact in it, and the folder's owner,
// who manages everything under it, reads it. Sharing the folder with a reader
// signs the editor's item at once. Adding a manager changes the item's
// managers, which only its owner signs: the new manager sees a stub until the
// editor's page applies it by itself. Deleting the folder moves the editor's
// item to the editor's top level and ends the reader's access to it.
import path from 'node:path';
import { test, expect } from './test.mjs';
import { MARKER, cli, cliJson, contentFrame, freshUser, loadState, runCli, signIn } from './helpers.mjs';

// settled waits until the Artifacts lists are not being loaded.
async function settled(page) {
  await expect(page.locator('#own')).not.toHaveAttribute('aria-busy', 'true', { timeout: 60_000 });
  await expect(page.locator('#shared')).not.toHaveAttribute('aria-busy', 'true', { timeout: 60_000 });
}

// artifacts opens the Artifacts tab and waits for both lists.
async function artifacts(page) {
  await page.goto(`${loadState().appOrigin}/app`);
  await page.getByRole('tab', { name: 'Artifacts' }).click();
  await settled(page);
}

// reads opens the artifact and expects its content, or not.
async function reads(page, id, yes) {
  await page.goto(`${loadState().appOrigin}/shared/${id}`);
  if (yes) {
    await expect((await contentFrame(page)).locator('#marker')).toHaveText(MARKER);
  } else {
    await expect(page.locator('#status')).toBeVisible();
    expect(page.frames().filter((f) => f.url().includes('.localhost')), 'artifact frames').toEqual([]);
  }
}

// signedIn opens a new context signed in as user.
async function signedIn(browser, user) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await signIn(page, user.email, user.password);
  return { context, page };
}

test("others' items: place in someone's folder, share it, a stub until applied, and delete the folder", async ({ browser, ownerPage, browserName }) => {
  const s = loadState();
  const domain = s.users.owner.email.split('@')[1];
  const stamp = `${browserName}-${Date.now()}`;
  const editor = await freshUser(`of-ed-${stamp}`, domain);
  const reader = await freshUser(`of-rd-${stamp}`, domain);
  const manager = await freshUser(`of-mg-${stamp}`, domain);
  const asEditor = (args) => runCli(s.bin, editor.config, args);
  const top = `others-${stamp}`;
  const doc = `of-doc-${stamp}`;
  const marker = path.join(s.fixturesDir, 'marker');

  // The owner makes the folder and shares it with the editor, who puts their
  // own artifact in it.
  cli('owner', ['folder', 'create', top]);
  const topId = cliJson('owner', ['artifact', 'list']).find((a) => a.name === top).id;
  cli('owner', ['share', topId, editor.email, '--role', 'editor']);
  asEditor(['push', marker, '--artifact', doc, '--create', '--in', topId]);
  const docId = JSON.parse(asEditor(['artifact', 'list', '--json'])).find((a) => a.name === doc).id;

  // The folder's owner sees the editor's item in the folder, and reads it.
  await artifacts(ownerPage);
  await ownerPage.locator(`#own tr[data-id="${topId}"]`).getByRole('button', { name: top }).click();
  await expect(ownerPage.locator(`#own tr[data-id="${docId}"]`)).toHaveCount(1);
  await reads(ownerPage, docId, true);

  // The folder's owner manages the editor's item, so sharing the folder with
  // the reader signs it too, and nothing waits.
  const out = cli('owner', ['share', topId, reader.email, '--role', 'viewer']);
  expect(out).not.toContain('waits on');

  const ed = await signedIn(browser, editor);
  const rd = await signedIn(browser, reader);
  const mg = await signedIn(browser, manager);
  try {
    await reads(rd.page, docId, true);

    // Adding a manager changes the item's managers, which only the editor
    // signs: the item waits on them.
    const out2 = cli('owner', ['share', topId, manager.email, '--role', 'manager']);
    expect(out2).toContain(`${docId}: waits on ${editor.email}`);

    // The new manager sees the item as a stub naming its owner, and cannot
    // read it.
    await artifacts(mg.page);
    await mg.page.locator(`#shared tr[data-id="${topId}"]`).getByRole('button', { name: top }).click();
    const stub = mg.page.locator(`#shared tr[data-id="${docId}"]`);
    await expect(stub).toHaveAttribute('data-stub', 'true');
    await expect(stub.locator('.stub-note')).toHaveText(`not shared with you yet, owned by ${editor.email}`);
    await expect(stub.getByRole('link')).toHaveCount(0);
    await reads(mg.page, docId, false);

    // The editor opens the Artifacts tab, and the item comes up to date with
    // no click, which the status says; the new manager can then read it.
    await artifacts(ed.page);
    await expect(ed.page.locator('#artifacts-status')).toHaveText('1 of 1 items up to date.');
    await reads(mg.page, docId, true);

    // Deleting the folder says the editor's item moves to its owner, then
    // moves it there, and the reader loses it.
    await artifacts(ownerPage);
    const row = ownerPage.locator(`#own tr[data-id="${topId}"]`);
    await row.getByRole('button', { name: 'Delete' }).click();
    await expect(row.getByRole('button', { name: /Delete/ })).toHaveText(
      `Delete 1 folder and 0 artifacts of yours, and move 1 item other people own (${editor.email}) to their owners' top level?`);
    await row.getByRole('button', { name: /Delete/ }).click();
    await expect(row).toHaveCount(0, { timeout: 60_000 });
    const moved = JSON.parse(asEditor(['artifact', 'list', '--json'])).find((a) => a.id === docId);
    expect(moved.parent ?? null).toBeNull();
    await reads(ed.page, docId, true);
    await reads(rd.page, docId, false);
    await reads(mg.page, docId, false);
  } finally {
    await ed.context.close();
    await rd.context.close();
    await mg.context.close();
  }
});

test("others' items: an editor makes a folder inside someone's folder, and takes the owner's item out", async ({ browser, browserName }) => {
  const s = loadState();
  const domain = s.users.owner.email.split('@')[1];
  const stamp = `${browserName}-${Date.now()}`;
  const editor = await freshUser(`of-ed2-${stamp}`, domain);
  const top = `others2-${stamp}`;
  const sub = `of-sub-${stamp}`;
  const doc = `of-own-${stamp}`;
  cli('owner', ['folder', 'create', top]);
  cli('owner', ['push', path.join(s.fixturesDir, 'marker'), '--artifact', doc, '--create', '--in', top]);
  const listed = () => cliJson('owner', ['artifact', 'list']);
  const topId = listed().find((a) => a.name === top).id;
  const docId = listed().find((a) => a.name === doc).id;
  cli('owner', ['share', topId, editor.email, '--role', 'editor']);

  const ed = await signedIn(browser, editor);
  try {
    await artifacts(ed.page);
    await ed.page.locator(`#shared tr[data-id="${topId}"]`).getByRole('button', { name: top }).click();
    await expect(ed.page.locator('#shared-crumbs')).toContainText(top);

    // The editor's new folder is theirs, inside the owner's folder, and the
    // owner reads it as the folder's owner.
    await ed.page.getByLabel('New folder name in the shared folder').fill(sub);
    await ed.page.getByRole('button', { name: 'New folder here' }).click();
    await expect(ed.page.locator('#artifacts-status')).toHaveText('Folder created.', { timeout: 60_000 });
    await settled(ed.page);
    await expect(ed.page.locator('#shared tr').filter({ hasText: sub })).toHaveCount(1);
    const made = listed().find((a) => a.name === sub);
    expect(made, 'the owner reads the editor\'s folder').toBeTruthy();
    expect(made.parent).toBe(topId);
    expect(made.owner).not.toBe(listed().find((a) => a.id === topId).owner);

    // The editor takes the owner's item out of the folder: it goes to the
    // owner's top level.
    await ed.page.locator(`#shared tr[data-id="${docId}"]`).getByRole('button', { name: 'Remove from folder' }).click();
    await expect(ed.page.locator('#artifacts-status')).toHaveText("Removed from the folder. It is at its owner's top level now.", { timeout: 60_000 });
    await settled(ed.page);
    await expect(ed.page.locator(`#shared tr[data-id="${docId}"]`)).toHaveCount(0);
    expect(listed().find((a) => a.id === docId).parent ?? null).toBeNull();
  } finally {
    await ed.context.close();
  }
});
