// Folders holding other people's items, in a real browser (F3). An editor of
// the owner's folder puts their own artifact in it, and the folder's owner
// reads it. When the owner shares the folder with a reader, the editor's item
// waits on the editor: the reader sees a stub until the editor clicks Apply.
// Deleting the folder moves the editor's item to the editor's top level and
// ends the reader's access to it.
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

test("others' items: place in someone's folder, a stub until applied, and delete the folder", async ({ browser, ownerPage, browserName }) => {
  const s = loadState();
  const domain = s.users.owner.email.split('@')[1];
  const stamp = `${browserName}-${Date.now()}`;
  const editor = await freshUser(`of-ed-${stamp}`, domain);
  const reader = await freshUser(`of-rd-${stamp}`, domain);
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

  // Sharing the folder with the reader cannot sign the editor's item, so
  // the item waits on the editor.
  const out = cli('owner', ['share', topId, reader.email, '--role', 'viewer']);
  expect(out).toContain(`${docId}: waits on ${editor.email}`);

  const ed = await signedIn(browser, editor);
  const rd = await signedIn(browser, reader);
  try {
    // The reader sees the item as a stub naming its owner, and cannot read it.
    await artifacts(rd.page);
    await rd.page.locator(`#shared tr[data-id="${topId}"]`).getByRole('button', { name: top }).click();
    const stub = rd.page.locator(`#shared tr[data-id="${docId}"]`);
    await expect(stub).toHaveAttribute('data-stub', 'true');
    await expect(stub.locator('.stub-note')).toHaveText(`not shared with you yet, owned by ${editor.email}`);
    await expect(stub.getByRole('link')).toHaveCount(0);
    await reads(rd.page, docId, false);

    // The editor is told the item is out of step with its folder, and
    // applies it with one click.
    await artifacts(ed.page);
    await expect(ed.page.locator('#apply-text')).toContainText(doc);
    await ed.page.locator('#apply-button').click();
    await expect(ed.page.locator('#artifacts-status')).toContainText('items up to date', { timeout: 60_000 });
    await settled(ed.page);
    await expect(ed.page.locator('#apply-bar')).toBeHidden();
    await reads(rd.page, docId, true);

    // Deleting the folder says the editor's item moves to its owner, then
    // moves it there, and the reader loses it.
    await artifacts(ownerPage);
    const row = ownerPage.locator(`#own tr[data-id="${topId}"]`);
    await row.getByRole('button', { name: 'Delete' }).click();
    await expect(row.getByRole('button', { name: /Delete/ })).toHaveText(
      "Delete 1 folder and 0 artifacts of yours, and move 1 item other people own to their owners' top level?");
    await row.getByRole('button', { name: /Delete/ }).click();
    await expect(row).toHaveCount(0, { timeout: 60_000 });
    const moved = JSON.parse(asEditor(['artifact', 'list', '--json'])).find((a) => a.id === docId);
    expect(moved.parent ?? null).toBeNull();
    await reads(ed.page, docId, true);
    await reads(rd.page, docId, false);
  } finally {
    await ed.context.close();
    await rd.context.close();
  }
});
