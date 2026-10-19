// Managers in a real browser. The owner makes a member manager of a fresh
// artifact. The manager opens the share dialog from their Shared with you
// list, shares with a reader, then removes them, which starts an epoch the
// manager signs and wraps to the owner. The owner's page then reads that epoch
// through its own wrap and adds the estate copy.
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { test, expect } from './test.mjs';
import { MARKER, cli, contentFrame, loadState, logSize, mailedLink, runCli, signIn } from './helpers.mjs';

// freshUser signs up, verifies, and signs in with the command-line tool.
async function freshUser(local, domain) {
  const s = loadState();
  const email = `${local}@${domain}`;
  const password = `e2e-${local}-password-Qm47vz`;
  const config = path.join(s.tmp, 'config', local, 'config.json');
  mkdirSync(path.dirname(config), { recursive: true });
  const before = logSize();
  runCli(s.bin, config, ['signup', '--host', s.appOrigin, '--email', email, '--password-stdin'], { input: `${password}\n` });
  runCli(s.bin, config, ['confirm-email', await mailedLink(new RegExp(`${s.appOrigin}/verify#token=[A-Za-z0-9_-]+`), before)]);
  runCli(s.bin, config, ['login', '--host', s.appOrigin, '--email', email, '--password-stdin'], { input: `${password}\n` });
  return { email, password };
}

// openDialog opens the share dialog for id from the given list, #own or
// #shared.
async function openDialog(page, list, id) {
  const s = loadState();
  await page.goto(`${s.appOrigin}/app`);
  await page.getByRole('tab', { name: 'Artifacts' }).click();
  await page.locator(`${list} tr[data-id="${id}"]`).getByRole('button', { name: 'Share' }).click();
  const dialog = page.locator('dialog#share');
  await expect(dialog).toBeVisible();
  return dialog;
}

const row = (dialog, email) => dialog.locator('#members tr').filter({ hasText: email });

test('manager: shares and unshares from the dialog, and the owner reads the epoch the manager started', async ({ browser, ownerPage, browserName }) => {
  const s = loadState();
  const domain = s.users.owner.email.split('@')[1];
  const stamp = `${browserName}-${Date.now()}`;
  const manager = await freshUser(`mgr-${stamp}`, domain);
  const reader = await freshUser(`rdr-${stamp}`, domain);
  const id = JSON.parse(cli('owner', ['push', path.join(s.fixturesDir, 'marker'), '--artifact', `mgr-doc-${stamp}`, '--create', '--json'])).artifact.id;
  cli('owner', ['share', id, manager.email, '--role', 'manager']);

  // The manager shares from their Shared with you row, and cannot make
  // anyone a manager or touch the owner's or their own entry.
  const mctx = await browser.newContext();
  const mpage = await mctx.newPage();
  await signIn(mpage, manager.email, manager.password);
  let dialog = await openDialog(mpage, '#shared', id);
  await expect(dialog.locator('#share-role option[value=manager]')).toBeHidden();
  await expect(dialog.locator('#share-role option[value=manager]')).toBeDisabled();
  await expect(row(dialog, s.users.owner.email).locator('select')).toHaveCount(0);
  await expect(row(dialog, manager.email).locator('select')).toHaveCount(0);
  await dialog.locator('#share-email').fill(reader.email);
  await dialog.locator('#share-role').selectOption('viewer');
  await dialog.getByRole('button', { name: 'Share' }).click();
  await expect(dialog.locator('#share-status')).toContainText(`Shared with ${reader.email} as viewer.`, { timeout: 60_000 });

  const rctx = await browser.newContext();
  const rpage = await rctx.newPage();
  await signIn(rpage, reader.email, reader.password);
  await rpage.goto(`${s.appOrigin}/shared/${id}`);
  await expect((await contentFrame(rpage)).locator('#marker')).toHaveText(MARKER);
  await rctx.close();

  // Removing the reader starts a new epoch, signed by the manager.
  await row(dialog, reader.email).getByRole('button', { name: 'Remove' }).click();
  await expect(row(dialog, reader.email)).toHaveCount(0, { timeout: 90_000 });
  await mctx.close();

  // The owner reads the new epoch through its own wrap, and the page adds
  // the estate copy the manager could not make.
  await ownerPage.goto(`${s.appOrigin}/shared/${id}`);
  await expect((await contentFrame(ownerPage)).locator('#marker')).toHaveText(MARKER);
  await expect.poll(async () => ownerPage.evaluate(async (aid) => {
    const keys = await (await fetch(`/api/artifacts/${aid}/keys`)).json();
    return keys.estate.map((e) => e.epoch).sort();
  }, id), { timeout: 30_000 }).toEqual([1, 2]);

  // The owner's dialog lists the manager, and offers the manager role.
  dialog = await openDialog(ownerPage, '#own', id);
  await expect(row(dialog, manager.email).getByLabel(`Role of ${manager.email}`)).toHaveValue('manager');
  await expect(dialog.locator('#share-role option[value=manager]')).toBeEnabled();
});
