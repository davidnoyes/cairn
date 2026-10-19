// Viewer accounts in a real browser: a user who can read what is shared with
// them and change nothing. One signs up from the viewer domain; another is a
// member an administrator demotes while an artifact still lists them as
// editor, which is the case the server's own check has to catch.
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { test, expect } from './test.mjs';
import { MARKER, cli, loadState, logSize, mailedLink, openShared, runCli, signIn } from './helpers.mjs';

const query = (frame, sql, params = []) =>
  frame.evaluate(([q, p]) => window.cairn.db.query(q, p), [sql, params]);
const queryError = (frame, sql, params = []) =>
  frame.evaluate(([q, p]) => window.cairn.db.query(q, p).then(() => null, (e) => e.message), [sql, params]);

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
  const run = (args, opts) => runCli(s.bin, config, args, opts);
  return { email, password, config, run };
}

// cliError runs a command that must fail and returns what it printed.
function cliError(run, args) {
  try {
    run(args);
  } catch (err) {
    return `${err.stdout ?? ''}${err.stderr ?? ''}`;
  }
  throw new Error(`cairn ${args.join(' ')} succeeded`);
}

test('viewer: a viewer-domain sign-up reads what is shared with it, cannot be made an editor, and changes nothing', async ({ page, browserName }) => {
  const s = loadState();
  const domain = s.users.owner.email.split('@')[1];
  const reader = await freshUser(`reader-${browserName}-${Date.now()}`, `viewer.${domain}`);
  expect(JSON.parse(reader.run(['whoami', '--json'])).user.role).toBe('viewer');

  expect(cliError((args) => cli('owner', args), ['share', 'plain-doc', reader.email, '--role', 'editor'])).toContain('is a viewer account and can only be a viewer');
  cli('owner', ['share', 'plain-doc', reader.email]);

  await signIn(page, reader.email, reader.password);
  await expect(page.locator('#viewer-note')).toBeVisible();
  await expect(page.locator('#create-hint')).toBeHidden();
  const frame = await openShared(page, s.artifacts['plain-doc'].id);
  await expect(frame.locator('#marker')).toHaveText(MARKER);

  // Even its own API key creates nothing.
  expect(cliError(reader.run, ['push', path.join(s.fixturesDir, 'marker'), '--artifact', `reader-doc-${browserName}`, '--create'])).toContain('a viewer account cannot change anything');
});

test('viewer: a demoted editor still listed as editor reads but cannot write, in the browser or with the command-line tool', async ({ ownerPage, page, browserName }) => {
  const s = loadState();
  const domain = s.users.owner.email.split('@')[1];
  const user = await freshUser(`demoted-${browserName}-${Date.now()}`, domain);
  const { id, version } = s.artifacts['data-doc'];
  cli('owner', ['share', 'data-doc', user.email, '--role', 'editor']);
  const table = `viewer_${browserName}`;
  user.run(['db', 'query', '--artifact', id, '--version', version, `CREATE TABLE IF NOT EXISTS ${table} (k TEXT)`]);

  // The administrator makes them a viewer account on the Admin tab.
  await ownerPage.goto(`${s.appOrigin}/app`);
  await ownerPage.getByRole('tab', { name: 'Admin' }).click();
  const row = ownerPage.locator('#users tr[data-user]').filter({ hasText: user.email });
  await row.getByLabel(`Account of ${user.email}`).selectOption('viewer');
  await expect(row.locator('.pill', { hasText: 'viewer account' })).toBeVisible();

  await signIn(page, user.email, user.password);
  await expect(page.locator('#viewer-note')).toBeVisible();
  const frame = await openShared(page, id);
  await expect(frame.locator('#marker')).toHaveText(MARKER);
  expect((await query(frame, `SELECT COUNT(*) FROM ${table}`)).rows).toEqual([[0]]);
  expect(await queryError(frame, `INSERT INTO ${table} VALUES (?)`, ['from the browser'])).toBe('a viewer account cannot change anything');
  expect(cliError(user.run, ['db', 'query', '--artifact', id, '--version', version, `INSERT INTO ${table} VALUES ('from the tool')`])).toContain('a viewer account cannot change anything');
  expect(JSON.parse(cli('owner', ['db', 'query', '--artifact', id, '--version', version, '--json', `SELECT COUNT(*) FROM ${table}`])).rows).toEqual([[0]]);

  // Made a member again, they write once more.
  await row.getByLabel(`Account of ${user.email}`).selectOption('member');
  await expect(row.locator('.pill', { hasText: 'viewer account' })).toHaveCount(0);
  user.run(['db', 'query', '--artifact', id, '--version', version, `INSERT INTO ${table} VALUES ('back')`]);
});
