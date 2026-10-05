// Milestone 5 browser tests: the client-side database and stored files. See
// design/e2e-api.md "Client-side database and files". Every engine runs
// against the same server, so each test names its tables and files after the
// engine, and puts back any membership it changes.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { expect, test } from './test.mjs';
import { MARKER, cli, contentFrame, files, loadState, openShared, signIn } from './helpers.mjs';

// openData opens data-doc and waits until it renders, so the worker has keys.
async function openData(page) {
  const frame = await openShared(page, loadState().artifacts['data-doc'].id);
  await expect(frame.locator('#marker')).toHaveText(MARKER);
  return frame;
}

const query = (frame, sql, params = []) =>
  frame.evaluate(([q, p]) => window.cairn.db.query(q, p), [sql, params]);

// queryError runs a query that should fail and returns its message.
const queryError = (frame, sql, params = []) =>
  frame.evaluate(([q, p]) => window.cairn.db.query(q, p).then(() => null, (e) => e.message), [sql, params]);

test('guestbook: a note lands and survives a reload, with nothing fetched from outside the server', async ({ ownerPage, browserName }) => {
  const s = loadState();
  const outside = [];
  await ownerPage.route('**/*', (route) => {
    const host = new URL(route.request().url()).hostname;
    if (host === 'localhost' || host.endsWith('.localhost')) return route.continue();
    outside.push(route.request().url());
    return route.abort();
  });
  const note = `guestbook-${browserName}-${Date.now()}`;
  let frame = await openShared(ownerPage, s.artifacts.guestbook.id);
  await expect(frame.locator('#mode')).toHaveText('remote');
  // The page fills in #who just before it listens for submit.
  await expect(frame.locator('#who')).not.toHaveText('…');
  await frame.locator('#message').fill(note);
  await frame.locator('#message').press('Enter');
  await expect(frame.locator('#entries')).toContainText(note);

  await ownerPage.reload();
  frame = await contentFrame(ownerPage);
  await expect(frame.locator('#entries')).toContainText(note);
  // Resource timing sees what the worker served too, which page.route does not.
  const loaded = await frame.evaluate(() => performance.getEntriesByType('resource').map((e) => e.name));
  const origin = new URL(frame.url()).origin;
  expect(loaded.filter((u) => new URL(u).origin !== origin), 'resources from another origin').toEqual([]);
  expect(loaded.some((u) => new URL(u).pathname === '/_cairn/sql-wasm.wasm'), 'sql.js wasm from /_cairn/').toBe(true);
  expect(outside).toEqual([]);
});

test('poll: a vote is counted', async ({ ownerPage }) => {
  const frame = await openShared(ownerPage, loadState().artifacts.poll.id);
  const option = frame.locator('button.option').first();
  await expect(option).toBeVisible();
  const before = Number(await frame.locator('#total').innerText());
  await option.click();
  await expect(frame.locator('#total')).toHaveText(String(before + 1));
});

test('drive: an uploaded file is listed, and still listed after a reload', async ({ ownerPage, browserName }) => {
  const name = `drive-${browserName}-${Date.now()}.txt`;
  let frame = await openShared(ownerPage, loadState().artifacts.drive.id);
  await expect(frame.locator('#pick')).toBeVisible();
  await frame.locator('#file-input').setInputFiles({ name, mimeType: 'text/plain', buffer: Buffer.from('drive body') });
  await expect(frame.locator('#list')).toContainText(name);
  await ownerPage.reload();
  frame = await contentFrame(ownerPage);
  await expect(frame.locator('#list')).toContainText(name);
});

test('two pages writing at once both land', async ({ ownerPage, browserName }) => {
  const table = `race_${browserName}`;
  const a = await openData(ownerPage);
  const other = await ownerPage.context().newPage();
  try {
    const b = await openData(other);
    await query(a, `CREATE TABLE IF NOT EXISTS ${table} (who TEXT, n INTEGER)`);
    await query(a, `DELETE FROM ${table}`);
    const write = (frame, who) => frame.evaluate(async ([t, w]) => {
      for (let i = 0; i < 5; i++) await window.cairn.db.query(`INSERT INTO ${t} VALUES (?, ?)`, [w, i]);
    }, [table, who]);
    await Promise.all([write(a, 'a'), write(b, 'b')]);
    const counted = await query(b, `SELECT who, count(*) FROM ${table} GROUP BY who ORDER BY who`);
    expect(counted.rows).toEqual([['a', 5], ['b', 5]]);
  } finally {
    await other.close();
  }
});

test('a removed editor cannot write, and the change re-seals what they wrote', async ({ ownerPage, browser, browserName }) => {
  const s = loadState();
  const { id, version } = s.artifacts['data-doc'];
  const editor = s.users.editor;
  const table = `trust_${browserName}`;
  // Re-runnable: an earlier engine's run left the editor removed.
  cli('owner', ['share', 'data-doc', editor.email, '--role', 'editor']);
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await signIn(page, editor.email, editor.password);
    let owner = await openData(ownerPage);
    await query(owner, `CREATE TABLE IF NOT EXISTS ${table} (who TEXT)`);
    await query(owner, `DELETE FROM ${table}`);
    const asEditor = await openData(page);
    await query(asEditor, `INSERT INTO ${table} VALUES ('editor')`);
    const written = JSON.parse(cli('owner', ['db', 'revisions', '--artifact', id, '--version', version, '--json']))[0];

    cli('owner', ['share', 'data-doc', editor.email, '--role', 'viewer']);
    // The editor's page still holds the old record, so the shell signs; the
    // server is what refuses.
    expect(await queryError(asEditor, `INSERT INTO ${table} VALUES ('removed')`)).toMatch(/./);

    // The demotion re-sealed the editor's revision under the new epoch, signed
    // by the owner, so the owner reads it.
    const resealed = JSON.parse(cli('owner', ['db', 'revisions', '--artifact', id, '--version', version, '--json']))[0];
    expect(resealed.revision).toBeGreaterThan(written.revision);
    expect(resealed.epoch).toBeGreaterThan(written.epoch);
    await ownerPage.reload();
    owner = await contentFrame(ownerPage);
    await expect(owner.locator('#marker')).toHaveText(MARKER);
    expect((await query(owner, `SELECT who FROM ${table}`)).rows).toEqual([['editor']]);
  } finally {
    cli('owner', ['share', 'data-doc', editor.email, '--role', 'editor']);
    await context.close();
  }
});

test('cairn db restore puts back a kept revision, and the browser reads it', async ({ ownerPage, browserName }) => {
  const { id, version } = loadState().artifacts['data-doc'];
  const db = ['--artifact', id, '--version', version];
  const table = `restore_${browserName}`;
  const frame = await openData(ownerPage);
  await query(frame, `CREATE TABLE IF NOT EXISTS ${table} (n INTEGER)`);
  await query(frame, `DELETE FROM ${table}`);
  await query(frame, `INSERT INTO ${table} VALUES (1)`);
  const kept = JSON.parse(cli('owner', ['db', 'revisions', ...db, '--json']))[0].revision;
  await query(frame, `DELETE FROM ${table}`);

  const out = JSON.parse(cli('owner', ['db', 'restore', ...db, '--revision', String(kept), '--json']));
  expect(out.restored).toBe(kept);
  expect(out.revision).toBeGreaterThan(kept + 1);
  expect((await query(frame, `SELECT n FROM ${table}`)).rows).toEqual([[1]]);
});

test('cairn db query and batch read what the browser wrote, and the browser reads what they wrote', async ({ ownerPage, browserName }) => {
  const { id, version } = loadState().artifacts['data-doc'];
  const db = ['--artifact', id, '--version', version];
  const table = `cli_${browserName}`;
  const frame = await openData(ownerPage);
  await query(frame, `CREATE TABLE IF NOT EXISTS ${table} (k TEXT, n INTEGER, x REAL, z TEXT)`);
  await query(frame, `DELETE FROM ${table}`);
  await query(frame, `INSERT INTO ${table} VALUES (?, ?, ?, ?)`, ['browser', 1, 1.5, null]);
  cli('owner', ['db', 'batch', ...db], { input: JSON.stringify([
    { sql: `INSERT INTO ${table} VALUES (?, ?, ?, ?)`, params: ['cli', 2, 2.5, null] },
    { sql: `UPDATE ${table} SET n = n + 10 WHERE k = ?`, params: ['browser'] },
  ]) });

  const sql = `SELECT k, n, x, z FROM ${table} ORDER BY k`;
  // Flags go before the statement: the command stops reading flags there.
  const fromCli = JSON.parse(cli('owner', ['db', 'query', ...db, '--json', sql]));
  const fromBrowser = await query(frame, sql);
  expect(fromBrowser.rows).toEqual([['browser', 11, 1.5, null], ['cli', 2, 2.5, null]]);
  expect(fromCli.columns).toEqual(fromBrowser.columns);
  expect(fromCli.rows).toEqual(fromBrowser.rows);
});

test('the server keeps the last 10 revisions', async ({ ownerPage, browserName }) => {
  const s = loadState();
  const { id, version } = s.artifacts['data-doc'];
  const table = `keep_${browserName}`;
  const frame = await openData(ownerPage);
  await query(frame, `CREATE TABLE IF NOT EXISTS ${table} (n INTEGER)`);
  for (let i = 0; i < 11; i++) await query(frame, `INSERT INTO ${table} VALUES (?)`, [i]);
  const revisions = await frame.evaluate(async (url) => (await fetch(url)).json(),
    `/api/artifacts/${id}/versions/${version}/db/revisions`);
  expect(revisions).toHaveLength(10);
  const numbers = revisions.map((r) => r.revision);
  expect(numbers).toEqual([...numbers].sort((x, y) => y - x));
  expect(numbers[0] - numbers[9]).toBe(9);
});

test('a database over the size cap is refused, and the change is not kept', async ({ ownerPage, browserName }) => {
  const table = `big_${browserName}`;
  const frame = await openData(ownerPage);
  // The suite's server runs with --max-db-mb 1; random bytes do not shrink.
  expect(await queryError(frame, `CREATE TABLE ${table} AS SELECT randomblob(1200000) AS b`)).toMatch(/over 1 MiB/);
  const left = await query(frame, "SELECT count(*) FROM sqlite_master WHERE name = ?", [table]);
  expect(left.rows).toEqual([[0]]);
});

test('no stored file name, file body, or database value appears under the data directory', async ({ ownerPage, browserName }) => {
  const s = loadState();
  const name = `SECRET-NAME-${browserName}-4b1e.txt`;
  const body = `SECRET-BODY-${browserName}-c09d`;
  const value = `SECRET-VALUE-${browserName}-77a2`;
  const frame = await openData(ownerPage);
  await frame.evaluate(async ([n, b]) => window.cairn.files.upload(n, b), [name, body]);
  await query(frame, 'CREATE TABLE IF NOT EXISTS secrets (v TEXT)');
  await query(frame, 'INSERT INTO secrets VALUES (?)', [value]);
  expect(await frame.evaluate(async (n) => (await window.cairn.files.download(n)).text(), name)).toBe(body);

  const stored = files(s.dataDir);
  expect(stored.filter((f) => path.relative(s.dataDir, f).includes(name)), 'paths holding the file name').toEqual([]);
  for (const needle of [name, body, value]) {
    const bytes = Buffer.from(needle);
    expect(stored.filter((f) => readFileSync(f).includes(bytes)), `files holding ${needle}`).toEqual([]);
  }
});
