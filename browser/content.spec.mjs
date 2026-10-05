// Milestone 4 browser tests, written before the feature: encrypted content and
// isolation. See design/e2e-api.md "Encrypted content and serving".
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { expect, test } from './test.mjs';
import { MARKER, PAGE2_MARKER, TEAM_MARKER, cli, cliJson, contentFrame, files, loadState, openShared } from './helpers.mjs';

test('renders: a private artifact shows its content, and no stored file holds the plaintext', async ({ ownerPage }) => {
  const s = loadState();
  const frame = await openShared(ownerPage, s.artifacts['plain-doc'].id);
  await expect(frame.locator('#marker')).toHaveText(MARKER);

  const needle = Buffer.from(MARKER);
  const leaks = files(s.dataDir).filter((f) => readFileSync(f).includes(needle));
  expect(leaks, 'files under the data dir that hold the plaintext marker').toEqual([]);
});

test('hostile: an artifact cannot navigate the top page, read the session, or call the app API', async ({ ownerPage }) => {
  const s = loadState();
  const id = s.artifacts['hostile-doc'].id;
  const frame = await openShared(ownerPage, id);
  await expect(frame.locator('#results')).toHaveText(/^\{/, { timeout: 60_000 });
  const r = JSON.parse(await frame.locator('#results').textContent());

  expect(r.cookie ?? '', 'document.cookie').toBe('');
  const fetched = r.appFetch;
  expect(
    fetched.error !== undefined || [401, 403, 404].includes(fetched.status),
    `app-origin fetch with credentials: ${JSON.stringify(fetched)}`,
  ).toBe(true);
  for (const name of ['membershipPut', 'deleteArtifact', 'transfer', 'keys']) {
    expect(r.api[name], `${name} from the content origin`).toEqual({ status: 404 });
  }

  // Give the shell time to act on the navigate messages, then check it did not.
  await ownerPage.waitForTimeout(2000);
  const top = new URL(ownerPage.url());
  expect(top.origin, 'top page origin').toBe(s.appOrigin);
  expect(top.pathname, 'top page path').toMatch(new RegExp(`^/shared/${id}(/|$)`));
  expect(ownerPage.context().pages().length, 'no extra pages opened').toBe(1);
});

test('public link: renders in a fresh browser context, and the key leaves the address bar', async ({ browser }) => {
  const s = loadState();
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(s.publicLink);
    const frame = await contentFrame(page, { url: s.publicLink });
    await expect(frame.locator('#marker')).toHaveText(MARKER);
    // The shell strips the fragment before anything else, so the key is in
    // no address, frame address, or history entry the page can still read.
    const key = new URLSearchParams(new URL(s.publicLink).hash.slice(1)).get('k');
    expect(key, 'the public link carries a key').toBeTruthy();
    expect(new URL(page.url()).hash, 'top page fragment').toBe('');
    expect(frame.url(), 'content frame address').not.toContain(key);
    const state = await page.evaluate(() => JSON.stringify(history.state));
    expect(state ?? '', 'history state').not.toContain(key);
  } finally {
    await context.close();
  }
});

// linkChecks runs the link and diagram checks against /<base>/<links id>.
async function linkChecks(page, base) {
  const s = loadState();
  const markerId = s.artifacts['plain-doc'].id;
  const frame = await openShared(page, s.artifacts['links-doc'].id, base);

  await expect(frame.locator('svg').first(), 'Mermaid diagram').toBeVisible();

  await page.context().route('https://example.com/**', (route) =>
    route.fulfill({ contentType: 'text/html', body: '<h1>stub</h1>' }));
  const popupPromise = page.context().waitForEvent('page');
  await frame.locator('#external').click();
  const popup = await popupPromise;
  await expect(popup).toHaveURL(/^https:\/\/example\.com\//);
  await popup.close();

  await frame.locator('#internal').click();
  await page.waitForURL(new RegExp(`^${s.appOrigin}/${base}/${markerId}(/|$)`));
}

test('links: internal links replace the page, external links open a tab, Mermaid renders', async ({ ownerPage }) => {
  await linkChecks(ownerPage, 'shared');
});

test('full screen: links and diagrams work at /full/<id>', async ({ ownerPage }) => {
  await linkChecks(ownerPage, 'full');
  await expect(ownerPage.locator('header'), 'no chrome while the artifact shows').toBeHidden();
});

test('full screen: a signed-out visitor told to sign in gets the sign-in link', async ({ browser }) => {
  const s = loadState();
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto(`${s.appOrigin}/full/${s.artifacts['plain-doc'].id}`);
    await expect(page.locator('#status')).toContainText('Sign in');
    await expect(page.locator('#account')).toBeVisible();
    await expect(page.locator('#account')).toHaveAttribute('href', `/login?next=/shared/${s.artifacts['plain-doc'].id}`);
  } finally {
    await context.close();
  }
});

test.describe('worker restart', () => {
  test.skip(({ browserName }) => browserName !== 'chromium', 'stopping a service worker needs the Chromium-only CDP ServiceWorker domain');

  test('after the browser stops the service worker, the next page recovers through the handshake', async ({ ownerPage }) => {
    const s = loadState();
    const frame = await openShared(ownerPage, s.artifacts['plain-doc'].id);
    await expect(frame.locator('#marker')).toHaveText(MARKER);

    const cdp = await ownerPage.context().newCDPSession(ownerPage);
    await cdp.send('ServiceWorker.enable');
    await cdp.send('ServiceWorker.stopAllWorkers');

    await frame.locator('#next').click();
    // The shell's address does not reach page two, but contentFrame only
    // loads it again for Firefox's lost navigation, and this runs in Chromium.
    const next = await contentFrame(ownerPage);
    await expect(next.locator('#marker')).toHaveText(PAGE2_MARKER);
  });
});

test.describe('downloads', () => {
  // frame.js takes the click, fetches the bytes through the worker, and the
  // shell saves them, so every engine downloads the same way.
  test('a download link to the database or a stored file saves the plaintext, in every engine', async ({ ownerPage }) => {
    const s = loadState();
    const frame = await openShared(ownerPage, s.artifacts['plain-doc'].id);
    await expect(frame.locator('#marker')).toHaveText(MARKER);
    const urls = await frame.evaluate(async () => {
      const { cairn } = window;
      await cairn.ready();
      await cairn.db.query('CREATE TABLE IF NOT EXISTS t (x)');
      await cairn.files.upload('note.txt', 'DOWNLOAD-MARKER');
      return { db: cairn.db.downloadURL, file: cairn.files.url('note.txt') };
    });
    for (const [href, starts] of [[urls.db, 'SQLite format 3'], [urls.file, 'DOWNLOAD-MARKER']]) {
      const downloading = ownerPage.waitForEvent('download');
      await frame.evaluate((h) => {
        const a = Object.assign(document.createElement('a'), { href: h, download: '' });
        document.body.append(a);
        a.click();
        a.remove();
      }, href);
      const download = await downloading;
      expect(await download.failure(), `download of ${href}`).toBeNull();
      expect(readFileSync(await download.path()).toString('latin1'), `download of ${href}`).toMatch(new RegExp(`^${starts}`));
    }
  });
});

test('no storage: the content origin writes nothing to Cache Storage or IndexedDB', async ({ ownerPage }) => {
  const s = loadState();
  const frame = await openShared(ownerPage, s.artifacts['plain-doc'].id);
  await expect(frame.locator('#marker')).toHaveText(MARKER);
  const counts = await frame.evaluate(async () => ({
    caches: (await caches.keys()).length,
    databases: (await indexedDB.databases()).length,
  }));
  expect(counts).toEqual({ caches: 0, databases: 0 });
});

test('untrusted version: pushed by a demoted editor, it is not rendered until the owner vouches', async ({ ownerPage }) => {
  const s = loadState();
  const team = s.artifacts['team-doc'];
  const editor = s.users.editor.email;

  // Re-runnable: an earlier engine's run left the editor demoted.
  cli('owner', ['share', 'team-doc', editor, '--role', 'editor']);
  const pushed = cliJson('editor', ['push', path.join(s.fixturesDir, 'team'), '--artifact', 'team-doc']);
  const vid = pushed.version.id;
  cli('owner', ['share', 'team-doc', editor, '--role', 'viewer']);

  await ownerPage.goto(`${s.appOrigin}/shared/${team.id}/${vid}`);
  await expect(ownerPage.getByText(/no longer an editor/i)).toBeVisible();
  const hasFrame = ownerPage.frames().some((f) => /\.localhost$/.test(new URL(f.url()).hostname));
  expect(hasFrame, 'an untrusted version must not get a content frame').toBe(false);

  cli('owner', ['vouch', 'team-doc', vid]);
  await ownerPage.reload();
  const frame = await contentFrame(ownerPage);
  await expect(frame.locator('#marker')).toHaveText(TEAM_MARKER);
});

test('tampered blob: a changed stored byte shows an error and never the content', async ({ ownerPage }) => {
  const s = loadState();
  const art = s.artifacts['tamper-doc'];
  const blobs = files(path.join(s.dataDir, 'content', art.id)).filter((f) => path.basename(path.dirname(f)) === 'blobs');
  expect(blobs.length, `blob files under content/${art.id}/*/blobs/`).toBeGreaterThan(0);

  const originals = blobs.map((f) => [f, readFileSync(f)]);
  try {
    // The blob for index.html has a random ID, so change the last byte of each.
    for (const [f, bytes] of originals) {
      const changed = Buffer.from(bytes);
      changed[changed.length - 1] ^= 0x01;
      writeFileSync(f, changed);
    }
    await ownerPage.goto(`${s.appOrigin}/shared/${art.id}`);
    // The error shows in one of two places: the shell's status line (the
    // manifest fails its check), or the content frame (a file fails in the
    // worker). Nothing else counts, so a browser error page cannot pass.
    const shown = /error|fail|tamper|corrupt|integrity|could not|cannot|unable/i;
    await expect
      .poll(async () => {
        const status = ownerPage.locator('#status');
        if (await status.isVisible().catch(() => false) && shown.test(await status.innerText())) return true;
        const frame = ownerPage.frames().find((f) => /^[0-9a-f-]{36}\.localhost$/.test(new URL(f.url(), 'about:blank').hostname));
        return !!frame && shown.test(await frame.locator('body').innerText().catch(() => ''));
      }, { message: 'an error is shown in the shell status or the content frame' })
      .toBe(true);
    for (const f of ownerPage.frames()) {
      expect(await f.locator('body').innerText().catch(() => '')).not.toContain(MARKER);
    }
  } finally {
    for (const [f, bytes] of originals) writeFileSync(f, bytes);
  }
});

test('app pages: /login refuses framing', async ({ request }) => {
  const s = loadState();
  const res = await request.get(`${s.appOrigin}/login`);
  expect(res.headers()['content-security-policy']).toContain("frame-ancestors 'none'");
});

test('app pages: the shell allows only content origins as frames', async ({ ownerContext }) => {
  const s = loadState();
  const res = await ownerContext.request.get(`${s.appOrigin}/shared/${s.artifacts['plain-doc'].id}`);
  expect(res.status()).toBe(200);
  const csp = res.headers()['content-security-policy'] ?? '';
  expect(csp).toMatch(new RegExp(String.raw`frame-src[^;]*\*\.localhost:${s.port}`));
});
