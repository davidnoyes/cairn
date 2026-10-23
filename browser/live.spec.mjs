// Live update in a real browser: an open shared page shows a new version, or
// an overwritten one, by itself, and comes back to where it was scrolled. A
// page that names a version stays on it.
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { test, expect } from './test.mjs';
import { cli, contentFrame, loadState, openShared } from './helpers.mjs';

// doc writes a long page whose #marker reads text, and returns its directory.
// A late page adds its lines from script half a second after it loads, as a
// page that renders on the client does.
function doc(slug, text, { late = false } = {}) {
  const dir = path.join(loadState().tmp, 'live', slug, text);
  mkdirSync(dir, { recursive: true });
  const lines = Array.from({ length: 300 }, (_, i) => `<p>Line ${i}</p>`).join('');
  const body = late ? '<script src="late.js"></script>' : lines;
  if (late) {
    writeFileSync(path.join(dir, 'late.js'), `setTimeout(() => document.body.insertAdjacentHTML('beforeend', ${JSON.stringify(lines)}), 500);\n`);
  }
  writeFileSync(path.join(dir, 'index.html'), `<!doctype html><html><body>\n<h1 id="marker">${text}</h1>\n${body}\n</body></html>\n`);
  return dir;
}

const push = (slug, text, args = [], opts = {}) => JSON.parse(cli('owner', ['push', doc(slug, text, opts), '--artifact', slug, ...args, '--json']));

// shows waits for the page to show text. The shell reloads itself for an
// update, so the content frame is found again on every try.
async function shows(page, text, timeout = 30_000) {
  await expect(async () => {
    const frame = await contentFrame(page, { timeout: 5_000 });
    await expect(frame.locator('#marker')).toHaveText(text, { timeout: 1_000 });
  }).toPass({ timeout });
  return contentFrame(page);
}

test('live: an open page shows a new version, then an overwrite, with no navigation by the reader', async ({ ownerPage, browserName }) => {
  const slug = `live-follow-${browserName}`;
  const { id } = push(slug, 'first', ['--create']).artifact;
  await openShared(ownerPage, id);
  await shows(ownerPage, 'first');

  push(slug, 'second');
  await shows(ownerPage, 'second');
  push(slug, 'third', ['--overwrite', 'latest']);
  await shows(ownerPage, 'third');
  expect(new URL(ownerPage.url()).pathname, 'the page still follows the newest version').toBe(`/shared/${id}`);
});

test('live: the page comes back to where it was scrolled, even when it renders its content late', async ({ ownerPage, browserName }) => {
  const slug = `live-scroll-${browserName}`;
  const { id } = push(slug, 'before', ['--create']).artifact;
  await openShared(ownerPage, id);
  let frame = await shows(ownerPage, 'before');
  await frame.evaluate(() => window.scrollTo(0, 2000));
  // frame.js reports the position at most every 200 ms.
  await ownerPage.waitForTimeout(600);

  push(slug, 'after', [], { late: true });
  frame = await shows(ownerPage, 'after');
  await expect.poll(() => frame.evaluate(() => window.scrollY)).toBeGreaterThan(1900);
});

test('live: a page that names a version stays on it when a new one is pushed', async ({ ownerPage, browserName }) => {
  const slug = `live-pinned-${browserName}`;
  const pinned = push(slug, 'pinned', ['--create']);
  await openShared(ownerPage, pinned.artifact.id, 'shared', pinned.version.id);
  await shows(ownerPage, 'pinned');
  await ownerPage.evaluate(() => { window.__notReloaded = true; });

  // Two polls after the push: the watch saw the new version, and ignored it.
  const polled = () => ownerPage.waitForResponse((r) => new URL(r.url()).pathname === `/api/artifacts/${pinned.artifact.id}/versions`, { timeout: 15_000 });
  push(slug, 'newer');
  await polled();
  await polled();
  expect(await ownerPage.evaluate(() => window.__notReloaded), 'the page was not reloaded').toBe(true);
  await shows(ownerPage, 'pinned', 5_000);
});
