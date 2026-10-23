// Live update in a real browser: an open shared page shows a new version, or
// an overwritten one, by itself, and comes back to where it was scrolled. A
// page that names a version stays on it.
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { test, expect } from './test.mjs';
import { cli, contentFrame, loadState, openShared } from './helpers.mjs';

// doc writes a long page whose #marker reads text, and returns its directory.
function doc(slug, text) {
  const dir = path.join(loadState().tmp, 'live', slug, text);
  mkdirSync(dir, { recursive: true });
  const filler = Array.from({ length: 300 }, (_, i) => `<p>Line ${i}</p>`).join('\n');
  writeFileSync(path.join(dir, 'index.html'), `<!doctype html><html><body>\n<h1 id="marker">${text}</h1>\n${filler}\n</body></html>\n`);
  return dir;
}

const push = (slug, text, args = []) => JSON.parse(cli('owner', ['push', doc(slug, text), '--artifact', slug, ...args, '--json']));

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

test('live: the page comes back to where it was scrolled', async ({ ownerPage, browserName }) => {
  const slug = `live-scroll-${browserName}`;
  const { id } = push(slug, 'before', ['--create']).artifact;
  await openShared(ownerPage, id);
  let frame = await shows(ownerPage, 'before');
  await frame.evaluate(() => window.scrollTo(0, 2000));
  // frame.js reports a position 200 ms after scrolling stops.
  await ownerPage.waitForTimeout(600);

  push(slug, 'after');
  frame = await shows(ownerPage, 'after');
  await expect.poll(() => frame.evaluate(() => window.scrollY)).toBeGreaterThan(1900);
});

test('live: a page that names a version stays on it when a new one is pushed', async ({ ownerPage, browserName }) => {
  const slug = `live-pinned-${browserName}`;
  const pinned = push(slug, 'pinned', ['--create']);
  await openShared(ownerPage, pinned.artifact.id, 'shared', pinned.version.id);
  await shows(ownerPage, 'pinned');
  await ownerPage.evaluate(() => { window.__notReloaded = true; });

  push(slug, 'newer');
  // Longer than the shell's 5 s between polls, with room for a slow one.
  await ownerPage.waitForTimeout(12_000);
  expect(await ownerPage.evaluate(() => window.__notReloaded), 'the page was not reloaded').toBe(true);
  await shows(ownerPage, 'pinned', 5_000);
});
