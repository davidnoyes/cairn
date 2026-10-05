// Shared by the global setup and the specs. Imports nothing from Playwright so
// the setup can use it too.
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

export const MARKER = 'CAIRN-PLAINTEXT-MARKER-7f3a';
export const PAGE2_MARKER = 'CAIRN-PAGE-TWO-MARKER-91c4';
export const TEAM_MARKER = 'CAIRN-TEAM-MARKER-5d2e';

// loadState reads the JSON the global setup wrote. Its path travels in the
// environment, which the workers inherit.
export function loadState() {
  return JSON.parse(readFileSync(process.env.CAIRN_E2E_STATE, 'utf8'));
}

// runCli runs the cairn binary with one user's CLI state. CAIRN_HOST and
// CAIRN_API_KEY are dropped so nothing reaches a server other than the test's.
export function runCli(bin, config, args, { input } = {}) {
  const env = { ...process.env, CAIRN_CONFIG: config };
  delete env.CAIRN_HOST;
  delete env.CAIRN_API_KEY;
  return execFileSync(bin, args, { env, input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
}

// cli runs the CLI as a named user: 'owner', 'editor' or 'viewer'.
export function cli(user, args, opts) {
  const s = loadState();
  return runCli(s.bin, s.users[user].config, args, opts);
}

export function cliJson(user, args) {
  return JSON.parse(cli(user, [...args, '--json']));
}

// signIn goes through the real form. Argon2id runs in wasm, so it is slow.
export async function signIn(page, email, password) {
  const s = loadState();
  await page.goto(`${s.appOrigin}/login`);
  try {
    await page.locator('#email').fill(email);
  } catch (e) {
    // The page disables its form when the browser fails its crypto check.
    const shown = await page.locator('#error').textContent().catch(() => '');
    throw new Error(`the sign-in form took no input (error shown: ${JSON.stringify(shown)}): ${e.message}`);
  }
  await page.locator('#password').fill(password);
  await page.locator('#submit').click();
  try {
    await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 60_000 });
  } catch (e) {
    const shown = await page.locator('#error').textContent().catch(() => '');
    throw new Error(`sign-in did not leave /login (error shown: ${JSON.stringify(shown)}): ${e.message}`);
  }
}

// contentFrame returns the artifact's frame: the one on a <uuid>.localhost
// origin, once it has left the boot page for the content. A frame taken while
// still on /_cairn/boot navigates under the caller, and Firefox can then hang
// a locator on it past its own timeout. Firefox can also leave a frame's
// reported URL on the boot page after the content has loaded, so a frame
// still reported there is asked for its own location. Rarely, Firefox's driver
// misses the navigation altogether: the content renders, but the frame keeps a
// dead context and never answers. A frame that stays silent for five seconds
// is that case, so the page is loaded again once, from url, for a fresh frame
// tree. url defaults to the page's address, so a caller whose frame that
// address alone does not reproduce (a public link, whose key the shell strips
// from the address) passes the one it opened. A boot page that is really stuck
// still answers, so it still fails. It throws when none appears within the
// timeout.
export async function contentFrame(page, { url = page.url(), timeout = 20_000 } = {}) {
  const artifactFrames = () => page.frames().filter((f) => /^[0-9a-f-]{36}\.localhost$/.test(safeHost(f.url())));
  const deadline = Date.now() + timeout;
  let silentSince = 0;
  let reloaded = false;
  while (Date.now() < deadline) {
    let silent = false;
    for (const f of artifactFrames()) {
      if (!safePath(f.url()).startsWith('/_cairn/')) return f;
      const asked = f.evaluate(() => location.pathname).catch(() => '/_cairn/');
      const actual = await Promise.race([asked, page.waitForTimeout(1000).then(() => null)]);
      if (actual === null) {
        silent = true;
        silentSince ||= Date.now();
        if (!reloaded && Date.now() - silentSince >= 5_000) {
          reloaded = true;
          silentSince = 0;
          console.warn('contentFrame: the artifact frame went silent on the boot page; loading the page again');
          // By way of about:blank, since a url that differs from the address
          // only in its fragment would not load the page again.
          await page.goto('about:blank');
          await page.goto(url, { timeout: Math.max(1000, deadline - Date.now()) });
          break;
        }
        continue;
      }
      if (!actual.startsWith('/_cairn/')) return f;
    }
    if (!silent) silentSince = 0;
    await page.waitForTimeout(250);
  }
  const seen = page.frames().map((f) => f.url()).join(', ');
  throw new Error(`no artifact content frame appeared at ${page.url()} (frames: ${seen})`);
}

function safeHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

function safePath(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return '';
  }
}

// files lists every regular file under dir.
export function files(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...files(p));
    else if (e.isFile()) out.push(p);
  }
  return out;
}

// openShared opens an app-origin page for an artifact and returns its content frame.
export async function openShared(page, id, base = 'shared', vid = '') {
  const s = loadState();
  await page.goto(`${s.appOrigin}/${base}/${id}${vid ? `/${vid}` : ''}`);
  return contentFrame(page);
}

// signedInContext opens a fresh context signed in as a named user.
export async function signedInContext(browser, user, password) {
  const u = loadState().users[user];
  const context = await browser.newContext();
  const page = await context.newPage();
  await signIn(page, u.email, password ?? u.password);
  return { context, page };
}

// cliWithKey runs the CLI headless with an API key and no saved state, the
// way an agent would: CAIRN_HOST is the test server, never anything else.
export function cliWithKey(key, args) {
  const s = loadState();
  const env = { ...process.env, CAIRN_HOST: s.appOrigin, CAIRN_API_KEY: key, CAIRN_CONFIG: path.join(s.tmp, 'no-config.json') };
  return execFileSync(s.bin, args, { env, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
}

// mailedLink waits for the newest link matching re in the log:// mailer's
// output that was not there before `after` bytes of the log.
export async function mailedLink(re, after, timeout = 20_000) {
  const s = loadState();
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const m = readFileSync(s.logPath, 'utf8').slice(after).match(new RegExp(re.source, 'g'));
    if (m) return m[m.length - 1];
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`no mailed link matching ${re} appeared`);
}

export function logSize() {
  return readFileSync(loadState().logPath, 'utf8').length;
}
