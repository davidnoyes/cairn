// Tests for boot.js, the content origin's boot page script: registering the
// worker, telling the shell it is ready, handing the worker the keys, and
// moving on to the version, against a fake window, document, and worker.
// Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appOriginFromMeta, checkKeysTarget, readyMessage, run } from './boot.js';

const APP = 'https://cairn.example';
const ID = '11111111-2222-4333-8444-555555555555';
const VID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const OTHER_VID = 'aaaaaaaa-bbbb-4ccc-8ddd-ffffffffffff';
const CONTENT = `https://${ID}.cairn.example:8443`;

const meta = (content) => ({ querySelector: (sel) => (sel === 'meta[name="cairn-app-origin"]' && content !== null ? { getAttribute: () => content } : null) });

test('appOriginFromMeta accepts an http(s) origin and returns it as an origin', () => {
  assert.equal(appOriginFromMeta(meta(APP)), APP);
  assert.equal(appOriginFromMeta(meta('http://localhost:8080')), 'http://localhost:8080');
  assert.equal(appOriginFromMeta(meta(APP + '/path?q=1')), APP);
});

test('appOriginFromMeta refuses a missing, empty, or non-http(s) value', () => {
  for (const v of [null, '', 'javascript:alert(1)', 'ftp://x.example', 'data:text/html,x', 'not a url', 'null']) {
    assert.equal(appOriginFromMeta(meta(v)), null, String(v));
  }
});

test('readyMessage names no version at the boot URL', () => {
  assert.deepEqual(readyMessage('/_cairn/boot'), { cairn: 'ready', version: null, path: null });
  assert.deepEqual(readyMessage('/'), { cairn: 'ready', version: null, path: null });
  assert.deepEqual(readyMessage(`/${VID}`), { cairn: 'ready', version: null, path: null });
});

test('readyMessage names the version and path of a content URL', () => {
  assert.deepEqual(readyMessage(`/${VID}/sub/page.html`), { cairn: 'ready', version: VID, path: '/sub/page.html' });
  assert.deepEqual(readyMessage(`/${VID}/`), { cairn: 'ready', version: VID, path: '/index.html' });
  assert.deepEqual(readyMessage(`/${VID}/a%20b.html`), { cairn: 'ready', version: VID, path: '/a b.html' });
});

test('checkKeysTarget wants a lowercase UUID version and a path starting with a slash', () => {
  assert.doesNotThrow(() => checkKeysTarget({ version: VID, path: '/' }));
  assert.doesNotThrow(() => checkKeysTarget({ version: VID, path: '/a/b.html' }));
  for (const bad of [
    { version: VID.toUpperCase(), path: '/' },
    { version: 'x', path: '/' },
    { version: `${VID}/..`, path: '/' },
    { version: 5, path: '/' },
    { version: [VID], path: '/' },
    { version: 'x' + VID, path: '/' },
    { version: VID, path: 'a' },
    { version: VID, path: '' },
    { version: VID, path: 7 },
    { version: VID },
    { path: '/' },
  ]) {
    assert.throws(() => checkKeysTarget(bad), undefined, JSON.stringify(bad));
  }
});

// --- run ---

// setup builds the fakes. registered holds the register call; the worker is
// active, and controls the page unless controlled is false.
function setup({ metaContent = APP, controlled = true, pathname = '/_cairn/boot', register = null } = {}) {
  const container = new EventTarget();
  const worker = { posted: [], postMessage(m) { this.posted.push(m); } };
  container.controller = controlled ? worker : null;
  container.registered = [];
  container.register = register || (async (url, opts) => {
    container.registered.push([url, opts]);
    return {};
  });
  container.ready = Promise.resolve({ active: worker });
  const win = new EventTarget();
  win.parent = { posted: [], postMessage(m, o) { this.posted.push([m, o]); } };
  const shown = [];
  const doc = {
    ...meta(metaContent),
    createElement: () => ({}),
    body: { appendChild: (el) => shown.push(el) },
  };
  const replaced = [];
  const loc = { pathname, replace: (u) => replaced.push(u) };
  const done = run({ doc, win, loc, nav: { serviceWorker: container } });
  return { container, worker, win, doc, shown, replaced, done };
}

const tick = () => new Promise((r) => setImmediate(r));
const msg = (data, source, origin) => Object.assign(new Event('message'), { data, source, origin });
const keys = (o = {}) => ({ cairn: 'keys', version: VID, path: '/index.html', ...o });
const text = (shown) => shown.map((e) => e.textContent).join('\n');

test('a missing or bad app origin shows an error and registers nothing', async () => {
  for (const metaContent of [null, '', 'javascript:alert(1)']) {
    const s = setup({ metaContent });
    await s.done;
    assert.match(text(s.shown), /error/i);
    assert.deepEqual(s.container.registered, []);
    assert.deepEqual(s.win.parent.posted, []);
  }
});

test('it registers the worker as a module at the root scope, with the app origin in the query', async () => {
  const s = setup();
  await tick();
  assert.deepEqual(s.container.registered, [[`/_cairn/sw.js?app=${encodeURIComponent(APP)}`, { type: 'module', scope: '/', updateViaCache: 'none' }]]);
});

test('it posts ready to the parent at the app origin once the worker controls the page', async () => {
  const s = setup();
  await tick();
  assert.deepEqual(s.win.parent.posted, [[{ cairn: 'ready', version: null, path: null }, APP]]);
});

// Firefox leaves the boot page uncontrolled on a repeat visit, and no
// controllerchange follows. The navigation to the version is still the
// worker's, so the page talks to the registration's active worker.
test('an uncontrolled page hands the keys to the active worker without waiting for control', async () => {
  const s = setup({ controlled: false, pathname: `/${VID}/x.html` });
  await tick();
  assert.deepEqual(s.win.parent.posted, [[{ cairn: 'ready', version: VID, path: '/x.html' }, APP]]);
  s.win.dispatchEvent(msg(keys(), s.win.parent, APP));
  await tick();
  assert.deepEqual(s.worker.posted, [keys()]);
  s.container.dispatchEvent(msg({ cairn: 'keys-ok', version: VID }, s.worker, undefined));
  await s.done;
  assert.deepEqual(s.replaced, [`/${VID}/index.html`]);
});

test('the keys go to the active worker, not an older one still controlling the page', async () => {
  const s = setup();
  const old = { posted: [], postMessage(m) { this.posted.push(m); } };
  s.container.controller = old;
  await tick();
  s.win.dispatchEvent(msg(keys(), s.win.parent, APP));
  await tick();
  assert.deepEqual(old.posted, []);
  assert.deepEqual(s.worker.posted, [keys()]);
  s.container.dispatchEvent(msg({ cairn: 'keys-ok', version: VID }, old, undefined));
  await tick();
  assert.deepEqual(s.replaced, [], 'only the active worker confirms');
});

test('a registration failure is shown as an error, as text', async () => {
  const s = setup({ register: async () => { throw new Error('blocked <img src=x>'); } });
  await s.done;
  assert.match(text(s.shown), /error.*blocked <img src=x>/i);
  assert.deepEqual(s.win.parent.posted, []);
});

test('keys from the parent at the app origin go to the worker, then it moves to the version', async () => {
  const s = setup();
  await tick();
  const k = keys({ path: '/sub/page.html', extra: 'passed on' });
  s.win.dispatchEvent(msg(k, s.win.parent, APP));
  await tick();
  assert.deepEqual(s.worker.posted, [k]);
  assert.deepEqual(s.replaced, [], 'not before the worker confirms');
  s.container.dispatchEvent(msg({ cairn: 'keys-ok', version: VID }, s.worker, undefined));
  await s.done;
  assert.deepEqual(s.replaced, [`/${VID}/sub/page.html`]);
});

test('keys from another source or origin are ignored', async () => {
  const s = setup();
  await tick();
  s.win.dispatchEvent(msg(keys(), { postMessage() {} }, APP));
  s.win.dispatchEvent(msg(keys(), s.win.parent, 'https://evil.example'));
  s.win.dispatchEvent(msg(keys(), s.win.parent, CONTENT));
  s.win.dispatchEvent(msg(keys(), null, APP));
  await tick();
  assert.deepEqual(s.worker.posted, []);
  assert.equal(text(s.shown), '');
});

test('other messages from the parent are ignored', async () => {
  const s = setup();
  await tick();
  for (const data of [{ cairn: 'token', token: null, tokenExpires: null }, { cairn: 'ready' }, 'keys', null, 3]) {
    s.win.dispatchEvent(msg(data, s.win.parent, APP));
  }
  await tick();
  assert.deepEqual(s.worker.posted, []);
  assert.equal(text(s.shown), '');
});

test('keys with a bad version or path are refused with an error and never reach the worker', async () => {
  for (const bad of [{ version: VID.toUpperCase() }, { version: '../x' }, { path: 'index.html' }, { path: undefined }]) {
    const s = setup();
    await tick();
    s.win.dispatchEvent(msg(keys(bad), s.win.parent, APP));
    await tick();
    assert.deepEqual(s.worker.posted, [], JSON.stringify(bad));
    assert.match(text(s.shown), /error/i);
    assert.deepEqual(s.replaced, []);
  }
});

test('only the first keys message is taken', async () => {
  const s = setup();
  await tick();
  s.win.dispatchEvent(msg(keys(), s.win.parent, APP));
  await tick();
  s.win.dispatchEvent(msg(keys({ version: OTHER_VID }), s.win.parent, APP));
  await tick();
  assert.equal(s.worker.posted.length, 1);
});

test('only a keys-ok for the same version from the worker moves it on', async () => {
  const s = setup();
  await tick();
  s.win.dispatchEvent(msg(keys(), s.win.parent, APP));
  await tick();
  s.container.dispatchEvent(msg({ cairn: 'keys-ok', version: OTHER_VID }, s.worker, undefined));
  s.container.dispatchEvent(msg({ cairn: 'keys-ok', version: VID }, { other: true }, undefined));
  s.container.dispatchEvent(msg({ cairn: 'keys-ok', version: VID }, null, undefined));
  s.container.dispatchEvent(msg({ cairn: 'keys-ok' }, s.worker, undefined));
  s.container.dispatchEvent(msg(null, s.worker, undefined));
  await tick();
  assert.deepEqual(s.replaced, []);
  s.container.dispatchEvent(msg({ cairn: 'keys-ok', version: VID }, s.worker, undefined));
  await s.done;
  assert.deepEqual(s.replaced, [`/${VID}/index.html`]);
});

test('keys-error shows the error and stays on the boot page', async () => {
  const s = setup();
  await tick();
  s.win.dispatchEvent(msg(keys(), s.win.parent, APP));
  await tick();
  s.container.dispatchEvent(msg({ cairn: 'keys-error', version: OTHER_VID, error: 'wrong one' }, s.worker, undefined));
  s.container.dispatchEvent(msg({ cairn: 'keys-error', version: VID, error: 'a file is missing' }, { other: true }, undefined));
  assert.equal(text(s.shown), '');
  s.container.dispatchEvent(msg({ cairn: 'keys-error', version: VID, error: 'manifest hash <b>x</b>' }, s.worker, undefined));
  await s.done;
  assert.match(text(s.shown), /error.*manifest hash <b>x<\/b>/i);
  assert.deepEqual(s.replaced, []);
});

test('a keys-error with no usable message still shows an error', async () => {
  const s = setup();
  await tick();
  s.win.dispatchEvent(msg(keys(), s.win.parent, APP));
  await tick();
  s.container.dispatchEvent(msg({ cairn: 'keys-error', version: VID, error: 5 }, s.worker, undefined));
  await s.done;
  assert.match(text(s.shown), /error/i);
});
