// Tests for frame.js, the script the worker adds to every artifact page:
// link handling, Mermaid loading, and message relaying, against a minimal
// fake window and document.
// Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appOriginFrom, install, linkAction } from './frame.js';

const APP = 'https://cairn.example';
const ID = '11111111-2222-4333-8444-555555555555';
const VID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const CONTENT = `https://${ID}.cairn.example:8443`;
const BASE = `${CONTENT}/${VID}/index.html`;

// act classifies a click on href in a page of the version.
const act = (href, app = APP) => linkAction(href, BASE, CONTENT, app);

test('appOriginFrom reads the app origin from the worker script URL', () => {
  const u = (q) => `${CONTENT}/_cairn/sw.js${q}`;
  assert.equal(appOriginFrom(u(`?app=${encodeURIComponent(APP)}`)), APP);
  assert.equal(appOriginFrom(u(`?app=${encodeURIComponent(APP + '/some/path')}`)), APP);
  assert.equal(appOriginFrom(u('')), null);
  assert.equal(appOriginFrom(u('?app=')), null);
  assert.equal(appOriginFrom(u('?app=javascript:alert(1)')), null);
  assert.equal(appOriginFrom(u('?app=ftp://x.example')), null);
  assert.equal(appOriginFrom('not a url'), null);
  assert.equal(appOriginFrom(undefined), null);
});

test('an external http(s) link opens in a new tab', () => {
  assert.deepEqual(act('https://github.com/foo/bar'), { open: 'https://github.com/foo/bar' });
  assert.deepEqual(act('http://example.com/'), { open: 'http://example.com/' });
});

test('a page of this version or another version is left to the frame', () => {
  assert.equal(act('./other.html'), null);
  assert.equal(act('sub/page.html?x=1'), null);
  assert.equal(act('#hash'), null);
  assert.equal(act(`/${VID}/x.html`), null);
  assert.equal(act('/aaaaaaaa-bbbb-4ccc-8ddd-ffffffffffff/index.html'), null);
});

test('a /shared/ path on the content origin goes to the shell as the path alone', () => {
  assert.deepEqual(act(`/shared/${ID}`), { navigate: `/shared/${ID}` });
  assert.deepEqual(act(`/shared/${ID}/`), { navigate: `/shared/${ID}/` });
  assert.deepEqual(act(`/shared/${ID}/${VID}`), { navigate: `/shared/${ID}/${VID}` });
  assert.deepEqual(act(`${CONTENT}/shared/${ID}/${VID}/`), { navigate: `/shared/${ID}/${VID}/` });
});

test('a /shared/ look-alike is not sent to the shell', () => {
  const paths = [
    '/shared/not-a-uuid',
    `/shared/${VID.toUpperCase()}`,
    `/shared/${ID}/${VID}/x`,
    `/shared/${ID}/x`,
    `/shared/${ID}/${VID}/${VID}`,
    '/shared/',
    `/x/shared/${ID}`,
  ];
  for (const p of paths) assert.equal(act(p), null, p);
});

test('a link to the app origin goes to the shell as an absolute URL', () => {
  assert.deepEqual(act(`${APP}/admin`), { navigate: `${APP}/admin` });
  assert.deepEqual(act(`${APP}/`), { navigate: `${APP}/` });
  assert.deepEqual(act(`${APP}/shared/${ID}?q=1#x`), { navigate: `${APP}/shared/${ID}?q=1#x` });
});

test('a lookalike of the app or content origin is external', () => {
  assert.deepEqual(act('https://cairn.example.evil.test/'), { open: 'https://cairn.example.evil.test/' });
  assert.deepEqual(act('http://cairn.example/'), { open: 'http://cairn.example/' });
  assert.deepEqual(act(`https://${ID}.cairn.example/x`), { open: `https://${ID}.cairn.example/x` });
  assert.deepEqual(act('https://other.cairn.example:8443/x'), { open: 'https://other.cairn.example:8443/x' });
});

test('without an app origin, external links still open but nothing is sent to the shell', () => {
  assert.deepEqual(act('https://github.com/', null), { open: 'https://github.com/' });
  assert.deepEqual(act(`${APP}/admin`, null), { open: `${APP}/admin` });
  assert.equal(act(`/shared/${ID}`, null), null);
});

test('non-http(s) protocols and bad URLs are left alone', () => {
  assert.equal(act('mailto:a@b.com'), null);
  assert.equal(act('javascript:alert(1)'), null);
  assert.equal(act('data:text/html,hi'), null);
  assert.equal(act('http://[bad'), null);
});

// --- wiring ---

// fakeDoc: diagram is the one selector (such as 'pre.mermaid') with a match;
// script says a mermaid.js script is already in the page.
function fakeDoc({ readyState = 'complete', baseTarget = null, diagram = null, script = false } = {}) {
  const doc = new EventTarget();
  doc.readyState = readyState;
  doc.baseURI = BASE;
  doc.querySelector = (sel) => {
    if (sel === 'base[target]') return baseTarget ? { getAttribute: () => baseTarget } : null;
    if (sel.startsWith('script')) return script ? {} : null;
    return diagram && sel.split(',').map((s) => s.trim()).includes(diagram) ? {} : null;
  };
  doc.added = [];
  doc.createElement = (tag) => ({ tagName: tag.toUpperCase() });
  doc.body = { appendChild: (el) => doc.added.push(el) };
  doc.inside = new Set();
  doc.contains = (el) => doc.inside.has(el);
  return doc;
}

function fakeAnchor(attrs) {
  return {
    getAttribute: (k) => (k in attrs ? attrs[k] : null),
    hasAttribute: (k) => k in attrs,
    closest() { return this; },
  };
}

const CTRL_URL = `${CONTENT}/_cairn/sw.js?app=${encodeURIComponent(APP)}`;

// setup installs frame.js on fakes. sw is the controller's script URL, or
// null for no controller.
function setup({ sw = CTRL_URL, doc: docOpts, win: winOpts } = {}) {
  const win = new EventTarget();
  win.location = { origin: CONTENT };
  win.opened = [];
  win.open = (...args) => win.opened.push(args);
  win.parent = { posted: [], transfers: [], postMessage(m, o, t) { this.posted.push([m, o]); this.transfers.push(t); } };
  win.warnings = [];
  win.console = { warn: (m) => win.warnings.push(m) };
  win.fetched = [];
  win.fetch = async (url) => {
    win.fetched.push(url);
    return new Response('bytes', { headers: { 'Content-Disposition': 'attachment; filename="database.db"' } });
  };
  win.HTMLAnchorElement = class {
    click() {
      win.nativeClicks = (win.nativeClicks ?? 0) + 1;
    }
  };
  Object.assign(win, winOpts);
  const doc = fakeDoc(docOpts);
  const container = new EventTarget();
  container.controller = sw ? { scriptURL: sw, posted: [], postMessage(m) { this.posted.push(m); } } : null;
  install(win, doc, { serviceWorker: container });
  return { win, doc, container, controller: container.controller };
}

function click(doc, anchor, init = {}) {
  const ev = new Event('click', { cancelable: true });
  Object.assign(ev, { button: 0, metaKey: false, ctrlKey: false, shiftKey: false, altKey: false }, init);
  Object.defineProperty(ev, 'target', { value: anchor });
  doc.dispatchEvent(ev);
  return ev;
}

const msg = (data, source, origin) => Object.assign(new Event('message'), { data, source, origin });

test('an external link opens a new tab with noopener and the click is cancelled', () => {
  const { win, doc } = setup();
  const ev = click(doc, fakeAnchor({ href: 'https://example.com/' }));
  assert.deepEqual(win.opened, [['https://example.com/', '_blank', 'noopener,noreferrer']]);
  assert.equal(ev.defaultPrevented, true);
});

test('the click listener runs in the capture phase', () => {
  const doc = fakeDoc();
  const seen = [];
  const real = doc.addEventListener.bind(doc);
  doc.addEventListener = (type, fn, opts) => {
    seen.push([type, opts]);
    real(type, fn, opts);
  };
  const win = new EventTarget();
  win.location = { origin: CONTENT };
  install(win, doc, { serviceWorker: { controller: null, addEventListener() {} } });
  assert.deepEqual(seen.filter(([t]) => t === 'click').map(([, o]) => o), [true]);
});

test('an artifact handler that stops the click cannot hide it from frame.js', () => {
  const { win, doc } = setup();
  let artifactRan = false;
  doc.addEventListener('click', (e) => {
    artifactRan = true;
    e.stopImmediatePropagation();
  });
  click(doc, fakeAnchor({ href: 'https://example.com/' }));
  assert.equal(artifactRan, true);
  assert.equal(win.opened.length, 1);
});

test('a link to a /shared/ path or the app origin is posted to the shell at the app origin', () => {
  const { win, doc } = setup();
  const a = click(doc, fakeAnchor({ href: `/shared/${ID}` }));
  const b = click(doc, fakeAnchor({ href: `${APP}/admin` }));
  assert.deepEqual(win.parent.posted, [
    [{ cairn: 'navigate', href: `/shared/${ID}` }, APP],
    [{ cairn: 'navigate', href: `${APP}/admin` }, APP],
  ]);
  assert.equal(a.defaultPrevented && b.defaultPrevented, true);
  assert.deepEqual(win.opened, []);
});

test('a link within the artifact is left to the frame', () => {
  const { win, doc } = setup();
  const ev = click(doc, fakeAnchor({ href: 'page2.html' }));
  assert.deepEqual([win.opened, win.parent.posted], [[], []]);
  assert.equal(ev.defaultPrevented, false);
});

test('modified, non-primary, download, and targeted clicks are left alone', () => {
  const { win, doc } = setup();
  const ext = { href: 'https://example.com/' };
  const evs = [
    click(doc, fakeAnchor(ext), { metaKey: true }),
    click(doc, fakeAnchor(ext), { ctrlKey: true }),
    click(doc, fakeAnchor(ext), { shiftKey: true }),
    click(doc, fakeAnchor(ext), { altKey: true }),
    click(doc, fakeAnchor(ext), { button: 1 }),
    click(doc, fakeAnchor({ ...ext, download: '' })),
    click(doc, fakeAnchor({ ...ext, target: '_blank' })),
    click(doc, fakeAnchor({ href: `/shared/${ID}`, target: '_blank' })),
    click(doc, fakeAnchor({ ...ext, target: '_top' })),
    click(doc, fakeAnchor({ ...ext, target: 'named' })),
    click(doc, fakeAnchor({})),
    click(doc, { closest: () => null }),
  ];
  assert.deepEqual([win.opened, win.parent.posted], [[], []]);
  assert.ok(evs.every((ev) => !ev.defaultPrevented));
});

test('an explicit _self target is treated as none', () => {
  const { win, doc } = setup();
  click(doc, fakeAnchor({ href: 'https://example.com/', target: '_self' }));
  assert.equal(win.opened.length, 1);
});

test('base target applies unless the anchor sets its own', () => {
  const blank = setup({ doc: { baseTarget: '_blank' } });
  click(blank.doc, fakeAnchor({ href: 'https://example.com/' }));
  assert.deepEqual(blank.win.opened, []);
  const self = setup({ doc: { baseTarget: '_blank' } });
  click(self.doc, fakeAnchor({ href: 'https://example.com/', target: '_self' }));
  assert.equal(self.win.opened.length, 1);
});

test('with no controller, external links open and nothing is posted', () => {
  const { win, doc } = setup({ sw: null });
  click(doc, fakeAnchor({ href: 'https://example.com/' }));
  const ev = click(doc, fakeAnchor({ href: `/shared/${ID}` }));
  click(doc, fakeAnchor({ href: `${APP}/admin` }));
  assert.equal(win.opened.length, 2, 'the app-origin link opens in a tab too');
  assert.deepEqual(win.parent.posted, []);
  assert.equal(ev.defaultPrevented, false);
});

test('a worker URL without a valid app origin posts nothing and relays nothing', () => {
  const { win, doc, controller, container } = setup({ sw: `${CONTENT}/_cairn/sw.js` });
  click(doc, fakeAnchor({ href: `/shared/${ID}` }));
  container.dispatchEvent(msg({ cairn: 'need-keys', version: VID }, controller, undefined));
  assert.deepEqual(win.parent.posted, []);
  win.dispatchEvent(msg({ cairn: 'token', token: null, tokenExpires: null }, win.parent, APP));
  assert.deepEqual(controller.posted, []);
});

test('the app origin is read from the controller when it arrives after install', () => {
  const { win, doc, container } = setup({ sw: null });
  container.controller = { scriptURL: CTRL_URL, postMessage() {} };
  click(doc, fakeAnchor({ href: `/shared/${ID}` }));
  assert.equal(win.parent.posted.length, 1);
});

// --- messages ---

const KEYS = { cairn: 'keys', version: VID, anything: 1 };
const TOKEN = { cairn: 'token', token: 't', tokenExpires: 5 };

test('keys and token from the parent at the app origin go to the worker', () => {
  const { win, controller } = setup();
  win.dispatchEvent(msg(KEYS, win.parent, APP));
  win.dispatchEvent(msg(TOKEN, win.parent, APP));
  assert.deepEqual(controller.posted, [KEYS, TOKEN]);
});

test('keys and token from another source or origin are dropped', () => {
  const { win, controller } = setup();
  const other = { postMessage() {} };
  win.dispatchEvent(msg(KEYS, other, APP));
  win.dispatchEvent(msg(KEYS, win.parent, 'https://evil.example'));
  win.dispatchEvent(msg(KEYS, win.parent, CONTENT));
  win.dispatchEvent(msg(TOKEN, other, APP));
  win.dispatchEvent(msg(TOKEN, win.parent, 'https://evil.example'));
  win.dispatchEvent(msg(KEYS, null, APP));
  assert.deepEqual(controller.posted, []);
});

test('only keys and token are forwarded to the worker', () => {
  const { win, controller } = setup();
  const others = [{ cairn: 'need-keys', version: VID }, { cairn: 'navigate', href: '/' }, { cairn: 'keys-ok' }, 'keys', null, 5, {}];
  for (const data of others) win.dispatchEvent(msg(data, win.parent, APP));
  assert.deepEqual(controller.posted, []);
});

test('a message with no controller is dropped without error', () => {
  const { win } = setup({ sw: null });
  win.dispatchEvent(msg(KEYS, win.parent, APP));
});

test('need-keys from the worker is relayed to the parent at the app origin', () => {
  const { win, container, controller } = setup();
  container.dispatchEvent(msg({ cairn: 'need-keys', version: VID, extra: 1 }, controller, undefined));
  assert.deepEqual(win.parent.posted, [[{ cairn: 'need-keys', version: VID }, APP]]);
});

test('worker messages from another source, or of another kind, are not relayed', () => {
  const { win, container, controller } = setup();
  container.dispatchEvent(msg({ cairn: 'need-keys', version: VID }, { other: true }, undefined));
  container.dispatchEvent(msg({ cairn: 'need-keys', version: VID }, null, undefined));
  container.dispatchEvent(msg({ cairn: 'need-keys', version: 7 }, controller, undefined));
  container.dispatchEvent(msg({ cairn: 'keys-ok', version: VID }, controller, undefined));
  container.dispatchEvent(msg({ cairn: 'navigate', href: '/' }, controller, undefined));
  container.dispatchEvent(msg(null, controller, undefined));
  assert.deepEqual(win.parent.posted, []);
});

// --- Mermaid ---

const scripts = (doc) => doc.added.filter((el) => el.tagName === 'SCRIPT').map((el) => el.src);

test('a page with a diagram gets /_cairn/mermaid.js', () => {
  for (const diagram of ['pre.mermaid', 'code.language-mermaid', 'code.mermaid']) {
    const { doc } = setup({ doc: { diagram } });
    assert.deepEqual(scripts(doc), ['/_cairn/mermaid.js'], diagram);
  }
});

test('no diagram, a mermaid.js script already present, or window.mermaid, adds nothing', () => {
  assert.deepEqual(scripts(setup().doc), []);
  assert.deepEqual(scripts(setup({ doc: { diagram: 'pre.mermaid', script: true } }).doc), []);
  assert.deepEqual(scripts(setup({ doc: { diagram: 'pre.mermaid' }, win: { mermaid: {} } }).doc), []);
});

test('Mermaid waits for the DOM to be ready, and is added once', () => {
  const { doc } = setup({ doc: { diagram: 'pre.mermaid', readyState: 'loading' } });
  assert.deepEqual(scripts(doc), []);
  doc.dispatchEvent(new Event('DOMContentLoaded'));
  assert.deepEqual(scripts(doc), ['/_cairn/mermaid.js']);
  doc.dispatchEvent(new Event('DOMContentLoaded'));
  assert.equal(scripts(doc).length, 1);
});

test('frame.js tolerates a browser with no service worker object', () => {
  const win = new EventTarget();
  win.location = { origin: CONTENT };
  install(win, fakeDoc(), {});
  win.dispatchEvent(msg(KEYS, win.parent, APP));
});

// --- downloads ---

const flush = () => new Promise((r) => setTimeout(r, 10));
const text = (buf) => new TextDecoder().decode(buf);

test('a download of this origin is fetched through the worker and handed to the shell', async () => {
  const { win, doc } = setup();
  const ev = click(doc, fakeAnchor({ href: 'data/report.csv', download: 'mine.csv' }));
  assert.equal(ev.defaultPrevented, true);
  await flush();
  assert.deepEqual(win.fetched, [`${CONTENT}/${VID}/data/report.csv`]);
  const [[m, origin]] = win.parent.posted;
  assert.equal(origin, APP);
  assert.equal(m.cairn, 'download');
  assert.equal(m.name, 'mine.csv');
  assert.equal(text(m.bytes), 'bytes');
  assert.deepEqual(win.parent.transfers, [[m.bytes]], 'the bytes are transferred, not copied');
});

test('a download with no name takes the Content-Disposition filename, else the last segment', async () => {
  const a = setup();
  click(a.doc, fakeAnchor({ href: `/api/artifacts/${ID}/versions/${VID}/db/download`, download: '' }));
  await flush();
  assert.equal(a.win.parent.posted[0][0].name, 'database.db');
  const b = setup({ win: { fetch: async () => new Response('x') } });
  click(b.doc, fakeAnchor({ href: 'files/my%20notes.txt?x=1#y', download: '' }));
  await flush();
  assert.equal(b.win.parent.posted[0][0].name, 'my notes.txt');
  const c = setup({ win: { fetch: async () => new Response('x') } });
  click(c.doc, fakeAnchor({ href: 'files/bad%E0', download: '' }));
  await flush();
  assert.equal(c.win.parent.posted[0][0].name, 'bad%E0');
  const d = setup({ win: { fetch: async () => new Response('x', { headers: { 'Content-Disposition': 'attachment; filename=""' } }) } });
  click(d.doc, fakeAnchor({ href: 'files/real.txt', download: '' }));
  await flush();
  assert.equal(d.win.parent.posted[0][0].name, 'real.txt', 'an empty filename is not a name');
});

test('a blob: download is handed to the shell', async () => {
  const { win, doc } = setup();
  const url = `blob:${CONTENT}/0b0e5b1e-0000-4000-8000-000000000000`;
  const ev = click(doc, fakeAnchor({ href: url, download: 'export.json' }));
  assert.equal(ev.defaultPrevented, true);
  await flush();
  assert.deepEqual(win.fetched, [url]);
  assert.equal(win.parent.posted[0][0].name, 'export.json');
  const opaque = setup();
  const ev2 = click(opaque.doc, fakeAnchor({ href: 'blob:null/0b0e5b1e-0000-4000-8000-000000000000', download: 'o.json' }));
  assert.equal(ev2.defaultPrevented, true, 'a blob: URL of an opaque origin too');
  await flush();
  assert.equal(opaque.win.parent.posted[0][0].name, 'o.json');
});

test('a download from another origin, or with no app origin, is left to the browser', async () => {
  const { win, doc } = setup();
  const evs = [
    click(doc, fakeAnchor({ href: 'https://example.com/x.zip', download: '' })),
    click(doc, fakeAnchor({ href: `${APP}/x.zip`, download: '' })),
    click(doc, fakeAnchor({ href: 'data:text/plain,hi', download: 'a.txt' })),
    click(doc, fakeAnchor({ href: 'http://[bad', download: '' })),
  ];
  const none = setup({ sw: null });
  evs.push(click(none.doc, fakeAnchor({ href: 'x.csv', download: '' })));
  await flush();
  assert.ok(evs.every((ev) => !ev.defaultPrevented));
  assert.deepEqual([win.fetched, win.parent.posted, none.win.parent.posted], [[], [], []]);
});

test('a download that fails to fetch is reported, and nothing is posted', async () => {
  const { win, doc } = setup({ win: { fetch: async () => new Response('no', { status: 404 }) } });
  click(doc, fakeAnchor({ href: 'gone.csv', download: '' }));
  await flush();
  assert.deepEqual(win.parent.posted, []);
  assert.deepEqual(win.warnings, ['[cairn] the download failed: HTTP 404']);
  const b = setup({ win: { fetch: async () => { throw new Error('offline'); } } });
  click(b.doc, fakeAnchor({ href: 'x.csv', download: '' }));
  await flush();
  assert.deepEqual(b.win.warnings, ['[cairn] the download failed: offline']);
});

test('a script click on a detached download anchor is handed to the shell', async () => {
  const { win } = setup();
  const a = Object.assign(new win.HTMLAnchorElement(), fakeAnchor({ href: 'x.csv', download: 'x.csv' }));
  a.click();
  await flush();
  assert.equal(win.nativeClicks, undefined, 'the browser is not asked to click it');
  assert.equal(win.parent.posted[0][0].name, 'x.csv');
});

test('a script click on an anchor in the document, or on any other anchor, clicks as usual', async () => {
  const { win, doc } = setup();
  const inDoc = Object.assign(new win.HTMLAnchorElement(), fakeAnchor({ href: 'x.csv', download: '' }));
  doc.inside.add(inDoc);
  inDoc.click();
  Object.assign(new win.HTMLAnchorElement(), fakeAnchor({ href: 'page.html' })).click();
  Object.assign(new win.HTMLAnchorElement(), fakeAnchor({ href: 'https://example.com/x', download: '' })).click();
  const none = setup({ sw: null });
  Object.assign(new none.win.HTMLAnchorElement(), fakeAnchor({ href: 'x.csv', download: '' })).click();
  await flush();
  assert.equal(win.nativeClicks, 3);
  assert.equal(none.win.nativeClicks, 1);
  assert.deepEqual([win.parent.posted, win.fetched], [[], []]);
});

test('frame.js tolerates a window with no HTMLAnchorElement', () => {
  setup({ win: { HTMLAnchorElement: undefined } });
});

// --- signing ---

test('sign from the worker is relayed to the parent at the app origin, with its port', () => {
  const { win, container, controller } = setup();
  const port = { port: true };
  const ev = msg({ cairn: 'sign', purpose: 'revision', bodies: [{ a: 1 }], extra: 1 }, controller, undefined);
  ev.ports = [port];
  container.dispatchEvent(ev);
  assert.deepEqual(win.parent.posted, [[{ cairn: 'sign', purpose: 'revision', bodies: [{ a: 1 }] }, APP]]);
  assert.deepEqual(win.parent.transfers, [[port]]);
});

test('sign is relayed with its own purpose and bodies, and no other message from the worker takes a port', () => {
  const { win, container, controller } = setup();
  const port = { port: true };
  const rec = msg({ cairn: 'sign', purpose: 'record', bodies: [{ a: 1 }, { b: 2 }] }, controller, undefined);
  rec.ports = [port];
  container.dispatchEvent(rec);
  assert.deepEqual(win.parent.posted, [[{ cairn: 'sign', purpose: 'record', bodies: [{ a: 1 }, { b: 2 }] }, APP]]);
  win.parent.posted.length = 0;
  for (const cairn of ['bogus', 'keys', 'token', 'signed', 'download']) {
    const ev = msg({ cairn, purpose: 'revision', bodies: [] }, controller, undefined);
    ev.ports = [{}];
    container.dispatchEvent(ev);
  }
  assert.deepEqual(win.parent.posted, []);
});

test('sign with no port, or from another source, is not relayed', () => {
  const { win, container, controller } = setup();
  container.dispatchEvent(msg({ cairn: 'sign', purpose: 'revision', bodies: [] }, controller, undefined));
  const empty = msg({ cairn: 'sign', purpose: 'revision', bodies: [] }, controller, undefined);
  empty.ports = [];
  container.dispatchEvent(empty);
  const other = msg({ cairn: 'sign', purpose: 'revision', bodies: [] }, { other: true }, undefined);
  other.ports = [{}];
  container.dispatchEvent(other);
  assert.deepEqual(win.parent.posted, []);
});

test('sign from the shell side is not passed to the worker', () => {
  const { win, controller } = setup();
  win.dispatchEvent(msg({ cairn: 'sign', purpose: 'revision', bodies: [] }, win.parent, APP));
  win.dispatchEvent(msg({ cairn: 'download', name: 'a', bytes: new ArrayBuffer(1) }, win.parent, APP));
  assert.deepEqual(controller.posted, []);
});
