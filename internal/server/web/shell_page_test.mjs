// Tests for shell.mjs against a fake document and window, over the fake
// server of viewer_fixture.mjs: what it shows, when it frames, which messages
// it acts on, and where it sends keys. The logic is tested in viewer_test.mjs.
// Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { checkKeysMessage } from './content.mjs';
import {
  ARTIFACT, ORIGIN, V1, V2, buildWorld, fakeKeyStore, fakeStorage, keyStoreRecord, makeServer, makeUser, makeVersion,
  vouchFor,
} from './viewer_fixture.mjs';
import { UNTRUSTED_MESSAGE } from './viewer.mjs';
import { REVEAL_MS, SCROLL_WAIT_MS, WATCH_MS, downloadName, revealGate, run, viewKey, watchVersions } from './shell.mjs';
import { ApiError } from './account.mjs';
import { metaItem } from './sharing_fixture.mjs';

const CONTENT = `http://${ARTIFACT}.localhost:8080`;
const U = {};
for (const name of ['owner', 'editor', 'viewer', 'outsider']) U[name] = await makeUser(name);

// A fake element records what the page does to it. Assigning innerHTML or
// outerHTML is what Trusted Types forbids, so it is recorded as a violation.
function fakeDom(dataset) {
  const violations = [];
  const make = (tag) => {
    const el = {
      tag,
      children: [],
      attrs: {},
      listeners: {},
      textContent: '',
      appendChild(c) {
        this.children.push(c);
        c.parent = this;
        return c;
      },
      replaceChildren(...c) {
        this.children = c;
      },
      setAttribute(k, v) {
        this.attrs[k] = v;
      },
      addEventListener(type, fn) {
        this.listeners[type] = fn;
      },
      click() {
        this.clicked = (this.clicked ?? 0) + 1;
      },
      focus() {
        this.focused = (this.focused ?? 0) + 1;
      },
      remove() {
        this.removed = true;
        // A frame leaves the page, so a test can see which frames are shown;
        // a download's anchor stays listed, for its test to read back.
        if (tag === 'iframe') this.parent.children = this.parent.children.filter((c) => c !== this);
      },
    };
    for (const sink of ['innerHTML', 'outerHTML']) {
      Object.defineProperty(el, sink, {
        set: (v) => {
          violations.push(`${tag}.${sink}=${v}`);
        },
      });
    }
    if (tag === 'iframe') {
      el.contentWindow = { posted: [], postMessage(m, origin) { this.posted.push([m, origin]); } };
    }
    return el;
  };
  const els = {};
  for (const id of ['name', 'desc', 'version', 'fullscreen', 'account', 'status', 'frame-host']) els[id] = make(id);
  els.status.hidden = true;
  const body = make('body');
  body.dataset = dataset;
  return {
    violations,
    els,
    document: {
      title: '',
      visibilityState: 'visible',
      listeners: {},
      addEventListener(type, fn) {
        this.listeners[type] = fn;
      },
      body,
      getElementById: (id) => els[id],
      createElement: make,
      write: () => violations.push('document.write'),
    },
  };
}

// page builds a shell page for who (or nobody) and runs it.
async function page({ who = null, mode = 'shared', version = '', path = '/', isPublic = false, hash = '', members, build, noRun, record, worldOpts = {} } = {}) {
  const world = await buildWorld({
    owner: U.owner,
    members: members ?? [{ user: U.editor, role: 'editor' }, { user: U.viewer, role: 'viewer' }],
    isPublic,
    ...worldOpts,
  });
  const server = makeServer(world, { who: who && U[who], linkTokenB64: '*' });
  for (const [vid, seq, signer] of [[V1, 1, U.owner], [V2, 2, U.owner]]) {
    server.versions.set(vid, await makeVersion(world, vid, { signer: { user: signer.id, seed: signer.ed.seed }, seq }));
  }
  // The server holds the name and description sealed, as it does for real.
  server.artifact = {
    id: ARTIFACT,
    meta: {
      name: await metaItem({ world }, { field: 'name', value: 'Guestbook' }),
      description: await metaItem({ world }, { field: 'description', value: 'Sign here' }),
    },
  };
  await build?.({ world, server });
  const dom = fakeDom({ artifact: ARTIFACT, version, path, mode, contentOrigin: CONTENT });
  const handlers = {};
  const timers = [];
  const assigned = [];
  const replaced = [];
  const reloaded = [];
  const window = {
    location: { origin: ORIGIN, pathname: `/shared/${ARTIFACT}`, search: '', hash, assign: (p) => assigned.push(p), replace: (p) => reloaded.push(p) },
    history: { replaceState: (...a) => replaced.push(a) },
    fetch: server.fetch,
    localStorage: fakeStorage(),
    sessionStorage: fakeStorage(),
    addEventListener: (type, fn) => {
      handlers[type] = fn;
    },
    setTimeout: (fn, ms) => {
      timers.push({ fn, ms });
      return timers.length;
    },
    clearTimeout: () => {},
    Blob,
    URL: {
      created: [],
      revoked: [],
      createObjectURL(blob) {
        this.created.push(blob);
        return `blob:${ORIGIN}/${this.created.length}`;
      },
      revokeObjectURL(url) {
        this.revoked.push(url);
      },
    },
  };
  const keyStore = fakeKeyStore(record !== undefined ? record : who ? await keyStoreRecord(U[who]) : null);
  const p = { world, server, dom, window, handlers, timers, assigned, replaced, reloaded, keyStore };
  p.frame = () => dom.els['frame-host'].children[0];
  p.frames = () => dom.els['frame-host'].children;
  p.status = () => dom.els.status;
  p.start = () => run(window, dom.document, keyStore);
  if (!noRun) await p.start();
  // post delivers a message to the shell as the frame, or as source/origin say.
  p.post = async (data, { source = p.frame()?.contentWindow, origin = CONTENT, ports = [] } = {}) => {
    handlers.message({ data, source, origin, ports });
    await settle();
  };
  p.posted = () => p.frame().contentWindow.posted;
  // waitPosted waits until n messages have gone to the frame: settle is a
  // fixed wait, which a busy machine outlasts, so a test that reads a message
  // waits for it, not for the clock.
  p.waitPosted = async (n = 1) => {
    for (let i = 0; i < 2000 && p.posted().length < n; i++) await new Promise((r) => setTimeout(r, 5));
    return p.posted();
  };
  p.firstPosted = async () => (await p.waitPosted())[0];
  return p;
}

// settle lets the shell's async answers finish.
const settle = () => new Promise((r) => setTimeout(r, 30));

test('a member sees the artifact, and the frame holds the boot page, sandboxed', async () => {
  const p = await page({ who: 'viewer' });
  assert.equal(p.status().hidden, true);
  assert.equal(p.dom.els.name.textContent, 'Guestbook');
  assert.equal(p.dom.els.desc.textContent, 'Sign here');
  assert.equal(p.dom.document.title, 'Guestbook');
  assert.deepEqual(p.dom.els.version.children.map((o) => [o.value, o.textContent, o.selected]), [[V2, '#2', true], [V1, '#1', false]]);
  assert.equal(p.dom.els.fullscreen.href, `/full/${ARTIFACT}/${V2}`);
  const f = p.frame();
  assert.equal(f.tag, 'iframe');
  assert.deepEqual(f.attrs, {
    src: `${CONTENT}/_cairn/boot`,
    title: 'Guestbook',
    sandbox: 'allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-downloads',
  });
  assert.equal(p.dom.els['frame-host'].children.length, 1);
  assert.deepEqual(p.dom.violations, []);
});

test('the frame stays hidden until its first load after the keys were sent, and is never hidden again', async () => {
  const p = await page({ who: 'viewer' });
  const f = p.frame();
  assert.equal(f.className, 'pending', 'hidden from the start');
  // The boot page loads before the shell has answered: still hidden.
  f.listeners.load();
  assert.equal(f.className, 'pending');
  await p.post({ cairn: 'ready', version: null, path: null });
  await p.waitPosted();
  assert.equal(f.className, 'pending', 'the keys alone do not show it');
  f.listeners.load();
  assert.equal(f.className, '');
  // A later load, or a version switch, leaves it shown.
  await p.post({ cairn: 'need-keys', version: V1 });
  f.listeners.load();
  assert.equal(f.className, '');
});

test('the frame is shown after a few seconds even when no keys were asked for', async () => {
  const p = await page({ who: 'viewer' });
  assert.equal(p.frame().className, 'pending');
  const timer = p.timers.find((t) => t.ms === REVEAL_MS);
  assert.ok(timer, 'a timer was set');
  timer.fn();
  assert.equal(p.frame().className, '');
});

test('revealGate shows once: on the first load after an answer, or on the timeout', () => {
  const run = () => {
    const shown = [];
    return { shown, gate: revealGate(() => shown.push('show')) };
  };
  let t = run();
  t.gate.loaded();
  t.gate.loaded();
  assert.deepEqual(t.shown, [], 'a load with no answer shows nothing');
  t.gate.answered();
  assert.deepEqual(t.shown, [], 'an answer alone shows nothing');
  t.gate.loaded();
  t.gate.loaded();
  t.gate.timeout();
  assert.deepEqual(t.shown, ['show']);
  t = run();
  t.gate.timeout();
  t.gate.answered();
  t.gate.loaded();
  assert.deepEqual(t.shown, ['show'], 'the timeout shows it, and nothing shows it twice');
});

test('the name, description, and version names come from the sealed fields, never from plaintext the server adds', async () => {
  const p = await page({
    who: 'viewer',
    build: async ({ world, server }) => {
      Object.assign(server.artifact, { name: 'Server name', description: 'Server description' });
      Object.assign(server.versions.get(V2).json, {
        name: 'server-v2',
        meta: {
          name: await metaItem({ world }, { version: V2, field: 'name', value: 'Release' }),
          changelog: await metaItem({ world }, { version: V2, field: 'changelog', value: 'Fixed the list' }),
        },
      });
      Object.assign(server.versions.get(V1).json, { name: 'server-v1', changelog: 'server-changelog' });
    },
  });
  assert.equal(p.dom.els.name.textContent, 'Guestbook');
  assert.equal(p.dom.els.desc.textContent, 'Sign here');
  assert.deepEqual(p.dom.els.version.children.map((o) => o.textContent), ['#2 Release', '#1']);
  assert.equal(p.frame().attrs.title, 'Guestbook');
  await p.post({ cairn: 'ready', version: null, path: null });
  const created = (v) => p.server.versions.get(v).json.createdAt;
  assert.deepEqual((await p.firstPosted())[0].context.versions, [
    { id: V2, seq: 2, name: 'Release', changelog: 'Fixed the list', createdAt: created(V2) },
    { id: V1, seq: 1, name: '', changelog: '', createdAt: created(V1) },
  ]);
});

test('a name that fails its checks, or that nobody wrote, shows the artifact ID', async () => {
  for (const name of [async (world) => metaItem({ world }, { field: 'name', value: 'Forged', signer: U.viewer }), null]) {
    const p = await page({
      who: 'viewer',
      build: async ({ world, server }) => {
        if (name) server.artifact.meta.name = await name(world); else delete server.artifact.meta.name;
        server.versions.get(V2).json.meta = { name: await metaItem({ world }, { version: V2, field: 'name', value: 'Forged', signer: U.viewer }) };
      },
    });
    assert.equal(p.status().hidden, true);
    assert.equal(p.dom.els.name.textContent, ARTIFACT);
    assert.equal(p.dom.document.title, ARTIFACT);
    assert.equal(p.frame().attrs.title, ARTIFACT);
    assert.equal(p.dom.els.desc.textContent, 'Sign here');
    assert.deepEqual(p.dom.els.version.children.map((o) => o.textContent), ['#2', '#1']);
  }
});

test('the page version is the one framed and shown, and the fullscreen link names it', async () => {
  const p = await page({ who: 'viewer', version: V1 });
  assert.equal(p.dom.els.fullscreen.href, `/full/${ARTIFACT}/${V1}`);
  assert.deepEqual(p.dom.els.version.children.map((o) => o.selected), [false, true]);
  await p.post({ cairn: 'ready', version: null, path: null });
  assert.equal((await p.firstPosted())[0].version, V1);
});

test('changing the picker goes to that version', async () => {
  const p = await page({ who: 'viewer' });
  p.dom.els.version.value = V1;
  p.dom.els.version.listeners.change();
  assert.deepEqual(p.assigned, [`/shared/${ARTIFACT}/${V1}`]);
});

test('ready with no version answers with the page version and path, to the content origin only', async () => {
  const p = await page({ who: 'editor', path: '/app/x%20y', version: V1 });
  await p.post({ cairn: 'ready', version: null, path: null });
  await p.waitPosted();
  assert.equal(p.posted().length, 1);
  const [msg, origin] = await p.firstPosted();
  assert.equal(origin, CONTENT);
  checkKeysMessage(msg);
  assert.equal(msg.version, V1);
  assert.equal(msg.path, '/app/x%20y');
  assert.equal(msg.ak, e2e.b64(p.world.aks[1]));
  assert.match(msg.token, /^tok-/, 'the content token is minted before the first keys');
  assert.equal(msg.tokenExpires, 2000000000);
  assert.equal(msg.context.artifact.name, 'Guestbook');
  assert.equal(msg.signer.user, U.owner.id);
});

test('ready for a version verifies it and uses the message path', async () => {
  const p = await page({ who: 'viewer', version: V1 });
  p.server.calls.length = 0;
  await p.post({ cairn: 'ready', version: V2, path: '/deep/page.html' });
  const [msg] = await p.firstPosted();
  assert.equal(msg.version, V2);
  assert.equal(msg.path, '/deep/page.html');
  assert.ok(p.server.calls.some((c) => c.path === `/api/artifacts/${ARTIFACT}/versions/${V2}/manifest`), 'verified first');
});

test('need-keys answers for the named version with path /', async () => {
  const p = await page({ who: 'viewer', path: '/x' });
  await p.post({ cairn: 'need-keys', version: V1 });
  const [msg] = await p.firstPosted();
  assert.equal(msg.version, V1);
  assert.equal(msg.path, '/');
});

test('no message is ever posted to a wildcard origin', async () => {
  const p = await page({ who: 'viewer' });
  await p.post({ cairn: 'ready', version: null, path: null });
  await p.post({ cairn: 'need-keys', version: V1 });
  p.timers[0].fn();
  await settle();
  assert.ok((await p.waitPosted(3)).length >= 3);
  for (const [, origin] of p.posted()) assert.equal(origin, CONTENT);
});

test('a message from another window, or another origin, is ignored', async () => {
  const p = await page({ who: 'viewer' });
  p.server.calls.length = 0;
  const msgs = [
    { cairn: 'ready', version: null, path: null },
    { cairn: 'need-keys', version: V1 },
    { cairn: 'navigate', href: `/shared/${ARTIFACT}` },
    { cairn: 'login' },
  ];
  for (const m of msgs) {
    await p.post(m, { source: { postMessage() {} } });
    await p.post(m, { source: null });
    await p.post(m, { origin: 'http://evil.localhost:8080' });
    await p.post(m, { origin: ORIGIN });
    await p.post(m, { origin: CONTENT.replace('http:', 'https:') });
  }
  assert.deepEqual(p.posted(), []);
  assert.deepEqual(p.assigned, []);
  assert.deepEqual(p.server.calls, []);
});

test('a message that is not an object, or names nothing, is ignored', async () => {
  const p = await page({ who: 'viewer' });
  for (const m of [null, 'ready', 7, {}, { cairn: 'keys' }, { cairn: 'other', version: V1 }]) await p.post(m);
  assert.deepEqual(p.posted(), []);
});

test('ready and need-keys for a version that is not a lowercase UUID are ignored', async () => {
  const p = await page({ who: 'viewer' });
  p.server.calls.length = 0;
  for (const version of ['../x', 'abcdef01-abcd-4bcd-8bcd-abcdef012345'.toUpperCase(), 7, undefined, {}, '']) {
    await p.post({ cairn: 'ready', version, path: '/' });
    await p.post({ cairn: 'need-keys', version });
  }
  assert.deepEqual(p.posted(), []);
  assert.deepEqual(p.server.calls, []);
  assert.equal(p.status().hidden, true);
});

test('ready with a path that does not start with a slash, or leaves the version, is ignored', async () => {
  const p = await page({ who: 'viewer' });
  for (const path of ['x', '', null, 7, '/%2e%2e/api/x', '/.\t./api/x']) await p.post({ cairn: 'ready', version: V1, path });
  assert.deepEqual(p.posted(), []);
});

test('a page path that leaves the version gets no keys', async () => {
  const p = await page({ who: 'viewer', version: V1, path: `/%2e%2e/api/artifacts/${ARTIFACT}/versions/${V1}/files/x.html` });
  await p.post({ cairn: 'ready', version: null, path: null });
  assert.deepEqual(p.posted(), []);
});

test('an owner whose wrap of a manager\'s epoch is bad still sees the artifact, and is told that epoch is unreadable', async () => {
  const p = await page({
    who: 'owner',
    members: [{ user: U.editor, role: 'manager' }, { user: U.viewer, role: 'viewer' }],
    worldOpts: { epoch2By: U.editor },
    build: async ({ world }) => {
      const good = await e2e.wrap({ purpose: 'ak', artifact: ARTIFACT, epoch: 2, recipientId: U.owner.id, recipientPub: U.owner.x.pub }, world.aks[2]);
      world.wraps[U.owner.id] = [{ epoch: 2, wrapped: e2e.b64(new Uint8Array(good.length)), fp: U.owner.fp }];
    },
  });
  assert.equal(p.dom.els.name.textContent, 'Guestbook');
  assert.equal(p.status().hidden, false);
  assert.equal(p.status().textContent, 'Your key for epoch 2 could not be read, so what was sealed under it will not open. Remove the manager who started it to start a new epoch.');
});

// A page for an owner whose wraps of the epochs a manager started, bad, do not
// open: epochs lists the epochs from 2 on, and bad those with a bad wrap.
async function badWrapsPage(epochs, bad) {
  return page({
    who: 'owner',
    members: [{ user: U.editor, role: 'manager' }, { user: U.viewer, role: 'viewer' }],
    worldOpts: { laterEpochs: epochs.map((by) => (by ? { by: U.editor } : {})) },
    build: async ({ world }) => {
      world.wraps[U.owner.id] = world.wraps[U.owner.id].map((w) => (bad.includes(w.epoch) ? { ...w, wrapped: e2e.b64(crypto.getRandomValues(new Uint8Array(w.wrapped.length))) } : w));
    },
  });
}

test('an owner told of two or three unreadable epochs gets them all in one sentence, and still opens the good one', async () => {
  const two = await badWrapsPage([true, false, true], [2, 4]);
  assert.equal(two.dom.els.name.textContent, 'Guestbook');
  assert.equal(two.status().textContent, 'Your keys for epochs 2 and 4 could not be read, so what was sealed under them will not open. Remove the managers who started them to start a new epoch.');
  const three = await badWrapsPage([true, false, true, false, true], [2, 4, 6]);
  assert.equal(three.status().textContent, 'Your keys for epochs 2, 4, and 6 could not be read, so what was sealed under them will not open. Remove the managers who started them to start a new epoch.');
});

test('a version the frame names that is not this artifact\'s gets no keys, and shows nothing', async () => {
  const p = await page({ who: 'viewer' });
  await p.post({ cairn: 'need-keys', version: '66666666-6666-4666-8666-666666666667' });
  await p.post({ cairn: 'ready', version: '66666666-6666-4666-8666-666666666667', path: '/' });
  assert.deepEqual(p.posted(), []);
  assert.equal(p.status().hidden, true, p.status().textContent);
});

test('a page version the server does not have is not framed, and says it was not found', async () => {
  const p = await page({ who: 'viewer', version: '66666666-6666-4666-8666-666666666667' });
  assert.equal(p.frame(), undefined);
  assert.equal(p.status().textContent, 'This version could not be found. It may have been deleted.');
});

test('a version that is not trusted gets no keys, and the person is told', async () => {
  const p = await page({ who: 'viewer' });
  const bad = await makeVersion(p.world, '88888888-8888-4888-8888-888888888888', { signer: { user: U.outsider.id, seed: U.outsider.ed.seed }, seq: 3 });
  p.server.versions.set(bad.json.id, bad);
  await p.post({ cairn: 'need-keys', version: bad.json.id });
  assert.deepEqual(p.posted(), []);
  assert.equal(p.status().hidden, false);
  assert.equal(p.status().textContent, UNTRUSTED_MESSAGE);
});

test('a page version that is not trusted is never framed, and says why in the contract\'s words', async () => {
  const p = await page({
    who: 'viewer',
    version: V1,
    build: async ({ world, server }) => {
      server.versions.set(V1, await makeVersion(world, V1, { signer: { user: U.viewer.id, seed: U.viewer.ed.seed } }));
    },
  });
  assert.equal(p.frame(), undefined);
  assert.equal(p.status().hidden, false);
  assert.equal(p.status().textContent, 'This version was pushed by someone who is no longer an editor, and the owner has not reviewed it.');
});

test('the same version is framed once the owner has vouched for it', async () => {
  const p = await page({
    who: 'viewer',
    version: V1,
    build: async ({ world, server }) => {
      const v = await makeVersion(world, V1, { signer: { user: U.viewer.id, seed: U.viewer.ed.seed } });
      v.json.vouch = await vouchFor(U.owner, V1, v.manifestHash);
      server.versions.set(V1, v);
    },
  });
  assert.equal(p.status().hidden, true);
  await p.post({ cairn: 'ready', version: null, path: null });
  assert.equal((await p.firstPosted())[0].signer, null);
});

test('nothing is framed after a failure, and each failure is shown', async () => {
  const noAccess = await page({ isPublic: true });
  assert.equal(noAccess.frame(), undefined);
  assert.equal(noAccess.status().hidden, false);
  assert.match(noAccess.status().textContent, /Sign in.*full public link/);

  const broken = await page({
    who: 'viewer',
    build: ({ server }) => {
      const base = server.fetch;
      server.fetch = async (path, init) => (path.endsWith('/membership') ? new Response('not json', { status: 200 }) : base(path, init));
    },
  });
  assert.equal(broken.frame(), undefined);
  assert.equal(broken.status().hidden, false);
  assert.match(broken.status().textContent, /could not be verified/);

  const ended = await page({
    who: 'viewer',
    build: ({ server }) => {
      const base = server.fetch;
      server.fetch = async (path, init) => (path === '/api/me' ? new Response('{}', { status: 500 }) : base(path, init));
    },
  });
  assert.equal(ended.frame(), undefined);
  assert.equal(ended.status().hidden, false);
  assert.match(ended.status().textContent, /^This artifact could not be verified, so it is not shown\. /);

  const signedOut = await page({
    who: 'viewer',
    build: ({ server }) => {
      const base = server.fetch;
      server.fetch = async (path, init) => (path === `/api/artifacts/${ARTIFACT}` ? new Response('{}', { status: 401 }) : base(path, init));
    },
  });
  assert.equal(signedOut.frame(), undefined);
  assert.equal(signedOut.status().textContent, 'Your session has ended. Sign in again.');
});

test('a session whose keys this browser does not hold goes to sign in, and back, with nothing framed or asked', async () => {
  for (const record of [null, await keyStoreRecord(U.editor)]) {
    const p = await page({ who: 'viewer', record, mode: 'full', noRun: true });
    p.window.location.pathname = `/full/${ARTIFACT}/${V1}`;
    await p.start();
    assert.equal(p.frame(), undefined);
    assert.deepEqual(p.assigned, [`/login?next=${encodeURIComponent(`/full/${ARTIFACT}/${V1}`)}`]);
    assert.equal(p.status().hidden, true, p.status().textContent);
  }
});

test('an artifact with no versions says so and is not framed', async () => {
  const p = await page({ who: 'viewer', build: ({ server }) => server.versions.clear() });
  assert.equal(p.frame(), undefined);
  assert.match(p.status().textContent, /no versions/);
});

test('a folder says so, links to the Artifacts tab, and asks for no versions', async () => {
  const p = await page({
    who: 'owner',
    build: async ({ world, server }) => {
      server.artifact = { id: ARTIFACT, kind: 'folder', parent: null, meta: { name: await metaItem({ world }, { field: 'name', value: 'Plans' }) } };
    },
  });
  assert.equal(p.frame(), undefined);
  assert.equal(p.dom.els.name.textContent, 'Plans');
  assert.equal(p.status().hidden, false);
  assert.match(p.status().textContent, /folder/);
  const [link] = p.status().children;
  assert.equal(link.tag, 'a');
  assert.equal(link.href, '/app');
  assert.match(link.textContent, /Artifacts tab/);
  assert.equal(p.server.calls.some((c) => c.path.includes('/versions')), false);
  assert.deepEqual(p.dom.violations, []);
});

test('a visitor with a public link opens it, and the link leaves the address bar first', async () => {
  const p = await page({ isPublic: true, members: [], noRun: true });
  p.window.location.hash = `#k=${e2e.b64(p.world.aks[1])}&e=1&o=${U.owner.fp}`;
  await p.start();
  assert.deepEqual(p.replaced, [[null, '', `/shared/${ARTIFACT}`]]);
  assert.equal(p.status().hidden, true, p.status().textContent);
  await p.post({ cairn: 'ready', version: null, path: null });
  const [msg] = await p.firstPosted();
  checkKeysMessage(msg);
  assert.equal(msg.token, null);
  assert.deepEqual(msg.context.users, []);
  assert.equal(msg.linkToken, e2e.b64(await e2e.linkToken(p.world.aks[1], ARTIFACT, 1)));
});

test('a visitor with a public link keeps it when changing version or going full screen', async () => {
  const p = await page({ isPublic: true, members: [], noRun: true });
  const hash = `#k=${e2e.b64(p.world.aks[1])}&e=1&o=${U.owner.fp}`;
  p.window.location.hash = hash;
  await p.start();
  assert.equal(p.dom.els.fullscreen.href, `/full/${ARTIFACT}/${V2}${hash}`);
  p.dom.els.version.value = V1;
  p.dom.els.version.listeners.change();
  assert.deepEqual(p.assigned, [`/shared/${ARTIFACT}/${V1}${hash}`]);
});

test('a member who follows a public link opens as a member, and the key is not carried on', async () => {
  const p = await page({ who: 'viewer', isPublic: true, noRun: true });
  p.window.location.hash = `#k=${e2e.b64(p.world.aks[1])}&e=1&o=${U.owner.fp}`;
  await p.start();
  assert.ok(p.frame());
  assert.equal(p.dom.els.fullscreen.href, `/full/${ARTIFACT}/${V2}`);
  p.dom.els.version.value = V1;
  p.dom.els.version.listeners.change();
  assert.deepEqual(p.assigned, [`/shared/${ARTIFACT}/${V1}`]);
});

test('a member\'s page anchor is not carried to another version', async () => {
  const p = await page({ who: 'viewer', hash: '#section' });
  assert.equal(p.dom.els.fullscreen.href, `/full/${ARTIFACT}/${V2}`);
  p.dom.els.version.value = V1;
  p.dom.els.version.listeners.change();
  assert.deepEqual(p.assigned, [`/shared/${ARTIFACT}/${V1}`]);
});

test('a malformed fragment is removed, and the error is shown', async () => {
  const p = await page({ isPublic: true, hash: '#k=nonsense' });
  assert.deepEqual(p.replaced, [[null, '', `/shared/${ARTIFACT}`]]);
  assert.equal(p.frame(), undefined);
  assert.equal(p.status().hidden, false);
  assert.match(p.status().textContent, /^This link is incomplete or damaged\./);
});

test('a member who opens a page with a fragment that is not a link sees the artifact', async () => {
  const p = await page({ who: 'viewer', hash: '#section' });
  assert.deepEqual(p.replaced, [[null, '', `/shared/${ARTIFACT}`]]);
  assert.ok(p.frame());
  assert.equal(p.status().hidden, true, p.status().textContent);
});

test('navigate goes to a shared page of one or two ids, and to full in full mode', async () => {
  const B = 'fedcba98-fedc-4bad-8bad-fedcba987654';
  const p = await page({ who: 'viewer' });
  await p.post({ cairn: 'navigate', href: `/shared/${B}` });
  await p.post({ cairn: 'navigate', href: `${ORIGIN}/shared/${B}/${V1}?q=1#f` });
  assert.deepEqual(p.assigned, [`/shared/${B}`, `/shared/${B}/${V1}`]);
  const full = await page({ who: 'viewer', mode: 'full' });
  await full.post({ cairn: 'navigate', href: `/shared/${B}` });
  assert.deepEqual(full.assigned, [`/full/${B}`]);
});

test('navigate ignores everything else', async () => {
  const p = await page({ who: 'viewer' });
  const asString = { toString: () => `/shared/${V1}` };
  for (const href of ['javascript:alert(1)', '//evil.example', '/\\evil.example', '/admin', '/shared/not-a-uuid', 'https://evil.example/', asString, null, 7, undefined]) {
    await p.post({ cairn: 'navigate', href });
  }
  assert.deepEqual(p.assigned, []);
});

test('login goes to sign in and back to this page, carrying a public link but not a member\'s anchor', async () => {
  const p = await page({ isPublic: true, members: [], noRun: true });
  const hash = `#k=${e2e.b64(p.world.aks[1])}&e=1&o=${U.owner.fp}`;
  p.window.location.hash = hash;
  await p.start();
  await p.post({ cairn: 'login' });
  assert.deepEqual(p.assigned, [`/login?next=${encodeURIComponent(`/shared/${ARTIFACT}`)}${hash}`]);

  const member = await page({ who: 'viewer', mode: 'full', hash: '#section', noRun: true });
  member.window.location.pathname = `/full/${ARTIFACT}/${V1}`;
  await member.start();
  await member.post({ cairn: 'login' });
  assert.deepEqual(member.assigned, [`/login?next=${encodeURIComponent(`/full/${ARTIFACT}/${V1}`)}`]);

  const pinned = await page({ isPublic: true, members: [], noRun: true });
  const pinnedHash = `#k=${e2e.b64(pinned.world.aks[1])}&e=1&o=${U.owner.fp}`;
  pinned.window.location.pathname = `/shared/${ARTIFACT}/${V1}`;
  pinned.window.location.hash = pinnedHash;
  await pinned.start();
  await pinned.post({ cairn: 'login' });
  assert.deepEqual(pinned.assigned, [`/login?next=${encodeURIComponent(`/shared/${ARTIFACT}/${V1}`)}${pinnedHash}`]);
});

test('the content token is renewed and posted to the frame', async () => {
  const p = await page({ who: 'viewer' });
  const renewal = (t) => t.ms !== REVEAL_MS && t.ms !== WATCH_MS;
  assert.equal(p.timers.filter(renewal).length, 1);
  p.timers.find(renewal).fn();
  await settle();
  const [msg, origin] = (await p.waitPosted()).at(-1);
  assert.equal(origin, CONTENT);
  assert.equal(msg.cairn, 'token');
  assert.match(msg.token, /^tok-/);
  assert.equal(msg.tokenExpires, 2000000000);
  // Later keys carry the newest token.
  const before = p.posted().length;
  await p.post({ cairn: 'need-keys', version: V1 });
  assert.equal((await p.waitPosted(before + 1)).at(-1)[0].token, msg.token);
});

test('a failed renewal is shown', async () => {
  const p = await page({ who: 'viewer' });
  const base = p.server.fetch;
  p.window.fetch = async (path, init) => (init?.method === 'POST' ? new Response('{}', { status: 401 }) : base(path, init));
  p.timers[0].fn();
  await settle();
  assert.equal(p.status().hidden, false);
  assert.equal(p.status().textContent, 'Your access could not be renewed. Reload the page, or sign in again.');
});

test('the shell never assigns innerHTML or writes the document', async () => {
  const p = await page({ who: 'viewer' });
  await p.post({ cairn: 'ready', version: null, path: null });
  assert.deepEqual(p.dom.violations, []);
});

test('a version id the server lists that is not a UUID is left out of the picker', async () => {
  const p = await page({
    who: 'viewer',
    build: ({ server }) => {
      server.versions.set('bad', { json: { id: '../evil', seq: 9, epoch: 1, name: '', manifestHash: '0'.repeat(64), vouch: null }, blob: new Uint8Array(0) });
    },
  });
  assert.equal(p.status().hidden, true, p.status().textContent);
  assert.deepEqual(p.dom.els.version.children.map((o) => o.value), [V2, V1]);
  assert.equal(p.dom.els.fullscreen.href, `/full/${ARTIFACT}/${V2}`);
});

// port is the shell's end of a MessageChannel, recording what it is sent.
function port() {
  return { sent: [], postMessage(m) { this.sent.push(m); } };
}

const signReq = (p, over = {}) => ({
  cairn: 'sign',
  purpose: 'revision',
  bodies: [{ artifact: ARTIFACT, version: V1, revision: 1, epoch: p.world.top, sha256: 'a'.repeat(64) }],
  ...over,
});

test('keys carry the writers: the owner and each editor under their listed key', async () => {
  const p = await page({ who: 'viewer', version: V1 });
  await p.post({ cairn: 'ready', version: null, path: null });
  const [msg] = await p.firstPosted();
  checkKeysMessage(msg);
  assert.deepEqual(msg.writers, { [U.owner.id]: [e2e.b64(U.owner.ed.pub)], [U.editor.id]: [e2e.b64(U.editor.ed.pub)] });
  assert.equal(msg.publicWrites, false);
  assert.equal(msg.currentEpoch, p.world.top);
});

test('sign: an editor gets the bodies signed under their key, on the port the frame sent', async () => {
  const p = await page({ who: 'editor' });
  const reply = port();
  await p.post(signReq(p), { ports: [reply] });
  assert.equal(reply.sent.length, 1);
  assert.equal(reply.sent[0].cairn, 'signed');
  const [env] = reply.sent[0].envelopes;
  assert.equal(env.signer, U.editor.id);
  const body = await e2e.openEnvelope(env, U.editor.ed.pub, 'revision');
  assert.equal(body.version, V1);
  assert.deepEqual(p.posted(), [], 'nothing goes to the frame window itself');
});

test('sign: a viewer, or a body the shell will not sign, gets a sign-error', async () => {
  const viewer = await page({ who: 'viewer' });
  const r1 = port();
  await viewer.post(signReq(viewer), { ports: [r1] });
  assert.equal(r1.sent.length, 1);
  assert.equal(r1.sent[0].cairn, 'sign-error');
  assert.match(r1.sent[0].error, /cannot change/);
  const editor = await page({ who: 'editor' });
  const r2 = port();
  await editor.post(signReq(editor, { purpose: 'manifest' }), { ports: [r2] });
  assert.deepEqual(r2.sent, [{ cairn: 'sign-error', error: 'unknown purpose' }]);
});

test('sign: a request with no port, or from another window or origin, is not answered', async () => {
  const p = await page({ who: 'editor' });
  await p.post(signReq(p));
  const r = port();
  await p.post(signReq(p), { ports: [r], source: { postMessage() {} } });
  await p.post(signReq(p), { ports: [r], origin: ORIGIN });
  assert.deepEqual(r.sent, []);
  assert.deepEqual(p.posted(), []);
});

test('download: the bytes are saved as an octet-stream file under the name asked for', async () => {
  const p = await page({ who: 'viewer' });
  const bytes = new TextEncoder().encode('SQLite format 3');
  await p.post({ cairn: 'download', name: 'database.db', bytes: bytes.buffer });
  const [blob] = p.window.URL.created;
  assert.equal(blob.type, 'application/octet-stream');
  assert.equal(await blob.text(), 'SQLite format 3');
  const a = p.dom.document.body.children[0];
  assert.equal(a.tag, 'a');
  assert.equal(a.href, `blob:${ORIGIN}/1`);
  assert.equal(a.download, 'database.db');
  assert.equal(a.clicked, 1);
  assert.equal(a.removed, true);
  assert.deepEqual(p.window.URL.revoked, [], 'not revoked before the browser reads it');
  const timer = p.timers.find((t) => t.ms === 60000);
  timer.fn();
  assert.deepEqual(p.window.URL.revoked, [`blob:${ORIGIN}/1`]);
  await p.post({ cairn: 'download', name: 'x.bin', bytes: new Uint8Array([1, 2]) });
  assert.equal(p.window.URL.created.length, 2, 'a typed array is accepted too');
  await p.post({ cairn: 'download', name: '../../etc/my file.bin', bytes: new Uint8Array([3]) });
  assert.equal(p.dom.document.body.children[2].download, 'my file.bin', 'a path is cut to its last segment');
});

test('download: anything that is not bytes, or not from the frame, saves nothing', async () => {
  const p = await page({ who: 'viewer' });
  for (const bytes of ['text', null, [1, 2], { length: 2 }]) await p.post({ cairn: 'download', name: 'a', bytes });
  await p.post({ cairn: 'download', name: 'a', bytes: new ArrayBuffer(1) }, { origin: ORIGIN });
  await p.post({ cairn: 'download', name: 'a', bytes: new ArrayBuffer(1) }, { source: { postMessage() {} } });
  assert.deepEqual(p.window.URL.created, []);
  assert.deepEqual(p.dom.document.body.children, []);
});

test('downloadName keeps the last segment, without control characters, or falls back', () => {
  assert.equal(downloadName('database.db'), 'database.db');
  assert.equal(downloadName('a/b/report.csv'), 'report.csv');
  assert.equal(downloadName('a\\b\\report.csv'), 'report.csv');
  assert.equal(downloadName('re\u0000po\u001frt\u007f.txt'), 'report.txt');
  assert.equal(downloadName('  spaced.txt  '), 'spaced.txt');
  assert.equal(downloadName('my report.txt'), 'my report.txt');
  assert.equal(downloadName('x'.repeat(300)).length, 200);
  for (const bad of ['', '/', 'a/', '.', '..', 'a/..', '\u0001', 5, null, undefined]) assert.equal(downloadName(bad), 'download', String(bad));
});

// --- live update ---

const V3 = '33333333-3333-4333-8333-333333333333';
const ver = (id, manifestHash) => ({ id, manifestHash });

test('viewKey names the newest version, or the pinned one, with its manifest hash', () => {
  const versions = [ver(V2, 'h2'), ver(V1, 'h1')];
  assert.equal(viewKey(versions, ''), `${V2}:h2`);
  assert.equal(viewKey(versions, V1), `${V1}:h1`);
  assert.equal(viewKey(versions, V3), '', 'a pinned version that is gone');
  assert.equal(viewKey([], ''), '', 'no versions at all');
});

// watcher runs watchVersions over fakes: answers is what each list() call
// returns, in turn (a function throws instead). tick() runs the pending timer.
function watcher({ versions = [ver(V2, 'h2'), ver(V1, 'h1')], pinned = '', answers = [], visible = true } = {}) {
  const w = { changes: 0, lists: 0, timers: [], gate: null };
  w.document = {
    visibilityState: visible ? 'visible' : 'hidden',
    listeners: {},
    addEventListener(type, fn) {
      this.listeners[type] = fn;
    },
  };
  w.watch = watchVersions({
    versions,
    pinned,
    list: async () => {
      const answer = answers[w.lists++] ?? versions;
      if (w.gate) await w.gate;
      if (typeof answer === 'function') return answer();
      return answer;
    },
    onChange: () => w.changes++,
    document: w.document,
    setTimeout: (fn, ms) => w.timers.push({ fn, ms }),
  });
  w.tick = async () => {
    const t = w.timers.shift();
    assert.equal(t.ms, WATCH_MS);
    await t.fn();
  };
  w.show = async () => {
    w.document.visibilityState = 'visible';
    await w.document.listeners.visibilitychange();
  };
  return w;
}

test('watchVersions polls every few seconds and calls nothing while the versions stay the same', async () => {
  const w = watcher();
  assert.equal(w.timers.length, 1, 'the first poll is scheduled');
  await w.tick();
  await w.tick();
  assert.equal(w.lists, 2);
  assert.equal(w.changes, 0);
  assert.equal(w.timers.length, 1, 'the next poll is scheduled after each one');
});

test('a page that follows the newest version reloads for a new version, and for an overwrite', async () => {
  let w = watcher({ answers: [[ver(V3, 'h3'), ver(V2, 'h2'), ver(V1, 'h1')]] });
  await w.tick();
  assert.equal(w.changes, 1);
  assert.equal(w.timers.length, 0, 'nothing more is polled once it has changed');
  w = watcher({ answers: [[ver(V2, 'h2-new'), ver(V1, 'h1')]] });
  await w.tick();
  assert.equal(w.changes, 1);
});

test('a pinned page ignores a new version, and reloads when its own version is overwritten or deleted', async () => {
  let w = watcher({ pinned: V1, answers: [[ver(V3, 'h3'), ver(V2, 'h2'), ver(V1, 'h1')]] });
  await w.tick();
  assert.equal(w.changes, 0);
  w = watcher({ pinned: V1, answers: [[ver(V2, 'h2'), ver(V1, 'h1-new')]] });
  await w.tick();
  assert.equal(w.changes, 1);
  w = watcher({ pinned: V1, answers: [[ver(V2, 'h2')]] });
  await w.tick();
  assert.equal(w.changes, 1);
});

test('a hidden tab does not poll, and polls at once when it is shown again', async () => {
  const w = watcher({ visible: false, answers: [[ver(V3, 'h3')]] });
  await w.tick();
  assert.equal(w.lists, 0);
  assert.equal(w.timers.length, 1, 'it keeps its schedule while hidden');
  await w.show();
  assert.equal(w.lists, 1);
  assert.equal(w.changes, 1);
  const still = watcher();
  still.document.visibilityState = 'hidden';
  await still.document.listeners.visibilitychange();
  assert.equal(still.lists, 0, 'being hidden polls nothing');
});

test('a failed poll keeps watching, and a 401 stops it', async () => {
  let w = watcher({ answers: [() => { throw new TypeError('network down'); }, [ver(V3, 'h3')]] });
  await w.tick();
  assert.equal(w.changes, 0);
  await w.tick();
  assert.equal(w.changes, 1, 'the poll after the failure still sees the change');
  w = watcher({ answers: [() => { throw new ApiError('session ended', 401); }] });
  await w.tick();
  assert.equal(w.timers.length, 0, 'nothing more is scheduled');
  await w.show();
  assert.equal(w.lists, 1, 'and showing the tab polls nothing');
});

test('a poll does not start while the one before it is still waiting', async () => {
  const w = watcher({ answers: [[ver(V3, 'h3')]] });
  let release;
  w.gate = new Promise((r) => { release = r; });
  const first = w.tick();
  await w.show();
  assert.equal(w.lists, 1, 'the tab being shown did not start a second poll');
  release();
  await first;
  assert.equal(w.changes, 1);
});

test('an update that does not check out reloads the page at its own address, and keeps a public link', async () => {
  const p = await page({ isPublic: true, members: [], noRun: true });
  const hash = `#k=${e2e.b64(p.world.aks[1])}&e=1&o=${U.owner.fp}`;
  p.window.location.hash = hash;
  await p.start();
  await handshake(p, p.frame());
  const watch = p.timers.find((t) => t.ms === WATCH_MS);
  assert.ok(watch, 'the shell watches for updates');
  await watch.fn();
  assert.deepEqual(p.reloaded, [], 'nothing changed yet');
  p.server.versions.get(V2).json.manifestHash = 'overwritten';
  await p.timers.filter((t) => t.ms === WATCH_MS).at(-1).fn();
  assert.deepEqual(p.reloaded, [`/shared/${ARTIFACT}${hash}`]);
});

test('a member\'s reload carries no fragment, and a pinned page ignores a new version', async () => {
  let p = await page({ who: 'viewer', hash: '#section' });
  await handshake(p, p.frame());
  p.server.versions.get(V2).json.manifestHash = 'overwritten';
  await p.timers.find((t) => t.ms === WATCH_MS).fn();
  assert.deepEqual(p.reloaded, [`/shared/${ARTIFACT}`]);
  p = await page({ who: 'viewer', version: V1 });
  await handshake(p, p.frame());
  p.server.versions.get(V2).json.manifestHash = 'overwritten';
  await p.timers.find((t) => t.ms === WATCH_MS).fn();
  assert.deepEqual(p.reloaded, []);
});

test('the reload keeps the reading position, and the next page scrolls back to it before it is shown', async () => {
  const p = await page({ who: 'viewer' });
  await handshake(p, p.frame());
  await p.post({ cairn: 'scroll', y: 300 });
  await p.post({ cairn: 'scroll', y: 1250 });
  p.server.versions.get(V2).json.manifestHash = 'overwritten';
  await p.timers.find((t) => t.ms === WATCH_MS).fn();
  const key = `cairn-scroll:${ARTIFACT}`;
  assert.equal(p.window.sessionStorage.getItem(key), '1250');

  // The reloaded page: same tab, so the same sessionStorage.
  const next = await page({ who: 'viewer', noRun: true });
  next.window.sessionStorage = p.window.sessionStorage;
  await next.start();
  assert.equal(next.window.sessionStorage.getItem(key), null, 'the position is used once');
  const f = next.frame();
  f.listeners.load();
  await next.post({ cairn: 'ready', version: null, path: null });
  await next.waitPosted();
  assert.equal(next.posted().some(([m]) => m.cairn === 'scroll-to'), false, 'not before the version has loaded');
  f.listeners.load();
  assert.deepEqual(next.posted().at(-1), [{ cairn: 'scroll-to', y: 1250 }, CONTENT]);
  assert.equal(f.className, 'pending', 'hidden while it scrolls');
  await next.post({ cairn: 'scrolled' });
  assert.equal(f.className, '');
});

test('a frame the timeout shows is not scrolled: the version never loaded', async () => {
  const p = await page({ who: 'viewer', noRun: true });
  p.window.sessionStorage.setItem(`cairn-scroll:${ARTIFACT}`, '900');
  await p.start();
  p.timers.find((t) => t.ms === REVEAL_MS).fn();
  assert.equal(p.frame().className, '');
  assert.deepEqual(p.posted(), []);
});

test('a frame waiting on its scroll is shown after a few seconds even with no answer', async () => {
  const p = await page({ who: 'viewer', noRun: true });
  p.window.sessionStorage.setItem(`cairn-scroll:${ARTIFACT}`, '900');
  await p.start();
  await handshake(p, p.frame());
  assert.equal(p.frame().className, 'pending');
  p.timers.find((t) => t.ms === SCROLL_WAIT_MS).fn();
  assert.equal(p.frame().className, '');
});

test('with no saved position, showing the frame scrolls nothing', async () => {
  const p = await page({ who: 'viewer' });
  await p.post({ cairn: 'ready', version: null, path: null });
  await p.waitPosted();
  p.frame().listeners.load();
  assert.equal(p.posted().some(([m]) => m.cairn === 'scroll-to'), false);
});

test('a scroll position from another window or origin, or one that is not a position, is not kept', async () => {
  const p = await page({ who: 'viewer' });
  await handshake(p, p.frame());
  await p.post({ cairn: 'scroll', y: 400 });
  await p.post({ cairn: 'scroll', y: 999 }, { source: {} });
  await p.post({ cairn: 'scroll', y: 999 }, { origin: ORIGIN });
  for (const y of [-1, NaN, Infinity, '999', null]) await p.post({ cairn: 'scroll', y });
  p.server.versions.get(V2).json.manifestHash = 'overwritten';
  await p.timers.find((t) => t.ms === WATCH_MS).fn();
  assert.equal(p.window.sessionStorage.getItem(`cairn-scroll:${ARTIFACT}`), '400');
});

test('a page never scrolled saves no position', async () => {
  const p = await page({ who: 'viewer' });
  await handshake(p, p.frame());
  p.server.versions.get(V2).json.manifestHash = 'overwritten';
  await p.timers.find((t) => t.ms === WATCH_MS).fn();
  assert.equal(p.reloaded.length, 1);
  assert.equal(p.window.sessionStorage.getItem(`cairn-scroll:${ARTIFACT}`), null);
});

test('a frame load forgets the position, which belonged to the page before it', async () => {
  const p = await page({ who: 'viewer' });
  await handshake(p, p.frame());
  await p.post({ cairn: 'scroll', y: 2000 });
  p.frame().listeners.load();
  p.server.versions.get(V2).json.manifestHash = 'overwritten';
  await p.timers.find((t) => t.ms === WATCH_MS).fn();
  assert.equal(p.reloaded.length, 1);
  assert.equal(p.window.sessionStorage.getItem(`cairn-scroll:${ARTIFACT}`), null);
});

test('a position that cannot be saved does not stop the reload', async () => {
  const p = await page({ who: 'viewer' });
  await handshake(p, p.frame());
  p.window.sessionStorage.setItem = () => { throw new Error('QuotaExceededError'); };
  await p.post({ cairn: 'scroll', y: 400 });
  p.server.versions.get(V2).json.manifestHash = 'overwritten';
  await p.timers.find((t) => t.ms === WATCH_MS).fn();
  assert.deepEqual(p.reloaded, [`/shared/${ARTIFACT}`]);
});

test('a version id that is not a UUID, listed after the page opened, does not reload it', async () => {
  const p = await page({ who: 'viewer' });
  await handshake(p, p.frame());
  p.server.versions.set('bad', { json: { id: '../evil', seq: 9, epoch: 1, name: '', manifestHash: '0'.repeat(64), vouch: null }, blob: new Uint8Array(0) });
  await p.timers.find((t) => t.ms === WATCH_MS).fn();
  assert.deepEqual(p.reloaded, []);
  assert.equal(p.frames().length, 1, 'nor swaps anything in');
});

test('after a change, resume watches again from the versions it is given', async () => {
  const V4 = '44444444-4444-4444-8444-444444444444';
  const three = [ver(V3, 'h3'), ver(V2, 'h2'), ver(V1, 'h1')];
  const w = watcher({ answers: [three, three, [ver(V4, 'h4'), ...three]] });
  await w.tick();
  assert.equal(w.changes, 1);
  assert.equal(w.timers.length, 0);
  w.watch.resume(three);
  assert.equal(w.timers.length, 1);
  await w.tick();
  assert.equal(w.changes, 1, 'the versions it resumed from are not a change');
  await w.tick();
  assert.equal(w.changes, 2);
});

test('a poll waits for its change to be handled', async () => {
  let handled;
  const w = watcher({ answers: [[ver(V3, 'h3')]] });
  const pending = new Promise((r) => { handled = r; });
  w.watch = null;
  const doc = w.document;
  let lists = 0;
  const watch = watchVersions({
    versions: [ver(V2, 'h2')],
    pinned: '',
    list: async () => { lists++; return [ver(V3, 'h3')]; },
    onChange: () => pending,
    document: doc,
    setTimeout: (fn) => w.timers.push({ fn, ms: WATCH_MS }),
  });
  const tick = w.timers.at(-1).fn();
  await new Promise((r) => setTimeout(r, 10));
  watch.resume([ver(V3, 'h3')]);
  await doc.listeners.visibilitychange();
  assert.equal(lists, 1, 'no poll while the change is being handled');
  handled();
  await tick;
});

// --- swapping in a new version ---

// handshake answers frame f's boot page and loads the version, as the content
// origin would.
async function handshake(p, f) {
  await p.post({ cairn: 'ready', version: null, path: null }, { source: f.contentWindow });
  for (let i = 0; i < 2000 && !f.contentWindow.posted.some(([m]) => m.cairn === 'keys'); i++) await new Promise((r) => setTimeout(r, 5));
  f.listeners.load();
}

// addVersion puts a version the owner signed on the server, a new one or one
// that replaces vid in place.
async function addVersion(p, vid, seq) {
  p.server.versions.set(vid, await makeVersion(p.world, vid, { signer: { user: U.owner.id, seed: U.owner.ed.seed }, seq }));
}

// poll runs the newest watch timer, and waits for what it started.
const poll = (p) => p.timers.filter((t) => t.ms === WATCH_MS).at(-1).fn();

const keysTo = (f) => f.contentWindow.posted.filter(([m]) => m.cairn === 'keys').map(([m]) => m);

test('a new version is swapped in without a reload: its frame loads hidden over the old one, then replaces it', async () => {
  const p = await page({ who: 'viewer' });
  const old = p.frame();
  await handshake(p, old);
  assert.equal(old.className, '');
  await addVersion(p, V3, 3);
  await poll(p);
  assert.deepEqual(p.reloaded, []);
  const options = () => p.dom.els.version.children.map((o) => [o.value, o.selected]);
  assert.deepEqual(options(), [[V2, true], [V1, false]], 'the header waits for the new version to show');
  assert.equal(p.frames().length, 2);
  const next = p.frames()[1];
  assert.equal(next.className, 'pending');
  assert.equal(next.attrs.src, `${CONTENT}/_cairn/boot`);
  assert.equal(next.attrs.sandbox, old.attrs.sandbox);
  assert.equal(old.className, '', 'the old version stays in view');
  await handshake(p, next);
  const [keys] = keysTo(next);
  assert.equal(keys.version, V3);
  assert.deepEqual(keys.context.versions.map((v) => v.id), [V3, V2, V1]);
  assert.equal(next.className, '');
  assert.deepEqual(p.frames(), [next]);
  assert.deepEqual(options(), [[V3, true], [V2, false], [V1, false]], 'and changes with it');
  assert.equal(p.dom.els.fullscreen.href, `/full/${ARTIFACT}/${V3}`);
  assert.equal(keysTo(old).length, 1, 'the old frame got nothing more');
  assert.deepEqual(p.dom.violations, []);
});

test('the new frame is scrolled to where the reader is in the old one, and shown once it is there', async () => {
  const p = await page({ who: 'viewer' });
  const old = p.frame();
  await handshake(p, old);
  await p.post({ cairn: 'scroll', y: 1200 }, { source: old.contentWindow });
  await addVersion(p, V3, 3);
  await poll(p);
  const next = p.frames()[1];
  // The reader goes on reading the old frame while the new one boots.
  await p.post({ cairn: 'scroll', y: 1500 }, { source: old.contentWindow });
  await p.post({ cairn: 'scrolled', y: 10 }, { source: old.contentWindow });
  await handshake(p, next);
  assert.deepEqual(next.contentWindow.posted.at(-1), [{ cairn: 'scroll-to', y: 1500 }, CONTENT]);
  assert.equal(next.className, 'pending', 'hidden while it scrolls');
  assert.equal(p.frames().length, 2);
  await p.post({ cairn: 'scrolled' }, { source: old.contentWindow });
  assert.equal(next.className, 'pending', 'the old frame cannot show it');
  await p.post({ cairn: 'scrolled' }, { source: next.contentWindow });
  assert.equal(next.className, '');
  assert.deepEqual(p.frames(), [next]);
});

test('a new frame waiting on its scroll is shown after a few seconds even with no answer', async () => {
  const p = await page({ who: 'viewer' });
  const old = p.frame();
  await handshake(p, old);
  await p.post({ cairn: 'scroll', y: 800 }, { source: old.contentWindow });
  await addVersion(p, V3, 3);
  await poll(p);
  const next = p.frames()[1];
  await handshake(p, next);
  assert.equal(next.className, 'pending');
  p.timers.filter((t) => t.ms === SCROLL_WAIT_MS).at(-1).fn();
  assert.equal(next.className, '');
  assert.deepEqual(p.frames(), [next]);
});


test('a pinned page swaps in its own version when it is overwritten, and keeps watching', async () => {
  const p = await page({ who: 'viewer', version: V1 });
  const old = p.frame();
  await handshake(p, old);
  const before = p.server.versions.get(V1).json.manifestHash;
  await addVersion(p, V1, 1);
  assert.notEqual(p.server.versions.get(V1).json.manifestHash, before);
  await poll(p);
  assert.deepEqual(p.reloaded, []);
  const next = p.frames()[1];
  await handshake(p, next);
  assert.equal(keysTo(next)[0].version, V1);
  assert.deepEqual(p.frames(), [next]);
  await addVersion(p, V3, 3);
  await poll(p);
  assert.deepEqual(p.frames(), [next], 'a newer version leaves the pinned page alone');
});



test('until it is replaced, the old frame keeps working: its links are followed, and its keys go to it', async () => {
  const p = await page({ who: 'viewer' });
  const old = p.frame();
  await handshake(p, old);
  await addVersion(p, V3, 3);
  await poll(p);
  const next = p.frames()[1];
  const from = { source: old.contentWindow };
  await p.post({ cairn: 'need-keys', version: V1 }, from);
  for (let i = 0; i < 2000 && keysTo(old).length < 2; i++) await new Promise((r) => setTimeout(r, 5));
  assert.equal(keysTo(old)[1].version, V1, 'in-artifact navigation in the old frame still gets its keys');
  assert.deepEqual(keysTo(next), [], 'nothing went to the new frame');
  next.listeners.load();
  assert.equal(next.className, 'pending', 'and the new frame was not marked answered');
  await p.post({ cairn: 'navigate', href: `/shared/${ARTIFACT}/${V1}` }, from);
  assert.deepEqual(p.assigned, [`/shared/${ARTIFACT}/${V1}`]);
});

test('no update starts while a swap is in flight; watching resumes once the new frame is shown', async () => {
  const V4 = '44444444-4444-4444-8444-444444444444';
  const p = await page({ who: 'viewer' });
  const old = p.frame();
  await handshake(p, old);
  await addVersion(p, V3, 3);
  await poll(p);
  const next = p.frames()[1];
  const watches = () => p.timers.filter((t) => t.ms === WATCH_MS).length;
  const before = watches();
  await p.post({ cairn: 'scroll', y: 600 }, { source: old.contentWindow });
  await addVersion(p, V4, 4);
  await poll(p);
  assert.deepEqual(p.frames(), [old, next], 'no third frame');
  assert.equal(watches(), before, 'nothing more is scheduled');
  assert.equal(old.className, '', 'the old version stays in view');
  await handshake(p, next);
  await p.post({ cairn: 'scrolled' }, { source: next.contentWindow });
  assert.equal(watches(), before + 1, 'showing the new frame resumes the watch, once');
  p.timers.filter((t) => t.ms === SCROLL_WAIT_MS).at(-1).fn();
  assert.equal(watches(), before + 1, 'and the wait running out later does not resume it twice');
  await poll(p);
  const third = p.frames().at(-1);
  assert.deepEqual(p.frames(), [next, third]);
  await handshake(p, third);
  assert.equal(keysTo(third)[0].version, V4);
  assert.deepEqual(p.frames(), [third]);
});

test('a new version that never loads leaves the old one in view, and the page reloads at the old position', async () => {
  const p = await page({ who: 'viewer' });
  const old = p.frame();
  await handshake(p, old);
  await p.post({ cairn: 'scroll', y: 900 }, { source: old.contentWindow });
  await addVersion(p, V3, 3);
  await poll(p);
  const next = p.frames()[1];
  p.timers.filter((t) => t.ms === REVEAL_MS).at(-1).fn();
  assert.deepEqual(p.reloaded, [`/shared/${ARTIFACT}`]);
  assert.equal(p.window.sessionStorage.getItem(`cairn-scroll:${ARTIFACT}`), '900');
  assert.equal(old.className, '');
  assert.equal(next.className, 'pending', 'the unloaded frame is never shown');
  assert.deepEqual(p.frames(), [old, next]);
});

test('keys go to the frame that asked, and a frame removed while its version is checked gets nothing', async () => {
  const p = await page({ who: 'viewer' });
  const old = p.frame();
  await handshake(p, old);
  // Hold the old frame's check of V1 until the swap has finished.
  let release;
  const held = new Promise((r) => { release = r; });
  const base = p.server.fetch;
  p.window.fetch = async (path, init) => {
    if (String(path).endsWith(`/versions/${V1}`)) await held;
    return base(path, init);
  };
  await p.post({ cairn: 'need-keys', version: V1 }, { source: old.contentWindow });
  await addVersion(p, V3, 3);
  await poll(p);
  const next = p.frames()[1];
  await handshake(p, next);
  assert.deepEqual(p.frames(), [next]);
  release();
  await settle();
  assert.equal(keysTo(old).length, 1, 'the removed frame got no keys');
  assert.equal(keysTo(next).length, 1, 'nor did the frame that did not ask');
  assert.equal(p.status().hidden, true, p.status().textContent);
});

test('focus in the old frame moves to the new one when it is shown', async () => {
  const p = await page({ who: 'viewer' });
  const old = p.frame();
  await handshake(p, old);
  p.dom.document.activeElement = old;
  await addVersion(p, V3, 3);
  await poll(p);
  const next = p.frames()[1];
  await handshake(p, next);
  assert.equal(next.focused, 1);
  // Focus elsewhere stays where it is.
  p.dom.document.activeElement = p.dom.els.version;
  await addVersion(p, '44444444-4444-4444-8444-444444444444', 4);
  await poll(p);
  const third = p.frames()[1];
  await handshake(p, third);
  assert.equal(third.focused, undefined);
});

test('a renewed token goes to every frame on the page, the old one and the one loading', async () => {
  const p = await page({ who: 'viewer' });
  const old = p.frame();
  await handshake(p, old);
  await addVersion(p, V3, 3);
  await poll(p);
  const next = p.frames()[1];
  const renewal = (t) => ![REVEAL_MS, WATCH_MS, SCROLL_WAIT_MS].includes(t.ms);
  p.timers.filter(renewal).at(-1).fn();
  await settle();
  const tokens = (f) => f.contentWindow.posted.filter(([m]) => m.cairn === 'token');
  assert.equal(tokens(old).length, 1);
  assert.equal(tokens(next).length, 1);
});

test('an update opens the artifact again, so its members and keys are current', async () => {
  const p = await page({ who: 'viewer' });
  await handshake(p, p.frame());
  const membership = () => p.server.calls.filter((c) => c.path === `/api/artifacts/${ARTIFACT}/membership`).length;
  const before = membership();
  await addVersion(p, V3, 3);
  await poll(p);
  assert.equal(membership(), before + 1);
});

test('a public link visitor\'s page swaps in a new version too', async () => {
  const p = await page({ isPublic: true, members: [], noRun: true });
  p.window.location.hash = `#k=${e2e.b64(p.world.aks[1])}&e=1&o=${U.owner.fp}`;
  await p.start();
  const old = p.frame();
  await handshake(p, old);
  await addVersion(p, V3, 3);
  await poll(p);
  assert.deepEqual(p.reloaded, []);
  const next = p.frames()[1];
  await handshake(p, next);
  const [keys] = keysTo(next);
  assert.equal(keys.version, V3);
  assert.equal(keys.linkToken, e2e.b64(await e2e.linkToken(p.world.aks[1], ARTIFACT, 1)));
  assert.deepEqual(p.frames(), [next]);
});
