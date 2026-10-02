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
import { run } from './shell.mjs';

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
        return c;
      },
      setAttribute(k, v) {
        this.attrs[k] = v;
      },
      addEventListener(type, fn) {
        this.listeners[type] = fn;
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
  return {
    violations,
    els,
    document: {
      title: '',
      body: { dataset },
      getElementById: (id) => els[id],
      createElement: make,
      write: () => violations.push('document.write'),
    },
  };
}

// page builds a shell page for who (or nobody) and runs it.
async function page({ who = null, mode = 'shared', version = '', path = '/', isPublic = false, hash = '', members, build, noRun } = {}) {
  const world = await buildWorld({
    owner: U.owner,
    members: members ?? [{ user: U.editor, role: 'editor' }, { user: U.viewer, role: 'viewer' }],
    isPublic,
  });
  const server = makeServer(world, { who: who && U[who], linkTokenB64: '*' });
  for (const [vid, seq, signer] of [[V1, 1, U.owner], [V2, 2, U.owner]]) {
    server.versions.set(vid, await makeVersion(world, vid, { signer: { user: signer.id, seed: signer.ed.seed }, seq }));
  }
  await build?.({ world, server });
  const dom = fakeDom({ artifact: ARTIFACT, version, path, mode, contentOrigin: CONTENT });
  const handlers = {};
  const timers = [];
  const assigned = [];
  const replaced = [];
  const window = {
    location: { origin: ORIGIN, pathname: `/shared/${ARTIFACT}`, search: '', hash, assign: (p) => assigned.push(p) },
    history: { replaceState: (...a) => replaced.push(a) },
    fetch: server.fetch,
    localStorage: fakeStorage(),
    addEventListener: (type, fn) => {
      handlers[type] = fn;
    },
    setTimeout: (fn, ms) => {
      timers.push({ fn, ms });
      return timers.length;
    },
    clearTimeout: () => {},
  };
  const keyStore = fakeKeyStore(who ? await keyStoreRecord(U[who]) : null);
  const p = { world, server, dom, window, handlers, timers, assigned, replaced, keyStore };
  p.frame = () => dom.els['frame-host'].children[0];
  p.status = () => dom.els.status;
  p.start = () => run(window, dom.document, keyStore);
  if (!noRun) await p.start();
  // post delivers a message to the shell as the frame, or as source/origin say.
  p.post = async (data, { source = p.frame()?.contentWindow, origin = CONTENT } = {}) => {
    handlers.message({ data, source, origin });
    await settle();
  };
  p.posted = () => p.frame().contentWindow.posted;
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

test('the page version is the one framed and shown, and the fullscreen link names it', async () => {
  const p = await page({ who: 'viewer', version: V1 });
  assert.equal(p.dom.els.fullscreen.href, `/full/${ARTIFACT}/${V1}`);
  assert.deepEqual(p.dom.els.version.children.map((o) => o.selected), [false, true]);
  await p.post({ cairn: 'ready', version: null, path: null });
  assert.equal(p.posted()[0][0].version, V1);
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
  assert.equal(p.posted().length, 1);
  const [msg, origin] = p.posted()[0];
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
  const [msg] = p.posted()[0];
  assert.equal(msg.version, V2);
  assert.equal(msg.path, '/deep/page.html');
  assert.ok(p.server.calls.some((c) => c.path === `/api/artifacts/${ARTIFACT}/versions/${V2}/manifest`), 'verified first');
});

test('need-keys answers for the named version with path /', async () => {
  const p = await page({ who: 'viewer', path: '/x' });
  await p.post({ cairn: 'need-keys', version: V1 });
  const [msg] = p.posted()[0];
  assert.equal(msg.version, V1);
  assert.equal(msg.path, '/');
});

test('no message is ever posted to a wildcard origin', async () => {
  const p = await page({ who: 'viewer' });
  await p.post({ cairn: 'ready', version: null, path: null });
  await p.post({ cairn: 'need-keys', version: V1 });
  p.timers[0].fn();
  await settle();
  assert.ok(p.posted().length >= 3);
  for (const [, origin] of p.posted()) assert.equal(origin, CONTENT);
});

test('a message from another window, or another origin, is ignored', async () => {
  const p = await page({ who: 'viewer' });
  p.server.calls.length = 0;
  const msgs = [
    { cairn: 'ready', version: null, path: null },
    { cairn: 'need-keys', version: V1 },
    { cairn: 'navigate', href: `/shared/${ARTIFACT}` },
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

test('ready with a path that does not start with a slash is ignored', async () => {
  const p = await page({ who: 'viewer' });
  for (const path of ['x', '', null, 7]) await p.post({ cairn: 'ready', version: V1, path });
  assert.deepEqual(p.posted(), []);
});

test('a version that is not this artifact\'s is ignored without a message', async () => {
  const p = await page({ who: 'viewer' });
  await p.post({ cairn: 'need-keys', version: '66666666-6666-4666-8666-666666666667' });
  assert.deepEqual(p.posted(), []);
  assert.equal(p.status().hidden, true);
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
  assert.equal(p.posted()[0][0].signer, null);
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
});

test('an artifact with no versions says so and is not framed', async () => {
  const p = await page({ who: 'viewer', build: ({ server }) => server.versions.clear() });
  assert.equal(p.frame(), undefined);
  assert.match(p.status().textContent, /no versions/);
});

test('a visitor with a public link opens it, and the link leaves the address bar first', async () => {
  const p = await page({ isPublic: true, members: [], noRun: true });
  p.window.location.hash = `#k=${e2e.b64(p.world.aks[1])}&e=1&o=${U.owner.fp}`;
  await p.start();
  assert.deepEqual(p.replaced, [[null, '', `/shared/${ARTIFACT}`]]);
  assert.equal(p.status().hidden, true, p.status().textContent);
  await p.post({ cairn: 'ready', version: null, path: null });
  const [msg] = p.posted()[0];
  checkKeysMessage(msg);
  assert.equal(msg.token, null);
  assert.deepEqual(msg.context.users, []);
  assert.equal(msg.linkToken, e2e.b64(await e2e.linkToken(p.world.aks[1], ARTIFACT, 1)));
});

test('a malformed fragment is removed, and the error is shown', async () => {
  const p = await page({ isPublic: true, hash: '#k=nonsense' });
  assert.deepEqual(p.replaced, [[null, '', `/shared/${ARTIFACT}`]]);
  assert.equal(p.frame(), undefined);
  assert.equal(p.status().hidden, false);
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

test('the content token is renewed and posted to the frame', async () => {
  const p = await page({ who: 'viewer' });
  assert.equal(p.timers.length, 1);
  p.timers[0].fn();
  await settle();
  const [msg, origin] = p.posted().at(-1);
  assert.equal(origin, CONTENT);
  assert.equal(msg.cairn, 'token');
  assert.match(msg.token, /^tok-/);
  assert.equal(msg.tokenExpires, 2000000000);
  // Later keys carry the newest token.
  await p.post({ cairn: 'need-keys', version: V1 });
  assert.equal(p.posted().at(-1)[0].token, msg.token);
});

test('a failed renewal is shown', async () => {
  const p = await page({ who: 'viewer' });
  const base = p.server.fetch;
  p.window.fetch = async (path, init) => (init?.method === 'POST' ? new Response('{}', { status: 401 }) : base(path, init));
  p.timers[0].fn();
  await settle();
  assert.equal(p.status().hidden, false);
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
