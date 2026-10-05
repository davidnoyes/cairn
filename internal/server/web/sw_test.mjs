// Tests for sw.js against a minimal fake service worker global: event
// listeners, clients, and fetch. The checks themselves are tested in
// content_test.mjs; these tests cover the wiring. Run with:
// node --test internal/server/web/*_test.mjs
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { APP, ARTIFACT, OTHER, USER, VERSION, enc, fixture } from './content_fixture.mjs';

const ORIGIN = `http://${ARTIFACT}.localhost:8080`;
const listeners = {};
const posted = []; // messages sent to window clients
const calls = []; // every fetch the worker made
let skipped = 0;
let claimed = 0;
let table = {}; // url -> body for the fake network
let matchGate = null; // a promise clients.matchAll waits on
let getGate = null; // a promise clients.get waits on
let clientUrl = `${ORIGIN}/${VERSION}/index.html`; // what clients.get finds; null for none
let netHook = null; // (request) => promise of a Response, or of nothing to use the table
let signHook = null; // (message, port) => void, for a sign request posted to the page

globalThis.self = {
  location: new URL(`${ORIGIN}/_cairn/sw.js?app=${encodeURIComponent(APP)}`),
  registration: { scope: `${ORIGIN}/` },
  addEventListener: (type, fn) => {
    listeners[type] = fn;
  },
  skipWaiting: () => {
    skipped++;
  },
  clients: {
    claim: async () => {
      claimed++;
    },
    matchAll: async () => {
      await matchGate;
      return [{ postMessage: (m) => posted.push(m) }];
    },
    get: async () => {
      await getGate;
      return clientUrl === null ? null : { url: clientUrl, postMessage: (m, transfer) => signHook?.(m, transfer[0]) };
    },
  },
};
globalThis.fetch = async (r) => {
  const req = typeof r === 'string' ? new Request(r) : r;
  calls.push(req);
  const hooked = netHook && (await netHook(req));
  if (hooked) return hooked;
  const body = table[req.url];
  return body ? new Response(body) : new Response('no', { status: 404 });
};

await import('./sw.js');

// A source of null is a message with no sender.
function send(data, origin = ORIGIN, source = undefined) {
  const replies = [];
  const waits = [];
  listeners.message({
    data,
    origin,
    source: source === undefined ? { postMessage: (m) => replies.push(m) } : source,
    waitUntil: (p) => waits.push(p),
  });
  return Promise.all(waits).then(() => replies);
}

function dispatch(url, init = {}, clientId = 'c1') {
  const { mode, ...rest } = init;
  const request = new Request(url, rest);
  Object.defineProperty(request, 'mode', { value: mode ?? 'no-cors' });
  let responded = null;
  listeners.fetch({ request, clientId, respondWith: (p) => (responded = p) });
  return responded;
}

async function keysFor(f, over = {}) {
  return {
    cairn: 'keys',
    artifact: ARTIFACT,
    version: VERSION,
    epoch: 3,
    ak: e2e.b64(f.ak),
    signer: { user: USER, ed25519: e2e.b64(f.key.pub) },
    manifestHash: f.args.manifestHash,
    token: 'tok',
    tokenExpires: null,
    linkToken: null,
    context: { artifact: { id: ARTIFACT, name: 'n', description: 'd' }, users: [] },
    path: '/index.html',
    aks: { 3: e2e.b64(f.ak) },
    currentEpoch: 3,
    writers: { [USER]: [e2e.b64(f.key.pub)] },
    publicWrites: false,
    ...over,
  };
}

const V2 = '55555555-5555-4555-8555-555555555555';

function register(fx, version = VERSION) {
  const api = `${ORIGIN}/api/artifacts/${ARTIFACT}/versions/${version}`;
  table[`${api}/manifest`] = fx.manifestBlob;
  for (const [id, blob] of Object.entries(fx.blobs)) table[`${api}/blobs/${id}`] = blob;
}

const f = await fixture();
const f2 = await fixture({ version: V2 });
register(f);
register(f2, V2);
const baseTable = { ...table };

test('install and activate take over at once', async () => {
  listeners.install();
  let waited;
  listeners.activate({ waitUntil: (p) => (waited = p) });
  await waited;
  assert.equal(skipped, 1);
  assert.equal(claimed, 1);
});

test('without keys: a navigation gets the boot page', async () => {
  table[`${ORIGIN}/_cairn/boot`] = enc.encode('boot');
  const res = await dispatch(`${ORIGIN}/${VERSION}/index.html`, { mode: 'navigate' });
  assert.equal(await res.text(), 'boot');
});

test('without keys: a subresource asks the page, then answers 503 after 10 seconds', async () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    posted.length = 0;
    const p = dispatch(`${ORIGIN}/${VERSION}/app/main.js`);
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(posted, [{ cairn: 'need-keys', version: VERSION }]);
    mock.timers.tick(10000);
    assert.equal((await p).status, 503);
  } finally {
    mock.timers.reset();
  }
});

test('refuses keys from another origin, for another artifact, or with an unknown field', async () => {
  assert.deepEqual(await send(await keysFor(f), 'http://evil.example'), []);
  calls.length = 0;
  const other = await send(await keysFor(f, { artifact: OTHER, context: { artifact: { id: OTHER, name: 'n', description: 'd' }, users: [] } }));
  assert.equal(other[0].cairn, 'keys-error');
  assert.equal(calls.length, 0, 'no fetch for another artifact');
  const extra = await send(await keysFor(f, { extra: 1 }));
  assert.deepEqual([extra[0].cairn, extra[0].version], ['keys-error', VERSION]);
  assert.equal((await dispatch(`${ORIGIN}/${VERSION}/x.js`, { mode: 'navigate' }).then((r) => r.text())), 'boot');
});

test('a manifest that fails its hash is reported and nothing is stored', async () => {
  const replies = await send(await keysFor(f, { manifestHash: '1'.repeat(64) }));
  assert.equal(replies[0].cairn, 'keys-error');
  const res = await dispatch(`${ORIGIN}/${VERSION}/index.html`, { mode: 'navigate' });
  assert.equal(await res.text(), 'boot');
});

test('with keys it serves decrypted files', async () => {
  const replies = await send(await keysFor(f));
  assert.deepEqual(replies, [{ cairn: 'keys-ok', version: VERSION }]);

  const page = await dispatch(`${ORIGIN}/${VERSION}/`, { mode: 'navigate' });
  assert.equal(page.headers.get('Content-Security-Policy'), `frame-ancestors ${APP}`);
  assert.equal(await page.text(), '<script src="/_cairn/frame.js"></script><html>hi</html>');
  const js = await dispatch(`${ORIGIN}/${VERSION}/app/main.js`);
  assert.equal(await js.text(), 'console.log(1)');
  assert.equal((await dispatch(`${ORIGIN}/${VERSION}/missing.js`)).status, 404);
  assert.equal((await dispatch(`${ORIGIN}/${VERSION}/index.html`, { method: 'POST' })).status, 405);
});

test('the manifest is opened once', async () => {
  calls.length = 0;
  await dispatch(`${ORIGIN}/${VERSION}/app/main.js`);
  assert.equal(calls.filter((r) => r.url.endsWith('/manifest')).length, 0);
});

test('it does not intercept /_cairn/ or another origin', () => {
  assert.equal(dispatch(`${ORIGIN}/_cairn/frame.js`), null);
  assert.equal(dispatch(`http://elsewhere.example/${VERSION}/x`), null);
  assert.equal(dispatch(`${ORIGIN}/plain`), null);
});

test('api: answers two reads itself, and adds the token to the rest', async () => {
  calls.length = 0;
  const art = await dispatch(`${ORIGIN}/api/artifacts/${ARTIFACT}`);
  assert.equal(art.status, 200);
  assert.deepEqual(await art.json(), { id: ARTIFACT, name: 'n', description: 'd' });
  const users = await dispatch(`${ORIGIN}/api/users`);
  assert.equal(users.status, 200);
  assert.deepEqual(await users.json(), []);
  assert.equal(calls.length, 0);

  await dispatch(`${ORIGIN}/api/artifacts/${ARTIFACT}/db`, { headers: { Authorization: 'Bearer evil' } });
  assert.equal(calls[0].headers.get('Authorization'), 'Bearer tok');
});

test('api: a navigation (a download link) carries the token like any other request', async () => {
  calls.length = 0;
  await dispatch(`${ORIGIN}/api/artifacts/${ARTIFACT}/db/download`, { mode: 'navigate' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].headers.get('Authorization'), 'Bearer tok');
});

test('api: a navigation that is not a GET (a form from another site) is refused, and nothing is sent', async () => {
  calls.length = 0;
  const res = await dispatch(`${ORIGIN}/api/artifacts/${ARTIFACT}/versions/${VERSION}/db/batch`,
    { mode: 'navigate', method: 'POST', body: '{"statements":[]}' }, '');
  assert.equal(res.status, 405);
  assert.equal(calls.length, 0);
});

test('a token message replaces the token, and only from this origin', async () => {
  await send({ cairn: 'token', token: 'new', tokenExpires: 5 }, 'http://evil.example');
  await send({ cairn: 'token', token: 'bad' });
  await send({ cairn: 'token', token: 'new', tokenExpires: 5 });
  calls.length = 0;
  await dispatch(`${ORIGIN}/api/x`);
  assert.equal(calls[0].headers.get('Authorization'), 'Bearer new');
});

// The tests below each start a fresh worker, so they do not depend on the
// keys an earlier test left behind.
let loads = 0;
async function fresh(search = `?app=${encodeURIComponent(APP)}`, scope = `${ORIGIN}/`) {
  self.location = new URL(`${ORIGIN}/_cairn/sw.js${search}`);
  self.registration = { scope };
  table = { ...baseTable, [`${ORIGIN}/_cairn/boot`]: enc.encode('boot') };
  matchGate = null;
  getGate = null;
  clientUrl = `${ORIGIN}/${VERSION}/index.html`;
  netHook = null;
  signHook = null;
  posted.length = 0;
  calls.length = 0;
  await import(`./sw.js?fresh=${++loads}`);
}

const tick = () => new Promise((r) => setImmediate(r));

// Artifact code shares the origin and could register this script at a
// narrower scope, such as /_cairn/, where it would control the boot page.
// The worker refuses to start anywhere but the origin root.
test('a worker registered at any scope but the origin root refuses to start', async () => {
  for (const scope of [`${ORIGIN}/_cairn/`, `${ORIGIN}/${VERSION}/`, 'https://other.example/']) {
    await assert.rejects(fresh(undefined, scope), /scope/, scope);
  }
  await fresh();
});

function gate() {
  let open;
  const promise = new Promise((r) => (open = r));
  return [promise, open];
}

async function fakeTimers(fn) {
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    await fn();
  } finally {
    mock.timers.reset();
  }
}

const isManifest = (req) => req.url.endsWith('/manifest');
const blobCalls = () => calls.filter((r) => r.url.includes('/blobs/'));

async function apiAuth(headers = {}) {
  calls.length = 0;
  await dispatch(`${ORIGIN}/api/artifacts/${ARTIFACT}/db`, { headers });
  return calls.at(-1).headers.get('Authorization');
}

async function mainJsAuth(version = VERSION) {
  calls.length = 0;
  assert.equal((await dispatch(`${ORIGIN}/${version}/app/main.js`)).status, 200);
  return blobCalls().at(-1).headers.get('Authorization');
}

test('need-keys: a request with no keys waits for them, then is served', async () => {
  await fresh();
  await fakeTimers(async () => {
    const p = dispatch(`${ORIGIN}/${VERSION}/app/main.js`);
    await tick();
    assert.deepEqual(posted, [{ cairn: 'need-keys', version: VERSION }]);
    await send(await keysFor(f));
    const res = await p;
    assert.equal(res.status, 200);
    assert.equal(await res.text(), 'console.log(1)');
  });
});

test('need-keys: keys that land while the pages are listed are not missed', async () => {
  await fresh();
  await fakeTimers(async () => {
    const [gated, release] = gate();
    matchGate = gated;
    const p = dispatch(`${ORIGIN}/${VERSION}/app/main.js`);
    await tick();
    assert.deepEqual(await send(await keysFor(f)), [{ cairn: 'keys-ok', version: VERSION }]);
    release();
    assert.equal((await p).status, 200);
  });
});

test('need-keys: a timed-out wait is forgotten, so the next request asks again', async () => {
  await fresh();
  await fakeTimers(async () => {
    const first = dispatch(`${ORIGIN}/${VERSION}/app/main.js`);
    await tick();
    mock.timers.tick(10000);
    assert.equal((await first).status, 503);
    posted.length = 0;
    const second = dispatch(`${ORIGIN}/${VERSION}/app/main.js`);
    await tick();
    assert.deepEqual(posted, [{ cairn: 'need-keys', version: VERSION }]);
    await send(await keysFor(f));
    assert.equal((await second).status, 200);
  });
});

test('need-keys: five requests waiting on one manifest open it once', async () => {
  await fresh();
  const [gated, release] = gate();
  netHook = async (req) => (isManifest(req) ? gated : undefined);
  const keys = send(await keysFor(f));
  await tick();
  const waiting = Array.from({ length: 5 }, () => dispatch(`${ORIGIN}/${VERSION}/app/main.js`));
  await tick();
  release();
  assert.deepEqual(await keys, [{ cairn: 'keys-ok', version: VERSION }]);
  for (const res of await Promise.all(waiting)) assert.equal(res.status, 200);
  assert.equal(calls.filter(isManifest).length, 1);
});

test('api with no keys asks for the version of the calling client', async () => {
  await fresh();
  await fakeTimers(async () => {
    const p = dispatch(`${ORIGIN}/api/artifacts/${ARTIFACT}/db`);
    await tick();
    assert.deepEqual(posted, [{ cairn: 'need-keys', version: VERSION }]);
    await send(await keysFor(f));
    await p;
    assert.equal(calls.at(-1).url, `${ORIGIN}/api/artifacts/${ARTIFACT}/db`);
    assert.equal(calls.at(-1).headers.get('Authorization'), 'Bearer tok');
  });
});

test('api with no keys: keys that land while the client is looked up are not missed', async () => {
  await fresh();
  await fakeTimers(async () => {
    const [gated, release] = gate();
    getGate = gated;
    const p = dispatch(`${ORIGIN}/api/artifacts/${ARTIFACT}/db`);
    await tick();
    await send(await keysFor(f));
    release();
    await p;
    assert.equal(calls.at(-1).url, `${ORIGIN}/api/artifacts/${ARTIFACT}/db`);
  });
});

test('api with no keys that never arrive answers 503 after 10 seconds', async () => {
  await fresh();
  await fakeTimers(async () => {
    const p = dispatch(`${ORIGIN}/api/artifacts/${ARTIFACT}/db`);
    await tick();
    mock.timers.tick(10000);
    assert.equal((await p).status, 503);
    assert.equal(calls.length, 0, 'nothing forwarded without keys');
  });
});

test('api with no keys and no known client answers 503 and asks nobody', async () => {
  for (const [url, clientId] of [
    [null, 'c1'],
    [`${ORIGIN}/plain`, 'c1'],
    [`${ORIGIN}/${VERSION}/index.html`, ''],
  ]) {
    await fresh();
    await fakeTimers(async () => {
      clientUrl = url;
      const res = await dispatch(`${ORIGIN}/api/artifacts/${ARTIFACT}/db`, {}, clientId);
      assert.equal(res.status, 503, `${url} ${clientId}`);
      assert.deepEqual(posted, []);
    });
  }
});

test('token: a renewal to null drops the Authorization header', async () => {
  await fresh();
  await send(await keysFor(f));
  assert.equal(await apiAuth(), 'Bearer tok');
  await send({ cairn: 'token', token: null, tokenExpires: null });
  assert.equal(await apiAuth({ Authorization: 'Bearer evil' }), null);
});

test('token: a renewal reaches every version held', async () => {
  await fresh();
  await send(await keysFor(f));
  await send(await keysFor(f2, { version: V2 }));
  await send({ cairn: 'token', token: 'new', tokenExpires: 5 });
  assert.equal(await mainJsAuth(VERSION), 'Bearer new');
  assert.equal(await mainJsAuth(V2), 'Bearer new');
});

test('token: a renewal before any keys is harmless and does not outlive newer keys', async () => {
  await fresh();
  assert.deepEqual(await send({ cairn: 'token', token: 'early', tokenExpires: 5 }), []);
  await send(await keysFor(f));
  assert.equal(await apiAuth(), 'Bearer tok');
  assert.equal(await mainJsAuth(), 'Bearer tok');
});

test('token: a renewal during a keys check is not lost', async () => {
  await fresh();
  const [gated, release] = gate();
  netHook = async (req) => (isManifest(req) ? gated : undefined);
  const keys = send(await keysFor(f));
  await tick();
  await send({ cairn: 'token', token: 'renewed', tokenExpires: 5 });
  release();
  assert.deepEqual(await keys, [{ cairn: 'keys-ok', version: VERSION }]);
  assert.equal(await apiAuth(), 'Bearer renewed');
  assert.equal(await mainJsAuth(), 'Bearer renewed');
});

test('keys: an older message that finishes last does not replace a newer one', async () => {
  await fresh();
  const [gateOld, releaseOld] = gate();
  const [gateNew, releaseNew] = gate();
  const gates = [gateOld, gateNew];
  netHook = async (req) => (isManifest(req) ? gates.shift() : undefined);
  const old = send(await keysFor(f, { token: 'old' }));
  await tick();
  const newer = send(await keysFor(f, { token: 'new' }));
  await tick();
  releaseNew();
  await newer;
  releaseOld();
  await old;
  assert.equal(await apiAuth(), 'Bearer new');
  assert.equal(await mainJsAuth(), 'Bearer new');
});

test('keys: a failed manifest fetch is reported, and a retry succeeds', async () => {
  await fresh();
  netHook = async (req) => (isManifest(req) ? new Response('', { status: 500 }) : undefined);
  assert.deepEqual(await send(await keysFor(f)), [
    { cairn: 'keys-error', version: VERSION, error: 'manifest fetch failed: 500' },
  ]);
  netHook = null;
  assert.deepEqual(await send(await keysFor(f, { version: 5 })), [
    { cairn: 'keys-error', version: null, error: 'version is not a lowercase UUID' },
  ]);
  assert.deepEqual(await send(await keysFor(f)), [{ cairn: 'keys-ok', version: VERSION }]);
  assert.equal((await dispatch(`${ORIGIN}/${VERSION}/app/main.js`)).status, 200);
});

test('keys: a wrong signature, epoch, or signer is reported with its reason', async () => {
  await fresh();
  const other = await e2e.generateEd25519();
  const cases = [
    [{ signer: { user: USER, ed25519: e2e.b64(other.pub) } }, 'manifest signature does not verify'],
    [{ epoch: 4, currentEpoch: 4, aks: { 4: e2e.b64(f.ak) } }, 'manifest epoch mismatch'],
    [{ signer: { user: OTHER, ed25519: e2e.b64(f.key.pub) } }, 'manifest signer mismatch'],
  ];
  for (const [over, error] of cases) {
    assert.deepEqual(await send(await keysFor(f, over)), [{ cairn: 'keys-error', version: VERSION, error }]);
  }
  assert.equal(await dispatch(`${ORIGIN}/${VERSION}/index.html`, { mode: 'navigate' }).then((r) => r.text()), 'boot');
});

test('content: HEAD is served, and any other method is refused', async () => {
  await fresh();
  await send(await keysFor(f));
  assert.equal((await dispatch(`${ORIGIN}/${VERSION}/app/main.js`, { method: 'HEAD' })).status, 200);
  assert.equal((await dispatch(`${ORIGIN}/${VERSION}/app/main.js`, { method: 'PUT', body: 'x' })).status, 405);
  assert.equal((await dispatch(`${ORIGIN}/${VERSION}/app/main.js`, { method: 'POST', body: 'x' })).status, 405);
});

test('the app origin comes from the query, and anything else frames nowhere', async () => {
  const cases = [
    ['', "'none'"],
    ['?app=garbage', "'none'"],
    ['?app=javascript:x', "'none'"],
    ['?app=ftp://x', "'none'"],
    [`?app=${encodeURIComponent('https://app.example:9/path?q')}`, 'https://app.example:9'],
  ];
  for (const [search, ancestors] of cases) {
    await fresh(search);
    await send(await keysFor(f));
    const page = await dispatch(`${ORIGIN}/${VERSION}/`, { mode: 'navigate' });
    assert.equal(page.headers.get('Content-Security-Policy'), `frame-ancestors ${ancestors}`, search);
  }
});

test('messages: one with no source is refused', async () => {
  await fresh();
  assert.deepEqual(await send(await keysFor(f), ORIGIN, null), []);
  assert.equal(calls.length, 0, 'no fetch for a sourceless keys message');
  assert.equal(await dispatch(`${ORIGIN}/${VERSION}/index.html`, { mode: 'navigate' }).then((r) => r.text()), 'boot');
  await send(await keysFor(f));
  await send({ cairn: 'token', token: 'x', tokenExpires: null }, ORIGIN, null);
  assert.equal(await apiAuth(), 'Bearer tok');
});

test('messages: data that is not a message is ignored', async () => {
  await fresh();
  for (const data of [null, undefined, 'keys', 42, [], {}, { cairn: 'nope' }]) {
    assert.deepEqual(await send(data), [], String(data));
  }
  assert.equal(calls.length, 0);
});

const DATA = `${ORIGIN}/api/artifacts/${ARTIFACT}/versions/${VERSION}`;
const ENVELOPE = { body: 'b', sig: 's', signer: USER };

test('data: a route for another artifact is not found, and nothing is sent', async () => {
  await fresh();
  const res = await dispatch(`${ORIGIN}/api/artifacts/${OTHER}/versions/${VERSION}/db`);
  assert.equal(res.status, 404);
  assert.equal(calls.length, 0);
});

test('data: a navigation that is not a GET is refused, and nothing is sent', async () => {
  await fresh();
  const res = await dispatch(`${DATA}/db`, { mode: 'navigate', method: 'PUT', body: 'x' });
  assert.equal(res.status, 405);
  assert.equal(calls.length, 0);
});

test('data: without keys it asks the page, then answers 503 after 10 seconds', async () => {
  await fresh();
  await fakeTimers(async () => {
    const p = dispatch(`${DATA}/db`);
    await tick();
    assert.deepEqual(posted, [{ cairn: 'need-keys', version: VERSION }]);
    mock.timers.tick(10000);
    assert.equal((await p).status, 503);
  });
  assert.equal(calls.length, 0);
});

test('data: with keys a read goes to the server with the token', async () => {
  await fresh();
  await send(await keysFor(f));
  const res = await dispatch(`${DATA}/db`);
  assert.equal(res.status, 404);
  assert.match(await res.text(), /no database yet/);
  assert.equal(calls.at(-1).url, `${DATA}/db`);
  assert.equal(calls.at(-1).headers.get('Authorization'), 'Bearer tok');
});

test('data: a write is signed through the page that made it, then sent with the token', async () => {
  await fresh();
  await send(await keysFor(f));
  const asked = [];
  signHook = (m, port) => {
    asked.push(m);
    port.postMessage({ cairn: 'signed', envelopes: [ENVELOPE] });
  };
  netHook = async (req) => (req.method === 'PUT' ? new Response('{}') : undefined);
  const res = await dispatch(`${DATA}/db`, { method: 'PUT', headers: { 'If-Match': '"0"' }, body: 'db' });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { revision: 1 });
  assert.equal(asked.length, 1);
  assert.equal(asked[0].cairn, 'sign');
  assert.equal(asked[0].purpose, 'revision');
  assert.deepEqual(Object.keys(asked[0].bodies[0]), ['artifact', 'version', 'revision', 'epoch', 'sha256']);
  const put = calls.at(-1);
  assert.equal(put.headers.get('Authorization'), 'Bearer tok');
  assert.equal(put.headers.get('If-Match'), '"0"');
  assert.deepEqual(JSON.parse((await put.formData()).get('record')), ENVELOPE);
});

test('data: a write the shell refuses is a 403 that carries its reason', async () => {
  await fresh();
  await send(await keysFor(f));
  signHook = (m, port) => port.postMessage({ cairn: 'sign-error', error: 'You cannot change the data of this artifact.' });
  const res = await dispatch(`${DATA}/db`, { method: 'PUT', headers: { 'If-Match': '"0"' }, body: 'db' });
  assert.equal(res.status, 403);
  assert.match(await res.text(), /You cannot change the data/);
  assert.ok(!calls.some((r) => r.method === 'PUT'));
});

test('data: an answer that is neither signed nor a sign error is refused', async () => {
  await fresh();
  await send(await keysFor(f));
  signHook = (m, port) => port.postMessage({ cairn: 'sign-error', error: 42 });
  const res = await dispatch(`${DATA}/db`, { method: 'PUT', headers: { 'If-Match': '"0"' }, body: 'db' });
  assert.equal(res.status, 403);
  assert.match(await res.text(), /the shell did not sign/);
});

test('data: a write with no page to sign through is a 403', async () => {
  for (const [id, url] of [['c1', null], ['', `${ORIGIN}/${VERSION}/index.html`]]) {
    await fresh();
    await send(await keysFor(f));
    clientUrl = url;
    signHook = () => assert.fail('nothing to ask');
    const res = await dispatch(`${DATA}/db`, { method: 'PUT', headers: { 'If-Match': '"0"' }, body: 'db' }, id);
    assert.equal(res.status, 403, `client ${JSON.stringify(id)}`);
    assert.match(await res.text(), /no page to sign through/);
  }
});

test('data: a shell that does not answer is a 403 after 30 seconds', async () => {
  await fresh();
  await send(await keysFor(f));
  let asked = 0;
  signHook = () => asked++;
  await fakeTimers(async () => {
    let done = false;
    const p = dispatch(`${DATA}/db`, { method: 'PUT', headers: { 'If-Match': '"0"' }, body: 'db' }).then((r) => {
      done = true;
      return r;
    });
    for (let i = 0; i < 20 && asked === 0; i++) await tick();
    assert.equal(asked, 1);
    mock.timers.tick(29999);
    await tick();
    assert.equal(done, false);
    mock.timers.tick(1);
    const res = await p;
    assert.equal(res.status, 403);
    assert.match(await res.text(), /the shell did not answer/);
  });
});
