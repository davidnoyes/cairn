// Tests for data.mjs, the worker's database and stored-file routes, against
// an in-memory server that stores what the worker uploads and serves it back
// as the real one does, with hooks to tamper with what it serves.
// Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { ARTIFACT, OTHER, USER, VERSION, enc, randomBytes, sha256Hex } from './content_fixture.mjs';
import { checkSigned, handleData, parseDataPath } from './data.mjs';

const ORIGIN = `http://${ARTIFACT}.localhost:8080`;
const API = `${ORIGIN}/api/artifacts/${ARTIFACT}/versions/${VERSION}`;
const V2 = '55555555-5555-4555-8555-555555555555';
const CSP = "sandbox; default-src 'none'; frame-ancestors 'none'";

const writer = await e2e.generateEd25519();
const stranger = await e2e.generateEd25519();
const ak3 = randomBytes(32);
const ak4 = randomBytes(32);

function baseKeys(over = {}) {
  return {
    artifact: ARTIFACT,
    version: VERSION,
    epoch: 3,
    currentEpoch: 4,
    aks: { 3: e2e.b64(ak3), 4: e2e.b64(ak4) },
    writers: { [USER]: [e2e.b64(writer.pub)] },
    publicWrites: false,
    token: 'tok',
    linkToken: null,
    ...over,
  };
}

// signer signs as the shell would: {v: 1, ...body}, as user under key.
function signer(key = writer, user = USER) {
  return async (purpose, bodies) =>
    Promise.all(bodies.map((b) => e2e.newEnvelope(key.seed, user, purpose, enc.encode(JSON.stringify({ v: 1, ...b })))));
}

// fakeServer stores revisions and files as the server does. It checks
// If-Match and nothing else: the client trusts the server for none of it.
function fakeServer() {
  const srv = {
    revisions: [], // {revision, epoch, blob, record, signerKey}
    files: new Map(), // address -> {epoch, blob, record, meta, metaRecord, signerKey}
    calls: [],
    signerKey: e2e.b64(writer.pub),
    hook: null, // (req) => Response | undefined
    extraItems: [], // appended to the file list as the server sent them
  };
  srv.listItem = (address, f) => ({
    address,
    epoch: f.epoch,
    size: f.blob.length,
    updatedAt: '2026-10-05T00:00:00Z',
    record: JSON.parse(f.record),
    meta: e2e.b64(f.meta),
    metaRecord: JSON.parse(f.metaRecord),
    signerKey: f.signerKey,
  });
  srv.fetch = async (req) => {
    srv.calls.push(req);
    const hooked = srv.hook && (await srv.hook(req));
    if (hooked) return hooked;
    const url = new URL(req.url);
    const prefix = new URL(API).pathname;
    if (!url.pathname.startsWith(`${prefix}/`)) return Response.json({ error: 'unexpected' }, { status: 500 });
    const rest = url.pathname.slice(prefix.length);
    const latest = srv.revisions.at(-1);
    if (rest === '/db' && req.method === 'GET') {
      if (!latest) return Response.json({ error: 'no database' }, { status: 404 });
      if (req.headers.get('If-None-Match') === `"${latest.revision}"`) return new Response(null, { status: 304, headers: { ETag: `"${latest.revision}"` } });
      return new Response(latest.blob, {
        headers: {
          ETag: `"${latest.revision}"`,
          'X-Cairn-Revision': String(latest.revision),
          'X-Cairn-Epoch': String(latest.epoch),
          'X-Cairn-Record': e2e.b64(enc.encode(latest.record)),
          'X-Cairn-Signer-Key': latest.signerKey,
        },
      });
    }
    if (rest === '/db' && req.method === 'PUT') {
      const want = `"${latest ? latest.revision : 0}"`;
      if (req.headers.get('If-Match') !== want) return Response.json({ error: 'stale' }, { status: 412, headers: { ETag: want } });
      const form = await req.formData();
      const record = form.get('record');
      const body = e2e.decodeStrict(e2e.unb64(JSON.parse(record).body), e2e.BODY_SCHEMAS.revision);
      const blob = new Uint8Array(await form.get('blob').arrayBuffer());
      srv.revisions.push({ revision: body.revision, epoch: body.epoch, blob, record, signerKey: srv.signerKey });
      return Response.json({ revision: body.revision });
    }
    if (rest === '/files' && req.method === 'GET') {
      return Response.json([...[...srv.files.entries()].map(([address, f]) => srv.listItem(address, f)), ...srv.extraItems]);
    }
    const m = /^\/files\/([0-9a-f]{64})$/.exec(rest);
    if (m) {
      const f = srv.files.get(m[1]);
      if (req.method === 'GET') {
        if (!f) return Response.json({ error: 'not found' }, { status: 404 });
        return new Response(f.blob, {
          headers: { 'X-Cairn-Epoch': String(f.epoch), 'X-Cairn-Record': e2e.b64(enc.encode(f.record)), 'X-Cairn-Signer-Key': f.signerKey },
        });
      }
      if (req.method === 'PUT') {
        const form = await req.formData();
        const record = form.get('record');
        const body = e2e.decodeStrict(e2e.unb64(JSON.parse(record).body), e2e.BODY_SCHEMAS.record);
        srv.files.set(m[1], {
          epoch: body.epoch,
          record,
          blob: new Uint8Array(await form.get('blob').arrayBuffer()),
          metaRecord: form.get('metaRecord'),
          meta: new Uint8Array(await form.get('meta').arrayBuffer()),
          signerKey: srv.signerKey,
          order: [...form.keys()],
        });
        return new Response(null, { status: 204 });
      }
      if (req.method === 'DELETE') {
        if (!f) return Response.json({ error: 'not found' }, { status: 404 });
        srv.files.delete(m[1]);
        return new Response(null, { status: 204 });
      }
    }
    return Response.json({ error: 'unexpected' }, { status: 500 });
  };
  return srv;
}

function setup({ keys = baseKeys(), sign = signer() } = {}) {
  const srv = fakeServer();
  const warnings = [];
  const ctx = {
    keys,
    origin: ORIGIN,
    fetchFn: srv.fetch,
    sign,
    seen: new Map(),
    now: () => new Date('2026-10-05T12:00:00Z'),
    warn: (m) => warnings.push(m),
  };
  const call = (path, init = {}) => {
    const url = `${API}/${path}`;
    const route = parseDataPath(new URL(url).pathname);
    assert.ok(route, `not a data route: ${path}`);
    return handleData(ctx, route, new Request(url, init));
  };
  return { srv, ctx, call, warnings };
}

const putDb = (call, bytes, rev) => call('db', { method: 'PUT', headers: { 'If-Match': `"${rev}"` }, body: bytes });
const bytes = async (res) => new Uint8Array(await res.arrayBuffer());

// sealedRevision stores a revision the test builds itself, for refusals.
async function sealedRevision(srv, { revision = 1, epoch = 4, ak = ak4, key = writer, user = USER, body = {}, ctx = {}, plain = enc.encode('db') } = {}) {
  const blob = await e2e.sealBlob(ak, { artifact: ARTIFACT, version: VERSION, kind: 'database', name: String(revision), ...ctx }, plain);
  const b = { v: 1, artifact: ARTIFACT, version: VERSION, revision, epoch, sha256: await sha256Hex(blob), ...body };
  const env = await e2e.newEnvelope(key.seed, user, 'revision', enc.encode(JSON.stringify(b)));
  srv.revisions.push({ revision, epoch, blob, record: JSON.stringify(env), signerKey: e2e.b64(key.pub) });
}

test('parseDataPath picks out the database and file routes, and nothing else', () => {
  const p = `/api/artifacts/${ARTIFACT}/versions/${VERSION}`;
  assert.deepEqual(parseDataPath(`${p}/db`), { artifact: ARTIFACT, version: VERSION, route: 'db', path: null });
  assert.deepEqual(parseDataPath(`${p}/db/download`), { artifact: ARTIFACT, version: VERSION, route: 'download', path: null });
  assert.deepEqual(parseDataPath(`${p}/files`), { artifact: ARTIFACT, version: VERSION, route: 'files', path: null });
  assert.deepEqual(parseDataPath(`${p}/files/a%20b/c.txt`), { artifact: ARTIFACT, version: VERSION, route: 'file', path: 'a b/c.txt' });
  for (const bad of [
    `${p}/db/revisions`,
    `${p}/db/`,
    `${p}/files/`,
    `${p}/files/a//b`,
    `${p}/files/../x`,
    `${p}/files/%2e%2e/x`,
    `${p}/files/a%2Fb`,
    `${p}/files/a%5Cb`,
    `${p}/files/a%00b`,
    `${p}/files/a/./b`,
    `${p}/files/.`,
    `${p}/dbx`,
    `${p}/filesx`,
    `/api/artifacts/${ARTIFACT}-zz/versions/${VERSION}/db`,
    `/api/artifacts/${ARTIFACT}/versions/${VERSION.slice(0, -1)}/db`,
    `${p}/files/%E0%A4%A`,
    `${p}/manifest`,
    `/api/artifacts/${ARTIFACT}/versions/AAAAAAAA-2222-4222-8222-222222222222/db`,
    `/api/artifacts/${ARTIFACT}/db`,
    `/x/api/artifacts/${ARTIFACT}/versions/${VERSION}/db`,
  ]) {
    assert.equal(parseDataPath(bad), null, bad);
  }
});

test('db: a write is sealed and signed, and reads back as plaintext with its revision', async () => {
  const { srv, call } = setup();
  const none = await call('db');
  assert.equal(none.status, 404);
  assert.deepEqual(await none.json(), { error: 'no database yet' });
  const res = await putDb(call, enc.encode('first'), 0);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { revision: 1 });
  assert.equal(res.headers.get('ETag'), '"1"');
  const stored = srv.revisions[0];
  assert.equal(stored.epoch, 4, 'written under the current epoch');
  assert.ok(!new TextDecoder().decode(stored.blob).includes('first'), 'the server got plaintext');
  const sent = srv.calls.at(-1);
  assert.equal(sent.headers.get('Authorization'), 'Bearer tok');
  assert.equal(sent.headers.get('If-Match'), '"0"');
  const got = await call('db');
  assert.equal(got.status, 200);
  assert.equal(got.headers.get('ETag'), '"1"');
  assert.equal(got.headers.get('Content-Security-Policy'), CSP);
  assert.equal(got.headers.get('X-Content-Type-Options'), 'nosniff');
  assert.equal(got.headers.get('Cache-Control'), 'no-store');
  assert.equal(got.headers.get('Content-Disposition'), null, 'only a download is an attachment');
  assert.equal(new TextDecoder().decode(await bytes(got)), 'first');
});

test('db: a matching If-None-Match is a 304, and the record is not fetched again', async () => {
  const { call } = setup();
  await putDb(call, enc.encode('x'), 0);
  const res = await call('db', { headers: { 'If-None-Match': '"1"' } });
  assert.equal(res.status, 304);
  assert.equal(res.headers.get('ETag'), '"1"');
  assert.equal((await call('db', { headers: { 'If-None-Match': '"0"' } })).status, 200);
});

test('db: only an If-None-Match naming a revision is passed to the server', async () => {
  const { srv, call } = setup();
  await putDb(call, enc.encode('x'), 0);
  for (const inm of ['W/"1"', '1', '"1"x', 'x"1"', '"01"', '*', '"12345678901234567"']) {
    await call('db', { headers: { 'If-None-Match': inm } });
    assert.equal(srv.calls.at(-1).headers.get('If-None-Match'), null, inm);
  }
  for (const inm of ['"1"', '"0"']) {
    await call('db', { headers: { 'If-None-Match': inm } });
    assert.equal(srv.calls.at(-1).headers.get('If-None-Match'), inm);
  }
});

test('db: a 304 with no ETag answers with the revision the client named', async () => {
  const { srv, call } = setup();
  srv.hook = (req) => (req.method === 'GET' ? new Response(null, { status: 304 }) : undefined);
  const res = await call('db', { headers: { 'If-None-Match': '"1"' } });
  assert.equal(res.status, 304);
  assert.equal(res.headers.get('ETag'), '"1"');
  assert.equal(res.headers.get('Content-Security-Policy'), CSP);
});

test('db: download is the plaintext as database.db', async () => {
  const { call } = setup();
  await putDb(call, enc.encode('dl'), 0);
  const res = await call('db/download', { headers: { 'If-None-Match': '"1"' } });
  assert.equal(res.status, 200, 'a download ignores If-None-Match');
  assert.equal(res.headers.get('Content-Disposition'), 'attachment; filename="database.db"');
  assert.equal(res.headers.get('Content-Security-Policy'), CSP);
  assert.equal(new TextDecoder().decode(await bytes(res)), 'dl');
});

test('db: a write needs If-Match naming a revision, and sends nothing without one', async () => {
  for (const h of [undefined, '1', '"x"', '"01"', 'W/"1"', '"1"x', 'x"1"', '"12345678901234567"']) {
    const { srv, call } = setup();
    const res = await call('db', { method: 'PUT', headers: h === undefined ? {} : { 'If-Match': h }, body: 'x' });
    assert.equal(res.status, 428, String(h));
    assert.equal(srv.calls.length, 0, String(h));
  }
});

test('db: a stale write passes on the 412 with the latest ETag, and the revision moves on', async () => {
  const { srv, call } = setup();
  await putDb(call, enc.encode('a'), 0);
  const res = await putDb(call, enc.encode('b'), 0);
  assert.equal(res.status, 412);
  assert.equal(res.headers.get('ETag'), '"1"');
  assert.equal((await putDb(call, enc.encode('b'), 1)).status, 200);
  assert.equal(srv.revisions.at(-1).revision, 2);
});

test('db: the revision signed is the one after If-Match', async () => {
  const { srv, call } = setup();
  srv.hook = async (req) => {
    if (req.method !== 'PUT') return undefined;
    const form = await req.formData();
    const body = e2e.decodeStrict(e2e.unb64(JSON.parse(form.get('record')).body), e2e.BODY_SCHEMAS.revision);
    assert.deepEqual([...form.keys()], ['record', 'blob']);
    assert.equal(body.revision, 8);
    assert.equal(body.epoch, 4);
    assert.equal(body.sha256, await sha256Hex(new Uint8Array(await form.get('blob').arrayBuffer())));
    return Response.json({ revision: 8 });
  };
  assert.equal((await putDb(call, enc.encode('x'), 7)).status, 200);
});

test('db: other server refusals pass on with their message', async () => {
  for (const status of [409, 413, 403]) {
    const { srv, call } = setup();
    srv.hook = (req) => (req.method === 'PUT' ? Response.json({ error: `nope ${status}` }, { status, headers: { ETag: '"9"' } }) : undefined);
    const res = await putDb(call, enc.encode('x'), 0);
    assert.equal(res.status, status);
    assert.equal(res.headers.get('ETag'), null, 'only a 412 carries the latest ETag');
    assert.deepEqual(await res.json(), { error: `nope ${status}` });
  }
});

test('db: a 412 with no ETag passes on none, and a refusal that is not JSON keeps its status', async () => {
  const { srv, call } = setup();
  srv.hook = (req) => (req.method === 'PUT' ? Response.json({ error: 'stale' }, { status: 412 }) : undefined);
  const res = await putDb(call, enc.encode('x'), 0);
  assert.equal(res.status, 412);
  assert.equal(res.headers.get('ETag'), null);
  for (const [body, status] of [['<html>', 502], [JSON.stringify({ error: 5 }), 403], ['null', 500]]) {
    srv.hook = () => new Response(body, { status });
    const got = await call('db');
    assert.equal(got.status, status);
    assert.deepEqual(await got.json(), { error: `the server answered ${status}` });
  }
});

test('db: a write lower than a revision already read leaves the highest seen', async () => {
  const { srv, call } = setup();
  await sealedRevision(srv, { revision: 5 });
  assert.equal((await call('db')).status, 200);
  srv.hook = (req) => (req.method === 'PUT' ? Response.json({ revision: 2 }) : undefined);
  assert.equal((await putDb(call, enc.encode('x'), 1)).status, 200);
  srv.hook = null;
  srv.revisions.length = 0;
  await sealedRevision(srv, { revision: 4 });
  assert.equal((await call('db')).status, 502);
});

test('db: a read counts as seen, so the server cannot serve the revision before it', async () => {
  const { srv, call } = setup();
  await sealedRevision(srv, { revision: 2 });
  assert.equal((await call('db')).status, 200);
  srv.revisions.length = 0;
  await sealedRevision(srv, { revision: 1 });
  const res = await call('db');
  assert.equal(res.status, 502);
  assert.match((await res.json()).error, /older than revision 2/);
  srv.revisions.length = 0;
  await sealedRevision(srv, { revision: 2 });
  assert.equal((await call('db')).status, 200, 'the same revision again is fine');
});

test('db: the shell refusing to sign is a 403, and nothing is sent', async () => {
  const { srv, call } = setup({
    sign: async () => {
      throw new Error('you cannot write here');
    },
  });
  const res = await putDb(call, enc.encode('x'), 0);
  assert.equal(res.status, 403);
  assert.deepEqual(await res.json(), { error: 'you cannot write here' });
  assert.equal(srv.calls.length, 0);
});

test('db: an answer from the shell that is not envelopes is a 403', async () => {
  for (const answer of [null, [], [null], [{ body: 'x', sig: 'y' }], [{ body: 1, sig: 'y', signer: USER }], [{ body: 'x', sig: 1, signer: USER }], 'x']) {
    const { srv, call } = setup({ sign: async () => answer });
    assert.equal((await putDb(call, enc.encode('x'), 0)).status, 403, JSON.stringify(answer));
    assert.equal(srv.calls.length, 0);
  }
});

test('db: with no AK for the current epoch, a write is a 403', async () => {
  const { srv, call } = setup({ keys: baseKeys({ aks: { 3: e2e.b64(ak3) } }) });
  assert.equal((await putDb(call, enc.encode('x'), 0)).status, 403);
  assert.equal(srv.calls.length, 0);
});

test('db: a revision passes every check, under an earlier epoch too', async () => {
  const { srv, call } = setup();
  await sealedRevision(srv, { epoch: 3, ak: ak3 });
  const res = await call('db');
  assert.equal(res.status, 200);
  assert.equal(new TextDecoder().decode(await bytes(res)), 'db');
});

const refusals = {
  'a signer who is not a writer': { user: OTHER, msg: /may not write/ },
  'a key not listed for the signer': { key: stranger, msg: /may not write/ },
  'another artifact': { body: { artifact: OTHER }, msg: /another artifact/ },
  'another version': { body: { version: V2 }, msg: /another version/ },
  'another revision than the header': { body: { revision: 2 }, msg: /another revision/ },
  'another epoch than the header': { body: { epoch: 3 }, msg: /another epoch than the server named/ },
  'a sha256 that is not the blob': { body: { sha256: '0'.repeat(64) }, msg: /does not match its signature/ },
  'a blob sealed for another revision': { ctx: { name: '2' } },
  'a blob sealed under another AK': { ak: ak3 },
  'a body version that is not 1': { body: { v: 2 } },
};
for (const [what, over] of Object.entries(refusals)) {
  test(`db: a revision with ${what} is refused`, async () => {
    const { srv, call } = setup();
    await sealedRevision(srv, over);
    const res = await call('db');
    assert.equal(res.status, 502);
    const { error } = await res.json();
    assert.match(error, /could not be verified/);
    if (over.msg) assert.match(error, over.msg);
  });
}

test('db: a revision under an epoch before the version is refused, even with its AK', async () => {
  const ak2 = randomBytes(32);
  const { srv, call } = setup({ keys: baseKeys({ aks: { 2: e2e.b64(ak2), 3: e2e.b64(ak3), 4: e2e.b64(ak4) } }) });
  await sealedRevision(srv, { epoch: 2, ak: ak2 });
  const res = await call('db');
  assert.equal(res.status, 502);
  assert.match((await res.json()).error, /before the version/);
});

test('db: a revision under an epoch the keys hold no AK for is refused', async () => {
  const { srv, call } = setup({ keys: baseKeys({ aks: { 4: e2e.b64(ak4) } }) });
  await sealedRevision(srv, { epoch: 3, ak: ak3 });
  assert.match((await (await call('db')).json()).error, /no key for epoch 3/);
});

test('db: while publicWrites is on, any signer is accepted', async () => {
  const { srv, call } = setup({ keys: baseKeys({ publicWrites: true }) });
  await sealedRevision(srv, { user: OTHER, key: stranger });
  assert.equal((await call('db')).status, 200);
});

test('db: a revision lower than one already seen is refused', async () => {
  const { srv, call } = setup();
  await putDb(call, enc.encode('a'), 0);
  await putDb(call, enc.encode('b'), 1);
  assert.equal((await call('db')).status, 200);
  srv.revisions.pop();
  const res = await call('db');
  assert.equal(res.status, 502);
  assert.match((await res.json()).error, /older than revision 2/);
});

test('db: a write counts as seen, so the server cannot serve the revision before it', async () => {
  const { srv, call } = setup();
  await putDb(call, enc.encode('a'), 0);
  await putDb(call, enc.encode('b'), 1);
  srv.revisions.pop();
  assert.equal((await call('db')).status, 502);
});

test('db: a read answered before a write lands is not taken for a rollback', async () => {
  const { srv, ctx, call } = setup();
  await putDb(call, enc.encode('a'), 0);
  // Another page's write of revision 2 lands while this read of 1 is in flight.
  let raced = false;
  ctx.fetchFn = async (req) => {
    const res = await srv.fetch(req);
    if (req.method === 'GET' && !raced) {
      raced = true;
      assert.equal((await putDb(call, enc.encode('b'), 1)).status, 200);
    }
    return res;
  };
  const res = await call('db');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('ETag'), '"1"');
  assert.equal(ctx.seen.get(VERSION), 2, 'the slower read does not lower what was seen');
  srv.revisions.pop();
  assert.equal((await call('db')).status, 502, 'a read sent after the write may not go below it');
});

test('db: a 304 for a revision below one already seen is refused', async () => {
  const { srv, call } = setup();
  await putDb(call, enc.encode('a'), 0);
  await putDb(call, enc.encode('b'), 1);
  srv.revisions.pop();
  const res = await call('db', { headers: { 'If-None-Match': '"1"' } });
  assert.equal(res.status, 502);
  assert.match((await res.json()).error, /older than revision 2/);
});

test('db: a 304 to a read that named no revision is refused', async () => {
  const { srv, call } = setup();
  srv.hook = (req) => (req.method === 'GET' ? new Response(null, { status: 304, headers: { ETag: '"1"' } }) : undefined);
  const res = await call('db');
  assert.equal(res.status, 502);
  assert.match((await res.json()).error, /a 304 to a read that named no revision/);
});

test('db: malformed headers are refused, each for its own reason', async () => {
  for (const [name, value, why] of [
    ['X-Cairn-Revision', '01', /revision is not a number/],
    ['X-Cairn-Revision', '1x', /revision is not a number/],
    ['X-Cairn-Revision', '12345678901234567', /revision is not a number/],
    ['X-Cairn-Revision', null, /revision is not a number/],
    ['X-Cairn-Epoch', 'x', /epoch is not a number/],
    ['X-Cairn-Epoch', '04', /epoch is not a number/],
    ['X-Cairn-Epoch', '4x', /epoch is not a number/],
    ['X-Cairn-Epoch', '+4', /epoch is not a number/],
    ['X-Cairn-Epoch', '12345678901234567', /epoch is not a number/],
    ['X-Cairn-Epoch', null, /epoch is not a number/],
    ['X-Cairn-Record', '!!', /./],
    ['X-Cairn-Record', null, /no record/],
    ['X-Cairn-Signer-Key', '!!', /not base64url/],
    ['X-Cairn-Signer-Key', e2e.b64(new Uint8Array(31)), /not 32 bytes/],
    ['X-Cairn-Signer-Key', e2e.b64(new Uint8Array(33)), /not 32 bytes/],
  ]) {
    const { srv, call } = setup();
    await putDb(call, enc.encode('a'), 0);
    const real = srv.fetch;
    const res0 = await real(new Request(`${API}/db`));
    const h = new Headers(res0.headers);
    if (value === null) h.delete(name);
    else h.set(name, value);
    const blob = await res0.arrayBuffer();
    srv.hook = (req) => (req.method === 'GET' ? new Response(blob, { headers: h }) : undefined);
    const res = await call('db');
    assert.equal(res.status, 502, `${name}: ${value}`);
    assert.match((await res.json()).error, why, `${name}: ${value}`);
  }
});

test('db: a server failure on read passes on', async () => {
  const { srv, call } = setup();
  srv.hook = () => Response.json({ error: 'gone' }, { status: 403 });
  const res = await call('db');
  assert.equal(res.status, 403);
  assert.deepEqual(await res.json(), { error: 'gone' });
});

test('methods a route does not take are refused', async () => {
  const { srv, call } = setup();
  for (const [path, method] of [
    ['db', 'POST'],
    ['db', 'DELETE'],
    ['db/download', 'PUT'],
    ['files', 'PUT'],
    ['files/a.txt', 'POST'],
    ['files/a.txt', 'HEAD'],
    ['db', 'constructor'],
    ['files/a.txt', 'toString'],
  ]) {
    const res = await call(path, { method, body: method === 'HEAD' ? undefined : method === 'POST' || method === 'PUT' ? 'x' : undefined });
    assert.equal(res.status, 405, `${method} ${path}`);
  }
  assert.equal(srv.calls.length, 0);
});

// files

test('files: a file is stored under its address, with nothing of its path on the server', async () => {
  const { srv, call } = setup();
  const res = await call('files/notes/a%20b.txt', { method: 'PUT', body: 'hello' });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { path: 'notes/a b.txt', size: 5, modifiedAt: '2026-10-05T12:00:00.000Z' });
  const address = await e2e.fileAddress(await e2e.fileKey(ak4, ARTIFACT, 4), 'notes/a b.txt');
  const f = srv.files.get(address);
  assert.ok(f, 'not stored at its address');
  assert.deepEqual(f.order, ['record', 'blob', 'metaRecord', 'meta']);
  assert.equal(f.epoch, 4);
  for (const req of srv.calls) assert.ok(!req.url.includes('notes'), req.url);
  const all = new TextDecoder().decode(new Uint8Array([...f.blob, ...f.meta]));
  assert.ok(!all.includes('hello') && !all.includes('notes'), 'the server got plaintext');
  const meta = e2e.decodeStrict(e2e.unb64(JSON.parse(f.metaRecord).body), e2e.BODY_SCHEMAS.record);
  assert.equal(meta.kind, 'file-meta');
  assert.equal(meta.name, address);
  assert.equal(meta.sha256, await sha256Hex(f.meta));
});

test('files: list, get, and delete by path', async () => {
  const { call } = setup();
  await call('files/b.txt', { method: 'PUT', body: 'bee' });
  await call('files/a.png', { method: 'PUT', body: 'png' });
  const list = await (await call('files')).json();
  assert.deepEqual(
    list.map((f) => [f.path, f.size]),
    [
      ['a.png', 3],
      ['b.txt', 3],
    ],
  );
  const got = await call('files/a.png');
  assert.equal(got.status, 200);
  assert.equal(got.headers.get('Content-Type'), 'image/png');
  assert.equal(got.headers.get('Content-Security-Policy'), CSP);
  assert.equal(new TextDecoder().decode(await bytes(got)), 'png');
  assert.equal((await call('files/a.png', { method: 'DELETE' })).status, 204);
  assert.equal((await call('files/a.png')).status, 404);
  assert.equal((await call('files/a.png', { method: 'DELETE' })).status, 404);
});

// storeAt stores a file the test builds itself, under epoch and ak, with
// overrides for each refusal.
async function storeAt(srv, path, { epoch = 3, ak = ak3, key = writer, user = USER, text = 'old', metaPath = path, record = {}, metaRecord = {}, metaOver = {}, address = null } = {}) {
  const addr = address ?? (await e2e.fileAddress(await e2e.fileKey(ak, ARTIFACT, epoch), path));
  const c = (kind) => ({ artifact: ARTIFACT, version: VERSION, kind, name: addr });
  const blob = await e2e.sealBlob(ak, c('file'), enc.encode(text));
  const meta = await e2e.sealBlob(ak, c('file-meta'), enc.encode(JSON.stringify({ v: 1, path: metaPath, size: text.length, modifiedAt: 't', ...metaOver })));
  const envOf = async (kind, b, over) =>
    JSON.stringify(
      await e2e.newEnvelope(
        key.seed,
        user,
        'record',
        enc.encode(JSON.stringify({ v: 1, ...c(kind), epoch, sha256: await sha256Hex(b), ...over })),
      ),
    );
  srv.files.set(addr, {
    epoch,
    blob,
    meta,
    record: await envOf('file', blob, record),
    metaRecord: await envOf('file-meta', meta, metaRecord),
    signerKey: e2e.b64(key.pub),
  });
  return addr;
}

test('files: a file from an earlier epoch is read, and a write moves it to the current one', async () => {
  const { srv, call } = setup();
  const old = await storeAt(srv, 'x.txt');
  assert.equal(new TextDecoder().decode(await bytes(await call('files/x.txt'))), 'old');
  assert.deepEqual(
    (await (await call('files')).json()).map((f) => f.path),
    ['x.txt'],
  );
  await call('files/x.txt', { method: 'PUT', body: 'new' });
  assert.ok(!srv.files.has(old), 'the earlier address was not deleted');
  assert.equal(srv.files.size, 1);
  assert.equal(new TextDecoder().decode(await bytes(await call('files/x.txt'))), 'new');
});

test('files: when a path is under two epochs, the list and a read take the newer', async () => {
  const { srv, call } = setup();
  await storeAt(srv, 'x.txt', { text: 'old' });
  await storeAt(srv, 'x.txt', { epoch: 4, ak: ak4, text: 'newer' });
  const list = await (await call('files')).json();
  assert.deepEqual(list, [{ path: 'x.txt', size: 5, modifiedAt: 't' }]);
  assert.equal(new TextDecoder().decode(await bytes(await call('files/x.txt'))), 'newer');
});

test('files: a delete removes the path under every epoch', async () => {
  const { srv, call } = setup();
  await storeAt(srv, 'x.txt');
  await storeAt(srv, 'x.txt', { epoch: 4, ak: ak4 });
  assert.equal((await call('files/x.txt', { method: 'DELETE' })).status, 204);
  assert.equal(srv.files.size, 0);
});

test('files: a delete the server refuses passes on', async () => {
  const { srv, call } = setup();
  srv.hook = (req) => (req.method === 'DELETE' ? Response.json({ error: 'no' }, { status: 403 }) : undefined);
  assert.equal((await call('files/x.txt', { method: 'DELETE' })).status, 403);
});

// listedAs moves a stored file's list entry under another address, as a
// server that lies about it would.
async function listedAs(srv, path, change) {
  const a = await storeAt(srv, path);
  const f = srv.files.get(a);
  srv.files.delete(a);
  srv.extraItems.push({ ...srv.listItem(a, f), ...change(a) });
}

test('files: an entry that fails a check is left out of the list, with a warning that names it', async () => {
  const cases = {
    'metadata moved onto another address': [
      async (srv) => {
        const a = await storeAt(srv, 'a.txt');
        const b = await storeAt(srv, 'b.txt');
        const fa = srv.files.get(a);
        const fb = srv.files.get(b);
        srv.files.set(a, { ...fa, meta: fb.meta, metaRecord: fb.metaRecord });
        srv.files.delete(b);
      },
      /signed for another address/,
    ],
    'metadata naming a path whose address is another': [
      async (srv) => {
        const addr = await e2e.fileAddress(await e2e.fileKey(ak3, ARTIFACT, 3), 'real.txt');
        await storeAt(srv, 'real.txt', { metaPath: 'fake.txt', address: addr });
      },
      /belongs to another file/,
    ],
    'a signer who is not a writer': [(srv) => storeAt(srv, 'a.txt', { user: OTHER, key: stranger }), /may not write/],
    'a record of the wrong kind': [(srv) => storeAt(srv, 'a.txt', { record: { kind: 'file-meta' } }), /another kind/],
    'a meta record of the wrong kind': [(srv) => storeAt(srv, 'a.txt', { metaRecord: { kind: 'file' } }), /another kind/],
    'a record for another address': [(srv) => storeAt(srv, 'a.txt', { record: { name: 'f'.repeat(64) } }), /another address/],
    'a meta sha256 that is not the blob': [(srv) => storeAt(srv, 'a.txt', { metaRecord: { sha256: '0'.repeat(64) } }), /does not match its signature/],
    'an invalid path': [(srv) => storeAt(srv, '../a.txt'), /path is not valid/],
    'an epoch the entry does not match': [
      async (srv) => {
        const a = await storeAt(srv, 'a.txt');
        srv.files.get(a).epoch = 4;
      },
      /another epoch than the server named/,
    ],
    'an epoch that is not a number': [(srv) => listedAs(srv, 'a.txt', () => ({ epoch: '3' })), /epoch is not a number/],
    'metadata of another version': [(srv) => storeAt(srv, 'a.txt', { metaOver: { v: 2 } }), /metadata version unsupported/],
    'an entry that is null': [(srv) => srv.extraItems.push(null), /not an object/],
    'an entry that is a number': [(srv) => srv.extraItems.push(5), /not an object/],
    'an address that is short': [(srv) => listedAs(srv, 'a.txt', (a) => ({ address: a.slice(0, 32) })), /address is not 64 hex/],
    'an address that is long': [(srv) => listedAs(srv, 'a.txt', (a) => ({ address: `${a}0` })), /address is not 64 hex/],
    'an address with a prefix': [(srv) => listedAs(srv, 'a.txt', (a) => ({ address: `x${a}` })), /address is not 64 hex/],
    'an address in capitals': [(srv) => listedAs(srv, 'a.txt', (a) => ({ address: a.toUpperCase() })), /address is not 64 hex/],
    'an address that is not a string': [(srv) => listedAs(srv, 'a.txt', () => ({ address: 5 })), /address is not 64 hex/],
  };
  for (const [what, [build, why]] of Object.entries(cases)) {
    const { srv, call, warnings } = setup();
    await build(srv);
    await storeAt(srv, 'good.txt');
    const list = await (await call('files')).json();
    assert.deepEqual(
      list.map((f) => f.path),
      ['good.txt'],
      what,
    );
    assert.equal(warnings.length, 1, `${what}: ${warnings}`);
    assert.match(warnings[0], why, what);
  }
});

test('files: an empty file is listed with size 0, and a list in any order comes out sorted', async () => {
  for (const order of [
    ['c.txt', 'a.txt', 'b.txt'],
    ['b.txt', 'c.txt', 'a.txt'],
    ['a.txt', 'b.txt', 'c.txt'],
    ['c.txt', 'b.txt', 'a.txt'],
  ]) {
    const { srv, call } = setup();
    for (const path of order) await storeAt(srv, path, { text: path === 'a.txt' ? '' : 'x' });
    const list = await (await call('files')).json();
    assert.deepEqual(
      list.map((f) => [f.path, f.size]),
      [
        ['a.txt', 0],
        ['b.txt', 1],
        ['c.txt', 1],
      ],
      order.join(),
    );
  }
});

test('files: a path stored under two epochs lists the newer, whichever comes first', async () => {
  const { srv, call } = setup();
  await storeAt(srv, 'x.txt', { epoch: 4, ak: ak4, text: 'newer' });
  await storeAt(srv, 'x.txt', { text: 'old' });
  assert.deepEqual(await (await call('files')).json(), [{ path: 'x.txt', size: 5, modifiedAt: 't' }]);
});

test('files: a list that is not a list, or a refused list, fails', async () => {
  const { srv, call } = setup();
  srv.hook = () => Response.json({ not: 'a list' });
  const res = await call('files');
  assert.equal(res.status, 502);
  assert.match((await res.json()).error, /not a list/);
  srv.hook = () => Response.json({ error: 'x' }, { status: 403 });
  assert.equal((await call('files')).status, 403);
});

test('files: a read checks the record, the epoch header, and the blob', async () => {
  const cases = {
    'a record for another address': { record: { name: 'f'.repeat(64) } },
    'a signer who is not a writer': { user: OTHER, key: stranger },
    'a sha256 that is not the blob': { record: { sha256: '0'.repeat(64) } },
  };
  for (const [what, over] of Object.entries(cases)) {
    const { srv, call } = setup();
    await storeAt(srv, 'a.txt', over);
    assert.equal((await call('files/a.txt')).status, 502, what);
  }
  const { srv, call } = setup();
  const a = await storeAt(srv, 'a.txt');
  srv.files.get(a).epoch = 4;
  assert.equal((await call('files/a.txt')).status, 502, 'epoch header');
});

test('files: a write under no key for the current epoch is a 403', async () => {
  const { srv, call } = setup({ keys: baseKeys({ aks: { 3: e2e.b64(ak3) } }) });
  assert.equal((await call('files/a.txt', { method: 'PUT', body: 'x' })).status, 403);
  assert.equal(srv.calls.length, 0);
});

test('files: a write the server refuses passes on, and older copies stay', async () => {
  const { srv, call } = setup();
  const old = await storeAt(srv, 'a.txt');
  srv.hook = (req) => (req.method === 'PUT' ? Response.json({ error: 'too big' }, { status: 413 }) : undefined);
  const res = await call('files/a.txt', { method: 'PUT', body: 'x' });
  assert.equal(res.status, 413);
  assert.ok(srv.files.has(old));
});

test('checkSigned refuses a key that is not base64url or not 32 bytes', async () => {
  const env = await e2e.newEnvelope(writer.seed, USER, 'revision', enc.encode('{}'));
  await assert.rejects(checkSigned(baseKeys(), 'revision', env, '!!', { epoch: 4 }), /not base64url/);
  await assert.rejects(checkSigned(baseKeys(), 'revision', env, e2e.b64(new Uint8Array(16)), { epoch: 4 }), /not 32 bytes/);
  await assert.rejects(checkSigned(baseKeys(), 'revision', env, e2e.b64(new Uint8Array(33)), { epoch: 4 }), /not 32 bytes/);
});

test('files: an epoch the keys hold no AK for is skipped, and one before the version is not read', async () => {
  const ak2 = randomBytes(32);
  const { srv, call } = setup({ keys: baseKeys({ aks: { 4: e2e.b64(ak4) } }) });
  assert.equal((await call('files/a.txt')).status, 404);
  assert.equal((await call('files/a.txt', { method: 'DELETE' })).status, 404);
  const below = setup({ keys: baseKeys({ aks: { 2: e2e.b64(ak2), 3: e2e.b64(ak3), 4: e2e.b64(ak4) } }) });
  await storeAt(below.srv, 'a.txt', { epoch: 2, ak: ak2 });
  assert.equal((await below.call('files/a.txt')).status, 404, 'read from before the version');
  assert.equal((await below.call('files/a.txt', { method: 'DELETE' })).status, 404);
  assert.equal(below.srv.files.size, 1, 'deleted from before the version');
  assert.equal(srv.calls.length, 2, 'asked for an address it holds no key for');
});

test('files: a read the server refuses passes on', async () => {
  const { srv, call } = setup();
  srv.hook = (req) => (req.method === 'GET' ? Response.json({ error: 'denied' }, { status: 403 }) : undefined);
  const res = await call('files/a.txt');
  assert.equal(res.status, 403);
  assert.deepEqual(await res.json(), { error: 'denied' });
});

test('files: a delete finds the file under one epoch, either one', async () => {
  for (const [epoch, ak] of [
    [3, ak3],
    [4, ak4],
  ]) {
    const { srv, call } = setup();
    await storeAt(srv, 'x.txt', { epoch, ak });
    assert.equal((await call('files/x.txt', { method: 'DELETE' })).status, 204, `epoch ${epoch}`);
    assert.equal(srv.files.size, 0);
    assert.equal((await call('files/x.txt', { method: 'DELETE' })).status, 404);
  }
});

test('files: a write whose cleanup of older copies fails still succeeds', async () => {
  const { srv, call } = setup();
  const old = await storeAt(srv, 'a.txt');
  srv.hook = (req) => {
    if (req.method === 'DELETE') throw new TypeError('network down');
    return undefined;
  };
  const res = await call('files/a.txt', { method: 'PUT', body: 'new' });
  assert.equal(res.status, 200);
  assert.ok(srv.files.has(old));
});

test('checkSigned looks a signer up as its own entry, not through the prototype', async () => {
  const env = await e2e.newEnvelope(writer.seed, 'constructor', 'revision', enc.encode('{}'));
  await assert.rejects(checkSigned(baseKeys(), 'revision', env, e2e.b64(writer.pub), { epoch: 4 }), /may not write/);
});

test('db: a 304 answers with the revision the client named, whatever ETag the server sends', async () => {
  const { srv, call } = setup();
  await putDb(call, enc.encode('x'), 0);
  srv.hook = (req) => (req.method === 'GET' ? new Response(null, { status: 304, headers: { ETag: '"9"' } }) : undefined);
  const res = await call('db', { headers: { 'If-None-Match': '"1"' } });
  assert.equal(res.status, 304);
  assert.equal(res.headers.get('ETag'), '"1"');
});

test('files: a delete that fails part way leaves the newest copy, not an older one', async () => {
  const { srv, call } = setup();
  await storeAt(srv, 'x.txt', { text: 'old' });
  await storeAt(srv, 'x.txt', { epoch: 4, ak: ak4, text: 'newer' });
  const [older] = [...srv.files].find(([, f]) => f.epoch !== 4);
  srv.hook = (req) => (req.method === 'DELETE' && req.url.endsWith(older) ? Response.json({ error: 'disk on fire' }, { status: 500 }) : undefined);
  assert.notEqual((await call('files/x.txt', { method: 'DELETE' })).status, 204);
  srv.hook = null;
  assert.equal(new TextDecoder().decode(await bytes(await call('files/x.txt'))), 'newer');
});
