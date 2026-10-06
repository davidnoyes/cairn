// Tests for content.mjs: every function the content-origin worker leans on,
// with fixtures sealed and signed by e2e.mjs itself. Run with:
// node --test internal/server/web/*_test.mjs
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import * as c from './content.mjs';
import { APP, ARTIFACT, OTHER, USER, VERSION, enc, fixture, randomBytes, sha256Hex } from './content_fixture.mjs';

const dec = new TextDecoder();

describe('parseContentPath', () => {
  const p = (s) => c.parseContentPath(s);
  test('maps files and indexes', () => {
    assert.deepEqual(p(`/${VERSION}/a/b.js`), { version: VERSION, path: 'a/b.js' });
    assert.deepEqual(p(`/${VERSION}/`), { version: VERSION, path: 'index.html' });
    assert.deepEqual(p(`/${VERSION}/docs/`), { version: VERSION, path: 'docs/index.html' });
    assert.deepEqual(p(`/${VERSION}/a%20b/%C3%A9.txt`), { version: VERSION, path: 'a b/é.txt' });
  });
  test('refuses what could escape or confuse', () => {
    for (const bad of [
      `/${VERSION}`,
      `/${VERSION}/../x`,
      `/${VERSION}/a/./b`,
      `/${VERSION}/%2e%2e/x`,
      `/${VERSION}/a//b`,
      `/${VERSION}//a`,
      `/${VERSION}/a%00b`,
      `/${VERSION}/a%5Cb`,
      `/${VERSION}/a\\b`,
      `/${VERSION}/a%2Fb`,
      `/${VERSION}/%E0%A4%A`,
      '/AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA/a',
      '/not-a-uuid/a',
      '/',
      'x',
    ]) {
      assert.equal(p(bad), null, bad);
    }
  });
});

describe('contentTarget', () => {
  test('returns the address of a path inside the version', () => {
    assert.equal(c.contentTarget(VERSION, '/'), `/${VERSION}/`);
    assert.equal(c.contentTarget(VERSION, '/a/b.html'), `/${VERSION}/a/b.html`);
    assert.equal(c.contentTarget(VERSION, '/app/x%20y'), `/${VERSION}/app/x%20y`);
    assert.equal(c.contentTarget(VERSION, '/a b.html'), `/${VERSION}/a b.html`);
  });
  test('refuses a path a browser would resolve outside the version', () => {
    for (const path of [
      '/%2e%2e/api/x',
      '/.%2e/api/x',
      '/%2E%2e/api/x',
      '/../api/x',
      '/a/../../api/x',
      '/./x',
      '/.\t./api/x',
      '/.\n./api/x',
      '/\\..\\api/x',
      '/a//b',
      '//evil.example/x',
      'index.html',
      '',
      7,
      null,
    ]) {
      assert.equal(c.contentTarget(VERSION, path), null, JSON.stringify(path));
    }
  });
  test('refuses a version that is not a lowercase UUID', () => {
    for (const version of ['x', 'ABCDEF01-ABCD-4BCD-8BCD-ABCDEF012345', `${VERSION}/..`, 5, null]) {
      assert.equal(c.contentTarget(version, '/'), null, String(version));
    }
  });
});

describe('classifyRequest', () => {
  test('dispatches by prefix', () => {
    assert.equal(c.classifyRequest('/_cairn/boot').kind, 'cairn');
    assert.equal(c.classifyRequest('/_cairn').kind, 'cairn');
    assert.equal(c.classifyRequest('/api/users').kind, 'api');
    assert.deepEqual(c.classifyRequest(`/${VERSION}/x.js`), { kind: 'content', version: VERSION, path: 'x.js' });
    assert.equal(c.classifyRequest('/other').kind, 'none');
    assert.equal(c.classifyRequest(`/${VERSION}/../_cairn/x`).kind, 'none');
  });
});

describe('openManifest', () => {
  test('opens a good manifest, signed', async () => {
    const f = await fixture();
    const m = await c.openManifest(f.args);
    assert.equal(m.files.length, 3);
  });
  test('opens a good manifest through a vouch (no signer)', async () => {
    const f = await fixture({ signerUser: OTHER });
    assert.ok(await c.openManifest({ ...f.args, signer: null }));
  });
  test('refuses a wrong manifest hash', async () => {
    const f = await fixture();
    await assert.rejects(c.openManifest({ ...f.args, manifestHash: '0'.repeat(64) }), /hash/);
  });
  test('refuses a wrong signer user', async () => {
    const f = await fixture({ signerUser: OTHER });
    await assert.rejects(c.openManifest(f.args), /signer/);
  });
  test('refuses a signature by another key', async () => {
    const f = await fixture();
    const other = await e2e.generateEd25519();
    await assert.rejects(c.openManifest({ ...f.args, signer: { user: USER, ed25519: other.pub } }), /signature/);
  });
  test('refuses wrong epoch, version, and artifact', async () => {
    const f = await fixture();
    await assert.rejects(c.openManifest({ ...f.args, epoch: 4 }), /epoch/);
    const g = await fixture({ manifest: { epoch: 9 } });
    await assert.rejects(c.openManifest(g.args), /epoch/);
    const h = await fixture({ manifest: { version: OTHER } });
    await assert.rejects(c.openManifest(h.args), /version/);
    const i = await fixture({ manifest: { artifact: OTHER } });
    await assert.rejects(c.openManifest(i.args), /artifact/);
    const j = await fixture({ manifest: { v: 2 } });
    await assert.rejects(c.openManifest(j.args), /version/);
  });
  test('refuses a blob sealed for another context or key', async () => {
    const f = await fixture();
    await assert.rejects(c.openManifest({ ...f.args, version: OTHER }), e2e.DecryptError);
    await assert.rejects(c.openManifest({ ...f.args, ak: randomBytes(32) }), e2e.DecryptError);
    const g = await fixture({ ctx: { name: 'x' } });
    await assert.rejects(c.openManifest(g.args), e2e.DecryptError);
  });
  test('refuses a tampered or truncated manifest blob', async () => {
    const f = await fixture();
    const bad = f.manifestBlob.slice();
    bad[bad.length - 1] ^= 1;
    await assert.rejects(c.openManifest({ ...f.args, blob: bad }), e2e.DecryptError);
    await assert.rejects(c.openManifest({ ...f.args, blob: f.manifestBlob.slice(0, 40) }), e2e.DecryptError);
  });
  test('refuses bad entries', async () => {
    const good = { blob: '0'.repeat(32), size: 1, sha256: '0'.repeat(64) };
    const cases = {
      'duplicate path': [[{ path: 'a', ...good }, { path: 'a', ...good }], /duplicated/],
      'dotdot path': [[{ path: '../a', ...good }], /path invalid/],
      'empty segment': [[{ path: 'a//b', ...good }], /path invalid/],
      'leading slash': [[{ path: '/a', ...good }], /path invalid/],
      'backslash path': [[{ path: 'a\\b', ...good }], /path invalid/],
      'empty path': [[{ path: '', ...good }], /path invalid/],
      'short blob id': [[{ path: 'a', ...good, blob: '0'.repeat(31) }], /blob id/],
      'upper blob id': [[{ path: 'a', ...good, blob: 'A'.repeat(32) }], /blob id/],
      'bad sha': [[{ path: 'a', ...good, sha256: 'z'.repeat(64) }], /sha256/],
      'negative size': [[{ path: 'a', ...good, size: -1 }], /non-negative/],
    };
    for (const [name, [files, why]] of Object.entries(cases)) {
      const f = await fixture({ manifest: { files } });
      await assert.rejects(c.openManifest(f.args), why, name);
    }
  });
  test('refuses an unknown field in the body', async () => {
    const f = await fixture({ manifest: { extra: 1 } });
    await assert.rejects(c.openManifest(f.args), e2e.FormatError);
  });
});

describe('lookup', () => {
  const manifest = {
    files: [
      { path: 'index.html' },
      { path: 'a/b.js' },
      { path: 'cairn.js' },
    ],
  };
  test('finds files', () => {
    assert.equal(c.lookup(manifest, 'a/b.js').entry.path, 'a/b.js');
    assert.equal(c.lookup(manifest, 'cairn.js').kind, 'file');
  });
  test('serves helpers the manifest lacks', () => {
    for (const name of ['mermaid.js', 'sql-wasm.js', 'sql-wasm.wasm']) {
      assert.deepEqual(c.lookup(manifest, name), { kind: 'helper', name });
    }
    assert.equal(c.lookup(manifest, 'sub/cairn.js'), null);
  });
  test('falls back to index.html for a navigation without an extension', () => {
    assert.equal(c.lookup(manifest, 'some/route', { navigation: true }).entry.path, 'index.html');
    assert.equal(c.lookup(manifest, 'some/route', { navigation: false }), null);
    assert.equal(c.lookup(manifest, 'some/route'), null);
    assert.equal(c.lookup(manifest, 'missing.js', { navigation: true }), null);
    assert.equal(c.lookup(manifest, 'v1/route.v2', { navigation: true }), null);
  });
  test('redirects a directory without its trailing slash', () => {
    const m = { files: [{ path: 'index.html' }, { path: 'docs/index.html' }, { path: 'docs/a.html' }] };
    assert.deepEqual(c.lookup(m, 'docs', { navigation: true }), { kind: 'directory' });
    assert.deepEqual(c.lookup(m, 'docs', { navigation: false }), { kind: 'directory' });
    assert.equal(c.lookup(m, 'docs/index.html').entry.path, 'docs/index.html');
    assert.equal(c.lookup(m, 'doc', { navigation: true }).entry.path, 'index.html');
  });
  test('has no fallback without an index', () => {
    assert.equal(c.lookup({ files: [] }, 'route', { navigation: true }), null);
  });
});

describe('openFile', () => {
  test('opens each file', async () => {
    const f = await fixture();
    const m = await c.openManifest(f.args);
    for (const entry of m.files) {
      const plain = await c.openFile({ ak: f.ak, artifact: ARTIFACT, version: VERSION, entry, blob: f.blobs[entry.blob] });
      assert.equal(plain.length, entry.size);
    }
  });
  test('refuses a wrong hash, tamper, truncation, size, and context', async () => {
    const f = await fixture();
    const entry = f.entries[0];
    const blob = f.blobs[entry.blob];
    const args = { ak: f.ak, artifact: ARTIFACT, version: VERSION, entry, blob };
    await assert.rejects(c.openFile({ ...args, entry: { ...entry, sha256: '0'.repeat(64) } }), /sha256/);
    const tampered = blob.slice();
    tampered[tampered.length - 1] ^= 1;
    await assert.rejects(c.openFile({ ...args, blob: tampered }), /sha256/);
    // Hash matches the tampered bytes, so only decryption can refuse it.
    await assert.rejects(c.openFile({ ...args, blob: tampered, entry: { ...entry, sha256: await sha256Hex(tampered) } }));
    const short = blob.slice(0, blob.length - 3);
    await assert.rejects(c.openFile({ ...args, blob: short, entry: { ...entry, sha256: await sha256Hex(short) } }));
    await assert.rejects(c.openFile({ ...args, entry: { ...entry, size: entry.size + 1 } }), /size/);
    await assert.rejects(c.openFile({ ...args, entry: { ...entry, path: 'other.html' } }));
    await assert.rejects(c.openFile({ ...args, version: OTHER }));
  });
});

describe('mediaType', () => {
  test('uses the table', () => {
    assert.equal(c.mediaType('index.html'), 'text/html; charset=utf-8');
    assert.equal(c.mediaType('a/b.JS'), 'text/javascript; charset=utf-8');
    assert.equal(c.mediaType('x.css'), 'text/css; charset=utf-8');
    assert.equal(c.mediaType('x.wasm'), 'application/wasm');
    assert.equal(c.mediaType('x.woff2'), 'font/woff2');
    assert.equal(c.mediaType('x.svg'), 'image/svg+xml');
  });
  test('defaults to octet-stream', () => {
    assert.equal(c.mediaType('x.unknown'), 'application/octet-stream');
    assert.equal(c.mediaType('noext'), 'application/octet-stream');
    assert.equal(c.mediaType('a.b/noext'), 'application/octet-stream');
    assert.equal(c.mediaType('x.constructor'), 'application/octet-stream');
  });
});

describe('injectFrameScript', () => {
  const tag = '<script src="/_cairn/frame.js"></script>';
  const run = (s) => dec.decode(c.injectFrameScript(enc.encode(s)));
  test('goes first without a doctype', () => {
    assert.equal(run('<p>hi'), tag + '<p>hi');
    assert.equal(run(''), tag);
  });
  test('goes after a doctype, any case, with leading space', () => {
    assert.equal(run('<!DOCTYPE html><p>'), '<!DOCTYPE html>' + tag + '<p>');
    assert.equal(run('  \n<!doctype HTML PUBLIC "x">\n<p>'), '  \n<!doctype HTML PUBLIC "x">' + tag + '\n<p>');
  });
  test('keeps a byte-order mark first', () => {
    const out = c.injectFrameScript(new Uint8Array([0xef, 0xbb, 0xbf, ...enc.encode('<!DOCTYPE html>x')]));
    assert.deepEqual([...out.subarray(0, 3)], [0xef, 0xbb, 0xbf]);
    assert.equal(dec.decode(out.subarray(3)), '<!DOCTYPE html>' + tag + 'x');
    const bare = c.injectFrameScript(new Uint8Array([0xef, 0xbb, 0xbf, 0x78]));
    assert.equal(dec.decode(bare.subarray(3)), tag + 'x');
  });
  test('leaves a doctype-like text later alone', () => {
    assert.equal(run('<p><!DOCTYPE html>'), tag + '<p><!DOCTYPE html>');
  });
});

describe('contentHeaders', () => {
  test('sets the fixed headers and the CSP on HTML', () => {
    const h = c.contentHeaders('text/html; charset=utf-8', { appOrigin: APP });
    assert.equal(h['X-Content-Type-Options'], 'nosniff');
    assert.equal(h['Cache-Control'], 'no-store');
    assert.equal(h['Content-Type'], 'text/html; charset=utf-8');
    assert.equal(h['Content-Security-Policy'], `frame-ancestors ${APP}`);
  });
  test('leaves the CSP off anything else', () => {
    assert.equal(c.contentHeaders('text/css', { appOrigin: APP })['Content-Security-Policy'], undefined);
  });
});

function goodKeys() {
  const ak = e2e.b64(randomBytes(32));
  return {
    cairn: 'keys',
    artifact: ARTIFACT,
    version: VERSION,
    epoch: 3,
    ak,
    signer: { user: USER, ed25519: e2e.b64(randomBytes(32)) },
    manifestHash: '0'.repeat(64),
    token: 'tok',
    tokenExpires: '2030-01-01T00:00:00Z',
    linkToken: e2e.b64(randomBytes(16)),
    context: {
      artifact: { id: ARTIFACT, name: 'n', description: 'd' },
      users: [{ id: USER, name: 'u', email: 'u@example.com' }],
      versions: [{ id: VERSION, seq: 1, name: 'v1', changelog: 'first', createdAt: '2026-01-01T00:00:00Z' }],
    },
    path: '/index.html',
    aks: { 3: ak, 4: e2e.b64(randomBytes(32)) },
    currentEpoch: 4,
    writers: { [USER]: [e2e.b64(randomBytes(32))], [OTHER]: [] },
    publicWrites: false,
  };
}

describe('checkKeysMessage', () => {
  test('accepts a full message and the nullable forms', () => {
    assert.ok(c.checkKeysMessage(goodKeys()));
    const k = { ...goodKeys(), signer: null, token: null, tokenExpires: null, linkToken: null };
    k.context = { artifact: k.context.artifact, users: [], versions: [] };
    assert.ok(c.checkKeysMessage(k));
  });
  test('refuses unknown and missing fields', () => {
    assert.throws(() => c.checkKeysMessage({ ...goodKeys(), extra: 1 }), /fields/);
    const k = goodKeys();
    delete k.path;
    assert.throws(() => c.checkKeysMessage(k), /fields/);
    assert.throws(() => c.checkKeysMessage({ ...goodKeys(), signer: { ...goodKeys().signer, x: 1 } }), /fields/);
    const ctx = goodKeys().context;
    assert.throws(() => c.checkKeysMessage({ ...goodKeys(), context: { ...ctx, extra: 1 } }), /fields/);
    assert.throws(() => c.checkKeysMessage({ ...goodKeys(), context: { ...ctx, users: [{ id: USER, name: 'u' }] } }), /fields/);
    assert.throws(() => c.checkKeysMessage({ ...goodKeys(), context: { artifact: ctx.artifact, users: [] } }), /fields/);
    assert.throws(() => c.checkKeysMessage({ ...goodKeys(), context: { ...ctx, versions: [{ ...ctx.versions[0], meta: {} }] } }), /fields/);
  });
  test('refuses wrong types and values', () => {
    const bad = (over, why) => assert.throws(() => c.checkKeysMessage({ ...goodKeys(), ...over }), c.ContentError, why);
    bad({ cairn: 'token' }, 'type');
    bad({ artifact: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }, 'upper uuid');
    bad({ version: 'x' }, 'version');
    bad({ epoch: -1 }, 'negative epoch');
    bad({ epoch: 1.5 }, 'fraction epoch');
    bad({ epoch: '3' }, 'string epoch');
    bad({ ak: 'AAAA' }, 'short ak');
    bad({ ak: e2e.b64(randomBytes(32)) + '=' }, 'padded ak');
    // 16 bytes is a valid AES-128 key, so only the length check refuses it.
    assert.throws(() => c.checkKeysMessage({ ...goodKeys(), ak: e2e.b64(randomBytes(16)) }), /ak has the wrong length/);
    bad({ signer: { user: 'x', ed25519: e2e.b64(randomBytes(32)) } }, 'signer user');
    bad({ signer: { user: USER, ed25519: 'AAAA' } }, 'signer key');
    bad({ manifestHash: 'A'.repeat(64) }, 'upper hash');
    bad({ token: 5 }, 'token type');
    bad({ tokenExpires: {} }, 'expires type');
    bad({ linkToken: '+++' }, 'link token');
    bad({ path: 'index.html' }, 'path');
    bad({ path: '/%2e%2e/api/x' }, 'path climbing out of the version');
    bad({ path: '/.\t./api/x' }, 'path a browser resolves out of the version');
    bad({ context: null }, 'context');
    bad({ context: { artifact: { id: OTHER, name: 'n', description: 'd' }, users: [] } }, 'context artifact id');
    bad({ context: { artifact: { id: ARTIFACT, name: 1, description: 'd' }, users: [] } }, 'context name');
    bad({ context: { artifact: goodKeys().context.artifact, users: {} } }, 'users type');
    bad({ context: { artifact: goodKeys().context.artifact, users: [{ id: 'x', name: 'u', email: 'e' }] } }, 'user id');
    const ver = (over) => ({ context: { ...goodKeys().context, versions: [{ ...goodKeys().context.versions[0], ...over }] } });
    bad({ context: { ...goodKeys().context, versions: {} } }, 'versions type');
    bad(ver({ id: 'x' }), 'version id');
    bad(ver({ seq: 1.5 }), 'fraction seq');
    bad(ver({ seq: '1' }), 'string seq');
    bad(ver({ name: 1 }), 'version name');
    bad(ver({ changelog: null }), 'version changelog');
    bad(ver({ createdAt: 7 }), 'version createdAt');
    assert.throws(() => c.checkKeysMessage(null));
    assert.throws(() => c.checkKeysMessage([]));
  });
  test('accepts the data keys at the bounds, and refuses anything else', () => {
    const g = goodKeys();
    assert.ok(c.checkKeysMessage({ ...g, aks: { 3: g.ak }, currentEpoch: 3, writers: {}, publicWrites: true }));
    const bad = (over, why) => assert.throws(() => c.checkKeysMessage({ ...g, ...over }), c.ContentError, why);
    const key = () => e2e.b64(randomBytes(32));
    bad({ currentEpoch: 2 }, 'current epoch before the version');
    bad({ currentEpoch: '4' }, 'string current epoch');
    bad({ currentEpoch: 4.5 }, 'fraction current epoch');
    bad({ aks: null }, 'null aks');
    bad({ aks: [g.ak] }, 'array aks');
    bad({ aks: { 3: g.ak, 2: key() } }, 'aks before the version');
    bad({ aks: { 3: g.ak, 5: key() } }, 'aks after the current epoch');
    bad({ aks: { 3: g.ak, '04': key() } }, 'aks epoch not canonical');
    bad({ aks: { 3: g.ak, x: key() } }, 'aks epoch not a number');
    bad({ aks: { 3: g.ak, 4: 'AAAA' } }, 'short ak in aks');
    bad({ aks: { 4: key() } }, "aks without the version's AK");
    bad({ aks: { 3: key() } }, "aks with another AK for the version's epoch");
    bad({ writers: null }, 'null writers');
    bad({ writers: [] }, 'array writers');
    bad({ writers: { x: [] } }, 'writer not a uuid');
    bad({ writers: { [USER]: key() } }, 'writer keys not an array');
    bad({ writers: { [USER]: '' } }, 'writer keys an empty string, which has no elements to refuse');
    bad({ writers: { [USER]: ['AAAA'] } }, 'short writer key');
    bad({ publicWrites: 'false' }, 'string publicWrites');
    bad({ publicWrites: null }, 'null publicWrites');
  });
});

describe('checkTokenMessage', () => {
  test('accepts and refuses', () => {
    assert.ok(c.checkTokenMessage({ cairn: 'token', token: 't', tokenExpires: 5 }));
    assert.ok(c.checkTokenMessage({ cairn: 'token', token: null, tokenExpires: null }));
    assert.throws(() => c.checkTokenMessage({ cairn: 'token', token: 't' }));
    assert.throws(() => c.checkTokenMessage({ cairn: 'token', token: 1, tokenExpires: null }));
    assert.throws(() => c.checkTokenMessage({ cairn: 'keys', token: 't', tokenExpires: null }));
  });
});

describe('apiRequest', () => {
  const keys = goodKeys();
  const req = (path, init) => new Request(`http://x.localhost:8080${path}`, init);

  test('answers the artifact read from context', async () => {
    const res = c.apiRequest(req(`/api/artifacts/${ARTIFACT}`), keys);
    assert.ok(res instanceof Response);
    assert.deepEqual(await res.json(), keys.context.artifact);
  });
  test('answers the users read from context', async () => {
    const res = c.apiRequest(req('/api/users'), keys);
    assert.deepEqual(await res.json(), keys.context.users);
  });
  test('answers the versions read from context, since the server holds only their sealed names', async () => {
    const res = c.apiRequest(req(`/api/artifacts/${ARTIFACT}/versions`), keys);
    assert.ok(res instanceof Response);
    assert.deepEqual(await res.json(), keys.context.versions);
  });
  test('forwards any other artifact or method', () => {
    assert.ok(c.apiRequest(req(`/api/artifacts/${OTHER}`), keys) instanceof Request);
    assert.ok(c.apiRequest(req(`/api/artifacts/${ARTIFACT}`, { method: 'DELETE' }), keys) instanceof Request);
    assert.ok(c.apiRequest(req(`/api/artifacts/${OTHER}/versions`), keys) instanceof Request);
    assert.ok(c.apiRequest(req(`/api/artifacts/${ARTIFACT}/versions`, { method: 'POST' }), keys) instanceof Request);
  });
  test('adds the held credentials', () => {
    const out = c.apiRequest(req(`/api/artifacts/${ARTIFACT}/db`), keys);
    assert.equal(out.headers.get('Authorization'), 'Bearer tok');
    assert.equal(out.headers.get('X-Cairn-Link-Token'), keys.linkToken);
  });
  test('overwrites a caller-supplied credential', () => {
    const out = c.apiRequest(
      req('/api/x', { headers: { Authorization: 'Bearer evil', 'X-Cairn-Link-Token': 'evil', 'X-Other': 'keep' } }),
      keys,
    );
    assert.equal(out.headers.get('Authorization'), 'Bearer tok');
    assert.equal(out.headers.get('X-Cairn-Link-Token'), keys.linkToken);
    assert.equal(out.headers.get('X-Other'), 'keep');
  });
  test('drops a caller-supplied credential when none is held', () => {
    const none = { ...keys, token: null, linkToken: null };
    const out = c.apiRequest(req('/api/x', { headers: { Authorization: 'Bearer evil', 'X-Cairn-Link-Token': 'evil' } }), none);
    assert.equal(out.headers.get('Authorization'), null);
    assert.equal(out.headers.get('X-Cairn-Link-Token'), null);
    const nokeys = c.apiRequest(req('/api/x', { headers: { Authorization: 'Bearer evil' } }), null);
    assert.equal(nokeys.headers.get('Authorization'), null);
  });
});

describe('serveFile and fetchManifest', () => {
  const origin = `http://${ARTIFACT}.localhost:8080`;

  async function setup(over = {}) {
    const f = await fixture(over);
    const keys = { ...goodKeys(), ak: e2e.b64(f.ak), signer: { user: USER, ed25519: e2e.b64(f.key.pub) }, manifestHash: f.args.manifestHash };
    const seen = [];
    const byUrl = {
      [`${origin}/api/artifacts/${ARTIFACT}/versions/${VERSION}/manifest`]: f.manifestBlob,
      [`${origin}/_cairn/cairn.js`]: enc.encode('/*cairn*/'),
    };
    for (const [id, blob] of Object.entries(f.blobs)) {
      byUrl[`${origin}/api/artifacts/${ARTIFACT}/versions/${VERSION}/blobs/${id}`] = blob;
    }
    const fetchFn = async (r) => {
      const url = typeof r === 'string' ? r : r.url;
      seen.push(r);
      const body = byUrl[url];
      return body ? new Response(body) : new Response('no', { status: 404 });
    };
    return { f, keys, fetchFn, seen, byUrl };
  }
  const base = (s, path, navigation = false) => ({
    keys: s.keys, manifest: s.manifest, path, navigation, origin, appOrigin: APP, fetchFn: s.fetchFn,
  });

  test('serves a page with the frame script, and a script', async () => {
    const s = await setup();
    s.manifest = await c.fetchManifest({ keys: s.keys, origin, fetchFn: s.fetchFn });
    const html = await c.serveFile(base(s, 'index.html', true));
    assert.equal(html.status, 200);
    assert.equal(html.headers.get('Content-Security-Policy'), `frame-ancestors ${APP}`);
    assert.equal(await html.text(), '<script src="/_cairn/frame.js"></script><html>hi</html>');
    const js = await c.serveFile(base(s, 'app/main.js'));
    assert.equal(js.headers.get('Content-Type'), 'text/javascript; charset=utf-8');
    assert.equal(js.headers.get('Content-Security-Policy'), null);
    assert.equal(await js.text(), 'console.log(1)');
    const spa = await c.serveFile(base(s, 'some/route', true));
    assert.match(await spa.text(), /hi/);
  });
  test('sends credentials with the manifest and blob fetches', async () => {
    const s = await setup();
    s.manifest = await c.fetchManifest({ keys: s.keys, origin, fetchFn: s.fetchFn });
    await c.serveFile(base(s, 'app/main.js'));
    assert.ok(s.seen.length >= 2);
    for (const r of s.seen) assert.equal(r.headers.get('Authorization'), 'Bearer tok');
  });
  test('serves a helper from /_cairn/', async () => {
    const s = await setup();
    s.manifest = await c.fetchManifest({ keys: s.keys, origin, fetchFn: s.fetchFn });
    const res = await c.serveFile(base(s, 'cairn.js'));
    assert.equal(await res.text(), '/*cairn*/');
    assert.equal(res.headers.get('X-Content-Type-Options'), 'nosniff');
  });
  test('redirects a directory to its trailing slash', async () => {
    const s = await setup({ files: { 'index.html': '<html>hi</html>', 'my docs/index.html': '<p>d</p>' } });
    s.manifest = await c.fetchManifest({ keys: s.keys, origin, fetchFn: s.fetchFn });
    const res = await c.serveFile(base(s, 'my docs', true));
    assert.equal(res.status, 301);
    assert.equal(res.headers.get('Location'), `${origin}/${VERSION}/my%20docs/`);
    assert.equal(s.seen.length, 1);
  });
  test('encodes ? and # in a redirected directory name', async () => {
    const s = await setup({ files: { 'index.html': '<html>hi</html>', 'a?b#c/index.html': '<p>d</p>' } });
    s.manifest = await c.fetchManifest({ keys: s.keys, origin, fetchFn: s.fetchFn });
    const res = await c.serveFile(base(s, 'a?b#c', true));
    assert.equal(res.headers.get('Location'), `${origin}/${VERSION}/a%3Fb%23c/`);
  });
  test('sets the CSP on HTML fetched without navigating', async () => {
    const s = await setup();
    s.manifest = await c.fetchManifest({ keys: s.keys, origin, fetchFn: s.fetchFn });
    const html = await c.serveFile(base(s, 'index.html', false));
    assert.equal(html.headers.get('Content-Security-Policy'), `frame-ancestors ${APP}`);
  });
  test('answers 404 for a missing file', async () => {
    const s = await setup();
    s.manifest = await c.fetchManifest({ keys: s.keys, origin, fetchFn: s.fetchFn });
    assert.equal((await c.serveFile(base(s, 'nope.js'))).status, 404);
  });
  test('shows an error page for a tampered blob, with nothing from the version', async () => {
    const s = await setup();
    s.manifest = await c.fetchManifest({ keys: s.keys, origin, fetchFn: s.fetchFn });
    const id = s.f.entries.find((e) => e.path === 'app/main.js').blob;
    const url = `${origin}/api/artifacts/${ARTIFACT}/versions/${VERSION}/blobs/${id}`;
    const bad = s.byUrl[url].slice();
    bad[bad.length - 1] ^= 1;
    s.byUrl[url] = bad;
    const res = await c.serveFile(base(s, 'app/main.js'));
    assert.equal(res.status, 500);
    assert.doesNotMatch(await res.text(), /console/);
  });
  test('shows an error page when the blob is missing', async () => {
    const s = await setup();
    s.manifest = await c.fetchManifest({ keys: s.keys, origin, fetchFn: s.fetchFn });
    const id = s.f.entries.find((e) => e.path === 'app/main.js').blob;
    delete s.byUrl[`${origin}/api/artifacts/${ARTIFACT}/versions/${VERSION}/blobs/${id}`];
    assert.equal((await c.serveFile(base(s, 'app/main.js'))).status, 502);
  });
  test('shows the fixed error page for every serve-time verification failure', async () => {
    const blobUrl = (s, path) =>
      `${origin}/api/artifacts/${ARTIFACT}/versions/${VERSION}/blobs/${s.f.entries.find((e) => e.path === path).blob}`;
    const entryOf = (s, path) => s.manifest.files.find((e) => e.path === path);
    const flip = (b) => {
      const t = b.slice();
      t[t.length - 1] ^= 1;
      return t;
    };
    const cases = {
      'wrong sha256 in the entry': async (s) => {
        entryOf(s, 'app/main.js').sha256 = '0'.repeat(64);
      },
      'size mismatch': async (s) => {
        entryOf(s, 'app/main.js').size += 1;
      },
      'blob sealed under another path': async (s) => {
        const other = s.byUrl[blobUrl(s, 'index.html')];
        s.byUrl[blobUrl(s, 'app/main.js')] = other;
        entryOf(s, 'app/main.js').sha256 = await sha256Hex(other);
      },
      'blob of a different file': async (s) => {
        s.byUrl[blobUrl(s, 'app/main.js')] = s.byUrl[blobUrl(s, 'index.html')];
      },
      'tampered HTML': async (s) => {
        const bad = flip(s.byUrl[blobUrl(s, 'index.html')]);
        s.byUrl[blobUrl(s, 'index.html')] = bad;
        entryOf(s, 'index.html').sha256 = await sha256Hex(bad);
        return 'index.html';
      },
    };
    for (const [name, tamper] of Object.entries(cases)) {
      const s = await setup();
      s.manifest = await c.fetchManifest({ keys: s.keys, origin, fetchFn: s.fetchFn });
      const path = (await tamper(s)) ?? 'app/main.js';
      const res = await c.serveFile(base(s, path, true));
      assert.equal(res.status, 500, name);
      assert.equal(
        await res.text(),
        '<!DOCTYPE html><title>Cannot open</title><p>This version could not be verified, so it was not shown.</p>',
        name,
      );
      assert.equal(res.headers.get('Content-Type'), 'text/html; charset=utf-8', name);
      assert.equal(res.headers.get('X-Content-Type-Options'), 'nosniff', name);
      assert.equal(res.headers.get('Cache-Control'), 'no-store', name);
      assert.equal(res.headers.get('Content-Security-Policy'), null, name);
    }
  });
  test('answers 502 when a helper cannot be fetched', async () => {
    const s = await setup();
    s.manifest = await c.fetchManifest({ keys: s.keys, origin, fetchFn: s.fetchFn });
    delete s.byUrl[`${origin}/_cairn/cairn.js`];
    assert.equal((await c.serveFile(base(s, 'cairn.js'))).status, 502);
  });
  test('fetchManifest refuses a failed fetch and a wrong hash', async () => {
    const s = await setup();
    await assert.rejects(c.fetchManifest({ keys: s.keys, origin, fetchFn: async () => new Response('', { status: 404 }) }), /fetch/);
    await assert.rejects(c.fetchManifest({ keys: { ...s.keys, manifestHash: '1'.repeat(64) }, origin, fetchFn: s.fetchFn }), /hash/);
  });
});
