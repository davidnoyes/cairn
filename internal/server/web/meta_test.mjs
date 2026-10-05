// Tests for meta.mjs: reading and writing the encrypted metadata fields, with
// records built by e2e.mjs behind the fake server of viewer_fixture.mjs. Each
// read check has a test that breaks only that check. Run with:
// node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { ARTIFACT, ORIGIN, OTHER_ARTIFACT, V1, V2, buildWorld, fakeKeyStore, fakeStorage, keyStoreRecord, makeServer, makeUser } from './viewer_fixture.mjs';
import { openArtifact } from './viewer.mjs';
import { META_FIELDS, MetaError, describeArtifact, readMeta, writeMeta } from './meta.mjs';

const U = {};
for (const name of ['owner', 'editor', 'viewer', 'outsider']) U[name] = await makeUser(name);
const records = {};
for (const name of Object.keys(U)) records[name] = await keyStoreRecord(U[name]);
const enc = new TextEncoder();
const STD_MEMBERS = [
  { user: U.editor, role: 'editor' },
  { user: U.viewer, role: 'viewer' },
];

async function scene({ who = 'owner', members = STD_MEMBERS, epoch2 = false, isPublic = false, publicWrites = false } = {}) {
  const world = await buildWorld({ owner: U.owner, members, epoch2, isPublic, publicWrites });
  const server = makeServer(world, { who: U[who], linkTokenB64: '*' });
  const deps = { fetch: server.fetch, keyStore: fakeKeyStore(records[who]), storage: fakeStorage(), origin: ORIGIN };
  const opened = await openArtifact(deps, { artifact: ARTIFACT, link: null });
  return { world, server, deps, opened };
}

// item builds one meta item as the server serves it. Every part of the
// record and blob can be changed.
async function item(world, o = {}) {
  const signer = o.signer ?? U.owner;
  const field = o.field ?? 'name';
  const version = o.version ?? '';
  const epoch = o.epoch ?? 1;
  const ak = o.ak ?? world.aks[epoch];
  const plain = o.plain ?? enc.encode(o.value ?? 'Guestbook');
  const blob = await e2e.sealBlob(ak, { artifact: ARTIFACT, version: o.sealVersion ?? version, kind: 'meta', name: o.sealName ?? field }, plain);
  const sha256 = o.sha256 ?? (await e2e.bodyHash(blob));
  const body = {
    v: 1,
    artifact: o.artifact ?? ARTIFACT,
    version: o.bodyVersion ?? version,
    kind: o.kind ?? 'meta',
    name: o.name ?? field,
    epoch,
    sha256,
    ...o.extra,
  };
  const seed = o.seed ?? signer.ed.seed;
  const record = await e2e.newEnvelope(seed, o.signerId ?? signer.id, o.purpose ?? 'record', enc.encode(JSON.stringify(body)));
  const pub = o.signerKey ?? signer.ed.pub;
  return { record, signerKey: e2e.b64(pub), blob: e2e.b64(o.blobBytes ?? blob) };
}

const read = (s, meta, version = '') => readMeta(s.deps, s.opened, meta, version);

test('META_FIELDS lists the fields of each scope', () => {
  assert.deepEqual(META_FIELDS, { artifact: ['name', 'description'], version: ['name', 'changelog'] });
});

// ---- reading ----

test('readMeta reads an owner-signed field and an editor-signed one, as a member', async () => {
  const s = await scene({ who: 'viewer' });
  const meta = {
    name: await item(s.world, { value: 'Guestbook' }),
    description: await item(s.world, { field: 'description', signer: U.editor, value: 'Sign here' }),
  };
  assert.deepEqual(await read(s, meta), { values: { name: 'Guestbook', description: 'Sign here' }, unreadable: [] });
});

test('readMeta reads a version field under its version', async () => {
  const s = await scene();
  const meta = { changelog: await item(s.world, { field: 'changelog', version: V1, value: 'First' }) };
  assert.deepEqual(await read(s, meta, V1), { values: { changelog: 'First' }, unreadable: [] });
});

test('readMeta leaves a field nobody wrote out of both lists, and an empty value is a value', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { plain: new Uint8Array(0) }) };
  assert.deepEqual(await read(s, meta), { values: { name: '' }, unreadable: [] });
  assert.deepEqual(await read(s, {}), { values: {}, unreadable: [] });
  assert.deepEqual(await read(s, undefined), { values: {}, unreadable: [] });
});

test('readMeta ignores a field the scope does not have', async () => {
  const s = await scene();
  const meta = { changelog: await item(s.world, { field: 'changelog' }), name: await item(s.world) };
  assert.deepEqual(await read(s, meta), { values: { name: 'Guestbook' }, unreadable: [] });
});

test('readMeta keeps a leading byte-order mark', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { value: '﻿Bom' }) };
  assert.equal((await read(s, meta)).values.name, '﻿Bom');
});

test('readMeta reads a field sealed under an earlier epoch the reader holds', async () => {
  const s = await scene({ epoch2: true });
  const meta = { name: await item(s.world, { epoch: 1 }) };
  assert.deepEqual((await read(s, meta)).values, { name: 'Guestbook' });
});

test('one bad field does not make the others unreadable', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { kind: 'file' }), description: await item(s.world, { field: 'description', value: 'ok' }) };
  assert.deepEqual(await read(s, meta), { values: { description: 'ok' }, unreadable: ['name'] });
});

test('readMeta refuses a record signed by someone else under the owner id', async () => {
  const s = await scene();
  // The outsider signs and offers their own key, naming the owner as signer.
  const meta = { name: await item(s.world, { signerId: U.owner.id, seed: U.outsider.ed.seed, signerKey: U.outsider.ed.pub }) };
  assert.deepEqual(await read(s, meta), { values: {}, unreadable: ['name'] });
});

test('readMeta refuses a signature that does not verify under the offered key', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { seed: U.outsider.ed.seed }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a signer the chain never lists', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { signer: U.outsider }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a signer who is a viewer', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { signer: U.viewer }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses an editor the latest record no longer lists', async () => {
  const s = await scene({ members: [{ user: U.viewer, role: 'viewer' }] });
  const meta = { name: await item(s.world, { signer: U.editor }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a signer under a key other than the one the record lists', async () => {
  const s = await scene({ members: [{ user: U.editor, role: 'editor', fp: 'f'.repeat(64) }, { user: U.viewer, role: 'viewer' }] });
  const meta = { name: await item(s.world, { signer: U.editor }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses any signer through a public link with public writes on', async () => {
  const s = await scene({ isPublic: true, publicWrites: true });
  const meta = { name: await item(s.world, { signer: U.outsider }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a record of another purpose, even from the owner', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { purpose: 'revision', extra: {} }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a record body with a field the schema does not have', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { extra: { extra: 1 } }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a record of another kind', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { kind: 'file-meta' }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a record for another artifact', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { artifact: OTHER_ARTIFACT }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a record for another version, and an artifact record read as a version one', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { version: V1, bodyVersion: V2 }) };
  assert.deepEqual((await read(s, meta, V1)).unreadable, ['name']);
  const artifactField = { name: await item(s.world, {}) };
  assert.deepEqual((await read(s, artifactField, V1)).unreadable, ['name']);
});

test('readMeta refuses a record for another field name', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { name: 'description', sealName: 'name' }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a field whose blob was sealed under another field name', async () => {
  const s = await scene();
  // The record names the right field, but the blob is bound to another one.
  const meta = { name: await item(s.world, { sealName: 'description' }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a blob sealed for another version', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { sealVersion: V1 }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a record whose epoch is not the one the blob was sealed under', async () => {
  const s = await scene({ epoch2: true });
  const meta = { name: await item(s.world, { epoch: 2, ak: s.world.aks[1] }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a record of an epoch whose AK the reader does not hold', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { epoch: 2, ak: s.world.aks[2] }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a blob that does not match the signed hash', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { sha256: '0'.repeat(64) }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
  const swapped = await item(s.world, { value: 'Other' });
  const real = await item(s.world, { value: 'Real' });
  assert.deepEqual((await read(s, { name: { ...real, blob: swapped.blob } })).unreadable, ['name']);
});

test('readMeta refuses plaintext that is not UTF-8', async () => {
  const s = await scene();
  const meta = { name: await item(s.world, { plain: new Uint8Array([0xff, 0xfe, 0x41]) }) };
  assert.deepEqual((await read(s, meta)).unreadable, ['name']);
});

test('readMeta refuses a lone surrogate written as raw UTF-8 bytes', async () => {
  const s = await scene();
  // U+D800 as three bytes: what a hostile client writes, and TextEncoder never would.
  const meta = { name: await item(s.world, { plain: new Uint8Array([0x41, 0xed, 0xa0, 0x80, 0x42]) }) };
  assert.deepEqual(await read(s, meta), { values: {}, unreadable: ['name'] });
});

test('readMeta refuses plaintext over 16 KiB, and takes exactly 16 KiB', async () => {
  const s = await scene();
  const over = { name: await item(s.world, { plain: enc.encode('a'.repeat(16385)) }) };
  assert.deepEqual((await read(s, over)).unreadable, ['name']);
  const exact = { name: await item(s.world, { plain: enc.encode('a'.repeat(16384)) }) };
  assert.equal((await read(s, exact)).values.name.length, 16384);
});

test('readMeta marks a malformed item unreadable instead of throwing', async () => {
  const s = await scene();
  for (const bad of [null, 'x', {}, { record: 1, signerKey: 'a', blob: 'a' }, { ...(await item(s.world)), blob: '!!' }, { ...(await item(s.world)), signerKey: 'AAAA' }]) {
    assert.deepEqual(await read(s, { name: bad }), { values: {}, unreadable: ['name'] });
  }
});

// ---- an artifact in the app's list ----

test('describeArtifact opens the artifact as a member and reads its name and description', async () => {
  const s = await scene({ who: 'viewer' });
  const view = { id: ARTIFACT, meta: { name: await item(s.world, { value: 'Guestbook' }), description: await item(s.world, { field: 'description', value: 'Sign here' }) } };
  assert.deepEqual(await describeArtifact(s.deps, view), { name: 'Guestbook', description: 'Sign here', named: true, error: null });
});

test('describeArtifact shows an artifact with no name, or an empty one, under its ID', async () => {
  const s = await scene();
  assert.deepEqual(await describeArtifact(s.deps, { id: ARTIFACT }), { name: ARTIFACT, description: '', named: false, error: null });
  const empty = { id: ARTIFACT, meta: { name: await item(s.world, { value: '' }) } };
  assert.deepEqual(await describeArtifact(s.deps, empty), { name: ARTIFACT, description: '', named: false, error: null });
});

test('describeArtifact shows an unreadable name under the ID, and says why', async () => {
  const s = await scene();
  const view = { id: ARTIFACT, meta: { name: await item(s.world, { signer: U.viewer }), description: await item(s.world, { field: 'description', value: 'ok' }) } };
  const got = await describeArtifact(s.deps, view);
  assert.equal(got.name, ARTIFACT);
  assert.equal(got.description, 'ok');
  assert.equal(got.named, false);
  assert.match(got.error.message, /name/);
});

test('describeArtifact shows an artifact that does not open under its ID, without throwing', async () => {
  const world = await buildWorld({ owner: U.owner, members: STD_MEMBERS });
  const server = makeServer(world, { who: U.outsider });
  const deps = { fetch: server.fetch, keyStore: fakeKeyStore(records.outsider), storage: fakeStorage(), origin: ORIGIN };
  const view = { id: ARTIFACT, meta: { name: await item(world, { value: 'Guestbook' }) } };
  const got = await describeArtifact(deps, view);
  assert.deepEqual({ ...got, error: null }, { name: ARTIFACT, description: '', named: false, error: null });
  assert.ok(got.error instanceof Error);
});

// ---- writing ----

// metaServer records the PUTs the fake server receives.
function withMetaPuts(s) {
  const puts = [];
  const base = s.server.fetch;
  s.deps.fetch = async (path, init = {}) => {
    if ((init.method ?? 'GET') === 'PUT' && /\/meta\//.test(path)) {
      puts.push({ path, body: JSON.parse(init.body), headers: init.headers });
      return new Response('{"ok":true}', { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return base(path, init);
  };
  return puts;
}

test('writeMeta seals under the current epoch, signs, and sends the artifact path', async () => {
  const s = await scene({ epoch2: true });
  const puts = withMetaPuts(s);
  await writeMeta(s.deps, s.opened, '', 'name', 'Guestbook ✓');
  assert.equal(puts.length, 1);
  assert.equal(puts[0].path, `/api/artifacts/${ARTIFACT}/meta/name`);
  assert.deepEqual(Object.keys(puts[0].body).sort(), ['blob', 'record']);
  const env = e2e.decodeEnvelope(JSON.stringify(puts[0].body.record));
  assert.equal(env.signer, U.owner.id);
  const body = await e2e.openEnvelope(env, U.owner.ed.pub, 'record');
  assert.deepEqual(body, { v: 1, artifact: ARTIFACT, version: '', kind: 'meta', name: 'name', epoch: 2, sha256: body.sha256 });
  const blob = e2e.unb64(puts[0].body.blob);
  assert.equal(body.sha256, await e2e.bodyHash(blob));
  const plain = await e2e.openBlob(s.world.aks[2], { artifact: ARTIFACT, version: '', kind: 'meta', name: 'name' }, blob);
  assert.equal(new TextDecoder().decode(plain), 'Guestbook ✓');
});

test('writeMeta sends a version field to the version path', async () => {
  const s = await scene({ who: 'editor' });
  const puts = withMetaPuts(s);
  await writeMeta(s.deps, s.opened, V1, 'changelog', 'Fixed');
  assert.equal(puts[0].path, `/api/artifacts/${ARTIFACT}/versions/${V1}/meta/changelog`);
  const body = await e2e.openEnvelope(e2e.decodeEnvelope(JSON.stringify(puts[0].body.record)), U.editor.ed.pub, 'record');
  assert.equal(body.version, V1);
  assert.equal(body.name, 'changelog');
});

test('a field written by writeMeta reads back through readMeta', async () => {
  const s = await scene({ who: 'editor', epoch2: true });
  const puts = withMetaPuts(s);
  await writeMeta(s.deps, s.opened, '', 'description', 'Round trip');
  const served = { description: { record: puts[0].body.record, signerKey: e2e.b64(U.editor.ed.pub), blob: puts[0].body.blob } };
  assert.deepEqual(await read(s, served), { values: { description: 'Round trip' }, unreadable: [] });
  await writeMeta(s.deps, s.opened, V2, 'name', '');
  const empty = { name: { record: puts[1].body.record, signerKey: e2e.b64(U.editor.ed.pub), blob: puts[1].body.blob } };
  assert.deepEqual(await read(s, empty, V2), { values: { name: '' }, unreadable: [] });
});

test('writeMeta refuses an unknown field, and a field of the other scope, before sending', async () => {
  const s = await scene();
  const puts = withMetaPuts(s);
  for (const [version, field] of [['', 'title'], ['', 'changelog'], [V1, 'description'], [V1, 'constructor'], ['', '__proto__']]) {
    await assert.rejects(() => writeMeta(s.deps, s.opened, version, field, 'x'), MetaError);
  }
  assert.equal(puts.length, 0);
});

test('writeMeta refuses a value over 16 KiB of UTF-8, and takes exactly 16 KiB', async () => {
  const s = await scene();
  const puts = withMetaPuts(s);
  await assert.rejects(() => writeMeta(s.deps, s.opened, '', 'name', 'a'.repeat(16385)), MetaError);
  // 5462 three-byte characters are 16386 bytes, fewer than 16385 characters.
  await assert.rejects(() => writeMeta(s.deps, s.opened, '', 'name', '€'.repeat(5462)), MetaError);
  assert.equal(puts.length, 0);
  await writeMeta(s.deps, s.opened, '', 'name', 'a'.repeat(16384));
  assert.equal(puts.length, 1);
});

test('writeMeta refuses a value that is not a string or is not well formed', async () => {
  const s = await scene();
  const puts = withMetaPuts(s);
  for (const v of [null, undefined, 5, '\ud800']) {
    await assert.rejects(() => writeMeta(s.deps, s.opened, '', 'name', v), MetaError);
  }
  assert.equal(puts.length, 0);
});

test('writeMeta refuses a viewer, and a link holder even with public writes on', async () => {
  const viewer = await scene({ who: 'viewer' });
  const puts = withMetaPuts(viewer);
  await assert.rejects(() => writeMeta(viewer.deps, viewer.opened, '', 'name', 'x'), MetaError);
  assert.equal(puts.length, 0);

  const world = await buildWorld({ owner: U.owner, members: STD_MEMBERS, isPublic: true, publicWrites: true });
  const server = makeServer(world, { who: U.outsider, linkTokenB64: '*' });
  const deps = { fetch: server.fetch, keyStore: fakeKeyStore(records.outsider), storage: fakeStorage(), origin: ORIGIN };
  const link = { host: ORIGIN, artifact: ARTIFACT, ak: world.aks[1], epoch: 1, o: U.owner.fp };
  const opened = await openArtifact(deps, { artifact: ARTIFACT, link });
  assert.equal(opened.mode, 'link');
  await assert.rejects(() => writeMeta(deps, opened, '', 'name', 'x'), MetaError);
});

test('writeMeta refuses when the caller holds no key for the current epoch', async () => {
  const s = await scene();
  const puts = withMetaPuts(s);
  s.opened.aks.delete(s.opened.latest.epoch);
  await assert.rejects(() => writeMeta(s.deps, s.opened, '', 'name', 'x'), MetaError);
  assert.equal(puts.length, 0);
});

test('writeMeta passes on the server refusal', async () => {
  const s = await scene();
  s.deps.fetch = async () => new Response('{"error":"epoch moved"}', { status: 409, headers: { 'Content-Type': 'application/json' } });
  await assert.rejects(() => writeMeta(s.deps, s.opened, '', 'name', 'x'), { message: 'epoch moved', status: 409 });
});
