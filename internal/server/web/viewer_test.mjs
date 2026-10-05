// Tests for viewer.mjs against real chains, wraps, estate copies, keyrings,
// manifests, and vouches (see viewer_fixture.mjs), behind a fake fetch that
// serves them. Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { ApiError } from './account.mjs';
import { ContentError, checkKeysMessage } from './content.mjs';
import {
  ARTIFACT, OTHER_ARTIFACT, ORIGIN, V1, V2, buildWorld, fakeKeyStore, fakeStorage, keyStoreRecord,
  makeServer, makeUser, makeVersion, readServerKeyring, rotationRecord, seedKeyring, succession, vouchFor,
} from './viewer_fixture.mjs';
import {
  KeyringBusyError, LinkError, LockedError, NoAccessError, UNTRUSTED_MESSAGE, UntrustedVersionError, VersionGoneError, WriteError, canWrite, keepToken,
  keysMessage, listVersions, loadContext, mintToken, navigateTarget, openArtifact, prepareVersion, signBodies, takeLink, trustVersion,
  writerKeys,
} from './viewer.mjs';

const U = {};
for (const name of ['owner', 'editor', 'viewer', 'outsider']) U[name] = await makeUser(name);
const records = {};
for (const name of Object.keys(U)) records[name] = await keyStoreRecord(U[name]);

const STD_MEMBERS = [
  { user: U.editor, role: 'editor' },
  { user: U.viewer, role: 'viewer' },
];

// scene is a world, a fake server with `who` signed in (or nobody), and the
// deps the viewer takes. record overrides the key-store record.
async function scene({ who = null, members = STD_MEMBERS, isPublic = false, epoch2 = false, publicWrites = false, record, owner = U.owner } = {}) {
  const world = await buildWorld({ owner, members, isPublic, epoch2, publicWrites });
  const server = makeServer(world, { who: who && U[who], linkTokenB64: '*' });
  const rec = record === undefined ? (who ? records[who] : null) : record;
  const deps = { fetch: server.fetch, keyStore: fakeKeyStore(rec), storage: fakeStorage(), origin: ORIGIN };
  return { world, server, deps };
}

function linkFor(world, over = {}) {
  const epoch = world.top;
  return { host: ORIGIN, artifact: ARTIFACT, ak: world.aks[epoch], epoch, o: U.owner.fp, ...over };
}

const open = (s, link = null) => openArtifact(s.deps, { artifact: ARTIFACT, link });
const headOf = async (world, i) => e2e.bodyHash(e2e.unb64(world.records[i].body));
const pinOf = (fp) => ({ fp, state: 'unverified', rotSeq: 0, rotHead: '' });
const signerOf = (u, seed = u.ed.seed) => ({ user: u.id, seed });

// ---- member mode ----

test('member mode opens for the owner from the estate copies and records the chain', async () => {
  const s = await scene({ who: 'owner' });
  const opened = await open(s);
  assert.equal(opened.mode, 'member');
  assert.equal(opened.linkToken, null);
  assert.deepEqual(opened.aks.get(1), s.world.aks[1]);
  assert.equal(opened.latest.seq, 2);
  assert.equal(opened.caller.id, U.owner.id);

  const kr = await readServerKeyring(s.server, U.owner);
  assert.equal(kr.rev, 1);
  assert.deepEqual(kr.epochs[ARTIFACT], { epoch: 1, seq: 2, head: await headOf(s.world, 1), ack: 0 });
  assert.deepEqual(kr.pins, {}, 'the creator is the caller, so there is no first-sight pin');
  // The caller's own fingerprint anchors the chain: the directory is not asked for them.
  assert.equal(s.server.calls.some((c) => c.path.startsWith('/api/users/')), false);
  // The anchor stored is the one for the keyring just written.
  const anchor = e2e.loadKeyringAnchor(s.deps.storage, U.owner.id, U.owner.fp);
  assert.deepEqual(anchor, await e2e.keyringAnchorOf(1, e2e.unb64(s.server.keyring.keyring)));
});

test('member mode opens for an editor from their wraps and pins the creator unverified', async () => {
  const s = await scene({ who: 'editor' });
  const opened = await open(s);
  assert.equal(opened.mode, 'member');
  assert.deepEqual(opened.aks.get(1), s.world.aks[1]);
  const kr = await readServerKeyring(s.server, U.editor);
  assert.deepEqual(kr.pins[U.owner.id], pinOf(U.owner.fp));
  assert.deepEqual(kr.epochs[ARTIFACT], { epoch: 1, seq: 2, head: await headOf(s.world, 1), ack: 0 });
  assert.equal(s.server.putCount, 1);
});

test('member mode opens every epoch for an editor, and a viewer is a member too', async () => {
  const s = await scene({ who: 'viewer', epoch2: true });
  const opened = await open(s);
  assert.equal(opened.mode, 'member');
  assert.deepEqual(opened.aks.get(1), s.world.aks[1]);
  assert.deepEqual(opened.aks.get(2), s.world.aks[2]);
  assert.equal(opened.latest.epoch, 2);
});

test('a second open finds the keyring current and writes nothing', async () => {
  const s = await scene({ who: 'editor' });
  await open(s);
  s.server.calls.length = 0;
  await open(s);
  assert.equal(s.server.putCount, 1);
  assert.equal(s.server.calls.some((c) => c.path.startsWith('/api/users/')), false, 'the pin anchors it now');
});

test('the creator is anchored at the pinned fingerprint, not the directory', async () => {
  const s = await scene({ who: 'editor' });
  const k = e2e.newKeyring();
  k.pins[U.owner.id] = { fp: 'f'.repeat(64), state: 'verified', rotSeq: 0, rotHead: '' };
  await seedKeyring(s.server, U.editor, k);
  await assert.rejects(() => open(s), e2e.ChainError);
  // The same keyring pinned at the right fingerprint opens, and stays verified.
  k.pins[U.owner.id] = { fp: U.owner.fp, state: 'verified', rotSeq: 0, rotHead: '' };
  await seedKeyring(s.server, U.editor, k);
  s.deps.storage = fakeStorage();
  await open(s);
  assert.equal((await readServerKeyring(s.server, U.editor)).pins[U.owner.id].state, 'verified');
});

test('a creator the directory no longer lists is anchored at the owner keys the server served', async () => {
  const s = await scene({ who: 'editor' });
  s.server.notFound.add(U.owner.id);
  const opened = await open(s);
  assert.equal(opened.mode, 'member');
  assert.deepEqual((await readServerKeyring(s.server, U.editor)).pins[U.owner.id], pinOf(U.owner.fp));
  // Owner keys that do not hash to the first record's fingerprint anchor nothing.
  const bad = await scene({ who: 'editor' });
  bad.server.notFound.add(U.owner.id);
  const base = bad.server.fetch;
  bad.deps.fetch = async (path, init) => {
    const resp = await base(path, init);
    if (!path.endsWith('/membership')) return resp;
    const m = await resp.json();
    m.owners = { [U.owner.fp]: U.editor.pair };
    return new Response(JSON.stringify(m), { status: 200 });
  };
  await assert.rejects(() => open(bad), e2e.ChainError);
});

test('a directory error other than 404 is not read as a missing creator', async () => {
  const s = await scene({ who: 'editor' });
  const base = s.server.fetch;
  s.deps.fetch = async (path, init) => (path.startsWith('/api/users/') ? new Response('{}', { status: 500 }) : base(path, init));
  await assert.rejects(() => open(s), (err) => err.status === 500);
});

test('the keyring anchor is stored when the keyring is only read', async () => {
  const s = await scene({ who: 'editor' });
  await open(s);
  const k = await readServerKeyring(s.server, U.editor);
  k.rev = 3;
  await seedKeyring(s.server, U.editor, k);
  const fresh = fakeStorage();
  s.deps.storage = fresh;
  await open(s);
  assert.equal(s.server.putCount, 1, 'nothing to write');
  const anchor = e2e.loadKeyringAnchor(fresh, U.editor.id, U.editor.fp);
  assert.deepEqual(anchor, await e2e.keyringAnchorOf(3, e2e.unb64(s.server.keyring.keyring)));
});

test('a keyring that rolls back against the stored anchor is refused', async () => {
  const s = await scene({ who: 'editor' });
  e2e.saveKeyringAnchor(s.deps.storage, U.editor.id, U.editor.fp, { rev: 5, hash: '0'.repeat(64) });
  await assert.rejects(() => open(s), e2e.KeyringRollbackError);
});

test('a keyring that forks the stored anchor is refused', async () => {
  const s = await scene({ who: 'editor' });
  e2e.saveKeyringAnchor(s.deps.storage, U.editor.id, U.editor.fp, { rev: 0, hash: '0'.repeat(64) });
  await assert.rejects(() => open(s), e2e.KeyringForkError);
});

test('a chain shorter than the keyring pins, or forked at it, is refused', async () => {
  const s = await scene({ who: 'owner' });
  const k = e2e.newKeyring();
  k.epochs[ARTIFACT] = { epoch: 1, seq: 3, head: 'a'.repeat(64), ack: 0 };
  await seedKeyring(s.server, U.owner, k);
  await assert.rejects(() => open(s), e2e.RollbackError);
  k.epochs[ARTIFACT] = { epoch: 1, seq: 2, head: 'a'.repeat(64), ack: 0 };
  await seedKeyring(s.server, U.owner, k);
  s.deps.storage = fakeStorage();
  await assert.rejects(() => open(s), e2e.ForkError);
});

test('a wrap whose AK does not match the chain akCommit is refused', async () => {
  const s = await scene({ who: 'editor' });
  const other = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await e2e.wrap({ purpose: 'ak', artifact: ARTIFACT, epoch: 1, recipientId: U.editor.id, recipientPub: U.editor.x.pub }, other);
  s.server.keysOverride = { wraps: [{ epoch: 1, wrapped: e2e.b64(wrapped), fp: U.editor.fp }], estate: [] };
  await assert.rejects(() => open(s), { name: 'ChainError', message: /akCommit/ });
});

test('an estate copy whose AK does not match the chain akCommit is refused', async () => {
  const s = await scene({ who: 'owner' });
  const other = crypto.getRandomValues(new Uint8Array(32));
  const sealed = await e2e.seal(await e2e.ekSealCryptoKey(U.owner.ek), ['estate', ARTIFACT, '1'], other);
  s.server.keysOverride = { wraps: [], estate: [{ epoch: 1, sealed: e2e.b64(sealed) }] };
  await assert.rejects(() => open(s), { name: 'ChainError', message: /akCommit/ });
});

test('a wrap or estate copy for an epoch the chain does not list is refused', async () => {
  const s = await scene({ who: 'owner' });
  const sealed = await e2e.seal(await e2e.ekSealCryptoKey(U.owner.ek), ['estate', ARTIFACT, '7'], s.world.aks[1]);
  s.server.keysOverride = { wraps: [], estate: [...s.world.estate, { epoch: 7, sealed: e2e.b64(sealed) }] };
  await assert.rejects(() => open(s), e2e.ChainError);
});

test('a missing epoch is refused', async () => {
  for (const who of ['owner', 'editor']) {
    const s = await scene({ who, epoch2: true });
    s.server.keysOverride = {
      wraps: s.world.wraps[U[who].id]?.slice(0, 1) ?? [],
      estate: who === 'owner' ? s.world.estate.slice(0, 1) : [],
    };
    await assert.rejects(() => open(s), { name: 'ChainError', message: /epoch 2/ }, who);
  }
});

test('the keyring write retries on 409 and keeps the other device change', async () => {
  const s = await scene({ who: 'editor' });
  const other = e2e.newKeyring();
  other.rev = 1;
  other.pins['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'] = pinOf('e'.repeat(64));
  const sealed = await e2e.sealKeyring(await e2e.mkSealCryptoKey(U.editor.mk), other);
  s.server.onPut = () => {
    s.server.onPut = null;
    s.server.keyring = { rev: 1, keyring: e2e.b64(sealed) };
  };
  await open(s);
  assert.equal(s.server.putCount, 2);
  const kr = await readServerKeyring(s.server, U.editor);
  assert.equal(kr.rev, 2);
  assert.ok(kr.pins['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'], "the other device's pin survives");
  assert.ok(kr.pins[U.owner.id]);
  assert.ok(kr.epochs[ARTIFACT]);
});

test('the keyring write gives up after five conflicts', async () => {
  const s = await scene({ who: 'editor' });
  s.server.conflicts = 99;
  await assert.rejects(() => open(s), KeyringBusyError);
  assert.equal(s.server.putCount, 5);
});

test('a creator pinned at another fingerprint than the chain was verified against is refused on a merge', async () => {
  // The first read pins nothing; another device pins the creator at another
  // fingerprint before the write, so the merge refuses.
  const s = await scene({ who: 'editor' });
  const other = e2e.newKeyring();
  other.rev = 1;
  other.pins[U.owner.id] = pinOf('d'.repeat(64));
  const sealed = await e2e.sealKeyring(await e2e.mkSealCryptoKey(U.editor.mk), other);
  s.server.onPut = () => {
    s.server.onPut = null;
    s.server.keyring = { rev: 1, keyring: e2e.b64(sealed) };
  };
  await assert.rejects(() => open(s), { name: 'PinConflictError' });
});

test('a chain forked at the same seq on a merge is refused', async () => {
  const s = await scene({ who: 'editor' });
  const other = e2e.newKeyring();
  other.rev = 1;
  other.pins[U.owner.id] = pinOf(U.owner.fp);
  other.epochs[ARTIFACT] = { epoch: 1, seq: 2, head: 'c'.repeat(64), ack: 0 };
  const sealed = await e2e.sealKeyring(await e2e.mkSealCryptoKey(U.editor.mk), other);
  s.server.onPut = () => {
    s.server.onPut = null;
    s.server.keyring = { rev: 1, keyring: e2e.b64(sealed) };
  };
  await assert.rejects(() => open(s), e2e.ForkError);
});

test('a merge keeps the higher seq another device stored, and the acknowledged handover', async () => {
  const s = await scene({ who: 'editor' });
  const other = e2e.newKeyring();
  other.rev = 1;
  other.pins[U.owner.id] = pinOf(U.owner.fp);
  other.epochs[ARTIFACT] = { epoch: 1, seq: 1, head: 'c'.repeat(64), ack: 4 };
  const sealed = await e2e.sealKeyring(await e2e.mkSealCryptoKey(U.editor.mk), other);
  s.server.onPut = () => {
    s.server.onPut = null;
    s.server.keyring = { rev: 1, keyring: e2e.b64(sealed) };
  };
  await open(s);
  const kr = await readServerKeyring(s.server, U.editor);
  assert.deepEqual(kr.epochs[ARTIFACT], { epoch: 1, seq: 2, head: await headOf(s.world, 1), ack: 4 });
});

// ---- who gets which mode ----

test('a signed-in non-member opens with a link, in link mode, and writes no keyring', async () => {
  const s = await scene({ who: 'outsider', isPublic: true });
  const opened = await open(s, linkFor(s.world));
  assert.equal(opened.mode, 'link');
  assert.equal(opened.caller.id, U.outsider.id);
  assert.equal(s.server.putCount, 0);
});

test('a signed-in non-member without a link is told to sign in or use the full link', async () => {
  const s = await scene({ who: 'outsider', isPublic: true });
  await assert.rejects(() => open(s), NoAccessError);
});

test('a visitor without a link is told to sign in or use the full link', async () => {
  const s = await scene({ isPublic: true });
  await assert.rejects(() => open(s), { name: 'NoAccessError', message: /Sign in.*full public link/ });
  assert.deepEqual(s.server.calls.map((c) => c.path), ['/api/me'], 'only whether there is a session');
});

test('a visitor with a link is never asked whether there is a session', async () => {
  const s = await scene({ isPublic: true });
  assert.equal((await open(s, linkFor(s.world))).mode, 'link');
  assert.equal(s.server.calls.some((c) => c.path === '/api/me'), false);
});

test('a session whose keys this browser does not hold, or holds for another user, is locked: it signs in again', async () => {
  for (const record of [null, records.editor]) {
    const s = await scene({ who: 'owner', isPublic: true, record });
    await assert.rejects(() => open(s), LockedError);
    assert.equal(s.server.calls.some((c) => c.path.includes('/membership')), false, 'nothing is fetched before the keys');
  }
});

test('a session without keys still opens a link, as a visitor', async () => {
  const s = await scene({ who: 'owner', isPublic: true, record: null });
  const opened = await open(s, linkFor(s.world));
  assert.equal(opened.mode, 'link');
  assert.equal(opened.caller, null);
});

test('whether there is a session fails loudly, not as locked or no access', async () => {
  const s = await scene({ isPublic: true });
  const base = s.server.fetch;
  s.deps.fetch = async (path, init) => (path === '/api/me' ? new Response('{}', { status: 500 }) : base(path, init));
  await assert.rejects(() => open(s), (err) => err.status === 500);
});

test('a member who also has the link opens as a member', async () => {
  const s = await scene({ who: 'editor', isPublic: true });
  assert.equal((await open(s, linkFor(s.world))).mode, 'member');
});

test('a key-store record without the Ed25519 public key reads as signed out, and says to sign in again', async () => {
  const { ed25519Pub, ...old } = records.editor;
  assert.ok(ed25519Pub);
  const s = await scene({ who: 'editor', isPublic: true, record: old });
  const opened = await open(s, linkFor(s.world));
  assert.equal(opened.mode, 'link');
  assert.equal(opened.caller, null);
  assert.equal(s.server.calls.some((c) => c.path.startsWith('/api/me')), false);
  await assert.rejects(() => open(s), { name: 'NoAccessError', message: /Sign out, then sign in again/ });
  const fresh = await scene({ isPublic: true });
  await assert.rejects(() => open(fresh), (err) => err instanceof NoAccessError && !/Sign out/.test(err.message));
});

test('a key-store record for another user than the session reads as signed out', async () => {
  const s = await scene({ who: 'owner', isPublic: true, record: records.editor });
  const opened = await open(s, linkFor(s.world));
  assert.equal(opened.mode, 'link');
  assert.equal(opened.caller, null);
  assert.equal(s.server.putCount, 0);
});

test('a record whose session has ended reads as signed out', async () => {
  const s = await scene({ who: null, isPublic: true, record: records.editor });
  const opened = await open(s, linkFor(s.world));
  assert.equal(opened.mode, 'link');
  assert.equal(opened.caller, null);
});

test('a membership error other than refusal is not read as "not a member"', async () => {
  const s = await scene({ who: 'editor' });
  const base = s.server.fetch;
  s.deps.fetch = async (path, init) => (path.endsWith('/membership') ? new Response('{}', { status: 500 }) : base(path, init));
  await assert.rejects(() => open(s), (err) => err.status === 500);
});

test('a signed-in non-member who can read the membership is not a member', async () => {
  const s = await scene({ who: 'outsider', isPublic: true });
  s.server.openMembership = true;
  const opened = await open(s, linkFor(s.world));
  assert.equal(opened.mode, 'link');
  assert.equal(s.server.putCount, 0, 'nothing is recorded for an artifact the caller is not listed in');
  await assert.rejects(() => open(s), NoAccessError);
});

test('a refusal to show the membership, 403 or 404, is "not a member"; other errors are not', async () => {
  for (const status of [403, 404]) {
    const s = await scene({ who: 'outsider', isPublic: true });
    const base = s.server.fetch;
    s.deps.fetch = async (path, init) => (path.endsWith('/membership') && !init.headers['X-Cairn-Link-Token'] ? new Response('{}', { status }) : base(path, init));
    assert.equal((await open(s, linkFor(s.world))).mode, 'link', String(status));
    await assert.rejects(() => open(s), NoAccessError, String(status));
  }
});

test('a chain whose owner rotated after the keyring pinned them verifies through the rotation records', async () => {
  const next = await makeUser('owner');
  const s = await scene({ who: 'editor', owner: next });
  const k = e2e.newKeyring();
  k.pins[U.owner.id] = pinOf(U.owner.fp);
  await seedKeyring(s.server, U.editor, k);
  await assert.rejects(() => open(s), e2e.ChainError, 'no rotation record links the pin to the chain');
  s.deps.storage = fakeStorage();
  s.server.rotations = { [U.owner.id]: [await rotationRecord(U.owner, next)] };
  assert.equal((await open(s)).mode, 'member');
});

test('a merge replaces an older epochs entry with the chain just verified', async () => {
  const s = await scene({ who: 'editor' });
  const k = e2e.newKeyring();
  k.pins[U.owner.id] = pinOf(U.owner.fp);
  k.epochs[ARTIFACT] = { epoch: 1, seq: 1, head: await headOf(s.world, 0), ack: 0 };
  await seedKeyring(s.server, U.editor, k);
  await open(s);
  assert.equal(s.server.putCount, 1);
  assert.deepEqual((await readServerKeyring(s.server, U.editor)).epochs[ARTIFACT], { epoch: 1, seq: 2, head: await headOf(s.world, 1), ack: 0 });
});

test('a chain already recorded is still written when the creator is not yet pinned', async () => {
  const s = await scene({ who: 'editor' });
  const k = e2e.newKeyring();
  k.epochs[ARTIFACT] = { epoch: 1, seq: 2, head: await headOf(s.world, 1), ack: 0 };
  await seedKeyring(s.server, U.editor, k);
  await open(s);
  assert.equal(s.server.putCount, 1);
  assert.deepEqual((await readServerKeyring(s.server, U.editor)).pins[U.owner.id], pinOf(U.owner.fp));
});

// ---- the owner's released successor ----

// heirScene is a scene in which the outsider is the owner's released
// successor, with the nomination opts describes.
async function heirScene(opts = {}) {
  const s = await scene({ who: 'outsider' });
  s.server.successor = U.outsider;
  s.server.successions = [await succession(U.owner, U.outsider, opts)];
  return s;
}

test('successor: a released successor opens the owner\'s artifact from the estate copies, reads only, and records the chain', async () => {
  const s = await heirScene();
  const opened = await open(s);
  assert.equal(opened.mode, 'member');
  assert.deepEqual(opened.aks.get(1), s.world.aks[1]);
  assert.equal(canWrite(opened), false);
  const kr = await readServerKeyring(s.server, U.outsider);
  assert.equal(kr.epochs[ARTIFACT].seq, 2);
  assert.deepEqual(kr.pins[U.owner.id], pinOf(U.owner.fp));
});

test('successor: every epoch opens, and a missing estate copy is refused', async () => {
  const heirAt = async (s) => Object.assign(s.server, { successor: U.outsider, successions: [await succession(U.owner, U.outsider)] });
  const full = await scene({ who: 'outsider', epoch2: true });
  await heirAt(full);
  assert.deepEqual((await open(full)).aks.get(2), full.world.aks[2]);
  const short = await scene({ who: 'outsider', epoch2: true });
  await heirAt(short);
  short.server.keysOverride = { wraps: [], estate: short.world.estate.slice(0, 1) };
  await assert.rejects(open(short), /no key for you for epoch 2/);
});

test('successor: an estate copy that does not match the chain akCommit is refused', async () => {
  const s = await heirScene();
  const other = await buildWorld({ owner: U.owner, members: STD_MEMBERS });
  s.server.keysOverride = { wraps: [], estate: other.estate };
  await assert.rejects(open(s), /estate copy of epoch 1 does not match/);
});

test('successor: a nomination the owner\'s key does not verify is refused', async () => {
  const s = await heirScene({ seed: U.editor.ed.seed });
  await assert.rejects(open(s), /nomination record of owner@example.com does not verify/);
});

test('successor: a nomination for another user, successor, fingerprint, or action is refused', async () => {
  const cases = [
    [{ user: U.editor.id }, /is for/],
    [{ successor: U.editor.id }, /names .* not you/],
    [{ successorFp: U.editor.fp }, /another fingerprint than your own/],
    [{ action: 'remove' }, /has the action "remove"/],
  ];
  for (const [over, want] of cases) {
    const s = await heirScene({ over });
    await assert.rejects(open(s), want, JSON.stringify(over));
  }
});

test('successor: the owner\'s key comes from the directory, else from the succession list when the directory no longer lists them', async () => {
  const listed = await heirScene({ seed: U.editor.ed.seed });
  listed.server.successions[0].user.ed25519Pub = U.editor.pair.ed25519;
  await assert.rejects(open(listed), /does not verify/);
  const gone = await heirScene();
  gone.server.notFound.add(U.owner.id);
  assert.equal((await open(gone)).mode, 'member');
});

test('successor: a nomination that is not released yet opens nothing', async () => {
  const s = await heirScene({ released: false });
  await assert.rejects(open(s), (err) => err instanceof NoAccessError && /not released to you yet/.test(err.message));
});

test('successor: estate copies with no nomination from the artifact\'s owner, or with wraps of the caller\'s own, are not the successor path', async () => {
  const none = await heirScene();
  none.server.successions = [];
  await assert.rejects(open(none), NoAccessError);
  const wraps = await heirScene();
  wraps.server.keysOverride = { wraps: [{ epoch: 1, wrapped: e2e.b64(new Uint8Array(80)), fp: U.outsider.fp }], estate: wraps.world.estate };
  await assert.rejects(open(wraps), NoAccessError);
  assert.ok(!wraps.server.calls.some((c) => c.path === '/api/successions'));
});

test('successor: a caller the server serves no keys to falls back to the link', async () => {
  const s = await scene({ who: 'outsider', isPublic: true });
  s.server.openMembership = true;
  s.server.successions = [await succession(U.owner, U.outsider)];
  const opened = await open(s, linkFor(s.world));
  assert.equal(opened.mode, 'link');
  assert.ok(!s.server.calls.some((c) => c.path === '/api/successions'));
});

// ---- link mode ----

test('link mode opens with a valid link, with the link AK for its epoch only, and sends the token', async () => {
  const s = await scene({ isPublic: true, epoch2: true });
  const link = linkFor(s.world);
  const opened = await open(s, link);
  assert.equal(opened.mode, 'link');
  assert.equal(opened.caller, null);
  assert.deepEqual([...opened.aks.keys()], [2]);
  assert.deepEqual(opened.aks.get(2), s.world.aks[2]);
  const token = e2e.b64(await e2e.linkToken(link.ak, ARTIFACT, 2));
  assert.equal(opened.linkToken, token);
  const m = s.server.calls.find((c) => c.path.endsWith('/membership'));
  assert.equal(m.headers['X-Cairn-Link-Token'], token);
  // Later requests carry it too.
  s.server.versions.set(V1, await makeVersion(s.world, V1, { epoch: 2, signer: signerOf(U.owner) }));
  await prepareVersion(s.deps, opened, V1);
  for (const c of s.server.calls.filter((x) => x.path.includes('/versions/'))) {
    assert.equal(c.headers['X-Cairn-Link-Token'], token, c.path);
  }
});

test('link mode refuses a link for another artifact or host', async () => {
  const s = await scene({ isPublic: true });
  await assert.rejects(() => open(s, linkFor(s.world, { artifact: OTHER_ARTIFACT })), { name: 'LinkError', message: /another artifact/ });
  await assert.rejects(() => open(s, linkFor(s.world, { host: 'https://evil.example' })), { name: 'LinkError', message: /another server/ });
  assert.equal(s.server.calls.length, 0, 'nothing is sent before the link is checked');
});

test('link mode refuses a stale link', async () => {
  const s = await scene({ isPublic: true, epoch2: true });
  await assert.rejects(() => open(s, linkFor(s.world, { ak: s.world.aks[1], epoch: 1 })), e2e.StaleLinkError);
});

test('link mode refuses a key that does not match the chain akCommit', async () => {
  const s = await scene({ isPublic: true });
  const bad = linkFor(s.world, { ak: crypto.getRandomValues(new Uint8Array(32)) });
  await assert.rejects(() => open(s, bad), { name: 'ChainError', message: /akCommit/ });
});

test('link mode refuses a link whose owner fingerprint the chain does not reach, and a private artifact', async () => {
  const s = await scene({ isPublic: true });
  await assert.rejects(() => open(s, linkFor(s.world, { o: 'b'.repeat(64) })), e2e.ChainError);
  const priv = await scene({ isPublic: false });
  await assert.rejects(() => open(priv, linkFor(priv.world)), { name: 'ChainError', message: /public/ });
});

test('link mode names a link the server will not honor, with 403 or 404', async () => {
  for (const status of [403, 404]) {
    const s = await scene({ isPublic: true });
    const base = s.server.fetch;
    s.deps.fetch = async (path, init) => (path.endsWith('/membership') ? new Response('{}', { status }) : base(path, init));
    await assert.rejects(() => open(s, linkFor(s.world)), LinkError, String(status));
  }
  const s = await scene({ isPublic: true });
  const base = s.server.fetch;
  s.deps.fetch = async (path, init) => (path.endsWith('/membership') ? new Response('{}', { status: 500 }) : base(path, init));
  await assert.rejects(() => open(s, linkFor(s.world)), (err) => err.status === 500);
});

test('link mode follows an owner who rotated after the link was made', async () => {
  const next = await makeUser('owner');
  const s = await scene({ isPublic: true, owner: next });
  const link = linkFor(s.world, { o: U.owner.fp });
  await assert.rejects(() => open(s, link), e2e.ChainError, 'without the rotation record');
  s.server.rotations = { [U.owner.id]: [await rotationRecord(U.owner, next)] };
  assert.equal((await open(s, link)).mode, 'link');
});

// ---- takeLink ----

function fakePage(hash) {
  const calls = [];
  return {
    calls,
    location: { origin: ORIGIN, pathname: `/shared/${ARTIFACT}`, search: '?x=1', hash },
    history: { replaceState: (...a) => calls.push(a) },
  };
}

test('takeLink returns null, and leaves the address alone, when there is no fragment', () => {
  const p = fakePage('');
  assert.equal(takeLink(p.location, p.history, ARTIFACT), null);
  assert.deepEqual(p.calls, []);
});

test('takeLink removes the fragment, then returns the link', () => {
  const ak = crypto.getRandomValues(new Uint8Array(32));
  const full = e2e.publicLink(ORIGIN, ARTIFACT, ak, 3, U.owner.fp);
  const p = fakePage(full.slice(full.indexOf('#')));
  const link = takeLink(p.location, p.history, ARTIFACT);
  assert.deepEqual(p.calls, [[null, '', `/shared/${ARTIFACT}?x=1`]]);
  assert.deepEqual(link, { host: ORIGIN, artifact: ARTIFACT, ak, epoch: 3, o: U.owner.fp });
});

test('takeLink removes a malformed fragment before it throws a LinkError a person can act on', () => {
  for (const hash of ['#k=zz', '#nonsense', `#k=${e2e.b64(new Uint8Array(32))}&e=1`]) {
    const p = fakePage(hash);
    assert.throws(() => takeLink(p.location, p.history, ARTIFACT), { name: 'LinkError', message: /incomplete or damaged/ }, hash);
    assert.deepEqual(p.calls, [[null, '', `/shared/${ARTIFACT}?x=1`]], hash);
  }
});

test('a fragment that is not a link does not stop a member, and is reported to anyone else', async () => {
  const linkError = new LinkError('bad link');
  const m = await scene({ who: 'editor' });
  assert.equal((await openArtifact(m.deps, { artifact: ARTIFACT, link: null, linkError })).mode, 'member');
  const v = await scene({ isPublic: true });
  await assert.rejects(() => openArtifact(v.deps, { artifact: ARTIFACT, link: null, linkError }), (err) => err === linkError);
});

// ---- trust ----

async function trustScene(opts = {}) {
  const s = await scene({ who: 'viewer', ...opts });
  await opts.prepare?.(s);
  s.opened = await open(s, opts.isPublic && !opts.who ? linkFor(s.world) : null);
  return s;
}

async function trust(s, { signer, vouch, over, hash, epoch = 1, vid = V1 }) {
  const v = await makeVersion(s.world, vid, { epoch, signer, over, vouch, hash });
  s.server.versions.set(vid, v);
  return { v, run: () => trustVersion(s.deps, s.opened, v.json) };
}

test('trust: a manifest signed by the owner is trusted, and names the owner key', async () => {
  const s = await trustScene();
  const { run } = await trust(s, { signer: signerOf(U.owner) });
  assert.deepEqual(await run(), { signer: { user: U.owner.id, ed25519: e2e.b64(U.owner.ed.pub) } });
});

test('trust: a manifest signed by a listed editor is trusted', async () => {
  const s = await trustScene();
  const { run } = await trust(s, { signer: signerOf(U.editor) });
  assert.deepEqual(await run(), { signer: { user: U.editor.id, ed25519: e2e.b64(U.editor.ed.pub) } });
});

test('trust: the caller\'s own keys are used when they signed, without asking the directory', async () => {
  const s = await scene({ who: 'editor' });
  s.opened = await open(s);
  s.server.notFound.add(U.editor.id);
  const { run } = await trust(s, { signer: signerOf(U.editor) });
  assert.equal((await run()).signer.user, U.editor.id);
});

test('trust: an editor who rotated since listed is trusted under the new key', async () => {
  const next = await makeUser('editor');
  const s = await trustScene({
    prepare: async (sc) => {
      sc.server.rotations = { [U.editor.id]: [await rotationRecord(U.editor, next)] };
      sc.server.directory.set(U.editor.id, { id: U.editor.id, name: 'editor', email: 'e@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
    },
  });
  const { run } = await trust(s, { signer: signerOf(U.editor, next.ed.seed) });
  assert.equal((await run()).signer.ed25519, e2e.b64(next.ed.pub));
});

test('trust: a version signed before the editor rotated is trusted under the old key', async () => {
  const next = await makeUser('editor');
  const s = await trustScene({
    members: [{ user: U.editor, role: 'editor', fp: next.fp }, { user: U.viewer, role: 'viewer' }],
    prepare: async (sc) => {
      sc.server.rotations = { [U.editor.id]: [await rotationRecord(U.editor, next)] };
      sc.server.directory.set(U.editor.id, { id: U.editor.id, name: 'editor', email: 'e@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
    },
  });
  const { run } = await trust(s, { signer: signerOf(U.editor) });
  assert.equal((await run()).signer.ed25519, e2e.b64(U.editor.ed.pub));
});

test('trust: a key no rotation links to the listed one is refused', async () => {
  const s = await trustScene();
  const next = await makeUser('editor');
  s.server.directory.set(U.editor.id, { id: U.editor.id, name: 'editor', email: 'e@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  const { run } = await trust(s, { signer: signerOf(U.editor, next.ed.seed) });
  await assert.rejects(run, UntrustedVersionError);
});

test('trust: a signer who is now a viewer is refused without a vouch', async () => {
  const s = await trustScene();
  const { run } = await trust(s, { signer: signerOf(U.viewer) });
  await assert.rejects(run, { name: 'UntrustedVersionError', message: UNTRUSTED_MESSAGE });
  assert.equal(UNTRUSTED_MESSAGE, 'This version was pushed by someone who is no longer an editor, and the owner has not reviewed it.');
});

test('trust: a signer the chain never lists is refused', async () => {
  const s = await trustScene();
  const { run } = await trust(s, { signer: signerOf(U.outsider) });
  await assert.rejects(run, UntrustedVersionError);
});

test('trust: a listed editor whose account the directory no longer publishes is refused', async () => {
  const s = await trustScene();
  s.server.notFound.add(U.editor.id);
  const { run } = await trust(s, { signer: signerOf(U.editor) });
  await assert.rejects(run, UntrustedVersionError);
});

// vouchTrial builds a version signed by a viewer (so only a vouch can trust
// it) whose vouch is made by make(manifestHash).
async function vouchTrial(make) {
  const s = await trustScene();
  const first = await makeVersion(s.world, V1, { signer: signerOf(U.viewer) });
  // The vouch names the manifest of this exact version, so serve that one.
  s.server.versions.set(V1, { ...first, json: { ...first.json, vouch: await make(first.manifestHash, s) } });
  return () => trustVersion(s.deps, s.opened, s.server.versions.get(V1).json);
}

test('trust: a key the record lists for the editor does not make another user an editor', async () => {
  // The editor entry lists the viewer's fingerprint. A manifest the viewer signs
  // under their own key matches that fingerprint, but the viewer is not the editor.
  const s = await trustScene({ members: [{ user: U.editor, role: 'editor', fp: U.viewer.fp }, { user: U.viewer, role: 'viewer' }] });
  const { run } = await trust(s, { signer: signerOf(U.viewer) });
  await assert.rejects(run, UntrustedVersionError);
});

test('trust: a key a rotation record names is a candidate when the directory has none', async () => {
  const next = await makeUser('editor');
  const s = await trustScene({
    prepare: async (sc) => {
      sc.server.rotations = { [U.editor.id]: [await rotationRecord(U.editor, next)] };
      sc.server.notFound.add(U.editor.id);
    },
  });
  const { run } = await trust(s, { signer: signerOf(U.editor, next.ed.seed) });
  assert.equal((await run()).signer.ed25519, e2e.b64(next.ed.pub));
});

test('trust: a viewer\'s version is accepted with the owner\'s vouch, and there is no signer', async () => {
  const run = await vouchTrial((h) => vouchFor(U.owner, V1, h));
  assert.deepEqual(await run(), { signer: null });
});

test('trust: a vouch is refused for another manifestHash, version, or artifact', async () => {
  for (const [name, make] of [
    ['manifest', () => vouchFor(U.owner, V1, 'f'.repeat(64))],
    ['version', (h) => vouchFor(U.owner, V1, h, { over: { version: V2 } })],
    ['artifact', (h) => vouchFor(U.owner, V1, h, { over: { artifact: OTHER_ARTIFACT } })],
  ]) {
    await assert.rejects(await vouchTrial(make), UntrustedVersionError, name);
  }
});

test('trust: a vouch not signed by the owner is refused', async () => {
  for (const [name, make] of [
    ['editor key and signer', (h) => vouchFor(U.owner, V1, h, { seed: U.editor.ed.seed, signer: U.editor.id })],
    ['editor key under the owner id', (h) => vouchFor(U.owner, V1, h, { seed: U.editor.ed.seed })],
    ['owner key under an editor id', (h) => vouchFor(U.owner, V1, h, { signer: U.editor.id })],
    ['another purpose', (h) => vouchFor(U.owner, V1, h, { purpose: 'manifest' })],
  ]) {
    await assert.rejects(await vouchTrial(make), UntrustedVersionError, name);
  }
});

test('trust: a vouch counts only under a key whose fingerprint is the record ownerFp', async () => {
  // The directory serves the owner's rotated keys, while the record still
  // lists the old fingerprint. A vouch under the new keys is not the owner's.
  const next = await makeUser('owner');
  const rotate = (s) => {
    s.server.directory.set(U.owner.id, { id: U.owner.id, name: 'owner', email: 'o@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  };
  const s = await trustScene();
  rotate(s);
  const first = await makeVersion(s.world, V1, { signer: signerOf(U.viewer) });
  const newKey = { ...first, json: { ...first.json, vouch: await vouchFor(U.owner, V1, first.manifestHash, { seed: next.ed.seed }) } };
  s.server.versions.set(V1, newKey);
  await assert.rejects(() => trustVersion(s.deps, s.opened, newKey.json), UntrustedVersionError);
  const oldKey = { ...first, json: { ...first.json, vouch: await vouchFor(U.owner, V1, first.manifestHash) } };
  s.server.versions.set(V1, oldKey);
  assert.deepEqual(await trustVersion(s.deps, s.opened, oldKey.json), { signer: null });
});

test('trust: a manifest whose signature does not verify is refused', async () => {
  const s = await trustScene();
  const stranger = await e2e.generateEd25519();
  for (const [name, signer] of [
    ['owner id, stranger key', { user: U.owner.id, seed: stranger.seed }],
    ['editor id, owner key', { user: U.editor.id, seed: U.owner.ed.seed }],
    ['owner id, editor key', { user: U.owner.id, seed: U.editor.ed.seed }],
  ]) {
    const { run } = await trust(s, { signer });
    await assert.rejects(run, UntrustedVersionError, name);
  }
});

test('trust: a trusted signer\'s manifest that is broken is a different error', async () => {
  const s = await trustScene();
  const stale = await trust(s, { signer: signerOf(U.owner), hash: 'a'.repeat(64) });
  await assert.rejects(stale.run, ContentError);
  const wrongVersion = await trust(s, { signer: signerOf(U.owner), over: { version: V2 } });
  await assert.rejects(wrongVersion.run, { name: 'ContentError', message: /version/ });
  const wrongEpoch = await trust(s, { signer: signerOf(U.owner), over: { epoch: 9 } });
  await assert.rejects(wrongEpoch.run, { name: 'ContentError', message: /epoch/ });
});

test('trust: a manifest sealed under another key fails to open', async () => {
  const s = await trustScene();
  const t = await trust(s, { signer: signerOf(U.owner) });
  s.server.versions.get(V1).blob = await e2e.sealBlob(crypto.getRandomValues(new Uint8Array(32)), { artifact: ARTIFACT, version: V1, kind: 'manifest', name: '' }, new TextEncoder().encode('{}'));
  await assert.rejects(t.run, e2e.DecryptError);
});

test('trust: a manifest over 16 MiB is refused unread, and one of 16 MiB is read', async () => {
  const s = await trustScene();
  const t = await trust(s, { signer: signerOf(U.owner) });
  s.server.versions.get(V1).blob = new Uint8Array((16 << 20) + 1);
  await assert.rejects(t.run, { name: 'FormatError', message: /16 MiB/ });
  s.server.versions.get(V1).blob = new Uint8Array(16 << 20);
  await assert.rejects(t.run, (err) => err.name === 'FormatError' && !/16 MiB/.test(err.message));
});

test('trust through a link: the owner, a listed editor, and a vouch', async () => {
  const s = await trustScene({ who: null, isPublic: true });
  assert.equal(s.opened.mode, 'link');
  assert.equal((await (await trust(s, { signer: signerOf(U.owner) })).run()).signer.user, U.owner.id);
  assert.equal((await (await trust(s, { signer: signerOf(U.editor), vid: V2 })).run()).signer.user, U.editor.id);
  const first = await makeVersion(s.world, V1, { signer: signerOf(U.viewer) });
  const vouched = { ...first, json: { ...first.json, vouch: await vouchFor(U.owner, V1, first.manifestHash) } };
  s.server.versions.set(V1, vouched);
  assert.deepEqual(await trustVersion(s.deps, s.opened, vouched.json), { signer: null });
  // No directory is read through a link.
  assert.equal(s.server.calls.some((c) => c.path.startsWith('/api/users/')), false);
});

test('trust through a link: an editor whose keys the membership does not serve is refused', async () => {
  const s = await trustScene({ who: null, isPublic: true });
  const base = s.server.fetch;
  s.deps.fetch = async (path, init) => {
    const resp = await base(path, init);
    if (!path.endsWith('/membership')) return resp;
    const m = await resp.json();
    return new Response(JSON.stringify({ ...m, keys: {} }), { status: 200 });
  };
  s.opened = await open(s, linkFor(s.world));
  const { run } = await trust(s, { signer: signerOf(U.editor) });
  await assert.rejects(run, UntrustedVersionError);
});

test('trust through a link: a version at another epoch has no key', async () => {
  const s = await trustScene({ who: null, isPublic: true, epoch2: true });
  const { run } = await trust(s, { signer: signerOf(U.owner), epoch: 1 });
  await assert.rejects(run, LinkError);
});

// ---- versions, keys, tokens ----

test('prepareVersion refuses an answer for another version', async () => {
  const s = await trustScene();
  const t = await trust(s, { signer: signerOf(U.owner) });
  s.server.versions.set(V2, t.v);
  await assert.rejects(() => prepareVersion(s.deps, s.opened, V2), e2e.FormatError);
  assert.equal((await prepareVersion(s.deps, s.opened, V1)).version.id, V1);
});

test('prepareVersion: only a version the server does not have is not found; a later 404 is not', async () => {
  const s = await trustScene();
  await trust(s, { signer: signerOf(U.owner) });
  await assert.rejects(() => prepareVersion(s.deps, s.opened, V2), VersionGoneError);
  const fetch = s.deps.fetch;
  const deps = { ...s.deps, fetch: (url, init) => (/\/manifest$/.test(String(url)) ? Promise.resolve(new Response('{}', { status: 404 })) : fetch(url, init)) };
  await assert.rejects(() => prepareVersion(deps, s.opened, V1), (err) => err instanceof ApiError && err.status === 404 && !(err instanceof VersionGoneError));
});

test('listVersions is every version as a member, and the link epoch only through a link', async () => {
  const s = await trustScene({ epoch2: true });
  s.server.versions.set(V1, await makeVersion(s.world, V1, { epoch: 1, signer: signerOf(U.owner), seq: 1 }));
  s.server.versions.set(V2, await makeVersion(s.world, V2, { epoch: 2, signer: signerOf(U.owner), seq: 2 }));
  assert.deepEqual((await listVersions(s.deps, s.opened)).map((v) => v.id), [V2, V1]);
  const pub = await scene({ isPublic: true, epoch2: true });
  pub.server.versions = s.server.versions;
  const opened = await open(pub, linkFor(pub.world));
  assert.deepEqual((await listVersions(pub.deps, opened)).map((v) => v.id), [V2]);
});

test('keysMessage builds what checkKeysMessage accepts, with the AK of the version epoch', async () => {
  const s = await trustScene({ epoch2: true });
  const t = await trust(s, { signer: signerOf(U.owner), epoch: 2 });
  const { signer } = await t.run();
  const context = await loadContext(s.deps, s.opened, s.server.artifact);
  const writers = await writerKeys(s.deps, s.opened);
  const msg = keysMessage(s.opened, t.v.json, { signer, token: 'tok', tokenExpires: 123, path: '/a/b', context, writers });
  checkKeysMessage(msg);
  assert.deepEqual(msg.aks, { 2: e2e.b64(s.world.aks[2]) }, 'no AK from before the version');
  assert.equal(msg.currentEpoch, 2);
  assert.equal(msg.writers, writers);
  assert.equal(msg.publicWrites, false);
  const older = keysMessage(s.opened, { ...t.v.json, epoch: 1 }, { signer, token: null, tokenExpires: null, path: '/', context, writers });
  checkKeysMessage(older);
  assert.deepEqual(older.aks, { 1: e2e.b64(s.world.aks[1]), 2: e2e.b64(s.world.aks[2]) }, 'every AK from the version to the latest');
  assert.equal(msg.artifact, ARTIFACT);
  assert.equal(msg.version, V1);
  assert.equal(msg.epoch, 2);
  assert.equal(msg.ak, e2e.b64(s.world.aks[2]));
  assert.equal(msg.manifestHash, t.v.manifestHash);
  assert.deepEqual(msg.signer, signer);
  assert.equal(msg.linkToken, null);
  assert.equal(msg.path, '/a/b');
  assert.equal(msg.token, 'tok');
  assert.equal(msg.tokenExpires, 123);
  // A vouched version has no signer, and a visitor no tokens.
  const bare = keysMessage(s.opened, t.v.json, { signer: null, token: null, tokenExpires: null, path: '/', context, writers });
  checkKeysMessage(bare);
  assert.equal(bare.signer, null);
});

test('keysMessage carries the link token, and refuses an epoch the link does not open', async () => {
  const s = await trustScene({ who: null, isPublic: true, epoch2: true });
  const t = await trust(s, { signer: signerOf(U.owner), epoch: 2 });
  const context = await loadContext(s.deps, s.opened, s.server.artifact);
  const msg = keysMessage(s.opened, t.v.json, { signer: null, token: null, tokenExpires: null, path: '/', context, writers: await writerKeys(s.deps, s.opened) });
  checkKeysMessage(msg);
  assert.equal(msg.linkToken, s.opened.linkToken);
  assert.deepEqual(msg.aks, { 2: e2e.b64(s.world.aks[2]) }, 'a link opens its own epoch only');
  assert.throws(() => keysMessage(s.opened, { ...t.v.json, epoch: 1 }, { signer: null, token: null, tokenExpires: null, path: '/', context }), LinkError);
});

test('writerKeys lists the owner and each editor under their listed key, and no viewer', async () => {
  const s = await trustScene();
  const w = await writerKeys(s.deps, s.opened);
  assert.deepEqual(Object.keys(w).sort(), [U.owner.id, U.editor.id].sort());
  assert.deepEqual(w[U.owner.id], [e2e.b64(U.owner.ed.pub)]);
  assert.deepEqual(w[U.editor.id], [e2e.b64(U.editor.ed.pub)]);
});

test('writerKeys leaves out a key the directory serves under another fingerprint', async () => {
  const s = await trustScene();
  const next = await makeUser('editor');
  s.server.directory.set(U.editor.id, { id: U.editor.id, name: 'editor', email: 'e@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  const w = await writerKeys(s.deps, s.opened);
  assert.deepEqual(w[U.editor.id], []);
});

test('writerKeys follows a rotation from the listed key, and keeps the listed one', async () => {
  const next = await makeUser('editor');
  const s = await trustScene({
    prepare: async (sc) => {
      sc.server.rotations = { [U.editor.id]: [await rotationRecord(U.editor, next)] };
      sc.server.directory.set(U.editor.id, { id: U.editor.id, name: 'editor', email: 'e@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
    },
  });
  const w = await writerKeys(s.deps, s.opened);
  assert.deepEqual(w[U.editor.id].sort(), [e2e.b64(U.editor.ed.pub), e2e.b64(next.ed.pub)].sort());
});

test('writerKeys skips a candidate pair that does not decode', async () => {
  const s = await trustScene();
  s.server.directory.set(U.editor.id, { id: U.editor.id, name: 'editor', email: 'e@example.com', x25519Pub: 'AAAA', ed25519Pub: 'AAAA' });
  const w = await writerKeys(s.deps, s.opened);
  assert.deepEqual(w[U.editor.id], []);
  assert.deepEqual(w[U.owner.id], [e2e.b64(U.owner.ed.pub)]);
});

test('writerKeys through a link uses the editor keys the membership answer serves', async () => {
  const s = await trustScene({ who: null, isPublic: true });
  const w = await writerKeys(s.deps, s.opened);
  assert.deepEqual(w[U.owner.id], [e2e.b64(U.owner.ed.pub)]);
  assert.equal(s.server.calls.some((c) => c.path.startsWith('/api/users/')), false, 'a link visitor asks no directory');
});

test('canWrite: the owner and an editor can, a viewer and a visitor cannot', async () => {
  assert.equal(canWrite((await trustScene({ who: 'owner' })).opened), true);
  assert.equal(canWrite((await trustScene({ who: 'editor' })).opened), true);
  assert.equal(canWrite((await trustScene({ who: 'viewer' })).opened), false);
  assert.equal(canWrite((await trustScene({ who: null, isPublic: true })).opened), false);
});

test('canWrite: through a link, a signed-in caller can only while public writes are on', async () => {
  const on = await scene({ who: 'outsider', isPublic: true, publicWrites: true });
  const opened = await open(on, linkFor(on.world));
  assert.equal(opened.mode, 'link');
  assert.equal(canWrite(opened), true);
  const off = await scene({ who: 'outsider', isPublic: true });
  assert.equal(canWrite(await open(off, linkFor(off.world))), false);
  const visitor = await scene({ isPublic: true, publicWrites: true });
  assert.equal(canWrite(await open(visitor, linkFor(visitor.world))), false, 'a visitor has no keys to sign with');
  // A member who is a viewer opens as a member, not through the link.
  const viewer = await scene({ who: 'viewer', isPublic: true, publicWrites: true });
  assert.equal(canWrite(await open(viewer, linkFor(viewer.world))), false);
});

test('canWrite: a caller with no key-store record cannot', async () => {
  const s = await trustScene({ who: 'owner' });
  assert.equal(canWrite({ ...s.opened, record: null }), false);
});

test('canWrite: a caller the page has not signed in cannot, whatever its record holds', async () => {
  const s = await trustScene({ who: 'owner' });
  assert.equal(canWrite({ ...s.opened, caller: null }), false);
});

const H = (c) => c.repeat(64);
const revisionBody = (over = {}) => ({ artifact: ARTIFACT, version: V2, revision: 3, epoch: 1, sha256: H('a'), ...over });
const recordBody = (over = {}) => ({ artifact: ARTIFACT, version: V2, kind: 'file', name: H('b'), epoch: 1, sha256: H('c'), ...over });

test('signBodies signs as the caller, {v: 1} in schema order, and the worker can verify it', async () => {
  const s = await trustScene({ who: 'editor' });
  const [env] = await signBodies(s.opened, 'revision', [revisionBody()]);
  assert.equal(env.signer, U.editor.id);
  assert.equal(new TextDecoder().decode(e2e.unb64(env.body)), JSON.stringify({ v: 1, artifact: ARTIFACT, version: V2, revision: 3, epoch: 1, sha256: H('a') }));
  assert.deepEqual(await e2e.openEnvelope(env, U.editor.ed.pub, 'revision'), { v: 1, ...revisionBody() });
  const two = await signBodies(s.opened, 'record', [recordBody(), recordBody({ kind: 'file-meta', name: H('d') })]);
  assert.equal(two.length, 2);
  assert.equal(new TextDecoder().decode(e2e.unb64(two[1].body)), JSON.stringify({ v: 1, artifact: ARTIFACT, version: V2, kind: 'file-meta', name: H('d'), epoch: 1, sha256: H('c') }));
  assert.equal(await e2e.verifyEnvelope(U.editor.ed.pub, 'manifest', env), false, 'signed for its purpose only');
});

test('signBodies refuses a caller who cannot write', async () => {
  const s = await trustScene({ who: 'viewer' });
  await assert.rejects(signBodies(s.opened, 'revision', [revisionBody()]), WriteError);
});

test('signBodies refuses a body it was not built to sign', async () => {
  const s = await trustScene({ who: 'owner', epoch2: true });
  const rev = (over) => [revisionBody({ epoch: 2, ...over })];
  const rec = (over) => [recordBody({ epoch: 2, ...over })];
  assert.equal((await signBodies(s.opened, 'revision', rev({}))).length, 1, 'the good body signs');
  const cases = [
    ['manifest', rev({}), 'purpose'],
    ['membership', rev({}), 'purpose'],
    ['toString', rev({}), 'inherited purpose'],
    ['revision', [], 'no bodies'],
    ['revision', [...rev({}), ...rev({}), ...rev({})], 'three bodies'],
    ['revision', revisionBody({ epoch: 2 }), 'not an array'],
    ['revision', [null], 'null body'],
    ['revision', [[1]], 'array body'],
    ['revision', rev({ extra: 1 }), 'extra field'],
    ['revision', [{ artifact: ARTIFACT, version: V2, revision: 3, epoch: 2 }], 'missing field'],
    ['revision', rev({ v: 2 }), 'v supplied'],
    ['revision', rev({ artifact: OTHER_ARTIFACT }), 'other artifact'],
    ['revision', rev({ version: 'x' }), 'version'],
    ['revision', rev({ version: V2.toUpperCase().replace(/5/g, 'A') }), 'upper version'],
    ['revision', rev({ epoch: 1 }), 'old epoch'],
    ['revision', rev({ epoch: 3 }), 'future epoch'],
    ['revision', rev({ epoch: '2' }), 'string epoch'],
    ['revision', rev({ sha256: H('A') }), 'upper sha'],
    ['revision', rev({ sha256: 'a'.repeat(63) }), 'short sha'],
    ['revision', rev({ revision: 0 }), 'revision 0'],
    ['revision', rev({ revision: 1.5 }), 'fraction revision'],
    ['revision', rev({ revision: '3' }), 'string revision'],
    ['revision', rec({}), 'record body for a revision'],
    ['record', rev({}), 'revision body for a record'],
    ['record', rec({ kind: 'database' }), 'kind'],
    ['record', rec({ name: 'notes.txt' }), 'name'],
    ['record', rec({ name: H('B') }), 'upper name'],
  ];
  for (const [purpose, bodies, what] of cases) {
    await assert.rejects(signBodies(s.opened, purpose, bodies), WriteError, what);
  }
  // A good first body does not carry a bad second one.
  await assert.rejects(signBodies(s.opened, 'record', [...rec({}), ...rec({ artifact: OTHER_ARTIFACT })]), WriteError);
});

test('signBodies signs the first revision, and in schema order whatever order the body came in', async () => {
  const s = await trustScene({ who: 'owner', epoch2: true });
  const reversed = Object.fromEntries(Object.entries(revisionBody({ epoch: 2, revision: 1 })).reverse());
  const [env] = await signBodies(s.opened, 'revision', [reversed]);
  assert.equal(
    new TextDecoder().decode(e2e.unb64(env.body)),
    JSON.stringify({ v: 1, artifact: ARTIFACT, version: V2, revision: 1, epoch: 2, sha256: H('a') }),
  );
});

test('signBodies names why it will not sign a body, and a value that only looks like a string does not pass', async () => {
  const s = await trustScene({ who: 'owner', epoch2: true });
  const rev = (over) => [revisionBody({ epoch: 2, ...over })];
  const rec = (over) => [recordBody({ epoch: 2, ...over })];
  const upperFirst = `AAAAAAAA${V2.slice(8)}`;
  const cases = [
    ['revision', ['x'], /not an object/],
    ['revision', [null], /not an object/],
    ['revision', [[1]], /not an object/],
    ['revision', rev({ zzz: 1 }), /wrong fields/],
    ['revision', rev({ version: [V2] }), /names no version/],
    ['revision', rev({ version: `${V2}a` }), /names no version/],
    ['revision', rev({ version: `g${V2}` }), /names no version/],
    ['revision', rev({ version: upperFirst }), /names no version/],
    ['revision', rev({ sha256: [H('a')] }), /no sha256/],
    ['revision', rev({ sha256: 'a'.repeat(65) }), /no sha256/],
    ['revision', rev({ sha256: `g${H('a')}` }), /no sha256/],
    ['revision', rev({ revision: 0 }), /no revision/],
    ['record', rec({ name: [H('b')] }), /names no address/],
    ['record', rec({ name: 'b'.repeat(65) }), /names no address/],
    ['record', rec({ name: `g${H('b')}` }), /names no address/],
    ['record', rec({ kind: 'database' }), /wrong kind/],
  ];
  for (const [purpose, bodies, why] of cases) {
    await assert.rejects(signBodies(s.opened, purpose, bodies), (err) => err instanceof WriteError && why.test(err.message), `${JSON.stringify(bodies)}`);
  }
  assert.equal((await signBodies(s.opened, 'record', rec({ kind: 'file' }))).length, 1);
  assert.equal((await signBodies(s.opened, 'record', rec({ kind: 'file-meta' }))).length, 1);
});

test('loadContext lists the owner and members from the directory, and nobody for a visitor', async () => {
  const s = await trustScene();
  const ctx = await loadContext(s.deps, s.opened, { name: 'Guestbook', description: 'Sign here' });
  assert.deepEqual(ctx.artifact, { id: ARTIFACT, name: 'Guestbook', description: 'Sign here' });
  assert.deepEqual(ctx.users.map((u) => u.id).sort(), [U.owner.id, U.editor.id, U.viewer.id].sort());
  assert.deepEqual(Object.keys(ctx.users[0]).sort(), ['email', 'id', 'name']);
  s.server.notFound.add(U.editor.id);
  assert.equal((await loadContext(s.deps, s.opened, { name: 'n' })).users.length, 2, 'a user the directory dropped is skipped');
  assert.equal((await loadContext(s.deps, s.opened, { name: 'n' })).artifact.description, '');

  const pub = await scene({ isPublic: true });
  const visitor = await open(pub, linkFor(pub.world));
  assert.deepEqual((await loadContext(pub.deps, visitor, { name: 'n' })).users, []);
});

test('mintToken posts for a member without a link token', async () => {
  const s = await trustScene();
  const got = await mintToken(s.deps, s.opened);
  assert.equal(got.tokenExpires, 2000000000);
  assert.match(got.token, /^tok-/);
  const call = s.server.calls.find((c) => c.method === 'POST');
  assert.equal(call.path, `/api/artifacts/${ARTIFACT}/content-token`);
  assert.equal(call.headers['X-Cairn-Link-Token'], undefined);
});

test('mintToken sends the link token for a signed-in link holder, and mints nothing for a visitor', async () => {
  const s = await scene({ who: 'outsider', isPublic: true });
  const opened = await open(s, linkFor(s.world));
  assert.equal((await mintToken(s.deps, opened)).tokenExpires, 2000000000);
  assert.equal(s.server.calls.find((c) => c.method === 'POST').headers['X-Cairn-Link-Token'], opened.linkToken);

  const v = await scene({ isPublic: true });
  const visitor = await open(v, linkFor(v.world));
  assert.deepEqual(await mintToken(v.deps, visitor), { token: null, tokenExpires: null });
  assert.equal(v.server.calls.some((c) => c.method === 'POST'), false);
});

// ---- token renewal ----

function clock(startMs, mintFn) {
  const c = { now: startMs, timers: [], cleared: [], minted: 0, got: [], errors: [] };
  c.keeper = keepToken({
    mint: mintFn ?? (async () => ({ token: `t${c.minted++}`, tokenExpires: Math.floor(c.now / 1000) + 600 })),
    onToken: (t) => c.got.push(t),
    onError: (e) => c.errors.push(e),
    now: () => c.now,
    setTimeout: (fn, ms) => {
      c.timers.push({ fn, ms });
      return c.timers.length;
    },
    clearTimeout: (id) => c.cleared.push(id),
  });
  return c;
}

test('the token is renewed a minute before it expires, and again after that', async () => {
  const c = clock(1_000_000);
  assert.deepEqual(await c.keeper.start(), { token: 't0', tokenExpires: 1600 });
  assert.equal(c.timers.length, 1);
  assert.equal(c.timers[0].ms, 540_000);
  c.now += 540_000;
  await c.timers[0].fn();
  assert.deepEqual(c.got, [{ token: 't1', tokenExpires: 2140 }]);
  assert.deepEqual(c.keeper.current(), { token: 't1', tokenExpires: 2140 });
  assert.equal(c.timers.length, 2, 'the next renewal is scheduled');
  assert.equal(c.timers[1].ms, 540_000);
});

test('a token already inside its last minute is renewed at once', async () => {
  const c = clock(1_000_000, async () => ({ token: 't', tokenExpires: 1030 }));
  await c.keeper.start();
  assert.equal(c.timers[0].ms, 0);
});

test('a visitor has no token to renew', async () => {
  const c = clock(1_000_000, async () => ({ token: null, tokenExpires: null }));
  await c.keeper.start();
  assert.equal(c.timers.length, 0);
});

test('a renewal the server refuses is reported and not retried', async () => {
  for (const status of [401, 403]) {
    let n = 0;
    const c = clock(1_000_000, async () => {
      if (n++ > 0) throw new ApiError('no', status);
      return { token: 't', tokenExpires: 1600 };
    });
    await c.keeper.start();
    await c.timers[0].fn();
    assert.equal(c.errors.length, 1, status);
    assert.equal(c.got.length, 0, status);
    assert.equal(c.timers.length, 1, status);
  }
});

test('a renewal that fails otherwise is retried every 10 seconds, and reported once the token is about to expire', async () => {
  let fail = true;
  const c = clock(1_000_000, async () => {
    if (c.minted++ > 0 && fail) throw new Error('network');
    return { token: `t${c.minted}`, tokenExpires: Math.floor(c.now / 1000) + 600 };
  });
  await c.keeper.start();
  c.now += 540_000;
  await c.timers[0].fn();
  assert.equal(c.errors.length, 0, 'not reported while the token has time left');
  assert.equal(c.timers.length, 2);
  assert.equal(c.timers[1].ms, 10_000);
  fail = false;
  c.now += 10_000;
  await c.timers[1].fn();
  assert.equal(c.got.length, 1, 'the retry renews');
  assert.equal(c.timers[2].ms, 540_000, 'and the next renewal is scheduled as usual');

  fail = true;
  c.now += 540_000;
  await c.timers[2].fn();
  for (let i = 3; c.timers.length > i; i++) {
    c.now += c.timers[i].ms;
    await c.timers[i].fn();
  }
  assert.equal(c.errors.length, 1, 'reported once the token has less than 10 seconds left');
  assert.ok(c.timers.length > 4, 'after several retries');
  assert.ok(c.timers.length < 10);
});

test('stopping cancels the renewal, and a timer that still fires does nothing', async () => {
  const c = clock(1_000_000);
  await c.keeper.start();
  c.keeper.stop();
  assert.deepEqual(c.cleared, [1]);
  await c.timers[0].fn();
  assert.equal(c.minted, 1);
  assert.equal(c.timers.length, 1);
});

// ---- navigation ----

const A = '0123abcd-0123-4abc-8abc-0123456789ab';
const B = 'fedcba98-fedc-4bad-8bad-fedcba987654';

test('navigateTarget accepts a shared page of one or two ids, and maps to full in full mode', () => {
  for (const [href, mode, want] of [
    [`/shared/${A}`, 'shared', `/shared/${A}`],
    [`/shared/${A}/${B}`, 'shared', `/shared/${A}/${B}`],
    [`/shared/${A}/`, 'shared', `/shared/${A}`],
    [`/shared/${A}/${B}/`, 'shared', `/shared/${A}/${B}`],
    [`${ORIGIN}/shared/${A}`, 'shared', `/shared/${A}`],
    [`/shared/${A}`, 'full', `/full/${A}`],
    [`/shared/${A}/${B}`, 'full', `/full/${A}/${B}`],
    [`/shared/${A}/${B}?x=1#frag`, 'shared', `/shared/${A}/${B}`],
    [`/shared/${A}?x=1`, 'full', `/full/${A}`],
  ]) {
    assert.equal(navigateTarget(href, { origin: ORIGIN, mode }), want, `${mode} ${href}`);
  }
});

test('navigateTarget refuses everything else', () => {
  for (const href of [
    '/admin',
    '/',
    'https://evil.example/',
    `https://evil.example/shared/${A}`,
    `//evil.example/shared/${A}`,
    '//evil.example',
    '/\\evil.example',
    `/\\evil.example/shared/${A}`,
    'javascript:alert(1)',
    `http://localhost:8081/shared/${A}`,
    `https://localhost:8080/shared/${A}`,
    '/shared/not-a-uuid',
    `/shared/${A.toUpperCase()}`,
    `/shared/${A.slice(0, 8).toUpperCase()}${A.slice(8)}`,
    `/x/shared/${A}`,
    `/a/b/shared/${A}/${B}`,
    `/shared/${A}/${B.toUpperCase()}`,
    `/shared/${A}/${B}/extra`,
    `/shared/${A}/${B}/${A}`,
    `/shared/${A}/not-a-uuid`,
    `/full/${A}`,
    `/shared/${A}x`,
    `/xshared/${A}`,
    `/shared/../admin`,
    `/shared/${A}/..`,
    '',
    'http://[bad',
  ]) {
    assert.equal(navigateTarget(href, { origin: ORIGIN, mode: 'shared' }), null, href);
  }
});
