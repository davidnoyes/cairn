// Tests for sharing.mjs against real chains, wraps, estate copies, keyrings,
// databases, files, versions and metadata (see sharing_fixture.mjs), behind a
// stateful fake of the server. They mirror the Go tests of internal/client
// (share_test.go, epoch_test.go, public_test.go, reseal_test.go and
// reseal_version_test.go), and every refusal has a test of its own. Run with:
// node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { ApiError } from './account.mjs';
import { V1, V2, buildWorld, readServerKeyring, rotationRecord, seedKeyring, makeUser } from './viewer_fixture.mjs';
import { openArtifact } from './viewer.mjs';
import { readMeta } from './meta.mjs';
import { ARTIFACT, ORIGIN, depsFor, extraUser, keyStoreRecord, makeShareServer, metaItem, seedDatabase, seedFile, seedMeta, seedVersion } from './sharing_fixture.mjs';
import { KeyChangedError, SharingError, members, pin, publicLinkFor, reseal, setPublic, share, unshare } from './sharing.mjs';

const U = {};
for (const name of ['owner', 'editor', 'viewer', 'outsider']) U[name] = await makeUser(name);
U.other = await extraUser('other', '88888888-8888-4888-8888-888888888888');
const records = {};
for (const name of Object.keys(U)) records[name] = await keyStoreRecord(U[name]);
const enc = new TextEncoder();
const dec = new TextDecoder();

const STD_MEMBERS = [
  { user: U.editor, role: 'editor' },
  { user: U.viewer, role: 'viewer' },
];

async function scene({ who = 'owner', members: m = STD_MEMBERS, users = [U.outsider, U.other], ...worldOpts } = {}) {
  const world = await buildWorld({ owner: U.owner, members: m, ...worldOpts });
  const server = makeShareServer(world, { who: U[who], users });
  return { world, server, deps: depsFor(server, records[who]) };
}

const bodyOf = (env) => JSON.parse(dec.decode(e2e.unb64(env.body)));
const lastPut = (s) => s.server.puts.membership.at(-1);
const noPuts = (s) => assert.deepEqual(s.server.puts, { membership: [], meta: [], db: [], file: [], version: [] });
const headOf = (world, i) => e2e.bodyHash(e2e.unb64(world.records[i].body));

async function unwrapFor(name, w) {
  const ctx = { purpose: 'ak', artifact: ARTIFACT, epoch: w.epoch, recipientId: U[name].id, recipientPub: U[name].x.pub };
  return e2e.unwrap(records[name].x25519, ctx, e2e.unb64(w.wrapped));
}

async function estateAK(put, epoch) {
  const copy = put.estate.find((e) => e.epoch === epoch);
  return e2e.open(await e2e.ekSealCryptoKey(U.owner.ek), ['estate', ARTIFACT, String(epoch)], e2e.unb64(copy.sealed));
}

const pinned = (fp, state = 'unverified') => ({ fp, state, rotSeq: 0, rotHead: '' });

async function seedPins(s, pins) {
  const k = e2e.newKeyring();
  Object.assign(k.pins, pins);
  await seedKeyring(s.server, U.owner, k);
}

// openAs opens the artifact as another signed-in user, on the same server.
async function openAs(s, name) {
  const deps = asUser(s, name);
  return openArtifact(deps, { artifact: ARTIFACT, link: null });
}

// asUser is the deps of another signed-in user on the same server, which holds
// the owner's keyring until the user has one of their own.
function asUser(s, name) {
  s.server.who = U[name];
  s.server.keyring = { rev: 0, keyring: '' };
  return depsFor(s.server, records[name]);
}

// ---- share ----

test('share adds a viewer at the current epoch with a wrap of every epoch, and pins them', async () => {
  const s = await scene({ epoch2: true });
  const res = await share(s.deps, ARTIFACT, ' OUTSIDER@Example.com ', 'viewer');
  assert.equal(res.epoch, 2);
  assert.equal(res.reseal, null);
  assert.equal(s.server.puts.membership.length, 1);
  const put = lastPut(s);
  const body = bodyOf(put.membership);
  assert.equal(body.seq, 4);
  assert.equal(body.epoch, 2);
  assert.equal(body.akCommit, bodyOf(s.world.records[2]).akCommit);
  assert.equal(body.prev, await headOf(s.world, 2));
  assert.deepEqual(body.members.map((m) => m.user), [U.editor.id, U.viewer.id, U.outsider.id]);
  assert.deepEqual(body.members.at(-1), { user: U.outsider.id, role: 'viewer', fp: U.outsider.fp });
  assert.equal(body.transfer, '');
  assert.equal(body.handover, '');
  assert.deepEqual(put.estate, []);
  assert.equal(put.linkTokenHash, '');
  assert.deepEqual(put.wraps.map((w) => [w.user, w.epoch]), [[U.outsider.id, 1], [U.outsider.id, 2]]);
  for (const w of put.wraps) assert.deepEqual(await unwrapFor('outsider', w), s.world.aks[w.epoch]);
  const kr = await readServerKeyring(s.server, U.owner);
  assert.deepEqual(kr.pins[U.outsider.id], pinned(U.outsider.fp));
  assert.equal(kr.epochs[ARTIFACT].seq, 4, 'the read-back stored the new chain');
  // The new member opens it with the wraps they were given.
  const opened = await openAs(s, 'outsider');
  assert.deepEqual(opened.aks.get(1), s.world.aks[1]);
  assert.deepEqual(opened.aks.get(2), s.world.aks[2]);
});

test('share finds a user by ID', async () => {
  const s = await scene();
  await share(s.deps, ARTIFACT, U.other.id, 'editor');
  assert.deepEqual(bodyOf(lastPut(s).membership).members.at(-1), { user: U.other.id, role: 'editor', fp: U.other.fp });
});

test('share promotes a viewer to editor in the same epoch with no wrap', async () => {
  const s = await scene();
  const res = await share(s.deps, ARTIFACT, 'viewer@example.com', 'editor');
  assert.equal(res.promoted, true);
  assert.equal(res.epoch, 1);
  const put = lastPut(s);
  assert.deepEqual(put.wraps, []);
  assert.deepEqual(bodyOf(put.membership).members.find((m) => m.user === U.viewer.id), { user: U.viewer.id, role: 'editor', fp: U.viewer.fp });
});

test('share with the role they already hold writes nothing', async () => {
  const s = await scene();
  const res = await share(s.deps, ARTIFACT, 'viewer@example.com', 'viewer');
  assert.equal(res.unchanged, true);
  noPuts(s);
});

test('share demoting an editor starts a new epoch and wraps it to every member', async () => {
  const s = await scene();
  const res = await share(s.deps, ARTIFACT, 'editor@example.com', 'viewer');
  assert.equal(res.demoted, true);
  assert.equal(res.epoch, 2);
  const put = lastPut(s);
  const body = bodyOf(put.membership);
  assert.equal(body.epoch, 2);
  assert.deepEqual(body.members, [{ user: U.editor.id, role: 'viewer', fp: U.editor.fp }, { user: U.viewer.id, role: 'viewer', fp: U.viewer.fp }]);
  assert.deepEqual(body.excluded, []);
  const ak2 = await estateAK(put, 2);
  assert.equal(await e2e.akCommit(ak2, ARTIFACT, 2), body.akCommit);
  assert.notDeepEqual(ak2, s.world.aks[1]);
  assert.deepEqual(put.wraps.map((w) => [w.user, w.epoch]), [[U.editor.id, 2], [U.viewer.id, 2]]);
  assert.deepEqual(await unwrapFor('editor', put.wraps[0]), ak2);
  assert.equal(res.reseal.error, undefined);
  assert.equal((await readServerKeyring(s.server, U.owner)).epochs[ARTIFACT].epoch, 2);
});

test('share demoting an editor on a public artifact returns the new link', async () => {
  const s = await scene({ isPublic: true });
  const res = await share(s.deps, ARTIFACT, 'editor@example.com', 'viewer');
  const put = lastPut(s);
  const link = e2e.parseLink(res.link);
  assert.equal(link.epoch, 2);
  assert.deepEqual(link.ak, await estateAK(put, 2));
  assert.equal(put.linkTokenHash, await e2e.linkTokenHash(await e2e.linkToken(link.ak, ARTIFACT, 2)));
});

test('share refuses a changed key until the owner accepts it, then pins the new one', async () => {
  const s = await scene();
  await seedPins(s, { [U.viewer.id]: pinned('a'.repeat(64), 'verified') });
  const err = await share(s.deps, ARTIFACT, 'viewer@example.com', 'editor').catch((e) => e);
  assert.ok(err instanceof KeyChangedError);
  assert.equal(err.user, U.viewer.id);
  assert.equal(err.email, 'viewer@example.com');
  assert.equal(err.fp, U.viewer.fp);
  assert.equal(err.pinnedFp, 'a'.repeat(64));
  noPuts(s);
  assert.equal((await readServerKeyring(s.server, U.owner)).pins[U.viewer.id].fp, 'a'.repeat(64), 'the pin is not touched');

  const res = await share(s.deps, ARTIFACT, 'viewer@example.com', 'editor', { acceptNewKey: true });
  assert.equal(res.prior, 'changed');
  assert.deepEqual((await readServerKeyring(s.server, U.owner)).pins[U.viewer.id], pinned(U.viewer.fp));
  assert.equal(s.server.puts.membership.length, 1);
});

test('share demoting an editor whose keys changed, accepting them, wraps every epoch under the new keys', async () => {
  const s = await scene({ members: [{ user: U.editor, role: 'editor', fp: 'f'.repeat(64) }, { user: U.viewer, role: 'viewer' }] });
  await seedPins(s, { [U.editor.id]: pinned('a'.repeat(64), 'verified') });
  const err = await share(s.deps, ARTIFACT, 'editor@example.com', 'viewer').catch((e) => e);
  assert.ok(err instanceof KeyChangedError);
  noPuts(s);
  const res = await share(s.deps, ARTIFACT, 'editor@example.com', 'viewer', { acceptNewKey: true });
  assert.equal(res.epoch, 2);
  const put = lastPut(s);
  assert.deepEqual(put.wraps.map((w) => [w.user, w.epoch]), [[U.editor.id, 1], [U.editor.id, 2], [U.viewer.id, 2]]);
  assert.deepEqual(bodyOf(put.membership).members[0], { user: U.editor.id, role: 'viewer', fp: U.editor.fp });
  assert.deepEqual((await readServerKeyring(s.server, U.owner)).pins[U.editor.id], pinned(U.editor.fp));
});

test('share refuses a directory key that is not 32 bytes', async () => {
  const s = await scene();
  s.server.directory.set(U.outsider.id, { ...s.server.directory.get(U.outsider.id), x25519Pub: e2e.b64(new Uint8Array(16)) });
  await assert.rejects(() => share(s.deps, ARTIFACT, 'viewer@example.com', 'editor'), e2e.FormatError);
  s.server.directory.set(U.outsider.id, { ...s.server.directory.get(U.outsider.id), x25519Pub: U.outsider.pair.x25519, ed25519Pub: e2e.b64(new Uint8Array(33)) });
  await assert.rejects(() => pin(s.deps, 'viewer@example.com'), e2e.FormatError);
  noPuts(s);
});

test('share refuses a changed key it cannot place when the rotation records are unreadable, and says so', async () => {
  const s = await scene();
  await seedPins(s, { [U.viewer.id]: pinned('a'.repeat(64)) });
  const base = s.server.fetch;
  s.deps.fetch = async (path, init) => (path.endsWith('/rotations') ? new Response('{"error":"boom"}', { status: 500 }) : base(path, init));
  const err = await share(s.deps, ARTIFACT, 'viewer@example.com', 'editor').catch((e) => e);
  assert.ok(err instanceof KeyChangedError);
  assert.ok(err.fetchErr instanceof ApiError);
  assert.match(err.message, /Could not read the rotation records/);
  noPuts(s);
});

test('share lists a member who rotated under their new keys, wrapping every epoch', async () => {
  const s = await scene();
  const next = await makeUser('outsider');
  next.id = U.viewer.id;
  s.server.directory.set(U.viewer.id, { id: U.viewer.id, name: 'viewer', email: 'viewer@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  s.server.rotations[U.viewer.id] = [await rotationRecord(U.viewer, next)];
  await seedPins(s, { [U.viewer.id]: pinned(U.viewer.fp, 'verified') });
  const res = await share(s.deps, ARTIFACT, 'viewer@example.com', 'editor');
  assert.equal(res.prior, 'rotated');
  assert.equal(res.wasVerified, true);
  const body = bodyOf(lastPut(s).membership);
  assert.deepEqual(body.members.find((m) => m.user === U.viewer.id), { user: U.viewer.id, role: 'editor', fp: next.fp });
  assert.deepEqual(lastPut(s).wraps.map((w) => w.epoch), [1]);
  const stored = (await readServerKeyring(s.server, U.owner)).pins[U.viewer.id];
  assert.equal(stored.fp, next.fp);
  assert.equal(stored.state, 'unverified', 'a rotation drops a verified pin');
  assert.equal(stored.rotSeq, 1);
});

test('share refusals', async () => {
  const s = await scene();
  const code = async (p) => (await p.catch((e) => e)).code;
  assert.equal(await code(share(s.deps, ARTIFACT, 'outsider@example.com', 'owner')), 'bad-role');
  assert.equal(await code(share(s.deps, ARTIFACT, 'outsider@example.com', '')), 'bad-role');
  assert.equal(await code(share(s.deps, ARTIFACT, 'owner@example.com', 'viewer')), 'share-self');
  assert.equal(await code(share(s.deps, ARTIFACT, 'nobody@example.com', 'viewer')), 'unknown-user');
  noPuts(s);

  const editor = await scene({ who: 'editor' });
  assert.equal(await code(share(editor.deps, ARTIFACT, 'outsider@example.com', 'viewer')), 'not-owner');
  noPuts(editor);

  const signedOut = await scene();
  signedOut.deps.keyStore = { load: async () => null };
  assert.equal(await code(share(signedOut.deps, ARTIFACT, 'outsider@example.com', 'viewer')), 'not-signed-in');

  // The owner's session with another user's keys left in the browser.
  const locked = await scene();
  locked.deps.keyStore = { load: async () => records.editor };
  assert.equal(await code(share(locked.deps, ARTIFACT, 'outsider@example.com', 'viewer')), 'not-signed-in');
  noPuts(locked);
});

test('share refuses a directory in which two users share an email or a fingerprint', async () => {
  const email = await scene();
  email.server.directory.set(U.other.id, { ...email.server.directory.get(U.other.id), email: 'Outsider@example.com' });
  assert.equal((await share(email.deps, ARTIFACT, 'viewer@example.com', 'editor').catch((e) => e)).code, 'directory-duplicate');
  noPuts(email);

  const fp = await scene();
  fp.server.directory.set(U.other.id, { ...fp.server.directory.get(U.outsider.id), id: U.other.id, email: 'other@example.com' });
  const err = await share(fp.deps, ARTIFACT, 'viewer@example.com', 'editor').catch((e) => e);
  assert.equal(err.code, 'directory-duplicate');
  assert.match(err.message, /fingerprint/);
  noPuts(fp);
});

test('share refuses a chain whose epoch is below the one the keyring pins', async () => {
  const s = await scene();
  const k = e2e.newKeyring();
  k.epochs[ARTIFACT] = { epoch: 5, seq: 2, head: await headOf(s.world, 1), ack: 0 };
  await seedKeyring(s.server, U.owner, k);
  await assert.rejects(() => share(s.deps, ARTIFACT, 'outsider@example.com', 'viewer'), e2e.StaleEpochError);
  noPuts(s);
});

test('share refuses a chain shorter than, or forked from, the one the keyring pins', async () => {
  const s = await scene({ epoch2: true });
  const k = e2e.newKeyring();
  k.epochs[ARTIFACT] = { epoch: 2, seq: 3, head: await headOf(s.world, 2), ack: 0 };
  await seedKeyring(s.server, U.owner, k);
  s.server.records = s.world.records.slice(0, 2);
  await assert.rejects(() => share(s.deps, ARTIFACT, 'outsider@example.com', 'viewer'), e2e.RollbackError);
  k.rev = 1;
  k.epochs[ARTIFACT].head = 'e'.repeat(64);
  s.server.records = [...s.world.records];
  await seedKeyring(s.server, U.owner, k);
  s.deps.storage = depsFor(s.server, records.owner).storage;
  await assert.rejects(() => share(s.deps, ARTIFACT, 'outsider@example.com', 'viewer'), e2e.ForkError);
  noPuts(s);
});

test('share refuses an estate copy that misses the akCommit', async () => {
  const s = await scene();
  const wrong = crypto.getRandomValues(new Uint8Array(32));
  s.server.estate = [{ epoch: 1, sealed: e2e.b64(await e2e.seal(await e2e.ekSealCryptoKey(U.owner.ek), ['estate', ARTIFACT, '1'], wrong)) }];
  await assert.rejects(() => share(s.deps, ARTIFACT, 'outsider@example.com', 'viewer'), e2e.ChainError);
  noPuts(s);
});

test('share leaves no pin when the membership write fails', async () => {
  const s = await scene();
  s.server.failPut = (kind) => (kind === 'membership' ? new Response('{"error":"nope"}', { status: 500 }) : null);
  await assert.rejects(() => share(s.deps, ARTIFACT, 'outsider@example.com', 'viewer'), { status: 500 });
  assert.deepEqual((await readServerKeyring(s.server, U.owner)).pins, {});
});

test('share refuses a team artifact and an unacknowledged handover', async () => {
  const team = await scene();
  const latest = bodyOf(team.world.records[1]);
  const record = await e2e.newEnvelope(U.owner.ed.seed, U.owner.id, 'membership', enc.encode(JSON.stringify({ ...latest, seq: 3, team: 'viewer', prev: await headOf(team.world, 1) })));
  team.server.records = [...team.world.records, record];
  for (const fn of [
    () => share(team.deps, ARTIFACT, 'outsider@example.com', 'viewer'),
    () => unshare(team.deps, ARTIFACT, 'editor@example.com'),
    () => setPublic(team.deps, ARTIFACT, true),
  ]) assert.equal((await fn().catch((e) => e)).code, 'team-unsupported');
  noPuts(team);

  // An administrator hands the artifact to the editor, who is listed as one.
  const h = await scene();
  const prev = bodyOf(h.world.records[1]);
  const handover = await e2e.newEnvelope(U.editor.ed.seed, U.editor.id, 'membership', enc.encode(JSON.stringify({
    ...prev, seq: 3, owner: U.editor.id, ownerFp: U.editor.fp, members: prev.members.filter((m) => m.user !== U.editor.id), handover: 'admin', prev: await headOf(h.world, 1),
  })));
  h.server.records = [...h.world.records, handover];
  h.server.owners[U.editor.fp] = U.editor.pair;
  for (const fn of [
    () => share(h.deps, ARTIFACT, 'outsider@example.com', 'viewer'),
    () => reseal(h.deps, ARTIFACT),
  ]) {
    const err = await fn().catch((e) => e);
    assert.equal(err.code, 'handover-not-acked');
    assert.equal(err.seq, 3);
  }
  noPuts(h);
});

// ---- unshare ----

test('unshare starts a new epoch wrapped to the members who stay, and excludes the one removed', async () => {
  const s = await scene();
  const res = await unshare(s.deps, ARTIFACT, U.editor.id);
  assert.equal(res.epoch, 2);
  assert.equal(res.user.id, U.editor.id);
  assert.deepEqual(res.excluded.map((x) => [x.user.id, x.reason]), [[U.editor.id, 'removed']]);
  assert.equal(res.link, '');
  const put = lastPut(s);
  const body = bodyOf(put.membership);
  assert.equal(body.epoch, 2);
  assert.equal(body.seq, 3);
  assert.deepEqual(body.members, [{ user: U.viewer.id, role: 'viewer', fp: U.viewer.fp }]);
  assert.deepEqual(body.excluded, [{ user: U.editor.id, fp: U.editor.fp, email: 'editor@example.com' }]);
  assert.notEqual(body.akCommit, bodyOf(s.world.records[1]).akCommit);
  const ak2 = await estateAK(put, 2);
  assert.equal(await e2e.akCommit(ak2, ARTIFACT, 2), body.akCommit);
  assert.equal(put.estate.length, 1);
  assert.equal(put.linkTokenHash, '');
  // The new AK goes to the member who stays, and to nobody else.
  assert.deepEqual(put.wraps.map((w) => [w.user, w.epoch]), [[U.viewer.id, 2]]);
  assert.deepEqual(await unwrapFor('viewer', put.wraps[0]), ak2);
  assert.equal(res.reseal.error, undefined);
  // The read-back verified the chain and the keyring stores it.
  assert.equal((await readServerKeyring(s.server, U.owner)).epochs[ARTIFACT].seq, 3);
});

test('unshare by email, and a removed member who is the last one', async () => {
  const s = await scene({ members: [{ user: U.viewer, role: 'viewer' }] });
  await unshare(s.deps, ARTIFACT, 'Viewer@example.com');
  assert.deepEqual(bodyOf(lastPut(s).membership).members, []);
  assert.deepEqual(lastPut(s).wraps, []);
});

test('unshare refusals', async () => {
  const s = await scene();
  const code = async (p) => (await p.catch((e) => e)).code;
  assert.equal(await code(unshare(s.deps, ARTIFACT, 'owner@example.com')), 'unshare-owner');
  assert.equal(await code(unshare(s.deps, ARTIFACT, 'outsider@example.com')), 'not-member');
  assert.equal(await code(unshare(s.deps, ARTIFACT, 'nobody@example.com')), 'unknown-user');
  assert.equal(await code(unshare(s.deps, ARTIFACT, U.outsider.id)), 'not-member');
  noPuts(s);
  const editor = await scene({ who: 'editor' });
  assert.equal(await code(unshare(editor.deps, ARTIFACT, 'viewer@example.com')), 'not-owner');
  noPuts(editor);
});

test('unshare twice finds the user is no longer a member', async () => {
  const s = await scene();
  await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.equal((await unshare(s.deps, ARTIFACT, 'editor@example.com').catch((e) => e)).code, 'not-member');
});

test('a next epoch refuses a member whose keys changed since the record listed them', async () => {
  const s = await scene();
  const next = await makeUser('outsider');
  s.server.directory.set(U.viewer.id, { id: U.viewer.id, name: 'viewer', email: 'viewer@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  const err = await unshare(s.deps, ARTIFACT, 'editor@example.com').catch((e) => e);
  assert.equal(err.code, 'member-key-changed');
  noPuts(s);
});

test('a next epoch refuses a pinned member whose keys changed, with the KeyChangedError', async () => {
  const s = await scene();
  await seedPins(s, { [U.viewer.id]: pinned('a'.repeat(64), 'verified') });
  const err = await unshare(s.deps, ARTIFACT, 'editor@example.com').catch((e) => e);
  assert.ok(err instanceof KeyChangedError);
  assert.equal(err.user, U.viewer.id);
  noPuts(s);
});

test('a next epoch pins a member whose rotation chain explains their new keys', async () => {
  const s = await scene();
  const next = await makeUser('outsider');
  // The record lists the viewer under the new keys already, as a re-share would.
  s.server.records = [...s.world.records];
  s.server.directory.set(U.viewer.id, { id: U.viewer.id, name: 'viewer', email: 'viewer@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  s.server.rotations[U.viewer.id] = [await rotationRecord(U.viewer, next)];
  await share(s.deps, ARTIFACT, 'viewer@example.com', 'viewer');
  const put = lastPut(s);
  assert.equal(bodyOf(put.membership).members.find((m) => m.user === U.viewer.id).fp, next.fp);
  // Now the next epoch lists them under the same keys, and nothing is left to decide.
  await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.equal(bodyOf(lastPut(s).membership).members[0].fp, next.fp);
});

test('a next epoch refuses an AK that an earlier epoch used', async () => {
  const s = await scene();
  s.deps.newAK = async () => s.world.aks[1];
  await assert.rejects(() => unshare(s.deps, ARTIFACT, 'editor@example.com'), e2e.ReusedAkError);
  noPuts(s);
});

test('a next epoch uses the AK deps.newAK makes, and a random one otherwise', async () => {
  const s = await scene();
  const ak = crypto.getRandomValues(new Uint8Array(32));
  s.deps.newAK = async () => ak;
  await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.deepEqual(await estateAK(lastPut(s), 2), ak);
});

test('a next epoch refuses a stale epoch', async () => {
  const s = await scene();
  const k = e2e.newKeyring();
  k.epochs[ARTIFACT] = { epoch: 4, seq: 2, head: await headOf(s.world, 1), ack: 0 };
  await seedKeyring(s.server, U.owner, k);
  await assert.rejects(() => unshare(s.deps, ARTIFACT, 'editor@example.com'), e2e.StaleEpochError);
  noPuts(s);
});

test('a next epoch keeps the entries of earlier exclusions', async () => {
  const s = await scene();
  await unshare(s.deps, ARTIFACT, 'editor@example.com');
  await unshare(s.deps, ARTIFACT, 'viewer@example.com');
  const body = bodyOf(lastPut(s).membership);
  assert.equal(body.epoch, 3);
  assert.deepEqual(body.excluded.map((x) => x.user), [U.editor.id, U.viewer.id]);
});

test('share by name readmits an excluded user, dropping their entry and wrapping every epoch', async () => {
  const s = await scene();
  await unshare(s.deps, ARTIFACT, 'viewer@example.com');
  const res = await share(s.deps, ARTIFACT, 'viewer@example.com', 'viewer');
  assert.deepEqual(res.dropped.map((x) => x.user), [U.viewer.id]);
  const put = lastPut(s);
  const body = bodyOf(put.membership);
  assert.deepEqual(body.excluded, []);
  assert.deepEqual(body.members.map((m) => m.user), [U.editor.id, U.viewer.id]);
  assert.equal(body.epoch, 2);
  assert.deepEqual(put.wraps.map((w) => [w.user, w.epoch]), [[U.viewer.id, 1], [U.viewer.id, 2]]);
});

test('unshare removes a member whose account was deleted, naming them by ID', async () => {
  const s = await scene();
  s.server.directory.delete(U.viewer.id);
  const res = await unshare(s.deps, ARTIFACT, U.viewer.id);
  assert.equal(res.user.id, U.viewer.id);
  assert.match(res.excluded[0].reason, /account was deleted/);
  const body = bodyOf(lastPut(s).membership);
  assert.deepEqual(body.excluded, [{ user: U.viewer.id, fp: U.viewer.fp, email: U.viewer.id }]);
  assert.deepEqual(body.members.map((m) => m.user), [U.editor.id]);
});

test('a next epoch refuses a listed member whose account was deleted', async () => {
  const s = await scene();
  s.server.directory.delete(U.viewer.id);
  const err = await unshare(s.deps, ARTIFACT, 'editor@example.com').catch((e) => e);
  assert.equal(err.code, 'member-deleted');
  noPuts(s);
});

test('unshare on a public artifact returns the new link and its token hash', async () => {
  const s = await scene({ isPublic: true });
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  const put = lastPut(s);
  const link = e2e.parseLink(res.link);
  assert.equal(link.host, ORIGIN);
  assert.equal(link.artifact, ARTIFACT);
  assert.equal(link.epoch, 2);
  assert.equal(link.o, U.owner.fp);
  assert.deepEqual(link.ak, await estateAK(put, 2));
  assert.equal(bodyOf(put.membership).public, true);
  assert.equal(put.linkTokenHash, await e2e.linkTokenHash(await e2e.linkToken(link.ak, ARTIFACT, 2)));
  const old = await e2e.linkTokenHash(await e2e.linkToken(s.world.aks[1], ARTIFACT, 1));
  assert.notEqual(put.linkTokenHash, old, 'the old link stops working');
});

test('unshare names the new link when the read-back fails', async () => {
  const s = await scene({ isPublic: true });
  const base = s.server.fetch;
  let written = false;
  s.deps.fetch = async (path, init = {}) => {
    const resp = await base(path, init);
    if ((init.method ?? 'GET') === 'PUT' && path.endsWith('/membership')) written = true;
    if (written && path.endsWith('/membership') && (init.method ?? 'GET') === 'GET') {
      const data = await resp.json();
      const last = data.records.at(-1);
      data.records[data.records.length - 1] = { ...last, sig: e2e.b64(new Uint8Array(64)) };
      return new Response(JSON.stringify(data), { status: 200 });
    }
    return resp;
  };
  const err = await unshare(s.deps, ARTIFACT, 'editor@example.com').catch((e) => e);
  assert.ok(err instanceof SharingError);
  assert.equal(err.code, 'read-back');
  assert.match(err.message, /reading it back failed/);
  assert.match(err.message, new RegExp(`the new public link is ${ORIGIN}/shared/${ARTIFACT}#k=`));
});

// ---- public ----

test('setPublic on makes a link whose token hash the record carries, in the same epoch', async () => {
  const s = await scene();
  const res = await setPublic(s.deps, ARTIFACT, true);
  assert.equal(res.epoch, 1);
  assert.equal(res.reseal, null);
  const link = e2e.parseLink(res.link);
  assert.deepEqual(link, { host: ORIGIN, artifact: ARTIFACT, ak: s.world.aks[1], epoch: 1, o: U.owner.fp });
  const put = lastPut(s);
  const body = bodyOf(put.membership);
  assert.equal(body.public, true);
  assert.equal(body.publicWrites, false);
  assert.equal(body.epoch, 1);
  assert.equal(body.seq, 3);
  assert.deepEqual([put.wraps, put.estate], [[], []]);
  assert.equal(put.linkTokenHash, await e2e.linkTokenHash(await e2e.linkToken(s.world.aks[1], ARTIFACT, 1)));
  assert.equal((await readServerKeyring(s.server, U.owner)).epochs[ARTIFACT].seq, 3);
});

test('setPublic on twice writes one record', async () => {
  const s = await scene();
  const first = await setPublic(s.deps, ARTIFACT, true);
  const again = await setPublic(s.deps, ARTIFACT, true);
  assert.equal(again.unchanged, true);
  assert.equal(again.link, first.link);
  assert.equal(s.server.puts.membership.length, 1);
});

test('setPublic sets public writes, and leaves them as they are when not given', async () => {
  const s = await scene();
  await setPublic(s.deps, ARTIFACT, true, { writes: true });
  assert.equal(bodyOf(lastPut(s).membership).publicWrites, true);
  const kept = await setPublic(s.deps, ARTIFACT, true);
  assert.equal(kept.unchanged, true);
  assert.equal(kept.publicWrites, true);
  await setPublic(s.deps, ARTIFACT, true, { writes: false });
  assert.equal(bodyOf(lastPut(s).membership).publicWrites, false);
  assert.equal(s.server.puts.membership.length, 2);
});

test('setPublic off on a public artifact starts a new epoch, so the old link stops working', async () => {
  const s = await scene({ isPublic: true, publicWrites: true });
  const res = await setPublic(s.deps, ARTIFACT, false);
  assert.equal(res.link, null);
  assert.equal(res.epoch, 2);
  assert.equal(res.newEpoch, true);
  assert.ok(res.reseal);
  const put = lastPut(s);
  const body = bodyOf(put.membership);
  assert.equal(body.public, false);
  assert.equal(body.publicWrites, false);
  assert.equal(body.epoch, 2);
  assert.equal(put.linkTokenHash, '');
  const ak2 = await estateAK(put, 2);
  assert.equal(await e2e.akCommit(ak2, ARTIFACT, 2), body.akCommit);
  assert.deepEqual(put.wraps.map((w) => [w.user, w.epoch]), [[U.editor.id, 2], [U.viewer.id, 2]]);
  assert.deepEqual(body.excluded, []);
});

test('setPublic off on a private artifact writes nothing', async () => {
  const s = await scene();
  const res = await setPublic(s.deps, ARTIFACT, false);
  assert.equal(res.unchanged, true);
  noPuts(s);
});

test('setPublic refuses public writes with off, a caller who is not the owner, and a host no link can name', async () => {
  const s = await scene();
  assert.equal((await setPublic(s.deps, ARTIFACT, false, { writes: true }).catch((e) => e)).code, 'public-writes-with-off');
  assert.equal((await setPublic(s.deps, ARTIFACT, false, { writes: false }).catch((e) => e)).code, 'public-writes-with-off');
  const editor = await scene({ who: 'editor' });
  assert.equal((await setPublic(editor.deps, ARTIFACT, true).catch((e) => e)).code, 'not-owner');
  s.deps.origin = 'ftp://example.com';
  assert.equal((await setPublic(s.deps, ARTIFACT, true).catch((e) => e)).code, 'bad-host');
  noPuts(s);
  noPuts(editor);
});

test('publicLinkFor rebuilds the link for any member, and is null for a private artifact', async () => {
  const priv = await scene();
  assert.equal(await publicLinkFor(priv.deps, ARTIFACT), null);
  const s = await scene({ isPublic: true, epoch2: true });
  const owner = await publicLinkFor(s.deps, ARTIFACT);
  const link = e2e.parseLink(owner);
  assert.deepEqual([link.epoch, link.ak], [2, s.world.aks[2]]);
  assert.equal(await publicLinkFor(asUser(s, 'viewer'), ARTIFACT), owner);
  noPuts(s);
});

test('publicLinkFor returns the link setPublic made', async () => {
  const s = await scene();
  const res = await setPublic(s.deps, ARTIFACT, true);
  assert.equal(await publicLinkFor(s.deps, ARTIFACT), res.link);
});

// ---- pins ----

test('pin records a user unverified on first sight, and verified when asked', async () => {
  const s = await scene();
  const first = await pin(s.deps, 'outsider@example.com');
  assert.deepEqual([first.prior, first.state, first.wasVerified, first.user.id], ['new', 'unverified', false, U.outsider.id]);
  assert.deepEqual((await readServerKeyring(s.server, U.owner)).pins[U.outsider.id], pinned(U.outsider.fp));
  const second = await pin(s.deps, 'outsider@example.com', { verified: true });
  assert.deepEqual([second.prior, second.state], ['unverified', 'verified']);
  assert.equal((await readServerKeyring(s.server, U.owner)).pins[U.outsider.id].state, 'verified');
  // Pinning again without verifying does not downgrade, and writes nothing.
  const rev = s.server.keyring.rev;
  const third = await pin(s.deps, U.outsider.id);
  assert.equal(third.state, 'verified');
  assert.equal(s.server.keyring.rev, rev);
});

test('pin refuses a changed key until the owner accepts it', async () => {
  const s = await scene();
  await seedPins(s, { [U.outsider.id]: pinned('a'.repeat(64), 'verified') });
  const err = await pin(s.deps, 'outsider@example.com').catch((e) => e);
  assert.ok(err instanceof KeyChangedError);
  assert.equal(err.fp, U.outsider.fp);
  assert.equal((await readServerKeyring(s.server, U.owner)).pins[U.outsider.id].fp, 'a'.repeat(64));
  const res = await pin(s.deps, 'outsider@example.com', { acceptNewKey: true });
  assert.deepEqual([res.prior, res.state], ['changed', 'unverified']);
  assert.equal((await readServerKeyring(s.server, U.owner)).pins[U.outsider.id].fp, U.outsider.fp);
});

test('pin follows a rotation chain, and says it dropped a verified pin', async () => {
  const s = await scene();
  const next = await makeUser('outsider');
  s.server.directory.set(U.outsider.id, { id: U.outsider.id, name: 'outsider', email: 'outsider@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  s.server.rotations[U.outsider.id] = [await rotationRecord(U.outsider, next)];
  await seedPins(s, { [U.outsider.id]: pinned(U.outsider.fp, 'verified') });
  const res = await pin(s.deps, 'outsider@example.com');
  assert.deepEqual([res.prior, res.state, res.wasVerified], ['rotated', 'unverified', true]);
  const stored = (await readServerKeyring(s.server, U.owner)).pins[U.outsider.id];
  assert.deepEqual([stored.fp, stored.rotSeq], [next.fp, 1]);
});

test('pin does not say a rotation dropped a verified pin when the pin was unverified', async () => {
  const s = await scene();
  const next = await makeUser('outsider');
  s.server.directory.set(U.outsider.id, { id: U.outsider.id, name: 'outsider', email: 'outsider@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  s.server.rotations[U.outsider.id] = [await rotationRecord(U.outsider, next)];
  await seedPins(s, { [U.outsider.id]: pinned(U.outsider.fp) });
  const res = await pin(s.deps, 'outsider@example.com');
  assert.deepEqual([res.prior, res.state, res.wasVerified], ['rotated', 'unverified', false]);
});

test('pin refuses to overwrite a pin another device stored meanwhile', async () => {
  const s = await scene();
  let gets = 0;
  s.server.onKeyringGet = async () => {
    if (++gets !== 2) return;
    const k = await readServerKeyring(s.server, U.owner);
    k.rev += 1;
    k.pins[U.outsider.id] = pinned('c'.repeat(64));
    await seedKeyring(s.server, U.owner, k);
  };
  const err = await pin(s.deps, 'outsider@example.com').catch((e) => e);
  assert.equal(err.code, 'pin-conflict');
  assert.equal((await readServerKeyring(s.server, U.owner)).pins[U.outsider.id].fp, 'c'.repeat(64));
});

test('pin keeps a pin another device verified at the same fingerprint', async () => {
  const s = await scene();
  let gets = 0;
  s.server.onKeyringGet = async () => {
    if (++gets !== 2) return;
    const k = await readServerKeyring(s.server, U.owner);
    k.rev += 1;
    k.pins[U.outsider.id] = pinned(U.outsider.fp, 'verified');
    await seedKeyring(s.server, U.owner, k);
  };
  await pin(s.deps, 'outsider@example.com');
  assert.equal((await readServerKeyring(s.server, U.owner)).pins[U.outsider.id].state, 'verified');
});

test('pin by an unknown name, or with a duplicate directory, is refused', async () => {
  const s = await scene();
  assert.equal((await pin(s.deps, 'nobody@example.com').catch((e) => e)).code, 'unknown-user');
  s.server.directory.set(U.other.id, { ...s.server.directory.get(U.other.id), email: 'outsider@example.com' });
  assert.equal((await pin(s.deps, 'viewer@example.com').catch((e) => e)).code, 'directory-duplicate');
});

// ---- members ----

test('members lists the owner and each member with their pin state', async () => {
  const s = await scene({ isPublic: true });
  await seedPins(s, { [U.editor.id]: pinned(U.editor.fp, 'verified') });
  s.server.directory.delete(U.viewer.id);
  const res = await members(s.deps, ARTIFACT);
  assert.deepEqual([res.artifact, res.epoch, res.seq, res.public, res.publicWrites], [ARTIFACT, 1, 2, true, false]);
  assert.deepEqual(res.members, [
    { user: U.owner.id, role: 'owner', fp: U.owner.fp, currentFp: U.owner.fp, name: 'owner', email: 'owner@example.com', state: 'self', wasVerified: false },
    { user: U.editor.id, role: 'editor', fp: U.editor.fp, currentFp: U.editor.fp, name: 'editor', email: 'editor@example.com', state: 'verified', wasVerified: false },
    { user: U.viewer.id, role: 'viewer', fp: U.viewer.fp, currentFp: '', name: '', email: '', state: '-', wasVerified: false },
  ]);
});

test('members shows a first sight as new, a rotation as rotated, and a rollback as a conflict', async () => {
  const s = await scene();
  const next = await makeUser('outsider');
  s.server.directory.set(U.editor.id, { id: U.editor.id, name: 'editor', email: 'editor@example.com', x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  s.server.rotations[U.editor.id] = [await rotationRecord(U.editor, next)];
  await seedPins(s, { [U.editor.id]: pinned(U.editor.fp, 'verified') });
  const rows = (await members(s.deps, ARTIFACT)).members;
  assert.deepEqual(rows.map((r) => r.state), ['self', 'rotated', 'new']);
  assert.equal(rows[1].wasVerified, true);
  // The record still lists the old keys; currentFp is the keys the directory serves now.
  assert.deepEqual([rows[1].fp, rows[1].currentFp], [U.editor.fp, next.fp]);

  await seedPins(s, { [U.viewer.id]: { fp: 'b'.repeat(64), state: 'verified', rotSeq: 1, rotHead: 'd'.repeat(64) } });
  s.deps.storage = depsFor(s.server, records.owner).storage;
  assert.equal((await members(s.deps, ARTIFACT)).members[2].state, 'conflict');
});

test('members works for a member who is not the owner', async () => {
  const s = await scene({ who: 'viewer' });
  const rows = (await members(s.deps, ARTIFACT)).members;
  assert.equal(rows.find((r) => r.user === U.viewer.id).state, 'self');
  assert.equal(rows[0].state, 'unverified', 'the creator was pinned on first sight');
});

// ---- re-sealing ----

// dataScene is an artifact with data under epoch 1: a database and a file in
// the older version V1, and the latest version V2, with metadata.
async function dataScene(opts = {}) {
  const s = await scene(opts);
  await seedVersion(s.server, { id: V1, seq: 1 });
  await seedVersion(s.server, { id: V2, seq: 2, files: { 'index.html': '<p>two</p>', 'app/main.js': 'x=1' } });
  await seedDatabase(s.server, { version: V1, revision: 4, plain: enc.encode('rows') });
  s.address = await seedFile(s.server, { version: V1, path: 'notes/a.txt', plain: enc.encode('hello') });
  await seedMeta(s.server, { field: 'name', value: 'Guestbook' });
  await seedMeta(s.server, { field: 'description', value: 'Sign here' });
  await seedMeta(s.server, { version: V2, field: 'name', value: 'v2' });
  await seedMeta(s.server, { version: V2, field: 'changelog', value: 'Second' });
  return s;
}

test('unshare re-seals the database, files, latest version and metadata under the new epoch', async () => {
  const s = await dataScene();
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  const ak2 = await estateAK(lastPut(s), 2);
  assert.equal(res.reseal.error, undefined);
  assert.deepEqual(res.reseal.skipped, []);
  assert.equal(res.reseal.resealed.length, 7);

  // The database: a new revision after the one read, signed by the owner.
  assert.equal(s.server.puts.db.length, 1);
  const db = s.server.puts.db[0];
  assert.deepEqual([db.version, db.ifMatch, db.revision, db.epoch], [V1, '"4"', 5, 2]);
  assert.equal(db.env.signer, U.owner.id);
  assert.equal(dec.decode(await e2e.openBlob(ak2, { artifact: ARTIFACT, version: V1, kind: 'database', name: '5' }, db.blob)), 'rows');
  assert.equal((await e2e.openEnvelope(db.env, U.owner.ed.pub, 'revision')).sha256, await e2e.bodyHash(db.blob));

  // The file: at its address under epoch 2, and the old address deleted.
  assert.equal(s.server.puts.file.length, 1);
  const f = s.server.puts.file[0];
  const newAddress = await e2e.fileAddress(await e2e.fileKey(ak2, ARTIFACT, 2), 'notes/a.txt');
  assert.deepEqual([f.address, f.epoch], [newAddress, 2]);
  assert.notEqual(newAddress, s.address);
  assert.equal(dec.decode(await e2e.openBlob(ak2, { artifact: ARTIFACT, version: V1, kind: 'file', name: newAddress }, f.blob)), 'hello');
  const meta = e2e.decodeStrict(await e2e.openBlob(ak2, { artifact: ARTIFACT, version: V1, kind: 'file-meta', name: newAddress }, f.meta), e2e.FILE_META_SCHEMA);
  assert.deepEqual([meta.path, meta.size, meta.modifiedAt], ['notes/a.txt', 5, '2026-01-01T00:00:00.000Z'], 'the modification time is kept');
  assert.deepEqual(s.server.deleted, [s.address]);
  assert.equal(await e2e.openEnvelope(f.record, U.owner.ed.pub, 'record').then((b) => b.epoch), 2);

  // The latest version only, as a replacement with the same ID.
  assert.equal(s.server.puts.version.length, 1);
  const v = s.server.puts.version[0];
  assert.equal(v.version, V2);
  assert.deepEqual(Object.keys(v.part).sort(), ['epoch', 'id', 'manifestHash']);
  assert.deepEqual([v.part.id, v.part.epoch], [V2, 2]);
  const env = e2e.decodeEnvelope(await e2e.openBlob(ak2, { artifact: ARTIFACT, version: V2, kind: 'manifest', name: '' }, v.manifest));
  const manifest = await e2e.openEnvelope(env, U.owner.ed.pub, 'manifest');
  assert.equal(env.signer, U.owner.id);
  assert.equal(v.part.manifestHash, await e2e.bodyHash(e2e.unb64(env.body)));
  assert.equal(manifest.epoch, 2);
  assert.deepEqual(manifest.files.map((x) => x.path), ['app/main.js', 'index.html']);
  for (const entry of manifest.files) {
    const blob = v.blobs.get(entry.blob);
    assert.equal(entry.sha256, await e2e.bodyHash(blob));
    const plain = await e2e.openBlob(ak2, { artifact: ARTIFACT, version: V2, kind: 'content', name: entry.path }, blob);
    assert.equal(dec.decode(plain), entry.path === 'index.html' ? '<p>two</p>' : 'x=1');
  }

  // The metadata fields: artifact and latest version, each under epoch 2.
  assert.deepEqual(s.server.puts.meta.map((m) => [m.version, m.field]), [['', 'name'], ['', 'description'], [V2, 'name'], [V2, 'changelog']]);
  for (const m of s.server.puts.meta) assert.equal(bodyOf(m.item.record).epoch, 2);
  const opened = await openArtifact(s.deps, { artifact: ARTIFACT, link: null });
  assert.deepEqual(await readMeta(s.deps, opened, s.server.artifactMeta), { values: { name: 'Guestbook', description: 'Sign here' }, unreadable: [] });
  assert.deepEqual(await readMeta(s.deps, opened, s.server.versions.get(V2).meta, V2), { values: { name: 'v2', changelog: 'Second' }, unreadable: [] });
});

test('reseal run again leaves what is already under the current epoch', async () => {
  const s = await dataScene();
  await unshare(s.deps, ARTIFACT, 'editor@example.com');
  const before = structuredClone(Object.fromEntries(Object.entries(s.server.puts).map(([k, v]) => [k, v.length])));
  const res = await reseal(s.deps, ARTIFACT);
  assert.deepEqual(res, { resealed: [], skipped: [] });
  assert.deepEqual(Object.fromEntries(Object.entries(s.server.puts).map(([k, v]) => [k, v.length])), before);
});

test('reseal in the first epoch does nothing', async () => {
  const s = await dataScene();
  assert.deepEqual(await reseal(s.deps, ARTIFACT), { resealed: [], skipped: [] });
  assert.equal(s.server.puts.db.length + s.server.puts.file.length + s.server.puts.version.length + s.server.puts.meta.length, 0);
});

test('reseal refuses a reader', async () => {
  const s = await dataScene({ who: 'viewer', epoch2: true });
  assert.equal((await reseal(s.deps, ARTIFACT).catch((e) => e)).code, 'cannot-reseal');
  noPuts(s);
});

test('reseal by an editor re-seals under the epoch, signed by them', async () => {
  const s = await dataScene({ who: 'editor', epoch2: true });
  const res = await reseal(s.deps, ARTIFACT);
  assert.equal(res.skipped.length, 0);
  assert.equal(s.server.puts.db[0].env.signer, U.editor.id);
  assert.equal(s.server.puts.version[0].version, V2);
});

test('reseal on an editor with the key they listed under rejects an editor listed under another', async () => {
  const s = await dataScene({ who: 'editor', epoch2: true, members: [{ user: U.editor, role: 'editor', fp: 'f'.repeat(64) }, { user: U.viewer, role: 'viewer' }] });
  assert.equal((await reseal(s.deps, ARTIFACT).catch((e) => e)).code, 'cannot-reseal');
});

test('reseal keeps the last revision of an editor the change removed', async () => {
  const s = await scene();
  await seedVersion(s.server, { id: V1 });
  await seedDatabase(s.server, { version: V1, revision: 2, signer: U.editor });
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.equal(s.server.puts.db.length, 1);
  assert.equal(s.server.puts.db[0].env.signer, U.owner.id, 'the owner signs what the editor wrote');
  assert.deepEqual(res.reseal.skipped.filter((x) => /database/.test(x.what)), []);
});

test('reseal leaves what an earlier removal left, and says so', async () => {
  const s = await scene();
  await seedVersion(s.server, { id: V1 });
  await unshare(s.deps, ARTIFACT, 'editor@example.com');
  // A revision and a file signed by the editor, who is gone from the record before this change.
  await seedDatabase(s.server, { version: V1, revision: 3, signer: U.editor });
  await seedFile(s.server, { version: V1, path: 'f.txt', signer: U.editor });
  const res = await unshare(s.deps, ARTIFACT, 'viewer@example.com');
  assert.equal(s.server.puts.db.length, 0);
  assert.equal(s.server.puts.file.length, 0);
  assert.equal(res.reseal.skipped.length, 2);
  assert.match(res.reseal.skipped[0].what, /database of version/);
  assert.match(res.reseal.skipped[0].reason, /may not write/);
  assert.match(res.reseal.skipped[1].what, /stored file of version/);
});

test('reseal keeps a revision written through a public link while public writes were on', async () => {
  const s = await scene({ isPublic: true, publicWrites: true });
  await seedVersion(s.server, { id: V1 });
  await seedDatabase(s.server, { version: V1, signer: U.outsider });
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.deepEqual(res.reseal.skipped, []);
  assert.equal(s.server.puts.db.length, 1);
});

test('reseal skips a revision that opens under no key it holds', async () => {
  const s = await scene();
  await seedVersion(s.server, { id: V1 });
  await seedDatabase(s.server, { version: V1, plain: enc.encode('x') });
  s.server.dbs.get(V1).blob = (await e2e.sealBlob(crypto.getRandomValues(new Uint8Array(32)), { artifact: ARTIFACT, version: V1, kind: 'database', name: '1' }, enc.encode('x')));
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.equal(res.reseal.skipped.length, 1);
  assert.match(res.reseal.skipped[0].reason, /does not match its signature/);
  assert.equal(s.server.puts.db.length, 0);
});

test('reseal skips a stored file the server no longer has', async () => {
  const s = await scene();
  await seedVersion(s.server, { id: V1 });
  const address = await seedFile(s.server, { version: V1, path: 'gone.txt' });
  const base = s.server.fetch;
  s.deps.fetch = async (path, init) => ((init?.method ?? 'GET') === 'GET' && path.endsWith(`/files/${address}`) ? new Response('{"error":"nf"}', { status: 404 }) : base(path, init));
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.match(res.reseal.skipped[0].reason, /no longer has the file/);
  assert.equal(s.server.puts.file.length, 0);
});

test('reseal does not write a file twice when its path is already under the current epoch', async () => {
  const s = await scene({ epoch2: true });
  await seedVersion(s.server, { id: V1, epoch: 1 });
  const old = await seedFile(s.server, { version: V1, path: 'a.txt', epoch: 1, plain: enc.encode('old') });
  await seedFile(s.server, { version: V1, path: 'a.txt', epoch: 2, plain: enc.encode('new') });
  const res = await reseal(s.deps, ARTIFACT);
  assert.equal(s.server.puts.file.length, 0, 'the newer copy stays');
  assert.deepEqual(s.server.deleted, [old]);
  assert.deepEqual(res.skipped, []);
});

test('reseal leaves the latest version signed by someone the change removed', async () => {
  const s = await scene();
  await seedVersion(s.server, { id: V1, signer: U.editor });
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.equal(s.server.puts.version.length, 0);
  assert.equal(res.reseal.skipped.length, 1);
  assert.equal(res.reseal.skipped[0].what, `version ${V1}`);
  assert.match(res.reseal.skipped[0].reason, /waits for the owner's review: it was signed by someone the change removed/);
});

test('reseal leaves a vouched version whose signer the change removed', async () => {
  const s = await scene();
  await seedVersion(s.server, { id: V1, signer: U.editor });
  const v = s.server.versions.get(V1);
  const vouch = await e2e.newEnvelope(U.owner.ed.seed, U.owner.id, 'vouch', enc.encode(JSON.stringify({ v: 1, artifact: ARTIFACT, version: V1, manifest: v.json.manifestHash })));
  v.json.vouch = vouch;
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.equal(s.server.puts.version.length, 0);
  assert.match(res.reseal.skipped[0].reason, /signed by someone the change removed/);
});

test('reseal leaves a version whose blob does not match its manifest', async () => {
  const s = await scene();
  await seedVersion(s.server, { id: V1, files: { 'index.html': 'a', 'b.js': 'b' }, badBlob: 'b.js' });
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.equal(s.server.puts.version.length, 0);
  assert.match(res.reseal.skipped[0].reason, /the blob of b\.js: it does not match the manifest's hash/);
});

test('reseal leaves a version whose manifest does not match its hash', async () => {
  const s = await scene();
  await seedVersion(s.server, { id: V1 });
  s.server.versions.get(V1).json.manifestHash = '0'.repeat(64);
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.equal(s.server.puts.version.length, 0);
  assert.equal(res.reseal.skipped.length, 1);
});

test('reseal leaves a version whose blob cannot be fetched', async () => {
  const s = await scene();
  await seedVersion(s.server, { id: V1 });
  s.server.blobs.get(V1).clear();
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.equal(s.server.puts.version.length, 0);
  assert.match(res.reseal.skipped[0].what, /version/);
});

test('reseal replaces only the version with the highest seq, whatever the order', async () => {
  const s = await scene();
  await seedVersion(s.server, { id: V2, seq: 9 });
  await seedVersion(s.server, { id: V1, seq: 3 });
  await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.deepEqual(s.server.puts.version.map((v) => v.version), [V2]);
});

test('reseal leaves a metadata field that fails its checks, and re-seals the others', async () => {
  const s = await scene();
  await seedMeta(s.server, { field: 'name', value: 'Fine' });
  await seedMeta(s.server, { field: 'description', value: 'Forged', signer: U.outsider });
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.deepEqual(s.server.puts.meta.map((m) => m.field), ['name']);
  assert.equal(res.reseal.skipped.length, 1);
  assert.equal(res.reseal.skipped[0].what, 'the description of the artifact');
});

test('reseal keeps the metadata of an editor the change removed', async () => {
  const s = await scene();
  await seedMeta(s.server, { field: 'name', value: 'By editor', signer: U.editor });
  await unshare(s.deps, ARTIFACT, 'editor@example.com');
  const put = s.server.puts.meta[0];
  assert.equal(put.item.record.signer, U.owner.id);
  const opened = await openArtifact(s.deps, { artifact: ARTIFACT, link: null });
  assert.equal((await readMeta(s.deps, opened, s.server.artifactMeta)).values.name, 'By editor');
});

test('reseal leaves a metadata field already under the current epoch even when the record before would refuse it', async () => {
  const s = await scene({ epoch2: true });
  s.server.artifactMeta.name = await metaItem(s, { field: 'name', value: 'Now', epoch: 2, signer: U.owner });
  s.server.artifactMeta.description = await metaItem(s, { field: 'description', value: 'Later', epoch: 2, signer: U.outsider });
  const res = await reseal(s.deps, ARTIFACT);
  assert.deepEqual(res, { resealed: [], skipped: [] });
});

test('a re-seal that fails part way is reported, and reseal finishes it', async () => {
  const s = await dataScene();
  s.server.failPut = (kind) => (kind === 'db' ? new Response('{"error":"disk full"}', { status: 500 }) : null);
  const res = await unshare(s.deps, ARTIFACT, 'editor@example.com');
  assert.equal(res.epoch, 2, 'the epoch change itself stands');
  assert.match(res.reseal.error.message, new RegExp(`version ${V1}: disk full`));
  assert.deepEqual(res.reseal.resealed, []);
  s.server.failPut = null;
  const again = await reseal(s.deps, ARTIFACT);
  assert.equal(again.resealed.length, 7);
  assert.equal(s.server.puts.db.length, 1);
});

test('reseal throws the failure with what it had done', async () => {
  const s = await dataScene({ epoch2: true });
  s.server.failPut = (kind) => (kind === 'file' ? new Response('{"error":"no"}', { status: 500 }) : null);
  const err = await reseal(s.deps, ARTIFACT).catch((e) => e);
  assert.ok(err.result);
  assert.equal(err.result.resealed.length, 1);
});

test('a reseal of the database refuses a revision older than one already seen', async () => {
  const s = await scene({ epoch2: true });
  // V2 is the latest version, so the re-seal replaces that one and leaves V1 at its epoch.
  await seedVersion(s.server, { id: V2, seq: 9 });
  await seedVersion(s.server, { id: V1 });
  await seedDatabase(s.server, { version: V1, revision: 5 });
  await reseal(s.deps, ARTIFACT);
  await seedDatabase(s.server, { version: V1, revision: 2 });
  const err = await reseal(s.deps, ARTIFACT).catch((e) => e);
  assert.match(err.message, /older than revision 6, already seen/);
});

test('a version PUT the server answers 409 for is an epoch-moved error', async () => {
  const s = await dataScene({ epoch2: true });
  s.server.failPut = (kind) => (kind === 'version' ? new Response('{"error":"moved to a new epoch"}', { status: 409 }) : null);
  const err = await reseal(s.deps, ARTIFACT).catch((e) => e);
  assert.equal(err.code, 'epoch-moved');
});
