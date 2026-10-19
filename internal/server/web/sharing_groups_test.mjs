// Tests for the team share (Everyone) and group shares in sharing.mjs: sharing
// with a group, approving newcomers, listing approved users and excluding
// users who left in every new epoch, dropping a deleted group. They run against
// real chains, wraps, approvals, group records and keyrings behind the stateful
// fake of sharing_fixture.mjs, which answers GET .../pending and refuses a
// record the real server refuses. They mirror the Go tests of internal/client
// (approve_test.go, groupshare_test.go, epoch_test.go). Run with:
// node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { ApiError } from './account.mjs';
import { buildWorld, makeUser, readServerKeyring, rotationRecord, seedKeyring } from './viewer_fixture.mjs';
import { ARTIFACT, changeGroup, depsFor, extraUser, keyStoreRecord, makeShareServer, seedGroup } from './sharing_fixture.mjs';
import { GroupKeyChangedError, KeyChangedError, approvableCount, approve, members, setPublic, setTeam, share, shareGroup, unshare, unshareGroup, waiting } from './sharing.mjs';

const U = {};
for (const name of ['owner', 'editor', 'viewer', 'outsider']) U[name] = await makeUser(name);
U.other = await extraUser('other', '88888888-8888-4888-8888-888888888888');
U.manager = await extraUser('manager', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
U.carol = await extraUser('carol', 'cccccccc-cccc-4ccc-8ccc-cccccccccccc');
U.dave = await extraUser('dave', 'dddddddd-dddd-4ddd-8ddd-dddddddddddd');
const records = {};
for (const name of Object.keys(U)) records[name] = await keyStoreRecord(U[name]);
const enc = new TextEncoder();
const dec = new TextDecoder();

const G1 = 'b1b1b1b1-1111-4111-8111-111111111111';
const G2 = 'b2b2b2b2-2222-4222-8222-222222222222';

const STD_MEMBERS = [
  { user: U.editor, role: 'editor' },
  { user: U.viewer, role: 'viewer' },
];

async function scene({ who = 'owner', members: m = STD_MEMBERS, users = [U.outsider, U.other, U.carol, U.dave], groups = [], ...worldOpts } = {}) {
  const world = await buildWorld({ owner: U.owner, members: m, ...worldOpts });
  const server = makeShareServer(world, { who: U[who], users });
  for (const g of groups) await seedGroup(server, g);
  return { world, server, deps: depsFor(server, records[who]) };
}

const bodyOf = (env) => JSON.parse(dec.decode(e2e.unb64(env.body)));
const lastPut = (s) => s.server.puts.membership.at(-1);
const lastBody = (s) => bodyOf(lastPut(s).membership);
const ids = (users) => users.map((u) => u.id);
const codeOf = async (p) => (await p.catch((e) => e)).code;
const noRecords = (s, n = 0) => assert.equal(s.server.puts.membership.length, n, 'no record was written');

// asUser is the deps of another signed-in user on the same server, who has a
// keyring of their own to start.
function asUser(s, name) {
  s.server.who = U[name];
  s.server.keyring = { rev: 0, keyring: '' };
  return depsFor(s.server, records[name]);
}

async function unwrapFor(name, w) {
  const ctx = { purpose: 'ak', artifact: ARTIFACT, epoch: w.epoch, recipientId: U[name].id, recipientPub: U[name].x.pub };
  return e2e.unwrap(records[name].x25519, ctx, e2e.unb64(w.wrapped));
}

// The pending list as a lying server serves it: extra entries appended.
function lyingPending(s, entries) {
  const base = s.server.fetch;
  s.deps.fetch = async (path, init) => {
    const resp = await base(path, init);
    if (!path.endsWith('/pending')) return resp;
    const list = await resp.json();
    return new Response(JSON.stringify([...list, ...entries]), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
}

const wire = (u, state, group = []) => ({ id: u.id, name: u.name, email: `${u.name}@example.com`, x25519Pub: u.pair.x25519, ed25519Pub: u.pair.ed25519, state, group, approval: null });

// ---- sharing with a group ----

test('share with a group lists it, approves the members whose checks pass, and leaves a fingerprint mismatch waiting', async () => {
  const s = await scene({ groups: [{ id: G1, name: 'Design', members: [{ user: U.outsider }, { user: U.other, fp: 'f'.repeat(64) }] }] });
  const res = await shareGroup(s.deps, ARTIFACT, G1, 'editor');
  assert.deepEqual(res.group, { id: G1, name: 'Design' });
  assert.equal(res.unchanged, false);
  assert.deepEqual(ids(res.approved), [U.outsider.id]);
  assert.deepEqual(res.pending.map((p) => p.user.id), [U.other.id]);
  assert.ok(res.pending[0].error instanceof GroupKeyChangedError);
  assert.equal(res.pending[0].error.groupFp, 'f'.repeat(64));
  // The record lists the group, in the same epoch, and changes nothing else.
  noRecords(s, 1);
  const body = lastBody(s);
  assert.deepEqual(body.groups, [{ group: G1, role: 'editor' }]);
  assert.deepEqual([body.epoch, body.seq, body.team], [1, 3, 'none']);
  assert.deepEqual(body.members.map((m) => m.user), [U.editor.id, U.viewer.id]);
  assert.deepEqual(lastPut(s).wraps, []);
  // The member approved holds a wrap of every epoch, and an approval of their fingerprint.
  assert.equal(s.server.approves.length, 1);
  const sent = s.server.approves[0];
  assert.deepEqual([sent.user, sent.fp], [U.outsider.id, U.outsider.fp]);
  assert.deepEqual(sent.wraps.map((w) => w.epoch), [1]);
  assert.deepEqual(await unwrapFor('outsider', sent.wraps[0]), s.world.aks[1]);
  assert.deepEqual(bodyOf(sent.approval), { v: 1, artifact: ARTIFACT, epoch: 1, user: U.outsider.id, fp: U.outsider.fp });
  assert.equal(sent.approval.signer, U.owner.id);
  assert.deepEqual((await readServerKeyring(s.server, U.owner)).pins[U.outsider.id], { fp: U.outsider.fp, state: 'unverified', rotSeq: 0, rotHead: '' });
  // The other member waits, held by the group.
  const w = await waiting(s.deps, ARTIFACT);
  assert.deepEqual(w.newcomers.map((n) => [n.user, n.email, n.fp, n.groups, n.everyone]), [[U.other.id, 'other@example.com', U.other.fp, [{ id: G1, name: 'Design' }], false]]);
  assert.deepEqual(w.left, []);
});

test('share with a group again lists the members it approved, then is unchanged, and a new role is a new record', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  noRecords(s, 1);
  // The group is listed now, so the server names it as holding the approved member.
  const again = await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  assert.equal(again.unchanged, false);
  assert.deepEqual(again.pending, [], 'the approved member is not approved again');
  assert.deepEqual(ids(again.listed), [U.outsider.id]);
  assert.deepEqual(lastBody(s).members.find((m) => m.user === U.outsider.id), { user: U.outsider.id, role: 'viewer', fp: U.outsider.fp });
  assert.deepEqual(lastPut(s).wraps, []);
  noRecords(s, 2);
  const third = await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  assert.equal(third.unchanged, true);
  noRecords(s, 2);
  // Changing the role changes the group's entry, and a member listed already keeps their role.
  const editor = await shareGroup(s.deps, ARTIFACT, G1, 'editor');
  assert.equal(editor.unchanged, false);
  assert.deepEqual(lastBody(s).groups, [{ group: G1, role: 'editor' }]);
  assert.equal(lastBody(s).members.find((m) => m.user === U.outsider.id).role, 'viewer');
});

test('share with a group refuses a bad role, an unknown group, and a caller who may not sign', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  assert.equal(await codeOf(shareGroup(s.deps, ARTIFACT, G1, 'manager')), 'bad-role');
  assert.equal(await codeOf(shareGroup(s.deps, ARTIFACT, G2, 'viewer')), 'unknown-group');
  assert.equal(await codeOf(shareGroup(asUser(s, 'editor'), ARTIFACT, G1, 'viewer')), 'not-owner');
  assert.equal(await codeOf(unshareGroup(asUser(s, 'viewer'), ARTIFACT, G1)), 'not-owner');
  noRecords(s);
  assert.equal(s.server.approves.length, 0);
});

test('share with a group fails closed on a chain that does not verify, and writes nothing', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  const [rec] = s.server.groups.get(G1);
  // The body names another group name than the one signed.
  const body = bodyOf(rec);
  rec.body = e2e.b64(enc.encode(JSON.stringify({ ...body, name: 'Forged' })));
  await assert.rejects(shareGroup(s.deps, ARTIFACT, G1, 'viewer'));
  noRecords(s);
  assert.equal(s.server.approves.length, 0);
});

test('a group whose chain stops verifying fails a later change closed, and no approved user is listed on its word', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'editor');
  const [rec] = s.server.groups.get(G1);
  rec.body = e2e.b64(enc.encode(JSON.stringify({ ...bodyOf(rec), name: 'Forged' })));
  assert.equal(await codeOf(unshare(s.deps, ARTIFACT, 'viewer@example.com')), 'group-unverified');
  noRecords(s, 1);
});

test('a group the server holds a user under, whose chain does not list them, approves and lists nobody', async () => {
  const s = await scene({ groups: [{ id: G1, members: [] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  lyingPending(s, [wire(U.carol, 'new', [G1])]);
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'carol@example.com')), 'not-in-group');
  assert.equal(s.server.approves.length, 0);
  // An approved user the chain does not list is reported unlisted, and a next epoch excludes them.
  s.server.approvals.set(U.carol.id, { fp: U.carol.fp, envelope: null });
  lyingPending(s, [{ ...wire(U.carol, 'approved', [G1]), approval: await e2e.signApproval(U.owner.ed.seed, U.owner.id, { artifact: ARTIFACT, epoch: 1, user: U.carol.id, fp: U.carol.fp }) }]);
  const res = await unshare(s.deps, ARTIFACT, 'viewer@example.com');
  assert.deepEqual(lastBody(s).members.map((m) => m.user), [U.editor.id]);
  assert.deepEqual(res.listed, []);
  assert.match(res.excluded.find((x) => x.user.id === U.carol.id).reason, /^their approval does not check out: .*does not list/);
});

test('share with a group keeps a manager of the artifact able to sign it, in a version 2 record', async () => {
  const s = await scene({ who: 'manager', members: [{ user: U.manager, role: 'manager' }], groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  const res = await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  assert.deepEqual(ids(res.approved), [U.outsider.id]);
  const body = lastBody(s);
  assert.deepEqual([body.v, body.signer, body.signerFp], [2, U.manager.id, U.manager.fp]);
  assert.deepEqual(body.groups, [{ group: G1, role: 'viewer' }]);
});

// ---- approving ----

test('approve a later joiner of a listed group', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  await changeGroup(s.server, G1, { add: [{ user: U.other }] });
  assert.deepEqual((await waiting(s.deps, ARTIFACT)).newcomers.map((n) => n.user), [U.other.id]);
  const res = await approve(s.deps, ARTIFACT, 'other@example.com');
  assert.deepEqual([res.user.id, res.epoch, res.prior], [U.other.id, 1, 'new']);
  assert.equal(s.server.approves.length, 2);
  assert.deepEqual((await waiting(s.deps, ARTIFACT)).newcomers, []);
  assert.equal((await readServerKeyring(s.server, U.owner)).pins[U.other.id].fp, U.other.fp);
  // They hold every epoch's key; nothing was listed.
  noRecords(s, 1);
});

test('approve wraps every epoch, and an approval of a user the group record lists under another fingerprint needs the key accepted', async () => {
  const s = await scene({ epoch2: true, groups: [{ id: G1, members: [{ user: U.outsider, fp: 'e'.repeat(64) }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  assert.equal(s.server.approves.length, 0, 'the group lists them under another fingerprint');
  const err = await approve(s.deps, ARTIFACT, 'outsider@example.com').catch((e) => e);
  assert.ok(err instanceof GroupKeyChangedError);
  assert.deepEqual([err.group, err.groupFp, err.user.fp], [G1, 'e'.repeat(64), U.outsider.fp]);
  assert.equal(s.server.approves.length, 0);
  const res = await approve(s.deps, ARTIFACT, 'outsider@example.com', { acceptNewKey: true });
  assert.equal(res.epoch, 2);
  const sent = s.server.approves[0];
  assert.deepEqual(sent.wraps.map((w) => w.epoch), [1, 2]);
  for (const w of sent.wraps) assert.deepEqual(await unwrapFor('outsider', w), s.world.aks[w.epoch]);
  assert.equal(bodyOf(sent.approval).epoch, 2);
});

test('approve refuses each user it must, before it asks the server', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'outsider@example.com')), 'no-team');
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'outsider@example.com')), 'already-approved');
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'viewer@example.com')), 'already-listed');
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'owner@example.com')), 'already-listed');
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'carol@example.com')), 'not-waiting');
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'nobody@example.com')), 'unknown-user');
  assert.equal(await codeOf(approve(asUser(s, 'viewer'), ARTIFACT, 'carol@example.com')), 'not-approver');
  assert.equal(s.server.approves.length, 1);
});

test('approve refuses a user the record excludes, and a user whose keys changed after they were wrapped to', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }, { user: U.other }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  // The owner removes the editor: the record excludes them, and they are in the group again.
  await unshare(s.deps, ARTIFACT, 'editor@example.com');
  await changeGroup(s.server, G1, { add: [{ user: U.editor }] });
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'editor@example.com')), 'excluded');
  // The approved user's keys change, with no rotation record to explain it.
  const next = await makeUser('outsider');
  Object.assign(s.server.directory.get(U.outsider.id), { x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'outsider@example.com')), 'changed-key');
});

test("approve refuses a pinned key that changed until it is accepted, and the group's key change is a warning of its own", async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  const k = e2e.newKeyring();
  k.pins[U.outsider.id] = { fp: 'd'.repeat(64), state: 'verified', rotSeq: 0, rotHead: '' };
  await seedKeyring(s.server, U.owner, k);
  const res = await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  assert.deepEqual(ids(res.approved), []);
  assert.ok(res.pending[0].error instanceof KeyChangedError, 'a changed pin leaves them waiting');
  await assert.rejects(approve(s.deps, ARTIFACT, 'outsider@example.com'), KeyChangedError);
  assert.equal(s.server.approves.length, 0);
  await approve(s.deps, ARTIFACT, 'outsider@example.com', { acceptNewKey: true });
  assert.equal((await readServerKeyring(s.server, U.owner)).pins[U.outsider.id].fp, U.outsider.fp);
});

test('approve leaves the pin unwritten when the server refuses', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  await changeGroup(s.server, G1, { add: [{ user: U.other }] });
  s.server.failPut = (kind) => (kind === 'approve' ? new Response('{"error":"nope"}', { status: 409 }) : null);
  await assert.rejects(approve(s.deps, ARTIFACT, 'other@example.com'), { status: 409 });
  assert.equal((await readServerKeyring(s.server, U.owner)).pins[U.other.id], undefined);
});

// ---- editors approve ----

test('an editor sees the newcomers and approves them, and nothing else', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  const deps = asUser(s, 'editor');
  const w = await waiting(deps, ARTIFACT);
  assert.equal(w.canApprove, true);
  assert.deepEqual(w.newcomers.map((n) => n.user).sort(), [U.carol.id, U.dave.id, U.other.id, U.outsider.id].sort());
  assert.ok(w.newcomers.every((n) => n.everyone && n.groups.length === 0));
  assert.equal(await approvableCount(deps, ARTIFACT), 4);
  const res = await approve(deps, ARTIFACT, 'outsider@example.com');
  assert.equal(res.user.id, U.outsider.id);
  assert.equal(s.server.approves[0].approval.signer, U.editor.id);
  assert.equal(await approvableCount(deps, ARTIFACT), 3);
  assert.equal(await approvableCount(asUser(s, 'owner'), ARTIFACT), 3, 'the owner counts newcomers, not the people already approved');
  const again = asUser(s, 'editor');
  assert.equal(await codeOf(setTeam(again, ARTIFACT, 'none')), 'not-owner');
  assert.equal(await codeOf(unshare(again, ARTIFACT, 'viewer@example.com')), 'not-owner');
  noRecords(s, 1);
  // An editor never learns who left or who is approved.
  assert.deepEqual((await waiting(again, ARTIFACT)).left, []);
  // The owner lists the user the editor approved, after checking the editor's approval.
  const owner = asUser(s, 'owner');
  const out = await unshare(owner, ARTIFACT, 'viewer@example.com');
  assert.deepEqual(ids(out.listed), [U.outsider.id]);
  assert.deepEqual(lastBody(s).members.find((m) => m.user === U.outsider.id), { user: U.outsider.id, role: 'viewer', fp: U.outsider.fp });
  assert.deepEqual((await readServerKeyring(s.server, U.owner)).pins[U.outsider.id], { fp: U.outsider.fp, state: 'unverified', rotSeq: 0, rotHead: '' }, 'the owner pins who the record lists');
});

test('a viewer may approve nobody, and sees no newcomers', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  const deps = asUser(s, 'viewer');
  assert.deepEqual(await waiting(deps, ARTIFACT), { canApprove: false, team: 'viewer', newcomers: [], left: [] });
  assert.equal(await codeOf(approve(deps, ARTIFACT, 'outsider@example.com')), 'not-approver');
  await assert.rejects(approvableCount(deps, ARTIFACT), (err) => err instanceof ApiError && err.status === 403);
  assert.equal(s.server.approves.length, 0);
});

test('an approval signed by someone the record does not list is not listed on its word', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  // The server swaps in an approval that other signed.
  const forged = await e2e.signApproval(U.other.ed.seed, U.other.id, { artifact: ARTIFACT, epoch: 1, user: U.outsider.id, fp: U.outsider.fp });
  s.server.approvals.set(U.outsider.id, { fp: U.outsider.fp, envelope: forged });
  const res = await unshare(s.deps, ARTIFACT, 'viewer@example.com');
  assert.deepEqual(res.listed, []);
  assert.match(res.excluded.find((x) => x.user.id === U.outsider.id).reason, /^their approval does not check out: /);
  assert.deepEqual(lastBody(s).excluded.map((x) => x.user), [U.outsider.id, U.viewer.id].sort());
});

// ---- Everyone ----

test('Everyone on and off, and the team share is listed under the role it grants', async () => {
  const s = await scene();
  const on = await setTeam(s.deps, ARTIFACT, 'viewer');
  assert.deepEqual([on.unchanged, on.epoch, on.reseal], [false, 1, null]);
  assert.equal(lastBody(s).team, 'viewer');
  assert.equal(lastBody(s).epoch, 1);
  assert.equal((await setTeam(s.deps, ARTIFACT, 'viewer')).unchanged, true);
  noRecords(s, 1);
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  const edit = await setTeam(s.deps, ARTIFACT, 'editor');
  assert.deepEqual(ids(edit.listed), [U.outsider.id]);
  assert.equal(lastBody(s).team, 'editor');
  assert.deepEqual(lastBody(s).members.find((m) => m.user === U.outsider.id), { user: U.outsider.id, role: 'editor', fp: U.outsider.fp });
  assert.equal(edit.epoch, 1);
  assert.deepEqual(lastPut(s).wraps, []);
  // Off with nobody holding a wrap unlisted is a same-epoch record.
  const off = await setTeam(s.deps, ARTIFACT, 'none');
  assert.deepEqual([off.epoch, off.reseal, lastBody(s).team, lastBody(s).epoch], [1, null, 'none', 1]);
  assert.equal((await setTeam(s.deps, ARTIFACT, 'none')).unchanged, true);
  assert.equal(await codeOf(setTeam(s.deps, ARTIFACT, 'everyone')), 'bad-team');
  assert.equal(await codeOf(setTeam(asUser(s, 'editor'), ARTIFACT, 'viewer')), 'not-owner');
});

test('Everyone off while an approved user holds a wrap starts a new epoch that excludes them', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  const off = await setTeam(s.deps, ARTIFACT, 'none');
  assert.equal(off.epoch, 2);
  assert.deepEqual(off.excluded.map((x) => [x.user.id, x.reason]), [[U.outsider.id, 'team sharing ended while they held a wrap']]);
  assert.ok(off.reseal, 're-sealing ran');
  const put = lastPut(s);
  const body = bodyOf(put.membership);
  assert.deepEqual([body.epoch, body.team], [2, 'none']);
  assert.deepEqual(body.excluded, [{ user: U.outsider.id, fp: U.outsider.fp, email: 'outsider@example.com' }]);
  assert.deepEqual(put.wraps.map((w) => [w.user, w.epoch]).sort(), [[U.editor.id, 2], [U.viewer.id, 2]]);
  assert.equal(put.estate.length, 1);
});

test('Everyone off leaves an approved user a listed group still covers where they are, in the same epoch', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'editor');
  await setTeam(s.deps, ARTIFACT, 'viewer');
  const off = await setTeam(s.deps, ARTIFACT, 'none');
  assert.deepEqual([off.epoch, off.reseal], [1, null]);
  assert.deepEqual(lastBody(s).members.map((m) => m.user), [U.editor.id, U.viewer.id, U.outsider.id]);
  assert.deepEqual(lastBody(s).groups, [{ group: G1, role: 'editor' }]);
});

// ---- listing roles ----

test('approved users are listed under the highest of the team share and their groups, and a viewer account as a viewer', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }, { user: U.carol }] }, { id: G2, members: [{ user: U.dave }] }] });
  s.server.directory.get(U.carol.id).role = 'viewer';
  await shareGroup(s.deps, ARTIFACT, G1, 'editor');
  assert.deepEqual(lastBody(s).members.map((m) => m.user), [U.editor.id, U.viewer.id], 'nobody is listed before the group holds them');
  // Team viewer, group editor: the group's role is the higher.
  const on = await setTeam(s.deps, ARTIFACT, 'viewer');
  assert.deepEqual(on.listed.map((u) => u.id).sort(), [U.carol.id, U.outsider.id].sort());
  const roleOf = (id) => lastBody(s).members.find((m) => m.user === id).role;
  assert.equal(roleOf(U.outsider.id), 'editor', 'group editor over team viewer');
  assert.equal(roleOf(U.carol.id), 'viewer', 'a viewer account is a viewer whatever it is granted');
  // Team editor, group viewer: the team's role is the higher. Another user only the team holds gets it too.
  await shareGroup(s.deps, ARTIFACT, G2, 'viewer');
  await approve(s.deps, ARTIFACT, 'other@example.com');
  const edit = await setTeam(s.deps, ARTIFACT, 'editor');
  assert.deepEqual(edit.listed.map((u) => u.id).sort(), [U.dave.id, U.other.id].sort());
  assert.equal(roleOf(U.dave.id), 'editor', 'team editor over group viewer');
  assert.equal(roleOf(U.other.id), 'editor', 'no group holds them, the team share does');
  assert.equal(roleOf(U.outsider.id), 'editor');
});

test('a same-epoch share lists the approved users too, and wraps nothing for them', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  const res = await share(s.deps, ARTIFACT, 'carol@example.com', 'viewer');
  assert.deepEqual(ids(res.listed), [U.outsider.id]);
  assert.deepEqual(lastBody(s).members.map((m) => [m.user, m.role]), [[U.editor.id, 'editor'], [U.viewer.id, 'viewer'], [U.outsider.id, 'viewer'], [U.carol.id, 'viewer']].sort((a, b) => (a[0] < b[0] ? -1 : 1)));
  assert.deepEqual(lastPut(s).wraps.map((w) => w.user), [U.carol.id]);
});

test('share lists an approved user by name with no wraps, and refuses one whose approval does not check out', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  const res = await share(s.deps, ARTIFACT, 'outsider@example.com', 'editor');
  assert.deepEqual(res.listed, [], 'the user named is not listed twice');
  assert.deepEqual(lastBody(s).members.find((m) => m.user === U.outsider.id), { user: U.outsider.id, role: 'editor', fp: U.outsider.fp });
  assert.deepEqual(lastPut(s).wraps, [], 'they hold their wraps already');
  const forged = await scene();
  await setTeam(forged.deps, ARTIFACT, 'viewer');
  await approve(forged.deps, ARTIFACT, 'outsider@example.com');
  forged.server.approvals.set(U.outsider.id, { fp: U.outsider.fp, envelope: await e2e.signApproval(U.other.ed.seed, U.other.id, { artifact: ARTIFACT, epoch: 1, user: U.outsider.id, fp: U.outsider.fp }) });
  assert.equal(await codeOf(share(forged.deps, ARTIFACT, 'outsider@example.com', 'editor')), 'approval-unverified');
  noRecords(forged, 1);
});

// ---- leaving ----

async function leftScene() {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }, { user: U.other }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  await changeGroup(s.server, G1, { drop: [U.outsider] });
  return s;
}

test('a user who left every group shows as left, and the next epoch excludes them', async () => {
  const s = await leftScene();
  const w = await waiting(s.deps, ARTIFACT);
  assert.deepEqual(w.left.map((l) => [l.user, l.email, l.fp]), [[U.outsider.id, 'outsider@example.com', U.outsider.fp]]);
  assert.deepEqual(w.newcomers, []);
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'outsider@example.com')), 'not-waiting', 'they hold the key, and Remove is how it ends');
  const res = await unshare(s.deps, ARTIFACT, 'viewer@example.com');
  assert.deepEqual(res.excluded.map((x) => [x.user.id, x.reason]).sort(), [[U.outsider.id, 'left the group'], [U.viewer.id, 'removed']].sort());
  const put = lastPut(s);
  const body = bodyOf(put.membership);
  assert.deepEqual(body.excluded, [{ user: U.outsider.id, fp: U.outsider.fp, email: 'outsider@example.com' }, { user: U.viewer.id, fp: U.viewer.fp, email: 'viewer@example.com' }].sort((a, b) => (a.user < b.user ? -1 : 1)));
  assert.ok(!put.wraps.some((x) => x.user === U.outsider.id), 'no key of the new epoch goes to them');
});

test('removing a user who left starts a new epoch that excludes them, named by email', async () => {
  const s = await leftScene();
  const res = await unshare(s.deps, ARTIFACT, 'outsider@example.com');
  assert.equal(res.epoch, 2);
  assert.deepEqual(res.excluded.map((x) => [x.user.id, x.reason]), [[U.outsider.id, 'removed']]);
  assert.deepEqual(lastBody(s).excluded.map((x) => x.user), [U.outsider.id]);
  assert.deepEqual(lastBody(s).members.map((m) => m.user), [U.editor.id, U.viewer.id, U.other.id], 'the member the group still holds is listed');
  assert.equal(await codeOf(unshare(s.deps, ARTIFACT, 'outsider@example.com')), 'not-member', 'once excluded, nothing holds them');
});

test('a user who left is listed again by name without a new approval, and unshare refuses a user nothing holds', async () => {
  const s = await leftScene();
  const res = await share(s.deps, ARTIFACT, 'outsider@example.com', 'viewer');
  assert.equal(res.epoch, 1);
  assert.deepEqual(lastPut(s).wraps, [], 'they still hold the key');
  assert.equal(await codeOf(unshare(s.deps, ARTIFACT, 'carol@example.com')), 'not-member');
});

// ---- removing a group ----

test('removing a group someone read only through starts a new epoch that excludes them', async () => {
  const s = await scene({ groups: [{ id: G1, name: 'Design', members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  const res = await unshareGroup(s.deps, ARTIFACT, G1);
  assert.deepEqual([res.epoch, res.group], [2, { id: G1, name: 'Design' }]);
  assert.deepEqual(res.excluded.map((x) => [x.user.id, x.reason]), [[U.outsider.id, 'no group they belong to is shared with the artifact any more']]);
  assert.ok(res.reseal);
  const body = lastBody(s);
  assert.deepEqual([body.epoch, body.groups], [2, undefined]);
  assert.deepEqual(body.excluded, [{ user: U.outsider.id, fp: U.outsider.fp, email: 'outsider@example.com' }]);
  assert.equal((await members(s.deps, ARTIFACT)).groups.length, 0);
});

test('removing a group nobody read only through is a same-epoch record', async () => {
  // The group lists the user under another fingerprint, so nobody was approved.
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider, fp: 'f'.repeat(64) }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  const res = await unshareGroup(s.deps, ARTIFACT, G1);
  assert.deepEqual([res.epoch, res.reseal, res.excluded], [1, null, []]);
  assert.deepEqual([lastBody(s).epoch, lastBody(s).seq, lastBody(s).groups], [1, 4, undefined]);
});

test('removing a group another group or Everyone still covers is a same-epoch record', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }, { id: G2, members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  await shareGroup(s.deps, ARTIFACT, G2, 'viewer');
  assert.equal((await unshareGroup(s.deps, ARTIFACT, G1)).epoch, 1);
  assert.deepEqual(lastBody(s).groups, [{ group: G2, role: 'viewer' }]);
  await setTeam(s.deps, ARTIFACT, 'viewer');
  assert.equal((await unshareGroup(s.deps, ARTIFACT, G2)).epoch, 1, 'Everyone covers them');
  assert.equal(lastBody(s).team, 'viewer');
});

test('removing a group a user already left does not count that user, and a group not listed is refused', async () => {
  const s = await leftScene();
  assert.equal((await unshareGroup(s.deps, ARTIFACT, G1)).epoch, 2, 'the member the group holds still reads only through it');
  const t = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(t.deps, ARTIFACT, G1, 'viewer');
  await changeGroup(t.server, G1, { drop: [U.outsider] });
  assert.equal((await unshareGroup(t.deps, ARTIFACT, G1)).epoch, 1, 'a holder who had left is not counted');
  assert.equal(await codeOf(unshareGroup(t.deps, ARTIFACT, G1)), 'not-shared-with-group');
});

// ---- deleted groups ----

test('a deleted group is dropped from the next record, which says so, and grants nothing', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }, { id: G2, members: [{ user: U.other }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  await shareGroup(s.deps, ARTIFACT, G2, 'viewer');
  s.server.groups.delete(G1);
  const listed = await members(s.deps, ARTIFACT);
  assert.deepEqual(listed.groups, [{ id: G1, name: '', role: 'viewer', deleted: true }, { id: G2, name: 'Team', role: 'viewer', deleted: false }]);
  const res = await share(s.deps, ARTIFACT, 'carol@example.com', 'viewer');
  assert.deepEqual(res.droppedGroups, [G1]);
  assert.deepEqual(lastBody(s).groups, [{ group: G2, role: 'viewer' }]);
});

test('a deleted group leaves its approved members uncovered, so the next epoch excludes them and drops it', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  s.server.groups.delete(G1);
  const res = await unshare(s.deps, ARTIFACT, 'viewer@example.com');
  assert.deepEqual(res.droppedGroups, [G1]);
  assert.deepEqual(res.excluded.map((x) => [x.user.id, x.reason]).sort(), [[U.outsider.id, 'left the group'], [U.viewer.id, 'removed']].sort());
  assert.equal(lastBody(s).groups, undefined);
  // The group is still listed by ID to remove, with no name.
  const t = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(t.deps, ARTIFACT, G1, 'viewer');
  t.server.groups.delete(G1);
  const gone = await unshareGroup(t.deps, ARTIFACT, G1);
  assert.deepEqual([gone.group, gone.droppedGroups], [{ id: G1, name: '' }, []]);
});

test('every record the browser writes drops a deleted group: Everyone, public, and a group change', async () => {
  const s = await scene({ groups: [{ id: G1, members: [] }, { id: G2, members: [] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  await shareGroup(s.deps, ARTIFACT, G2, 'viewer');
  s.server.groups.delete(G1);
  assert.deepEqual((await setTeam(s.deps, ARTIFACT, 'viewer')).droppedGroups, [G1]);
  assert.deepEqual(lastBody(s).groups, [{ group: G2, role: 'viewer' }]);
  const t = await scene({ groups: [{ id: G1, members: [] }, { id: G2, members: [] }] });
  await shareGroup(t.deps, ARTIFACT, G1, 'viewer');
  await shareGroup(t.deps, ARTIFACT, G2, 'viewer');
  t.server.groups.delete(G1);
  assert.deepEqual((await setPublic(t.deps, ARTIFACT, true)).droppedGroups, [G1]);
  assert.deepEqual(lastBody(t).groups, [{ group: G2, role: 'viewer' }]);
});

// ---- making an artifact private with approved users ----

test('making a public artifact private lists the approved users and excludes the ones who left', async () => {
  const s = await scene({ isPublic: true, groups: [{ id: G1, members: [{ user: U.outsider }, { user: U.other }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  await changeGroup(s.server, G1, { drop: [U.other] });
  const res = await setPublic(s.deps, ARTIFACT, false);
  assert.equal(res.epoch, 2);
  assert.deepEqual(ids(res.listed), [U.outsider.id]);
  assert.deepEqual(res.excluded.map((x) => [x.user.id, x.reason]), [[U.other.id, 'left the group']]);
  assert.deepEqual(lastBody(s).members.map((m) => m.user), [U.editor.id, U.viewer.id, U.outsider.id]);
});

// ---- the next epoch, by the Go rules ----

// The state: epoch 1; the editor and the viewer are listed. Group G1 (editor)
// holds the outsider and dave, and G2 (viewer) holds other, and all three were
// approved. Dave then left G1 and is in no group. The owner removes the viewer.
//
// The Go client's buildNextEpoch (internal/client/epoch.go) makes, by hand:
//   members   the editor (stays), the outsider (approved; G1 grants editor:
//             grantedRole), other (approved; G2 grants viewer), sorted by user ID
//             (4444, 7777, 8888); the viewer is gone and dave is not listed
//   excluded  the viewer ("removed", under the fingerprint the record listed)
//             and dave ("left the group", p.State == PendingLeft), sorted by
//             user ID (6666, dddd), emails normalized
//   groups    G1 editor, G2 viewer: unchanged, as both still exist
//   team      none
//   epoch     2, with the new key wrapped to the editor, the outsider and other
//             only: the two approved hold the earlier epoch's wraps already
test('the next epoch the browser starts is the record the Go client builds from the same state', async () => {
  const s = await scene({ groups: [{ id: G1, members: [] }, { id: G2, members: [] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'editor');
  await shareGroup(s.deps, ARTIFACT, G2, 'viewer');
  await changeGroup(s.server, G1, { add: [{ user: U.outsider }, { user: U.dave }] });
  await changeGroup(s.server, G2, { add: [{ user: U.other }] });
  for (const who of ['outsider', 'dave', 'other']) await approve(s.deps, ARTIFACT, `${who}@example.com`);
  await changeGroup(s.server, G1, { drop: [U.dave] });
  const res = await unshare(s.deps, ARTIFACT, 'viewer@example.com');
  const put = lastPut(s);
  const body = bodyOf(put.membership);
  assert.deepEqual(body.members, [
    { user: U.editor.id, role: 'editor', fp: U.editor.fp },
    { user: U.outsider.id, role: 'editor', fp: U.outsider.fp },
    { user: U.other.id, role: 'viewer', fp: U.other.fp },
  ]);
  assert.deepEqual(body.excluded, [
    { user: U.viewer.id, fp: U.viewer.fp, email: 'viewer@example.com' },
    { user: U.dave.id, fp: U.dave.fp, email: 'dave@example.com' },
  ]);
  assert.deepEqual(body.groups, [{ group: G1, role: 'editor' }, { group: G2, role: 'viewer' }]);
  assert.equal(body.team, 'none');
  assert.equal(body.epoch, 2);
  assert.deepEqual(put.wraps.map((w) => [w.user, w.epoch]).sort(), [[U.editor.id, 2], [U.outsider.id, 2], [U.other.id, 2]].sort());
  assert.deepEqual(res.excluded.map((x) => x.reason), ['removed', 'left the group']);
  assert.deepEqual(ids(res.listed), [U.outsider.id, U.other.id]);
  // The key of the new epoch opens for those the record lists.
  const ak = await e2e.open(await e2e.ekSealCryptoKey(U.owner.ek), ['estate', ARTIFACT, '2'], e2e.unb64(put.estate[0].sealed));
  for (const w of put.wraps) assert.deepEqual(await unwrapFor(Object.keys(U).find((n) => U[n].id === w.user), w), ak);
});

test('a manager starting the next epoch lists the approved users and seals the key to the owner', async () => {
  const s = await scene({ who: 'manager', members: [{ user: U.manager, role: 'manager' }, { user: U.viewer, role: 'viewer' }], groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'editor');
  const res = await unshare(s.deps, ARTIFACT, 'viewer@example.com');
  assert.equal(res.epoch, 2);
  const put = lastPut(s);
  assert.deepEqual(bodyOf(put.membership).members.map((m) => [m.user, m.role]).sort(), [[U.manager.id, 'manager'], [U.outsider.id, 'editor']].sort());
  assert.deepEqual(put.estate, []);
  assert.ok(put.wraps.some((w) => w.user === U.owner.id && w.epoch === 2));
});

// ---- holders whose keys changed ----

// rekey gives the outsider other keys in the directory, as a reset or a
// rotation does, and returns the new keys' user.
async function rekey(s, { rotation = false } = {}) {
  const next = await makeUser('outsider');
  Object.assign(s.server.directory.get(U.outsider.id), { x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  if (rotation) s.server.rotations[U.outsider.id] = [await rotationRecord(U.outsider, next)];
  return next;
}

test('a holder whose keys changed after they were wrapped to is excluded under the pinned fingerprint, and ends Everyone only in a new epoch', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  await rekey(s);
  const off = await setTeam(s.deps, ARTIFACT, 'none');
  assert.equal(off.epoch, 2, 'a wrap for old keys is a holder the record must exclude');
  assert.deepEqual(off.excluded.map((x) => [x.user.id, x.reason]), [[U.outsider.id, 'their keys changed after they were wrapped to']]);
  assert.deepEqual(lastBody(s).excluded, [{ user: U.outsider.id, fp: U.outsider.fp, email: 'outsider@example.com' }]);
});

test('removing a holder whose keys changed excludes them as removed', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  await rekey(s);
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'outsider@example.com')), 'changed-key');
  const res = await unshare(s.deps, ARTIFACT, 'outsider@example.com');
  assert.deepEqual(res.excluded.map((x) => [x.user.id, x.reason]), [[U.outsider.id, 'removed']]);
  assert.deepEqual(lastBody(s).excluded.map((x) => x.fp), [U.outsider.fp]);
});

test('a holder whose old keys the client has no pin for makes a next epoch refuse, naming the way out', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  await approve(asUser(s, 'editor'), ARTIFACT, 'outsider@example.com');
  await rekey(s);
  const err = await unshare(asUser(s, 'owner'), ARTIFACT, 'viewer@example.com').catch((e) => e);
  assert.equal(err.code, 'wrap-key-unknown');
  assert.match(err.message, /Share with them again and accept the new key/);
  noRecords(s, 1);
});

test('a holder who rotated is excluded, from the owner pin or from the first rotation record', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  const next = await rekey(s, { rotation: true });
  const res = await unshare(s.deps, ARTIFACT, 'viewer@example.com');
  assert.equal(res.excluded.find((x) => x.user.id === U.outsider.id).reason, 'their keys rotated after they were approved, so the approval no longer checks out');
  assert.deepEqual(lastBody(s).excluded.find((x) => x.user === U.outsider.id), { user: U.outsider.id, fp: next.fp, email: 'outsider@example.com' }, 'under the keys they hold now');
  // An editor approved them, so the owner holds no pin: the chain starts at the first record's old keys.
  const t = await scene();
  await setTeam(t.deps, ARTIFACT, 'viewer');
  await approve(asUser(t, 'editor'), ARTIFACT, 'outsider@example.com');
  const later = await rekey(t, { rotation: true });
  const out = await unshare(asUser(t, 'owner'), ARTIFACT, 'viewer@example.com');
  assert.equal(out.excluded.find((x) => x.user.id === U.outsider.id).reason, 'their keys rotated after they were approved, so the approval no longer checks out');
  assert.deepEqual(lastBody(t).excluded.find((x) => x.user === U.outsider.id), { user: U.outsider.id, fp: later.fp, email: 'outsider@example.com' });
});

test('a rotated user whose rotation records cannot be read counts as changed, and a next epoch refuses to guess', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  await rekey(s, { rotation: true });
  const base = s.deps.fetch;
  const failWith = (status) => async (path, init) => {
    if (path.endsWith(`/api/users/${U.outsider.id}/rotations`)) return new Response('{"error":"boom"}', { status });
    const resp = await base(path, init);
    if (!path.endsWith('/membership') || init?.method !== 'GET') return resp;
    const data = await resp.json();
    delete data.rotations[U.outsider.id];
    return new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  s.deps.fetch = failWith(500);
  const err = await unshare(s.deps, ARTIFACT, 'viewer@example.com').catch((e) => e);
  assert.equal(err.code, 'rotations-unreadable');
  assert.match(err.message, /boom/);
  // A refusal of the user's own credentials ends the command rather than degrading it.
  s.deps.fetch = failWith(401);
  await assert.rejects(unshare(s.deps, ARTIFACT, 'viewer@example.com'), { status: 401 });
  noRecords(s, 1);
});

// ---- the other refusals ----

test('approve and the listing check that the pending list and the directory serve the same keys', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.carol }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  await changeGroup(s.server, G1, { add: [{ user: U.other }] });
  const other = await makeUser('outsider');
  const base = s.server.fetch;
  // The pending list serves other keys for the newcomer than the directory does.
  s.deps.fetch = async (path, init) => {
    const resp = await base(path, init);
    if (!path.endsWith('/pending')) return resp;
    const list = (await resp.json()).map((e) => (e.id === U.other.id ? { ...e, x25519Pub: other.pair.x25519, ed25519Pub: other.pair.ed25519 } : e));
    return new Response(JSON.stringify(list), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'other@example.com')), 'pending-keys-differ');
  assert.equal(s.server.approves.length, 1, 'only carol was approved');
  // The same approved user, as the pending list serves them, is not listed.
  lyingPending(s, [{ ...wire(U.carol, 'approved', [G1]), x25519Pub: other.pair.x25519, ed25519Pub: other.pair.ed25519, approval: s.server.approvals.get(U.carol.id).envelope }]);
  const res = await share(s.deps, ARTIFACT, 'outsider@example.com', 'viewer');
  assert.deepEqual(res.unlisted.map((x) => [x.user.id, x.error.code]), [[U.carol.id, 'pending-keys-differ']]);
});

test('an editor listed under another fingerprint than their current one may not approve', async () => {
  const s = await scene({ who: 'editor', members: [{ user: U.editor, role: 'editor', fp: 'c'.repeat(64) }] });
  assert.equal((await waiting(s.deps, ARTIFACT)).canApprove, false);
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'outsider@example.com')), 'not-approver');
});

test('approve refuses an unacknowledged handover', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  const prev = lastBody(s);
  const handover = await e2e.newEnvelope(U.editor.ed.seed, U.editor.id, 'membership', enc.encode(JSON.stringify({
    ...prev, seq: prev.seq + 1, owner: U.editor.id, ownerFp: U.editor.fp, members: prev.members.filter((m) => m.user !== U.editor.id), handover: 'admin', prev: await e2e.bodyHash(e2e.unb64(s.server.records.at(-1).body)),
  })));
  s.server.records = [...s.server.records, handover];
  s.server.owners[U.editor.fp] = U.editor.pair;
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'outsider@example.com')), 'handover-not-acked');
  assert.equal(s.server.approves.length, 0);
});

test('a record with no group asks the server for no groups, and lists groups after team, before public', async () => {
  const s = await scene();
  await share(s.deps, ARTIFACT, 'outsider@example.com', 'viewer');
  assert.deepEqual((await members(s.deps, ARTIFACT)).groups, []);
  assert.ok(!s.server.calls.some((c) => c.path === '/api/groups'), 'nothing to look up');
  assert.ok(!('groups' in lastBody(s)));
  const t = await scene({ groups: [{ id: G1, members: [] }] });
  await shareGroup(t.deps, ARTIFACT, G1, 'viewer');
  assert.match(dec.decode(e2e.unb64(lastPut(t).membership.body)), /"team":"none","groups":\[\{"group":"b1b1b1b1-1111-4111-8111-111111111111","role":"viewer"\}\],"public":false/);
});

test('members names the team share, the groups with the names the server holds, and who may approve', async () => {
  const s = await scene({ groups: [{ id: G1, name: 'Design', members: [] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'editor');
  await setTeam(s.deps, ARTIFACT, 'viewer');
  const owner = await members(s.deps, ARTIFACT);
  assert.deepEqual([owner.team, owner.canApprove, owner.callerRole], ['viewer', true, 'owner']);
  assert.deepEqual(owner.groups, [{ id: G1, name: 'Design', role: 'editor', deleted: false }]);
  const editor = await members(asUser(s, 'editor'), ARTIFACT);
  assert.deepEqual([editor.canApprove, editor.callerRole], [true, '']);
  assert.equal((await members(asUser(s, 'viewer'), ARTIFACT)).canApprove, false);
});

test('share names an approved user whose approval fails a check as unlisted, and lists nobody on its word', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  s.server.approvals.set(U.outsider.id, { fp: U.outsider.fp, envelope: await e2e.signApproval(U.other.ed.seed, U.other.id, { artifact: ARTIFACT, epoch: 1, user: U.outsider.id, fp: U.outsider.fp }) });
  const res = await share(s.deps, ARTIFACT, 'carol@example.com', 'viewer');
  assert.deepEqual(res.listed, []);
  assert.deepEqual(res.unlisted.map((x) => x.user.id), [U.outsider.id]);
  assert.deepEqual(lastBody(s).members.map((m) => m.user), [U.editor.id, U.viewer.id, U.carol.id].sort());
});

// ---- approving the members of a group that was just listed ----

test('sharing with a group leaves a member waiting when the server refuses their approval, and stops on a refusal of the credentials', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  s.server.failPut = (kind) => (kind === 'approve' ? new Response('{"error":"the artifact moved"}', { status: 409 }) : null);
  const res = await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  assert.deepEqual(res.approved, []);
  assert.deepEqual(res.pending.map((p) => [p.user.id, p.error.message]), [[U.outsider.id, 'the artifact moved']]);
  const t = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  t.server.failPut = (kind) => (kind === 'approve' ? new Response('{"error":"unauthorized"}', { status: 401 }) : null);
  await assert.rejects(shareGroup(t.deps, ARTIFACT, G1, 'viewer'), { status: 401 });
});

test('sharing with a group with the key accepted approves a member whose pin changed, and still leaves a group fingerprint mismatch waiting', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }, { user: U.other, fp: 'f'.repeat(64) }] }] });
  const k = e2e.newKeyring();
  k.pins[U.outsider.id] = { fp: 'd'.repeat(64), state: 'verified', rotSeq: 0, rotHead: '' };
  await seedKeyring(s.server, U.owner, k);
  const res = await shareGroup(s.deps, ARTIFACT, G1, 'viewer', { acceptNewKey: true });
  assert.deepEqual(ids(res.approved), [U.outsider.id]);
  assert.deepEqual(res.pending.map((p) => p.user.id), [U.other.id]);
  assert.ok(res.pending[0].error instanceof GroupKeyChangedError);
});

// ---- a manager removing a group ----

test('a manager removing a group in a new epoch seals the key to the owner, in a version 2 record', async () => {
  const s = await scene({ who: 'manager', members: [{ user: U.manager, role: 'manager' }], groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  const res = await unshareGroup(s.deps, ARTIFACT, G1);
  assert.equal(res.epoch, 2);
  const put = lastPut(s);
  const body = bodyOf(put.membership);
  assert.deepEqual([body.v, body.signer, body.epoch], [2, U.manager.id, 2]);
  assert.deepEqual(put.estate, []);
  assert.ok(put.wraps.some((w) => w.user === U.owner.id && w.epoch === 2));
  assert.deepEqual(body.excluded.map((x) => x.user), [U.outsider.id]);
});

// ---- what the server says, and the client checks ----

// rewritePending changes each entry of the pending list the server serves.
function rewritePending(s, change) {
  const base = s.server.fetch;
  s.deps.fetch = async (path, init) => {
    const resp = await base(path, init);
    if (!path.endsWith('/pending')) return resp;
    return new Response(JSON.stringify((await resp.json()).map(change)), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
}

test('a user the server calls rotated is changed unless their rotation records lead to their keys', async () => {
  // The server says rotated of a user the team share holds, whose approval the client checked.
  const lie = async () => {
    const s = await scene();
    await setTeam(s.deps, ARTIFACT, 'viewer');
    await approve(s.deps, ARTIFACT, 'outsider@example.com');
    rewritePending(s, (e) => (e.id === U.outsider.id ? { ...e, state: 'rotated' } : e));
    return s;
  };
  const reasonOf = async (s) => (await unshare(s.deps, ARTIFACT, 'viewer@example.com')).excluded.find((x) => x.user.id === U.outsider.id).reason;
  // Their keys did not change at all.
  assert.equal(await codeOf(unshare((await lie()).deps, ARTIFACT, 'viewer@example.com')), 'wrap-key-unknown');
  // Their keys changed, and there are no records to lead from the old keys to the new.
  const bare = await lie();
  await rekey(bare);
  assert.equal(await reasonOf(bare), 'their keys changed after they were wrapped to');
  // The records the server serves for the chain do not parse.
  const garbled = await lie();
  await rekey(garbled);
  garbled.server.rotations[U.outsider.id] = [{ body: e2e.b64(enc.encode('{}')), signer: U.outsider.id, sig: '', newSig: '' }];
  assert.equal(await reasonOf(garbled), 'their keys changed after they were wrapped to');
});

test('approve takes a listed member whose keys rotated for a listed member, and another user who rotated for a changed key', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  const next = await makeUser('viewer');
  Object.assign(s.server.directory.get(U.viewer.id), { x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  s.server.rotations[U.viewer.id] = [await rotationRecord(U.viewer, next)];
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'viewer@example.com')), 'already-listed');
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  await rekey(s, { rotation: true });
  assert.equal(await codeOf(approve(s.deps, ARTIFACT, 'outsider@example.com')), 'changed-key');
});

test('a group deleted while its member waits holds nobody, and their approval is not listed on its word', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.carol }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  s.server.groups.delete(G1);
  // The server still names the deleted group as the one that holds them.
  rewritePending(s, (e) => (e.id === U.carol.id ? { ...e, state: 'approved', group: [G1], approval: s.server.approvals.get(U.carol.id).envelope } : e));
  const res = await unshare(s.deps, ARTIFACT, 'viewer@example.com');
  assert.deepEqual(res.listed, []);
  assert.match(res.excluded.find((x) => x.user.id === U.carol.id).reason, /^their approval does not check out: .*does not list/);
});

test('a refusal of the credentials while a group is verified ends the change, and so does a signer whose key changed', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.carol }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  const base = s.deps.fetch;
  s.deps.fetch = async (path, init) => (path === `/api/groups/${G1}` ? new Response('{"error":"unauthorized"}', { status: 401 }) : base(path, init));
  await assert.rejects(unshare(s.deps, ARTIFACT, 'viewer@example.com'), { status: 401 });
  // A group another user manages: their key changes after the owner pinned it.
  const t = await scene({ users: [U.outsider, U.carol, U.manager], groups: [{ id: G1, manager: U.manager, members: [{ user: U.carol }] }] });
  await shareGroup(t.deps, ARTIFACT, G1, 'viewer');
  const next = await makeUser('manager');
  for (const dir of [t.server.directory, t.server.groupServer.directory]) Object.assign(dir.get(U.manager.id), { x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  await assert.rejects(unshare(t.deps, ARTIFACT, 'viewer@example.com'), KeyChangedError);
  await assert.rejects(shareGroup(t.deps, ARTIFACT, G1, 'viewer'), KeyChangedError);
  noRecords(t, 1);
});

test('while Everyone is on, a group record under another fingerprint does not stop an approval', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider, fp: 'f'.repeat(64) }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  await setTeam(s.deps, ARTIFACT, 'viewer');
  const res = await approve(s.deps, ARTIFACT, 'outsider@example.com');
  assert.equal(res.user.id, U.outsider.id);
});

test('removing a group does not count the listed group that holds nobody the removed one holds', async () => {
  const s = await scene({ groups: [{ id: G1, members: [] }, { id: G2, members: [] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  await shareGroup(s.deps, ARTIFACT, G2, 'viewer');
  await changeGroup(s.server, G1, { add: [{ user: U.outsider }] });
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  const res = await unshareGroup(s.deps, ARTIFACT, G1);
  assert.equal(res.epoch, 2);
  assert.deepEqual(lastBody(s).groups, [{ group: G2, role: 'viewer' }]);
});

test('Everyone off leaves a listed member whose keys changed alone, in the same epoch', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  const next = await makeUser('viewer');
  Object.assign(s.server.directory.get(U.viewer.id), { x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  const res = await setTeam(s.deps, ARTIFACT, 'none');
  assert.deepEqual([res.epoch, res.reseal, lastBody(s).epoch], [1, null, 1]);
});

test('groups are listed in the order of their IDs whatever order they were shared in', async () => {
  const s = await scene({ groups: [{ id: G1, members: [] }, { id: G2, members: [] }] });
  await shareGroup(s.deps, ARTIFACT, G2, 'viewer');
  await shareGroup(s.deps, ARTIFACT, G1, 'editor');
  assert.deepEqual(lastBody(s).groups, [{ group: G1, role: 'editor' }, { group: G2, role: 'viewer' }]);
});

test('removing a user a group still covers excludes them, and does not list them', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'editor');
  const res = await unshare(s.deps, ARTIFACT, 'outsider@example.com');
  assert.deepEqual(res.excluded.map((x) => [x.user.id, x.reason]), [[U.outsider.id, 'removed']]);
  assert.deepEqual(res.listed, []);
  assert.deepEqual(lastBody(s).members.map((m) => m.user), [U.editor.id, U.viewer.id]);
});

test('approving users who a server lists as a list that is not one is refused', async () => {
  const s = await scene();
  const base = s.server.fetch;
  s.deps.fetch = async (path, init) => (path.endsWith('/pending') ? new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }) : base(path, init));
  await assert.rejects(waiting(s.deps, ARTIFACT), e2e.FormatError);
  await assert.rejects(approvableCount(s.deps, ARTIFACT), e2e.FormatError);
});

test('an owner whose keys rotated since the record was signed approves nobody until the record lists the new key', async () => {
  const s = await scene();
  await setTeam(s.deps, ARTIFACT, 'viewer');
  const next = await makeUser('owner');
  Object.assign(next, { mk: U.owner.mk, ek: U.owner.ek }); // rotating keys keeps the account secrets
  s.server.rotations[U.owner.id] = [await rotationRecord(U.owner, next)];
  Object.assign(s.server.directory.get(U.owner.id), { x25519Pub: next.pair.x25519, ed25519Pub: next.pair.ed25519 });
  s.server.who = next;
  const deps = depsFor(s.server, await keyStoreRecord(next));
  assert.equal((await waiting(deps, ARTIFACT)).canApprove, false);
  assert.equal(await codeOf(approve(deps, ARTIFACT, 'outsider@example.com')), 'not-approver');
});

test('removing a group Everyone still covers, for a user only the group holds, is a same-epoch record', async () => {
  const s = await scene({ groups: [{ id: G2, members: [] }] });
  await shareGroup(s.deps, ARTIFACT, G2, 'viewer');
  await setTeam(s.deps, ARTIFACT, 'viewer');
  await changeGroup(s.server, G2, { add: [{ user: U.outsider }] });
  await approve(s.deps, ARTIFACT, 'outsider@example.com');
  const res = await unshareGroup(s.deps, ARTIFACT, G2);
  assert.deepEqual([res.epoch, res.reseal, res.excluded], [1, null, []]);
});

test('sharing with a group again approves nobody who is approved already, even when their approval is not listed', async () => {
  const s = await scene({ groups: [{ id: G1, members: [{ user: U.outsider }] }] });
  await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  s.server.approvals.set(U.outsider.id, { fp: U.outsider.fp, envelope: await e2e.signApproval(U.other.ed.seed, U.other.id, { artifact: ARTIFACT, epoch: 1, user: U.outsider.id, fp: U.outsider.fp }) });
  const again = await shareGroup(s.deps, ARTIFACT, G1, 'viewer');
  assert.deepEqual(again.unlisted.map((x) => x.user.id), [U.outsider.id]);
  assert.deepEqual([again.approved, again.pending], [[], []]);
});

test('every record that lists a user an editor approved pins them, since the owner holds no pin yet', async () => {
  const pinnedAfter = async (s) => (await readServerKeyring(s.server, U.owner)).pins[U.outsider.id];
  const unverified = { fp: U.outsider.fp, state: 'unverified', rotSeq: 0, rotHead: '' };
  // Everyone: an editor approves, and the owner changes the role Everyone grants.
  const team = await scene();
  await setTeam(team.deps, ARTIFACT, 'viewer');
  await approve(asUser(team, 'editor'), ARTIFACT, 'outsider@example.com');
  await setTeam(asUser(team, 'owner'), ARTIFACT, 'editor');
  assert.deepEqual(await pinnedAfter(team), unverified);
  // A share of someone else.
  const other = await scene();
  await setTeam(other.deps, ARTIFACT, 'viewer');
  await approve(asUser(other, 'editor'), ARTIFACT, 'outsider@example.com');
  await share(asUser(other, 'owner'), ARTIFACT, 'carol@example.com', 'viewer');
  assert.deepEqual(await pinnedAfter(other), unverified);
  // A group the owner shares again with another role.
  const group = await scene({ groups: [{ id: G1, members: [] }] });
  await shareGroup(group.deps, ARTIFACT, G1, 'viewer');
  await changeGroup(group.server, G1, { add: [{ user: U.outsider }] });
  await approve(asUser(group, 'editor'), ARTIFACT, 'outsider@example.com');
  await shareGroup(asUser(group, 'owner'), ARTIFACT, G1, 'editor');
  assert.deepEqual(await pinnedAfter(group), unverified);
  assert.equal(lastBody(group).members.find((m) => m.user === U.outsider.id).role, 'editor', 'listed under the role the new record gives the group');
});
