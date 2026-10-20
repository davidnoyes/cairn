// Tests for folders with other people's items (milestone F3), in sharing.mjs
// and folders.mjs: the folder owner's entry on an item someone else owns, the
// stubs the list gives for items the caller cannot read yet, placing an own
// item in a folder someone else owns, removing someone else's item from a
// folder, apply, and deleting a folder that holds other people's items. They
// run against real chains, wraps and keyrings behind folder_fixture.mjs, which
// refuses what internal/server/folders.go and internal/store/folders.go refuse.
// They mirror apply_test.go and folders_others_test.go in internal/client and
// internal/server. Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { makeUser } from './viewer_fixture.mjs';
import { depsFor, extraUser, keyStoreRecord, seedGroup } from './sharing_fixture.mjs';
import { makeFolderServer } from './folder_fixture.mjs';
import { createFolder, deleteTree, moveAndPlace, removeFromFolder, splitTrees } from './folders.mjs';
import { GroupKeyChangedError, apply, applyNote, fanOut, fanOutNote, planInherit, share } from './sharing.mjs';
import { openArtifact } from './viewer.mjs';

const U = {};
for (const name of ['owner', 'editor', 'viewer', 'outsider']) U[name] = await makeUser(name);
U.other = await extraUser('other', '88888888-8888-4888-8888-888888888888');
U.manager = await extraUser('manager', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
const records = {};
for (const name of Object.keys(U)) records[name] = await keyStoreRecord(U[name]);

// The cast: owner (O) owns the folder F; other (P) owns the items placed in it.
const F = 'f0000000-0000-4000-8000-0000000000f1';
const F2 = 'f0000000-0000-4000-8000-0000000000f2';
const AP = 'f0000000-0000-4000-8000-0000000000a1';
const AO = 'f0000000-0000-4000-8000-0000000000a2';
const A2 = 'f0000000-0000-4000-8000-0000000000a3';
const GROUP = 'b1b1b1b1-1111-4111-8111-111111111111';

const yes = () => true;
const listed = (user, role, via) => ({ user, role, ...(via ? { via } : {}) });

// scene serves items, each {id, kind, parent, owner, members, groups, folder},
// with who signed in. as(name) signs in as another user of the same server.
async function scene({ who = 'other', items, users = [U.outsider, U.other, U.manager, U.editor, U.viewer] }) {
  const server = await makeFolderServer({ who: U[who], users, items: items.map((i) => ({ kind: 'artifact', parent: null, owner: U.owner, ...i })) });
  const s = { server, deps: depsFor(server, records[who]) };
  // One keyring per user: the fake serves a single one, so a switch starts it again.
  s.as = (name) => {
    server.who = U[name];
    server.primary.keyring = { rev: 0, keyring: '' };
    return depsFor(server, records[name]);
  };
  return s;
}

const latest = (s, id) => s.server.latestOf(id);
const entry = (s, id, user) => latest(s, id).members.find((m) => m.user === user.id);
const list = async (s) => (await s.server.fetch('/api/artifacts')).json();
// viewsOf counts the reads of the view of id, which the fan-out of an item starts with.
const viewsOf = (s, id) => s.server.calls.filter((c) => c.method === 'GET' && c.path === `/api/artifacts/${id}`).length;
const stateOf = (res, id) => res.fanOut.items.find((i) => i.id === id);

async function unwrapFor(name, id, w) {
  const ctx = { purpose: 'ak', artifact: id, epoch: w.epoch, recipientId: U[name].id, recipientPub: U[name].x.pub };
  return e2e.unwrap(records[name].x25519, ctx, e2e.unb64(w.wrapped));
}

// F is O's folder, which P edits and V reads; AP is P's item inside it.
const folderOf = (extra = {}) => ({ id: F, kind: 'folder', members: [listed(U.other, 'editor'), listed(U.viewer, 'viewer')], ...extra });
const itemOfP = (extra = {}) => ({ id: AP, parent: F, owner: U.other, ...extra });

// ---- the folder owner's entry, in the plan ----

// The rule, worked by hand from the spec ("The folder's owner manages what is in
// it"): an item someone else owns lists the owner of its folder as a manager,
// via the folder, under the fingerprint the folder's latest record gives as
// ownerFp, besides the folder's own entries.
//
// State 1. The folder P is owned by o0 (ownerFp fo) and lists a1 as viewer
// (fp fa), and the group g1 as viewer. The item is owned by p0 and lists
// nothing. The owners differ, so the item wants: a1 as viewer via P, g1 as
// viewer via P, and o0 as manager via P with fo. Lists come out sorted by ID:
// a1, then o0. Both users are added, and nothing leaves, so no new epoch.
//
// State 2. The same folder, and an item owned by o0 itself, which lists a1 as
// viewer via P already: the owners are the same, so no entry for o0 is wanted,
// and the owner is never listed on their own item. The item is as its folder
// says: members a1 only, nothing added.
test('planInherit lists the folder owner as a manager via the folder on an item someone else owns (state 1), and not on their own (state 2)', () => {
  const parent = { owner: 'o0', ownerFp: 'fo', members: [{ user: 'a1', role: 'viewer', fp: 'fa' }], groups: [{ group: 'g1', role: 'viewer' }] };
  const one = planInherit({ owner: 'p0', members: [], groups: [] }, parent, 'P', yes, yes);
  assert.deepEqual(one, {
    members: [{ user: 'a1', role: 'viewer', fp: 'fa', via: 'P' }, { user: 'o0', role: 'manager', fp: 'fo', via: 'P' }],
    groups: [{ group: 'g1', role: 'viewer', via: 'P' }],
    added: ['a1', 'o0'],
    addedGroups: ['g1'],
    skippedUsers: [],
    skippedGroups: [],
    epoch: false,
  });
  const two = planInherit({ owner: 'o0', members: [{ user: 'a1', role: 'viewer', fp: 'fa', via: 'P' }], groups: [{ group: 'g1', role: 'viewer', via: 'P' }] }, parent, 'P', yes, yes);
  assert.deepEqual(two.members, [{ user: 'a1', role: 'viewer', fp: 'fa', via: 'P' }]);
  assert.deepEqual(two.added, []);
  assert.equal(two.epoch, false);
});

// State 3. A owns the folder FA, C owns the folder FC, and FC sits in FA, so
// FC's own record lists A as manager via FA (inherited). B's item sits in FC.
// The item wants FC's entries: A as manager, still marked FA, the nearest folder
// that lists them itself, and C, the owner of FC, as manager via FC.
test('planInherit marks the entry inherited from the folder above with that folder, and the owner of the folder the item sits in with it (state 3)', () => {
  const fc = { owner: 'c0', ownerFp: 'fc', members: [{ user: 'a0', role: 'manager', fp: 'fa', via: 'FA' }], groups: [] };
  const plan = planInherit({ owner: 'b0', members: [], groups: [] }, fc, 'FC', yes, yes);
  assert.deepEqual(plan.members, [{ user: 'a0', role: 'manager', fp: 'fa', via: 'FA' }, { user: 'c0', role: 'manager', fp: 'fc', via: 'FC' }]);
  assert.deepEqual(plan.added, ['a0', 'c0']);
});

test('the folder owner\'s entry follows the role merge: a direct grant keeps the higher role, and an entry via another folder follows this one', () => {
  const parent = { owner: 'o0', ownerFp: 'fo', members: [], groups: [] };
  const direct = planInherit({ owner: 'p0', members: [{ user: 'o0', role: 'manager', fp: 'fo' }] }, parent, 'P', yes, yes);
  assert.deepEqual(direct.members, [{ user: 'o0', role: 'manager', fp: 'fo' }], 'a direct manager stays one, with no mark');
  assert.deepEqual(direct.added, []);
  const viewer = planInherit({ owner: 'p0', members: [{ user: 'o0', role: 'viewer', fp: 'fo' }] }, parent, 'P', yes, yes);
  assert.deepEqual(viewer.members, [{ user: 'o0', role: 'manager', fp: 'fo' }], 'a direct viewer is raised to manager');
  const editor = planInherit({ owner: 'p0', members: [{ user: 'o0', role: 'editor', fp: 'fo' }] }, parent, 'P', yes, yes);
  assert.deepEqual(editor.members, [{ user: 'o0', role: 'manager', fp: 'fo' }], 'a direct editor is raised to manager');
  const old = planInherit({ owner: 'p0', members: [{ user: 'o0', role: 'editor', fp: 'fo', via: 'OLD' }] }, parent, 'P', yes, yes);
  assert.deepEqual(old.members, [{ user: 'o0', role: 'manager', fp: 'fo', via: 'P' }]);
  assert.equal(old.epoch, false, 'a raised role takes no next epoch');
});

test('the folder owner is skipped, and named, while their account is not usable, and not wanted at the top level', () => {
  const parent = { owner: 'o0', ownerFp: 'fo', members: [], groups: [] };
  const skipped = planInherit({ owner: 'p0', members: [] }, parent, 'P', (u) => u !== 'o0', yes);
  assert.deepEqual(skipped.members, []);
  assert.deepEqual(skipped.skippedUsers, ['o0']);
  assert.deepEqual(skipped.added, []);
  assert.deepEqual(planInherit({ owner: 'p0', members: [{ user: 'o0', role: 'editor', fp: 'fo', via: 'P' }] }, null, '', yes, yes).epoch, true, 'leaving the folder ends the entry');
});

// ---- the folder owner's entry, on create and in the fixture ----

test('a folder created inside someone else\'s folder lists the folder\'s owner as a manager via it, with a wrap of the key', async () => {
  const s = await scene({ items: [folderOf()] });
  const { id } = await createFolder(s.deps, { name: 'Mine', parent: F });
  const body = latest(s, id);
  assert.equal(body.owner, U.other.id);
  assert.deepEqual(body.members.map((m) => [m.user, m.role, m.via, m.fp]), [
    [U.viewer.id, 'viewer', F, U.viewer.fp],
    [U.owner.id, 'manager', F, U.owner.fp],
  ].sort((a, b) => (a[0] < b[0] ? -1 : 1)));
  const post = s.server.posts[0];
  assert.deepEqual(post.wraps.map((w) => w.user).sort(), [U.owner.id, U.viewer.id].sort());
  const ak = await e2e.open(await e2e.ekSealCryptoKey(U.other.ek), ['estate', id, '1'], e2e.unb64(post.estate[0].sealed));
  const w = post.wraps.find((x) => x.user === U.owner.id);
  assert.deepEqual(await unwrapFor('owner', id, w), ak, 'the folder\'s owner can open the new folder');
  assert.equal(s.server.inheritOf(id), 'ok');
  assert.equal((await list(s)).find((a) => a.id === id).owner, U.other.id);
  // The folder's owner manages it, from the view of the list.
  s.as('owner');
  assert.equal((await list(s)).find((a) => a.id === id).access, 'manager');
});

test('the folder\'s owner creating inside their own folder lists no entry for themselves', async () => {
  const s = await scene({ who: 'owner', items: [folderOf()] });
  const { id } = await createFolder(s.deps, { name: 'Mine', parent: F });
  assert.deepEqual(latest(s, id).members.map((m) => m.user), [U.other.id, U.viewer.id].sort());
});

test('a folder created inside a folder whose owner the directory no longer serves lists nobody for them, and is accepted', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.other, 'editor')] })] });
  s.server.primary.directory.delete(U.owner.id);
  const { id } = await createFolder(s.deps, { name: 'Mine', parent: F });
  assert.deepEqual(latest(s, id).members, []);
});

test('a folder created inside a folder whose owner the directory serves under another key is refused', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.other, 'editor')] })] });
  // The caller opened the folder once, which pinned its owner under the key they have.
  await openArtifact(s.deps, { artifact: F, link: null });
  s.server.primary.directory.get(U.owner.id).x25519Pub = U.outsider.pair.x25519;
  await assert.rejects(createFolder(s.deps, { name: 'Mine', parent: F }), (e) => e.code === 'member-key-changed');
  assert.deepEqual(s.server.posts, []);
});

// putAs PUTs the record after id's latest, signed by signer, with patch laid
// over its body, and returns the response.
async function putAs(s, id, signer, patch) {
  const kid = s.server.kids.get(id);
  const raw = e2e.unb64(kid.records.at(-1).body);
  const body = { ...JSON.parse(new TextDecoder().decode(raw)), ...patch };
  body.seq += 1;
  body.prev = await e2e.bodyHash(raw);
  const membership = await e2e.newEnvelope(signer.ed.seed, signer.id, 'membership', new TextEncoder().encode(JSON.stringify(body)));
  return s.server.fetch(`/api/artifacts/${id}/membership`, { method: 'PUT', body: JSON.stringify({ membership, wraps: [], estate: [], linkTokenHash: '' }) });
}

test('the server refuses a record for an item someone else owns that leaves out the folder\'s owner, or lists them below manager', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP()] });
  assert.equal(s.server.inheritOf(AP), 'pending', 'the item lacks the folder owner\'s entry');
  const missing = await putAs(s, AP, U.other, {});
  assert.equal(missing.status, 409);
  assert.match((await missing.json()).error, /inherit: member .* is missing/);
  const low = await putAs(s, AP, U.other, { members: [{ user: U.owner.id, role: 'viewer', fp: U.owner.fp, via: F }] });
  assert.equal(low.status, 409);
  assert.match((await low.json()).error, /is viewer/);
  const ok = await putAs(s, AP, U.other, { members: [{ user: U.owner.id, role: 'manager', fp: U.owner.fp, via: F }] });
  assert.equal(ok.status, 200);
  assert.equal(s.server.inheritOf(AP), 'ok');
});

test('the server refuses a record that lists the folder\'s owner as an editor via the folder, and says the folder lists them as manager', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP()] });
  const resp = await putAs(s, AP, U.other, { members: [{ user: U.owner.id, role: 'editor', fp: U.owner.fp, via: F }] });
  assert.equal(resp.status, 409);
  assert.match((await resp.json()).error, /inherit: member .* is editor: folder .* lists them as manager/);
  assert.equal(s.server.inheritOf(AP), 'pending');
  const missing = await putAs(s, AP, U.other, { members: [] });
  assert.match((await missing.json()).error, /member .* is missing: folder .* lists them as manager/);
});

test('the owner entry of an item ends with the folder: the item is pending once it leaves', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP({ members: [listed(U.owner, 'manager', F)] })] });
  assert.equal(s.server.inheritOf(AP), 'ok');
  s.as('owner');
  assert.equal(s.server.levelOf(AP), 'manager', 'the folder\'s owner manages it while it is inside');
  s.as('other');
  s.server.setParent(AP, null);
  assert.equal(s.server.inheritOf(AP), 'pending');
  assert.equal(s.server.levelOf(AP), 'owner');
  s.as('owner');
  assert.equal(s.server.levelOf(AP), '', 'the folder\'s owner reads it no longer');
});

test('an item that lists the folder\'s owner as an editor is pending, and its owner\'s apply raises the entry to manager without a next epoch', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP({ members: [listed(U.owner, 'editor', F)] })] });
  assert.equal(s.server.inheritOf(AP), 'pending');
  s.as('owner');
  assert.equal(s.server.levelOf(AP), 'editor', 'until then the entry grants what it lists');
  const res = await apply(s.as('other'));
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[AP, 'updated']]);
  assert.deepEqual(entry(s, AP, U.owner), { user: U.owner.id, role: 'manager', fp: U.owner.fp, via: F });
  assert.equal(s.server.inheritOf(AP), 'ok');
});

// ---- stubs ----

test('the list gives a stub for an item in a folder the caller reads and cannot read, with no name, and none for any other', async () => {
  const s = await scene({ who: 'owner', items: [folderOf(), itemOfP(), { id: A2, parent: null, owner: U.other }] });
  const all = await list(s);
  assert.deepEqual(all.find((a) => a.id === AP), { id: AP, kind: 'artifact', owner: U.other.id, parent: F, inherit: 'pending', access: 'none' });
  assert.equal(all.some((a) => a.id === A2), false, 'an unreadable item at the top level is not listed');
  assert.equal((await s.server.fetch(`/api/artifacts/${AP}`)).status, 404, 'a stub cannot be opened');
  // Someone who does not read the folder is told of nothing.
  s.as('outsider');
  assert.equal((await list(s)).length, 0);
  // The owner of the item reads it, and it is no stub.
  s.as('other');
  assert.equal((await list(s)).find((a) => a.id === AP).access, 'owner');
});

test('once its owner applies, the folder owner manages the item: the stub becomes the item, at manager access', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP()] });
  await apply(s.deps);
  s.as('owner');
  const view = (await list(s)).find((a) => a.id === AP);
  assert.equal(view.access, 'manager');
  assert.equal(view.inherit, 'ok');
  assert.equal(view.owner, U.other.id);
});

test('splitTrees on the list the server gives shows a stub in the folder\'s tree, and the caller\'s item in someone else\'s folder', async () => {
  const s = await scene({ who: 'owner', items: [folderOf(), itemOfP(), { id: AO, parent: F, owner: U.owner }] });
  const { own, shared } = splitTrees(await list(s), U.owner.id);
  assert.deepEqual(own.map((i) => [i.id, i.access]).sort(), [[AO, 'owner'], [AP, 'none'], [F, 'owner']].sort());
  assert.deepEqual(shared, []);
  s.as('other');
  const mine = splitTrees(await list(s), U.other.id);
  assert.deepEqual(mine.own, [], 'every item sits in the tree of the folder someone else owns');
  assert.deepEqual(mine.shared.map((i) => [i.id, i.access]).sort(), [[AO, 'none'], [AP, 'owner'], [F, 'editor']].sort(), 'the caller\'s own item among them, and the owner\'s pending one as a stub');
});

// ---- apply ----

test('apply adds the entries the folder lists, and the folder owner, with a wrap of every epoch', async () => {
  const s = await scene({ items: [folderOf(), itemOfP({ epoch2: true })] });
  assert.equal(s.server.inheritOf(AP), 'pending');
  const res = await apply(s.deps);
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[AP, 'updated']]);
  assert.equal(res.fanOut.total, 1);
  assert.equal(res.fanOut.failed, 0);
  assert.deepEqual(res.waiting, []);
  assert.deepEqual(entry(s, AP, U.viewer), { user: U.viewer.id, role: 'viewer', fp: U.viewer.fp, via: F });
  assert.deepEqual(entry(s, AP, U.owner), { user: U.owner.id, role: 'manager', fp: U.owner.fp, via: F });
  const put = s.server.records.find((r) => r.id === AP).put;
  assert.deepEqual(put.wraps.map((w) => [w.user, w.epoch]).sort(), [[U.owner.id, 1], [U.owner.id, 2], [U.viewer.id, 1], [U.viewer.id, 2]].sort());
  for (const w of put.wraps) assert.deepEqual(await unwrapFor(w.user === U.owner.id ? 'owner' : 'viewer', AP, w), s.server.kids.get(AP).world.aks[w.epoch]);
  assert.equal(s.server.inheritOf(AP), 'ok');
  // Running it again finds nothing.
  const again = await apply(s.deps);
  assert.deepEqual(again, { fanOut: { items: [], total: 0, failed: 0 }, waiting: [], approvals: [] });
});

test('apply starts the next epoch where a via no longer holds, and excludes who held the item only through it', async () => {
  const s = await scene({
    items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP({ members: [listed(U.viewer, 'viewer', F), listed(U.owner, 'manager', F)] })],
  });
  const res = await apply(s.deps);
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[AP, 'newEpoch']]);
  assert.deepEqual(res.fanOut.items[0].excluded.map((x) => x.user.id), [U.viewer.id]);
  assert.equal(latest(s, AP).epoch, 2);
  assert.equal(entry(s, AP, U.viewer), undefined);
  assert.deepEqual(entry(s, AP, U.owner), { user: U.owner.id, role: 'manager', fp: U.owner.fp, via: F });
  assert.equal(s.server.inheritOf(AP), 'ok');
});

test('apply writes a record naming no folder for an own item the server lists at the top level, and the folder owner\'s entry ends with it', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP({ parent: null, folder: F, members: [listed(U.owner, 'manager', F)] })] });
  assert.equal(s.server.inheritOf(AP), 'pending', 'the record still names the folder');
  const res = await apply(s.deps);
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[AP, 'newEpoch']]);
  assert.equal(latest(s, AP).folder, undefined);
  assert.deepEqual(latest(s, AP).members, []);
  assert.equal(s.server.inheritOf(AP), 'ok');
  assert.deepEqual(s.server.moves, [], 'nothing was moved: only the record was written');
});

test('apply writes the orphan\'s record at the same epoch when no entry came from the folder', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP({ parent: null, folder: F, members: [listed(U.viewer, 'viewer')] })] });
  const res = await apply(s.deps);
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[AP, 'updated']]);
  assert.equal(latest(s, AP).folder, undefined);
  assert.equal(latest(s, AP).epoch, 1);
  assert.deepEqual(entry(s, AP, U.viewer), { user: U.viewer.id, role: 'viewer', fp: U.viewer.fp }, 'a direct grant stays');
});

test('apply leaves an item whose record names another folder than the one it sits in as needing a move, and names the move', async () => {
  const s = await scene({ items: [folderOf(), itemOfP({ folder: '' })] });
  const res = await apply(s.deps);
  const item = stateOf(res, AP);
  assert.equal(item.state, 'needsMove');
  assert.equal(item.error.code, 'placement');
  assert.match(item.error.message, /move it to the folder/);
  assert.equal(res.fanOut.failed, 0, 'not a failure');
  assert.equal(s.server.records.length, 0);
  assert.match(applyNote(res, (e) => e.message), /1 item needs a move first: .*AP|1 item needs a move first/);
});

test('apply as a manager adds the folder\'s entries, and waits on the owner for a move of the folder', async () => {
  const mgr = (extra = {}) => itemOfP({ members: [listed(U.manager, 'manager'), listed(U.owner, 'manager', F)], ...extra });
  const base = folderOf({ members: [listed(U.other, 'editor'), listed(U.viewer, 'viewer'), listed(U.manager, 'editor')] });
  const s = await scene({ who: 'manager', items: [base, mgr()] });
  const res = await apply(s.deps);
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[AP, 'updated']]);
  assert.equal(entry(s, AP, U.viewer).via, F);
  assert.equal(latest(s, AP).v, 2, 'a manager signs as one');
  // The server lists the item at the top level: only its owner writes a record that names no folder.
  const t = await scene({ who: 'manager', items: [base, mgr({ parent: null, folder: F })] });
  const waits = await apply(t.deps);
  assert.deepEqual(waits.fanOut.items, []);
  assert.deepEqual(waits.waiting.map((i) => [i.id, i.state, i.owner, i.ownerEmail]), [[AP, 'waits', U.other.id, 'other@example.com']]);
  assert.equal(t.server.records.length, 0);
});

test('apply as a manager waits on the owner when the folder lists another manager', async () => {
  const base = folderOf({ members: [listed(U.other, 'editor'), listed(U.manager, 'editor'), listed(U.editor, 'manager')] });
  const s = await scene({ who: 'manager', items: [base, itemOfP({ members: [listed(U.manager, 'manager'), listed(U.owner, 'manager', F)] })] });
  const res = await apply(s.deps);
  assert.deepEqual(res.waiting.map((i) => i.id), [AP]);
  assert.deepEqual(res.fanOut.items, []);
  assert.equal(s.server.records.length, 0);
});

test('apply reports a pending item the caller cannot sign as waiting on its owner, a stub too, and writes nothing', async () => {
  const s = await scene({ who: 'owner', items: [folderOf(), itemOfP()] });
  const res = await apply(s.deps);
  assert.deepEqual(res.fanOut.items, []);
  assert.deepEqual(res.waiting.map((i) => [i.id, i.kind, i.state, i.owner, i.ownerEmail]), [[AP, 'artifact', 'waits', U.other.id, 'other@example.com']]);
  assert.equal(s.server.records.length, 0);
  assert.equal(applyNote(res, (e) => e.message), `1 of 1 items up to date.`.replace('1 of 1 items up to date.', `0 of 1 items up to date. 1 item waits on its owner, who applies it: ${AP} (other@example.com).`));
});

test('apply names the owner by ID when the directory does not hold them', async () => {
  const s = await scene({ who: 'owner', items: [folderOf(), itemOfP()] });
  s.server.primary.directory.delete(U.other.id);
  const res = await apply(s.deps);
  assert.deepEqual(res.waiting.map((i) => [i.owner, i.ownerEmail]), [[U.other.id, '']]);
  assert.match(applyNote(res, (e) => e.message), new RegExp(`${AP} \\(${U.other.id}\\)`));
});

test('apply visits an item inside a folder it wrote, because the folder\'s record says more now', async () => {
  const X = U.outsider;
  const items = [
    { id: F, kind: 'folder', members: [listed(U.other, 'editor'), listed(X, 'viewer')] },
    { id: F2, kind: 'folder', parent: F, owner: U.other },
    { id: AP, parent: F2, owner: U.other },
  ];
  const s = await scene({ items });
  assert.equal(s.server.inheritOf(AP), 'ok', 'the item matches its folder\'s record as it stands');
  assert.equal(s.server.inheritOf(F2), 'pending');
  const res = await apply(s.deps);
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[F2, 'updated'], [AP, 'updated']]);
  for (const id of [F2, AP]) {
    assert.equal(entry(s, id, X).via, F, id);
    assert.equal(entry(s, id, U.owner).via, F, id);
  }
  assert.equal(s.server.inheritOf(AP), 'ok');
});

test('apply does not visit an item below a folder it did not write', async () => {
  const items = [
    { id: F, kind: 'folder', members: [listed(U.other, 'editor')] },
    { id: F2, kind: 'folder', parent: F, owner: U.other, members: [listed(U.owner, 'manager', F)] },
    { id: AP, parent: F2, owner: U.other, members: [listed(U.owner, 'manager', F)] },
  ];
  const s = await scene({ items });
  const res = await apply(s.deps);
  assert.deepEqual(res.fanOut.items, []);
  assert.equal(s.server.records.length, 0);
  assert.equal(viewsOf(s, AP), 0, 'its view was not even read');
  assert.equal(viewsOf(s, F2), 0);
});

test('apply visits an item inside a folder it wrote at a next epoch too', async () => {
  const items = [
    { id: F, kind: 'folder', members: [listed(U.other, 'editor')] },
    // F2 lists a group through F that F no longer lists, which ends at a next epoch.
    { id: F2, kind: 'folder', parent: F, owner: U.other, groups: [{ group: GROUP, role: 'viewer', via: F }] },
    { id: AP, parent: F2, owner: U.other, members: [listed(U.owner, 'manager', F)] },
  ];
  const s = await scene({ items });
  assert.equal(s.server.inheritOf(AP), 'ok');
  const res = await apply(s.deps);
  assert.equal(stateOf(res, F2).state, 'newEpoch');
  assert.equal(viewsOf(s, AP), 1, 'the item below a folder written at a next epoch is visited');
});

test('apply records an item that fails and carries on, and counts it', async () => {
  const bad = folderOf({ members: [listed(U.other, 'editor'), { user: U.viewer, role: 'viewer', fp: 'ab'.repeat(32) }] });
  const s = await scene({ items: [bad, itemOfP(), { id: A2, parent: F, owner: U.other, members: [listed(U.owner, 'manager', F), listed(U.viewer, 'viewer', F)] }] });
  const res = await apply(s.deps);
  const failed = stateOf(res, AP);
  assert.equal(failed.state, 'failed');
  assert.equal(failed.error.code, 'member-key-changed');
  assert.equal(res.fanOut.failed, 1);
  assert.match(applyNote(res, (e) => e.message), /1 item could not be brought up to date: .*Choose Finish sharing to try again\./);
});

test('apply approves the newcomers of a group an item lists whose checks pass, and leaves the others waiting with the reason', async () => {
  const items = [
    folderOf({ groups: [{ group: GROUP, role: 'viewer' }] }),
    itemOfP({ members: [listed(U.owner, 'manager', F), listed(U.viewer, 'viewer', F)], groups: [{ group: GROUP, role: 'viewer', via: F }] }),
  ];
  const s = await scene({ items, users: [U.outsider, U.other, U.manager, U.editor, U.viewer] });
  await seedGroup(s.server.primary, { id: GROUP, name: 'Design', members: [{ user: U.outsider }, { user: U.editor, fp: 'cd'.repeat(32) }] });
  const res = await apply(s.deps);
  assert.deepEqual(res.fanOut.items, []);
  const ap = res.approvals.find((a) => a.id === AP);
  assert.deepEqual(ap.approved.map((u) => u.id), [U.outsider.id]);
  assert.equal(ap.pending.length, 1);
  assert.equal(ap.pending[0].user.id, U.editor.id);
  assert.ok(ap.pending[0].error instanceof GroupKeyChangedError);
  assert.deepEqual(s.server.kids.get(AP).approves.map((a) => a.user), [U.outsider.id]);
  assert.ok(res.approvals.some((a) => a.id === F), 'an editor of the folder approves there too');
  const note = applyNote(res, (e) => e.message);
  assert.match(note, /Approved .*outsider@example.com on /);
  assert.match(note, /still waiting for approval: editor@example.com on /);
  // Nothing more to do the second time, but the one left waiting.
  const again = await apply(s.deps);
  assert.deepEqual(again.approvals.find((a) => a.id === AP).approved, []);
});

test('apply never reads a stub', async () => {
  const s = await scene({ who: 'owner', items: [folderOf(), itemOfP()] });
  await apply(s.deps);
  assert.ok(!s.server.calls.some((c) => c.path.includes(`/api/artifacts/${AP}/`)), 'nothing of the stub was fetched');
});

test('apply skips, without a word, an item whose chain does not verify and a group that does not, and carries on', async () => {
  const items = [
    folderOf({ members: [listed(U.other, 'editor')] }),
    itemOfP({ members: [listed(U.owner, 'manager', F)] }),
    { id: A2, parent: null, owner: U.other, groups: [{ group: GROUP, role: 'viewer' }] },
  ];
  const s = await scene({ items });
  // The group does not exist on the server, and the first item's chain cannot be fetched.
  const broken = { ...s.deps, fetch: async (path, init) => (path.startsWith(`/api/artifacts/${AP}/membership`) ? new Response('{"error":"down"}', { status: 500 }) : s.deps.fetch(path, init)) };
  const res = await apply(broken);
  assert.deepEqual(res.approvals, []);
  assert.deepEqual(res.fanOut, { items: [], total: 0, failed: 0 });
});

test('apply ends with the failure that ends the command, and the result so far, whether it meets it on an item or on a group', async () => {
  const fail401 = (hit) => async (path, init) => (hit(path) ? new Response(`{"error":"unauthorized"}`, { status: 401 }) : fetch401base(path, init));
  let fetch401base;
  const onItem = await scene({ items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP(), { id: A2, parent: F, owner: U.other, members: [listed(U.owner, 'manager', F)] }] });
  fetch401base = onItem.deps.fetch;
  await assert.rejects(apply({ ...onItem.deps, fetch: fail401((path) => path === `/api/artifacts/${AP}`) }), (e) => e.status === 401 && Array.isArray(e.result.fanOut.items));
  const items = [folderOf({ members: [listed(U.other, 'editor')], groups: [{ group: GROUP, role: 'viewer' }] }), itemOfP({ members: [listed(U.owner, 'manager', F)], groups: [{ group: GROUP, role: 'viewer', via: F }] })];
  const onGroup = await scene({ items });
  await seedGroup(onGroup.server.primary, { id: GROUP, name: 'Design', members: [{ user: U.outsider }] });
  fetch401base = onGroup.deps.fetch;
  await assert.rejects(apply({ ...onGroup.deps, fetch: fail401((path) => path.startsWith(`/api/groups/${GROUP}`)) }), (e) => e.status === 401 && e.result.waiting.length === 0);
});

test('a fan-out that is not apply does not rewrite an item at the top level whose record names a folder: its placement is refused', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP({ parent: null, folder: F, members: [listed(U.owner, 'manager', F)] })] });
  const res = await fanOut(s.deps, AP, { includeRoot: true });
  assert.deepEqual(res.items.map((i) => [i.id, i.state, i.error?.code]), [[AP, 'failed', 'placement']]);
  assert.equal(s.server.records.length, 0);
});

test('applyNote says nothing is waiting when nothing is', () => {
  assert.equal(applyNote({ fanOut: { items: [], total: 0, failed: 0 }, waiting: [], approvals: [] }, (e) => e.message), 'Nothing was waiting to be applied.');
});

// ---- fanOut and the note ----

test('sharing a folder leaves an item someone else owns pending on its owner, and says so, then its owner applies it', async () => {
  const s = await scene({ who: 'owner', items: [folderOf({ members: [listed(U.other, 'editor')] }), { id: AO, parent: F, owner: U.owner }, itemOfP()] });
  const res = await share(s.deps, F, 'viewer@example.com', 'viewer');
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[AP, 'waits'], [AO, 'updated']]);
  assert.equal(res.fanOut.failed, 0, 'waiting is not a failure');
  const waiting = res.fanOut.items.find((i) => i.id === AP);
  assert.deepEqual([waiting.owner, waiting.ownerEmail], [U.other.id, 'other@example.com']);
  assert.equal(entry(s, AP, U.viewer), undefined, 'no record was written for it');
  assert.equal(latest(s, AO).members.some((m) => m.user === U.viewer.id), true);
  const note = fanOutNote(res, (e) => e.message);
  assert.equal(note, ` 1 of 2 items up to date. 1 item waits on its owner, who applies it: ${AP} (other@example.com).`);
  // Its owner applies the share, and the viewer is listed on it.
  const done = await apply(s.as('other'));
  assert.deepEqual(done.fanOut.items.map((i) => [i.id, i.state]), [[AP, 'updated']]);
  assert.equal(entry(s, AP, U.viewer).via, F);
});

test('the folder owner shares the folder: the item lists her as a manager, so she signs it herself with the newcomer added via the folder, and it does not wait', async () => {
  const s = await scene({ who: 'owner', items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP({ members: [listed(U.owner, 'manager', F)] })] });
  const res = await share(s.deps, F, 'outsider@example.com', 'viewer');
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[AP, 'updated']]);
  assert.equal(res.fanOut.failed, 0);
  assert.deepEqual(entry(s, AP, U.outsider), { user: U.outsider.id, role: 'viewer', fp: U.outsider.fp, via: F });
  assert.equal(latest(s, AP).v, 2, 'she signs as a manager');
  assert.equal(s.server.inheritOf(AP), 'ok');
  assert.deepEqual((await apply(s.deps)).waiting, []);
  s.as('outsider');
  assert.equal(s.server.levelOf(AP), 'viewer', 'the newcomer reads it');
  assert.equal(fanOutNote(res, (e) => e.message), ' 1 of 1 items up to date.');
});

test('the folder owner lists a manager on the folder: that changes the item\'s managers, which only its owner signs, so the item stays pending and apply says it waits on its owner', async () => {
  const s = await scene({ who: 'owner', items: [folderOf({ members: [listed(U.other, 'editor')] }), itemOfP({ members: [listed(U.owner, 'manager', F)] })] });
  const res = await share(s.deps, F, 'outsider@example.com', 'manager');
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state, i.error?.code]), [[AP, 'waits', undefined]]);
  assert.equal(res.fanOut.failed, 0);
  assert.equal(fanOutNote(res, (e) => e.message), ` 0 of 1 items up to date. 1 item waits on its owner, who applies it: ${AP} (other@example.com).`);
  assert.equal(entry(s, AP, U.outsider), undefined, 'no record was written for it');
  assert.equal(s.server.inheritOf(AP), 'pending');
  const waits = await apply(s.deps);
  assert.deepEqual(waits.waiting.map((i) => [i.id, i.state, i.ownerEmail]), [[AP, 'waits', 'other@example.com']]);
  // Its owner signs it.
  const done = await apply(s.as('other'));
  assert.deepEqual(done.fanOut.items.map((i) => [i.id, i.state]), [[AP, 'updated']]);
  assert.deepEqual(entry(s, AP, U.outsider), { user: U.outsider.id, role: 'manager', fp: U.outsider.fp, via: F });
  assert.equal(s.server.inheritOf(AP), 'ok');
});

test('a fan-out in which the walk meets a stub does not read it, and the walk does not go into a folder that waits', async () => {
  const items = [
    folderOf({ members: [listed(U.other, 'editor')] }),
    { id: F2, kind: 'folder', parent: F, owner: U.other },
    { id: AP, parent: F2, owner: U.other },
  ];
  const s = await scene({ who: 'owner', items });
  const res = await fanOut(s.deps, F);
  assert.deepEqual(res.items.map((i) => [i.id, i.state]), [[F2, 'waits']]);
  assert.ok(!s.server.calls.some((c) => c.path.includes(F2) && c.path !== '/api/artifacts'), 'the stub folder was not read');
});

test('fanOutNote names the items that wait on their owners and those that need a move, and counts neither as up to date or as failures', () => {
  const describe = (e) => e.message;
  const base = { error: null, skippedUsers: [], skippedGroups: [], pending: [] };
  const item = (extra) => ({ ...base, ...extra });
  const res = {
    fanOut: {
      total: 5,
      failed: 0,
      items: [
        item({ id: 'ok', state: 'updated' }),
        item({ id: 'w1', state: 'waits', owner: 'u1', ownerEmail: 'ann@example.com' }),
        item({ id: 'w2', state: 'waits', owner: 'u2', ownerEmail: '' }),
        item({ id: 'm1', state: 'needsMove', error: new Error('move m1 to F') }),
        item({ id: 'ok2', state: 'current' }),
      ],
    },
  };
  assert.equal(fanOutNote(res, describe), ' 2 of 5 items up to date. 2 items wait on their owners, who apply them: w1 (ann@example.com); w2 (u2). 1 item needs a move first: m1 (move m1 to F).');
  const two = { fanOut: { total: 2, failed: 0, items: [item({ id: 'm1', state: 'needsMove', error: new Error('a') }), item({ id: 'm2', state: 'needsMove', error: new Error('b') })] } };
  assert.equal(fanOutNote(two, describe), ' 0 of 2 items up to date. 2 items need a move first: m1 (a); m2 (b).');
});

// ---- placing an own item in someone else's folder ----

const sender = (s) => async (method, path, body) => {
  const resp = await s.server.fetch(path, { method, body: JSON.stringify(body) });
  if (!resp.ok) throw Object.assign(new Error(`${resp.status}`), { status: resp.status });
  return resp.status === 204 ? {} : resp.json();
};
const itemsOf = async (s) => splitTrees(await list(s), s.server.who.id);
const allOf = async (s) => { const t = await itemsOf(s); return [...t.own, ...t.shared]; };

test('an editor of a folder someone else owns places their own item in it, and it lists the folder\'s entries and its owner', async () => {
  const s = await scene({ items: [folderOf(), { id: AP, parent: null, owner: U.other }] });
  const res = await moveAndPlace(s.deps, sender(s), await allOf(s), AP, F);
  assert.deepEqual(res.items.map((i) => [i.id, i.state]), [[AP, 'updated']]);
  assert.equal(latest(s, AP).folder, F);
  assert.equal(entry(s, AP, U.viewer).via, F);
  assert.deepEqual(entry(s, AP, U.owner), { user: U.owner.id, role: 'manager', fp: U.owner.fp, via: F });
  assert.equal(s.server.kids.get(AP).parent, F);
  assert.equal(s.server.inheritOf(AP), 'ok');
  // The placement adds a manager, which only the owner signs, and the owner did.
  assert.equal(latest(s, AP).v, 1, 'the owner signs it as the owner');
  s.as('owner');
  assert.equal((await list(s)).find((a) => a.id === AP).access, 'manager', 'the folder\'s owner manages it');
});

test('a viewer of the folder cannot place an item in it, and a stranger is told the folder does not exist', async () => {
  const view = await scene({ items: [folderOf({ members: [listed(U.other, 'viewer')] }), { id: AP, parent: null, owner: U.other }] });
  await assert.rejects(moveAndPlace(view.deps, sender(view), await allOf(view), AP, F), /FolderError|editor access/);
  const direct = await view.server.fetch(`/api/artifacts/${AP}/parent`, { method: 'PUT', body: JSON.stringify({ parent: F }) });
  assert.equal(direct.status, 403, 'and the server refuses it too');
  const stranger = await scene({ items: [folderOf({ members: [] }), { id: AP, parent: null, owner: U.other }] });
  const resp = await stranger.server.fetch(`/api/artifacts/${AP}/parent`, { method: 'PUT', body: JSON.stringify({ parent: F }) });
  assert.equal(resp.status, 404);
  assert.equal(stranger.server.kids.get(AP).parent, null);
});

test('an editor who is not the item\'s owner cannot place it, but the server takes the owner\'s own move out and in', async () => {
  const s = await scene({ who: 'editor', items: [folderOf({ members: [listed(U.editor, 'editor')] }), itemOfP({ members: [listed(U.editor, 'editor')] })] });
  const resp = await s.server.fetch(`/api/artifacts/${AP}/parent`, { method: 'PUT', body: JSON.stringify({ parent: null }) });
  assert.equal(resp.status, 200, 'an editor of the folder may take it out');
  const back = await s.server.fetch(`/api/artifacts/${AP}/parent`, { method: 'PUT', body: JSON.stringify({ parent: F }) });
  assert.equal(back.status, 403, 'but only its owner or a manager places it');
});

test('a folder created in a folder someone else owns is the editor\'s, and belongs to them', async () => {
  const s = await scene({ items: [folderOf()] });
  const { id } = await createFolder(s.deps, { name: 'Mine', parent: F });
  assert.equal(s.server.kids.get(id).parent, F);
  const [view] = (await list(s)).filter((a) => a.id === id);
  assert.deepEqual([view.owner, view.access, view.parent], [U.other.id, 'owner', F]);
  await openArtifact(s.deps, { artifact: id, link: null });
});

// ---- removing someone else's item ----

test('an editor of a folder removes someone else\'s item, which goes to its owner\'s top level, and nothing is written to its record', async () => {
  const s = await scene({ who: 'editor', items: [folderOf({ members: [listed(U.editor, 'editor')] }), itemOfP({ members: [listed(U.editor, 'editor', F), listed(U.owner, 'manager', F)] })] });
  const items = await allOf(s);
  await removeFromFolder(sender(s), items, AP, U.editor.id);
  assert.equal(s.server.kids.get(AP).parent, null);
  assert.deepEqual(s.server.moves.map((m) => [m.id, m.target, m.by]), [[AP, null, U.editor.id]]);
  assert.equal(s.server.records.length, 0);
  assert.equal(s.server.inheritOf(AP), 'pending', 'its record still names the folder');
  // The owner of the item applies: the record names no folder, and the entries that came from the folder go.
  const res = await apply(s.as('other'));
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[AP, 'newEpoch']]);
  assert.equal(latest(s, AP).folder, undefined);
  assert.deepEqual(latest(s, AP).members, []);
  assert.equal(s.server.inheritOf(AP), 'ok');
});

test('a viewer of the folder cannot remove an item, and the owner of the folder may remove another\'s', async () => {
  const s = await scene({ who: 'viewer', items: [folderOf(), itemOfP({ members: [listed(U.viewer, 'viewer', F), listed(U.owner, 'manager', F)] })] });
  const resp = await s.server.fetch(`/api/artifacts/${AP}/parent`, { method: 'PUT', body: JSON.stringify({ parent: null }) });
  assert.equal(resp.status, 403);
  assert.equal(s.server.kids.get(AP).parent, F);
  s.as('owner');
  const ok = await s.server.fetch(`/api/artifacts/${AP}/parent`, { method: 'PUT', body: JSON.stringify({ parent: null }) });
  assert.equal(ok.status, 200);
  assert.equal(s.server.kids.get(AP).parent, null);
});

test('a folder\'s editor who removes an item they read only through the folder is answered with its stub', async () => {
  const s = await scene({ who: 'editor', items: [folderOf({ members: [listed(U.editor, 'editor')] }), itemOfP({ members: [listed(U.editor, 'editor', F)] })] });
  const resp = await s.server.fetch(`/api/artifacts/${AP}/parent`, { method: 'PUT', body: JSON.stringify({ parent: null }) });
  assert.equal(resp.status, 200);
  assert.equal((await resp.json()).access, 'none');
});

test('the owner of an item takes it out of a folder they no longer edit, so they can always clear a pending item', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.viewer, 'viewer')] }), itemOfP()] });
  assert.equal(s.server.levelOf(F), '', 'they no longer read the folder');
  const res = await moveAndPlace(s.deps, sender(s), await allOf(s), AP, null);
  assert.deepEqual(res.items.map((i) => [i.id, i.state]), [[AP, 'updated']]);
  assert.equal(s.server.kids.get(AP).parent, null);
  assert.equal(latest(s, AP).folder, undefined);
  assert.equal(s.server.inheritOf(AP), 'ok');
});

// ---- deleting a folder that holds other people's items ----

test('deleting a folder deletes the owner\'s own items first, then the folder, and the server moves what others own to their top level', async () => {
  const items = [
    folderOf({ members: [listed(U.other, 'editor')] }),
    { id: AO, parent: F, owner: U.owner },
    itemOfP({ members: [listed(U.owner, 'manager', F)] }),
    { id: F2, kind: 'folder', parent: F, owner: U.owner },
    { id: A2, parent: F2, owner: U.owner },
  ];
  const s = await scene({ who: 'owner', items });
  const send = sender(s);
  const all = (await itemsOf(s)).own;
  const order = [];
  const progress = [];
  const n = await deleteTree(async (id) => { order.push(id); await send('DELETE', `/api/artifacts/${id}`); }, all, F, (d, t) => progress.push([d, t]));
  assert.deepEqual(order, [A2, AO, F2, F]);
  assert.equal(n, 4);
  assert.deepEqual(progress, [[1, 4], [2, 4], [3, 4], [4, 4]]);
  assert.deepEqual(s.server.deleted, [A2, AO, F2, F]);
  assert.equal(s.server.kids.get(AP).parent, null, 'P\'s item is at P\'s top level');
  assert.equal(s.server.kids.has(F), false);
  s.as('other');
  assert.equal((await list(s)).find((a) => a.id === AP).parent, null);
});

test('the server refuses to delete a folder while an item its owner owns is inside, and deletes it once only others\' items are', async () => {
  const s = await scene({ who: 'owner', items: [folderOf({ members: [listed(U.other, 'editor')] }), { id: AO, parent: F, owner: U.owner }, itemOfP()] });
  const refused = await s.server.fetch(`/api/artifacts/${F}`, { method: 'DELETE' });
  assert.equal(refused.status, 409);
  await s.server.fetch(`/api/artifacts/${AO}`, { method: 'DELETE' });
  const ok = await s.server.fetch(`/api/artifacts/${F}`, { method: 'DELETE' });
  assert.equal(ok.status, 204);
  assert.equal(s.server.kids.get(AP).parent, null);
  // Only the owner deletes.
  const t = await scene({ who: 'other', items: [folderOf(), itemOfP()] });
  assert.equal((await t.server.fetch(`/api/artifacts/${F}`, { method: 'DELETE' })).status, 403);
});

test('a folder someone else owns, inside the deleted one, moves with what is inside it, and is not deleted', async () => {
  const items = [
    folderOf({ members: [listed(U.other, 'editor')] }),
    { id: F2, kind: 'folder', parent: F, owner: U.other, members: [listed(U.owner, 'manager', F)] },
    { id: AO, parent: F2, owner: U.owner, members: [listed(U.other, 'editor', F)] },
  ];
  const s = await scene({ who: 'owner', items });
  const order = [];
  const send = sender(s);
  await deleteTree(async (id) => { order.push(id); await send('DELETE', `/api/artifacts/${id}`); }, (await itemsOf(s)).own, F, () => {});
  assert.deepEqual(order, [F], 'the owner\'s item inside the other folder goes with it');
  assert.equal(s.server.kids.get(F2).parent, null);
  assert.equal(s.server.kids.get(AO).parent, F2);
});

test('the server refuses a folder created inside one the caller cannot read, or may only read', async () => {
  const s = await scene({ who: 'outsider', items: [folderOf()] });
  await assert.rejects(createFolder(s.deps, { name: 'Mine', parent: F }), (e) => e.status === 404);
  const viewer = s.as('viewer');
  await assert.rejects(createFolder(viewer, { name: 'Mine', parent: F }), (e) => e.status === 403);
  assert.deepEqual(s.server.posts, []);
});

test('apply signs nothing for an item in a folder its owner cannot read, and says how to take it out', async () => {
  const s = await scene({ items: [folderOf({ members: [listed(U.viewer, 'viewer')] }), itemOfP({ folder: F })] });
  assert.equal(s.server.inheritOf(AP), 'pending');
  const view = await (await s.server.fetch(`/api/artifacts/${AP}`)).json();
  assert.equal(view.parent, null);
  assert.equal(view.hiddenParent, true);
  const res = await apply(s.deps);
  const item = stateOf(res, AP);
  assert.equal(item.state, 'needsMove');
  assert.match(item.error.message, /folder you can no longer read.*Remove from folder.*cairn move f0000000-0000-4000-8000-0000000000a1 --top/);
  assert.equal(item.error.code, 'placement');
  assert.equal(res.fanOut.failed, 0, 'not a failure');
  assert.equal(s.server.records.length, 0, 'nothing was written');
  assert.equal(s.server.inheritOf(AP), 'pending');
});
