// Tests for shared folders in sharing.mjs and folders.mjs: sharing or
// unsharing a folder and fanning out to the items inside it, resuming an
// interrupted fan-out, finishing a pending item, the entries a new item lists
// inside a shared folder, and how the share dialog reads an inherited entry. They
// run against real chains, wraps, estate copies, versions and keyrings behind
// folder_fixture.mjs, a tree of items each served as sharing_fixture.mjs
// serves one, whose router refuses a record that leaves out an entry its folder
// lists or marks one falsely, as the server does. They mirror folder_share_test.go
// in internal/client. Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { V1, makeUser } from './viewer_fixture.mjs';
import { depsFor, extraUser, keyStoreRecord, seedGroup, seedMeta, seedVersion } from './sharing_fixture.mjs';
import { makeFolderServer } from './folder_fixture.mjs';
import { createFolder, moveAndPlace } from './folders.mjs';
import { SharingError, fanOut, memberControls, members, offersFinishSharing, planInherit, setPublic, setTeam, share, shareGroup, subtreeOrder, unshare, unshareGroup } from './sharing.mjs';
import { openArtifact } from './viewer.mjs';

const U = {};
for (const name of ['owner', 'editor', 'viewer', 'outsider']) U[name] = await makeUser(name);
U.other = await extraUser('other', '88888888-8888-4888-8888-888888888888');
U.manager = await extraUser('manager', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
const records = {};
for (const name of Object.keys(U)) records[name] = await keyStoreRecord(U[name]);

// The tree: F holds G and A1, G holds A2, and TOP is at the top level.
const F = 'f0000000-0000-4000-8000-000000000001';
const G = 'f0000000-0000-4000-8000-000000000002';
const A1 = 'f0000000-0000-4000-8000-000000000003';
const A2 = 'f0000000-0000-4000-8000-000000000004';
const TOP = 'f0000000-0000-4000-8000-000000000005';
const GROUP = 'b1b1b1b1-1111-4111-8111-111111111111';

// tree is the items of the tree, each with the members (and so on) in spec,
// by ID, as buildWorld takes them.
function tree(spec = {}) {
  const item = (id, kind, parent) => ({ id, kind, parent, owner: U.owner, ...spec[id] });
  return [item(F, 'folder', null), item(G, 'folder', F), item(A1, 'artifact', F), item(A2, 'artifact', G), item(TOP, 'artifact', null)];
}

async function scene({ who = 'owner', spec = {}, extra = [], users = [U.outsider, U.other, U.manager, U.editor, U.viewer] } = {}) {
  const server = await makeFolderServer({ who: U[who], users, items: [...tree(spec), ...extra] });
  return { server, deps: depsFor(server, records[who]) };
}

const latest = (s, id) => s.server.latestOf(id);
const bodyOf = (env) => JSON.parse(new TextDecoder().decode(e2e.unb64(env.body)));
const entry = (s, id, user) => latest(s, id).members.find((m) => m.user === user.id);
const wrote = (s) => s.server.records.map((r) => r.id);

async function unwrapFor(name, id, w) {
  const ctx = { purpose: 'ak', artifact: id, epoch: w.epoch, recipientId: U[name].id, recipientPub: U[name].x.pub };
  return e2e.unwrap(records[name].x25519, ctx, e2e.unb64(w.wrapped));
}

// ---- sharing a folder ----

test('sharing a folder lists the user on every item inside it, marked with the folder, and wraps every epoch to them', async () => {
  const s = await scene({ spec: { [A1]: { epoch2: true }, [A2]: { epoch2: true } } });
  const calls = [];
  const res = await share(s.deps, F, 'outsider@example.com', 'viewer', { progress: (done, total) => calls.push([done, total]) });
  // The folder first, then each folder before the items inside it.
  assert.deepEqual(wrote(s), [F, G, A2, A1]);
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[G, 'updated'], [A2, 'updated'], [A1, 'updated']]);
  assert.equal(res.fanOut.failed, 0);
  assert.deepEqual(calls, [[1, 3], [2, 3], [3, 3]]);
  assert.deepEqual(entry(s, F, U.outsider), { user: U.outsider.id, role: 'viewer', fp: U.outsider.fp });
  for (const id of [G, A1, A2]) assert.deepEqual(entry(s, id, U.outsider), { user: U.outsider.id, role: 'viewer', fp: U.outsider.fp, via: F }, id);
  // A new member holds a wrap of every epoch, each opening to the item's AK.
  for (const [id, epochs] of [[G, [1]], [A1, [1, 2]], [A2, [1, 2]]]) {
    const put = s.server.records.find((r) => r.id === id).put;
    assert.deepEqual(put.wraps.map((w) => [w.user, w.epoch]), epochs.map((e) => [U.outsider.id, e]), id);
    const kid = s.server.kids.get(id);
    for (const w of put.wraps) assert.deepEqual(await unwrapFor('outsider', id, w), kid.world.aks[w.epoch]);
  }
  assert.equal(s.server.inheritOf(A1), 'ok');
  assert.equal(s.server.inheritOf(A2), 'ok');
  assert.equal(s.server.inheritOf(TOP), 'ok');
  assert.equal(latest(s, TOP).members.length, 0, 'an item outside the folder is left alone');
});

test('a user an item lists through a folder that holds it by inheritance is marked with the folder that lists them themselves', async () => {
  const s = await scene();
  await share(s.deps, G, 'outsider@example.com', 'viewer');
  assert.equal(entry(s, A2, U.outsider).via, G);
  await share(s.deps, F, 'viewer@example.com', 'viewer');
  assert.equal(entry(s, G, U.viewer).via, F);
  assert.equal(entry(s, A2, U.viewer).via, F, 'G holds the entry by inheritance, so the mark names F');
  assert.equal(entry(s, A2, U.outsider).via, G, 'an entry already marked keeps its folder');
});

test('a direct grant keeps no mark and the higher of its role and the folder', async () => {
  const s = await scene({
    spec: {
      [G]: { members: [{ user: U.editor, role: 'viewer' }] },
      [A2]: { members: [{ user: U.editor, role: 'viewer', via: G }, { user: U.viewer, role: 'editor' }] },
    },
  });
  await share(s.deps, F, 'editor@example.com', 'editor');
  assert.deepEqual(entry(s, G, U.editor), { user: U.editor.id, role: 'editor', fp: U.editor.fp }, 'a direct grant is raised and stays direct');
  assert.deepEqual(entry(s, A2, U.editor), { user: U.editor.id, role: 'editor', fp: U.editor.fp, via: G }, 'G lists them itself, so the entry names G');
  assert.equal(entry(s, A1, U.editor).via, F);
  // A direct editor stays an editor under a folder that lists them as a viewer.
  await share(s.deps, F, 'viewer@example.com', 'viewer');
  assert.deepEqual(entry(s, A2, U.viewer), { user: U.viewer.id, role: 'editor', fp: U.viewer.fp });
  assert.equal(s.server.inheritOf(A2), 'ok');
});

test('sharing with a role an inherited entry already has makes it a direct grant, and removing it is refused', async () => {
  const s = await scene({ spec: { [F]: { members: [{ user: U.viewer, role: 'viewer' }] }, [A1]: { members: [{ user: U.viewer, role: 'viewer', via: F }] } } });
  await assert.rejects(unshare(s.deps, A1, 'viewer@example.com'), (e) => e.code === 'inherited');
  assert.equal(s.server.records.length, 0);
  // Asking for less than the folder gives keeps the folder's role.
  const res = await share(s.deps, A1, 'viewer@example.com', 'viewer');
  assert.equal(res.unchanged, false);
  assert.deepEqual(entry(s, A1, U.viewer), { user: U.viewer.id, role: 'viewer', fp: U.viewer.fp });
});

test('a record for an item keeps the marks of its inherited entries', async () => {
  const s = await scene({ spec: { [F]: { members: [{ user: U.viewer, role: 'viewer' }] }, [A1]: { members: [{ user: U.viewer, role: 'viewer', via: F }] } } });
  await share(s.deps, A1, 'outsider@example.com', 'viewer');
  assert.equal(entry(s, A1, U.viewer).via, F);
  assert.equal(entry(s, A1, U.outsider).via, undefined);
});

// ---- unsharing a folder ----

test('unsharing a folder starts a new epoch on each item, excludes who held it only through the folder, and seals the content again', async () => {
  const via = (user, role = 'viewer') => ({ user, role, via: F });
  const s = await scene({
    spec: {
      [F]: { members: [{ user: U.viewer, role: 'viewer' }] },
      [G]: { members: [via(U.viewer)] },
      [A1]: { members: [via(U.viewer)] },
      [A2]: { members: [{ user: U.viewer, role: 'viewer' }] },
    },
  });
  const a1 = s.server.kids.get(A1);
  await seedVersion(a1, { id: V1, files: { 'index.html': '<p>one</p>' } });
  await seedMeta(a1, { field: 'name', value: 'Plans' });
  const res = await unshare(s.deps, F, 'viewer@example.com');
  assert.equal(res.epoch, 2);
  assert.deepEqual(wrote(s), [F, G, A1]);
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[G, 'newEpoch'], [A2, 'current'], [A1, 'newEpoch']]);
  for (const id of [F, G, A1]) {
    const body = latest(s, id);
    assert.equal(body.epoch, 2, id);
    assert.deepEqual(body.members, [], id);
    assert.deepEqual(body.excluded.map((x) => x.user), [U.viewer.id], id);
  }
  assert.deepEqual(res.fanOut.items[0].excluded.map((x) => x.user.id), [U.viewer.id]);
  // The content is sealed again under the new epoch: the version, and the name.
  assert.deepEqual(a1.puts.version.map((v) => v.version), [V1]);
  assert.equal(a1.puts.version[0].part.epoch, 2);
  assert.deepEqual(res.fanOut.items[2].reseal.resealed.sort(), [`the name of the artifact`, `version ${V1}`].sort());
  // A folder holds no versions, so none were asked for.
  assert.equal(s.server.kids.get(G).calls.some((c) => c.path.endsWith('/versions')), false);
  // A direct entry is not touched: the item's record never changed.
  assert.equal(latest(s, A2).epoch, 1);
  assert.equal(entry(s, A2, U.viewer).role, 'viewer');
});

test('lowering a user on a folder lowers the entry on each item in a new epoch', async () => {
  const s = await scene({
    spec: {
      [F]: { members: [{ user: U.editor, role: 'editor' }] },
      [G]: { members: [{ user: U.editor, role: 'editor', via: F }] },
      [A1]: { members: [{ user: U.editor, role: 'editor', via: F }] },
      [A2]: { members: [{ user: U.editor, role: 'editor', via: F }] },
    },
  });
  const res = await share(s.deps, F, 'editor@example.com', 'viewer');
  assert.equal(res.demoted, true);
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[G, 'newEpoch'], [A2, 'newEpoch'], [A1, 'newEpoch']]);
  for (const id of [G, A1, A2]) {
    assert.deepEqual(entry(s, id, U.editor), { user: U.editor.id, role: 'viewer', fp: U.editor.fp, via: F }, id);
    assert.equal(latest(s, id).epoch, 2, id);
    assert.equal(s.server.inheritOf(id), 'ok', id);
  }
});

test('raising a user on a folder raises the entry on each item in the same epoch', async () => {
  const s = await scene({
    spec: {
      [F]: { members: [{ user: U.editor, role: 'viewer' }] },
      [A1]: { members: [{ user: U.editor, role: 'viewer', via: F }] },
    },
  });
  await share(s.deps, F, 'editor@example.com', 'editor');
  assert.deepEqual(entry(s, A1, U.editor), { user: U.editor.id, role: 'editor', fp: U.editor.fp, via: F });
  assert.equal(latest(s, A1).epoch, 1);
});

// ---- resuming ----

test('an item that fails is reported, and running the fan-out again finishes it', async () => {
  const s = await scene();
  s.server.kids.get(A1).failPut = () => new Response(JSON.stringify({ error: 'boom' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  const res = await share(s.deps, F, 'outsider@example.com', 'viewer');
  assert.equal(res.fanOut.failed, 1);
  assert.deepEqual(res.fanOut.items.map((i) => [i.id, i.state]), [[G, 'updated'], [A2, 'updated'], [A1, 'failed']]);
  assert.match(res.fanOut.items[2].error.message, /boom/);
  assert.equal(s.server.inheritOf(A1), 'pending');
  assert.equal(s.server.inheritOf(G), 'ok');

  s.server.kids.get(A1).failPut = null;
  const done = [];
  const again = await fanOut(s.deps, F, { progress: (d, t) => done.push([d, t]) });
  assert.deepEqual(again.items.map((i) => [i.id, i.state]), [[G, 'current'], [A2, 'current'], [A1, 'updated']]);
  assert.equal(again.failed, 0);
  assert.deepEqual(done, [[1, 3], [2, 3], [3, 3]], 'items already up to date count as done');
  assert.deepEqual(wrote(s), [F, G, A2, A1], 'the items already done were not written again');
  assert.equal(s.server.inheritOf(A1), 'ok');
});

test('a manager signs the records of a fan-out, and cannot add a manager through it', async () => {
  const mgr = (via) => ({ members: [{ user: U.manager, role: 'manager', ...(via ? { via: F } : {}) }] });
  const s = await scene({ who: 'manager', spec: { [F]: mgr(false), [G]: mgr(true), [A1]: mgr(true), [A2]: mgr(true) } });
  await share(s.deps, F, 'viewer@example.com', 'viewer');
  assert.deepEqual(wrote(s), [F, G, A2, A1]);
  for (const id of [F, G, A1, A2]) assert.equal(latest(s, id).v, 2, 'a manager signs as one');
  assert.equal(entry(s, A1, U.viewer).via, F);
  // The owner lists a second manager on the folder; the manager's fan-out cannot add them.
  const t = await scene({
    who: 'manager',
    spec: { [F]: { members: [{ user: U.manager, role: 'manager' }, { user: U.other, role: 'manager' }] }, [G]: mgr(true), [A1]: mgr(true) },
  });
  const res = await fanOut(t.deps, F);
  assert.deepEqual(res.items.map((i) => [i.id, i.state, i.error?.code]), [[G, 'failed', 'owner-only'], [A1, 'failed', 'owner-only']], 'A2 is not in the manager\'s list');
  assert.equal(t.server.records.length, 0);
});

// ---- finishing a pending item ----

test('Finish sharing brings a pending item, and a pending folder with what is inside it, up to date', async () => {
  const s = await scene({ spec: { [F]: { members: [{ user: U.viewer, role: 'viewer' }] }, [G]: { members: [{ user: U.viewer, role: 'viewer', via: F }] } } });
  assert.equal(s.server.inheritOf(A1), 'pending');
  const one = await fanOut(s.deps, A1, { includeRoot: true });
  assert.deepEqual(one.items.map((i) => [i.id, i.state]), [[A1, 'updated']]);
  assert.equal(entry(s, A1, U.viewer).via, F);
  assert.equal(s.server.inheritOf(A2), 'pending');
  const folder = await fanOut(s.deps, G, { includeRoot: true });
  assert.deepEqual(folder.items.map((i) => [i.id, i.state]), [[G, 'current'], [A2, 'updated']]);
  assert.equal(s.server.inheritOf(A2), 'ok');
  // Nothing pending: nothing written.
  const before = s.server.records.length;
  const none = await fanOut(s.deps, F, { includeRoot: true });
  assert.ok(none.items.every((i) => i.state === 'current'));
  assert.equal(s.server.records.length, before);
  await assert.rejects(fanOut(s.deps, 'f0000000-0000-4000-8000-0000000000ff'), (e) => e.code === 'no-artifact');
});

test('a user a folder lists under another key than the directory serves is not listed on an item', async () => {
  const s = await scene({ spec: { [F]: { members: [{ user: U.viewer, role: 'viewer', fp: 'e'.repeat(64) }] } } });
  const res = await fanOut(s.deps, F);
  assert.deepEqual(res.items.map((i) => [i.id, i.state, i.error?.code]), [[G, 'failed', 'member-key-changed'], [A2, 'current', undefined], [A1, 'failed', 'member-key-changed']]);
  assert.equal(s.server.records.length, 0);
});

test('only a pending item is read: a lying inherit is the server\'s word, and a current item is not touched', async () => {
  const s = await scene();
  const res = await fanOut(s.deps, F);
  assert.deepEqual(res.items.map((i) => i.state), ['current', 'current', 'current']);
  assert.equal(s.server.kids.get(A1).calls.filter((c) => c.path.endsWith('/membership')).length, 0, 'its chain was not read');
});

// ---- groups ----

test('sharing a folder with a group lists it on each item and approves its members there', async () => {
  const s = await scene();
  await seedGroup(s.server.primary, { id: GROUP, name: 'Design', members: [{ user: U.outsider }] });
  const res = await shareGroup(s.deps, F, GROUP, 'viewer');
  assert.deepEqual(res.fanOut.items.map((i) => i.state), ['updated', 'updated', 'updated']);
  for (const id of [F, G, A1, A2]) assert.equal(latest(s, id).groups[0].role, 'viewer');
  assert.equal(latest(s, F).groups[0].via, undefined);
  for (const id of [G, A1, A2]) assert.equal(latest(s, id).groups[0].via, F, id);
  assert.deepEqual(res.fanOut.items[0].approved.map((u) => u.id), [U.outsider.id]);
  for (const id of [G, A1, A2]) assert.deepEqual(s.server.kids.get(id).approves.map((a) => a.user), [U.outsider.id], id);
  assert.equal(s.server.inheritOf(A1), 'ok');
  // The group's entry on an item is the folder's to remove.
  await assert.rejects(unshareGroup(s.deps, A1, GROUP), (e) => e.code === 'inherited');
  const out = await unshareGroup(s.deps, F, GROUP);
  assert.equal(out.fanOut.failed, 0);
  assert.deepEqual(latest(s, A1).groups ?? [], []);
});

test('a group shared directly keeps its role when the folder lists it lower, and a role below the folder\'s is not offered', async () => {
  const s = await scene({ spec: { [F]: { groups: [{ group: GROUP, role: 'editor' }] }, [A1]: { groups: [{ group: GROUP, role: 'editor', via: F }] } } });
  await seedGroup(s.server.primary, { id: GROUP, name: 'Design', members: [{ user: U.outsider }] });
  const res = await shareGroup(s.deps, A1, GROUP, 'viewer');
  assert.equal(res.role, 'viewer');
  assert.deepEqual(latest(s, A1).groups, [{ group: GROUP, role: 'editor' }]);
});

// ---- the rules of a folder ----

test('a folder keeps its team share at none and stays private', async () => {
  const s = await scene();
  await assert.rejects(setTeam(s.deps, F, 'viewer'), (e) => e.code === 'folder-private');
  await assert.rejects(setPublic(s.deps, F, true), (e) => e.code === 'folder-private');
  assert.equal(s.server.records.length, 0);
  // An item inside it is shared as any other.
  await setTeam(s.deps, A1, 'viewer');
  assert.equal(latest(s, A1).team, 'viewer');
});

// ---- creating inside a shared folder ----

test('a folder created inside a shared folder lists the folder\'s entries, marked, with a wrap of its key for each user', async () => {
  const s = await scene({
    spec: {
      [F]: { members: [{ user: U.viewer, role: 'viewer' }, { user: U.editor, role: 'editor' }] },
      [G]: { members: [{ user: U.viewer, role: 'viewer', via: F }, { user: U.editor, role: 'editor', via: F }, { user: U.outsider, role: 'viewer' }] },
    },
  });
  const { id } = await createFolder(s.deps, { name: 'Sub', parent: F });
  const post = s.server.posts[0];
  const body = latest(s, id);
  assert.deepEqual(body.members, [
    { user: U.editor.id, role: 'editor', fp: U.editor.fp, via: F },
    { user: U.viewer.id, role: 'viewer', fp: U.viewer.fp, via: F },
  ]);
  assert.deepEqual(post.wraps.map((w) => [w.user, w.epoch]), [[U.editor.id, 1], [U.viewer.id, 1]]);
  const kid = s.server.kids.get(id);
  const ak = await e2e.open(await e2e.ekSealCryptoKey(U.owner.ek), ['estate', id, '1'], e2e.unb64(post.estate[0].sealed));
  assert.equal(body.akCommit, await e2e.akCommit(ak, id, 1));
  for (const w of post.wraps) assert.deepEqual(await unwrapFor(w.user === U.editor.id ? 'editor' : 'viewer', id, w), ak);
  assert.equal(s.server.inheritOf(id), 'ok');
  assert.equal(body.folder, F, 'the first record names the folder the item sits in');
  // The name was written under the key the record commits to.
  assert.deepEqual(kid.puts.meta.map((m) => m.field), ['name']);
  // In G, an entry the folder holds by inheritance names the folder that lists it, and a direct one is listed too.
  const inner = await createFolder(s.deps, { name: 'Deep', parent: G });
  assert.deepEqual(latest(s, inner.id).members.map((m) => [m.user, m.role, m.via]), [
    [U.editor.id, 'editor', F],
    [U.viewer.id, 'viewer', F],
    [U.outsider.id, 'viewer', G],
  ]);
  assert.equal(latest(s, inner.id).folder, G);
  await openArtifact(s.deps, { artifact: inner.id, link: null });
});

test('a folder created at the top level, or inside a folder nobody shares, lists nobody', async () => {
  const s = await scene();
  const a = await createFolder(s.deps, { name: 'Top' });
  s.server.calls.length = 0;
  const b = await createFolder(s.deps, { name: 'Inside', parent: F });
  assert.equal(s.server.calls.some((c) => c.path === '/api/users'), false, 'nobody to wrap to, so the directory is not read');
  assert.deepEqual(latest(s, a.id).members, []);
  assert.deepEqual(latest(s, b.id).members, []);
  assert.equal(latest(s, a.id).folder, undefined, 'a folder at the top level names none');
  assert.equal(latest(s, b.id).folder, F, 'a folder nobody shares still names where it sits');
  assert.deepEqual(s.server.posts[1].wraps, []);
});

test('a folder inside a shared folder is not created with a user the folder lists under another key', async () => {
  const s = await scene({ spec: { [F]: { members: [{ user: U.viewer, role: 'viewer', fp: 'e'.repeat(64) }] } } });
  await assert.rejects(createFolder(s.deps, { name: 'Sub', parent: F }), (e) => e instanceof SharingError && e.code === 'member-key-changed');
  assert.equal(s.server.posts.length, 0);
});

// ---- reading the dialog ----

test('members names the folder an entry comes from, by its name when the caller can read it and by its ID otherwise', async () => {
  const ghost = 'f0000000-0000-4000-8000-0000000000aa';
  const s = await scene({
    spec: {
      [F]: { members: [{ user: U.viewer, role: 'viewer' }] },
      [A1]: { members: [{ user: U.viewer, role: 'viewer', via: F }, { user: U.editor, role: 'editor', via: ghost }, { user: U.outsider, role: 'viewer' }] },
    },
  });
  await seedMeta(s.server.kids.get(F), { field: 'name', value: 'Plans' });
  const res = await members(s.deps, A1);
  const rows = Object.fromEntries(res.members.filter((m) => m.role !== 'owner').map((m) => [m.user, m]));
  assert.equal(rows[U.viewer.id].via, F);
  assert.equal(rows[U.viewer.id].viaName, 'Plans');
  assert.equal(rows[U.editor.id].viaName, ghost);
  assert.equal('via' in rows[U.outsider.id], false);
  assert.equal('viaName' in rows[U.outsider.id], false);
});

test('members names the folder a group comes from', async () => {
  const s = await scene({ spec: { [F]: { groups: [{ group: GROUP, role: 'viewer' }] }, [A1]: { groups: [{ group: GROUP, role: 'viewer', via: F }] } } });
  await seedGroup(s.server.primary, { id: GROUP, name: 'Design', members: [] });
  await seedMeta(s.server.kids.get(F), { field: 'name', value: 'Plans' });
  const res = await members(s.deps, A1);
  assert.deepEqual(res.groups.map((g) => [g.id, g.via, g.viaName]), [[GROUP, F, 'Plans']]);
  assert.equal((await members(s.deps, F)).groups[0].via, undefined);
});

test('an inherited entry offers no role and no remove', () => {
  const direct = { role: 'viewer', account: 'member' };
  assert.deepEqual(memberControls('owner', direct), { roles: ['viewer', 'editor', 'manager'], removable: true });
  assert.deepEqual(memberControls('owner', { ...direct, via: F }), { roles: [], removable: false });
  assert.deepEqual(memberControls('manager', { ...direct, via: F }), { roles: [], removable: false });
});

test('Finish sharing is offered to the owner and a manager of a pending item, and to nobody else', () => {
  assert.equal(offersFinishSharing({ inherit: 'pending', access: 'owner' }), true);
  assert.equal(offersFinishSharing({ inherit: 'pending', access: 'manager' }), true);
  assert.equal(offersFinishSharing({ inherit: 'pending', access: 'editor' }), false);
  assert.equal(offersFinishSharing({ inherit: 'pending', access: 'viewer' }), false);
  assert.equal(offersFinishSharing({ inherit: 'ok', access: 'owner' }), false);
  assert.equal(offersFinishSharing({ access: 'owner' }), false);
});

// ---- the plan, against folder_share.go ----

// The state below is worked by hand from planInherit in
// internal/client/folder_share.go, line by line, as the Go function runs it.
// The folder P lists a1 as viewer, b as editor, c as viewer, d0 as manager
// through the folder above it (via ABOVE), the item's own owner, and the groups
// g1 and g0 as viewer. The item lists b as viewer through OLD, c as editor
// directly, e as viewer through P, and the group g2 through P.
//   members: b is listed with a via, so it follows the folder: editor, and the
//     mark the folder gives it, P, not OLD; the role went up, so no new epoch.
//     c is direct: the folder's viewer is not higher, so it stays editor with no
//     via. e has a via and the folder does not list it: it leaves, which takes a
//     new epoch. a1 and d0 are listed by the folder and not by the item: added,
//     a1 marked P, the folder that lists it itself, and d0 with the folder's own
//     mark, ABOVE, the nearest folder. The owner is skipped. The lists come out
//     sorted by ID.
//   groups: g2 has a via and the folder does not list it: it leaves. g0 and g1
//     are added, marked P, in ID order.
test('planInherit gives what folder_share.go gives for one state', () => {
  const parent = {
    members: [
      { user: 'd0', role: 'manager', fp: 'fd', via: 'ABOVE' },
      { user: 'c0', role: 'viewer', fp: 'fc' },
      { user: 'b0', role: 'editor', fp: 'fb' },
      { user: 'o0', role: 'viewer', fp: 'fo' },
      { user: 'a1', role: 'viewer', fp: 'fa' },
    ],
  };
  const item = {
    owner: 'o0',
    members: [
      { user: 'b0', role: 'viewer', fp: 'fb', via: 'OLD' },
      { user: 'c0', role: 'editor', fp: 'fc' },
      { user: 'e0', role: 'viewer', fp: 'fe', via: 'P' },
    ],
    groups: [{ group: 'g2', role: 'viewer', via: 'P' }],
  };
  const plan = planInherit(item, parent, 'P', [{ group: 'g1', role: 'viewer' }, { group: 'g0', role: 'viewer' }]);
  assert.deepEqual(plan, {
    members: [
      { user: 'a1', role: 'viewer', fp: 'fa', via: 'P' },
      { user: 'b0', role: 'editor', fp: 'fb', via: 'P' },
      { user: 'c0', role: 'editor', fp: 'fc' },
      { user: 'd0', role: 'manager', fp: 'fd', via: 'ABOVE' },
    ],
    groups: [{ group: 'g0', role: 'viewer', via: 'P' }, { group: 'g1', role: 'viewer', via: 'P' }],
    added: ['a1', 'd0'],
    addedGroups: ['g0', 'g1'],
    epoch: true,
  });
  // An item at the top level wants only its direct grants.
  const top = planInherit(item, null, '', []);
  assert.deepEqual(top.members, [{ user: 'c0', role: 'editor', fp: 'fc' }]);
  assert.equal(top.epoch, true);
  assert.deepEqual(top.added, []);
  // An item that already matches its folder needs nothing.
  const same = planInherit({ owner: 'o0', members: [{ user: 'b0', role: 'editor', fp: 'fb', via: 'P' }] }, { members: [{ user: 'b0', role: 'editor', fp: 'fb' }] }, 'P', []);
  assert.equal(same.epoch, false);
  assert.deepEqual(same.added, []);
});

test('a role on the folder below the item\'s entry starts a new epoch in the plan, and an equal or higher one does not', () => {
  const entry = (role) => ({ members: [{ user: 'u', role, fp: 'f', via: 'P' }], owner: 'o' });
  const folder = (role) => ({ members: [{ user: 'u', role, fp: 'f' }] });
  assert.equal(planInherit(entry('editor'), folder('viewer'), 'P', []).epoch, true);
  assert.equal(planInherit(entry('editor'), folder('editor'), 'P', []).epoch, false);
  assert.equal(planInherit(entry('viewer'), folder('manager'), 'P', []).epoch, false);
  assert.equal(planInherit(entry('viewer'), folder('manager'), 'P', []).members[0].role, 'manager');
});

// ---- more of the rules ----

test('sharing an item with a role below the one its folder gives keeps the folder\'s role, and with a higher one raises it', async () => {
  const spec = { [F]: { members: [{ user: U.viewer, role: 'editor' }] }, [A1]: { members: [{ user: U.viewer, role: 'editor', via: F }] } };
  const s = await scene({ spec });
  await share(s.deps, A1, 'viewer@example.com', 'viewer');
  assert.deepEqual(entry(s, A1, U.viewer), { user: U.viewer.id, role: 'editor', fp: U.viewer.fp });
  assert.equal(latest(s, A1).epoch, 1, 'not a demotion');
  const t = await scene({ spec: { [F]: { members: [{ user: U.viewer, role: 'viewer' }] }, [A1]: { members: [{ user: U.viewer, role: 'viewer', via: F }] } } });
  const res = await share(t.deps, A1, 'viewer@example.com', 'editor');
  assert.equal(res.promoted, true);
  assert.deepEqual(entry(t, A1, U.viewer), { user: U.viewer.id, role: 'editor', fp: U.viewer.fp });
});

test('subtreeOrder visits folders before artifacts, each by ID, depth first, and stops at a loop and at the depth limit', () => {
  const at = (id, kind, parent) => ({ id, kind, parent });
  const all = [at('z', 'artifact', 'r'), at('b', 'artifact', 'r'), at('y', 'folder', 'r'), at('c', 'folder', 'r'), at('c1', 'artifact', 'c'), at('r', 'folder', null), at('out', 'artifact', null)];
  assert.deepEqual(subtreeOrder(all, 'r', false).map((i) => i.id), ['c', 'c1', 'y', 'b', 'z']);
  assert.deepEqual(subtreeOrder(all, 'r', true).map((i) => i.id), ['r', 'c', 'c1', 'y', 'b', 'z']);
  const loop = [at('a', 'folder', 'b'), at('b', 'folder', 'a')];
  assert.deepEqual(subtreeOrder(loop, 'a', false).map((i) => i.id), ['b']);
  const chain = Array.from({ length: 20 }, (_, i) => at(`d${i}`, 'folder', i === 0 ? 'root' : `d${i - 1}`));
  assert.equal(subtreeOrder([at('root', 'folder', null), ...chain], 'root', false).length, 16);
});

test('a failure that ends the command ends the fan-out, with what it did', async () => {
  const s = await scene({ spec: { [F]: { members: [{ user: U.viewer, role: 'viewer' }] } } });
  s.server.kids.get(A1).failPut = () => new Response(JSON.stringify({ error: 'sign in' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  const err = await fanOut(s.deps, F).catch((e) => e);
  assert.equal(err.status, 401);
  assert.deepEqual(err.result.items.map((i) => i.id), [G, A2], 'the items before it are in the result');
  assert.deepEqual(err.result.items.map((i) => i.state), ['updated', 'updated']);
});

test('an account the folder lists that no longer exists fails the item alone', async () => {
  const gone = await extraUser('gone', '99999999-0000-4999-8999-999999999999');
  const s = await scene({ spec: { [F]: { members: [{ user: gone, role: 'viewer' }, { user: U.viewer, role: 'viewer' }] } } });
  s.server.primary.directory.delete(gone.id);
  const res = await fanOut(s.deps, F);
  assert.deepEqual(res.items.map((i) => [i.id, i.error?.code]), [[G, 'member-deleted'], [A2, undefined], [A1, 'member-deleted']]);
  assert.equal(res.failed, 2);
});

test('an item whose handover waits for the caller fails alone', async () => {
  const s = await scene({ spec: { [F]: { members: [{ user: U.viewer, role: 'viewer' }] }, [A1]: { members: [{ user: U.editor, role: 'editor' }] } } });
  const kid = s.server.kids.get(A1);
  const prev = bodyOf(kid.world.records[1]);
  kid.records = [...kid.world.records, await e2e.newEnvelope(U.editor.ed.seed, U.editor.id, 'membership', new TextEncoder().encode(JSON.stringify({
    ...prev, seq: 3, owner: U.editor.id, ownerFp: U.editor.fp, members: [{ user: U.owner.id, role: 'manager', fp: U.owner.fp }], handover: 'admin', prev: await e2e.bodyHash(e2e.unb64(kid.world.records[1].body)),
  })))];
  kid.owners[U.editor.fp] = U.editor.pair;
  const res = await fanOut(s.deps, A1, { includeRoot: true });
  assert.equal(res.items[0].error.code, 'handover-not-acked');
  assert.equal(s.server.records.length, 0);
});

test('a user who holds the keys already, through a group, is listed with no new wraps', async () => {
  const s = await scene();
  await seedGroup(s.server.primary, { id: GROUP, name: 'Design', members: [{ user: U.outsider }] });
  await shareGroup(s.deps, A1, GROUP, 'viewer');
  assert.deepEqual(s.server.kids.get(A1).approves.map((a) => a.user), [U.outsider.id]);
  await share(s.deps, F, 'outsider@example.com', 'viewer');
  const put = s.server.records.filter((r) => r.id === A1).at(-1).put;
  assert.deepEqual(put.wraps, [], 'an approved user holds a wrap of every epoch');
  assert.equal(entry(s, A1, U.outsider).via, F);
  const other = s.server.records.filter((r) => r.id === G).at(-1).put;
  assert.deepEqual(other.wraps.map((w) => w.user), [U.outsider.id]);
});

test('sharing a folder with someone removed from an item lists them again on it', async () => {
  const s = await scene();
  await share(s.deps, A1, 'outsider@example.com', 'viewer');
  await unshare(s.deps, A1, 'outsider@example.com');
  assert.deepEqual(latest(s, A1).excluded.map((x) => x.user), [U.outsider.id]);
  await share(s.deps, F, 'outsider@example.com', 'viewer');
  assert.deepEqual(latest(s, A1).excluded, []);
  assert.equal(entry(s, A1, U.outsider).via, F);
});

test('a manager cannot list again someone removed from an item through a fan-out', async () => {
  const mgr = (via) => ({ members: [{ user: U.manager, role: 'manager', ...(via ? { via: F } : {}) }] });
  const s = await scene({ spec: { [F]: mgr(false), [A1]: mgr(true) } });
  // The owner removed the viewer from the item before the folder listed them.
  await share(s.deps, A1, 'viewer@example.com', 'viewer');
  await unshare(s.deps, A1, 'viewer@example.com');
  assert.deepEqual(latest(s, A1).excluded.map((x) => x.user), [U.viewer.id]);
  s.server.who = U.manager;
  s.server.primary.keyring = { rev: 0, keyring: '' };
  const res = await share(depsFor(s.server, records.manager), F, 'viewer@example.com', 'viewer');
  assert.equal(res.fanOut.items.find((i) => i.id === A1).error.code, 'owner-only');
  assert.deepEqual(latest(s, A1).excluded.map((x) => x.user), [U.viewer.id]);
});

test('a group the folder lists that no longer exists is not required of an item', async () => {
  const s = await scene({ spec: { [F]: { members: [{ user: U.viewer, role: 'viewer' }], groups: [{ group: GROUP, role: 'viewer' }] } } });
  const res = await fanOut(s.deps, F);
  assert.deepEqual(res.items.map((i) => i.state), ['updated', 'updated', 'updated']);
  assert.deepEqual(res.items.flatMap((i) => [...i.pending, ...i.approved]), []);
  for (const id of [G, A1, A2]) assert.deepEqual(latest(s, id).groups ?? [], [], id);
});

test('a folder\'s record is read once for the whole run', async () => {
  const s = await scene({ spec: { [F]: { members: [{ user: U.viewer, role: 'viewer' }] } } });
  await fanOut(s.deps, F);
  assert.equal(s.server.kids.get(F).calls.filter((c) => c.path.endsWith('/membership') && c.method === 'GET').length, 1);
});

test('a folder created inside a folder shared with a group lists the group, marked, and approves its members', async () => {
  const s = await scene({ spec: { [F]: { groups: [{ group: GROUP, role: 'editor' }] } } });
  await seedGroup(s.server.primary, { id: GROUP, name: 'Design', members: [{ user: U.outsider }] });
  const { id } = await createFolder(s.deps, { name: 'Sub', parent: F });
  assert.deepEqual(latest(s, id).groups, [{ group: GROUP, role: 'editor', via: F }]);
  assert.deepEqual(s.server.kids.get(id).approves.map((a) => a.user), [U.outsider.id]);
  assert.equal(s.server.inheritOf(id), 'ok');
});

test('a folder created inside a folder is refused by the server when it lists nobody the folder lists', async () => {
  const s = await scene({ spec: { [F]: { members: [{ user: U.viewer, role: 'viewer' }] } } });
  // The fixture refuses as the server does: a record that leaves the entry out.
  const first = { v: 1, artifact: 'f0000000-0000-4000-8000-0000000000bb', epoch: 1, seq: 1, owner: U.owner.id, ownerFp: U.owner.fp, akCommit: 'x', members: [], excluded: [], team: 'none', public: false, publicWrites: false, prev: '', transfer: '', handover: '' };
  const membership = await e2e.newEnvelope(U.owner.ed.seed, U.owner.id, 'membership', new TextEncoder().encode(JSON.stringify(first)));
  const resp = await s.server.fetch('/api/artifacts', { method: 'POST', body: JSON.stringify({ id: first.artifact, kind: 'folder', parent: F, membership, wraps: [], estate: [] }) });
  assert.equal(resp.status, 409);
  assert.match((await resp.json()).error, /inherit: member .* is missing/);
});

// ---- placement is signed ----

// Another folder of the owner's, with an item inside it, none of it in F.
const OTHER = 'f0000000-0000-4000-8000-0000000000a1';
const INSIDE = 'f0000000-0000-4000-8000-0000000000a2';
const foreignTree = [
  { id: OTHER, kind: 'folder', parent: null, owner: U.owner },
  { id: INSIDE, kind: 'artifact', parent: OTHER, owner: U.owner },
];

// hostile is deps whose server lies about the tree: list and view change the
// parent and inherit of an item in the list and in its own view, by ID. sent
// holds each PUT and POST, so a test can show that nothing was written.
function hostile(s, { list = {}, view = {} }) {
  const sent = [];
  const json = (body) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  const fetch = async (path, init = {}) => {
    const method = init.method ?? 'GET';
    if (method !== 'GET') sent.push(`${method} ${path}`);
    const resp = await s.server.fetch(path, init);
    if (method !== 'GET' || !resp.ok) return resp;
    const one = /^\/api\/artifacts\/([^/]+)$/.exec(path);
    if (path === '/api/artifacts') return json((await resp.json()).map((a) => ({ ...a, ...list[a.id] })));
    if (one && view[one[1]]) return json({ ...(await resp.json()), ...view[one[1]] });
    return resp;
  };
  return { deps: depsFor({ fetch }, records.owner), sent };
}
const wroteTo = (sent, id) => sent.some((x) => x.includes(`/api/artifacts/${id}/`));
const shareF = { [F]: { members: [{ user: U.viewer, role: 'viewer' }] }, [G]: { members: [{ user: U.viewer, role: 'viewer', via: F }] } };
const stateOf = (res, id) => res.items.find((i) => i.id === id);

test('a server that lists a foreign item under the folder does not get it a write: its record names another folder, or none', async () => {
  const claim = { parent: F, inherit: 'pending' };
  // The view says so too, or only says pending: the list alone puts it under F.
  for (const [folder, viewClaim] of [['', claim], [G, claim], ['', { inherit: 'pending' }]]) {
    const s = await scene({ spec: { ...shareF, [TOP]: { folder } } });
    const before = latest(s, TOP);
    const h = hostile(s, { list: { [TOP]: claim }, view: { [TOP]: viewClaim } });
    const res = await fanOut(h.deps, F);
    const foreign = stateOf(res, TOP);
    assert.equal(foreign.state, 'failed', folder);
    assert.ok(foreign.error instanceof SharingError && foreign.error.code === 'placement', folder);
    assert.equal(res.failed, 1);
    assert.deepEqual([G, A1, A2].map((id) => stateOf(res, id).state), ['current', 'updated', 'updated'], 'the others are brought up to date');
    assert.equal(wroteTo(h.sent, TOP), false, 'no write for the foreign item');
    assert.deepEqual(latest(s, TOP), before);
  }
});

test('a server that rewrites an item\'s parent in its view does not get it sealed to another folder', async () => {
  const s = await scene({ spec: shareF });
  const h = hostile(s, { view: { [A1]: { parent: G } } });
  const res = await fanOut(h.deps, F);
  assert.equal(stateOf(res, A1).error?.code, 'placement');
  assert.equal(wroteTo(h.sent, A1), false);
  assert.equal(entry(s, A1, U.viewer), undefined);
  assert.equal(stateOf(res, G).state, 'current');
  assert.equal(stateOf(res, A2).state, 'updated');
});

test('a foreign folder listed under the folder is refused, and so is everything inside it', async () => {
  const s = await scene({ spec: shareF, extra: foreignTree });
  const claim = { parent: F, inherit: 'pending' };
  const h = hostile(s, { list: { [OTHER]: claim }, view: { [OTHER]: claim } });
  const res = await fanOut(h.deps, F);
  assert.equal(stateOf(res, OTHER).error?.code, 'placement');
  assert.equal(stateOf(res, INSIDE).error?.code, 'placement');
  assert.equal(res.failed, 2);
  assert.equal(wroteTo(h.sent, OTHER) || wroteTo(h.sent, INSIDE), false);
  assert.equal(entry(s, INSIDE, U.viewer), undefined);
  assert.equal(stateOf(res, A1).state, 'updated');
});

test('a foreign folder the server calls current is refused as well', async () => {
  // Both lie about the parent, or only the list does: the folder's own record says where it sits.
  for (const view of [{ [OTHER]: { parent: F } }, {}]) {
    const s = await scene({ spec: shareF, extra: foreignTree });
    const h = hostile(s, { list: { [OTHER]: { parent: F } }, view });
    const res = await fanOut(h.deps, F);
    assert.equal(stateOf(res, OTHER).error?.code, 'placement', 'its place is checked whatever inherit says');
    assert.equal(stateOf(res, INSIDE).error?.code, 'placement');
  }
});

// ---- a move places the item ----

const itemsOf = (s) => [...s.server.kids].map(([id, k]) => ({ id, kind: k.kind, parent: k.parent, name: id }));
const sender = (s) => async (method, path, body) => {
  const resp = await s.server.fetch(path, { method, body: JSON.stringify(body) });
  if (!resp.ok) throw Object.assign(new Error(`${resp.status}`), { status: resp.status });
  return {};
};

test('a move into a shared folder writes the placement, and the item inherits the folder\'s entries', async () => {
  const s = await scene({ spec: shareF });
  const progress = [];
  const res = await moveAndPlace(s.deps, sender(s), itemsOf(s), TOP, F, (d, t) => progress.push([d, t]));
  assert.deepEqual(res.items.map((i) => [i.id, i.state]), [[TOP, 'updated']]);
  assert.deepEqual(progress, [[1, 1]]);
  assert.equal(latest(s, TOP).folder, F);
  assert.equal(entry(s, TOP, U.viewer).via, F);
  assert.equal(s.server.inheritOf(TOP), 'ok');
  assert.equal(s.server.kids.get(TOP).parent, F);
});

test('a move to the top level writes a record that names no folder, and starts a new epoch for who held it through the folder', async () => {
  const s = await scene({ spec: { ...shareF, [A1]: { members: [{ user: U.viewer, role: 'viewer', via: F }] } } });
  assert.equal(s.server.inheritOf(A1), 'ok');
  const res = await moveAndPlace(s.deps, sender(s), itemsOf(s), A1, null);
  assert.deepEqual(res.items.map((i) => [i.id, i.state]), [[A1, 'newEpoch']]);
  assert.equal(latest(s, A1).folder, undefined);
  assert.equal(entry(s, A1, U.viewer), undefined);
  assert.equal(s.server.inheritOf(A1), 'ok');
});

test('a move of a folder places it, and fans out to what is inside', async () => {
  const s = await scene({ spec: { ...shareF, [A2]: { members: [{ user: U.viewer, role: 'viewer', via: F }] } } });
  const res = await moveAndPlace(s.deps, sender(s), itemsOf(s), G, null);
  assert.deepEqual(res.items.map((i) => [i.id, i.state]), [[G, 'newEpoch'], [A2, 'newEpoch']]);
  assert.equal(latest(s, G).folder, undefined);
  assert.equal(latest(s, A2).folder, G);
  assert.equal(s.server.inheritOf(A2), 'ok');
});

test('a move that moves nothing places nothing', async () => {
  const s = await scene({ spec: shareF });
  assert.equal(await moveAndPlace(s.deps, sender(s), itemsOf(s), A1, F), null);
  await assert.rejects(moveAndPlace(s.deps, sender(s), itemsOf(s), F, G), /cannot move into itself/);
  assert.deepEqual(s.server.calls, []);
});

test('moving a pending item to the folder it already sits in places it again, since the caller chose the folder', async () => {
  // The server moved TOP into F, but no record names F yet, so it is pending.
  const s = await scene({ spec: shareF });
  await sender(s)('PUT', `/api/artifacts/${TOP}/parent`, { parent: F });
  assert.equal(s.server.inheritOf(TOP), 'pending');
  const items = itemsOf(s).map((i) => ({ ...i, inherit: s.server.inheritOf(i.id) }));
  const res = await moveAndPlace(s.deps, sender(s), items, TOP, F);
  assert.deepEqual(res.items.map((i) => [i.id, i.state]), [[TOP, 'updated']]);
  assert.equal(latest(s, TOP).folder, F);
  assert.equal(s.server.inheritOf(TOP), 'ok');
  // An item that is up to date where it sits is left alone.
  const again = itemsOf(s).map((i) => ({ ...i, inherit: s.server.inheritOf(i.id) }));
  assert.equal(await moveAndPlace(s.deps, sender(s), again, TOP, F), null);
});

test('a move into a folder nobody shares still writes the placement', async () => {
  const s = await scene();
  const res = await moveAndPlace(s.deps, sender(s), itemsOf(s), TOP, F);
  assert.deepEqual(res.items.map((i) => [i.id, i.state]), [[TOP, 'updated']]);
  assert.equal(latest(s, TOP).folder, F);
  assert.deepEqual(latest(s, TOP).members, []);
  assert.equal(s.server.inheritOf(TOP), 'ok');
});

// ---- what the fixture server refuses, as the server does ----

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

test('the server refuses a record that names another folder than the item sits in', async () => {
  const s = await scene();
  for (const folder of [G, '']) {
    const resp = await putAs(s, A1, U.owner, { folder });
    assert.equal(resp.status, 409, `folder ${folder}`);
    assert.match((await resp.json()).error, /placement/);
  }
  assert.equal((await putAs(s, A1, U.owner, { folder: F })).status, 200);
});

test('the server refuses a first record that names another folder than the one it is created in', async () => {
  const s = await scene();
  const id = 'f0000000-0000-4000-8000-0000000000bb';
  const first = { v: 1, artifact: id, epoch: 1, seq: 1, owner: U.owner.id, ownerFp: U.owner.fp, akCommit: 'x', members: [], excluded: [], team: 'none', public: false, publicWrites: false, prev: '', transfer: '', handover: '' };
  const membership = await e2e.newEnvelope(U.owner.ed.seed, U.owner.id, 'membership', new TextEncoder().encode(JSON.stringify(first)));
  const resp = await s.server.fetch('/api/artifacts', { method: 'POST', body: JSON.stringify({ id, kind: 'folder', parent: F, membership, wraps: [], estate: [] }) });
  assert.equal(resp.status, 409);
  assert.match((await resp.json()).error, /placement/);
});

test('the server refuses a manager\'s record that changes the folder, and an item whose record names another folder is pending', async () => {
  const s = await scene({ who: 'manager', spec: { [TOP]: { members: [{ user: U.manager, role: 'manager' }] } } });
  s.server.setParent(TOP, F);
  assert.equal(s.server.inheritOf(TOP), 'pending', 'the record names the top level, and the item sits in F');
  const resp = await putAs(s, TOP, U.manager, { v: 2, signer: U.manager.id, signerFp: U.manager.fp, folder: F });
  assert.equal(resp.status, 409);
  assert.match(await resp.text(), /manager cannot change the folder/);
  assert.equal((await putAs(s, TOP, U.owner, { folder: F })).status, 200);
  assert.equal(s.server.inheritOf(TOP), 'ok');
});

test('a manager cannot place an item, by a move or by a fan-out', async () => {
  const mgr = { members: [{ user: U.manager, role: 'manager' }, { user: U.viewer, role: 'viewer' }] };
  const s = await scene({ who: 'manager', spec: { [F]: mgr, [TOP]: { members: [{ user: U.manager, role: 'manager' }] } } });
  await assert.rejects(moveAndPlace(s.deps, sender(s), itemsOf(s), TOP, F), (e) => e.status === 403);
  // The owner moved it, and the record still names no folder.
  s.server.setParent(TOP, F);
  const res = await fanOut(s.deps, TOP, { includeRoot: true, placing: F });
  assert.deepEqual(res.items.map((i) => [i.id, i.state, i.error?.code]), [[TOP, 'failed', 'owner-only']]);
  assert.equal(s.server.records.length, 0);
  assert.equal(latest(s, TOP).folder, undefined);
});
