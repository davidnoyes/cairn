// Tests for groups.mjs against real group chains, keyrings, and keys (see
// groups_fixture.mjs), behind a stateful fake of the server. Every refusal
// has a test of its own. Run with:
// node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { ApiError } from './account.mjs';
import { rotationRecord } from './viewer_fixture.mjs';
import { KeyChangedError } from './sharing.mjs';
import { signedInCaller, updateKeyring } from './viewer.mjs';
import { addMember, createGroup, deleteGroup, groupMembers, listGroups, removeMember, renameGroup } from './groups.mjs';
import { bodyOf, depsFor, extraUser, groupRecord, keyStoreRecord, makeGroupServer, makeUser, readKeyring, seedKeyring } from './groups_fixture.mjs';

const U = {};
for (const name of ['owner', 'editor', 'viewer', 'outsider', 'manager']) U[name] = await makeUser(name);
U.other = await extraUser('other', '88888888-8888-4888-8888-888888888888');
U.low = await extraUser('low', '11111111-1111-4111-8111-111111111111');
const records = {};
for (const name of Object.keys(U)) records[name] = await keyStoreRecord(U[name]);

const GROUP = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const entry = (u, role = 'member') => ({ user: u.id, fp: u.fp, role });
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const headOf = (env) => e2e.bodyHash(e2e.unb64(env.body));

// scene is a server with every user in its directory, `who` signed in, and a
// group the owner made, GROUP, with the members given.
async function scene({ who = 'owner', members = [], roles = {}, isAdmin = false, seeded = true } = {}) {
  const server = makeGroupServer({ who: U[who], users: Object.values(U), roles, isAdmin });
  if (seeded) {
    server.groups.set(GROUP, [await groupRecord(U.owner, { group: GROUP, members: [entry(U.owner, 'manager'), ...members] })]);
  }
  return { server, deps: depsFor(server, records[who]) };
}

const puts = (s) => s.server.calls.filter((c) => c.method === 'PUT' && c.path.startsWith('/api/groups/'));
const lastRecord = (s) => bodyOf(s.server.groups.get(GROUP).at(-1));
const membersOf = (b) => b.members.map((m) => [m.user, m.role]);

// ---- listing ----

test('listGroups lists the caller\'s groups first, then the rest by name', async () => {
  const s = await scene();
  s.server.groups.set('b', [await groupRecord(U.editor, { group: 'b', name: 'Alpha' })]);
  s.server.groups.set('c', [await groupRecord(U.editor, { group: 'c', name: 'Beta', members: [entry(U.editor, 'manager'), entry(U.owner)] })]);
  s.server.groups.set('0', [await groupRecord(U.owner, { group: '0', name: 'Zed' })]);
  const list = await listGroups(s.deps);
  assert.deepEqual(list.map((g) => [g.id, g.name, g.role, g.members, g.seq]), [
    ['c', 'Beta', 'member', 2, 1],
    [GROUP, 'Team', 'manager', 1, 1],
    ['0', 'Zed', 'manager', 1, 1],
    ['b', 'Alpha', '', 1, 1],
  ]);
});

test('listGroups refuses an answer that is not a list', async () => {
  const s = await scene();
  s.deps.fetch = async () => json(200, { groups: [] });
  await assert.rejects(listGroups(s.deps), e2e.FormatError);
});

// ---- opening ----

test('a group shows its members from the chain, with names, emails, and pin states', async () => {
  const s = await scene({ members: [entry(U.editor), entry(U.viewer)] });
  const res = await groupMembers(s.deps, GROUP);
  assert.equal(res.name, 'Team');
  assert.equal(res.seq, 1);
  assert.equal(res.callerRole, 'manager');
  const row = (u) => res.members.find((m) => m.user === u.id);
  assert.deepEqual([row(U.owner).state, row(U.editor).state, row(U.viewer).state], ['self', 'new', 'new']);
  assert.equal(row(U.editor).email, 'editor@example.com');
  assert.equal(row(U.editor).name, 'editor');
  assert.equal(row(U.editor).fp, U.editor.fp);
  assert.equal(row(U.editor).role, 'member');
});

test('opening a group stores its seq and head in the keyring, and it is not written again', async () => {
  const s = await scene();
  await groupMembers(s.deps, GROUP);
  const kr = await readKeyring(s.server, U.owner);
  assert.deepEqual(kr.groups, { [GROUP]: { seq: 1, head: await headOf(s.server.groups.get(GROUP)[0]) } });
  const rev = s.server.keyring.rev;
  await groupMembers(s.deps, GROUP);
  assert.equal(s.server.keyring.rev, rev, 'a chain the keyring already holds is not written');
});

test('a member shows the pin state their key is in, and changed when the key differs from the pin', async () => {
  const s = await scene({ members: [entry(U.editor)] });
  const k = e2e.newKeyring();
  k.pins[U.editor.id] = { fp: 'a'.repeat(64), state: 'verified', rotSeq: 0, rotHead: '' };
  await seedKeyring(s.server, U.owner, k);
  const res = await groupMembers(s.deps, GROUP);
  assert.equal(res.members.find((m) => m.user === U.editor.id).state, 'changed');
});

test('a group whose chain is shorter than the keyring\'s seq is refused, and nothing is shown', async () => {
  const s = await scene();
  await groupMembers(s.deps, GROUP);
  const first = s.server.groups.get(GROUP)[0];
  await addMember(s.deps, GROUP, 'editor@example.com', 'member');
  s.server.groups.set(GROUP, [first]);
  await assert.rejects(groupMembers(s.deps, GROUP), e2e.RollbackError);
});

test('a group forked at the keyring\'s seq is refused', async () => {
  const s = await scene();
  await groupMembers(s.deps, GROUP);
  s.server.groups.set(GROUP, [await groupRecord(U.owner, { group: GROUP, name: 'Forked' })]);
  await assert.rejects(groupMembers(s.deps, GROUP), e2e.ForkError);
});

test('a group the server forged is refused: a record signed under another key', async () => {
  const s = await scene();
  const forged = await groupRecord(U.outsider, { group: GROUP, over: { signer: U.owner.id, signerFp: U.owner.fp } });
  s.server.groups.set(GROUP, [forged]);
  await assert.rejects(groupMembers(s.deps, GROUP), e2e.DecryptError);
  assert.equal(s.server.keyring.rev, 0, 'nothing was stored');
});

test('a group with no records is refused', async () => {
  const s = await scene();
  s.deps.fetch = async (path, init) => (path === `/api/groups/${GROUP}` ? json(200, { id: GROUP, records: [] }) : s.server.fetch(path, init));
  await assert.rejects(groupMembers(s.deps, GROUP), e2e.ChainError);
});

// ---- creating ----

test('createGroup signs the first record, with a random UUID and the caller as its one manager', async () => {
  const s = await scene({ seeded: false });
  const { id, name } = await createGroup(s.deps, 'Design');
  assert.match(id, UUID_V4);
  assert.equal(name, 'Design');
  const [record] = s.server.groups.get(id);
  const b = bodyOf(record);
  assert.deepEqual(b, {
    v: 1, group: id, seq: 1, prev: '', name: 'Design',
    members: [{ user: U.owner.id, fp: U.owner.fp, role: 'manager' }], signer: U.owner.id, signerFp: U.owner.fp,
  });
  assert.equal(record.signer, U.owner.id);
  assert.ok(await e2e.verifyEnvelope(U.owner.ed.pub, 'group', record));
  const kr = await readKeyring(s.server, U.owner);
  assert.deepEqual(kr.groups[id], { seq: 1, head: await headOf(record) });
  assert.notEqual((await createGroup(s.deps, 'Design')).id, id, 'each group has its own ID');
});

test('createGroup refuses a bad name before sending anything', async () => {
  const s = await scene({ seeded: false });
  for (const name of ['', 'x'.repeat(101), 'a\nb', 'a\u0085b']) {
    await assert.rejects(createGroup(s.deps, name), (err) => err.code === 'bad-name', JSON.stringify(name));
  }
  assert.deepEqual(s.server.calls.filter((c) => c.method === 'POST'), []);
});

test('a viewer account makes no group, and sends nothing', async () => {
  const s = await scene({ seeded: false, roles: { owner: 'viewer' } });
  await assert.rejects(createGroup(s.deps, 'Design'), (err) => err.code === 'viewer-account');
  assert.deepEqual(s.server.calls.filter((c) => c.method === 'POST'), []);
});

test('createGroup that the server answers with another record is a read-back failure', async () => {
  const s = await scene({ seeded: false });
  s.server.failPut = () => json(201, { id: GROUP, records: [] });
  await assert.rejects(createGroup(s.deps, 'Design'), (err) => err.code === 'read-back');
});

// ---- adding and changing ----

test('addMember signs the next record, sorted, and pins the new member unverified', async () => {
  const s = await scene();
  const res = await addMember(s.deps, GROUP, ' EDITOR@Example.com ', 'member');
  assert.equal(res.unchanged, false);
  const b = lastRecord(s);
  const first = s.server.groups.get(GROUP)[0];
  assert.equal(b.seq, 2);
  assert.equal(b.prev, await headOf(first));
  assert.equal(b.name, 'Team');
  assert.deepEqual(b.members, [entry(U.owner, 'manager'), entry(U.editor)].sort((x, y) => (x.user < y.user ? -1 : 1)));
  assert.equal(b.signer, U.owner.id);
  assert.equal(b.signerFp, U.owner.fp);
  const kr = await readKeyring(s.server, U.owner);
  assert.deepEqual(kr.pins[U.editor.id], { fp: U.editor.fp, state: 'unverified', rotSeq: 0, rotHead: '' });
  assert.deepEqual(kr.groups[GROUP], { seq: 2, head: await headOf(s.server.groups.get(GROUP)[1]) }, 'the read-back stored the new head');
});

test('addMember as manager lists them as manager, and a member can be made manager and back', async () => {
  const s = await scene({ members: [entry(U.editor)] });
  await addMember(s.deps, GROUP, 'editor@example.com', 'manager');
  assert.deepEqual(membersOf(lastRecord(s)).find(([u]) => u === U.editor.id), [U.editor.id, 'manager']);
  await addMember(s.deps, GROUP, 'editor@example.com', 'member');
  assert.deepEqual(membersOf(lastRecord(s)).find(([u]) => u === U.editor.id), [U.editor.id, 'member']);
  assert.equal(lastRecord(s).seq, 3);
});

test('addMember with the role and fingerprint the group lists sends no record', async () => {
  const s = await scene({ members: [entry(U.editor)] });
  const res = await addMember(s.deps, GROUP, 'editor@example.com', 'member');
  assert.equal(res.unchanged, true);
  assert.deepEqual(puts(s), []);
});

test('naming the sole manager as manager again changes nothing, and is not the last manager leaving', async () => {
  const s = await scene();
  const res = await addMember(s.deps, GROUP, 'owner@example.com', 'manager');
  assert.equal(res.unchanged, true);
  assert.deepEqual(puts(s), []);
});

test('a new member whose ID sorts before the others is listed first', async () => {
  const s = await scene();
  await addMember(s.deps, GROUP, 'low@example.com', 'member');
  assert.deepEqual(lastRecord(s).members.map((m) => m.user), [U.low.id, U.owner.id]);
});

test('addMember refuses a role other than member or manager', async () => {
  const s = await scene();
  for (const role of ['viewer', 'editor', 'owner', '']) {
    await assert.rejects(addMember(s.deps, GROUP, 'editor@example.com', role), (err) => err.code === 'bad-role', role);
  }
  assert.deepEqual(puts(s), []);
});

test('addMember refuses a viewer account as manager, and lists one as member', async () => {
  const s = await scene({ roles: { viewer: 'viewer' } });
  await assert.rejects(addMember(s.deps, GROUP, 'viewer@example.com', 'manager'), (err) => err.code === 'viewer-account');
  assert.deepEqual(puts(s), []);
  await addMember(s.deps, GROUP, 'viewer@example.com', 'member');
  assert.deepEqual(membersOf(lastRecord(s)).find(([u]) => u === U.viewer.id), [U.viewer.id, 'member']);
});

test('addMember refuses a user whose key changed from the pin, until it is accepted', async () => {
  const s = await scene();
  const k = e2e.newKeyring();
  k.pins[U.editor.id] = { fp: 'a'.repeat(64), state: 'verified', rotSeq: 0, rotHead: '' };
  await seedKeyring(s.server, U.owner, k);
  await assert.rejects(addMember(s.deps, GROUP, 'editor@example.com', 'member'), KeyChangedError);
  assert.deepEqual(puts(s), [], 'nothing was signed');
  await addMember(s.deps, GROUP, 'editor@example.com', 'member', { acceptNewKey: true });
  assert.deepEqual(lastRecord(s).members.find((m) => m.user === U.editor.id), entry(U.editor));
  const kr = await readKeyring(s.server, U.owner);
  assert.equal(kr.pins[U.editor.id].fp, U.editor.fp);
  assert.equal(kr.pins[U.editor.id].state, 'unverified');
});

test('addMember refuses a user the directory does not list', async () => {
  const s = await scene();
  await assert.rejects(addMember(s.deps, GROUP, 'nobody@example.com', 'member'), (err) => err.code === 'unknown-user');
  assert.deepEqual(puts(s), []);
});

test('addMember relists a member whose key changed, under the fingerprint the directory serves', async () => {
  const s = await scene({ members: [{ user: U.editor.id, fp: 'e'.repeat(64), role: 'member' }] });
  const k = e2e.newKeyring();
  k.pins[U.editor.id] = { fp: U.editor.fp, state: 'verified', rotSeq: 0, rotHead: '' };
  await seedKeyring(s.server, U.owner, k);
  const res = await addMember(s.deps, GROUP, 'editor@example.com', 'member');
  assert.equal(res.unchanged, false);
  assert.equal(lastRecord(s).members.find((m) => m.user === U.editor.id).fp, U.editor.fp);
});

test('only a manager changes a group, and nothing is signed for anyone else', async () => {
  const s = await scene({ who: 'editor', members: [entry(U.editor), entry(U.viewer)] });
  const refused = (err) => err.code === 'not-manager';
  await assert.rejects(addMember(s.deps, GROUP, 'outsider@example.com', 'member'), refused);
  await assert.rejects(removeMember(s.deps, GROUP, 'viewer@example.com'), refused);
  await assert.rejects(renameGroup(s.deps, GROUP, 'Other'), refused);
  assert.deepEqual(puts(s), []);
  const out = await scene({ who: 'outsider' });
  await assert.rejects(renameGroup(out.deps, GROUP, 'Other'), refused);
});

test('a second manager changes the group too, under their own signature', async () => {
  const s = await scene({ members: [entry(U.editor, 'manager')] });
  const other = depsFor(s.server, records.editor);
  s.server.who = U.editor;
  await addMember(other, GROUP, 'viewer@example.com', 'member');
  assert.equal(lastRecord(s).signer, U.editor.id);
  assert.equal(lastRecord(s).seq, 2);
});

// ---- the last manager ----

test('the last manager cannot be made a member or removed', async () => {
  const s = await scene({ members: [entry(U.editor)] });
  await assert.rejects(addMember(s.deps, GROUP, 'owner@example.com', 'member'), (err) => err.code === 'last-manager');
  await assert.rejects(removeMember(s.deps, GROUP, 'owner@example.com'), (err) => err.code === 'last-manager');
  assert.deepEqual(puts(s), []);
});

test('a manager can leave while another manager remains', async () => {
  const s = await scene({ members: [entry(U.editor, 'manager')] });
  await removeMember(s.deps, GROUP, 'owner@example.com');
  assert.deepEqual(membersOf(lastRecord(s)), [[U.editor.id, 'manager']]);
});

// ---- removing and renaming ----

test('removeMember signs a record without them', async () => {
  const s = await scene({ members: [entry(U.editor), entry(U.viewer)] });
  const res = await removeMember(s.deps, GROUP, 'editor@example.com');
  assert.equal(res.user.id, U.editor.id);
  assert.deepEqual(membersOf(lastRecord(s)).map(([u]) => u).sort(), [U.owner.id, U.viewer.id].sort());
  assert.equal(lastRecord(s).seq, 2);
});

test('removeMember refuses someone the group does not list', async () => {
  const s = await scene();
  await assert.rejects(removeMember(s.deps, GROUP, 'editor@example.com'), (err) => err.code === 'not-member');
  assert.deepEqual(puts(s), []);
});

test('renameGroup signs a record with the new name and the same members', async () => {
  const s = await scene({ members: [entry(U.editor)] });
  await renameGroup(s.deps, GROUP, 'New name');
  const b = lastRecord(s);
  assert.equal(b.name, 'New name');
  assert.deepEqual(b.members, s.server.groups.get(GROUP).map(bodyOf)[0].members);
});

test('renameGroup refuses a bad name before reading or signing', async () => {
  const s = await scene();
  for (const name of ['', 'x'.repeat(101), 'a\u0000b', 'a\u007fb']) {
    await assert.rejects(renameGroup(s.deps, GROUP, name), (err) => err.code === 'bad-name', JSON.stringify(name));
  }
  assert.deepEqual(s.server.calls.filter((c) => c.path.startsWith('/api/groups')), []);
});

// ---- the server's answers ----

test('a record that lost a race is a moved error, and the keyring is left alone', async () => {
  const s = await scene();
  s.server.failPut = () => json(409, { error: 'the group changed' });
  await assert.rejects(renameGroup(s.deps, GROUP, 'New'), (err) => err.code === 'moved' && /try the change again/.test(err.message));
  const kr = await readKeyring(s.server, U.owner);
  assert.equal(kr.groups[GROUP].seq, 1);
});

test('another failure of a write is passed on as it is', async () => {
  const s = await scene();
  s.server.failPut = () => json(403, { error: 'not a manager' });
  await assert.rejects(renameGroup(s.deps, GROUP, 'New'), (err) => err instanceof ApiError && err.status === 403);
});

test('a write the server answers with the old chain is a read-back failure', async () => {
  const s = await scene();
  s.server.failPut = () => json(200, { id: GROUP, records: s.server.groups.get(GROUP), signers: s.server.signersOf(s.server.groups.get(GROUP)) });
  await assert.rejects(renameGroup(s.deps, GROUP, 'New'), (err) => err.code === 'read-back' && /not the one this client signed/.test(err.message));
});

test('a write the server answers with a record another manager signed is a read-back failure', async () => {
  const s = await scene({ members: [entry(U.editor, 'manager')] });
  const members = [entry(U.owner, 'manager'), entry(U.editor, 'manager')];
  const first = s.server.groups.get(GROUP)[0];
  const theirs = await groupRecord(U.editor, { group: GROUP, seq: 2, prev: await headOf(first), members, name: 'Theirs' });
  s.server.failPut = () => json(200, { id: GROUP, records: [first, theirs], signers: s.server.signersOf([first, theirs]) });
  await assert.rejects(renameGroup(s.deps, GROUP, 'New'), (err) => err.code === 'read-back' && /not the one this client signed/.test(err.message));
});

test('a write the server answers with a chain it forged is a read-back failure', async () => {
  const s = await scene();
  const forged = await groupRecord(U.outsider, { group: GROUP, seq: 2, prev: await headOf(s.server.groups.get(GROUP)[0]), over: { signer: U.owner.id, signerFp: U.owner.fp } });
  s.server.failPut = () => json(200, { id: GROUP, records: [s.server.groups.get(GROUP)[0], forged], signers: s.server.signersOf([s.server.groups.get(GROUP)[0], forged]) });
  await assert.rejects(renameGroup(s.deps, GROUP, 'New'), (err) => err.code === 'read-back' && err.cause instanceof e2e.DecryptError);
});

// ---- deleting ----

test('deleteGroup deletes it, for a manager and for an administrator who is not in it', async () => {
  const s = await scene();
  await deleteGroup(s.deps, GROUP);
  assert.deepEqual(s.server.deleted, [GROUP]);
  const admin = await scene({ who: 'outsider', isAdmin: true });
  await deleteGroup(admin.deps, GROUP);
  assert.deepEqual(admin.server.deleted, [GROUP]);
});

test('deleteGroup passes on a refusal', async () => {
  const s = await scene();
  const real = s.deps.fetch;
  s.deps.fetch = async (path, init) => (init?.method === 'DELETE' ? json(403, { error: 'only a manager or an administrator deletes a group' }) : real(path, init));
  await assert.rejects(deleteGroup(s.deps, GROUP), (err) => err instanceof ApiError && err.status === 403 && /only a manager/.test(err.message));
});

// ---- rotation ----

test('a manager whose key rotated after an earlier record still verifies the chain, and signs the next one', async () => {
  const s = await scene({ members: [entry(U.editor)] });
  await groupMembers(s.deps, GROUP);
  const rotated = await makeUser('owner');
  rotated.mk = U.owner.mk;
  rotated.ek = U.owner.ek;
  s.server.rotations[U.owner.id] = [await rotationRecord(U.owner, rotated)];
  const wire = s.server.directory.get(U.owner.id);
  s.server.directory.set(U.owner.id, { ...wire, x25519Pub: rotated.pair.x25519, ed25519Pub: rotated.pair.ed25519 });
  const deps = depsFor(s.server, await keyStoreRecord(rotated));
  await renameGroup(deps, GROUP, 'After rotation');
  const [first, second] = s.server.groups.get(GROUP).map(bodyOf);
  assert.equal(first.signerFp, U.owner.fp);
  assert.equal(second.signerFp, rotated.fp);
  const view = await groupMembers(deps, GROUP);
  assert.equal(view.name, 'After rotation');
  assert.equal(view.seq, 2);
});

test('a signer whose key changed with no rotation records links nothing, and the chain is refused', async () => {
  const s = await scene({ members: [entry(U.editor)] });
  const rotated = await makeUser('owner');
  rotated.mk = U.owner.mk;
  rotated.ek = U.owner.ek;
  const wire = s.server.directory.get(U.owner.id);
  s.server.directory.set(U.owner.id, { ...wire, x25519Pub: rotated.pair.x25519, ed25519Pub: rotated.pair.ed25519 });
  const deps = depsFor(s.server, await keyStoreRecord(rotated));
  await assert.rejects(renameGroup(deps, GROUP, 'No rotation'), e2e.ChainError);
  assert.deepEqual(puts(s), []);
});

// ---- the signers' keys ----

// moveKeys makes the directory serve `user` under the keys of `as`, the way a
// server that made keys for a real user ID would.
function moveKeys(server, user, as) {
  server.directory.set(user.id, { ...server.directory.get(user.id), x25519Pub: as.pair.x25519, ed25519Pub: as.pair.ed25519 });
}

test('a group whose manager was deactivated is still read, from the keys the group serves', async () => {
  const s = await scene({ members: [entry(U.editor, 'manager')] });
  s.server.who = U.editor;
  await renameGroup(depsFor(s.server, records.editor), GROUP, 'Editor was here');
  s.server.deactivated.set(U.editor.id, s.server.directory.get(U.editor.id));
  s.server.directory.delete(U.editor.id);
  for (const who of ['owner', 'outsider']) {
    s.server.who = U[who];
    s.server.keyring = { rev: 0, keyring: '' };
    const res = await groupMembers(depsFor(s.server, records[who]), GROUP);
    assert.equal(res.name, 'Editor was here', who);
    assert.equal(res.members.find((m) => m.user === U.editor.id).state, '-', 'the directory no longer lists them');
  }
  assert.ok(!s.server.calls.some((c) => c.path.endsWith('/rotations')), 'the rotation records came with the group');
});

test('a signer not pinned yet is pinned unverified, once the chain verifies', async () => {
  const s = await scene({ who: 'editor', members: [entry(U.editor)] });
  const res = await groupMembers(s.deps, GROUP);
  const kr = await readKeyring(s.server, U.editor);
  assert.deepEqual(kr.pins[U.owner.id], { fp: U.owner.fp, state: 'unverified', rotSeq: 0, rotHead: '' });
  assert.equal(res.members.find((m) => m.user === U.owner.id).state, 'unverified', 'the members are shown against the pins as they are now');
  assert.equal(kr.pins[U.editor.id], undefined, 'the caller does not pin themselves');
  // With the chain already in the keyring, a signer pinned in the meantime is
  // still shown by the pin.
  await updateKeyring(s.deps, await signedInCaller(s.deps), (k) => { delete k.pins[U.owner.id]; });
  const again = await groupMembers(s.deps, GROUP);
  assert.equal(again.members.find((m) => m.user === U.owner.id).state, 'unverified');
  assert.deepEqual(kr.groups[GROUP].seq, 1);
});

test('nothing is pinned when the chain does not verify', async () => {
  const s = await scene({ who: 'editor' });
  s.server.groups.set(GROUP, [await groupRecord(U.outsider, { group: GROUP, over: { signer: U.owner.id, signerFp: U.owner.fp } })]);
  await assert.rejects(groupMembers(s.deps, GROUP), e2e.DecryptError);
  assert.equal(s.server.keyring.rev, 0);
});

test('a signer\'s served key that differs from the pin with no rotation is refused, naming them, until accepted', async () => {
  const s = await scene({ who: 'editor', members: [entry(U.editor)] });
  const k = e2e.newKeyring();
  k.pins[U.owner.id] = { fp: 'a'.repeat(64), state: 'verified', rotSeq: 0, rotHead: '' };
  await seedKeyring(s.server, U.editor, k);
  await assert.rejects(groupMembers(s.deps, GROUP), (err) => err instanceof KeyChangedError && err.user === U.owner.id && err.email === 'owner@example.com' && err.fp === U.owner.fp);
  assert.equal((await readKeyring(s.server, U.editor)).pins[U.owner.id].fp, 'a'.repeat(64), 'the pin stands');
  await groupMembers(s.deps, GROUP, { acceptNewKey: true });
  assert.deepEqual((await readKeyring(s.server, U.editor)).pins[U.owner.id], { fp: U.owner.fp, state: 'unverified', rotSeq: 0, rotHead: '' });
  await groupMembers(s.deps, GROUP);
});

test('every function that reads a chain refuses a changed signer key, and accepts it when asked', async () => {
  for (const [name, call] of [
    ['groupMembers', (d, o) => groupMembers(d, GROUP, o)],
    ['addMember', (d, o) => addMember(d, GROUP, 'viewer@example.com', 'member', o)],
    ['removeMember', (d, o) => removeMember(d, GROUP, 'viewer@example.com', o)],
    ['renameGroup', (d, o) => renameGroup(d, GROUP, 'Other', o)],
  ]) {
    const s = await scene({ who: 'editor', members: [entry(U.editor, 'manager'), entry(U.viewer)] });
    const k = e2e.newKeyring();
    k.pins[U.owner.id] = { fp: 'a'.repeat(64), state: 'verified', rotSeq: 0, rotHead: '' };
    await seedKeyring(s.server, U.editor, k);
    await assert.rejects(call(s.deps, {}), KeyChangedError, name);
    assert.deepEqual(puts(s), [], `${name} signed nothing`);
    await call(s.deps, { acceptNewKey: true });
  }
});

test('a signer whose key rotated from the pinned one is accepted, and the pin follows', async () => {
  const s = await scene({ who: 'editor', members: [entry(U.editor)] });
  const rotated = await makeUser('owner');
  rotated.mk = U.owner.mk;
  rotated.ek = U.owner.ek;
  s.server.rotations[U.owner.id] = [await rotationRecord(U.owner, rotated)];
  moveKeys(s.server, U.owner, rotated);
  s.server.who = U.owner;
  await renameGroup(depsFor(s.server, await keyStoreRecord(rotated)), GROUP, 'After rotation');
  s.server.who = U.editor;
  s.server.keyring = { rev: 0, keyring: '' };
  const k = e2e.newKeyring();
  k.pins[U.owner.id] = { fp: U.owner.fp, state: 'verified', rotSeq: 0, rotHead: '' };
  await seedKeyring(s.server, U.editor, k);
  const res = await groupMembers(s.deps, GROUP);
  assert.equal(res.name, 'After rotation');
  const pin = (await readKeyring(s.server, U.editor)).pins[U.owner.id];
  assert.deepEqual([pin.fp, pin.state, pin.rotSeq], [rotated.fp, 'unverified', 1]);
});

test('a chain a server signed with keys it made for a pinned user is refused', async () => {
  const s = await scene({ who: 'editor' });
  const k = e2e.newKeyring();
  k.pins[U.owner.id] = { fp: U.owner.fp, state: 'verified', rotSeq: 0, rotHead: '' };
  await seedKeyring(s.server, U.editor, k);
  moveKeys(s.server, U.owner, U.outsider);
  const rev = s.server.keyring.rev;
  s.server.groups.set(GROUP, [await groupRecord(U.outsider, {
    group: GROUP, members: [{ user: U.owner.id, fp: U.outsider.fp, role: 'manager' }], over: { signer: U.owner.id },
  })]);
  await assert.rejects(groupMembers(s.deps, GROUP), (err) => err instanceof KeyChangedError && err.user === U.owner.id);
  assert.equal(s.server.keyring.rev, rev, 'the keyring is as it was seeded');
});

test('a record is signed by its signer\'s keys and no one else\'s', async () => {
  // The first record claims the owner as its signer but was signed by the
  // editor's key, which the editor's own later record puts among the keys.
  const s = await scene({ who: 'outsider', members: [] });
  const first = await groupRecord(U.editor, {
    group: GROUP, members: [{ user: U.owner.id, fp: U.editor.fp, role: 'manager' }, entry(U.editor, 'manager')],
    over: { signer: U.owner.id },
  });
  const second = await groupRecord(U.editor, {
    group: GROUP, seq: 2, prev: await headOf(first), members: [{ user: U.owner.id, fp: U.editor.fp, role: 'manager' }, entry(U.editor, 'manager')],
  });
  s.server.groups.set(GROUP, [first, second]);
  await assert.rejects(groupMembers(s.deps, GROUP), (err) => err instanceof e2e.ChainError && /belongs to/.test(err.message));
});

test('a group view with no keys for a signer is refused', async () => {
  const s = await scene();
  s.deps.fetch = async (path, init) => {
    const resp = await s.server.fetch(path, init);
    if (path !== `/api/groups/${GROUP}`) return resp;
    const { signers, ...rest } = await resp.json();
    assert.ok(signers);
    return json(200, rest);
  };
  await assert.rejects(groupMembers(s.deps, GROUP), (err) => err instanceof e2e.ChainError && /did not serve the keys/.test(err.message));
});

test('the caller\'s own entry in the signers is ignored for their own key', async () => {
  const s = await scene();
  s.deps.fetch = async (path, init) => {
    const resp = await s.server.fetch(path, init);
    if (path !== `/api/groups/${GROUP}`) return resp;
    const view = await resp.json();
    view.signers[U.owner.id] = { ...view.signers[U.owner.id], x25519: U.outsider.pair.x25519, ed25519: U.outsider.pair.ed25519 };
    return json(200, view);
  };
  assert.equal((await groupMembers(s.deps, GROUP)).name, 'Team');
});

test('keys served that are not 32 bytes are a format error', async () => {
  const s = await scene({ who: 'editor', members: [entry(U.editor)] });
  s.deps.fetch = async (path, init) => {
    const resp = await s.server.fetch(path, init);
    if (path !== `/api/groups/${GROUP}`) return resp;
    const view = await resp.json();
    view.signers[U.owner.id].ed25519 = e2e.b64(new Uint8Array(31));
    return json(200, view);
  };
  await assert.rejects(groupMembers(s.deps, GROUP), e2e.FormatError);
});

test('rotation records that do not lead to a signer\'s current key make none of their keys signing keys', async () => {
  // The first record is signed under a key that only rotation records of
  // another user name. Were it trusted, the chain would verify.
  const s = await scene({ who: 'editor', members: [entry(U.editor)] });
  s.server.rotations[U.owner.id] = [await rotationRecord(U.outsider, U.other)];
  const first = await groupRecord(U.outsider, {
    group: GROUP, members: [{ user: U.owner.id, fp: U.outsider.fp, role: 'manager' }, entry(U.editor)], over: { signer: U.owner.id },
  });
  s.server.groups.set(GROUP, [first]);
  await assert.rejects(groupMembers(s.deps, GROUP), (err) => err instanceof e2e.ChainError && /no signer key/.test(err.message));
});

// ---- the directory vouches for a signer's served key ----

test('a signer the directory lists must have the served key there, even when nothing is pinned yet', async () => {
  const s = await scene({ who: 'editor', members: [entry(U.editor)] });
  const real = s.server.signersOf;
  s.server.signersOf = (recs) => {
    const out = real(recs);
    out[U.owner.id] = { ...out[U.owner.id], x25519: U.outsider.pair.x25519, ed25519: U.outsider.pair.ed25519 };
    return out;
  };
  await assert.rejects(
    groupMembers(s.deps, GROUP),
    (err) => err instanceof e2e.ChainError && /owner@example\.com/.test(err.message) && /directory/.test(err.message),
  );
  assert.equal(s.server.keyring.rev, 0, 'nothing was pinned from the planted key');
});

// ---- the keyring moves between a read and a write ----

// otherDeviceStores adds a record named name to the server's group and stores
// its head in the keyring, as another device of the same user would.
async function otherDeviceStores(s, name) {
  const chain = s.server.groups.get(GROUP);
  const next = await groupRecord(U.owner, { group: GROUP, seq: chain.length + 1, prev: await headOf(chain.at(-1)), name });
  chain.push(next);
  const head = await headOf(next);
  const other = depsFor(s.server, records.owner, { storage: s.deps.storage });
  await updateKeyring(other, await signedInCaller(other), (k) => {
    k.groups ??= {};
    k.groups[GROUP] = { seq: bodyOf(next).seq, head };
  });
}

// movesOnRead makes the next `times` reads of the directory, which follow the
// keyring's read, be followed by another device storing a newer head.
function movesOnRead(s, times) {
  const real = s.deps.fetch;
  let n = 0;
  s.deps.fetch = async (path, init) => {
    const resp = await real(path, init);
    if ((init?.method ?? 'GET') === 'GET' && path === '/api/users' && n < times) {
      n += 1;
      await otherDeviceStores(s, `Renamed ${n}`);
    }
    return resp;
  };
}

test('a first read that another device overtakes is read again, and shows the newer chain', async () => {
  const s = await scene();
  movesOnRead(s, 1);
  const res = await groupMembers(s.deps, GROUP);
  assert.deepEqual([res.name, res.seq], ['Renamed 1', 2]);
  assert.equal((await readKeyring(s.server, U.owner)).groups[GROUP].seq, 2, 'the entry did not go back');
});

test('a chain the keyring already holds is read again when another device overtakes it', async () => {
  const s = await scene();
  await groupMembers(s.deps, GROUP);
  movesOnRead(s, 1);
  const res = await groupMembers(s.deps, GROUP);
  assert.deepEqual([res.name, res.seq], ['Renamed 1', 2]);
});

test('a group that keeps moving is a keyring-moved error, and the entry has not gone back', async () => {
  const s = await scene();
  movesOnRead(s, 2);
  await assert.rejects(groupMembers(s.deps, GROUP), (err) => err.name === 'GroupError' && err.code === 'keyring-moved');
  assert.equal((await readKeyring(s.server, U.owner)).groups[GROUP].seq, 3);
});

// ---- deleting removes the entry ----

test('deleteGroup removes the group\'s keyring entry, after the server confirms', async () => {
  const s = await scene();
  await groupMembers(s.deps, GROUP);
  assert.ok((await readKeyring(s.server, U.owner)).groups?.[GROUP], 'the keyring holds the entry');
  const real = s.deps.fetch;
  s.deps.fetch = async (path, init) => (init?.method === 'DELETE' ? json(403, { error: 'no' }) : real(path, init));
  await assert.rejects(deleteGroup(s.deps, GROUP), ApiError);
  assert.ok((await readKeyring(s.server, U.owner)).groups?.[GROUP], 'a refused delete leaves it');
  s.deps.fetch = real;
  await deleteGroup(s.deps, GROUP);
  assert.equal((await readKeyring(s.server, U.owner)).groups?.[GROUP], undefined);
});
