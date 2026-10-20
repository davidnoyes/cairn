// Tests for folders.mjs: creating a folder against a fake server that stores
// what it is sent and serves it back, so the record the code signed is the one
// the existing verifier reads; and the tree, move, delete, and drag logic the
// Artifacts tab calls. Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { ORIGIN, fakeKeyStore, fakeStorage, keyStoreRecord, makeUser } from './viewer_fixture.mjs';
import { openArtifact } from './viewer.mjs';
import { readMeta } from './meta.mjs';
import {
  FolderError, applicable, breadcrumb, canEdit, canMoveInto, canPlaceIn, canRemoveFromFolder, childrenOf, createFolder, deleteSummary, deleteTree,
  describeList, isStub, makeDraggable, makeDropTarget, moveItem, moveTargets, removeFromFolder, renameFolder, rowActions, splitTrees, stubLabel, subtree,
} from './folders.mjs';

const owner = await makeUser('owner');
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

// makeServer serves the routes createFolder and the open that follows it
// call. Whatever POST /api/artifacts takes is served back as the artifact.
function makeServer() {
  const s = { calls: [], posts: [], metaPuts: [], keyring: { rev: 0, keyring: '' }, artifacts: new Map(), failMeta: false };
  s.fetch = async (path, init = {}) => {
    const method = init.method ?? 'GET';
    s.calls.push({ method, path });
    const p = new URL(path, ORIGIN).pathname;
    if (p === '/api/me') return json(200, { id: owner.id, email: 'owner@example.com', name: 'owner' });
    if (p === '/api/me/keyring' && method === 'GET') return json(200, s.keyring);
    if (p === '/api/me/keyring' && method === 'PUT') {
      const body = JSON.parse(init.body);
      s.keyring = { rev: body.rev, keyring: body.keyring };
      return json(200, {});
    }
    if (p === '/api/artifacts' && method === 'POST') {
      const body = JSON.parse(init.body);
      s.posts.push(body);
      s.artifacts.set(body.id, { body, meta: {} });
      return json(201, { id: body.id });
    }
    const m = /^\/api\/artifacts\/([^/]+)(?:\/(.*))?$/.exec(p);
    const a = m && s.artifacts.get(m[1]);
    if (!a) return json(404, { error: 'not found' });
    const rest = m[2] ?? '';
    if (rest === 'membership') return json(200, { records: [a.body.membership], offers: {}, owners: { [owner.fp]: owner.pair }, rotations: {}, successors: {}, ownerChanges: {} });
    if (rest === 'keys') return json(200, { wraps: [], estate: a.body.estate });
    if (rest === '') return json(200, { id: m[1], kind: a.body.kind ?? 'artifact', parent: a.body.parent ?? null, meta: a.meta });
    const meta = /^meta\/([^/]+)$/.exec(rest);
    if (meta && method === 'PUT') {
      if (s.failMeta) return json(500, { error: 'broken' });
      const body = JSON.parse(init.body);
      s.metaPuts.push({ id: m[1], field: meta[1], body });
      a.meta[meta[1]] = { record: body.record, signerKey: e2e.b64(owner.ed.pub), blob: body.blob };
      return json(200, { ok: true });
    }
    return json(404, { error: `no route ${method} ${p}` });
  };
  return s;
}

async function setup() {
  const server = makeServer();
  const deps = { fetch: server.fetch, keyStore: fakeKeyStore(await keyStoreRecord(owner)), storage: fakeStorage(), origin: ORIGIN };
  return { server, deps };
}

// nameOf reads a folder's name back the way the Artifacts tab does.
async function nameOf(server, deps, id) {
  const opened = await openArtifact(deps, { artifact: id, link: null });
  const view = await (await server.fetch(`/api/artifacts/${id}`)).json();
  return (await readMeta(deps, opened, view.meta)).values.name;
}

test('createFolder posts a folder whose signed record verifies, with its estate copy and name', async () => {
  const { server, deps } = await setup();
  const { id } = await createFolder(deps, { name: 'Plans' });
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(server.posts.length, 1);
  const post = server.posts[0];
  assert.deepEqual(Object.keys(post).sort(), ['estate', 'id', 'kind', 'membership', 'wraps']);
  assert.equal(post.id, id);
  assert.equal(post.kind, 'folder');
  assert.deepEqual(post.wraps, []);
  assert.deepEqual(post.estate.map((e) => e.epoch), [1]);

  // The existing verifier accepts the record, anchored at the owner's own key.
  const chain = await e2e.verifyChain({
    artifact: id, records: [post.membership], owners: { [owner.fp]: owner.pair }, offers: {}, successors: {}, anchor: owner.fp,
    currentOwnerFp: '', pin: null, linked: e2e.rotationLinker({}),
  });
  assert.equal(chain.latest.seq, 1);
  assert.equal(chain.latest.epoch, 1);
  assert.equal(chain.latest.owner, owner.id);
  assert.equal(chain.latest.ownerFp, owner.fp);
  assert.deepEqual(chain.latest.members, []);
  assert.equal(chain.latest.team, 'none');
  assert.equal(chain.latest.public, false);
  assert.equal(chain.latest.publicWrites, false);

  // The estate copy opens under EK to the AK the record commits to.
  const ak = await e2e.open(await e2e.ekSealCryptoKey(owner.ek), ['estate', id, '1'], e2e.unb64(post.estate[0].sealed));
  assert.equal(await e2e.akCommit(ak, id, 1), chain.latest.akCommit);

  // The name is written under that AK, and the folder opens and reads back.
  assert.deepEqual(server.metaPuts.map((p) => [p.id, p.field]), [[id, 'name']]);
  assert.equal(await nameOf(server, deps, id), 'Plans');
});

test('createFolder names the parent in the body, and omits it at the top level', async () => {
  const { server, deps } = await setup();
  const top = await createFolder(deps, { name: 'A', parent: null });
  const inner = await createFolder(deps, { name: 'B', parent: top.id });
  assert.equal(Object.hasOwn(server.posts[0], 'parent'), false);
  assert.equal(server.posts[1].parent, top.id);
  assert.notEqual(inner.id, top.id);
});

test('createFolder refuses a blank name before sending anything', async () => {
  const { server, deps } = await setup();
  for (const name of ['', '   ', '\n']) {
    await assert.rejects(createFolder(deps, { name }), (err) => err instanceof FolderError && /name/.test(err.message));
  }
  assert.deepEqual(server.calls, []);
});

test('createFolder trims the name it writes', async () => {
  const { server, deps } = await setup();
  const { id } = await createFolder(deps, { name: '  Plans  ' });
  assert.equal(await nameOf(server, deps, id), 'Plans');
});

test('createFolder says the folder exists when its name could not be written', async () => {
  const { server, deps } = await setup();
  server.failMeta = true;
  await assert.rejects(createFolder(deps, { name: 'Plans' }), (err) => err instanceof FolderError && err.created === true
    && /created without a name/.test(err.message) && /renamed/.test(err.message) && /broken/.test(err.message));
  assert.equal(server.posts.length, 1);
});

test('a refusal before the folder exists is not marked created', async () => {
  const { deps } = await setup();
  await assert.rejects(createFolder(deps, { name: ' ' }), (err) => err instanceof FolderError && err.created === false);
});

test('renameFolder writes the name field of the folder', async () => {
  const { server, deps } = await setup();
  const { id } = await createFolder(deps, { name: 'Old' });
  await renameFolder(deps, id, ' New ');
  assert.deepEqual(server.metaPuts.map((p) => p.field), ['name', 'name']);
  assert.equal(await nameOf(server, deps, id), 'New');
  await assert.rejects(renameFolder(deps, id, ' '), FolderError);
  assert.equal(server.metaPuts.length, 2);
});

// ---- the tree ----

// A is a folder with B inside it and artifact x; C is a folder at the top.
// They are the caller's own, owned by ME.
const ME = 'me';
const mine = (list) => list.map((i) => ({ owner: ME, access: 'owner', inherit: 'ok', ...i }));
const items = mine([
  { id: 'x', kind: 'artifact', parent: 'A', name: 'x file' },
  { id: 'z', kind: 'artifact', parent: null, name: 'Zebra' },
  { id: 'a2', kind: 'artifact', parent: null, name: 'apple' },
  { id: 'B', kind: 'folder', parent: 'A', name: 'Inner' },
  { id: 'A', kind: 'folder', parent: null, name: 'Work' },
  { id: 'C', kind: 'folder', parent: null, name: 'archive' },
  { id: 'D', kind: 'folder', parent: 'B', name: 'Deep' },
]);
const ids = (list) => list.map((i) => i.id);

test('childrenOf lists folders first, then artifacts, each sorted by name without regard to case', () => {
  assert.deepEqual(ids(childrenOf(items, null)), ['C', 'A', 'a2', 'z']);
  assert.deepEqual(ids(childrenOf(items, 'A')), ['B', 'x']);
  assert.deepEqual(ids(childrenOf(items, 'C')), []);
});

test('childrenOf breaks a tie in names by ID, so the order never depends on the server', () => {
  const same = [{ id: 'q', kind: 'artifact', parent: null, name: 'n' }, { id: 'p', kind: 'artifact', parent: null, name: 'n' }];
  assert.deepEqual(ids(childrenOf(same, null)), ['p', 'q']);
});

test('an item whose folder is not in the list shows at the top level', () => {
  const lost = [{ id: 'k', kind: 'artifact', parent: 'gone', name: 'k' }];
  assert.deepEqual(ids(childrenOf(lost, null)), ['k']);
});

// Shared with you is this tree over the items the caller does not own. The
// server gives an item no parent when the caller cannot read its folder, and
// an item whose folder is the caller's own is not in the list at all, so both
// show at the top.
const sharedItems = [
  { id: 'S', kind: 'folder', parent: null, name: 'Shared folder' },
  { id: 'S2', kind: 'folder', parent: 'S', name: 'Inside' },
  { id: 'i1', kind: 'artifact', parent: 'S', name: 'In S' },
  { id: 'i2', kind: 'artifact', parent: 'S2', name: 'In S2' },
  { id: 'hidden', kind: 'artifact', parent: null, name: 'Folder unreadable' },
  { id: 'mine', kind: 'artifact', parent: 'ownFolder', name: 'Folder is mine' },
];

test('a shared folder opens to the items inside it that the caller can read, and an item whose folder is unreadable stays at the top', () => {
  assert.deepEqual(ids(childrenOf(sharedItems, null)), ['S', 'mine', 'hidden']);
  assert.deepEqual(ids(childrenOf(sharedItems, 'S')), ['S2', 'i1']);
  assert.deepEqual(ids(childrenOf(sharedItems, 'S2')), ['i2']);
  assert.deepEqual(breadcrumb(sharedItems, 'S2'), [{ id: null, name: 'Top' }, { id: 'S', name: 'Shared folder' }, { id: 'S2', name: 'Inside' }]);
});

test('breadcrumb runs from the top level down to the folder in view', () => {
  assert.deepEqual(breadcrumb(items, null), [{ id: null, name: 'Top' }]);
  assert.deepEqual(breadcrumb(items, 'D'), [
    { id: null, name: 'Top' }, { id: 'A', name: 'Work' }, { id: 'B', name: 'Inner' }, { id: 'D', name: 'Deep' },
  ]);
});

test('breadcrumb of a folder that is gone is the top level', () => {
  assert.deepEqual(breadcrumb(items, 'nope'), [{ id: null, name: 'Top' }]);
});

test('breadcrumb stops at a loop in the server\'s parents', () => {
  const loop = [{ id: 'a', kind: 'folder', parent: 'b', name: 'a' }, { id: 'b', kind: 'folder', parent: 'a', name: 'b' }];
  assert.ok(breadcrumb(loop, 'a').length <= 3);
});

test('moveTargets offers the top level and every folder but the item itself and what is inside it', () => {
  assert.deepEqual(moveTargets(items, 'x').map((t) => t.id), [null, 'C', 'A', 'B', 'D']);
  assert.deepEqual(moveTargets(items, 'A').map((t) => t.id), [null, 'C']);
  assert.deepEqual(moveTargets(items, 'B').map((t) => t.id), [null, 'C', 'A']);
  assert.deepEqual(moveTargets(items, 'D').map((t) => t.id), [null, 'C', 'A', 'B']);
});

test('moveTargets labels a folder by its path', () => {
  const t = moveTargets(items, 'x');
  assert.deepEqual(t.map((x) => x.label), ['Top level', 'archive', 'Work', 'Work / Inner', 'Work / Inner / Deep']);
});

test('canMoveInto refuses a folder into itself or its own descendant', () => {
  assert.equal(canMoveInto(items, 'A', 'A'), false);
  assert.equal(canMoveInto(items, 'A', 'D'), false);
  assert.equal(canMoveInto(items, 'A', 'C'), true);
  assert.equal(canMoveInto(items, 'A', null), true);
  assert.equal(canMoveInto(items, 'x', 'B'), true);
});

test('subtree lists the artifacts and the folders, deepest first, the folder itself last', () => {
  const t = subtree(items, 'A');
  assert.deepEqual(t.artifacts, ['x']);
  assert.deepEqual(t.folders, ['D', 'B', 'A']);
  assert.deepEqual(t.moved, []);
  assert.deepEqual(subtree(items, 'C'), { artifacts: [], folders: ['C'], moved: [] });
});

// ---- move ----

test('moveItem puts the new parent, and null for the top level', async () => {
  const calls = [];
  const send = async (method, path, body) => { calls.push([method, path, body]); return {}; };
  assert.equal(await moveItem(send, items, 'x', 'C'), true);
  assert.equal(await moveItem(send, items, 'x', null), true);
  assert.deepEqual(calls, [['PUT', '/api/artifacts/x/parent', { parent: 'C' }], ['PUT', '/api/artifacts/x/parent', { parent: null }]]);
});

test('moveItem sends nothing for a cycle, or for the folder the item is in already', async () => {
  const calls = [];
  const send = async (...a) => { calls.push(a); return {}; };
  await assert.rejects(moveItem(send, items, 'A', 'D'), FolderError);
  await assert.rejects(moveItem(send, items, 'A', 'A'), FolderError);
  assert.equal(await moveItem(send, items, 'x', 'A'), false);
  assert.deepEqual(calls, []);
});

// ---- delete ----

test('deleteTree deletes the artifacts, then the folders deepest first, then the folder', async () => {
  const order = [];
  const progress = [];
  const del = async (id) => { order.push(id); };
  const n = await deleteTree(del, items, 'A', (done, total) => progress.push([done, total]));
  assert.deepEqual(order, ['x', 'D', 'B', 'A']);
  assert.deepEqual(progress, [[1, 4], [2, 4], [3, 4], [4, 4]]);
  assert.equal(n, 4);
});

test('deleteTree carries on past an item already gone, so a second run finishes', async () => {
  const order = [];
  const del = async (id) => {
    order.push(id);
    if (id === 'x' || id === 'D') throw Object.assign(new Error('not found'), { status: 404 });
  };
  await deleteTree(del, items, 'A', () => {});
  assert.deepEqual(order, ['x', 'D', 'B', 'A']);
});

test('deleteTree stops at any other failure, and leaves the folder', async () => {
  const order = [];
  const del = async (id) => {
    order.push(id);
    if (id === 'D') throw Object.assign(new Error('the folder is not empty'), { status: 409 });
  };
  await assert.rejects(deleteTree(del, items, 'A', () => {}), /not empty/);
  assert.deepEqual(order, ['x', 'D']);
});

// ---- drag and drop ----

// A fake element keeps its listeners and classes.
function fakeEl() {
  const classes = new Set();
  return {
    listeners: {},
    draggable: false,
    classList: { add: (c) => classes.add(c), remove: (c) => classes.delete(c), has: (c) => classes.has(c) },
    addEventListener(t, f) { this.listeners[t] = f; },
    children: [],
    contains(n) { return n === this || this.children.includes(n); },
  };
}
function fakeTransfer(data = {}) {
  return {
    data, effectAllowed: '', dropEffect: '', setData(t, v) { this.data[t] = v; }, getData(t) { return this.data[t] ?? ''; },
    clearData() { for (const t of Object.keys(this.data)) delete this.data[t]; },
    get types() { return Object.keys(this.data); },
  };
}
function fire(el, type, dataTransfer, extra = {}) {
  const ev = { dataTransfer, prevented: false, preventDefault() { this.prevented = true; }, ...extra };
  el.listeners[type](ev);
  return ev;
}

test('a dragged row carries its ID, and a drop on a folder moves it there', () => {
  const row = fakeEl();
  makeDraggable(row, 'x');
  assert.equal(row.draggable, true);
  const dt = fakeTransfer();
  fire(row, 'dragstart', dt);
  const moves = [];
  const target = fakeEl();
  makeDropTarget(target, 'C', (id, parent) => moves.push([id, parent]));
  const over = fire(target, 'dragover', dt);
  assert.equal(over.prevented, true);
  assert.equal(target.classList.has('drop'), true);
  const drop = fire(target, 'drop', dt);
  assert.equal(drop.prevented, true);
  assert.equal(target.classList.has('drop'), false);
  assert.deepEqual(moves, [['x', 'C']]);
});

test('a dragged row carries only its ID, not the URL of a link it was picked up by', () => {
  // A drag that starts on the row's name link arrives with the link's URL,
  // which a browser opens if the drop misses every target.
  const row = fakeEl();
  makeDraggable(row, 'x');
  const dt = fakeTransfer({ 'text/uri-list': '/shared/x', 'text/plain': '/shared/x' });
  fire(row, 'dragstart', dt);
  assert.deepEqual(dt.types, ['application/x-cairn-item']);
  assert.equal(dt.getData('application/x-cairn-item'), 'x');
});

test('dropping on the top-level breadcrumb moves to null', () => {
  const moves = [];
  const top = fakeEl();
  makeDropTarget(top, null, (id, parent) => moves.push([id, parent]));
  fire(top, 'drop', fakeTransfer({ 'application/x-cairn-item': 'x' }));
  assert.deepEqual(moves, [['x', null]]);
});

test('a drop that carries no row of ours moves nothing, and leaving a target clears its styling', () => {
  const moves = [];
  const target = fakeEl();
  makeDropTarget(target, 'C', (id, parent) => moves.push([id, parent]));
  const foreign = fakeTransfer({ 'text/plain': 'x' });
  assert.equal(fire(target, 'dragover', foreign).prevented, false);
  assert.equal(target.classList.has('drop'), false);
  fire(target, 'dragover', fakeTransfer({ 'application/x-cairn-item': 'x' }));
  assert.equal(target.classList.has('drop'), true);
  fire(target, 'dragleave', fakeTransfer());
  assert.equal(target.classList.has('drop'), false);
  fire(target, 'drop', foreign);
  assert.deepEqual(moves, []);
});

test('moving onto a child of a drop target keeps its highlight, and leaving it clears it', () => {
  const target = fakeEl();
  const child = fakeEl();
  target.children.push(child);
  makeDropTarget(target, 'C', () => {});
  fire(target, 'dragover', fakeTransfer({ 'application/x-cairn-item': 'x' }));
  fire(target, 'dragleave', fakeTransfer(), { relatedTarget: child });
  assert.equal(target.classList.has('drop'), true);
  fire(target, 'dragleave', fakeTransfer(), { relatedTarget: fakeEl() });
  assert.equal(target.classList.has('drop'), false);
  fire(target, 'dragover', fakeTransfer({ 'application/x-cairn-item': 'x' }));
  fire(target, 'dragleave', fakeTransfer(), { relatedTarget: null });
  assert.equal(target.classList.has('drop'), false);
});

// ---- other people's items ----

const them = (list) => list.map((i) => ({ owner: 'them', inherit: 'ok', access: 'viewer', ...i }));
const stub = (id, parent, owner = 'them') => ({ id, kind: 'artifact', parent, owner, access: 'none', inherit: 'pending' });

test('a stub is an item with access none, and says who owns it from the directory, or by ID when the directory lacks them', () => {
  assert.equal(isStub({ access: 'none' }), true);
  for (const access of ['viewer', 'editor', 'manager', 'owner']) assert.equal(isStub({ access }), false, access);
  const dir = [{ id: 'u1', email: 'ann@example.com' }, { id: 'u2', email: 'bob@example.com' }];
  assert.equal(stubLabel({ owner: 'u2' }, dir), 'not shared with you yet, owned by bob@example.com');
  assert.equal(stubLabel({ owner: 'u9' }, dir), 'not shared with you yet, owned by u9');
});

test('only an editor, a manager or the owner of a folder may put items in it', () => {
  for (const [access, may] of [['viewer', false], ['none', false], ['editor', true], ['manager', true], ['owner', true]]) assert.equal(canEdit({ access }), may, access);
});

test('splitTrees puts an item in the tree of its folder, and a top-level item by its owner', () => {
  const list = [
    { id: 'F', kind: 'folder', parent: null, owner: 'me', access: 'owner' },
    { id: 'theirs', kind: 'artifact', parent: 'F', owner: 'them', access: 'viewer' },
    { id: 'S', kind: 'folder', parent: null, owner: 'them', access: 'editor' },
    { id: 'mineInS', kind: 'artifact', parent: 'S', owner: 'me', access: 'owner' },
    { id: 'top', kind: 'artifact', parent: null, owner: 'me', access: 'owner' },
    { id: 'hidden', kind: 'artifact', parent: null, owner: 'them', access: 'viewer' },
    stub('pendingInF', 'F'),
    stub('pendingInS', 'S'),
  ];
  const { own, shared } = splitTrees(list, 'me');
  assert.deepEqual(own.map((i) => i.id), ['F', 'theirs', 'top', 'pendingInF']);
  assert.deepEqual(shared.map((i) => i.id), ['S', 'mineInS', 'hidden', 'pendingInS']);
  assert.deepEqual(own.find((i) => i.id === 'pendingInF'), { id: 'pendingInF', kind: 'artifact', parent: 'F', name: 'pendingInF', owner: 'them', access: 'none', inherit: 'pending' });
  assert.deepEqual(ids(childrenOf(own, 'F')), ['pendingInF', 'theirs'], 'a stub sorts by its ID, inside the folder');
  assert.deepEqual(ids(childrenOf(shared, 'S')), ['mineInS', 'pendingInS']);
});

test('splitTrees treats a parent that is not a folder, or a loop, as no folder', () => {
  const list = [
    { id: 'a', kind: 'artifact', parent: null, owner: 'them', access: 'viewer' },
    { id: 'b', kind: 'artifact', parent: 'a', owner: 'me', access: 'owner' },
    { id: 'l1', kind: 'folder', parent: 'l2', owner: 'me', access: 'owner' },
    { id: 'l2', kind: 'folder', parent: 'l1', owner: 'me', access: 'owner' },
  ];
  const { own, shared } = splitTrees(list, 'me');
  assert.deepEqual(own.map((i) => i.id), ['b', 'l1', 'l2']);
  assert.deepEqual(shared.map((i) => i.id), ['a']);
});

test('describeList reads every entry but a stub, in order, and never asks about a stub', async () => {
  const list = [{ id: 'a', access: 'owner' }, stub('s', 'F'), { id: 'b', access: 'viewer' }, stub('t', 'F')];
  const asked = [];
  const got = [];
  await describeList(list, async (a) => { asked.push(a.id); return `name of ${a.id}`; }, async (a, name) => { got.push([a.id, name]); });
  assert.deepEqual(asked, ['a', 'b']);
  assert.deepEqual(got, [['a', 'name of a'], ['b', 'name of b']]);
});

test('applicable lists the pending items the caller owns or manages, and no stub, editor item or current one', () => {
  const at = (id, access, inherit = 'pending') => ({ id, access, inherit });
  const list = [at('o', 'owner'), at('m', 'manager'), at('e', 'editor'), at('v', 'viewer'), at('s', 'none'), at('ok', 'owner', 'ok')];
  assert.deepEqual(applicable(list).map((i) => i.id), ['o', 'm']);
});

// F is a folder the caller owns; theirs is another person's item in it, a stub
// is another's pending item, mine is the caller's own; S is a folder someone
// else owns, in which the caller has the access the test sets.
const folderTree = (access) => [
  ...mine([{ id: 'F', kind: 'folder', parent: null, name: 'Mine' }, { id: 'mine', kind: 'artifact', parent: 'F', name: 'mine' }]),
  ...them([{ id: 'theirs', kind: 'artifact', parent: 'F', name: 'theirs' }, { id: 'S', kind: 'folder', parent: null, name: 'Theirs', access }, { id: 'inS', kind: 'artifact', parent: 'S', name: 'inS' }]),
  { ...stub('pending', 'F'), name: 'pending' },
];

test('an item someone else owns can be removed from a folder the caller may edit, and from no other', () => {
  const can = (list, id) => canRemoveFromFolder(list, id, ME);
  const own = folderTree('viewer');
  assert.equal(can(own, 'theirs'), true, 'the folder is the caller\'s');
  assert.equal(can(own, 'pending'), true, 'a stub is someone else\'s item too');
  assert.equal(can(own, 'mine'), false, 'the caller moves their own item, not removes it');
  assert.equal(can(own, 'F'), false, 'a top-level folder is in no folder');
  assert.equal(can(own, 'inS'), false, 'a folder the caller may only read');
  for (const [access, may] of [['editor', true], ['manager', true], ['viewer', false]]) assert.equal(can(folderTree(access), 'inS'), may, access);
  assert.equal(can(own, 'nope'), false);
});

test('the caller\'s own item in a folder they cannot read can be removed from it, by its owner only', () => {
  const hidden = { id: 'lost', kind: 'artifact', parent: null, hiddenParent: true, name: 'lost' };
  const list = [...folderTree('viewer'), ...mine([hidden])];
  assert.equal(canRemoveFromFolder(list, 'lost', ME), true);
  assert.deepEqual(rowActions(list.find((i) => i.id === 'lost'), list, ME), ['share', 'move', 'delete', 'remove']);
  const managed = [...folderTree('viewer'), ...them([{ ...hidden, access: 'manager' }])];
  assert.equal(canRemoveFromFolder(managed, 'lost', ME), false, 'a manager needs editor access to the folder');
  const top = [...folderTree('viewer'), ...mine([{ ...hidden, hiddenParent: undefined }])];
  assert.equal(canRemoveFromFolder(top, 'lost', ME), false, 'at the top level already');
});

test('rowActions: a stub offers nothing but removal, the owner Share, Move and Delete', () => {
  const list = folderTree('viewer');
  const actions = (id) => rowActions(list.find((i) => i.id === id), list, ME);
  assert.deepEqual(actions('pending'), ['remove'], 'no Share, Move, Delete, Open');
  assert.deepEqual(actions('mine'), ['share', 'move', 'delete']);
  assert.deepEqual(actions('F'), ['rename', 'share', 'move', 'delete']);
  assert.deepEqual(actions('theirs'), ['remove'], 'a viewer of someone else\'s item in the caller\'s folder');
  assert.deepEqual(actions('inS'), [], 'a viewer in a folder the caller cannot edit');
});

test('rowActions for someone else\'s item: Share for a manager, Approve for an editor, Remove from a folder the caller edits', () => {
  const list = folderTree('editor');
  const of = (access) => rowActions({ ...list.find((i) => i.id === 'inS'), access }, list, ME);
  assert.deepEqual(of('manager'), ['share', 'remove']);
  assert.deepEqual(of('editor'), ['approve', 'remove']);
  assert.deepEqual(of('viewer'), ['remove']);
  const readOnly = folderTree('viewer');
  assert.deepEqual(rowActions({ ...readOnly.find((i) => i.id === 'inS'), access: 'editor' }, readOnly, ME), ['approve'], 'no removal from a folder the caller cannot edit');
  assert.deepEqual(rowActions({ ...readOnly.find((i) => i.id === 'inS'), access: 'manager' }, readOnly, ME), ['share']);
});

test('moveTargets offers every folder the caller may edit, whoever owns it, labelled by its path', () => {
  const targets = (access, id = 'mine') => moveTargets(folderTree(access), id).map((t) => [t.id, t.label]);
  assert.deepEqual(targets('viewer'), [[null, 'Top level'], ['F', 'Mine']], 'a folder the caller may only read is not offered');
  assert.deepEqual(targets('editor'), [[null, 'Top level'], ['F', 'Mine'], ['S', 'Theirs']]);
  assert.deepEqual(targets('manager'), [[null, 'Top level'], ['F', 'Mine'], ['S', 'Theirs']]);
  const nested = [...folderTree('viewer'), ...them([{ id: 'S2', kind: 'folder', parent: 'S', name: 'Inner', access: 'editor' }])];
  assert.deepEqual(moveTargets(nested, 'mine').map((t) => [t.id, t.label]), [[null, 'Top level'], ['F', 'Mine'], ['S2', 'Theirs / Inner']], 'an editable folder inside a read-only one');
  assert.deepEqual(targets('none'), [[null, 'Top level'], ['F', 'Mine']], 'a stub folder is not offered');
});

test('canPlaceIn is true for the top level and a folder the caller may edit', () => {
  const list = folderTree('viewer');
  assert.equal(canPlaceIn(list, null), true);
  assert.equal(canPlaceIn(list, 'F'), true);
  assert.equal(canPlaceIn(list, 'S'), false);
  assert.equal(canPlaceIn(list, 'mine'), false, 'not a folder');
  assert.equal(canPlaceIn(list, 'nope'), false);
  assert.equal(canPlaceIn(folderTree('editor'), 'S'), true);
});

test('moveItem puts an own item in a folder someone else owns when the caller edits it, and refuses it otherwise', async () => {
  const calls = [];
  const send = async (...a) => { calls.push(a); return {}; };
  assert.equal(await moveItem(send, folderTree('editor'), 'mine', 'S'), true);
  assert.deepEqual(calls, [['PUT', '/api/artifacts/mine/parent', { parent: 'S' }]]);
  await assert.rejects(moveItem(send, folderTree('viewer'), 'mine', 'S'), FolderError);
  assert.equal(calls.length, 1, 'nothing was sent for a folder the caller cannot edit');
  assert.equal(await moveItem(send, folderTree('viewer'), 'mine', null), true, 'the top level is always theirs');
});

test('removeFromFolder moves the item to no folder, and sends nothing for one the caller may not remove', async () => {
  const calls = [];
  const send = async (...a) => { calls.push(a); return {}; };
  await removeFromFolder(send, folderTree('viewer'), 'theirs', ME);
  assert.deepEqual(calls, [['PUT', '/api/artifacts/theirs/parent', { parent: null }]]);
  await assert.rejects(removeFromFolder(send, folderTree('viewer'), 'mine', ME), FolderError);
  await assert.rejects(removeFromFolder(send, folderTree('viewer'), 'inS', ME), FolderError);
  assert.equal(calls.length, 1);
});

// Deleting F: the caller's own items go, down to a folder someone else owns,
// and what others own moves to their owners' top level.
const deletable = () => [
  ...mine([
    { id: 'F', kind: 'folder', parent: null, name: 'F' },
    { id: 'a1', kind: 'artifact', parent: 'F', name: 'a1' },
    { id: 'G', kind: 'folder', parent: 'F', name: 'G' },
    { id: 'a2', kind: 'artifact', parent: 'G', name: 'a2' },
    { id: 'inOthers', kind: 'artifact', parent: 'X', name: 'my item in their folder' },
  ]),
  ...them([
    { id: 'theirs', kind: 'artifact', parent: 'F', name: 'theirs' },
    { id: 'theirsInG', kind: 'artifact', parent: 'G', name: 'theirsInG' },
    { id: 'X', kind: 'folder', parent: 'F', name: 'X' },
    { id: 'inX', kind: 'artifact', parent: 'X', name: 'inX' },
  ]),
  { ...stub('pending', 'F'), name: 'pending' },
];

test('subtree of a folder with other people\'s items counts what goes and what moves, and does not go into a folder someone else owns', () => {
  const t = subtree(deletable(), 'F');
  assert.deepEqual(t.artifacts, ['a2', 'a1']);
  assert.deepEqual(t.folders, ['G', 'F']);
  assert.deepEqual([...t.moved].sort(), ['X', 'pending', 'theirs', 'theirsInG'], 'a folder counts once, with what is inside it; a stub moves too');
  assert.ok(!t.artifacts.includes('inOthers'), 'the caller\'s item inside X goes with X');
});

test('deleteSummary says how many items are deleted and how many others move, and says nothing of moves when none does', () => {
  const dir = [{ id: 'u2', email: 'bob@x.com' }, { id: 'u3', email: 'carol@y.com' }];
  const held = [stub('x', 'F', 'u2'), stub('y', 'F', 'u3'), stub('z', 'F', 'u2')];
  assert.equal(deleteSummary({ artifacts: ['a', 'b'], folders: ['F'], moved: [] }, held, dir), 'Delete 1 folder and 2 artifacts?');
  assert.equal(deleteSummary({ artifacts: ['a'], folders: ['G', 'F'], moved: ['x'] }, held, dir), 'Delete 2 folders and 1 artifact of yours, and move 1 item other people own (bob@x.com) to their owners\' top level?');
  assert.equal(deleteSummary({ artifacts: [], folders: ['F'], moved: ['y', 'x'] }, held, dir), 'Delete 1 folder and 0 artifacts of yours, and move 2 items other people own (bob@x.com, carol@y.com) to their owners\' top level?');
});

test('deleteSummary names each owner once, in order, and by ID when the directory lacks them', () => {
  const held = [stub('x', 'F', 'u9'), stub('y', 'F', 'u3'), stub('z', 'F', 'u9')];
  const dir = [{ id: 'u3', email: 'carol@y.com' }];
  assert.equal(deleteSummary({ artifacts: [], folders: ['F'], moved: ['z', 'y', 'x'] }, held, dir), 'Delete 1 folder and 0 artifacts of yours, and move 3 items other people own (carol@y.com, u9) to their owners\' top level?');
});

test('subtree of a folder the list does not hold moves nothing, rather than every child', () => {
  assert.deepEqual(subtree(items, 'missing'), { artifacts: [], folders: [], moved: [] });
  assert.deepEqual(subtree([stub('x', 'gone')], 'gone'), { artifacts: [], folders: [], moved: [] });
});

test('deleteTree deletes the owner\'s own items, artifacts first, then folders deepest first, and never what others own', async () => {
  const order = [];
  const n = await deleteTree(async (id) => { order.push(id); }, deletable(), 'F', () => {});
  assert.deepEqual(order, ['a2', 'a1', 'G', 'F']);
  assert.equal(n, 4);
});

test('an item whose parent is not a folder is not removed from anything', () => {
  const list = [...folderTree('editor'), ...them([{ id: 'art', kind: 'artifact', parent: null, name: 'art', access: 'editor' }, { id: 'odd', kind: 'artifact', parent: 'art', name: 'odd', access: 'editor' }])];
  assert.equal(canRemoveFromFolder(list, 'odd', ME), false);
});
