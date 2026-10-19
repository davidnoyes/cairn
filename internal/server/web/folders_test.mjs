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
  FolderError, breadcrumb, canMoveInto, childrenOf, createFolder, deleteTree, makeDraggable, makeDropTarget, moveItem, moveTargets,
  renameFolder, subtree,
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
  await assert.rejects(createFolder(deps, { name: 'Plans' }), (err) => err instanceof FolderError && /was created, but/.test(err.message) && /broken/.test(err.message));
  assert.equal(server.posts.length, 1);
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
const items = [
  { id: 'x', kind: 'artifact', parent: 'A', name: 'x file' },
  { id: 'z', kind: 'artifact', parent: null, name: 'Zebra' },
  { id: 'a2', kind: 'artifact', parent: null, name: 'apple' },
  { id: 'B', kind: 'folder', parent: 'A', name: 'Inner' },
  { id: 'A', kind: 'folder', parent: null, name: 'Work' },
  { id: 'C', kind: 'folder', parent: null, name: 'archive' },
  { id: 'D', kind: 'folder', parent: 'B', name: 'Deep' },
];
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
  assert.deepEqual(subtree(items, 'C'), { artifacts: [], folders: ['C'] });
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
  };
}
function fakeTransfer(data = {}) {
  return {
    data, effectAllowed: '', dropEffect: '', setData(t, v) { this.data[t] = v; }, getData(t) { return this.data[t] ?? ''; },
    get types() { return Object.keys(this.data); },
  };
}
function fire(el, type, dataTransfer) {
  const ev = { dataTransfer, prevented: false, preventDefault() { this.prevented = true; } };
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
