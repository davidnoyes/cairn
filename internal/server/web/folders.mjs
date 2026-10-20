// folders.mjs — folders on the Artifacts tab: creating one in the browser, the
// tree of the caller's own items, moving an item, deleting a folder with what
// it holds, and the drag and drop that moves a row. The rules are in
// design/e2e-api.md ("Folders"). A folder is an artifact with no content: it
// has its own key, a signed membership chain, and an encrypted name, so
// creating one mirrors the Go client's CreateArtifact.
//
// The tree functions take `items`, entries of GET /api/artifacts as
// {id, kind, parent, name, owner, access, inherit}, with name already read (a
// stub has none, and shows its ID). Nothing here reads a browser global;
// app.mjs passes in what it needs.
import * as e2e from './e2e.mjs';
import { call, openArtifact, signedInCaller } from './viewer.mjs';
import { writeMeta } from './meta.mjs';
import { approveListedGroups, canSign, fanOut, inheritFirst } from './sharing.mjs';

// FolderError is a refusal the page can show as it is. created is true when
// the folder exists anyway, so the page must not offer to create it again.
export class FolderError extends Error {
  constructor(message, { created = false } = {}) {
    super(message);
    this.name = 'FolderError';
    this.created = created;
  }
}

const encoder = new TextEncoder();

// cleanName is the name to write, or a FolderError for a blank one.
function cleanName(name) {
  const clean = String(name).trim();
  if (clean === '') throw new FolderError('Give the folder a name.');
  return clean;
}

// createFolder creates a private folder owned by the caller, inside parent
// (a folder ID, or null for the top level), and writes its name. It makes the
// ID and the first AK, signs the owner's first membership record (no members,
// no team, private), and seals the estate copy of the AK under EK. It then
// opens the folder, which checks the chain the server stored, and writes the
// name under the AK. Inside a shared folder it lists every user and group the
// parent lists, marked with the parent's name for them, as the server refuses
// a record without them, with a wrap of the first AK for each user; the
// members of each group are approved once it exists. It returns {id}. Mirrors
// CreateArtifact.
export async function createFolder(deps, { name, parent = null }) {
  const clean = cleanName(name);
  const caller = await signedInCaller(deps);
  if (!caller?.record) throw new FolderError('Sign in to create a folder.');
  const id = crypto.randomUUID();
  const ak = crypto.getRandomValues(new Uint8Array(32));
  const first = {
    v: 1,
    artifact: id,
    epoch: 1,
    seq: 1,
    owner: caller.record.userId,
    ownerFp: caller.fp,
    akCommit: await e2e.akCommit(ak, id, 1),
    members: [],
    excluded: [],
    team: 'none',
  };
  const wraps = parent === null ? [] : await inheritFirst(deps, first, parent, ak);
  const body = encoder.encode(JSON.stringify({
    ...first,
    public: false,
    publicWrites: false,
    prev: '',
    transfer: '',
    handover: '',
  }));
  const membership = await e2e.newEnvelope(caller.record.ed25519, caller.record.userId, 'membership', body);
  const ekKey = await e2e.ekSealCryptoKey(caller.record.ek);
  const estate = [{ epoch: 1, sealed: e2e.b64(await e2e.seal(ekKey, ['estate', id, '1'], ak)) }];
  const req = { id, kind: 'folder', membership, wraps, estate };
  if (parent !== null) req.parent = parent;
  await call(deps, null, 'POST', '/api/artifacts', { body: req });
  try {
    await writeName(deps, id, clean);
  } catch (err) {
    throw new FolderError(`The folder was created without a name, and can be renamed. Writing the name failed: ${err.message}`, { created: true });
  }
  // A member of a group the folder lists waits until someone approves them.
  // A group that does not verify leaves its members to whoever can.
  await approveListedGroups(deps, id, (first.groups ?? []).map((g) => g.group));
  return { id };
}

async function writeName(deps, id, name) {
  const opened = await openArtifact(deps, { artifact: id, link: null });
  await writeMeta(deps, opened, '', 'name', name);
}

// renameFolder writes a new name for the folder.
export async function renameFolder(deps, id, name) {
  await writeName(deps, id, cleanName(name));
}

// ------------------------------------------------------- other people's items

// isStub says whether the list entry a is a stub: an item in a folder the
// caller reads that they cannot read themselves yet. The server gives it no
// name, no key and no member list, and its access is none.
export const isStub = (a) => a.access === 'none';

// canEdit says whether the caller may put items in the folder a, and take
// other people's out: editor access, or manager or owner.
export const canEdit = (a) => ['editor', 'manager', 'owner'].includes(a.access);

// stubLabel is what the page says of a stub in place of a name: dir is the
// directory, {id, email}, and an owner it does not hold shows as the ID.
export const stubLabel = (a, dir) => `not shared with you yet, owned by ${dir.find((u) => u.id === a.owner)?.email ?? a.owner}`;

// treeItem is the entry of the folder trees for the list entry a.
const treeItem = (a) => ({ id: a.id, kind: a.kind ?? 'artifact', parent: a.parent ?? null, name: a.id, owner: a.owner, access: a.access, inherit: a.inherit ?? 'ok' });

// splitTrees puts every entry of the list in one of two trees, as tree items:
// an entry sits in the tree of the folder the server lists it in, when that
// folder is in the list, so an item someone else owns shows inside the
// caller's folder, and the caller's own item inside someone else's folder.
// An entry with no folder in the list is at the top of the caller's own tree
// when me (the caller's user ID) owns it, and of Shared with you otherwise.
export function splitTrees(list, me) {
  const byId = new Map(list.map((a) => [a.id, a]));
  const ownTree = (a, seen = new Set()) => {
    const folder = byId.get(a.parent);
    if (!folder || folder.kind !== 'folder' || seen.has(a.id)) return a.owner === me;
    return ownTree(folder, seen.add(a.id));
  };
  const own = [];
  const shared = [];
  for (const a of list) (ownTree(a) ? own : shared).push(treeItem(a));
  return { own, shared };
}

// describeList reads the name of each entry of the list with describe(a), in
// turn, and passes it to each(a, got). A stub is skipped: its name is sealed
// under a key the caller does not hold yet, so nothing in it can be read.
export async function describeList(list, describe, each) {
  for (const a of list) {
    if (isStub(a)) continue;
    await each(a, await describe(a));
  }
}

// applicable lists the entries the caller can apply: pending items they own
// or manage, who alone sign the record that brings an item in step.
export const applicable = (items) => items.filter((a) => a.inherit === 'pending' && canSign(a));

// nextAttempt decides whether the page applies on its own: todo is the IDs of
// the applicable items it has not tried yet, and tried is what to remember
// for the next list, the items still pending. An item that stays pending after
// an apply, because it waits on someone else or failed, is not tried again
// until it has been current and turned pending again, so the page never loops;
// a reload of the page starts with nothing tried.
export function nextAttempt(items, tried) {
  const pending = applicable(items).map((a) => a.id);
  return { todo: pending.filter((id) => !tried.has(id)), tried: new Set(pending) };
}

// canRemoveFromFolder says whether the caller (user ID me) may take the item
// id out of the folder it sits in, as an editor of the folder: it is someone
// else's, a stub too, and the folder is one the caller may edit. The server
// moves it to its owner's top level. Its owner may also take it out of a
// folder they can no longer read, which the server marks hiddenParent, as
// the server lets them.
export function canRemoveFromFolder(items, id, me) {
  const item = items.find((i) => i.id === id);
  if (item?.hiddenParent && item.owner === me) return true;
  const folder = items.find((i) => i.id === item?.parent && i.kind === 'folder');
  return Boolean(item && folder && item.owner !== me && canEdit(folder));
}

// rowActions is the controls a row offers, by name, for the entry a: the
// owner's own item Share, Move and Delete, and Rename for a folder; Share for a
// manager and Approve for an editor; and Remove from folder as
// canRemoveFromFolder allows. A stub, whose access is none, has nothing
// but the last: no Share, Move, Delete, nor Open.
export function rowActions(a, items, me) {
  const out = [];
  if (a.owner === me) {
    if (a.kind === 'folder') out.push('rename');
    out.push('share', 'move', 'delete');
  } else if (a.access === 'manager') {
    out.push('share');
  } else if (a.access === 'editor') {
    out.push('approve');
  }
  if (canRemoveFromFolder(items, a.id, me)) out.push('remove');
  return out;
}

// ------------------------------------------------------------------ tree

const byName = (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

// placeOf is the folder an item shows in: its parent when that is a folder in
// the list, else the top level, so an item whose folder cannot be seen is
// still reachable.
function placeOf(items, item) {
  return item.parent !== null && items.some((f) => f.id === item.parent && f.kind === 'folder') ? item.parent : null;
}

// childrenOf lists what sits in folder (null for the top level): folders
// first, then artifacts, each sorted by name, then ID.
export function childrenOf(items, folder) {
  const here = items.filter((i) => placeOf(items, i) === folder);
  return [...here.filter((i) => i.kind === 'folder').sort(byName), ...here.filter((i) => i.kind !== 'folder').sort(byName)];
}

// pathOf is the folders from the top level down to the one named, as items.
// A loop in the parents the server sent ends the walk.
function pathOf(items, folder) {
  const path = [];
  const seen = new Set();
  for (let at = items.find((i) => i.id === folder && i.kind === 'folder'); at && !seen.has(at.id); at = items.find((i) => i.id === placeOf(items, at))) {
    seen.add(at.id);
    path.unshift(at);
  }
  return path;
}

// breadcrumb is the segments over the table: the top level, then each folder
// down to the one in view. A folder that is not in the list reads as the top.
export function breadcrumb(items, folder) {
  return [{ id: null, name: 'Top' }, ...pathOf(items, folder).map((f) => ({ id: f.id, name: f.name }))];
}

// canMoveInto says whether item may go into target (a folder ID or null): not
// into itself, and not into a folder inside it.
export function canMoveInto(items, id, target) {
  return !pathOf(items, target).some((f) => f.id === id);
}

// canPlaceIn says whether the caller may put an item in target, a folder ID or
// null for their own top level: a folder they may edit, whoever owns it.
export function canPlaceIn(items, target) {
  if (target === null) return true;
  const folder = items.find((i) => i.id === target && i.kind === 'folder');
  return Boolean(folder && canEdit(folder));
}

// moveTargets is where an item may go: the top level, then every folder it
// may move into, in tree order, each labelled by its path. A folder someone
// else owns is offered when the caller may edit it.
export function moveTargets(items, id) {
  const out = [{ id: null, label: 'Top level' }];
  const walk = (folder, prefix) => {
    for (const f of childrenOf(items, folder).filter((i) => i.kind === 'folder')) {
      const label = prefix + f.name;
      if (canMoveInto(items, id, f.id) && canEdit(f)) out.push({ id: f.id, label });
      walk(f.id, label + ' / ');
    }
  };
  walk(null, '');
  return out;
}

// subtree is what deleting the folder takes with it: the artifact IDs, and the
// folder IDs deepest first, with the folder itself last, of the items its owner
// owns, down to any folder someone else owns; and moved, the IDs of the items
// someone else owns that sit in a folder being deleted, which the server moves
// to their owners' top level, a folder with everything inside it.
export function subtree(items, folder) {
  const artifacts = [];
  const folders = [];
  const moved = [];
  const root = items.find((i) => i.id === folder);
  // A folder the list does not hold has no owner to compare with: nothing goes
  // and nothing moves, rather than every child counting as moved.
  if (!root) return { artifacts, folders, moved };
  const owner = root.owner;
  const walk = (f) => {
    for (const c of childrenOf(items, f)) {
      if (c.owner !== owner) moved.push(c.id);
      else if (c.kind === 'folder') walk(c.id); else artifacts.push(c.id);
    }
    folders.push(f);
  };
  walk(folder);
  return { artifacts, folders, moved };
}

// deleteSummary is the question a folder's Delete asks again, from subtree's
// result: how many of the owner's items go, and how many of other people's
// move, and whose they are: items is the list the owners are read from, and dir
// the directory, which names an owner by address and falls back to their ID, as
// stubLabel does. Each owner is named once, in order of that name.
export function deleteSummary(t, items, dir) {
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const gone = `${plural(t.folders.length, 'folder', 'folders')} and ${plural(t.artifacts.length, 'artifact', 'artifacts')}`;
  if (t.moved.length === 0) return `Delete ${gone}?`;
  const owners = [...new Set(t.moved.map((id) => items.find((i) => i.id === id)?.owner))]
    .map((id) => dir.find((u) => u.id === id)?.email ?? id)
    .sort();
  return `Delete ${gone} of yours, and move ${plural(t.moved.length, 'item', 'items')} other people own (${owners.join(', ')}) to their owners' top level?`;
}

// ------------------------------------------------------------ move, delete

// moveItem puts the item in target, a folder ID or null. send is app.mjs's
// (method, path, body). It sends nothing and returns false when the item is
// there already, and refuses a folder moved into itself or a folder inside
// it. It returns true after a move.
export async function moveItem(send, items, id, target) {
  const item = items.find((i) => i.id === id);
  if (!canMoveInto(items, id, target)) throw new FolderError('A folder cannot move into itself or into a folder inside it.');
  if (!canPlaceIn(items, target)) throw new FolderError('You need editor access to that folder to put items in it.');
  if (item && (item.parent ?? null) === target) return false;
  await send('PUT', `/api/artifacts/${id}/parent`, { parent: target });
  return true;
}

// moveAndPlace moves the item as moveItem does and, after a move, writes the
// placement: the owner's record of the item names the new folder (null is the
// top level), and fanOut copies that folder's entries into it, and into
// everything inside it when it is a folder. send is app.mjs's (method, path,
// body), deps what sharing.mjs takes, and progress (done, total) is called as
// fanOut calls it. It returns null when nothing moved, else fanOut's result
// {items, total, failed}.
export async function moveAndPlace(deps, send, items, id, target, progress) {
  if (!(await moveItem(send, items, id, target))) {
    // Moving a pending item to the folder it already sits in places it there
    // again: the caller chose the folder, so a placement that failed earlier
    // can be finished this way. Anything else that moves nothing does nothing.
    const it = items.find((i) => i.id === id);
    if (!it || (it.parent ?? null) !== target || it.inherit !== 'pending') return null;
    // The list hides a folder the caller cannot read, so a pending item shown at
    // the top level may still sit in one. Its owner may always take it out,
    // which the server does for a move to the top level.
    if (target === null) await send('PUT', `/api/artifacts/${id}/parent`, { parent: null });
  }
  return fanOut(deps, id, { includeRoot: true, placing: target, progress });
}

// removeFromFolder takes the item id out of the folder it sits in, as
// canRemoveFromFolder allows: the server puts it at the top level of its
// owner, and nothing is written to its record. send is app.mjs's
// (method, path, body), me the caller's user ID.
export async function removeFromFolder(send, items, id, me) {
  if (!canRemoveFromFolder(items, id, me)) throw new FolderError('You can only remove an item from a folder you may edit, or your own item from a folder you can no longer read.');
  await send('PUT', `/api/artifacts/${id}/parent`, { parent: null });
}

// deleteTree deletes every item the folder's owner owns under it, artifacts,
// then the folders deepest first, then the folder, calling progress(done,
// total) after each. del(id) deletes one item. An item the server no longer
// has is skipped, so running it again finishes an interrupted delete. What
// other people own is not deleted: the server moves it to its owner's top level
// when the folder goes. It returns the number of items.
export async function deleteTree(del, items, folder, progress) {
  const { artifacts, folders } = subtree(items, folder);
  const all = [...artifacts, ...folders];
  let done = 0;
  for (const id of all) {
    try {
      await del(id);
    } catch (err) {
      if (err.status !== 404) throw err;
    }
    progress(++done, all.length);
  }
  return all.length;
}

// ------------------------------------------------------------ drag and drop

const DRAG_TYPE = 'application/x-cairn-item';

// makeDraggable lets a row be dragged, carrying the item's ID.
export function makeDraggable(el, id) {
  el.draggable = true;
  el.addEventListener('dragstart', (event) => {
    // A drag picked up by the row's name link carries the link's URL, which
    // a browser opens if the drop misses every target. Carry the ID alone.
    event.dataTransfer.clearData();
    event.dataTransfer.setData(DRAG_TYPE, id);
    event.dataTransfer.effectAllowed = 'move';
  });
}

// makeDropTarget lets a dragged row land on el, a folder row or a breadcrumb
// segment: move(id, target) runs on a drop. target is the folder's ID, or
// null for the top level. A drag of anything else is left alone.
export function makeDropTarget(el, target, move) {
  const ours = (event) => Array.from(event.dataTransfer?.types ?? []).includes(DRAG_TYPE);
  el.addEventListener('dragover', (event) => {
    if (!ours(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
    el.classList.add('drop');
  });
  // dragleave also fires when the pointer crosses into a child of el.
  el.addEventListener('dragleave', (event) => {
    if (event.relatedTarget && el.contains(event.relatedTarget)) return;
    el.classList.remove('drop');
  });
  el.addEventListener('drop', (event) => {
    el.classList.remove('drop');
    const id = event.dataTransfer?.getData(DRAG_TYPE);
    if (!id) return;
    event.preventDefault();
    move(id, target);
  });
}
