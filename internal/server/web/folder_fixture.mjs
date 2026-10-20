// Fixtures for the shared folder tests (sharing_folders_test.mjs): a fake
// server with a tree of folders and artifacts, each served by its own
// makeShareServer from sharing_fixture.mjs, so chains, wraps, estate copies,
// versions and metadata are real. The router in front of them adds what the
// server does for folders: the kind and parent of each item, inherit, a view a
// caller reads only while its via holds, and the refusals of a record that
// leaves out an entry its folder lists, marks an entry falsely, or names a
// folder other than the one the item sits in (see internal/membership
// checkInherited and RulePlacement, and internal/store/inherit.go), and what
// the server does for other people's items in a folder (internal/server/
// folders.go, internal/store/folders.go): a folder's owner is listed on every
// item inside it by someone else, as an editor via the folder; GET
// /api/artifacts lists an item the caller cannot read, in a folder they read,
// as a stub; an item is placed in a folder by an editor of it, and taken out
// by one, or by its owner; and a folder is deleted unless an item its owner
// owns is still inside, which moves what others own to the top level.
import * as e2e from './e2e.mjs';
import { ORIGIN, buildWorld } from './viewer_fixture.mjs';
import { makeShareServer } from './sharing_fixture.mjs';
import { bodyOf } from './groups_fixture.mjs';

const jsonResponse = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const rank = (role) => (role === 'owner' ? 4 : role === 'manager' ? 3 : role === 'editor' ? 2 : 1);

// makeFolderServer serves items, each {id, kind, parent, owner, members,
// groups, folder, ...worldOpts}: folder is the folder the item's records
// name, its parent unless a test says another; kind is artifact (the default) or folder, parent an
// item's ID or null, and members and groups are the entries of its record
// as buildWorld takes them (a via on an entry marks where it comes from). who
// is the signed-in user, users the directory beyond the owners and members.
// Fields: kids (the share server of each item, by ID, whose fields a test may
// read and change as sharing_fixture.mjs documents), records (every membership
// record the server took, {id, put}), and who. setParent(id, parent) moves an
// item; inheritOf(id) is the inherit its view carries.
export async function makeFolderServer({ who, users = [], items }) {
  const kids = new Map();
  const router = { kids, records: [], posts: [], who, calls: [], moves: [], deleted: [] };
  for (const it of items) {
    const world = await buildWorld({ owner: it.owner, members: it.members ?? [], groups: it.groups ?? [], artifact: it.id, epoch2: it.epoch2, folder: it.folder ?? it.parent ?? '' });
    const kid = makeShareServer(world, { who, users });
    kid.kind = it.kind ?? 'artifact';
    kid.parent = it.parent ?? null;
    kids.set(it.id, kid);
  }
  const primary = kids.values().next().value;
  const wire = (kid) => {
    kid.directory = primary.directory;
    kid.rotations = primary.rotations;
    kid.groups = primary.groups;
    kid.lapsed = () => viaState(kid.world.artifact).lapsed;
    Object.defineProperty(kid, 'who', { get: () => router.who, set: (v) => { router.who = v; }, configurable: true });
  };
  for (const kid of kids.values()) wire(kid);

  const latestOf = (id) => bodyOf(kids.get(id).records.at(-1));
  const ancestors = (id) => {
    const out = [];
    for (let at = kids.get(id)?.parent; at && kids.has(at) && out.length < 32; at = kids.get(at).parent) out.push(at);
    return out;
  };
  const groupExists = (g) => primary.groups.has(g);
  // listing is the entry folder via gives user: their member entry, or, for
  // the folder's owner, the editor entry every item of someone else lists.
  const listing = (via, user) => latestOf(via).members.find((x) => x.user === user) ?? (latestOf(via).owner === user ? { user, role: 'editor' } : undefined);

  // viaState is store.viaState: the users and groups whose via no longer
  // holds, and whether a via entry holds a higher role than its folder lists.
  const viaState = (id) => {
    const latest = latestOf(id);
    const anc = ancestors(id);
    const lapsed = { users: new Set(), groups: new Set() };
    let lowered = false;
    const check = (via, who, key) => (anc.includes(via) ? (key === 'members' ? listing(via, who) : (latestOf(via)[key] ?? []).find((x) => x.group === who)) : undefined);
    for (const m of latest.members.filter((x) => x.via)) {
      const f = check(m.via, m.user, 'members');
      if (!f) lapsed.users.add(m.user);
      else lowered ||= rank(m.role) > rank(f.role);
    }
    for (const g of (latest.groups ?? []).filter((x) => x.via)) {
      const f = check(g.via, g.group, 'groups');
      if (!f) lapsed.groups.add(g.group);
      else lowered ||= rank(g.role) > rank(f.role);
    }
    return { lapsed, lowered };
  };

  // inheritOf is store.InheritPending.
  const inheritOf = (id) => {
    const { lapsed, lowered } = viaState(id);
    if (lapsed.users.size > 0 || lapsed.groups.size > 0 || lowered) return 'pending';
    const parent = kids.get(id).parent;
    // A record that names another folder than the item sits in is pending, as
    // after a move until the owner writes the placement.
    if ((latestOf(id).folder ?? '') !== (parent ?? '')) return 'pending';
    if (!parent || !kids.has(parent)) return 'ok';
    const latest = latestOf(id);
    const folder = latestOf(parent);
    const ownerMissing = folder.owner !== latest.owner && primary.directory.has(folder.owner) && !(latest.members.find((m) => m.user === folder.owner) && rank(latest.members.find((m) => m.user === folder.owner).role) >= rank('editor'));
    const missing = ownerMissing || folder.members.some((p) => p.user !== latest.owner && !(latest.members.find((m) => m.user === p.user) && rank(latest.members.find((m) => m.user === p.user).role) >= rank(p.role)))
      || (folder.groups ?? []).some((p) => groupExists(p.group) && !((latest.groups ?? []).find((g) => g.group === p.group) && rank((latest.groups ?? []).find((g) => g.group === p.group).role) >= rank(p.role)));
    return missing ? 'pending' : 'ok';
  };

  // levelOf is how the signed-in user stands in an item: the owner, or a listed
  // member whose via holds, at no more than the folder lists them as.
  const levelOf = (id) => {
    const latest = latestOf(id);
    if (router.who.id === latest.owner) return 'owner';
    const m = latest.members.find((x) => x.user === router.who.id);
    if (!m) return '';
    if (!m.via) return m.role;
    const f = ancestors(id).includes(m.via) ? listing(m.via, m.user) : null;
    return f ? (rank(f.role) < rank(m.role) ? f.role : m.role) : '';
  };

  // checkInherited is membership.checkInherited, with the folder rule.
  const checkInherited = (id, kind, parent, body) => {
    if (kind === 'folder' && (body.team !== 'none' || body.public || body.publicWrites)) return 'folder: a folder lists users and groups only';
    const anc = parent ? [parent, ...ancestors(parent)] : [];
    for (const m of body.members.filter((x) => x.via)) {
      if (!anc.includes(m.via) || !listing(m.via, m.user)) return `via: member ${m.user} via ${m.via}: that folder does not contain the item and list them`;
    }
    for (const g of (body.groups ?? []).filter((x) => x.via)) {
      if (!anc.includes(g.via) || !(latestOf(g.via).groups ?? []).some((x) => x.group === g.group)) return `via: group ${g.group} via ${g.via}: that folder does not contain the item and list it`;
    }
    if (!parent || !kids.has(parent)) return '';
    const folder = latestOf(parent);
    for (const p of folder.members) {
      if (p.user === body.owner || !primary.directory.has(p.user)) continue; // a user the directory no longer serves is not required, as the server does
      const m = body.members.find((x) => x.user === p.user);
      if (!m) return `inherit: member ${p.user} is missing: folder ${parent} lists them as ${p.role}`;
      if (rank(m.role) < rank(p.role)) return `inherit: member ${p.user} is ${m.role}: folder ${parent} lists them as ${p.role}`;
    }
    // The folder's owner reads what is in it: an editor entry, via the folder,
    // while their account is one the directory serves.
    if (folder.owner !== body.owner && primary.directory.has(folder.owner)) {
      const m = body.members.find((x) => x.user === folder.owner);
      if (!m) return `inherit: member ${folder.owner} is missing: folder ${parent} lists them as editor`;
      if (rank(m.role) < rank('editor')) return `inherit: member ${folder.owner} is ${m.role}: folder ${parent} lists them as editor`;
    }
    for (const p of folder.groups ?? []) {
      if (!groupExists(p.group)) continue;
      const g = (body.groups ?? []).find((x) => x.group === p.group);
      if (!g) return `inherit: group ${p.group} is missing: folder ${parent} lists it as ${p.role}`;
      if (rank(g.role) < rank(p.role)) return `inherit: group ${p.group} is ${g.role}: folder ${parent} lists it as ${p.role}`;
    }
    return '';
  };

  // viewOf is the artifact view the server serves: the kid's own, with inherit,
  // the owner and the caller's access, and the parent only while the caller can
  // read it.
  const viewOf = async (id, resp) => {
    const view = await resp.json();
    const readable = (x) => kids.has(x) && levelOf(x) !== '';
    return { ...view, owner: latestOf(id).owner, access: levelOf(id), inherit: inheritOf(id), parent: view.parent && readable(view.parent) ? view.parent : null, public: false };
  };

  // stubOf is stubView: what the list says of an item the caller cannot read.
  const stubOf = (id) => ({ id, kind: kids.get(id).kind, owner: latestOf(id).owner, parent: kids.get(id).parent, inherit: 'pending', access: 'none' });

  // move is handlePutParent: entering a folder needs the right to manage the
  // item and editor access to the folder; leaving one needs editor access to
  // the folder, or ownership of the item; a folder's editor who does not
  // manage the item may only remove it. The caller may know of the item only
  // through the folder, which lists it as a stub.
  const move = async (id, target) => {
    const kid = kids.get(id);
    const level = levelOf(id);
    const seen = level !== '' || Boolean(kid.parent && kids.has(kid.parent) && levelOf(kid.parent) !== '');
    const entering = target !== null && target !== kid.parent;
    const leaving = kid.parent !== null && target !== kid.parent;
    const manages = level === 'owner' || level === 'manager';
    if (!manages && (entering || !leaving)) return seen ? jsonResponse(403, { error: "only the item's owner or a manager places it in a folder" }) : jsonResponse(404, { error: 'artifact not found' });
    if (leaving && level !== 'owner' && rank(levelOf(kid.parent)) < rank('editor')) return seen ? jsonResponse(403, { error: 'you need editor access to the folder the item sits in' }) : jsonResponse(404, { error: 'artifact not found' });
    if (entering) {
      if (!kids.has(target) || levelOf(target) === '') return jsonResponse(404, { error: 'folder not found' });
      if (rank(levelOf(target)) < rank('editor')) return jsonResponse(403, { error: 'you need editor access to the folder' });
    }
    kid.parent = target;
    router.moves.push({ id, target, by: router.who.id });
    // What the caller reads is judged after the move: an editor who removes an
    // item they read only through the folder gets its stub.
    if (levelOf(id) === '') return jsonResponse(200, stubOf(id));
    return jsonResponse(200, await viewOf(id, await kid.fetch(`/api/artifacts/${id}`)));
  };

  // remove is handleDeleteArtifact: only the owner deletes, and a folder only
  // while no item its owner owns is inside (DeleteFolderIfNoneOwned); what
  // others own moves to the top level, as ON DELETE SET NULL does.
  const remove = (id) => {
    const kid = kids.get(id);
    if (levelOf(id) !== 'owner') return jsonResponse(levelOf(id) === '' ? 404 : 403, { error: 'only the owner deletes' });
    const owner = latestOf(id).owner;
    const inside = [...kids.keys()].filter((k) => kids.get(k).parent === id);
    if (kid.kind === 'folder' && inside.some((k) => latestOf(k).owner === owner)) return jsonResponse(409, { error: 'the folder is not empty' });
    for (const k of inside) kids.get(k).parent = null;
    kids.delete(id);
    router.deleted.push(id);
    return new Response(null, { status: 204 });
  };

  // create is POST /api/artifacts: the first record of a new item, checked as
  // the server checks one, then served like any other item.
  const create = async (body) => {
    // parentRefusal: the folder must be readable, and the caller an editor of it.
    if (body.parent) {
      if (!kids.has(body.parent) || levelOf(body.parent) === '') return jsonResponse(404, { error: 'folder not found' });
      if (rank(levelOf(body.parent)) < rank('editor')) return jsonResponse(403, { error: 'you need editor access to the folder' });
    }
    const signed = JSON.parse(new TextDecoder().decode(e2e.unb64(body.membership.body)));
    const refused = checkInherited(body.id, body.kind ?? 'artifact', body.parent ?? null, signed);
    if (refused) return jsonResponse(409, { error: refused });
    if ((signed.folder ?? '') !== (body.parent ?? '')) return jsonResponse(409, { error: `placement: folder ${signed.folder ?? ''} is not the folder the item sits in, ${body.parent ?? ''}` });
    const owner = primary.userById.get(signed.owner);
    const wraps = {};
    for (const w of body.wraps) wraps[w.user] = [...(wraps[w.user] ?? []), { epoch: w.epoch, wrapped: w.wrapped, fp: primary.userById.get(w.user).fp }];
    const world = { artifact: body.id, owner, aks: {}, records: [body.membership], estate: body.estate, wraps, owners: { [owner.fp]: owner.pair }, members: [], top: 1, isPublic: false };
    const kid = makeShareServer(world, { who: router.who, users: [...primary.userById.values()] });
    kid.kind = body.kind ?? 'artifact';
    kid.parent = body.parent ?? null;
    wire(kid);
    kids.set(body.id, kid);
    router.posts.push(body);
    return jsonResponse(201, { id: body.id });
  };

  router.fetch = async (path, init = {}) => {
    const method = init.method ?? 'GET';
    router.calls.push({ method, path });
    const p = new URL(path, ORIGIN).pathname;
    if (p === '/api/artifacts' && method === 'GET') {
      const out = [];
      for (const id of kids.keys()) {
        if (levelOf(id) !== '') out.push(await viewOf(id, await kids.get(id).fetch(`/api/artifacts/${id}`)));
      }
      // An item the caller cannot read, inside a folder they can, is a stub.
      for (const id of kids.keys()) {
        const parent = kids.get(id).parent;
        if (levelOf(id) === '' && parent && kids.has(parent) && levelOf(parent) !== '') out.push(stubOf(id));
      }
      return jsonResponse(200, out);
    }
    if (p === '/api/artifacts' && method === 'POST') return create(JSON.parse(init.body));
    const m = /^\/api\/artifacts\/([^/]+)(?:\/(.*))?$/.exec(p);
    if (!m) return primary.fetch(path, init);
    const kid = kids.get(m[1]);
    if (!kid) return jsonResponse(404, { error: 'not found' });
    const rest = m[2] ?? '';
    if (rest === '' && method === 'GET') {
      if (levelOf(m[1]) === '') return jsonResponse(404, { error: 'artifact not found' });
      return jsonResponse(200, await viewOf(m[1], await kid.fetch(path, init)));
    }
    if (rest === '' && method === 'DELETE') return remove(m[1]);
    if (rest === 'membership' && method === 'PUT') {
      const body = JSON.parse(init.body);
      const signed = JSON.parse(new TextDecoder().decode(e2e.unb64(body.membership.body)));
      const latest = latestOf(m[1]);
      // RulePlacement comes before the inherited entries: the record names the
      // folder the item sits in, and a manager's record keeps the folder,
      // which only the owner moves.
      let refused = '';
      if ((signed.folder ?? '') !== (kid.parent ?? '')) refused = `placement: folder ${signed.folder ?? ''} is not the folder the item sits in, ${kid.parent ?? ''}`;
      if (!refused && signed.signer && (signed.folder ?? '') !== (latest.folder ?? '')) refused = 'a manager cannot change the folder';
      if (!refused) refused = checkInherited(m[1], kid.kind, kid.parent, signed);
      // A next epoch drops no member it does not exclude.
      if (!refused && signed.epoch > latest.epoch) {
        const lost = latest.members.find((x) => !signed.members.some((y) => y.user === x.user) && !signed.excluded.some((y) => y.user === x.user));
        if (lost) refused = `excluded: ${lost.user} is dropped and not excluded`;
      }
      if (refused) return jsonResponse(409, { error: refused });
      const resp = await kid.fetch(path, init);
      if (resp.ok) router.records.push({ id: m[1], body: signed, put: body });
      return resp;
    }
    // PUT .../parent moves the item: the tree changes, the record does not.
    if (rest === 'parent' && method === 'PUT') return move(m[1], JSON.parse(init.body).parent ?? null);
    return kid.fetch(path, init);
  };
  router.setParent = (id, parent) => { kids.get(id).parent = parent; };
  router.inheritOf = inheritOf;
  router.levelOf = levelOf;
  router.latestOf = latestOf;
  router.primary = primary;
  return router;
}
