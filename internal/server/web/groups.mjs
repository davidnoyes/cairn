// groups.mjs — what the browser does to a group: list groups, read one from an
// accepted chain, and add, change, remove, rename, and delete members. A group
// is a chain of signed records (design/e2e-api.md, "Groups"), checked here
// with e2e.mjs against the keyring's groups entry before a member is shown or
// a record is signed. The server is untrusted throughout. It mirrors the Go
// client's group commands, and takes `deps` as sharing.mjs does:
//
//   fetch(path, options)   like window.fetch
//   keyStore               {load()}, see keystore.mjs: the signed-in user's keys
//   storage                localStorage, which holds the keyring anchor
//
// The group view carries each signer's current keys and rotation records, a
// deactivated account's too. They are the server's word, so each is anchored at
// the keyring's pin for that user before it is used, as a share anchors a
// member, and rotationLinker connects the fingerprint a record lists to the one
// that signed.
import * as e2e from './e2e.mjs';
import { ApiError } from './account.mjs';
import { call, readKeyring, signedInCaller, updateKeyring } from './viewer.mjs';
import { checkPin, directory, fatalFetch, findUser, followPinFor, storePin, wasVerified } from './sharing.mjs';

const encoder = new TextEncoder();

// GroupError is a refusal of this module. code says which, for a page that
// answers it: not-signed-in, viewer-account, bad-role, bad-name, not-manager,
// not-member, last-manager, moved, keyring-moved, read-back.
export class GroupError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'GroupError';
    this.code = code;
  }
}

async function unlock(deps) {
  const caller = await signedInCaller(deps);
  if (!caller?.record) throw new GroupError('not-signed-in', 'Sign in to manage a group.');
  return caller;
}

const byUser = (a, b) => (a.user < b.user ? -1 : a.user > b.user ? 1 : 0);
const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// checkName is e2e.checkGroupName as a refusal the page shows.
function checkName(name) {
  try {
    e2e.checkGroupName(name);
  } catch (err) {
    throw new GroupError('bad-name', `A group name is 1 to 100 characters, with no control characters. ${err.message}.`, { cause: err });
  }
}

// ---- reading ----

// listGroups is every group the server lists: id, name, seq, members (the
// count), and role, the caller's own, which is empty for a group they are not
// in. The caller's groups come first. The name and count are the server's
// word until the group is opened.
export async function listGroups(deps) {
  const resp = await call(deps, null, 'GET', '/api/groups');
  if (!Array.isArray(resp)) throw new e2e.FormatError('the list of groups is not a list');
  const groups = resp.map((g) => ({ id: g.id, name: g.name, seq: g.seq, members: g.members, role: g.role ?? '' }));
  const notMine = (g) => (g.role === '' ? 1 : 0);
  return groups.sort((a, b) => notMine(a) - notMine(b) || compare(a.name, b.name) || compare(a.id, b.id));
}

async function fpOf(pair) {
  return e2e.toHex(await e2e.fingerprint(e2e.unb64(pair.x25519), e2e.unb64(pair.ed25519)));
}

// anchorSigners anchors the keys the group view serves for the users who
// signed a record. A signer's current key must be the keyring's pin for them,
// or follow from it by their rotation records: else it is a KeyChangedError
// unless acceptNewKey, and a signer not pinned yet is pinned unverified. The
// caller's own key is their own. A signer the directory still lists must have
// the same current key there as the answer serves, else it is a ChainError: a
// server cannot plant a key of its own for a real user. It returns {keys,
// rotations, pins}: keys maps a fingerprint to the {user, x25519, ed25519}
// that may have signed a record, rotations the records by user, and pins the
// pins to store once the chain verifies. A record may be signed by a signer's
// current key, or by an earlier one their rotation records link to it, and by
// no other: a key the server serves that nothing anchors is not one, and
// verifyGroupChain refuses a record whose key belongs to another user.
// Mirrors anchorSigners in groups.go.
async function anchorSigners(deps, caller, kr, dir, id, view, acceptNewKey) {
  const out = { keys: {}, rotations: {}, pins: new Map() };
  for (const user of new Set(view.records.map((env) => env.signer))) {
    const served = Object.hasOwn(view.signers ?? {}, user) ? view.signers[user] : null;
    if (!served) throw new e2e.ChainError(`the server did not serve the keys of ${user}, who signed a record of group ${id}`);
    out.rotations[user] = served.rotations ?? [];
    const own = user === caller.record.userId;
    const cur = own
      ? { x25519: e2e.b64(caller.record.x25519.publicKey), ed25519: e2e.b64(caller.record.ed25519Pub) }
      : { x25519: served.x25519, ed25519: served.ed25519 };
    let x25519Pub;
    let ed25519Pub;
    try {
      x25519Pub = e2e.unb64(cur.x25519);
      ed25519Pub = e2e.unb64(cur.ed25519);
    } catch (err) {
      throw new e2e.FormatError(`the keys the server served for ${user} are not base64`, { cause: err });
    }
    if (x25519Pub.length !== 32 || ed25519Pub.length !== 32) throw new e2e.FormatError(`the keys the server served for ${user} are not 32 bytes each`);
    const curFp = await fpOf(cur);
    if (!own) {
      const listed = dir.find((d) => d.id === user);
      const u = { id: user, email: listed?.email ?? user, resetAt: listed?.resetAt ?? '', x25519Pub, ed25519Pub, fp: curFp };
      const { pin } = await checkPin(deps, kr, u, acceptNewKey, out.rotations);
      if (listed && listed.fp !== curFp) {
        throw new e2e.ChainError(
          `the keys the server served for ${listed.email}, who signed a record of group ${id}, are not the ones the directory lists for them`,
        );
      }
      if (pin) out.pins.set(user, pin);
    }
    const linked = e2e.rotationLinker(out.rotations);
    out.keys[curFp] = { user, ...cur };
    for (const env of out.rotations[user]) {
      let b;
      try {
        b = e2e.decodeStrict(e2e.unb64(env.body), e2e.BODY_SCHEMAS.rotation);
      } catch {
        continue; // A rotation record that does not parse links nothing.
      }
      for (const pair of [b.old, b.new]) {
        let fp;
        try {
          fp = await fpOf(pair);
        } catch {
          continue;
        }
        if (await linked(user, fp, curFp)) {
          out.keys[fp] = { user, ...pair };
        }
      }
    }
  }
  return out;
}

// acceptGroup verifies the records of a group view against the keyring's
// groups entry, with each signer's keys anchored by anchorSigners, and stores
// the new seq and head there, and the pins of signers seen for the first time
// or whose keys rotated. It returns {chain, rotations, dir, keyring}. A chain
// shorter than the stored seq, or forked at it, is refused and nothing is
// stored. The keyring's entry never goes back: if another device stored a
// newer head after this chain was checked, it throws GroupError keyring-moved
// and openGroup reads the group again.
async function acceptGroup(deps, caller, id, view, acceptNewKey) {
  const records = view.records;
  if (!Array.isArray(records) || records.length === 0) throw new e2e.ChainError('no records');
  const kr = await readKeyring(deps, caller);
  const dir = await directory(deps);
  const signers = await anchorSigners(deps, caller, kr, dir, id, view, acceptNewKey);
  const { keys, rotations } = signers;
  const pin = Object.hasOwn(kr.groups ?? {}, id) ? kr.groups[id] : null;
  const chain = await e2e.verifyGroupChain({ group: id, records, keys, pin, linked: e2e.rotationLinker(rotations) });
  for (const [user, decided] of signers.pins) {
    await storePin(deps, caller, user, decided, Object.hasOwn(kr.pins, user) ? kr.pins[user].fp : '');
  }
  const moved = () => new GroupError('keyring-moved', 'Another device updated this group while it was being read. Try again.');
  const entryOf = (k) => (Object.hasOwn(k.groups ?? {}, id) ? k.groups[id] : null);
  let keyring;
  if (!pin || pin.seq < chain.seq) {
    keyring = await updateKeyring(deps, caller, (k) => {
      const cur = entryOf(k);
      if (cur && cur.seq === chain.seq && cur.head !== chain.head) throw new e2e.ForkError(`record ${cur.seq} of group ${id}`);
      if (cur && cur.seq > chain.seq) throw moved();
      if (!cur || cur.seq < chain.seq) {
        k.groups ??= {};
        k.groups[id] = { seq: chain.seq, head: chain.head };
      }
    });
  } else {
    // Nothing to write, but another device may have stored a newer head
    // since the keyring was read.
    keyring = await readKeyring(deps, caller);
    const held = entryOf(keyring);
    if (held && held.seq > chain.seq) throw moved();
  }
  return { chain, rotations, dir, keyring };
}

// openGroup reads a group and accepts its chain. If the keyring moved on
// meanwhile, it reads the group once more, so the chain shown is checked
// against the newer head.
async function openGroup(deps, caller, id, acceptNewKey) {
  for (let attempt = 0; ; attempt++) {
    const view = await call(deps, null, 'GET', `/api/groups/${id}`);
    try {
      return { view, ...(await acceptGroup(deps, caller, id, view, acceptNewKey)) };
    } catch (err) {
      if (!(err instanceof GroupError && err.code === 'keyring-moved' && attempt === 0)) throw err;
    }
  }
}

// callerRole is the role the latest record lists the caller under, or ''.
const callerRole = (caller, latest) => latest.members.find((m) => m.user === caller.record.userId)?.role ?? '';

// groupMembers opens a group and lists it from the chain it accepted: the
// name, the seq, the caller's role, and each member with their role, the
// fingerprint the record lists, the directory's current fingerprint (empty
// for a user it no longer lists), their account role (a viewer account is
// never a manager), and a pin state: self for the caller, - for
// a user the directory no longer lists, a pin state otherwise, and conflict
// when their rotation records fork or roll back. A signer whose key changed
// is a KeyChangedError unless acceptNewKey.
export async function groupMembers(deps, id, { acceptNewKey = false } = {}) {
  const caller = await unlock(deps);
  const { chain, rotations, dir, keyring } = await openGroup(deps, caller, id, acceptNewKey);
  const latest = chain.latest;
  const byId = new Map(dir.map((u) => [u.id, u]));
  const rows = [];
  for (const m of latest.members) {
    const u = byId.get(m.user);
    const row = { user: m.user, role: m.role, fp: m.fp, name: u?.name ?? '', email: u?.email ?? '', currentFp: u?.fp ?? '', account: u?.role ?? '', state: '', wasVerified: false };
    if (m.user === caller.record.userId) {
      row.state = 'self';
    } else if (!u) {
      row.state = '-';
    } else {
      const { state, fork, fetchErr } = await followPinFor(deps, keyring, u, rotations);
      if (fatalFetch(fetchErr)) throw fetchErr;
      row.state = fork ? 'conflict' : state;
      row.wasVerified = wasVerified(keyring, m.user, row.state);
    }
    rows.push(row);
  }
  return { id, name: latest.name, seq: latest.seq, callerRole: callerRole(caller, latest), members: rows };
}

// ---- writing ----

// putRecord signs the record that follows chain's latest, with the members
// and name given, and sends it. A 409 means another record won the race. The
// answer is read back like any group: the record it ends in must be this one.
async function putRecord(deps, caller, id, chain, { name, members }) {
  checkName(name);
  const body = {
    v: 1, group: id, seq: chain.seq + 1, prev: chain.head, name,
    members: [...members].sort(byUser).map((m) => ({ user: m.user, fp: m.fp, role: m.role })),
    signer: caller.record.userId, signerFp: caller.fp,
  };
  const record = await e2e.newEnvelope(caller.record.ed25519, caller.record.userId, 'group', encoder.encode(JSON.stringify(body)));
  let view;
  try {
    view = await call(deps, null, 'PUT', `/api/groups/${id}`, { body: { record } });
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      throw new GroupError('moved', 'Someone changed this group first. It was read again: try the change again.', { cause: err });
    }
    throw err;
  }
  await readBack(deps, caller, id, view, body.seq);
}

// readBack accepts the group the server answered a write with, whose latest
// record must be the one this client signed.
async function readBack(deps, caller, id, view, seq) {
  try {
    const { chain } = await acceptGroup(deps, caller, id, view, false);
    if (chain.seq !== seq || chain.latest.signer !== caller.record.userId || chain.latest.signerFp !== caller.fp) {
      throw new Error('the latest record is not the one this client signed');
    }
  } catch (err) {
    throw new GroupError('read-back', `The server accepted the new group record, but reading it back failed: ${err.message}`, { cause: err });
  }
}

// managerAction is the start of every change: the caller, the accepted chain,
// and the refusal when the latest record does not list the caller as manager.
async function managerAction(deps, id, acceptNewKey) {
  const caller = await unlock(deps);
  const opened = await openGroup(deps, caller, id, acceptNewKey);
  if (callerRole(caller, opened.chain.latest) !== 'manager') throw new GroupError('not-manager', 'Only a manager of the group can change it.');
  return { caller, chain: opened.chain, keyring: opened.keyring };
}

// createGroup makes a group named name, with the caller as its one manager,
// and returns {id, name}. A viewer account makes none.
export async function createGroup(deps, name) {
  const caller = await unlock(deps);
  if (caller.me.role === 'viewer') throw new GroupError('viewer-account', 'A viewer account cannot make a group.');
  checkName(name);
  const id = crypto.randomUUID();
  const body = {
    v: 1, group: id, seq: 1, prev: '', name,
    members: [{ user: caller.record.userId, fp: caller.fp, role: 'manager' }],
    signer: caller.record.userId, signerFp: caller.fp,
  };
  const record = await e2e.newEnvelope(caller.record.ed25519, caller.record.userId, 'group', encoder.encode(JSON.stringify(body)));
  const view = await call(deps, null, 'POST', '/api/groups', { body: { record } });
  await readBack(deps, caller, id, view, 1);
  return { id, name };
}

// addMember lists who, an email or a user ID, in the group with role member
// or manager, or changes their role. Their fingerprint comes from the
// directory and is checked against the caller's pin as sharing does: a user
// whose keys changed is a KeyChangedError unless acceptNewKey, and one seen
// for the first time is pinned unverified. A viewer account is never a
// manager. acceptNewKey accepts a changed key of a signer of the group too.
// Returns {user, role, unchanged, wasVerified}.
export async function addMember(deps, id, who, role, { acceptNewKey = false } = {}) {
  if (role !== 'member' && role !== 'manager') throw new GroupError('bad-role', `The role must be member or manager, not ${JSON.stringify(role)}.`);
  const { caller, chain, keyring } = await managerAction(deps, id, acceptNewKey);
  const dir = await directory(deps);
  const u = findUser(dir, who);
  if (role === 'manager' && u.role === 'viewer') throw new GroupError('viewer-account', `${u.email} is a viewer account and cannot be a manager.`);
  const { prior, pin: decided } = await checkPin(deps, keyring, u, acceptNewKey, null);
  const members = chain.latest.members.map((m) => ({ ...m }));
  const i = members.findIndex((m) => m.user === u.id);
  const res = { user: u, role, unchanged: i >= 0 && members[i].role === role && members[i].fp === u.fp, wasVerified: wasVerified(keyring, u.id, prior) };
  if (i >= 0 && members[i].role === 'manager' && role !== 'manager' && !members.some((m, j) => j !== i && m.role === 'manager')) {
    throw new GroupError('last-manager', 'A group keeps at least one manager. Make someone else a manager first.');
  }
  const basedOn = keyring.pins[u.id]?.fp ?? '';
  if (!res.unchanged) {
    const entry = { user: u.id, fp: u.fp, role };
    if (i >= 0) members[i] = entry; else members.push(entry);
    await putRecord(deps, caller, id, chain, { name: chain.latest.name, members });
  }
  if (decided) {
    try {
      await storePin(deps, caller, u.id, decided, basedOn);
    } catch (err) {
      throw new GroupError(err.code ?? 'pin', `The server accepted the new group record, but pinning ${u.email} failed: ${err.message}`, { cause: err });
    }
  }
  return res;
}

// removeMember takes who, an email or a user ID, out of the group. The last
// manager is not removed, nor is anyone the group does not list.
export async function removeMember(deps, id, who, { acceptNewKey = false } = {}) {
  const { caller, chain } = await managerAction(deps, id, acceptNewKey);
  const dir = await directory(deps);
  const u = findUser(dir, who);
  const members = chain.latest.members;
  const gone = members.find((m) => m.user === u.id);
  if (!gone) throw new GroupError('not-member', `${u.email} is not in the group.`);
  const rest = members.filter((m) => m.user !== u.id);
  if (!rest.some((m) => m.role === 'manager')) throw new GroupError('last-manager', 'A group keeps at least one manager. Make someone else a manager first.');
  await putRecord(deps, caller, id, chain, { name: chain.latest.name, members: rest });
  return { user: u };
}

// renameGroup gives the group another name.
export async function renameGroup(deps, id, name, { acceptNewKey = false } = {}) {
  checkName(name);
  const { caller, chain } = await managerAction(deps, id, acceptNewKey);
  await putRecord(deps, caller, id, chain, { name, members: chain.latest.members });
  return { name };
}

// deleteGroup deletes the group. The server allows a manager of it, or an
// administrator, so nothing is read first. Once the server confirms, the
// group's entry leaves the keyring; nothing else removes one.
export async function deleteGroup(deps, id) {
  const caller = await unlock(deps);
  const resp = await deps.fetch(`/api/groups/${id}`, { method: 'DELETE' });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    throw new ApiError(data.error || `request failed (${resp.status})`, resp.status);
  }
  await updateKeyring(deps, caller, (k) => {
    if (k.groups) delete k.groups[id];
  });
}
