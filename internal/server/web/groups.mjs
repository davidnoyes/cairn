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
// The group view the server serves has no keys, so a signer's key comes from
// the directory, or from the rotation records that name it, and rotationLinker
// connects the fingerprint a record lists to the one that signed.
import * as e2e from './e2e.mjs';
import { ApiError } from './account.mjs';
import { call, readKeyring, signedInCaller, updateKeyring } from './viewer.mjs';
import { checkPin, directory, fatalFetch, findUser, followPinFor, storePin, wasVerified } from './sharing.mjs';

const encoder = new TextEncoder();

// GroupError is a refusal of this module. code says which, for a page that
// answers it: not-signed-in, viewer-account, bad-role, bad-name, not-manager,
// not-member, last-manager, moved, read-back.
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

// rotationsOfUser is user's rotation records as the server serves them, none
// for a user it has no record of.
async function rotationsOfUser(deps, user) {
  try {
    return (await call(deps, null, 'GET', `/api/users/${user}/rotations`)).records ?? [];
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return [];
    throw err;
  }
}

async function fpOf(pair) {
  return e2e.toHex(await e2e.fingerprint(e2e.unb64(pair.x25519), e2e.unb64(pair.ed25519)));
}

// signerKeys is the fingerprint-to-key map verifyGroupChain reads, and the
// rotation records by user, for every user who signed a record: the
// directory's current key pair of each, and both pairs of each rotation
// record they have. verifyGroupChain keeps only a pair that hashes to its
// fingerprint, and a record's signer must reach the fingerprint a record lists
// through the rotation records themselves, which rotationLinker verifies.
async function signerKeys(deps, dir, records) {
  const keys = {};
  const rotations = {};
  const signers = new Set();
  for (const env of records) signers.add(e2e.decodeStrict(e2e.unb64(env.body), e2e.BODY_SCHEMAS.group).signer);
  for (const id of signers) {
    const u = dir.find((d) => d.id === id);
    if (u) keys[u.fp] = { x25519: e2e.b64(u.x25519Pub), ed25519: e2e.b64(u.ed25519Pub) };
    rotations[id] = await rotationsOfUser(deps, id);
    for (const env of rotations[id]) {
      let b;
      try {
        b = e2e.decodeStrict(e2e.unb64(env.body), e2e.BODY_SCHEMAS.rotation);
        for (const pair of [b.old, b.new]) keys[await fpOf(pair)] = pair;
      } catch {
        // A rotation record that does not parse links nothing.
      }
    }
  }
  return { keys, rotations };
}

// acceptGroup verifies a group's records against the keyring's groups entry,
// and stores the new seq and head there. It returns {chain, rotations, dir,
// keyring}. A chain shorter than the stored seq, or forked at it, is refused
// and nothing is stored.
async function acceptGroup(deps, caller, id, records) {
  if (!Array.isArray(records) || records.length === 0) throw new e2e.ChainError('no records');
  const kr = await readKeyring(deps, caller);
  const dir = await directory(deps);
  const { keys, rotations } = await signerKeys(deps, dir, records);
  const pin = Object.hasOwn(kr.groups ?? {}, id) ? kr.groups[id] : null;
  const chain = await e2e.verifyGroupChain({ group: id, records, keys, pin, linked: e2e.rotationLinker(rotations) });
  let keyring = kr;
  if (!pin || pin.seq < chain.seq) {
    keyring = await updateKeyring(deps, caller, (k) => {
      const cur = Object.hasOwn(k.groups ?? {}, id) ? k.groups[id] : null;
      if (cur && cur.seq === chain.seq && cur.head !== chain.head) throw new e2e.ForkError(`record ${cur.seq} of group ${id}`);
      if (!cur || cur.seq < chain.seq) {
        k.groups ??= {};
        k.groups[id] = { seq: chain.seq, head: chain.head };
      }
    });
  }
  return { chain, rotations, dir, keyring };
}

// openGroup reads a group and accepts its chain.
async function openGroup(deps, caller, id) {
  const view = await call(deps, null, 'GET', `/api/groups/${id}`);
  return { view, ...(await acceptGroup(deps, caller, id, view.records)) };
}

// callerRole is the role the latest record lists the caller under, or ''.
const callerRole = (caller, latest) => latest.members.find((m) => m.user === caller.record.userId)?.role ?? '';

// groupMembers opens a group and lists it from the chain it accepted: the
// name, the seq, the caller's role, and each member with their role, the
// fingerprint the record lists, the directory's current fingerprint (empty
// for a user it no longer lists), their account role (a viewer account is
// never a manager), and a pin state: self for the caller, - for
// a user the directory no longer lists, a pin state otherwise, and conflict
// when their rotation records fork or roll back.
export async function groupMembers(deps, id) {
  const caller = await unlock(deps);
  const { chain, rotations, dir, keyring } = await openGroup(deps, caller, id);
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
    const { chain } = await acceptGroup(deps, caller, id, view.records);
    if (chain.seq !== seq || chain.latest.signer !== caller.record.userId || chain.latest.signerFp !== caller.fp) {
      throw new Error('the latest record is not the one this client signed');
    }
  } catch (err) {
    throw new GroupError('read-back', `The server accepted the new group record, but reading it back failed: ${err.message}`, { cause: err });
  }
}

// managerAction is the start of every change: the caller, the accepted chain,
// and the refusal when the latest record does not list the caller as manager.
async function managerAction(deps, id) {
  const caller = await unlock(deps);
  const opened = await openGroup(deps, caller, id);
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
// manager. Returns {user, role, unchanged, wasVerified}.
export async function addMember(deps, id, who, role, { acceptNewKey = false } = {}) {
  if (role !== 'member' && role !== 'manager') throw new GroupError('bad-role', `The role must be member or manager, not ${JSON.stringify(role)}.`);
  const { caller, chain, keyring } = await managerAction(deps, id);
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
export async function removeMember(deps, id, who) {
  const { caller, chain } = await managerAction(deps, id);
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
export async function renameGroup(deps, id, name) {
  checkName(name);
  const { caller, chain } = await managerAction(deps, id);
  await putRecord(deps, caller, id, chain, { name, members: chain.latest.members });
  return { name };
}

// deleteGroup deletes the group. The server allows a manager of it, or an
// administrator, so nothing is read first.
export async function deleteGroup(deps, id) {
  await unlock(deps);
  const resp = await deps.fetch(`/api/groups/${id}`, { method: 'DELETE' });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    throw new ApiError(data.error || `request failed (${resp.status})`, resp.status);
  }
}
