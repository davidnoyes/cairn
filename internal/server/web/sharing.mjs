// sharing.mjs — what the owner's browser does to an artifact's membership: who
// has access, public links, pins, and re-sealing the data after an epoch
// change. It mirrors the Go client (internal/client/share.go, epoch.go,
// public.go, reseal.go) function by function, and every cryptographic
// operation comes from e2e.mjs. The server is untrusted throughout: every
// answer it gives is checked here, and every record is written only after the
// checks Go makes.
//
// Nothing here reads a browser global. Each function takes `deps` as
// viewer.mjs does:
//
//   fetch(path, options)   like window.fetch
//   keyStore               {load()}, see keystore.mjs: the signed-in user's keys
//   storage                localStorage, which holds the keyring anchor
//   origin                 the app origin, location.origin: the host of a public link
//   newAK()                optional; makes the 32 random bytes of a new epoch's AK
//
// Not ported: a member's rotation as pendingFor reports it (relistRotated, and
// the `rotated` handling in buildNextEpoch and Share: a listed member whose
// keys rotated is still shared again by name, and a next epoch refuses them
// until then), and acknowledging a handover, which is refused until the owner
// does so with the CLI. The team share and groups (approve.go, groupshare.go)
// are ported.
import * as e2e from './e2e.mjs';
import { ApiError } from './account.mjs';
import { UntrustedVersionError, call, callerAKs, checkArtifact, readKeyring, recordChain, signedInCaller, trustVersionManifest, updateKeyring, writerKeys } from './viewer.mjs';
import { checkSigned, openEntry } from './data.mjs';
import { listGroups, verifyGroup } from './groups.mjs';
import { META_FIELDS, openMetaItem, writeMeta } from './meta.mjs';

const encoder = new TextEncoder();

// SharingError is a refusal of this module. code says which, for a page that
// answers it: not-signed-in, bad-role, not-owner, share-self, unshare-owner,
// unknown-user, directory-duplicate, not-member, member-key-changed,
// member-deleted, pin-conflict, public-writes-with-off, cannot-reseal,
// handover-not-acked, no-write-key, read-back, epoch-moved, viewer-account,
// owner-only, owner-missing, not-approver, no-team, excluded, changed-key,
// already-listed, already-approved, not-waiting, pending-keys-differ,
// approval-unverified, not-in-group, group-unverified, unknown-group,
// not-shared-with-group, bad-team, rotations-unreadable, wrap-key-unknown.
export class SharingError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'SharingError';
    this.code = code;
  }
}

function formatFp(fp) {
  try {
    return e2e.formatFingerprint(e2e.fromHex(fp));
  } catch {
    return fp;
  }
}

// KeyChangedError means a user's current keys differ from the ones pinned for
// them, and no rotation chain explains it. fp is their current fingerprint.
// fork is set for rotation records that conflict with the pin (a fork or a
// rollback), which may be an attack, and fetchErr when the records could not
// be read, so nothing says whether the keys rotated: try again. Mirrors
// KeyChangedError.
export class KeyChangedError extends Error {
  constructor({ user, email, pinnedFp, fp, resetAt = '', fork = null, fetchErr = null }) {
    let message;
    if (fork instanceof e2e.RollbackError) {
      message = `WARNING: the server served fewer rotation records than you pinned for ${email} (${user}), and this may be an attack: pinned ${formatFp(pinnedFp)}, now ${formatFp(fp)} (${fork.message})`;
    } else if (fork) {
      message = `WARNING: the rotation records of ${email} (${user}) conflict with each other or with the record you pinned, and this may be an attack: pinned ${formatFp(pinnedFp)}, now ${formatFp(fp)} (${fork.message})`;
    } else if (fetchErr) {
      message = `Could not read the rotation records of ${email} (${user}), so it cannot tell whether their keys rotated: pinned ${formatFp(pinnedFp)}, now ${formatFp(fp)} (${fetchErr.message}). Try again before accepting a new key.`;
    } else {
      message = `The keys of ${email} (${user}) changed: pinned ${formatFp(pinnedFp)}, now ${formatFp(fp)}${resetAt ? `; the account was reset at ${resetAt}` : ''}. Confirm the new fingerprint with them, then accept the new key.`;
    }
    super(message);
    this.name = 'KeyChangedError';
    Object.assign(this, { user, email, pinnedFp, fp, resetAt, fork, fetchErr });
  }
}

// ---- the directory ----

function directoryUser(w) {
  const x25519Pub = e2e.unb64(w.x25519Pub);
  const ed25519Pub = e2e.unb64(w.ed25519Pub);
  if (x25519Pub.length !== 32) throw new e2e.FormatError(`the directory's X25519 key for ${w.id} is not 32 bytes`);
  if (ed25519Pub.length !== 32) throw new e2e.FormatError(`the directory's Ed25519 key for ${w.id} is not 32 bytes`);
  return { id: w.id, name: w.name, email: w.email, role: w.role ?? 'member', x25519Pub, ed25519Pub, resetAt: w.resetAt ?? '' };
}

export async function directory(deps) {
  const resp = await call(deps, null, 'GET', '/api/users');
  if (!Array.isArray(resp)) throw new e2e.FormatError('the directory is not a list');
  const out = [];
  for (const w of resp) {
    const u = directoryUser(w);
    u.fp = (await e2e.pinState(null, u.x25519Pub, u.ed25519Pub)).fp;
    out.push(u);
  }
  return out;
}

// checkDirectory refuses a directory in which two user IDs share a normalized
// email or a fingerprint. Mirrors CheckDirectory.
function checkDirectory(dir) {
  const emails = new Map();
  const fps = new Map();
  for (const u of dir) {
    const email = e2e.normalizeEmail(u.email);
    if (emails.has(email) && emails.get(email) !== u.id) {
      throw new SharingError('directory-duplicate', `The directory lists two users with the same email: ${emails.get(email)} and ${u.id} share ${email}.`);
    }
    if (fps.has(u.fp) && fps.get(u.fp) !== u.id) {
      throw new SharingError('directory-duplicate', `The directory lists two users with the same fingerprint: ${fps.get(u.fp)} and ${u.id} share ${formatFp(u.fp)}.`);
    }
    emails.set(email, u.id);
    fps.set(u.fp, u.id);
  }
}

// findUser finds who, an email (compared normalized) or a user ID, in the
// directory. It refuses a directory checkDirectory refuses. Mirrors FindUser.
export function findUser(dir, who) {
  checkDirectory(dir);
  const email = e2e.normalizeEmail(who);
  const u = dir.find((d) => d.id === who || e2e.normalizeEmail(d.email) === email);
  if (!u) throw new SharingError('unknown-user', `No user with that email or ID in the directory: ${who}`);
  return u;
}

// ---- pins ----

// fatalFetch says whether err, from a fetch of rotation records, ends the
// command rather than degrading it: the caller cancelled it, or the server
// refused its credentials.
export function fatalFetch(err) {
  return err !== null && (err?.name === 'AbortError' || (err instanceof ApiError && err.status === 401));
}

const hasPin = (kr, user) => Object.hasOwn(kr.pins, user);
const pinOf = (kr, user) => (hasPin(kr, user) ? kr.pins[user] : null);
const unverifiedPin = (fp) => ({ fp, state: e2e.PIN_UNVERIFIED, rotSeq: 0, rotHead: '' });

async function rotationsOf(deps, userId, known) {
  if (known && Object.hasOwn(known, userId)) return known[userId];
  const resp = await call(deps, null, 'GET', `/api/users/${userId}/rotations`);
  return resp.records;
}

// followPinFor is e2e.followPin for u against the keyring's pin. A pin on u's
// current keys reads no rotation records. A first pin reads them, and so does
// a pin on other keys, which a chain may explain. They come from known, the
// records the caller has by user ID, or else the server. fork is the error
// for records that conflict with the pin. Records the server fails to serve
// are no records: a first pin is taken at seq 0, and a pin on other keys is a
// plain change, which only acceptNewKey stores, never a fork. fetchErr is why
// the records could not be read, set for a pin on other keys, and for any
// failure fatalFetch says to stop on. Mirrors followPin in share.go.
export async function followPinFor(deps, kr, u, known) {
  const pinned = pinOf(kr, u.id);
  let records = [];
  if (!pinned || pinned.fp !== u.fp) {
    try {
      records = await rotationsOf(deps, u.id, known);
    } catch (err) {
      if (pinned || fatalFetch(err)) return { state: e2e.PIN_CHANGED, next: unverifiedPin(u.fp), fork: null, fetchErr: err };
    }
  }
  try {
    const { state, next } = await e2e.followPin(u.id, pinned, records, u.x25519Pub, u.ed25519Pub);
    return { state, next, fork: null, fetchErr: null };
  } catch (err) {
    if (err instanceof e2e.RotationForkError || err instanceof e2e.RollbackError) return { state: err.state, next: err.next, fork: err, fetchErr: null };
    throw err;
  }
}

// checkPin compares u's current keys with the keyring's pin, following the
// user's rotation records as followPinFor does. A changed key is a
// KeyChangedError unless acceptNewKey, and one a rotation chain explains is
// not a change: the state is rotated, and the pin to store is unverified. It
// returns {prior, pin}: the state before any change, and the pin to store, or
// null when the stored one stands. Mirrors checkPin.
export async function checkPin(deps, kr, u, acceptNewKey, known) {
  const { state, next, fork, fetchErr } = await followPinFor(deps, kr, u, known);
  if (fatalFetch(fetchErr)) throw fetchErr;
  switch (state) {
    case e2e.PIN_NEW:
    case e2e.PIN_ROTATED:
      return { prior: state, pin: next };
    case e2e.PIN_CHANGED:
      if (!acceptNewKey) {
        throw new KeyChangedError({ user: u.id, email: u.email, pinnedFp: kr.pins[u.id].fp, fp: u.fp, resetAt: u.resetAt, fork, fetchErr });
      }
      return { prior: state, pin: next };
    default:
      return { prior: state, pin: null };
  }
}

// wasVerified says whether prior is a rotation that dropped a verified pin to
// unverified, so the person is told to compare the keys again.
export function wasVerified(kr, user, prior) {
  return prior === e2e.PIN_ROTATED && pinOf(kr, user)?.state === e2e.PIN_VERIFIED;
}

// storePin writes a pin for user. basedOn is the fingerprint the keyring
// pinned for user when the caller decided on pin, or '' if it pinned none.
// Against the keyring as it is when written, which another device may have
// changed since: a pin at the same fingerprint is never downgraded from
// verified, and a pin at a fingerprint other than basedOn is a pin-conflict.
export async function storePin(deps, caller, user, pin, basedOn) {
  await updateKeyring(deps, caller, (kr) => {
    const cur = pinOf(kr, user);
    if (cur) {
      if (cur.fp === pin.fp && cur.state === e2e.PIN_VERIFIED) return;
      if (cur.fp !== pin.fp && cur.fp !== basedOn) throw new SharingError('pin-conflict', `Another device pinned this user at a different fingerprint; try again: ${user}`);
    }
    kr.pins[user] = pin;
  });
}

const samePin = (a, b) => a && b && a.fp === b.fp && a.state === b.state && a.rotSeq === b.rotSeq && a.rotHead === b.rotHead;

// pin records the current fingerprint of who in the keyring, unverified, or
// verified when the caller has compared it with them. A changed key is a
// KeyChangedError unless acceptNewKey; one a rotation chain explains is not.
// Mirrors Pin.
export async function pin(deps, who, { verified = false, acceptNewKey = false } = {}) {
  const caller = await unlock(deps);
  const dir = await directory(deps);
  const u = findUser(dir, who);
  const kr = await readKeyring(deps, caller);
  const { prior, pin: decided } = await checkPin(deps, kr, u, acceptNewKey, null);
  const next = { ...(decided ?? kr.pins[u.id]) };
  if (verified) next.state = e2e.PIN_VERIFIED;
  if (!samePin(pinOf(kr, u.id), next)) await storePin(deps, caller, u.id, next, pinOf(kr, u.id)?.fp ?? '');
  return { user: u, prior, state: next.state, wasVerified: wasVerified(kr, u.id, prior) };
}

// ---- verifying the artifact ----

async function unlock(deps) {
  const caller = await signedInCaller(deps);
  if (!caller?.record) throw new SharingError('not-signed-in', 'Sign in to manage an artifact.');
  return caller;
}

// verifyArtifact reads an artifact's membership chain and verifies it against
// the keyring, as viewer.mjs does to open one, and records it there.
// currentOwnerFp, when set, is the fingerprint the latest record must be
// signed under. Mirrors VerifyArtifact in keyring.go. It returns what
// openArtifact's member mode returns, less the AKs, with the keyring and the
// handover notice.
async function verifyArtifact(deps, caller, artifact, currentOwnerFp = '') {
  const kr = await readKeyring(deps, caller);
  const membership = await call(deps, null, 'GET', `/api/artifacts/${artifact}/membership`);
  const { chain, creator, newPin } = await checkArtifact(deps, caller, kr, artifact, membership, currentOwnerFp);
  const keyring = await recordChain(deps, caller, kr, artifact, chain, creator, newPin);
  let handover = null;
  if (chain.handovers.length > 0) {
    const seq = chain.handovers[chain.handovers.length - 1];
    const ack = Object.hasOwn(keyring.epochs, artifact) ? keyring.epochs[artifact].ack : 0;
    handover = { seq, date: membership.ownerChanges?.[String(seq)] ?? '', acked: ack >= seq };
  }
  return { mode: 'member', artifact, chain, latest: chain.latest, membership, keyring, handover, aks: new Map(), caller: caller.me, record: caller.record, linkToken: null, link: null };
}

// checkHandover is what each function that writes to an artifact calls once
// it holds the verified chain: an unacknowledged handover is refused.
function checkHandover(va) {
  if (va.handover && !va.handover.acked) {
    const err = new SharingError('handover-not-acked', `An administrator handed this artifact to a new owner${va.handover.date ? ` on ${va.handover.date}` : ''}, and you have not accepted it yet.`);
    err.seq = va.handover.seq;
    throw err;
  }
}

// callerRoleOf is how the caller may change the artifact's members: 'owner'
// when the latest record names them as owner under their current fingerprint,
// 'manager' when it lists them as manager under it, else ''.
function callerRoleOf(caller, va) {
  const { latest } = va;
  const id = caller.record.userId;
  if (latest.owner === id && latest.ownerFp === caller.fp) return 'owner';
  if (latest.members.some((m) => m.user === id && m.role === 'manager' && m.fp === caller.fp)) return 'manager';
  return '';
}

// adminRole is callerRoleOf, and refuses anyone else.
function adminRole(caller, va) {
  const role = callerRoleOf(caller, va);
  if (!role) throw new SharingError('not-owner', "Only the artifact's owner or a manager can change its members.");
  return role;
}

// checkOwnerOnly refuses a change to a manager's entry, or making someone a
// manager, when the caller is a manager: only the owner does either.
function checkOwnerOnly(manager, what) {
  if (manager) throw new SharingError('owner-only', `Only the artifact's owner can ${what}.`);
}

// adminAction is the start of every member-list change: the caller, the
// verified artifact, whether the caller is a manager rather than the owner,
// and the two refusals Share, Unshare and Public make before anything else.
async function adminAction(deps, artifactId) {
  const caller = await unlock(deps);
  const va = await verifyArtifact(deps, caller, artifactId);
  checkHandover(va);
  const manager = adminRole(caller, va) === 'manager';
  return { caller, va, manager };
}

const epochPinOf = (kr, artifact) => (Object.hasOwn(kr.epochs, artifact) ? kr.epochs[artifact] : null);

// ---- records ----

// ROLE_RANK orders the roles a member entry can hold.
const ROLE_RANK = new Map([['viewer', 0], ['editor', 1], ['manager', 2]]);

const byUser = (a, b) => (a.user < b.user ? -1 : a.user > b.user ? 1 : 0);

// membershipBody is next as the record after the verified chain's latest,
// fields in the order of the schema. transfer and handover are never set by
// these commands. A manager's record is version 2 and names the manager and
// their key's fingerprint last. groups follows team, and is left out while it
// is empty, as Go's omitempty does. Mirrors signNext.
function membershipBody(va, next, manager) {
  const body = {
    v: manager ? 2 : 1,
    artifact: va.artifact,
    epoch: next.epoch,
    seq: va.latest.seq + 1,
    owner: next.owner,
    ownerFp: next.ownerFp,
    akCommit: next.akCommit,
    members: next.members.map((m) => ({ user: m.user, role: m.role, fp: m.fp })),
    excluded: next.excluded.map((x) => ({ user: x.user, fp: x.fp, email: x.email })),
    team: next.team,
    ...((next.groups ?? []).length > 0 ? { groups: next.groups.map((g) => ({ group: g.group, role: g.role })) } : {}),
    public: next.public,
    publicWrites: next.publicWrites,
    prev: va.chain.head,
    transfer: '',
    handover: '',
  };
  if (manager) Object.assign(body, { signer: manager.user, signerFp: manager.fp });
  return body;
}

// akSet is the AKs the caller can read, with the epochs a wrap of the owner's
// could not give them, which callerAKs leaves out rather than refuse.
async function akSet(deps, caller, va) {
  const unreadable = [];
  const aks = await callerAKs(deps, caller, va.artifact, va.chain, unreadable);
  return { aks, unreadable };
}

// needAK is aks.get(epoch), refusing when the epoch is one the caller cannot
// read, with what the caller was about to do.
function needAK(aks, epoch, what) {
  if (!aks.has(epoch)) {
    throw new SharingError('epoch-unreadable', `Your key for epoch ${epoch} cannot be read, so you cannot ${what}. A manager sent you a bad key for it: remove that manager to start a new epoch you can read.`);
  }
  return aks.get(epoch);
}

// linkTokenHashFor is the hash of the epoch's link token the server stores for
// a public record, from the owner's estate copy of the epoch's AK.
async function linkTokenHashFor(deps, caller, va, epoch) {
  const { aks } = await akSet(deps, caller, va);
  return e2e.linkTokenHash(await e2e.linkToken(needAK(aks, epoch, 'make a public link for it'), va.artifact, epoch));
}

// putRecord signs next as the record after the verified chain's latest and
// PUTs it with wraps and, for a next epoch, the estate copy of its AK. A
// public record carries the hash of the epoch's link token, which the server
// requires of every public record: linkHash for a next epoch, whose estate
// copy the server does not hold yet, or '' to take it from the epoch's own.
// It drops each listed group that no longer exists from the record, and
// returns their IDs. Mirrors putRecord.
async function putRecord(deps, caller, va, nextIn, wraps, estate, linkHash) {
  const manager = va.latest.owner === caller.record.userId ? null : { user: caller.record.userId, fp: caller.fp };
  const { kept, dropped } = await liveGroups(deps, nextIn.groups ?? []);
  const next = { ...nextIn, groups: kept };
  const body = encoder.encode(JSON.stringify(membershipBody(va, next, manager)));
  const membership = await e2e.newEnvelope(caller.record.ed25519, caller.record.userId, 'membership', body);
  let hash = linkHash;
  if (next.public && hash === '') hash = await linkTokenHashFor(deps, caller, va, next.epoch);
  await call(deps, null, 'PUT', `/api/artifacts/${va.artifact}/membership`, { body: { membership, wraps, estate, linkTokenHash: hash } });
  return dropped;
}

// readBack verifies the artifact after the server accepted a record, which
// must still name the owner's key va lists, and whose latest record must be
// the caller's own: the owner's version 1 record, or a version 2 record the
// caller signed as a manager. A failure still names link, the new public link,
// when there is one: the old link already stopped working. Mirrors readBack.
async function readBack(deps, caller, va, link) {
  try {
    const { latest } = await verifyArtifact(deps, caller, va.artifact, va.latest.ownerFp);
    const id = caller.record.userId;
    const own = latest.v === 2 ? latest.signer === id && latest.signerFp === caller.fp : latest.owner === id && latest.ownerFp === caller.fp;
    if (!own) throw new Error('the latest record is not the one this client signed');
  } catch (err) {
    const msg = `The server accepted the new membership record, but reading it back failed: ${err.message}${link ? `; the new public link is ${link}` : ''}`;
    throw new SharingError('read-back', msg, { cause: err });
  }
}

async function wrapTo(u, artifact, epoch, ak) {
  const wrapped = await e2e.wrap({ purpose: 'ak', artifact, epoch, recipientId: u.id, recipientPub: u.x25519Pub }, ak);
  return { user: u.id, epoch, wrapped: e2e.b64(wrapped) };
}

// dropExcluded returns the entries no listed member matches, by user ID,
// fingerprint, or normalized email, and those a member matches, which a record
// that lists the member must drop.
function dropExcluded(excluded, members, dir) {
  const email = new Map(dir.map((d) => [d.id, e2e.normalizeEmail(d.email)]));
  const kept = [];
  const dropped = [];
  for (const x of excluded) {
    const matched = members.some((m) => x.user === m.user || x.fp === m.fp || e2e.normalizeEmail(x.email) === (email.get(m.user) ?? ''));
    (matched ? dropped : kept).push(x);
  }
  return { kept, dropped };
}

// ---- who is waiting: pending, groups, approving ----

// States of a pending entry, as GET /pending names them.
const PENDING_NEW = 'new';
const PENDING_APPROVED = 'approved';
const PENDING_LEFT = 'left';
const PENDING_KEY_CHANGED = 'keyChanged';
const PENDING_ROTATED = 'rotated';

// GroupKeyChangedError means a group's record lists a user under other keys
// than the directory serves for them now: a key-change warning, which
// acceptNewKey overrides. A manager of the group saw groupFp for the user, and
// the directory serves user.fp. Mirrors GroupKeyChangedError.
export class GroupKeyChangedError extends Error {
  constructor({ user, group, groupFp }) {
    super(`The record of group ${group} lists ${user.email} under fingerprint ${formatFp(groupFp)}, but the directory serves ${formatFp(user.fp)} now. Compare the fingerprint with them, then accept the new key.`);
    this.name = 'GroupKeyChangedError';
    Object.assign(this, { user, group, groupFp });
  }
}

const mayApprove = (caller, latest) => {
  const id = caller.record.userId;
  if (latest.owner === id) return latest.ownerFp === caller.fp;
  return latest.members.some((m) => m.user === id && m.fp === caller.fp && (m.role === 'editor' || m.role === 'manager'));
};

// errRotationsUnreadable is the refusal for a user the server calls rotated
// and whose rotation records could not be read: without them it cannot tell
// which keys their wraps were made for.
function errRotationsUnreadable(p) {
  return new SharingError('rotations-unreadable', `Cannot read the rotation records of ${p.user.email} (${p.user.id}): ${p.rotationsErr.message}. Without them it cannot tell which keys their wraps were made for. Try again when the records can be read.`, { cause: p.rotationsErr });
}

// checkRotated returns PENDING_ROTATED when u's rotation records lead from the
// fingerprint the latest record lists for them to their current keys, and
// PENDING_KEY_CHANGED otherwise, which includes records the server fails to
// serve: they cannot be verified, so the keys count as changed, and fetchErr
// says why they could not be read. For a user the record does not list, the
// chain starts at the owner's pin, or with no pin at the first record's old
// keys: nothing else says which keys they held. Only the owner and a manager
// are told of rotated. Mirrors checkRotated.
async function checkRotated(deps, caller, va, u) {
  const { latest } = va;
  if (latest.owner !== caller.record.userId && callerRoleOf(caller, va) !== 'manager') return { state: PENDING_KEY_CHANGED, fetchErr: null };
  let records;
  try {
    records = await rotationsOf(deps, u.id, va.membership.rotations);
  } catch (err) {
    return { state: PENDING_KEY_CHANGED, fetchErr: err };
  }
  let oldFp = '';
  const listed = latest.members.find((m) => m.user === u.id);
  if (listed) {
    oldFp = listed.fp;
  } else if (hasPin(va.keyring, u.id)) {
    oldFp = va.keyring.pins[u.id].fp;
  } else if (records.length > 0) {
    // The last resort takes the first record's old keys on the server's word,
    // which is safe: the verdict never writes a pin, it only decides whether
    // the client wraps to or excludes the user.
    try {
      const b = e2e.decodeStrict(e2e.unb64(records[0].body), e2e.BODY_SCHEMAS.rotation);
      oldFp = e2e.toHex(await e2e.fingerprint(e2e.unb64(b.old.x25519), e2e.unb64(b.old.ed25519)));
    } catch {
      // Records that do not parse name no keys.
    }
  }
  try {
    const res = await e2e.followRotations(u.id, records, { fp: oldFp, rotSeq: 0, rotHead: '' });
    if (oldFp === u.fp || res.fp !== u.fp) return { state: PENDING_KEY_CHANGED, fetchErr: null };
  } catch {
    return { state: PENDING_KEY_CHANGED, fetchErr: null };
  }
  return { state: PENDING_ROTATED, fetchErr: null };
}

// pendingFor lists the users the caller should be asked about, from GET
// /pending: {user, state, approval, groups, rotationsErr}. The server's word
// that a user is rotated is not enough: checkRotated decides. Mirrors
// pendingFor.
async function pendingFor(deps, caller, va) {
  const resp = await call(deps, null, 'GET', `/api/artifacts/${va.artifact}/pending`);
  if (!Array.isArray(resp)) throw new e2e.FormatError('the pending list is not a list');
  const out = [];
  for (const w of resp) {
    const user = directoryUser(w);
    user.fp = (await e2e.pinState(null, user.x25519Pub, user.ed25519Pub)).fp;
    let state = w.state;
    let rotationsErr = null;
    if (state === PENDING_ROTATED) {
      ({ state, fetchErr: rotationsErr } = await checkRotated(deps, caller, va, user));
      if (fatalFetch(rotationsErr)) throw rotationsErr;
    }
    out.push({ user, state, approval: w.approval ?? null, groups: w.group ?? [], rotationsErr });
  }
  return out;
}

// ---- groups in a member list ----

// groupChains verifies the chain of each group in ids that have lacks, and
// adds it. A group the server no longer holds (404) is added as null. A key
// change in a group's signers is a KeyChangedError as it is for a share.
// Verifying a group may pin its signers, so va's keyring is read again
// afterwards: a pin decided later is then based on what is stored.
async function groupChains(deps, caller, va, ids, have) {
  let verified = false;
  for (const id of ids) {
    if (have.has(id)) continue;
    try {
      have.set(id, (await verifyGroup(deps, id)).chain);
      verified = true;
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        have.set(id, null);
      } else if (err instanceof KeyChangedError || fatalFetch(err)) {
        throw err;
      } else {
        throw new SharingError('group-unverified', `Group ${id}: ${err.message}`, { cause: err });
      }
    }
  }
  if (verified) va.keyring = await readKeyring(deps, caller);
}

// listsUser returns the entry a group chain's latest record has for user.
const listsUser = (chain, user) => chain?.latest.members.find((m) => m.user === user) ?? null;

// holdingGroups returns the groups of rec that the server says hold p.
const holdingGroups = (rec, p) => (rec.groups ?? []).filter((g) => p.groups.includes(g.group)).map((g) => g.group);

// covers says whether the record gives the user in p a reason to read: the
// team share is on, or a group it lists holds them, on the server's word.
const covers = (rec, p) => rec.team !== 'none' || holdingGroups(rec, p).length > 0;

// holdersLose says whether next, a record after latest, leaves an unlisted
// holder in pending without a reason to read, so the server refuses it at the
// same epoch. An approved user loses it when next covers them no more. A user
// whose wrap is for old keys has no group the server names, so they lose it
// unless the record lists them: erring that way costs only an epoch. Mirrors
// holdersLose.
function holdersLose(pending, latest, next) {
  return pending.some((p) => {
    if (p.state === PENDING_APPROVED) return !covers(next, p);
    if (p.state === PENDING_KEY_CHANGED || p.state === PENDING_ROTATED) return !latest.members.some((m) => m.user === p.user.id);
    return false;
  });
}

// grantedRole is the role the record gives the approved user p: the highest of
// the team share's role and the roles of the listed groups whose verified
// chains list them. It is '' when the record covers them no more, and
// not-in-group when a group the server names holds them in no verified chain
// and nothing else covers them. Mirrors grantedRole.
async function grantedRole(deps, caller, va, rec, p, chains) {
  let role = rec.team !== 'none' ? rec.team : '';
  const ids = holdingGroups(rec, p);
  await groupChains(deps, caller, va, ids, chains);
  for (const g of rec.groups ?? []) {
    if (listsUser(chains.get(g.group), p.user.id) && (role === '' || ROLE_RANK.get(g.role) > ROLE_RANK.get(role))) role = g.role;
  }
  if (role === '' && ids.length > 0) throw new SharingError('not-in-group', `The verified record of the group does not list ${p.user.email}.`);
  return role;
}

// checkGroupCover is the group check of an approval. When the team share is
// off, the newcomer must be listed by a verified chain of a listed group that
// holds them, under the fingerprint the directory serves for them: a
// difference is a GroupKeyChangedError, which acceptNewKey overrides, and no
// chain listing them is not-in-group. While the team share is on, it covers
// them whatever the groups say. Mirrors checkGroupCover.
async function checkGroupCover(deps, caller, va, latest, p, u, acceptNewKey) {
  if (latest.team !== 'none') return;
  const ids = holdingGroups(latest, p);
  const chains = new Map();
  await groupChains(deps, caller, va, ids, chains);
  let differs = null;
  for (const id of ids) {
    const m = listsUser(chains.get(id), u.id);
    if (!m) continue;
    if (m.fp === u.fp) return;
    differs ??= new GroupKeyChangedError({ user: u, group: id, groupFp: m.fp });
  }
  if (!differs) throw new SharingError('not-in-group', `The verified record of the group does not list ${u.email}.`);
  if (!acceptNewKey) throw differs;
}

// liveGroups returns gs without the groups that no longer exist, as kept, and
// the IDs it dropped. A client builds every record this way: a deleted group
// grants nothing, and the record that keeps listing it only clutters the
// list. Nothing is asked when gs is empty. Mirrors liveGroups.
async function liveGroups(deps, gs) {
  if (gs.length === 0) return { kept: gs, dropped: [] };
  const all = await listGroups(deps);
  const kept = gs.filter((g) => all.some((s) => s.id === g.group));
  return { kept, dropped: gs.filter((g) => !kept.includes(g)).map((g) => g.group) };
}

// ---- listing and approving ----

// checkApproved runs the four checks of e2e.checkApproval on the approval in
// the pending entry p, and requires the directory to list the same keys for
// the user as the pending entry does, so the approval's fingerprint is the
// directory's. rotations are the rotation records the membership GET served,
// which let a signer's approval pass across a rotation. It does not look at
// the owner's pin. Mirrors checkApproved.
async function checkApproved(caller, latest, rotations, dir, p) {
  const keysOfUser = (u) => ({ x25519: e2e.b64(u.x25519Pub), ed25519: e2e.b64(u.ed25519Pub) });
  const approvalUser = (u) => ({ id: u.id, email: u.email, keys: keysOfUser(u) });
  const own = { x25519: e2e.b64(caller.record.x25519.publicKey), ed25519: e2e.b64(caller.record.ed25519Pub) };
  const keysOf = (id) => {
    if (id === caller.record.userId) return own;
    const d = dir.find((x) => x.id === id);
    return d ? keysOfUser(d) : null;
  };
  const served = keysOf(p.user.id);
  const mine = keysOfUser(p.user);
  if (served && (served.x25519 !== mine.x25519 || served.ed25519 !== mine.ed25519)) {
    throw new SharingError('pending-keys-differ', `The server serves different keys for ${p.user.email} in the directory and in the pending list.`);
  }
  let signerKeys = null;
  if (p.approval) {
    signerKeys = keysOf(p.approval.signer);
    if (!signerKeys) throw new e2e.ApprovalSignerError(`the directory does not list the signer ${p.approval.signer}`);
  }
  await e2e.checkApproval({ artifact: latest.artifact, latest, approval: p.approval, signerKeys, user: approvalUser(p.user), directory: dir.map(approvalUser), rotations });
}

// listApproved decides, for each approved user the server reports, whether
// the client may list them without asking, under the role rec gives them: the
// highest of its team share and its groups that hold them, from the groups'
// verified chains (grantedRole). It lists them only when the approval passes
// all four checks of e2e.checkApproval, the directory lists the keys the
// pending entry does, and the keys do not contradict the pin. A user failing a
// check, or whom a group holds in the server's word only, is reported as
// unlisted, never listed. A user rec gives no role is left for the caller to
// exclude. skip names users already in the record being built. Returns
// {members, listed, unlisted, pins}: pins maps a user to the {pin, basedOn} to
// store once the server accepts the record. An error is a failure that ends
// the command, never a user to leave unlisted. Mirrors listApproved.
async function listApproved(deps, caller, va, dir, pending, rec, skip) {
  const out = { members: [], listed: [], unlisted: [], pins: new Map() };
  const chains = new Map();
  for (const p of pending) {
    if (p.state !== PENDING_APPROVED || skip(p.user.id)) continue;
    let role;
    try {
      role = await grantedRole(deps, caller, va, rec, p, chains);
    } catch (err) {
      if (err.code !== 'not-in-group') throw err;
      out.unlisted.push({ user: p.user, error: err });
      continue;
    }
    if (role === '') continue;
    // A viewer account is listed as a viewer, whatever role it is granted.
    if (dir.find((d) => d.id === p.user.id)?.role === 'viewer') role = 'viewer';
    let pin = null;
    try {
      await checkApproved(caller, va.latest, va.membership.rotations, dir, p);
      ({ pin } = await checkPin(deps, va.keyring, p.user, false, va.membership.rotations));
    } catch (err) {
      if (fatalFetch(err)) throw err;
      out.unlisted.push({ user: p.user, error: err });
      continue;
    }
    out.members.push({ user: p.user.id, role, fp: p.user.fp });
    out.listed.push(p.user);
    if (pin) out.pins.set(p.user.id, { pin, basedOn: pinOf(va.keyring, p.user.id)?.fp ?? '' });
  }
  return out;
}

// storePins stores the pins a record decided once the server accepted it.
async function storePins(deps, caller, pins) {
  for (const [id, d] of pins) {
    try {
      await storePin(deps, caller, id, d.pin, d.basedOn);
    } catch (err) {
      throw new SharingError(err.code ?? 'pin', `The server accepted the new membership record, but pinning ${id} failed: ${err.message}`, { cause: err });
    }
  }
}

// ---- members, share, unshare ----

// memberControls says what the share dialog offers the caller for the member
// m of members()'s list: the roles the member's select offers, empty when the
// entry is read-only, and whether the entry may be removed. callerRole is
// members()'s. Only the owner offers or changes manager, and a viewer account
// is offered only viewer unless it keeps the editor or manager entry it had
// before its account changed.
export function memberControls(callerRole, m) {
  if (m.role === 'owner' || (m.role === 'manager' && callerRole !== 'owner')) return { roles: [], removable: false };
  const offered = callerRole === 'owner' ? ['viewer', 'editor', 'manager'] : ['viewer', 'editor'];
  const roles = m.account === 'viewer' ? offered.filter((r) => ROLE_RANK.get(r) === 0 || ROLE_RANK.get(r) <= ROLE_RANK.get(m.role)) : offered;
  return { roles, removable: true };
}

// members verifies an artifact's chain and lists its owner and members, each
// with the pin state of their current keys: self for the caller, - for a user
// the directory no longer lists, a pin state otherwise, and conflict when the
// rotation records fork or roll back. currentFp is the fingerprint of the
// keys the directory serves now, which differs from fp once they change, or
// empty for a user it no longer lists. wasVerified says a rotation dropped a
// verified pin. callerRole is owner, manager, or '' for the caller. team is
// the record's team share (none, viewer, or editor), groups the listed groups
// with their roles and the names the server holds for them, and canApprove
// says whether the caller may approve newcomers: the owner, a manager, or an
// editor. Mirrors Members and ListedGroups.
export async function members(deps, artifactId) {
  const caller = await unlock(deps);
  const va = await verifyArtifact(deps, caller, artifactId);
  const dir = await directory(deps);
  const byId = new Map(dir.map((u) => [u.id, u]));
  const latest = va.latest;
  const rows = [{ user: latest.owner, role: 'owner', fp: latest.ownerFp }, ...latest.members.map((m) => ({ user: m.user, role: m.role, fp: m.fp }))];
  for (const r of rows) {
    const u = byId.get(r.user);
    r.name = '';
    r.email = '';
    r.state = '';
    r.wasVerified = false;
    if (r.user === caller.record.userId) {
      r.state = 'self';
    } else if (!u) {
      r.state = '-';
    } else {
      const { state, fork, fetchErr } = await followPinFor(deps, va.keyring, u, va.membership.rotations);
      if (fatalFetch(fetchErr)) throw fetchErr;
      r.state = fork ? 'conflict' : state;
      r.wasVerified = wasVerified(va.keyring, r.user, r.state);
    }
    r.currentFp = u ? u.fp : '';
    // account is the person's server role, so the page can offer a viewer
    // account nothing but the viewer role.
    r.account = u ? u.role : '';
    if (u) {
      r.name = u.name;
      r.email = u.email;
    }
  }
  return {
    artifact: artifactId, epoch: latest.epoch, seq: latest.seq, public: latest.public, publicWrites: latest.publicWrites,
    callerRole: callerRoleOf(caller, va), canApprove: mayApprove(caller, latest), team: latest.team, groups: await listedGroups(deps, latest.groups ?? []), members: rows,
  };
}

// listedGroups is the groups of a record, in its order, with the names the
// server holds for them: {id, name, role, deleted}. A group the server no
// longer holds has no name. Mirrors ListedGroups.
async function listedGroups(deps, gs) {
  if (gs.length === 0) return [];
  const all = await listGroups(deps);
  return gs.map((g) => {
    const found = all.find((s) => s.id === g.group);
    return { id: g.group, name: found?.name ?? '', role: g.role, deleted: !found };
  });
}

// share adds who, an email or a user ID, to an artifact at its current epoch
// with role viewer, editor, or manager, or changes their role: promoting is a
// same-epoch record, and so is lowering a manager to editor, but demoting to
// viewer starts a new epoch. A manager can
// make every change below manager; making someone a manager, or changing a
// manager's entry, is the owner's alone and is refused with owner-only. Sharing by
// name with a user the owner excluded lists them again and drops the entries
// they match. It refuses a directory with duplicate emails or fingerprints,
// and a user whose keys changed since they were pinned unless acceptNewKey. A
// user seen for the first time is pinned unverified. A user the record did
// not list holds no wrap yet, so the new member gets a wrap of every epoch's
// AK, opened from the owner's estate copies and checked against the chain's
// akCommit. Returns {epoch, reseal}, with reseal the result of re-sealing
// when a new epoch started, else null, and more besides: user, prior, role,
// promoted, lowered (manager to editor), demoted (to viewer, in a new epoch),
// unchanged, dropped, wasVerified, listed and unlisted (approved team and
// group members the record also lists, and those whose approval failed a
// check), droppedGroups, and for a new epoch excluded and link. A user who is
// approved or left holds their wraps already, so they get none. Mirrors Share.
export async function share(deps, artifactId, who, role, { acceptNewKey = false } = {}) {
  if (!ROLE_RANK.has(role)) throw new SharingError('bad-role', `The role must be viewer, editor, or manager, not ${JSON.stringify(role)}.`);
  const { caller, va, manager } = await adminAction(deps, artifactId);
  const latest = va.latest;
  const dir = await directory(deps);
  const u = findUser(dir, who);
  if (u.id === latest.owner) throw new SharingError('share-self', 'The owner already has access to the artifact.');
  const { prior, pin: decided } = await checkPin(deps, va.keyring, u, acceptNewKey, va.membership.rotations);
  const res = {
    user: u, prior, wasVerified: wasVerified(va.keyring, u.id, prior), role, epoch: latest.epoch, reseal: null,
    promoted: false, lowered: false, demoted: false, unchanged: false, dropped: [], excluded: [], link: '',
    listed: [], unlisted: [], droppedGroups: [],
  };
  const pending = await pendingFor(deps, caller, va);
  // An approved user holds their wraps already, so the client takes the
  // server's word for it only after the check below. A user who left every
  // group holds their wraps still, and the owner who lists them by name decides
  // about them as for any share: there is no approval to check.
  const holder = pending.find((p) => p.user.id === u.id && (p.state === PENDING_APPROVED || p.state === PENDING_LEFT));
  if (holder && holder.state !== PENDING_LEFT) {
    try {
      await checkApproved(caller, latest, va.membership.rotations, dir, holder);
    } catch (err) {
      throw new SharingError('approval-unverified', `The approval of ${u.email} does not check out, so Cairn will not share with them: ${err.message}. Remove them to start a new epoch that excludes them.`, { cause: err });
    }
  }

  const list = latest.members.map((m) => ({ ...m }));
  const i = list.findIndex((m) => m.user === u.id);
  if (role === 'manager') checkOwnerOnly(manager, 'make someone a manager');
  if (i >= 0 && list[i].role === 'manager') checkOwnerOnly(manager, "change a manager's entry");
  // A viewer account writes nothing, so it can only be a viewer. An editor or
  // manager whose account became a viewer account keeps the entry, or becomes
  // an editor if it was a manager, until changed, as the server's membership
  // check allows.
  if (ROLE_RANK.get(role) > 0 && u.role === 'viewer' && !(i >= 0 && ROLE_RANK.get(list[i].role) >= ROLE_RANK.get(role))) {
    throw new SharingError('viewer-account', `${u.email} is a viewer account and can only be a viewer.`);
  }
  let needsWraps = true;
  let demote = false;
  if (i < 0) {
    list.push({ user: u.id, role, fp: u.fp });
    needsWraps = !holder;
  } else {
    const from = ROLE_RANK.get(list[i].role);
    const to = ROLE_RANK.get(role);
    demote = from > 0 && to === 0;
    res.promoted = to > from;
    res.demoted = demote;
    res.lowered = to < from && !demote;
    const relist = list[i].fp !== u.fp;
    needsWraps = relist;
    res.unchanged = !res.promoted && !res.demoted && !res.lowered && !relist;
    list[i] = { user: u.id, role, fp: u.fp };
  }
  const basedOn = pinOf(va.keyring, u.id)?.fp ?? '';
  if (demote) return shareNextEpoch(deps, caller, va, dir, pending, list, u, decided, basedOn, res, manager);
  if (res.unchanged) {
    if (decided) await storePin(deps, caller, u.id, decided, basedOn);
    return res;
  }
  const lst = await listApproved(deps, caller, va, dir, pending, latest, (id) => list.some((m) => m.user === id));
  list.push(...lst.members);
  Object.assign(res, { listed: lst.listed, unlisted: lst.unlisted });
  list.sort(byUser);

  const wraps = [];
  if (needsWraps) {
    // Defense in depth behind verifyChain's epoch pin, which already refuses a
    // stale epoch.
    e2e.checkEncryptEpoch(epochPinOf(va.keyring, artifactId), latest.epoch);
    const { aks } = await akSet(deps, caller, va);
    for (let epoch = 1; epoch <= latest.epoch; epoch++) wraps.push(await wrapTo(u, artifactId, epoch, needAK(aks, epoch, `share with ${u.email}, who needs it`)));
  }
  const { kept, dropped } = dropExcluded(latest.excluded, list, dir);
  // Only the owner lists someone anyone removed again.
  if (dropped.length > 0) checkOwnerOnly(manager, 'share again with someone removed from the artifact');
  res.dropped = dropped;
  res.droppedGroups = await putRecord(deps, caller, va, { ...latest, members: list, excluded: kept }, wraps, [], '');
  await storePins(deps, caller, lst.pins);
  if (decided) {
    try {
      await storePin(deps, caller, u.id, decided, basedOn);
    } catch (err) {
      throw new SharingError(err.code ?? 'pin', `The server accepted the new membership record, but pinning ${u.email} failed: ${err.message}`, { cause: err });
    }
  }
  await readBack(deps, caller, va, '');
  return res;
}

// shareNextEpoch is share when the change demotes an editor or manager: the
// demoted user stays listed as a viewer and the record starts a new epoch.
async function shareNextEpoch(deps, caller, va, dir, pending, list, u, decided, basedOn, res, manager) {
  const change = await putNextEpoch(deps, caller, va, dir, pending, { ...va.latest, members: list }, { decided: u.id, manager });
  res.epoch = va.latest.epoch + 1;
  Object.assign(res, { listed: change.listed, droppedGroups: change.dropped });
  if (decided) {
    try {
      await storePin(deps, caller, u.id, decided, basedOn);
    } catch (err) {
      throw new SharingError(err.code ?? 'pin', `The server accepted the new membership record, but pinning ${u.email} failed: ${err.message}`, { cause: err });
    }
  }
  await readBack(deps, caller, va, change.link);
  Object.assign(res, { excluded: change.excluded, link: change.link, reseal: await resealInto(deps, caller, va.artifact) });
  return res;
}

// buildNextEpoch builds a next-epoch record from next, the record to write
// with the members, team, groups, and public switches the change wants, and
// sends nothing. It makes the new AK, wraps it to every listed member, seals
// the estate copy, and excludes every user the record removes or drops, and
// every team or group member who holds a wrap and cannot be listed: the server
// refuses a record that leaves any of them out of both lists, so a member whose
// approval fails a check is excluded, and the owner lists them again by name
// with share. r.decided is a member whose pin the caller already decided;
// r.exclude is a user the caller removes, listed or holding a wrap; r.manager
// says the caller is a manager, not the owner. Returns, besides the record,
// listed: the approved users the record lists, with the role they are granted.
// Mirrors buildNextEpoch, less transfers and rotated members.
async function buildNextEpoch(deps, caller, va, dir, pending, nextIn, r) {
  const { artifact, latest } = va;
  const epoch = latest.epoch + 1;
  // Defense in depth behind verifyChain's epoch pin, which already refuses a
  // stale epoch.
  e2e.checkEncryptEpoch(epochPinOf(va.keyring, artifact), epoch);
  const next = { ...nextIn, members: [...nextIn.members] };
  const byId = new Map(dir.map((u) => [u.id, u]));
  const inMembers = (id) => next.members.some((m) => m.user === id);

  // Team and group members who hold a wrap are listed or excluded.
  const lst = await listApproved(deps, caller, va, dir, pending, next, (id) => inMembers(id) || id === r.exclude);
  next.members = [...next.members, ...lst.members].sort(byUser);

  const excludes = new Map();
  const excluded = [];
  const exclude1 = (u, fp, reason) => {
    // A deleted account has no email to give. The server takes any for a user
    // it no longer has; the ID and fingerprint still match.
    const email = e2e.normalizeEmail(u.email) || u.id;
    excludes.set(u.id, { user: u.id, fp, email });
    excluded.push({ user: u, reason });
  };
  // Removed members, under the fingerprint the previous record lists them.
  for (const m of latest.members) {
    if (inMembers(m.user)) continue;
    const u = byId.get(m.user);
    if (!u) exclude1({ id: m.user, email: '', fp: m.fp }, m.fp, 'removed; their account was deleted');
    else exclude1(u, m.fp, 'removed');
  }
  for (const p of pending) {
    if (excludes.has(p.user.id) || inMembers(p.user.id)) continue;
    if (p.state === PENDING_KEY_CHANGED && p.rotationsErr) {
      // The server says they rotated, and without their records no pin says
      // which key their wraps were made for.
      throw errRotationsUnreadable(p);
    } else if (p.state === PENDING_KEY_CHANGED) {
      // Not listed, so a wrap they hold was made for a key other than their
      // current one. The server accepts only a fingerprint it can account for,
      // which the client knows from its pin.
      const pinned = pinOf(va.keyring, p.user.id);
      if (!pinned || pinned.fp === p.user.fp) {
        throw new SharingError('wrap-key-unknown', `${p.user.email} holds a wrap made for a key that is no longer theirs, and Cairn does not know which. Share with them again and accept the new key, then remove them.`);
      }
      exclude1(p.user, pinned.fp, p.user.id === r.exclude ? 'removed' : 'their keys changed after they were wrapped to');
    } else if (p.user.id === r.exclude) {
      exclude1(p.user, p.user.fp, 'removed');
    } else if (p.state === PENDING_APPROVED || p.state === PENDING_ROTATED || p.state === PENDING_LEFT) {
      // A rotated user who is not listed holds wraps under their new keys and
      // an approval for their old ones, which no record can list.
      let reason = 'team sharing ended while they held a wrap';
      if (p.state === PENDING_ROTATED) reason = 'their keys rotated after they were approved, so the approval no longer checks out';
      else if (p.state === PENDING_LEFT) reason = 'left the group';
      else if (latest.team === 'none' || next.team !== 'none') reason = 'no group they belong to is shared with the artifact any more';
      const unlisted = lst.unlisted.find((x) => x.user.id === p.user.id);
      if (unlisted) reason = `their approval does not check out: ${unlisted.error.message}`;
      exclude1(p.user, p.user.fp, reason);
    }
  }

  // Every member is listed under their current keys, and a pinned key that
  // differs from them is the owner's to decide about.
  const pins = lst.pins;
  for (const m of next.members) {
    const u = byId.get(m.user);
    if (!u) {
      throw new SharingError('member-deleted', `The account of member ${m.user} was deleted, so no new key can be wrapped to them. Remove them first.`);
    }
    if (m.fp !== u.fp) {
      throw new SharingError('member-key-changed', `A member's keys changed since the record listed them: ${u.email} (${u.id}). Share with them again and accept the new key, or remove them.`);
    }
    if (m.user === r.decided) continue;
    const { prior, pin: decided } = await checkPin(deps, va.keyring, u, false, va.membership.rotations);
    if (decided && prior === e2e.PIN_ROTATED) pins.set(m.user, { pin: decided, basedOn: pinOf(va.keyring, m.user)?.fp ?? '' });
  }

  // An entry stays until a listed member matches it. A user listed again by
  // name drops theirs.
  for (const x of latest.excluded) {
    const matched = next.members.some((m) => x.user === m.user || x.fp === m.fp || e2e.normalizeEmail(x.email) === e2e.normalizeEmail(byId.get(m.user)?.email ?? ''));
    if (!matched && !excludes.has(x.user)) excludes.set(x.user, x);
  }
  next.excluded = [...excludes.values()].sort(byUser);

  // The new epoch's key, which no earlier epoch used.
  const { aks } = await akSet(deps, caller, va);
  const ak = await (deps.newAK ?? (async () => crypto.getRandomValues(new Uint8Array(32))))();
  e2e.checkNewAk(ak, [...aks.values()]);
  next.epoch = epoch;
  next.akCommit = await e2e.akCommit(ak, artifact, epoch);
  aks.set(epoch, ak);

  // The new epoch for every listed member, and every earlier epoch for one the
  // record adds: not listed under this fingerprint before, and holding no wrap
  // through an approval.
  const wraps = [];
  for (const m of next.members) {
    const u = byId.get(m.user);
    const held = latest.members.some((l) => l.user === m.user && l.fp === m.fp)
      || pending.some((p) => p.user.id === m.user && p.state === PENDING_APPROVED && p.user.fp === m.fp);
    const epochs = held ? [epoch] : Array.from({ length: epoch }, (_, k) => k + 1);
    for (const e of epochs) wraps.push(await wrapTo(u, artifact, e, needAK(aks, e, `share with ${u.email}, who needs it`)));
  }
  // The owner holds no wraps and reads each epoch through the estate copy,
  // which only the owner can seal. A manager sends none, and wraps the new
  // epoch to the owner instead; the owner's client adds the copy later.
  const estate = [];
  if (r.manager) {
    const owner = byId.get(latest.owner);
    if (!owner) throw new SharingError('owner-missing', "The owner's account is not in the directory, so no key can be wrapped to them.");
    // A server could serve its own key in the owner's place and so learn the
    // new AK: the directory's key must be the chain's, or follow from it.
    const linked = e2e.rotationLinker(va.membership.rotations);
    if (!(await linked(latest.owner, latest.ownerFp, owner.fp))) {
      throw new SharingError('owner-key-changed', "The owner's key in the directory is not the one the artifact's records name, so the new key cannot be sealed to them.");
    }
    wraps.push(await wrapTo(owner, artifact, epoch, ak));
  } else {
    const ekKey = await e2e.ekSealCryptoKey(caller.record.ek);
    estate.push({ epoch, sealed: e2e.b64(await e2e.seal(ekKey, ['estate', artifact, String(epoch)], ak)) });
  }

  // Build the link first: a host the link format refuses must fail before any
  // record is written.
  let link = '';
  let linkHash = '';
  if (next.public) {
    link = e2e.publicLink(deps.origin, artifact, ak, epoch, va.chain.bodies[0].ownerFp);
    linkHash = await e2e.linkTokenHash(await e2e.linkToken(ak, artifact, epoch));
  }
  return { next, wraps, estate, linkHash, link, excluded, pins, listed: lst.listed };
}

// putNextEpoch signs and PUTs a next-epoch record built as buildNextEpoch
// makes it, then stores the pins the build decided. It returns {excluded,
// link, listed, dropped}: dropped are the groups the record dropped because
// they no longer exist. Mirrors putNextEpoch.
async function putNextEpoch(deps, caller, va, dir, pending, next, r) {
  const b = await buildNextEpoch(deps, caller, va, dir, pending, next, r);
  const dropped = await putRecord(deps, caller, va, b.next, b.wraps, b.estate, b.linkHash);
  await storePins(deps, caller, b.pins);
  return { excluded: b.excluded, link: b.link, listed: b.listed, dropped };
}

// coverEndsNextEpoch is a change to the team share or the groups that leaves
// an unlisted holder of a wrap without a reason to read: a next-epoch record,
// next, that excludes each of them, and lists the ones another group or the
// team still covers. It reads the artifact back and re-seals. Returns what
// putNextEpoch does, with reseal.
async function coverEndsNextEpoch(deps, caller, va, pending, next, manager) {
  const dir = await directory(deps);
  const change = await putNextEpoch(deps, caller, va, dir, pending, next, { manager });
  await readBack(deps, caller, va, change.link);
  return { ...change, reseal: await resealInto(deps, caller, va.artifact) };
}

// unshare removes who, a member's email or user ID, from an artifact in a
// next-epoch record: the new epoch's AK is wrapped to every member who stays,
// and who is excluded is listed in the result. who may also be a team or group
// member who holds a wrap and is not listed, as a user who left every group
// is. The caller must be the owner or a manager. Returns {epoch, reseal, user,
// excluded, link, listed, droppedGroups}. Mirrors Unshare.
export async function unshare(deps, artifactId, who) {
  const { caller, va, manager } = await adminAction(deps, artifactId);
  const latest = va.latest;
  const dir = await directory(deps);
  let u;
  try {
    u = findUser(dir, who);
  } catch (err) {
    const m = latest.members.find((x) => x.user === who);
    if (err.code !== 'unknown-user' || !m) throw err;
    // A listed member whose account was deleted, named by user ID.
    u = { id: who, email: '', fp: m.fp };
  }
  if (u.id === latest.owner) throw new SharingError('unshare-owner', 'The owner cannot be removed from the artifact.');
  const pending = await pendingFor(deps, caller, va);
  const kept = latest.members.filter((m) => m.user !== u.id);
  const holds = pending.some((p) => p.user.id === u.id && [PENDING_APPROVED, PENDING_LEFT, PENDING_KEY_CHANGED, PENDING_ROTATED].includes(p.state));
  if (kept.length === latest.members.length && !holds) throw new SharingError('not-member', `The user is not a member of the artifact: ${u.email || u.id}`);
  if (latest.members.some((m) => m.user === u.id && m.role === 'manager')) checkOwnerOnly(manager, 'remove a manager');
  // Excluded whether listed or not, so a server that still reports a listed
  // user approved cannot get them listed again by the team.
  const change = await putNextEpoch(deps, caller, va, dir, pending, { ...latest, members: kept }, { exclude: u.id, manager });
  await readBack(deps, caller, va, change.link);
  return { epoch: latest.epoch + 1, user: u, excluded: change.excluded, link: change.link, listed: change.listed, droppedGroups: change.dropped, reseal: await resealInto(deps, caller, artifactId) };
}

// ---- approving, groups, and the team share ----

// approve approves who, a team or group member waiting for access, at the
// artifact's current epoch: it wraps the AK of every epoch to them and signs an
// approval of their name and fingerprint. The caller must be the owner or a
// listed editor or manager. It refuses, before asking the server, a user the
// chain excludes, a directory in which two user IDs share an email or a
// fingerprint, a user who is listed, already approved, or whose key changed
// after they were wrapped to, and a user whose pinned key changed, unless
// acceptNewKey. While the team share is off, the user must be listed by the
// verified chain of a listed group that holds them, under the fingerprint the
// directory serves for them: a difference is a GroupKeyChangedError, which
// acceptNewKey overrides too. The pin is stored once the server accepts the
// approval. Returns {user, prior, wasVerified, epoch}. Mirrors Approve.
export async function approve(deps, artifactId, who, { acceptNewKey = false } = {}) {
  const caller = await unlock(deps);
  const va = await verifyArtifact(deps, caller, artifactId);
  checkHandover(va);
  const latest = va.latest;
  if (!mayApprove(caller, latest)) throw new SharingError('not-approver', 'Only the artifact\'s owner, an editor, or a manager can approve people.');
  if (latest.team === 'none' && (latest.groups ?? []).length === 0) throw new SharingError('no-team', 'The artifact is not shared with Everyone or a group, so there is no one to approve.');
  const dir = await directory(deps);
  const u = findUser(dir, who);
  const x = e2e.excludedMatch(latest.excluded, u.id, u.fp, u.email);
  if (x) throw new SharingError('excluded', `${u.email} matches the excluded entry for ${x.email} (${x.user}).`);
  const pending = await pendingFor(deps, caller, va);
  const p = pending.find((e) => e.user.id === u.id) ?? null;
  const listed = latest.members.some((m) => m.user === u.id);
  // A listed member whose key changed is pending as keyChanged, so this check
  // comes before already-listed. A user who holds a wrap and rotated is listed
  // by the owner, by sharing with them again.
  if (p && (p.state === PENDING_KEY_CHANGED || (p.state === PENDING_ROTATED && !listed))) {
    throw new SharingError('changed-key', `The keys of ${u.email} changed after they were wrapped to or listed. The owner shares with them again.`);
  }
  if (u.id === latest.owner || listed) throw new SharingError('already-listed', `${u.email} is already a member of the artifact.`);
  if (!p || p.state === PENDING_LEFT) throw new SharingError('not-waiting', `${u.email} is not waiting for approval on this artifact.`);
  if (p.state === PENDING_APPROVED) throw new SharingError('already-approved', `${u.email} is already approved; the owner lists them in the next record.`);
  if (p.user.fp !== u.fp) throw new SharingError('pending-keys-differ', `The server serves different keys for ${u.email} in the directory and in the pending list.`);
  await checkGroupCover(deps, caller, va, latest, p, u, acceptNewKey);
  const { prior, pin: decided } = await checkPin(deps, va.keyring, u, acceptNewKey, va.membership.rotations);
  // Defense in depth behind verifyChain's epoch pin, which already refuses a
  // stale epoch.
  e2e.checkEncryptEpoch(epochPinOf(va.keyring, artifactId), latest.epoch);
  const { aks } = await akSet(deps, caller, va);
  const wraps = [];
  for (let epoch = 1; epoch <= latest.epoch; epoch++) {
    const w = await wrapTo(u, artifactId, epoch, needAK(aks, epoch, `approve ${u.email}, who needs it`));
    wraps.push({ epoch, wrapped: w.wrapped });
  }
  const approval = await e2e.signApproval(caller.record.ed25519, caller.record.userId, { artifact: artifactId, epoch: latest.epoch, user: u.id, fp: u.fp });
  const basedOn = pinOf(va.keyring, u.id)?.fp ?? '';
  await call(deps, null, 'POST', `/api/artifacts/${artifactId}/keys`, { body: { user: u.id, fp: u.fp, approval, wraps } });
  if (decided) {
    try {
      await storePin(deps, caller, u.id, decided, basedOn);
    } catch (err) {
      throw new SharingError(err.code ?? 'pin', `The server accepted the approval, but pinning ${u.email} failed: ${err.message}`, { cause: err });
    }
  }
  return { user: u, prior, wasVerified: wasVerified(va.keyring, u.id, prior), epoch: latest.epoch };
}

// byGroup sorts group shares by group ID, as a record lists them.
const byGroup = (a, b) => (a.group < b.group ? -1 : a.group > b.group ? 1 : 0);

// shareGroup lists the group groupId in the artifact's member list with role,
// viewer or editor, in a same-epoch record, or changes the role it is listed
// under. It then approves each current member of the group's verified chain
// who is waiting: the keys the directory serves for them must be the ones the
// group record lists, and the pin checks of approve must pass. The others stay
// pending, with a reason. The record also lists each approved member whose
// approval passes the four checks. The caller must be the owner or a manager.
// Returns {group: {id, name}, role, epoch, unchanged, approved, pending,
// listed, unlisted, droppedGroups}: approved are users, pending and unlisted
// are {user, error}. Mirrors ShareGroup.
export async function shareGroup(deps, artifactId, groupId, role, { acceptNewKey = false } = {}) {
  const { caller, va } = await adminAction(deps, artifactId);
  const latest = va.latest;
  if (!(await listGroups(deps)).some((g) => g.id === groupId)) throw new SharingError('unknown-group', `There is no group with the ID ${groupId}.`);
  if (role !== 'viewer' && role !== 'editor') throw new SharingError('bad-role', `A group is shared as viewer or editor, not ${JSON.stringify(role)}.`);
  const vg = await verifyGroup(deps, groupId, { acceptNewKey });
  va.keyring = await readKeyring(deps, caller);
  const res = { group: { id: groupId, name: vg.chain.latest.name }, role, epoch: latest.epoch, unchanged: false, approved: [], pending: [], listed: [], unlisted: [], droppedGroups: [] };
  const pending = await pendingFor(deps, caller, va);
  const dir = await directory(deps);
  const next = { ...latest, groups: (latest.groups ?? []).map((g) => ({ ...g })) };
  const at = next.groups.findIndex((g) => g.group === groupId);
  if (at >= 0) next.groups[at].role = role;
  else next.groups = [...next.groups, { group: groupId, role }].sort(byGroup);
  next.members = latest.members.map((m) => ({ ...m }));
  const lst = await listApproved(deps, caller, va, dir, pending, next, (id) => next.members.some((m) => m.user === id));
  Object.assign(res, { listed: lst.listed, unlisted: lst.unlisted });
  if (JSON.stringify(latest.groups ?? []) === JSON.stringify(next.groups) && lst.members.length === 0) {
    res.unchanged = true;
  } else {
    next.members = [...next.members, ...lst.members].sort(byUser);
    res.droppedGroups = await putRecord(deps, caller, va, next, [], [], '');
    await storePins(deps, caller, lst.pins);
    await readBack(deps, caller, va, '');
  }
  await approveGroupMembers(deps, artifactId, vg.chain, acceptNewKey, res);
  return res;
}

// approveGroupMembers approves each member of chain who waits as new, and
// records the outcome in res: approved, or pending with the reason. A member
// whose directory key differs from the chain's is left pending without a
// request, as is any whose approval fails a check; only a failure that ends
// the command, as fatalFetch says, is an error. The artifact is verified again
// first: the record that lists the group has landed. Mirrors
// approveGroupMembers.
async function approveGroupMembers(deps, artifactId, chain, acceptNewKey, res) {
  const caller = await unlock(deps);
  const va = await verifyArtifact(deps, caller, artifactId);
  const pending = await pendingFor(deps, caller, va);
  for (const m of chain.latest.members) {
    const p = pending.find((e) => e.user.id === m.user && e.state === PENDING_NEW);
    if (!p) continue;
    const u = p.user;
    if (u.fp !== m.fp) {
      res.pending.push({ user: u, error: new GroupKeyChangedError({ user: u, group: chain.latest.group, groupFp: m.fp }) });
      continue;
    }
    try {
      await approve(deps, artifactId, u.id, { acceptNewKey });
    } catch (refused) {
      if (fatalFetch(refused)) throw refused;
      res.pending.push({ user: u, error: refused });
      continue;
    }
    res.approved.push(u);
  }
}

// unshareGroup drops the group groupId, the ID of a listed group, which may be
// deleted, from the artifact's member list. When someone read the artifact
// only through that group, a next-epoch record drops it and excludes them.
// Otherwise a same-epoch record does. The caller must be the owner or a
// manager. Returns {group: {id, name}, epoch, reseal, excluded, link, listed,
// droppedGroups}: reseal is null for a same-epoch record. Mirrors
// UnshareGroup.
export async function unshareGroup(deps, artifactId, groupId) {
  const { caller, va, manager } = await adminAction(deps, artifactId);
  const latest = va.latest;
  if (!(latest.groups ?? []).some((g) => g.group === groupId)) throw new SharingError('not-shared-with-group', `The artifact is not shared with the group ${groupId}.`);
  let name = '';
  try {
    name = (await listGroups(deps)).find((s) => s.id === groupId)?.name ?? '';
  } catch (err) {
    if (fatalFetch(err)) throw err;
  }
  const pending = await pendingFor(deps, caller, va);
  const next = { ...latest, groups: latest.groups.filter((g) => g.group !== groupId) };
  const res = { group: { id: groupId, name }, epoch: latest.epoch, reseal: null, excluded: [], link: '', listed: [], droppedGroups: [] };
  if (holdersLose(pending, latest, next)) {
    const change = await coverEndsNextEpoch(deps, caller, va, pending, next, manager);
    return { ...res, epoch: latest.epoch + 1, reseal: change.reseal, excluded: change.excluded, link: change.link, listed: change.listed, droppedGroups: change.dropped };
  }
  res.droppedGroups = await putRecord(deps, caller, va, next, [], [], '');
  await readBack(deps, caller, va, '');
  return res;
}

// setTeam sets whom the artifact is shared with as Everyone (none, viewer, or
// editor) in a same-epoch record, and lists each approved team member whose
// approval passes the four checks, under the role the team grants. Setting none
// while a team member holds a wrap, and no listed group covers them, starts a
// new epoch, which excludes every such member. The caller must be the owner or
// a manager. Returns {team, epoch, unchanged, listed, unlisted, reseal,
// excluded, link, droppedGroups}. Mirrors Team.
export async function setTeam(deps, artifactId, team) {
  if (team !== 'none' && team !== 'viewer' && team !== 'editor') throw new SharingError('bad-team', `Everyone is none, viewer, or editor, not ${JSON.stringify(team)}.`);
  const { caller, va, manager } = await adminAction(deps, artifactId);
  const latest = va.latest;
  const pending = await pendingFor(deps, caller, va);
  const res = { team, epoch: latest.epoch, unchanged: false, listed: [], unlisted: [], reseal: null, excluded: [], link: '', droppedGroups: [] };
  const next = { ...latest, team };
  if (team === 'none' && holdersLose(pending, latest, next)) {
    // A team member holds a wrap while they are approved, or while a wrap they
    // hold is for keys that are no longer theirs. A listed group still covers
    // the approved ones it holds.
    const change = await coverEndsNextEpoch(deps, caller, va, pending, next, manager);
    return { ...res, epoch: latest.epoch + 1, reseal: change.reseal, excluded: change.excluded, link: change.link, listed: change.listed, droppedGroups: change.dropped };
  }
  const dir = await directory(deps);
  const lst = await listApproved(deps, caller, va, dir, pending, next, (id) => latest.members.some((m) => m.user === id));
  Object.assign(res, { listed: lst.listed, unlisted: lst.unlisted });
  if (latest.team === team && lst.members.length === 0) return { ...res, unchanged: true };
  next.members = [...latest.members, ...lst.members].sort(byUser);
  res.droppedGroups = await putRecord(deps, caller, va, next, [], [], '');
  await storePins(deps, caller, lst.pins);
  await readBack(deps, caller, va, '');
  return res;
}

// waiting is what the share dialog shows an approver: the newcomers waiting
// for approval, each with their fingerprint and the groups that hold them (or
// Everyone, which holds them all while the team share is on), and the users
// who left every group but still hold the key. An editor sees newcomers
// only. canApprove is false for anyone who may approve nobody. The server
// names the groups; each is verified when someone is approved.
// Returns {canApprove, team, newcomers, left}: a newcomer is {user, name,
// email, fp, groups: [{id, name}], everyone}, a user who left {user, name,
// email, fp}.
export async function waiting(deps, artifactId) {
  const caller = await unlock(deps);
  const va = await verifyArtifact(deps, caller, artifactId);
  const latest = va.latest;
  const res = { canApprove: mayApprove(caller, latest), team: latest.team, newcomers: [], left: [] };
  if (!res.canApprove) return res;
  const pending = await pendingFor(deps, caller, va);
  const held = pending.filter((p) => p.state === PENDING_NEW && p.groups.length > 0);
  const names = held.length > 0 ? new Map((await listGroups(deps)).map((g) => [g.id, g.name])) : new Map();
  const row = (p) => ({ user: p.user.id, name: p.user.name, email: p.user.email, fp: p.user.fp });
  for (const p of pending) {
    if (p.state === PENDING_NEW) res.newcomers.push({ ...row(p), groups: p.groups.map((id) => ({ id, name: names.get(id) ?? '' })), everyone: latest.team !== 'none' });
    if (p.state === PENDING_LEFT) res.left.push(row(p));
  }
  return res;
}

// approvableCount is how many newcomers the server says wait on an artifact:
// a hint for the Artifacts tab, a single request that checks nothing. The
// dialog verifies the artifact, and approve checks everything before it wraps.
export async function approvableCount(deps, artifactId) {
  const list = await call(deps, null, 'GET', `/api/artifacts/${artifactId}/pending`);
  if (!Array.isArray(list)) throw new e2e.FormatError('the list of people waiting is not a list');
  return list.filter((p) => p.state === PENDING_NEW).length;
}

// ---- public links ----

// setPublic makes the artifact public, or sets whether a signed-in link holder
// may write (writes, true or false; left as it is when omitted, which for an
// artifact going public is off), in a same-epoch record that carries the link
// token hash the server needs. The caller must be the owner. Off on a public
// artifact starts a new epoch, so the old link stops working, and off on a
// private one writes nothing. The link is built before any record is written,
// so a host the link format refuses leaves the artifact unchanged. Returns
// {link, epoch, reseal}: link is the public link when on, else null. Also
// public, publicWrites, unchanged, newEpoch, excluded, listed (approved users
// a new epoch lists), and droppedGroups. Mirrors Public.
export async function setPublic(deps, artifactId, on, { writes } = {}) {
  if (!on && writes !== undefined) throw new SharingError('public-writes-with-off', 'Public writes set who can write through a public link, so they go with on, not off.');
  const { caller, va, manager } = await adminAction(deps, artifactId);
  const latest = va.latest;
  const res = { link: null, epoch: latest.epoch, reseal: null, public: false, publicWrites: false, unchanged: false, newEpoch: false, excluded: [], listed: [], droppedGroups: [] };
  if (!on) {
    if (!latest.public) return { ...res, unchanged: true };
    return publicOffNextEpoch(deps, caller, va, res, manager);
  }
  const next = { ...latest, public: true, publicWrites: writes === undefined ? latest.publicWrites : writes };
  Object.assign(res, { public: true, publicWrites: next.publicWrites });
  // Build the link first: a host the link format refuses must fail before any
  // record is written, or the artifact is public with no link.
  res.link = await linkOf(deps, caller, va);
  if (latest.public && next.publicWrites === latest.publicWrites) return { ...res, unchanged: true };
  res.droppedGroups = await putRecord(deps, caller, va, next, [], [], '');
  await readBack(deps, caller, va, '');
  return res;
}

// linkOf is the public link of the latest epoch, built from the AK the caller
// holds.
async function linkOf(deps, caller, va) {
  const { aks } = await akSet(deps, caller, va);
  needAK(aks, va.latest.epoch, 'make its link');
  try {
    return e2e.publicLink(deps.origin, va.artifact, aks.get(va.latest.epoch), va.latest.epoch, va.chain.bodies[0].ownerFp);
  } catch (err) {
    throw new SharingError('bad-host', `Cannot make a link for host ${deps.origin}: ${err.message}`, { cause: err });
  }
}

// publicOffNextEpoch makes a public artifact private in a next-epoch record.
async function publicOffNextEpoch(deps, caller, va, res, manager) {
  const dir = await directory(deps);
  const pending = await pendingFor(deps, caller, va);
  const change = await putNextEpoch(deps, caller, va, dir, pending, { ...va.latest, public: false, publicWrites: false }, { manager });
  await readBack(deps, caller, va, '');
  return { ...res, epoch: va.latest.epoch + 1, newEpoch: true, excluded: change.excluded, listed: change.listed, droppedGroups: change.dropped, reseal: await resealInto(deps, caller, va.artifact) };
}

// publicLinkFor is the artifact's current public link, rebuilt from the
// current epoch's AK, which a member holds, or null when the artifact is not
// public.
export async function publicLinkFor(deps, artifactId) {
  const caller = await unlock(deps);
  const va = await verifyArtifact(deps, caller, artifactId);
  return va.latest.public ? linkOf(deps, caller, va) : null;
}

// ---- re-sealing ----

// bodyBefore is the last record before the chain's current epoch began, the
// record whose writers made what is to be re-sealed, or null when the chain is
// still in its first epoch.
function bodyBefore(chain) {
  for (let i = chain.bodies.length - 1; i >= 0; i--) if (chain.bodies[i].epoch < chain.latest.epoch) return chain.bodies[i];
  return null;
}

function akObject(aks) {
  const out = {};
  for (const [epoch, ak] of aks) out[String(epoch)] = e2e.b64(ak);
  return out;
}

const EPOCH_RE = /^(0|[1-9][0-9]{0,15})$/;
const REVISION_RE = /^[1-9][0-9]{0,15}$/;
const BLOB_ID_BYTES = 16;

// seenRevisions is the highest revision read or written per version for each
// deps: a read of a lower one is a rollback. Mirrors seenRevisions in data.go.
const seenRevisions = new WeakMap();

function noteLatest(deps, version, revision) {
  if (!seenRevisions.has(deps)) seenRevisions.set(deps, new Map());
  const seen = seenRevisions.get(deps);
  const key = `${deps.origin}/${version}`;
  if (revision < (seen.get(key) ?? 0)) throw new Error(`revision ${revision} is older than revision ${seen.get(key)}, already seen`);
  seen.set(key, revision);
}

function raiseSeen(deps, version, revision) {
  if (!seenRevisions.has(deps)) seenRevisions.set(deps, new Map());
  const seen = seenRevisions.get(deps);
  const key = `${deps.origin}/${version}`;
  if ((seen.get(key) ?? 0) < revision) seen.set(key, revision);
}

async function sendRaw(deps, method, path, { body, headers } = {}) {
  return deps.fetch(path, { method, headers: headers ?? {}, body });
}

async function failure(resp) {
  const data = await resp.json().catch(() => ({}));
  return new ApiError(data.error || `request failed (${resp.status})`, resp.status);
}

// fetched reads the blob a revision or file answer carries, and the envelope,
// epoch, and signer key in its headers, and checks nothing but their shape.
// Mirrors readFetched.
async function fetched(resp, withRevision) {
  const epoch = resp.headers.get('X-Cairn-Epoch');
  if (typeof epoch !== 'string' || !EPOCH_RE.test(epoch)) throw new e2e.FormatError('the epoch is not a number');
  const f = { epoch: Number(epoch), signerKey: resp.headers.get('X-Cairn-Signer-Key') ?? '', revision: 0 };
  if (withRevision) {
    const rev = resp.headers.get('X-Cairn-Revision');
    if (typeof rev !== 'string' || !REVISION_RE.test(rev)) throw new e2e.FormatError('the revision is not a number');
    f.revision = Number(rev);
  }
  const record = resp.headers.get('X-Cairn-Record');
  if (typeof record !== 'string') throw new e2e.FormatError('the record is not an envelope');
  f.env = e2e.decodeEnvelope(e2e.unb64(record));
  f.blob = new Uint8Array(await resp.arrayBuffer());
  return f;
}

function multipart(parts) {
  const form = new FormData();
  for (const [name, value, filename] of parts) {
    if (value instanceof Uint8Array) form.append(name, new Blob([value]), filename ?? name);
    else form.append(name, value);
  }
  return form;
}

async function putChecked(deps, path, form, headers) {
  const resp = await sendRaw(deps, 'PUT', path, { body: form, headers });
  if (resp.ok) return;
  const err = await failure(resp);
  if (resp.status === 409) throw new SharingError('epoch-moved', 'The artifact moved to a new epoch; run it again.', { cause: err });
  throw err;
}

// resealDatabase writes the latest revision again under the current epoch,
// when it was sealed under an earlier one and the check accepts it.
async function resealDatabase(deps, caller, va, aks, keys, v, res) {
  const path = `/api/artifacts/${va.artifact}/versions/${v.id}`;
  const resp = await sendRaw(deps, 'GET', `${path}/db`);
  if (resp.status === 404) return;
  if (!resp.ok) throw await failure(resp);
  const f = await fetched(resp, true);
  if (f.epoch >= va.latest.epoch) return;
  let plain;
  try {
    const { ak } = await checkSigned(keys, 'revision', f.env, f.signerKey, { epoch: f.epoch, revision: f.revision, blob: f.blob });
    plain = await e2e.openBlob(ak, { artifact: va.artifact, version: v.id, kind: 'database', name: String(f.revision) }, f.blob);
  } catch (err) {
    res.skipped.push({ what: `the database of version ${v.id}, revision ${f.revision}`, reason: err.message });
    return;
  }
  noteLatest(deps, v.id, f.revision);
  await putRevision(deps, caller, va, aks, v, plain, f.revision);
  res.resealed.push(`the database of version ${v.id}`);
}

// putRevision seals plain and signs it as revision base+1 under the current
// epoch, and uploads it with If-Match naming base. Mirrors PutRevision.
async function putRevision(deps, caller, va, aks, v, plain, base) {
  const epoch = va.latest.epoch;
  const ak = aks.get(epoch);
  if (!ak) throw new SharingError('no-write-key', `You hold no key for the artifact's current epoch ${epoch}.`);
  const revision = base + 1;
  const blob = await e2e.sealBlob(ak, { artifact: va.artifact, version: v.id, kind: 'database', name: String(revision) }, plain);
  const body = { v: 1, artifact: va.artifact, version: v.id, revision, epoch, sha256: await e2e.bodyHash(blob) };
  const record = await e2e.newEnvelope(caller.record.ed25519, caller.record.userId, 'revision', encoder.encode(JSON.stringify(body)));
  await putChecked(deps, `/api/artifacts/${va.artifact}/versions/${v.id}/db`, multipart([['record', JSON.stringify(record)], ['blob', blob]]), { 'If-Match': `"${base}"` });
  raiseSeen(deps, v.id, revision);
}

async function addressAt(artifact, aks, epoch, path) {
  return e2e.fileAddress(await e2e.fileKey(aks.get(epoch), artifact, epoch), path);
}

// resealFiles stores each file sealed under an earlier epoch and accepted by
// the check at its address under the current one, then deletes the old
// address. A path already stored under the current epoch keeps that copy.
async function resealFiles(deps, caller, va, aks, keys, v, res) {
  const base = `/api/artifacts/${va.artifact}/versions/${v.id}`;
  const listing = await sendRaw(deps, 'GET', `${base}/files`);
  if (!listing.ok) throw await failure(listing);
  const items = await listing.json();
  if (!Array.isArray(items)) throw new e2e.FormatError('the file list is not a list');
  const current = va.latest.epoch;
  const have = new Set(items.map((item) => item?.address));
  for (const item of items) {
    if (!(item?.epoch < current)) continue;
    let m;
    let plain;
    try {
      m = await openEntry(keys, item);
      plain = await readFile(deps, va, keys, v, item.epoch, item.address);
    } catch (err) {
      res.skipped.push({ what: `a stored file of version ${v.id}`, reason: err.message });
      continue;
    }
    const address = await addressAt(va.artifact, aks, current, m.path);
    if (!have.has(address)) {
      await putFile(deps, caller, va, aks, v, m.path, plain, m.modifiedAt);
      have.add(address);
    }
    const del = await sendRaw(deps, 'DELETE', `${base}/files/${item.address}`);
    if (!del.ok && del.status !== 404) throw await failure(del);
    res.resealed.push(`a stored file of version ${v.id}: ${m.path}`);
  }
}

// readFile reads the file at address, stored under epoch, and checks it.
async function readFile(deps, va, keys, v, epoch, address) {
  const resp = await sendRaw(deps, 'GET', `/api/artifacts/${va.artifact}/versions/${v.id}/files/${address}`);
  if (resp.status === 404) throw new Error('the server no longer has the file');
  if (!resp.ok) throw await failure(resp);
  const f = await fetched(resp, false);
  if (f.epoch !== epoch) throw new Error('the file is stored under another epoch than its address');
  const { ak } = await checkSigned(keys, 'record', f.env, f.signerKey, { epoch, kind: 'file', name: address, blob: f.blob });
  return e2e.openBlob(ak, { artifact: va.artifact, version: v.id, kind: 'file', name: address }, f.blob);
}

// putFile seals plain and its metadata for path under the current epoch, signs
// both, and stores them. Mirrors putAt.
async function putFile(deps, caller, va, aks, v, path, plain, modifiedAt) {
  const epoch = va.latest.epoch;
  const ak = aks.get(epoch);
  if (!ak) throw new SharingError('no-write-key', `You hold no key for the artifact's current epoch ${epoch}.`);
  const address = await addressAt(va.artifact, aks, epoch, path);
  const ctxOf = (kind) => ({ artifact: va.artifact, version: v.id, kind, name: address });
  const blob = await e2e.sealBlob(ak, ctxOf('file'), plain);
  const meta = await e2e.sealBlob(ak, ctxOf('file-meta'), encoder.encode(JSON.stringify({ v: 1, path, size: plain.length, modifiedAt })));
  const sign = async (kind, b) => {
    const body = { v: 1, artifact: va.artifact, version: v.id, kind, name: address, epoch, sha256: await e2e.bodyHash(b) };
    return e2e.newEnvelope(caller.record.ed25519, caller.record.userId, 'record', encoder.encode(JSON.stringify(body)));
  };
  const record = await sign('file', blob);
  const metaRecord = await sign('file-meta', meta);
  const form = multipart([['record', JSON.stringify(record)], ['blob', blob], ['metaRecord', JSON.stringify(metaRecord)], ['meta', meta]]);
  await putChecked(deps, `/api/artifacts/${va.artifact}/versions/${v.id}/files/${address}`, form);
}

// resealVersion replaces the artifact's latest version, the one with the
// highest seq, with the same files sealed under the current epoch and signed
// by the caller, under the same version ID. It does so only when the version's
// manifest and every blob verify under its own epoch and its signer is still
// the owner, an editor, or a manager in the latest record; otherwise the version is left
// as it is and noted in skipped, for the owner's review. Mirrors resealVersion.
async function resealVersion(deps, caller, va, aks, opened, v, res) {
  const current = va.latest.epoch;
  if (!v || v.epoch >= current) return;
  const skip = (reason) => res.skipped.push({ what: `version ${v.id}`, reason: `it waits for the owner's review: ${reason}` });
  let trusted;
  try {
    trusted = await trustVersionManifest(deps, opened, v);
  } catch (err) {
    if (err instanceof ApiError) throw err;
    skip(err instanceof UntrustedVersionError ? 'it was signed by someone the change removed' : err.message);
    return;
  }
  // A vouched version has no signer the latest record trusts.
  if (!trusted.signer) {
    skip('it was signed by someone the change removed');
    return;
  }
  const ak = aks.get(v.epoch);
  const newAK = aks.get(current);
  if (!newAK) throw new SharingError('no-write-key', `Version ${v.id}: you hold no key for epoch ${current}.`);
  const plains = new Map();
  for (const f of trusted.manifest.files) {
    let plain;
    try {
      const resp = await sendRaw(deps, 'GET', `/api/artifacts/${va.artifact}/versions/${v.id}/blobs/${f.blob}`);
      if (!resp.ok) throw await failure(resp);
      const blob = new Uint8Array(await resp.arrayBuffer());
      if ((await e2e.bodyHash(blob)) !== f.sha256) throw new Error("it does not match the manifest's hash");
      plain = await e2e.openBlob(ak, { artifact: va.artifact, version: v.id, kind: 'content', name: f.path }, blob);
    } catch (err) {
      skip(`the blob of ${f.path}: ${err.message}`);
      return;
    }
    plains.set(f.path, plain);
  }
  await uploadVersion(deps, caller, va, v, current, newAK, plains);
  res.resealed.push(`version ${v.id}`);
}

// uploadVersion seals files, a map of slash path to content, under ak, the AK
// of epoch, signs the manifest listing them, and replaces version v with
// them. The upload declares epoch, so the server refuses it if the epoch has
// moved since. Mirrors uploadVersion.
async function uploadVersion(deps, caller, va, v, epoch, ak, files) {
  const parts = [];
  const entries = [];
  for (const path of [...files.keys()].sort()) {
    const data = files.get(path);
    const blob = await e2e.sealBlob(ak, { artifact: va.artifact, version: v.id, kind: 'content', name: path }, data);
    const id = e2e.toHex(crypto.getRandomValues(new Uint8Array(BLOB_ID_BYTES)));
    parts.push(['blob', blob, id]);
    entries.push({ path, blob: id, size: data.length, sha256: await e2e.bodyHash(blob) });
  }
  const body = encoder.encode(JSON.stringify({ v: 1, artifact: va.artifact, version: v.id, epoch, files: entries }));
  const env = await e2e.newEnvelope(caller.record.ed25519, caller.record.userId, 'manifest', body);
  const sealed = await e2e.sealBlob(ak, { artifact: va.artifact, version: v.id, kind: 'manifest', name: '' }, encoder.encode(JSON.stringify(env)));
  parts.push(['manifest', sealed, 'manifest']);
  parts.push(['version', JSON.stringify({ id: v.id, epoch, manifestHash: await e2e.bodyHash(body) })]);
  await putChecked(deps, `/api/artifacts/${va.artifact}/versions/${v.id}`, multipart(parts));
}

// recordEpoch is the epoch a meta item's record names, read without checking
// it, or null. It only says whether the field is already under the current
// epoch; a field that is not is checked before anything is made of it.
function recordEpoch(item) {
  try {
    return e2e.decodeStrict(e2e.unb64(e2e.decodeEnvelope(JSON.stringify(item.record)).body), e2e.BODY_SCHEMAS.record).epoch;
  } catch {
    return null;
  }
}

// resealMeta writes each metadata field of the artifact and of version v again
// under the current epoch, signed by the caller, when it verifies under the
// record before the change. One that does not is left as it is and noted in
// skipped.
async function resealMeta(deps, va, aks, opened, old, v, res) {
  const view = await call(deps, null, 'GET', `/api/artifacts/${va.artifact}`);
  const keys = { artifact: va.artifact, epoch: 1, aks: akObject(aks), writers: old.writers, publicWrites: false };
  const scopes = [['', 'the artifact', view.meta]];
  if (v) scopes.push([v.id, `version ${v.id}`, v.meta]);
  for (const [versionId, label, meta] of scopes) {
    const fields = versionId === '' ? META_FIELDS.artifact : META_FIELDS.version;
    for (const field of fields) {
      if (!meta || !Object.hasOwn(meta, field)) continue;
      const epoch = recordEpoch(meta[field]);
      if (epoch !== null && epoch >= va.latest.epoch) continue;
      let value;
      try {
        ({ value } = await openMetaItem({ ...keys, version: versionId }, versionId, field, meta[field]));
      } catch (err) {
        res.skipped.push({ what: `the ${field} of ${label}`, reason: err.message });
        continue;
      }
      await writeMeta(deps, opened, versionId, field, value);
      res.resealed.push(`the ${field} of ${label}`);
    }
  }
}

// runReseal re-seals every version's data that verifies under the record
// before the current epoch began, and the latest version's content when
// someone the latest record still trusts signed it, then the metadata fields.
// What fails a check, such as a revision signed by someone the change removed,
// is left as it is and noted in res.skipped. On an error it has noted what it
// had done in res. Mirrors reseal.
async function runReseal(deps, caller, va, res) {
  const before = bodyBefore(va.chain);
  if (!before) return;
  const { aks } = await akSet(deps, caller, va);
  const opened = { ...va, aks };
  const old = { writers: await writerKeys(deps, { ...opened, latest: before }) };
  const versions = await call(deps, null, 'GET', `/api/artifacts/${va.artifact}/versions`);
  if (!Array.isArray(versions)) throw new e2e.FormatError('the version list is not a list');
  for (const v of versions) {
    const keys = { artifact: va.artifact, version: v.id, epoch: v.epoch, aks: akObject(aks), writers: old.writers, publicWrites: before.publicWrites };
    try {
      await resealDatabase(deps, caller, va, aks, keys, v, res);
      await resealFiles(deps, caller, va, aks, keys, v, res);
    } catch (err) {
      throw new Error(`version ${v.id}: ${err.message}`, { cause: err });
    }
  }
  let latestVersion = null;
  for (const v of versions) if (!latestVersion || v.seq > latestVersion.seq) latestVersion = v;
  await resealVersion(deps, caller, va, aks, opened, latestVersion, res);
  await resealMeta(deps, va, aks, opened, old, latestVersion, res);
}

// resealInto re-seals after the record that started a new epoch, and returns
// the outcome. A failure is res.error, with what was done before it: reseal
// runs it again.
async function resealInto(deps, caller, artifact) {
  const res = { resealed: [], skipped: [] };
  try {
    await runReseal(deps, caller, await verifyArtifact(deps, caller, artifact), res);
  } catch (err) {
    res.error = err;
  }
  return res;
}

// reseal seals the artifact's data and metadata under its current epoch again,
// signed by the caller, who must be the owner, an editor, or a manager. It is safe to run
// at any time: what is already under the current epoch is left as it is.
// Returns {resealed: [string], skipped: [{what, reason}]}; on an error the
// error carries the same as its result. Mirrors Reseal.
export async function reseal(deps, artifactId) {
  const caller = await unlock(deps);
  const va = await verifyArtifact(deps, caller, artifactId);
  checkHandover(va);
  const latest = va.latest;
  const id = caller.record.userId;
  const approver = latest.owner === id
    ? latest.ownerFp === caller.fp
    : latest.members.some((m) => m.user === id && (m.role === 'editor' || m.role === 'manager') && m.fp === caller.fp);
  if (!approver) throw new SharingError('cannot-reseal', "Only the artifact's owner, an editor, or a manager can re-seal its data.");
  e2e.checkEncryptEpoch(epochPinOf(va.keyring, artifactId), latest.epoch);
  const res = { resealed: [], skipped: [] };
  try {
    await runReseal(deps, caller, va, res);
  } catch (err) {
    err.result = res;
    throw err;
  }
  return res;
}
