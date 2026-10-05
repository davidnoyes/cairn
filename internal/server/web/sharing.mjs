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
// Deliberately not ported, because the browser has no approval or team
// screens yet: team sharing (approve.go, `team` other than "none"), which is
// refused, a member's rotation as pendingFor reports it, and acknowledging a
// handover, which is refused until the owner does so with the CLI.
import * as e2e from './e2e.mjs';
import { ApiError } from './account.mjs';
import { UntrustedVersionError, call, callerAKs, checkArtifact, readKeyring, recordChain, signedInCaller, trustVersionManifest, updateKeyring, writerKeys } from './viewer.mjs';
import { checkSigned, openEntry } from './data.mjs';
import { META_FIELDS, openMetaItem, writeMeta } from './meta.mjs';

const encoder = new TextEncoder();

// SharingError is a refusal of this module. code says which, for a page that
// answers it: not-signed-in, bad-role, not-owner, share-self, unshare-owner,
// unknown-user, directory-duplicate, not-member, member-key-changed,
// member-deleted, pin-conflict, public-writes-with-off, cannot-reseal,
// team-unsupported, handover-not-acked, no-write-key, read-back, epoch-moved.
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
  return { id: w.id, name: w.name, email: w.email, x25519Pub, ed25519Pub, resetAt: w.resetAt ?? '' };
}

async function directory(deps) {
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
function findUser(dir, who) {
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
function fatalFetch(err) {
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
async function followPinFor(deps, kr, u, known) {
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
async function checkPin(deps, kr, u, acceptNewKey, known) {
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
function wasVerified(kr, user, prior) {
  return prior === e2e.PIN_ROTATED && pinOf(kr, user)?.state === e2e.PIN_VERIFIED;
}

// storePin writes a pin for user. basedOn is the fingerprint the keyring
// pinned for user when the caller decided on pin, or '' if it pinned none.
// Against the keyring as it is when written, which another device may have
// changed since: a pin at the same fingerprint is never downgraded from
// verified, and a pin at a fingerprint other than basedOn is a pin-conflict.
async function storePin(deps, caller, user, pin, basedOn) {
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

function checkNoTeam(va) {
  if (va.latest.team !== 'none') throw new SharingError('team-unsupported', 'This artifact is shared with a team, which the browser cannot change yet. Use the cairn tool.');
}

function checkOwner(caller, va) {
  if (va.latest.owner !== caller.record.userId || va.latest.ownerFp !== caller.fp) {
    throw new SharingError('not-owner', "Only the artifact's owner can change its members.");
  }
}

// ownerAction is the start of every owner-side change: the caller, the
// verified artifact, and the three refusals Share, Unshare and Public make
// before anything else.
async function ownerAction(deps, artifactId) {
  const caller = await unlock(deps);
  const va = await verifyArtifact(deps, caller, artifactId);
  checkHandover(va);
  checkOwner(caller, va);
  checkNoTeam(va);
  return { caller, va };
}

const epochPinOf = (kr, artifact) => (Object.hasOwn(kr.epochs, artifact) ? kr.epochs[artifact] : null);

// ---- records ----

const byUser = (a, b) => (a.user < b.user ? -1 : a.user > b.user ? 1 : 0);

// membershipBody is next as the record after the verified chain's latest,
// fields in the order of the schema. transfer and handover are never set by
// these commands. Mirrors signNext.
function membershipBody(va, next) {
  return {
    v: 1,
    artifact: va.artifact,
    epoch: next.epoch,
    seq: va.latest.seq + 1,
    owner: next.owner,
    ownerFp: next.ownerFp,
    akCommit: next.akCommit,
    members: next.members.map((m) => ({ user: m.user, role: m.role, fp: m.fp })),
    excluded: next.excluded.map((x) => ({ user: x.user, fp: x.fp, email: x.email })),
    team: next.team,
    public: next.public,
    publicWrites: next.publicWrites,
    prev: va.chain.head,
    transfer: '',
    handover: '',
  };
}

// linkTokenHashFor is the hash of the epoch's link token the server stores for
// a public record, from the owner's estate copy of the epoch's AK.
async function linkTokenHashFor(deps, caller, va, epoch) {
  const aks = await callerAKs(deps, caller, va.artifact, va.chain);
  return e2e.linkTokenHash(await e2e.linkToken(aks.get(epoch), va.artifact, epoch));
}

// putRecord signs next as the record after the verified chain's latest and
// PUTs it with wraps and, for a next epoch, the estate copy of its AK. A
// public record carries the hash of the epoch's link token, which the server
// requires of every public record: linkHash for a next epoch, whose estate
// copy the server does not hold yet, or '' to take it from the epoch's own.
// Mirrors putRecord.
async function putRecord(deps, caller, va, next, wraps, estate, linkHash) {
  const body = encoder.encode(JSON.stringify(membershipBody(va, next)));
  const membership = await e2e.newEnvelope(caller.record.ed25519, caller.record.userId, 'membership', body);
  let hash = linkHash;
  if (next.public && hash === '') hash = await linkTokenHashFor(deps, caller, va, next.epoch);
  await call(deps, null, 'PUT', `/api/artifacts/${va.artifact}/membership`, { body: { membership, wraps, estate, linkTokenHash: hash } });
}

// readBack verifies the artifact after the server accepted a record. A failure
// still names link, the new public link, when there is one: the old link
// already stopped working. Mirrors readBack.
async function readBack(deps, caller, artifact, link) {
  try {
    await verifyArtifact(deps, caller, artifact, caller.fp);
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

// ---- members, share, unshare ----

// members verifies an artifact's chain and lists its owner and members, each
// with the pin state of their current keys: self for the caller, - for a user
// the directory no longer lists, a pin state otherwise, and conflict when the
// rotation records fork or roll back. currentFp is the fingerprint of the
// keys the directory serves now, which differs from fp once they change, or
// empty for a user it no longer lists. wasVerified says a rotation dropped a
// verified pin. Mirrors Members.
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
    if (u) {
      r.name = u.name;
      r.email = u.email;
    }
  }
  return { artifact: artifactId, epoch: latest.epoch, seq: latest.seq, public: latest.public, publicWrites: latest.publicWrites, members: rows };
}

// share adds who, an email or a user ID, to an artifact at its current epoch
// with role viewer or editor, or changes their role: promoting a viewer is a
// same-epoch record, and demoting an editor starts a new epoch. Sharing by
// name with a user the owner excluded lists them again and drops the entries
// they match. It refuses a directory with duplicate emails or fingerprints,
// and a user whose keys changed since they were pinned unless acceptNewKey. A
// user seen for the first time is pinned unverified. A user the record did
// not list holds no wrap yet, so the new member gets a wrap of every epoch's
// AK, opened from the owner's estate copies and checked against the chain's
// akCommit. Returns {epoch, reseal}, with reseal the result of re-sealing
// when a new epoch started, else null, and more besides: user, prior, role,
// promoted, demoted, unchanged, dropped, wasVerified, and for a new epoch
// excluded and link. Mirrors Share.
export async function share(deps, artifactId, who, role, { acceptNewKey = false } = {}) {
  if (role !== 'viewer' && role !== 'editor') throw new SharingError('bad-role', `The role must be viewer or editor, not ${JSON.stringify(role)}.`);
  const { caller, va } = await ownerAction(deps, artifactId);
  const latest = va.latest;
  const dir = await directory(deps);
  const u = findUser(dir, who);
  if (u.id === caller.record.userId) throw new SharingError('share-self', 'The owner already has access to the artifact.');
  const { prior, pin: decided } = await checkPin(deps, va.keyring, u, acceptNewKey, va.membership.rotations);
  const res = {
    user: u, prior, wasVerified: wasVerified(va.keyring, u.id, prior), role, epoch: latest.epoch, reseal: null,
    promoted: false, demoted: false, unchanged: false, dropped: [], excluded: [], link: '',
  };

  const list = latest.members.map((m) => ({ ...m }));
  const i = list.findIndex((m) => m.user === u.id);
  let needsWraps = true;
  let demote = false;
  if (i < 0) {
    list.push({ user: u.id, role, fp: u.fp });
  } else {
    demote = list[i].role === 'editor' && role === 'viewer';
    res.promoted = list[i].role !== role && !demote;
    res.demoted = demote;
    const relist = list[i].fp !== u.fp;
    needsWraps = relist;
    res.unchanged = !res.promoted && !demote && !relist;
    list[i] = { user: u.id, role, fp: u.fp };
  }
  const basedOn = pinOf(va.keyring, u.id)?.fp ?? '';
  if (demote) return shareNextEpoch(deps, caller, va, dir, list, u, decided, basedOn, res);
  if (res.unchanged) {
    if (decided) await storePin(deps, caller, u.id, decided, basedOn);
    return res;
  }
  list.sort(byUser);

  const wraps = [];
  if (needsWraps) {
    // Defense in depth behind verifyChain's epoch pin, which already refuses a
    // stale epoch.
    e2e.checkEncryptEpoch(epochPinOf(va.keyring, artifactId), latest.epoch);
    const aks = await callerAKs(deps, caller, artifactId, va.chain);
    for (let epoch = 1; epoch <= latest.epoch; epoch++) wraps.push(await wrapTo(u, artifactId, epoch, aks.get(epoch)));
  }
  const { kept, dropped } = dropExcluded(latest.excluded, list, dir);
  res.dropped = dropped;
  await putRecord(deps, caller, va, { ...latest, members: list, excluded: kept }, wraps, [], '');
  if (decided) {
    try {
      await storePin(deps, caller, u.id, decided, basedOn);
    } catch (err) {
      throw new SharingError(err.code ?? 'pin', `The server accepted the new membership record, but pinning ${u.email} failed: ${err.message}`, { cause: err });
    }
  }
  await readBack(deps, caller, artifactId, '');
  return res;
}

// shareNextEpoch is share when the change demotes an editor: the demoted user
// stays listed as a viewer and the record starts a new epoch.
async function shareNextEpoch(deps, caller, va, dir, list, u, decided, basedOn, res) {
  const change = await putNextEpoch(deps, caller, va, dir, { ...va.latest, members: list }, { decided: u.id });
  res.epoch = va.latest.epoch + 1;
  if (decided) {
    try {
      await storePin(deps, caller, u.id, decided, basedOn);
    } catch (err) {
      throw new SharingError(err.code ?? 'pin', `The server accepted the new membership record, but pinning ${u.email} failed: ${err.message}`, { cause: err });
    }
  }
  await readBack(deps, caller, va.artifact, change.link);
  Object.assign(res, { excluded: change.excluded, link: change.link, reseal: await resealInto(deps, caller, va.artifact) });
  return res;
}

// buildNextEpoch builds a next-epoch record from next, the record to write
// with the members and public switches the change wants, and sends nothing. It
// makes the new AK, wraps it to every listed member, seals the estate copy,
// and excludes every member the record removes. r.decided is a member whose
// pin the caller already decided; r.exclude is a user the caller removes.
// Mirrors buildNextEpoch, less teams and approvals.
async function buildNextEpoch(deps, caller, va, dir, nextIn, r) {
  const { artifact, latest } = va;
  const epoch = latest.epoch + 1;
  // Defense in depth behind verifyChain's epoch pin, which already refuses a
  // stale epoch.
  e2e.checkEncryptEpoch(epochPinOf(va.keyring, artifact), epoch);
  const next = { ...nextIn, members: [...nextIn.members].sort(byUser) };
  const byId = new Map(dir.map((u) => [u.id, u]));
  const inMembers = (id) => next.members.some((m) => m.user === id);

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

  // Every member is listed under their current keys, and a pinned key that
  // differs from them is the owner's to decide about.
  const pins = new Map();
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
  const aks = await callerAKs(deps, caller, artifact, va.chain);
  const ak = await (deps.newAK ?? (async () => crypto.getRandomValues(new Uint8Array(32))))();
  e2e.checkNewAk(ak, [...aks.values()]);
  next.epoch = epoch;
  next.akCommit = await e2e.akCommit(ak, artifact, epoch);
  aks.set(epoch, ak);

  // The new epoch for every listed member, and every earlier epoch for one the
  // record adds: not listed under this fingerprint before.
  const wraps = [];
  for (const m of next.members) {
    const u = byId.get(m.user);
    const held = latest.members.some((l) => l.user === m.user && l.fp === m.fp);
    const epochs = held ? [epoch] : Array.from({ length: epoch }, (_, k) => k + 1);
    for (const e of epochs) wraps.push(await wrapTo(u, artifact, e, aks.get(e)));
  }
  const ekKey = await e2e.ekSealCryptoKey(caller.record.ek);
  const estate = [{ epoch, sealed: e2e.b64(await e2e.seal(ekKey, ['estate', artifact, String(epoch)], ak)) }];

  // Build the link first: a host the link format refuses must fail before any
  // record is written.
  let link = '';
  let linkHash = '';
  if (next.public) {
    link = e2e.publicLink(deps.origin, artifact, ak, epoch, va.chain.bodies[0].ownerFp);
    linkHash = await e2e.linkTokenHash(await e2e.linkToken(ak, artifact, epoch));
  }
  return { next, wraps, estate, linkHash, link, excluded, pins };
}

// putNextEpoch signs and PUTs a next-epoch record built as buildNextEpoch
// makes it, then stores the pins the build decided. It returns {excluded,
// link}. Mirrors putNextEpoch.
async function putNextEpoch(deps, caller, va, dir, next, r) {
  const b = await buildNextEpoch(deps, caller, va, dir, next, r);
  await putRecord(deps, caller, va, b.next, b.wraps, b.estate, b.linkHash);
  for (const [id, d] of b.pins) {
    try {
      await storePin(deps, caller, id, d.pin, d.basedOn);
    } catch (err) {
      throw new SharingError(err.code ?? 'pin', `The server accepted the new membership record, but pinning ${id} failed: ${err.message}`, { cause: err });
    }
  }
  return { excluded: b.excluded, link: b.link };
}

// unshare removes who, a member's email or user ID, from an artifact in a
// next-epoch record: the new epoch's AK is wrapped to every member who stays,
// and who is excluded is listed in the result. The caller must be the owner.
// Returns {epoch, reseal, user, excluded, link}. Mirrors Unshare.
export async function unshare(deps, artifactId, who) {
  const { caller, va } = await ownerAction(deps, artifactId);
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
  if (u.id === caller.record.userId) throw new SharingError('unshare-owner', 'The owner cannot be removed from the artifact.');
  const kept = latest.members.filter((m) => m.user !== u.id);
  if (kept.length === latest.members.length) throw new SharingError('not-member', `The user is not a member of the artifact: ${u.email || u.id}`);
  const change = await putNextEpoch(deps, caller, va, dir, { ...latest, members: kept }, { exclude: u.id });
  await readBack(deps, caller, artifactId, change.link);
  return { epoch: latest.epoch + 1, user: u, excluded: change.excluded, link: change.link, reseal: await resealInto(deps, caller, artifactId) };
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
// public, publicWrites, unchanged, newEpoch, and excluded. Mirrors Public.
export async function setPublic(deps, artifactId, on, { writes } = {}) {
  if (!on && writes !== undefined) throw new SharingError('public-writes-with-off', 'Public writes set who can write through a public link, so they go with on, not off.');
  const { caller, va } = await ownerAction(deps, artifactId);
  const latest = va.latest;
  const res = { link: null, epoch: latest.epoch, reseal: null, public: false, publicWrites: false, unchanged: false, newEpoch: false, excluded: [] };
  if (!on) {
    if (!latest.public) return { ...res, unchanged: true };
    return publicOffNextEpoch(deps, caller, va, res);
  }
  const next = { ...latest, public: true, publicWrites: writes === undefined ? latest.publicWrites : writes };
  Object.assign(res, { public: true, publicWrites: next.publicWrites });
  // Build the link first: a host the link format refuses must fail before any
  // record is written, or the artifact is public with no link.
  res.link = await linkOf(deps, caller, va);
  if (latest.public && next.publicWrites === latest.publicWrites) return { ...res, unchanged: true };
  await putRecord(deps, caller, va, next, [], [], '');
  await readBack(deps, caller, artifactId, '');
  return res;
}

// linkOf is the public link of the latest epoch, built from the AK the caller
// holds.
async function linkOf(deps, caller, va) {
  const aks = await callerAKs(deps, caller, va.artifact, va.chain);
  try {
    return e2e.publicLink(deps.origin, va.artifact, aks.get(va.latest.epoch), va.latest.epoch, va.chain.bodies[0].ownerFp);
  } catch (err) {
    throw new SharingError('bad-host', `Cannot make a link for host ${deps.origin}: ${err.message}`, { cause: err });
  }
}

// publicOffNextEpoch makes a public artifact private in a next-epoch record.
async function publicOffNextEpoch(deps, caller, va, res) {
  const dir = await directory(deps);
  const change = await putNextEpoch(deps, caller, va, dir, { ...va.latest, public: false, publicWrites: false }, {});
  await readBack(deps, caller, va.artifact, '');
  return { ...res, epoch: va.latest.epoch + 1, newEpoch: true, excluded: change.excluded, reseal: await resealInto(deps, caller, va.artifact) };
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
// the owner or an editor in the latest record; otherwise the version is left
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
  const aks = await callerAKs(deps, caller, va.artifact, va.chain);
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
// signed by the caller, who must be the owner or an editor. It is safe to run
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
    : latest.members.some((m) => m.user === id && m.role === 'editor' && m.fp === caller.fp);
  if (!approver) throw new SharingError('cannot-reseal', "Only the artifact's owner or an editor can re-seal its data.");
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
