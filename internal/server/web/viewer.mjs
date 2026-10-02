// viewer.mjs — what the shell page (shell.mjs) does before it frames anything:
// verify the artifact's membership chain, open the keys, and decide whether a
// version is trusted. It mirrors the Go client (internal/client/) function by
// function, and every cryptographic operation comes from e2e.mjs and
// content.mjs. The server is untrusted throughout: every answer it gives is
// checked here.
//
// Nothing here reads a browser global. Each function takes `deps`:
//
//   fetch(path, options)   like window.fetch
//   keyStore               {load()}, see keystore.mjs
//   storage                localStorage, which holds the keyring anchor
//   origin                 the app origin, location.origin
import * as e2e from './e2e.mjs';
import { ApiError } from './account.mjs';
import { openManifest } from './content.mjs';

// UNTRUSTED_MESSAGE is the sentence the shell shows for a version it will not
// frame.
export const UNTRUSTED_MESSAGE = 'This version was pushed by someone who is no longer an editor, and the owner has not reviewed it.';

export class UntrustedVersionError extends Error {
  constructor() {
    super(UNTRUSTED_MESSAGE);
    this.name = 'UntrustedVersionError';
  }
}

// NoAccessError is an artifact the caller can open neither as a member nor
// with a public link.
export class NoAccessError extends Error {
  constructor(message = "You can't open this artifact. Sign in with an account that has access, or use the artifact's full public link.") {
    super(message);
    this.name = 'NoAccessError';
  }
}

const STALE_KEYS_MESSAGE = 'The keys this browser holds for you were saved by an older version of Cairn. Sign out, then sign in again.';

export class LinkError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LinkError';
  }
}

// KeyringBusyError mirrors ErrKeyringBusy.
export class KeyringBusyError extends Error {
  constructor() {
    super('The keyring kept changing on the server while this page tried to update it. Reload the page to try again.');
    this.name = 'KeyringBusyError';
  }
}

// PinConflictError mirrors ErrPinConflict: the keyring pins the creator at
// another fingerprint than the chain was verified against.
export class PinConflictError extends Error {
  constructor(user) {
    super(`The keyring pins ${user} at another fingerprint than this artifact's chain was verified against.`);
    this.name = 'PinConflictError';
  }
}

const KEYRING_RETRIES = 5;
const MAX_MANIFEST_BYTES = 16 << 20;
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const NAVIGATE_RE = new RegExp(`^/shared/(${UUID})(?:/(${UUID}))?/?$`);

// call sends one request and returns the parsed JSON answer, or the bytes
// when raw. A failure is an ApiError carrying the server's {"error"} message.
// A request made through a public link carries its token.
async function call(deps, linkToken, method, path, { body, raw } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (linkToken) headers['X-Cairn-Link-Token'] = linkToken;
  const resp = await deps.fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    throw new ApiError(data.error || `request failed (${resp.status})`, resp.status);
  }
  return raw ? new Uint8Array(await resp.arrayBuffer()) : resp.json();
}

// apiGet reads JSON for an opened artifact, carrying the link token when the
// artifact was opened through a link.
export function apiGet(deps, opened, path) {
  return call(deps, opened.linkToken, 'GET', path);
}

function notFound(err) {
  return err instanceof ApiError && err.status === 404;
}

function keyBytes(kp) {
  const x25519 = e2e.unb64(kp.x25519);
  const ed25519 = e2e.unb64(kp.ed25519);
  if (x25519.length !== 32 || ed25519.length !== 32) throw new e2e.FormatError('a public key is not 32 bytes');
  return { x25519, ed25519 };
}

async function fingerprintOf(kp) {
  const { x25519, ed25519 } = keyBytes(kp);
  return e2e.toHex(await e2e.fingerprint(x25519, ed25519));
}

// takeLink removes the fragment from the address bar, then reads the public
// link from it, so the key is out of the address bar and the history entry
// before anything else runs, even when the fragment is malformed. It returns
// null when there is no fragment, and throws LinkError when the fragment is
// not a link; openArtifact reports that only to someone who is not a member,
// so a member's page anchor does not lock them out. The link is read as one
// for this host and this artifact. Mirrors the public-link rules of ParseLink.
export function takeLink(location, history, artifact) {
  const hash = location.hash;
  if (!hash) return null;
  history.replaceState(null, '', location.pathname + location.search);
  try {
    return e2e.parseLink(location.origin + '/shared/' + artifact + hash);
  } catch {
    throw new LinkError('This link is incomplete or damaged. Copy the whole link and open it again.');
  }
}

// readKeyring fetches the keyring, opens it against the stored anchor, and
// stores the new anchor. Mirrors readKeyring and openKeyring in keyring.go.
async function readKeyring(deps, caller) {
  const anchor = e2e.loadKeyringAnchor(deps.storage, caller.record.userId, caller.fp);
  const resp = await call(deps, null, 'GET', '/api/me/keyring');
  const { keyring, anchor: next } = await e2e.openKeyring(caller.record.mkSeal, resp.rev, e2e.unb64(resp.keyring), anchor);
  e2e.saveKeyringAnchor(deps.storage, caller.record.userId, caller.fp, next);
  return keyring;
}

// updateKeyring reads the keyring, applies change to a copy, and writes it at
// the next rev, reading again and re-applying change when the server answers
// 409, up to five times. Mirrors UpdateKeyring in keyring.go.
async function updateKeyring(deps, caller, change) {
  for (let i = 0; i < KEYRING_RETRIES; i++) {
    const cur = await readKeyring(deps, caller);
    const next = structuredClone(cur);
    change(next);
    next.rev = cur.rev + 1;
    const sealed = await e2e.sealKeyring(caller.record.mkSeal, next);
    try {
      await call(deps, null, 'PUT', '/api/me/keyring', { body: { rev: next.rev, keyring: e2e.b64(sealed) } });
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) continue;
      throw err;
    }
    e2e.saveKeyringAnchor(deps.storage, caller.record.userId, caller.fp, await e2e.keyringAnchorOf(next.rev, sealed));
    return next;
  }
  throw new KeyringBusyError();
}

// creatorKeys is the creator's public keys for a first-sight anchor: the
// directory's, or, when the directory has no such user, the owner keys the
// server served for record 0's ownerFp. Both are server-served and
// unverified; the chain check then refuses keys that do not hash to the
// fingerprint record 0 names. Mirrors creatorKeys in keyring.go.
async function creatorKeys(deps, membership, creator) {
  let user;
  try {
    user = await call(deps, null, 'GET', `/api/users/${creator}`);
  } catch (err) {
    if (notFound(err)) {
      try {
        const first = e2e.decodeStrict(e2e.unb64(membership.records[0].body), e2e.BODY_SCHEMAS.membership);
        if (Object.hasOwn(membership.owners, first.ownerFp)) return keyBytes(membership.owners[first.ownerFp]);
      } catch {
        // Fall through: the 404 is the error to report.
      }
    }
    throw err;
  }
  return keyBytes({ x25519: user.x25519Pub, ed25519: user.ed25519Pub });
}

// checkArtifact verifies the membership chain against the keyring kr. The
// first record is anchored at the creator's pinned fingerprint, the caller's
// own when the caller created it, or on first sight the directory's. The
// keyring's epochs entry is the pin, so a chain shorter than the stored seq,
// or forked at it, is refused. It stores nothing, and returns the creator and
// the first-sight pin recordChain would store, or null. Mirrors
// checkArtifact in keyring.go.
async function checkArtifact(deps, caller, kr, artifact, membership) {
  const records = membership.records;
  if (!Array.isArray(records) || records.length === 0) throw new e2e.ChainError('no records');
  const creator = records[0].signer;
  let anchor = caller.fp;
  let newPin = null;
  if (creator !== caller.record.userId) {
    if (Object.hasOwn(kr.pins, creator)) {
      anchor = kr.pins[creator].fp;
    } else {
      const keys = await creatorKeys(deps, membership, creator);
      anchor = (await e2e.pinState(null, keys.x25519, keys.ed25519)).fp;
      newPin = { fp: anchor, state: e2e.PIN_UNVERIFIED, rotSeq: 0, rotHead: '' };
    }
  }
  const epoch = Object.hasOwn(kr.epochs, artifact) ? kr.epochs[artifact] : null;
  const chain = await e2e.verifyChain({
    artifact,
    records,
    owners: membership.owners,
    offers: membership.offers,
    anchor,
    pin: epoch && { epoch: epoch.epoch, seq: epoch.seq, head: epoch.head },
    linked: e2e.rotationLinker(membership.rotations),
  });
  return { chain, creator, newPin };
}

// recordChain stores a verified chain as the artifact's epochs entry, and a
// first-sight pin for its creator, unless the keyring already holds both. On
// a merge it keeps whichever entry has the higher seq, and refuses a creator
// pinned at another fingerprint than the chain was verified against, or the
// same seq at another head. Mirrors recordChain in keyring.go.
async function recordChain(deps, caller, kr, artifact, chain, creator, pin) {
  const prior = Object.hasOwn(kr.epochs, artifact) ? kr.epochs[artifact] : null;
  const latest = chain.latest;
  if (prior && pin === null && prior.epoch === latest.epoch && prior.seq === latest.seq && prior.head === chain.head) return kr;
  let anchorFP = '';
  if (pin) anchorFP = pin.fp;
  else if (creator !== caller.record.userId) anchorFP = kr.pins[creator].fp;
  return updateKeyring(deps, caller, (k) => {
    if (Object.hasOwn(k.pins, creator) && anchorFP !== '' && k.pins[creator].fp !== anchorFP) throw new PinConflictError(creator);
    const cur = Object.hasOwn(k.epochs, artifact) ? k.epochs[artifact] : null;
    if (cur && cur.seq === latest.seq && cur.head !== chain.head) {
      throw new e2e.ForkError(`record ${cur.seq} of artifact ${artifact}`);
    }
    if (!cur || cur.seq < latest.seq) {
      k.epochs[artifact] = { epoch: latest.epoch, seq: latest.seq, head: chain.head, ack: cur ? cur.ack : 0 };
    }
    if (pin && !Object.hasOwn(k.pins, creator)) k.pins[creator] = pin;
  });
}

// epochCommits is the akCommit the chain lists for each epoch, from the first
// record of that epoch. Mirrors epochCommits in share.go.
function epochCommits(chain) {
  const commits = new Map();
  for (const b of chain.bodies) if (!commits.has(b.epoch)) commits.set(b.epoch, b.akCommit);
  return commits;
}

async function checkCommit(ak, artifact, epoch, commits, what) {
  if (!commits.has(epoch) || (await e2e.akCommit(ak, artifact, epoch)) !== commits.get(epoch)) {
    throw new e2e.ChainError(`${what} of epoch ${epoch} does not match the chain's akCommit`);
  }
}

// callerAKs returns the AK of every epoch up to the chain's latest: for the
// owner from the estate copies, for anyone else by opening their own wraps.
// Each is checked against the akCommit the verified chain lists. Mirrors
// callerAKs in approve.go and epochAKs in share.go.
async function callerAKs(deps, caller, artifact, chain) {
  const commits = epochCommits(chain);
  const keys = await call(deps, null, 'GET', `/api/artifacts/${artifact}/keys`);
  const aks = new Map();
  if (chain.latest.owner === caller.record.userId) {
    const ekKey = await e2e.ekSealCryptoKey(caller.record.ek);
    for (const e of keys.estate) {
      const ak = await e2e.open(ekKey, ['estate', artifact, String(e.epoch)], e2e.unb64(e.sealed));
      await checkCommit(ak, artifact, e.epoch, commits, 'the estate copy');
      aks.set(e.epoch, ak);
    }
  } else {
    for (const w of keys.wraps) {
      const ak = await e2e.unwrap(
        caller.record.x25519,
        { purpose: 'ak', artifact, epoch: w.epoch, recipientId: caller.record.userId, recipientPub: caller.record.x25519.publicKey },
        e2e.unb64(w.wrapped),
      );
      await checkCommit(ak, artifact, w.epoch, commits, 'your wrap');
      aks.set(w.epoch, ak);
    }
  }
  for (let epoch = 1; epoch <= chain.latest.epoch; epoch++) {
    if (!aks.has(epoch)) throw new e2e.ChainError(`the server holds no key for you for epoch ${epoch}`);
  }
  return aks;
}

// signedInCaller is the signed-in user: a key-store record with the Ed25519
// public key, whose user is the one the server's session names. It returns
// null for a visitor, and {stale: true} for a record written before the
// Ed25519 public key was added to it, which reads as signed out.
async function signedInCaller(deps) {
  const record = await deps.keyStore.load();
  if (!record) return null;
  if (!(record.ed25519Pub instanceof Uint8Array)) return { stale: true };
  let me;
  try {
    me = await call(deps, null, 'GET', '/api/me');
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return null;
    throw err;
  }
  if (me.id !== record.userId) return null;
  const fp = e2e.toHex(await e2e.fingerprint(record.x25519.publicKey, record.ed25519Pub));
  return { me, record, fp };
}

function listed(latest, userId) {
  return latest.owner === userId || latest.members.some((m) => m.user === userId);
}

// openAsMember reads the keyring, verifies the chain against it, and when the
// caller is listed in the latest record, records the chain in the keyring and
// opens the caller's AKs. It returns null when the server will not show the
// caller the membership, or the caller is not listed. Mirrors VerifyArtifact
// in keyring.go.
async function openAsMember(deps, caller, artifact) {
  const kr = await readKeyring(deps, caller);
  let membership;
  try {
    membership = await call(deps, null, 'GET', `/api/artifacts/${artifact}/membership`);
  } catch (err) {
    if (err instanceof ApiError && (err.status === 403 || err.status === 404)) return null;
    throw err;
  }
  const { chain, creator, newPin } = await checkArtifact(deps, caller, kr, artifact, membership);
  if (!listed(chain.latest, caller.record.userId)) return null;
  await recordChain(deps, caller, kr, artifact, chain, creator, newPin);
  const aks = await callerAKs(deps, caller, artifact, chain);
  return { mode: 'member', artifact, chain, latest: chain.latest, aks, membership, caller: caller.me, record: caller.record, linkToken: null, link: null };
}

// openAsLink reads the membership with the link's token and verifies it as
// verifyLinkChain does. It writes no keyring. It does not pass the served
// editor keys on: they matter only to the editors verifyLinkChain returns,
// which this does not use, because a manifest's signer is checked against
// them in trustedSigner, rotation links included. Mirrors OpenLink in
// public.go.
async function openAsLink(deps, caller, artifact, link) {
  if (link.host !== deps.origin) throw new LinkError('This link is for another server.');
  if (link.artifact !== artifact) throw new LinkError('This link is for another artifact.');
  const linkToken = e2e.b64(await e2e.linkToken(link.ak, link.artifact, link.epoch));
  let membership;
  try {
    membership = await call(deps, linkToken, 'GET', `/api/artifacts/${artifact}/membership`);
  } catch (err) {
    if (err instanceof ApiError && (err.status === 403 || err.status === 404)) {
      throw new LinkError('This link does not open the artifact. The owner may have turned it off.');
    }
    throw err;
  }
  const { chain } = await e2e.verifyLinkChain({
    link,
    records: membership.records,
    owners: membership.owners,
    offers: membership.offers,
    rotations: membership.rotations,
  });
  return {
    mode: 'link',
    artifact,
    chain,
    latest: chain.latest,
    aks: new Map([[link.epoch, link.ak]]),
    membership,
    caller: caller ? caller.me : null,
    record: caller ? caller.record : null,
    linkToken,
    link,
  };
}

// openArtifact decides the mode and verifies. Signed in and listed in the
// latest record: member mode. Otherwise, with a public link: link mode.
// Otherwise it throws linkError, the LinkError takeLink threw, if any, and
// else NoAccessError. link is takeLink's result, or null. Returns what the
// later steps need: the mode, the chain and its latest record, the AKs by
// epoch, the membership answer, the caller (or null), the link token (or
// null), and the link.
export async function openArtifact(deps, { artifact, link, linkError = null }) {
  const found = await signedInCaller(deps);
  const caller = found?.stale ? null : found;
  if (caller) {
    const opened = await openAsMember(deps, caller, artifact);
    if (opened) return opened;
  }
  if (link) return openAsLink(deps, caller, artifact, link);
  if (linkError) throw linkError;
  throw new NoAccessError(found?.stale ? STALE_KEYS_MESSAGE : undefined);
}

// candidatePairs are the public key pairs the server or the caller's own keys
// offer for user: the caller's own, else (as a member) the directory's, or
// (through a link) the membership answer's editor keys; the owner keys the
// membership served; and the old and new pairs of the user's rotation
// records. A pair counts only once its fingerprint is checked, so where the
// keys come from does not matter. Mirrors manifestSignerKeys in review.go.
async function candidatePairs(deps, opened, user) {
  const pairs = [];
  if (opened.record && user === opened.record.userId) {
    pairs.push({ x25519: e2e.b64(opened.record.x25519.publicKey), ed25519: e2e.b64(opened.record.ed25519Pub) });
  } else if (opened.mode === 'member') {
    try {
      const u = await call(deps, null, 'GET', `/api/users/${user}`);
      pairs.push({ x25519: u.x25519Pub, ed25519: u.ed25519Pub });
    } catch (err) {
      if (!notFound(err)) throw err;
    }
  } else if (opened.membership.keys && Object.hasOwn(opened.membership.keys, user)) {
    pairs.push(opened.membership.keys[user]);
  }
  pairs.push(...Object.values(opened.membership.owners ?? {}));
  const rotations = opened.membership.rotations;
  for (const env of rotations && Object.hasOwn(rotations, user) ? rotations[user] : []) {
    try {
      const b = e2e.decodeStrict(e2e.unb64(env.body), e2e.BODY_SCHEMAS.rotation);
      pairs.push(b.old, b.new);
    } catch {
      // Skipping a record that does not decode can only shrink the candidates.
    }
  }
  return pairs;
}

// trustedSigner is the signer a manifest is trusted through, or null. The
// envelope's signer must be the latest record's owner or a member it lists as
// editor, and the signature must verify under a key pair whose fingerprint is
// the one the record lists for them, or one a rotation chain links to it.
// Trust is the latest record only: someone listed in an earlier record and
// since removed is not trusted, which is where review.go's checkManifest
// differs, as it accepts anyone the chain ever listed.
async function trustedSigner(deps, opened, env) {
  const latest = opened.latest;
  let listedFp;
  if (env.signer === latest.owner) {
    listedFp = latest.ownerFp;
  } else {
    const m = latest.members.find((x) => x.user === env.signer && x.role === 'editor');
    if (!m) return null;
    listedFp = m.fp;
  }
  const linked = e2e.rotationLinker(opened.membership.rotations);
  for (const kp of await candidatePairs(deps, opened, env.signer)) {
    let fp;
    try {
      fp = await fingerprintOf(kp);
    } catch {
      continue;
    }
    if (!(await linked(env.signer, listedFp, fp))) continue;
    const ed25519 = e2e.unb64(kp.ed25519);
    if (await e2e.verifyEnvelope(ed25519, 'manifest', env)) return { user: env.signer, ed25519: e2e.b64(ed25519) };
  }
  return null;
}

// vouched reports whether the version carries the latest record's owner's
// vouch: signed by the owner under a key whose fingerprint is the record's
// ownerFp, for this artifact, this version, and this manifestHash.
async function vouched(deps, opened, version) {
  const vouch = version.vouch;
  if (!vouch || vouch.signer !== opened.latest.owner) return false;
  for (const kp of await candidatePairs(deps, opened, opened.latest.owner)) {
    try {
      if ((await fingerprintOf(kp)) !== opened.latest.ownerFp) continue;
      const body = await e2e.openEnvelope(vouch, e2e.unb64(kp.ed25519), 'vouch');
      return body.artifact === opened.artifact && body.version === version.id && body.manifest === version.manifestHash;
    } catch {
      // A key that does not decode or verify is not the owner's.
    }
  }
  return false;
}

// trustVersion fetches the version's manifest, opens it under that epoch's
// AK, and decides whether the version is trusted: signed by the latest
// record's owner or an editor, or vouched for by the owner. It then runs
// openManifest with the chosen signer, so a version the shell trusts is one
// the worker accepts. Returns {signer}, which is null when trust is the vouch,
// or throws UntrustedVersionError. version is what GET
// /api/artifacts/{id}/versions/{vid} returns. Mirrors checkManifest in
// review.go.
export async function trustVersion(deps, opened, version) {
  const ak = opened.aks.get(version.epoch);
  if (!ak) throw new LinkError('This version was written under a key this link does not open.');
  const blob = await call(deps, opened.linkToken, 'GET', `/api/artifacts/${opened.artifact}/versions/${version.id}/manifest`, { raw: true });
  if (blob.length > MAX_MANIFEST_BYTES) throw new e2e.FormatError('the manifest is larger than 16 MiB');
  const plain = await e2e.openBlob(ak, { artifact: opened.artifact, version: version.id, kind: 'manifest', name: '' }, blob);
  const env = e2e.decodeEnvelope(plain);
  const signer = await trustedSigner(deps, opened, env);
  if (!signer && !(await vouched(deps, opened, version))) throw new UntrustedVersionError();
  await openManifest({ ak, artifact: opened.artifact, version: version.id, epoch: version.epoch, signer, manifestHash: version.manifestHash, blob });
  return { signer };
}

// prepareVersion reads the version of this artifact the server names, checks
// it is the one asked for, and decides whether it is trusted.
export async function prepareVersion(deps, opened, versionId) {
  const version = await apiGet(deps, opened, `/api/artifacts/${opened.artifact}/versions/${versionId}`);
  if (version.id !== versionId) throw new e2e.FormatError('the server answered for another version');
  const { signer } = await trustVersion(deps, opened, version);
  return { version, signer };
}

// listVersions is the artifact's versions, newest first. Through a link, only
// those at the link's epoch, which the visitor can open.
export async function listVersions(deps, opened) {
  const versions = await apiGet(deps, opened, `/api/artifacts/${opened.artifact}/versions`);
  return opened.mode === 'link' ? versions.filter((v) => v.epoch === opened.link.epoch) : versions;
}

// loadContext is the context a keys message carries: the artifact's id, name,
// and description, and the latest record's owner and members from the
// directory. A visitor with no account has no directory, so users is empty.
export async function loadContext(deps, opened, info) {
  const artifact = { id: opened.artifact, name: info.name, description: info.description ?? '' };
  if (!opened.caller) return { artifact, users: [] };
  const users = [];
  for (const id of [opened.latest.owner, ...opened.latest.members.map((m) => m.user)]) {
    try {
      const u = await call(deps, opened.linkToken, 'GET', `/api/users/${id}`);
      users.push({ id: u.id, name: u.name, email: u.email });
    } catch (err) {
      if (!notFound(err)) throw err;
    }
  }
  return { artifact, users };
}

// keysMessage builds the keys message for version, which checkKeysMessage in
// content.mjs accepts. signer is trustVersion's, token and tokenExpires are
// mintToken's.
export function keysMessage(opened, version, { signer, token, tokenExpires, path, context }) {
  const ak = opened.aks.get(version.epoch);
  if (!ak) throw new LinkError('This version was written under a key this link does not open.');
  return {
    cairn: 'keys',
    artifact: opened.artifact,
    version: version.id,
    epoch: version.epoch,
    ak: e2e.b64(ak),
    signer,
    manifestHash: version.manifestHash,
    token,
    tokenExpires,
    linkToken: opened.linkToken,
    context,
    path,
  };
}

// mintToken asks for a content-origin token when the caller is signed in,
// with the link token when the artifact was opened through a link. A visitor
// gets none.
export async function mintToken(deps, opened) {
  if (!opened.caller) return { token: null, tokenExpires: null };
  const resp = await call(deps, opened.linkToken, 'POST', `/api/artifacts/${opened.artifact}/content-token`, { body: {} });
  return { token: resp.token, tokenExpires: resp.expiresAt };
}

const RETRY_MS = 10000;

// keepToken mints the first token and renews it a minute before it expires,
// handing each renewal to onToken. A renewal the server refuses (401 or 403)
// goes to onError at once. Any other failure is retried every RETRY_MS, and
// goes to onError once the token has less than RETRY_MS left. now,
// setTimeout, and clearTimeout are injected for a test.
export function keepToken({ mint, onToken, onError, now = () => Date.now(), setTimeout: later = setTimeout, clearTimeout: cancel = clearTimeout }) {
  let current = { token: null, tokenExpires: null };
  let timer = null;
  let stopped = false;
  const schedule = () => {
    if (stopped || current.tokenExpires === null) return;
    const wait = Math.max(0, current.tokenExpires * 1000 - 60000 - now());
    timer = later(renew, wait);
  };
  const renew = async () => {
    if (stopped) return;
    try {
      current = await mint();
    } catch (err) {
      const refused = err instanceof ApiError && (err.status === 401 || err.status === 403);
      if (!refused && current.tokenExpires * 1000 - now() > RETRY_MS) timer = later(renew, RETRY_MS);
      else onError(err);
      return;
    }
    onToken(current);
    schedule();
  };
  return {
    current: () => current,
    async start() {
      current = await mint();
      schedule();
      return current;
    },
    stop() {
      stopped = true;
      if (timer !== null) cancel(timer);
    },
  };
}

// navigateTarget is the path the top page may navigate to for a link the
// frame asked for, or null. Only a /shared/<uuid> or /shared/<uuid>/<uuid>
// page on this origin, with lowercase UUIDs: it maps to /full/ in full mode
// and drops the query and fragment.
export function navigateTarget(href, { origin, mode }) {
  let url;
  try {
    url = new URL(href, origin);
  } catch {
    return null;
  }
  if (url.origin !== origin) return null;
  const m = NAVIGATE_RE.exec(url.pathname);
  if (!m) return null;
  return `/${mode === 'full' ? 'full' : 'shared'}/${m[1]}${m[2] ? `/${m[2]}` : ''}`;
}
