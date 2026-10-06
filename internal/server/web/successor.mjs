// successor.mjs — what the browser does for the successor: showing the user's
// own code, nominating someone, removing them, refusing a request, and
// asking for access as a successor. It mirrors the Go client
// (internal/client/successor.go), and every cryptographic operation comes
// from e2e.mjs. See "Successor" in design/e2e-api.md.
//
// Nothing here reads a browser global. Each function takes `deps` as
// sharing.mjs does:
//
//   fetch(path, options)               like window.fetch
//   keyStore                           {load()}, see keystore.mjs
//   stretch(password, email, params)   Argon2id, for the password check
import * as e2e from './e2e.mjs';
import { ApiError, unlock } from './account.mjs';
import { call } from './viewer.mjs';
import { directory, findUser } from './sharing.mjs';

const encoder = new TextEncoder();

const STALE = 'Another device changed your successor since this page read it. Try again.';

// staleSeq maps the server's 409 for a successor record whose seq is not one
// more than the last to a message that says so, and passes any other error
// on. Mirrors staleSeq.
function staleSeq(err) {
  if (err instanceof ApiError && err.status === 409 && err.message.startsWith('seq must be')) return new Error(STALE);
  return err;
}

async function signedIn(deps) {
  const record = await deps.keyStore.load();
  if (!record) throw new Error('Sign in to manage your successor.');
  return record;
}

// myCode is the user's own successor code, computed from the keys in this
// browser, never from the directory.
export async function myCode(record) {
  return e2e.successorCode(await e2e.fingerprint(record.x25519.publicKey, record.ed25519Pub));
}

// status reads the user's successor, any request, and the last record's seq.
export function status(deps) {
  return call(deps, null, 'GET', '/api/me/successor');
}

// signSuccessor signs a successor record of the caller's.
function signSuccessor(record, b) {
  const body = encoder.encode(JSON.stringify({ v: 1, user: record.userId, ...b }));
  return e2e.newEnvelope(record.ed25519, record.userId, 'successor', body);
}

// checkCode finds who in the directory and refuses a code that the keys the
// directory serves for them do not produce. It reads only. Mirrors
// CheckSuccessorCode.
async function checkCode(deps, who, code) {
  let want;
  try {
    want = e2e.parseSuccessorCode(code);
  } catch {
    throw new Error('That is not a successor code. It has 16 letters and digits in groups of four.');
  }
  const u = findUser(await directory(deps), who);
  if (!e2e.fromHex(u.fp).slice(0, want.length).every((b, i) => b === want[i])) {
    throw new Error(`The code does not match the keys the server lists for ${u.email}.`);
  }
  return u;
}

// nominate makes who, an email or user ID, the user's successor, after the
// code checked out against the directory. The password proves the user is
// present and opens EK, which is wrapped to the successor's X25519 key. It
// returns {user, seq}. Mirrors NominateSuccessor.
export async function nominate(deps, { who, code, password }) {
  const record = await signedIn(deps);
  const u = await checkCode(deps, who, code);
  if (u.id === record.userId) throw new Error('You cannot be your own successor.');
  const { authKey, bundle, mk } = await unlock(deps, password);
  let ek;
  let wrapped;
  try {
    ek = await e2e.open(await e2e.mkSealCryptoKey(mk), ['ek'], e2e.unb64(bundle.ek));
    wrapped = await e2e.wrap({ purpose: 'ek', artifact: record.userId, epoch: 0, recipientId: u.id, recipientPub: u.x25519Pub }, ek);
  } finally {
    for (const secret of [mk, ek]) secret?.fill(0);
  }
  const { seq } = await status(deps);
  const env = await signSuccessor(record, { seq: seq + 1, successor: u.id, successorFp: u.fp, action: 'nominate' });
  try {
    const out = await call(deps, null, 'PUT', '/api/me/successor', { body: { authKey, successor: u.id, record: env, wrapped: e2e.b64(wrapped) } });
    return { user: u, seq: out.seq };
  } catch (err) {
    throw staleSeq(err);
  }
}

// remove signs a remove record for the current successor and sends it. It
// returns the successor it removed. Mirrors RemoveSuccessor.
export async function remove(deps) {
  const record = await signedIn(deps);
  const st = await status(deps);
  if (!st.successor) throw new Error('You have no successor.');
  const env = await signSuccessor(record, { seq: st.seq + 1, successor: st.successor.id, successorFp: '', action: 'remove' });
  try {
    await call(deps, null, 'DELETE', '/api/me/successor', { body: { record: env } });
  } catch (err) {
    throw staleSeq(err);
  }
  return st.successor;
}

// refuse refuses a pending request. The nomination stays.
export function refuse(deps) {
  return call(deps, null, 'DELETE', '/api/me/successor/request');
}

// setNoticeEmail sets a personal address for notices, or clears it when
// address is empty. It returns whether the server still has to verify it.
export async function setNoticeEmail(deps, address) {
  const out = await call(deps, null, 'PUT', '/api/me/notice-email', { body: { email: address } });
  return out.status === 'check-email';
}

// successions lists the users whose nomination names the caller.
export function successions(deps) {
  return call(deps, null, 'GET', '/api/successions');
}

// requestAccess asks for access to the artifacts of the user with this ID. It
// returns {requestedAt, releaseAt}.
export function requestAccess(deps, userId) {
  return call(deps, null, 'POST', `/api/successions/${userId}/request`);
}

// who names a user by name and email, or by email alone.
export const who = (u) => (u.name ? `${u.name} (${u.email})` : u.email);
// day is the day of an RFC 3339 time.
const day = (time) => time.slice(0, 10);

// bannerView is what the banners at the top of every tab show for me, the
// caller from /api/me: a pending request, which the user can refuse, or a
// release, which only rotating keys ends, and which the CLI does.
export function bannerView(me) {
  const s = me.succession;
  const view = { banner: !!s, refuse: !!s && !s.released, rotate: !!me.mustRotate, text: '' };
  if (!s) return view;
  if (s.released) {
    view.text = `${who(s.successor)} can now read your artifacts.`;
    return view;
  }
  view.text = `${who(s.successor)} asked for access to your artifacts on ${day(s.requestedAt)}. They get it on ${day(s.releaseAt)} unless you refuse.`;
  if (s.deactivatedAt) view.text += ` An administrator deactivated your account on ${day(s.deactivatedAt)}.`;
  return view;
}

// refusalView is what /refuse says once a refusal succeeds: who asked and
// when, and the deactivation if an administrator deactivated the user while
// the request was pending.
export function refusalView(answer) {
  const done = `You refused the request that ${who(answer.successor)} made on ${day(answer.requestedAt)}. ` +
    'They stay your successor; to remove them, use Your successor on the Account tab, or run cairn successor remove.';
  const deactivated = answer.deactivatedAt
    ? `An administrator deactivated your account on ${day(answer.deactivatedAt)}, while the request was pending.`
    : '';
  return { done, deactivated };
}
