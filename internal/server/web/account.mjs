// account.mjs — the browser account flows: sign-up, verification, sign-in,
// password reset, and sign-out. It mirrors the Go client (internal/client/
// account.go) step for step, and every cryptographic operation comes from
// e2e.mjs. The page scripts only wire the DOM to these functions.
//
// Nothing here touches the DOM, the network, or storage directly. Each flow
// takes `deps`:
//
//   fetch(path, options)               like window.fetch
//   stretch(password, email, params)   Argon2id, off the UI thread in a page
//   strength(password, userInputs)     -> {score, feedback}, like zxcvbn
//   keyStore                           {save(record), clear()}, see keystore.mjs
import * as e2e from './e2e.mjs';

// MIN_SCORE is the lowest zxcvbn score a new password may have. Sign-in does
// not apply it: it authenticates a password that already exists.
export const MIN_SCORE = 3;

export const FORGOT_MESSAGE = 'If that address has an account, we sent a link to reset the password. Check your mail.';

const enc = new TextEncoder();

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// IncompleteLinkError is a link whose fragment has no token: opened a second
// time (the first open removed the fragment), or cut short in the mail.
export class IncompleteLinkError extends Error {
  constructor() {
    super('This link is incomplete. Open the link from your email again.');
    this.name = 'IncompleteLinkError';
  }
}

export class WeakPasswordError extends Error {
  constructor(feedback) {
    super('That password is too weak. Use a longer, less predictable passphrase, and leave out your name and email.');
    this.name = 'WeakPasswordError';
    this.feedback = feedback || {};
  }
}

// post sends a JSON body and returns the parsed JSON answer, or throws an
// ApiError carrying the server's {"error"} message.
async function post(deps, path, body) {
  const resp = await deps.fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new ApiError(data.error || `request failed (${resp.status})`, resp.status);
  return data;
}

// checkNewPassword enforces the same rules as the CLI's CheckNewPassword:
// non-empty, matching the confirmation, and scored at least MIN_SCORE.
function checkNewPassword(deps, password, confirm, userInputs) {
  if (password === '') throw new Error('The password must not be empty.');
  if (password !== confirm) throw new Error('The passwords do not match.');
  const result = deps.strength(password, userInputs);
  if (result.score < MIN_SCORE) throw new WeakPasswordError(result.feedback);
}

// sealField seals pt under key, bound to the single literal field name, and
// returns it base64url-encoded for the wire.
async function sealField(key, field, pt) {
  return e2e.b64(await e2e.seal(key, [field], pt));
}

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// generateAccount creates a brand-new key bundle: a fresh MK, X25519 and
// Ed25519 key pairs, EK, and a recovery code, all sealed under a freshly
// stretched password. Sign-up and a reset without the recovery code both
// start an account over from here. Raw secrets are zeroed once sealed.
async function generateAccount(deps, email, password) {
  const params = { alg: 'argon2id', m: 65536, t: 3, p: 1, salt: randomBytes(16) };
  const stretched = await deps.stretch(password, email, params);
  let authKey, kek;
  try {
    ({ authKey, kek } = await e2e.passwordCryptoKeys(stretched, 'seal'));
  } finally {
    stretched.fill(0);
  }

  const mk = randomBytes(32);
  const ek = randomBytes(32);
  let recovery, x25519, ed25519;
  try {
    recovery = e2e.newRecoveryCode();
    x25519 = await e2e.generateX25519();
    ed25519 = await e2e.generateEd25519();
    const sealKey = await e2e.mkSealCryptoKey(mk);

    const bundle = {
      kdf: { alg: params.alg, m: params.m, t: params.t, p: params.p, salt: e2e.b64(params.salt) },
      mkPassword: await sealField(kek, 'mk', mk),
      mkRecovery: await sealField(await e2e.recoveryKekCryptoKey(recovery.code, 'seal'), 'mk', mk),
      x25519Pub: e2e.b64(x25519.pub),
      x25519Priv: await sealField(sealKey, 'x25519', x25519.priv),
      ed25519Pub: e2e.b64(ed25519.pub),
      ed25519Priv: await sealField(sealKey, 'ed25519', ed25519.seed),
      ek: await sealField(sealKey, 'ek', ek),
    };
    return { authKey: e2e.b64(authKey), bundle, recoveryCode: recovery.display };
  } finally {
    for (const secret of [mk, ek, recovery?.code, x25519?.priv, ed25519?.seed]) secret?.fill(0);
  }
}

// signUp generates the keys and signs up. Nothing but wrapped material and
// the authentication key leaves this function. It returns the recovery code,
// which the page shows once.
export async function signUp(deps, { email, name, password, confirm }) {
  email = e2e.normalizeEmail(email);
  checkNewPassword(deps, password, confirm, [email, name]);
  const { authKey, bundle, recoveryCode } = await generateAccount(deps, email, password);
  await post(deps, '/api/auth/signup', { email, name, authKey, bundle });
  return { recoveryCode };
}

// parseKdf turns the wire form of the Argon2id parameters into what
// checkFloor and the stretch function take.
function parseKdf(kdf) {
  return { alg: kdf.alg, m: kdf.m, t: kdf.t, p: kdf.p, salt: e2e.unb64(kdf.salt) };
}

// signIn runs prelogin, checks the parameters against the floor, stretches the
// password, and logs in. It then opens MK from the bundle and stores the
// unwrapped keys through deps.keyStore. If the bundle will not open, it signs
// out again so the page is never half signed in.
export async function signIn(deps, { email, password }) {
  if (password === '') throw new Error('The password must not be empty.');
  email = e2e.normalizeEmail(email);
  const kdf = parseKdf(await post(deps, '/api/auth/prelogin', { email }));
  e2e.checkFloor(kdf);
  const stretched = await deps.stretch(password, email, kdf);
  let authKey, kek;
  try {
    ({ authKey, kek } = await e2e.passwordCryptoKeys(stretched, 'open'));
  } finally {
    stretched.fill(0);
  }

  const { user, bundle } = await post(deps, '/api/auth/login', { email, authKey: e2e.b64(authKey), client: 'web' });
  try {
    await deps.keyStore.save(await openBundle(user, bundle, kek));
  } catch (err) {
    await post(deps, '/api/auth/logout', {}).catch(() => {});
    throw err;
  }
  return user;
}

// openBundle opens MK with kek, then every sealed key under mkSealKey. MK and
// EK are opened straight into non-extractable HKDF keys. WebCrypto cannot
// unwrap a raw X25519 or Ed25519 private key, so each is decrypted to bytes
// and imported at once as non-extractable; the bytes are zeroed afterwards.
async function openBundle(user, bundle, kek) {
  const mk = await e2e.openKey(kek, ['mk'], e2e.unb64(bundle.mkPassword));
  const mkSeal = await e2e.mkSealCryptoKey(mk);
  let x25519Raw, ed25519Raw;
  try {
    x25519Raw = await e2e.open(mkSeal, ['x25519'], e2e.unb64(bundle.x25519Priv));
    ed25519Raw = await e2e.open(mkSeal, ['ed25519'], e2e.unb64(bundle.ed25519Priv));
    return {
      userId: user.id,
      email: user.email,
      mk,
      mkSeal,
      ek: await e2e.openKey(mkSeal, ['ek'], e2e.unb64(bundle.ek)),
      x25519: await e2e.importX25519PrivateKey(x25519Raw),
      ed25519: await e2e.importEd25519SigningKey(ed25519Raw),
    };
  } finally {
    x25519Raw?.fill(0);
    ed25519Raw?.fill(0);
  }
}

// takeToken reads the token from a "#token=" fragment and removes the
// fragment from the address bar, so the token is neither visible nor in the
// history entry once the page has it. It strips first and validates second.
export function takeToken(location, history) {
  const hash = location.hash;
  history.replaceState(null, '', location.pathname + location.search);
  const match = /^#token=([A-Za-z0-9_-]+)$/.exec(hash);
  if (!match) throw new IncompleteLinkError();
  return match[1];
}

// verifyFromLink follows a verification link: the token leaves the address
// bar before the request is made.
export async function verifyFromLink(deps, { location, history }) {
  const token = takeToken(location, history);
  await post(deps, '/api/auth/verify', { token });
}

// forgot asks for a reset link. The answer is the same for every address, so
// the page cannot reveal which have accounts.
export async function forgot(deps, { email }) {
  await post(deps, '/api/auth/forgot', { email: e2e.normalizeEmail(email) });
  return FORGOT_MESSAGE;
}

// resetBeginFromLink takes the token off the address bar, then asks the
// server what completing the reset needs, without using the token up.
export async function resetBeginFromLink(deps, { location, history }) {
  const token = takeToken(location, history);
  return { token, info: await post(deps, '/api/auth/reset/begin', { token }) };
}

async function tokenHash(tokenB64) {
  return e2e.toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', e2e.unb64(tokenB64))));
}

// resetWithRecovery opens MK with the recovery code and re-wraps it under the
// new password, keeping the account's key pairs. It proves it holds MK by
// signing a proof with the account's Ed25519 key. MK exists as raw bytes only
// for the length of this call, because it must be sealed again under the new
// password key, and WebCrypto cannot seal a non-extractable key.
export async function resetWithRecovery(deps, { token, info, recoveryCode, password, confirm }) {
  checkNewPassword(deps, password, confirm, [info.email]);
  let code;
  try {
    code = e2e.parseRecoveryCode(recoveryCode);
  } catch {
    throw new Error('That is not a recovery code. It has 26 letters and digits in groups of four.');
  }
  // The recovery KEK has to decrypt MK to raw bytes, which the non-extractable
  // recoveryKekCryptoKey cannot do (it only unwraps into a non-extractable
  // key), so its raw bytes are zeroed with the rest.
  let recoveryKek, mk, seed, stretched, proof, params, authKey, mkPassword;
  try {
    try {
      recoveryKek = await e2e.recoveryKek(code);
      mk = await e2e.open(recoveryKek, ['mk'], e2e.unb64(info.mkRecovery));
    } catch {
      throw new Error('That recovery code does not open this account. Check that you typed all 26 characters, in groups of four. If you lost it, choose "Start with new keys".');
    }
    seed = await e2e.open(await e2e.mkSealCryptoKey(mk), ['ed25519'], e2e.unb64(info.ed25519Priv));
    const proofBody = enc.encode(JSON.stringify({ v: 1, user: info.id, token: await tokenHash(token) }));
    proof = await e2e.sign(seed, 'reset', proofBody);

    params = { alg: 'argon2id', m: 65536, t: 3, p: 1, salt: randomBytes(16) };
    stretched = await deps.stretch(password, info.email, params);
    let kek;
    ({ authKey, kek } = await e2e.passwordCryptoKeys(stretched, 'seal'));
    mkPassword = await sealField(kek, 'mk', mk);
  } finally {
    for (const secret of [code, recoveryKek, mk, seed, stretched]) secret?.fill(0);
  }
  await post(deps, '/api/auth/reset/complete', {
    token,
    mode: 'recovery',
    authKey: e2e.b64(authKey),
    kdf: { alg: params.alg, m: params.m, t: params.t, p: params.p, salt: e2e.b64(params.salt) },
    mkPassword,
    proof: e2e.b64(proof),
  });
}

// resetWithoutRecovery discards the old key material: a new MK, key pairs,
// EK, and recovery code. Artifacts that others shared with the account stay
// unreadable until their owners share again. It returns the new recovery code.
export async function resetWithoutRecovery(deps, { token, info, password, confirm }) {
  checkNewPassword(deps, password, confirm, [info.email]);
  const { authKey, bundle, recoveryCode } = await generateAccount(deps, info.email, password);
  await post(deps, '/api/auth/reset/complete', { token, mode: 'new', authKey, bundle });
  return { recoveryCode };
}

// recoveryGroupIndex picks which group of a displayed recovery code the user
// must retype, to show they saved it. Like the CLI, it is chosen at random.
export function recoveryGroupIndex(display) {
  return crypto.getRandomValues(new Uint8Array(1))[0] % display.split('-').length;
}

// recoveryGroupMatches reports whether typed is group index of the code.
export function recoveryGroupMatches(display, index, typed) {
  return typed.trim().toUpperCase() === display.split('-')[index];
}

// signOut clears the unwrapped keys. The keyring anchor lives in
// localStorage, which this never touches, so it survives sign-out.
export async function signOut(deps) {
  await deps.keyStore.clear();
}
