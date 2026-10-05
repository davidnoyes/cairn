// data.mjs — the worker's data routes: a version's database and stored files,
// answered in plaintext to the artifact and stored on the server as sealed,
// signed blobs. sw.js wires these handlers to its fetch event; nothing here
// reads a global except WebCrypto and the Fetch classes, so node --test
// exercises every check. The rules are in design/e2e-api.md ("Client-side
// database and files").
import {
  FILE_META_SCHEMA,
  b64,
  decodeEnvelope,
  decodeStrict,
  fileAddress,
  fileKey,
  openBlob,
  openEnvelope,
  sealBlob,
  toHex,
  unb64,
} from './e2e.mjs';
import { ContentError, apiRequest, mediaType } from './content.mjs';

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const DATA_RE = new RegExp(`^/api/artifacts/(${UUID})/versions/(${UUID})/(db/download|db|files)(?:/(.*))?$`);
const ADDRESS_RE = /^[0-9a-f]{64}$/;
const REVISION_RE = /^[1-9][0-9]{0,15}$/;
const EPOCH_RE = /^(0|[1-9][0-9]{0,15})$/;
const ETAG_RE = /^"(0|[1-9][0-9]{0,15})"$/;

// The /api/ answers' policy (apiCSP in csp.go): none runs as a document.
const API_CSP = "sandbox; default-src 'none'; frame-ancestors 'none'";

const enc = new TextEncoder();

// WriteRefused is a write the worker cannot make: no key for the current
// epoch, or the shell would not sign.
export class WriteRefused extends Error {
  constructor(message) {
    super(message);
    this.name = 'WriteRefused';
  }
}

// validPath applies the upload rules to a stored file's path: no empty, "."
// or ".." segment, no backslash, no NUL.
function validPath(p) {
  if (typeof p !== 'string' || p.includes('\\') || p.includes('\0')) return false;
  return p.split('/').every((s) => s !== '' && s !== '.' && s !== '..');
}

// filePath decodes the {path...} of a file route segment by segment, as
// cairn.js encodes it, and returns null for a path validPath refuses or a
// segment that decodes to a slash.
function filePath(raw) {
  const segs = [];
  for (const s of raw.split('/')) {
    let d;
    try {
      d = decodeURIComponent(s);
    } catch {
      return null;
    }
    if (d.includes('/')) return null;
    segs.push(d);
  }
  const path = segs.join('/');
  return validPath(path) ? path : null;
}

// parseDataPath says whether pathname is one of the worker's data routes:
// {artifact, version, route, path}, where route is 'db', 'download',
// 'files', or 'file'. Anything else under /api/ is null and goes to the
// server as before.
export function parseDataPath(pathname) {
  const m = DATA_RE.exec(pathname);
  if (!m) return null;
  const [, artifact, version, kind, rest] = m;
  if (kind === 'files' && rest !== undefined) {
    const path = filePath(rest);
    return path === null ? null : { artifact, version, route: 'file', path };
  }
  if (rest !== undefined) return null;
  return { artifact, version, route: kind === 'db/download' ? 'download' : kind, path: null };
}

function headers(type, extra = {}) {
  return {
    'Content-Type': type,
    'Content-Security-Policy': API_CSP,
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    ...extra,
  };
}

function json(status, value, extra) {
  return new Response(JSON.stringify(value), { status, headers: headers('application/json', extra) });
}

function fail(status, error, extra) {
  return json(status, { error }, extra);
}

// passOn turns a server refusal into the worker's answer, keeping its
// message when it has one.
async function passOn(res, extra) {
  let error = `the server answered ${res.status}`;
  try {
    const body = await res.json();
    if (typeof body?.error === 'string') error = body.error;
  } catch {
    // Not JSON: keep the status alone.
  }
  return fail(res.status, error, extra);
}

async function sha256Hex(bytes) {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

function akFor(keys, epoch) {
  const k = String(epoch);
  return Object.hasOwn(keys.aks, k) ? unb64(keys.aks[k]) : null;
}

// checkSigned runs the checks a client makes on data it reads (steps 1 to 3
// of "Checking data a client reads") and returns the body and the AK of its
// epoch. want holds what was asked for: the epoch the server named, and the
// revision, or the kind and name, and the blob when the caller has it.
export async function checkSigned(keys, purpose, env, signerKey, want) {
  let key;
  try {
    key = unb64(signerKey);
  } catch {
    throw new ContentError('the signer key is not base64url');
  }
  if (key.length !== 32) throw new ContentError('the signer key is not 32 bytes');
  const writers = keys.writers;
  if (!keys.publicWrites && !(Object.hasOwn(writers, env.signer) && writers[env.signer].includes(b64(key)))) {
    throw new ContentError('signed by someone who may not write');
  }
  const body = await openEnvelope(env, key, purpose);
  if (body.artifact !== keys.artifact) throw new ContentError('signed for another artifact');
  if (body.version !== keys.version) throw new ContentError('signed for another version');
  if (body.epoch !== want.epoch) throw new ContentError('signed under another epoch than the server named');
  if (body.epoch < keys.epoch) throw new ContentError('signed under an epoch before the version');
  const ak = akFor(keys, body.epoch);
  if (!ak) throw new ContentError(`no key for epoch ${body.epoch}`);
  if (purpose === 'revision') {
    if (body.revision !== want.revision) throw new ContentError('signed for another revision');
  } else {
    if (body.kind !== want.kind) throw new ContentError('signed for another kind');
    if (body.name !== want.name) throw new ContentError('signed for another address');
  }
  if (want.blob && (await sha256Hex(want.blob)) !== body.sha256) throw new ContentError('the blob does not match its signature');
  return { body, ak };
}

function parseEpoch(v) {
  if (typeof v !== 'string' || !EPOCH_RE.test(v)) throw new ContentError('the epoch is not a number');
  return Number(v);
}

function envelopeHeader(v) {
  if (typeof v !== 'string') throw new ContentError('no record');
  return decodeEnvelope(unb64(v));
}

function server(ctx, suffix, init = {}) {
  const { keys, origin } = ctx;
  const url = `${origin}/api/artifacts/${keys.artifact}/versions/${keys.version}/${suffix}`;
  return ctx.fetchFn(apiRequest(new Request(url, init), keys));
}

// sign asks the shell to sign bodies and checks only the shape of what comes
// back: the server checks the signatures, and the frame could answer in the
// shell's place.
async function sign(ctx, purpose, bodies) {
  let envelopes;
  try {
    envelopes = await ctx.sign(purpose, bodies);
  } catch (err) {
    throw new WriteRefused(err.message);
  }
  if (!Array.isArray(envelopes) || envelopes.length !== bodies.length) throw new WriteRefused('the shell did not sign');
  for (const e of envelopes) {
    if (typeof e?.body !== 'string' || typeof e.sig !== 'string' || typeof e.signer !== 'string') {
      throw new WriteRefused('the shell did not sign');
    }
  }
  return envelopes;
}

function writeContext(keys) {
  const epoch = keys.currentEpoch;
  const ak = akFor(keys, epoch);
  if (!ak) throw new WriteRefused('no key for the current epoch');
  return { epoch, ak };
}

// readRevision fetches and checks the latest revision, all six steps. inm
// is the client's If-None-Match, passed on when it names a revision. It
// returns {response} for anything but a revision to open.
async function readRevision(ctx, inm) {
  const { keys } = ctx;
  const init = {};
  if (inm !== null && ETAG_RE.test(inm)) init.headers = { 'If-None-Match': inm };
  // The floor is what was seen before asking: a write that lands while this
  // read is in flight raises seen, but the server answered before it.
  const floor = ctx.seen.get(keys.version) ?? 0;
  const res = await server(ctx, 'db', init);
  if (res.status === 304) {
    if (!init.headers) throw new ContentError('a 304 to a read that named no revision');
    const kept = Number(ETAG_RE.exec(init.headers['If-None-Match'])[1]);
    if (kept < floor) throw new ContentError(`revision ${kept} is older than revision ${floor}, already seen`);
    const etag = res.headers.get('ETag');
    return { response: new Response(null, { status: 304, headers: headers('application/octet-stream', etag ? { ETag: etag } : {}) }) };
  }
  if (res.status === 404) return { response: fail(404, 'no database yet') };
  if (!res.ok) return { response: await passOn(res) };
  const revText = res.headers.get('X-Cairn-Revision');
  if (typeof revText !== 'string' || !REVISION_RE.test(revText)) throw new ContentError('the revision is not a number');
  const revision = Number(revText);
  const blob = new Uint8Array(await res.arrayBuffer());
  const env = envelopeHeader(res.headers.get('X-Cairn-Record'));
  const epoch = parseEpoch(res.headers.get('X-Cairn-Epoch'));
  const { ak } = await checkSigned(keys, 'revision', env, res.headers.get('X-Cairn-Signer-Key'), { epoch, revision, blob });
  const plain = await openBlob(ak, { artifact: keys.artifact, version: keys.version, kind: 'database', name: String(revision) }, blob);
  if (revision < floor) throw new ContentError(`revision ${revision} is older than revision ${floor}, already seen`);
  ctx.seen.set(keys.version, Math.max(revision, ctx.seen.get(keys.version) ?? 0));
  return { revision, plain };
}

async function getDb(ctx, request, download) {
  const got = await readRevision(ctx, download ? null : request.headers.get('If-None-Match'));
  if (got.response) return got.response;
  const extra = { ETag: `"${got.revision}"` };
  if (download) extra['Content-Disposition'] = 'attachment; filename="database.db"';
  return new Response(got.plain, { status: 200, headers: headers('application/octet-stream', extra) });
}

async function putDb(ctx, request) {
  const { keys } = ctx;
  const ifMatch = request.headers.get('If-Match');
  const m = ifMatch === null ? null : ETAG_RE.exec(ifMatch);
  if (!m) return fail(428, 'If-Match must name the revision the write is based on');
  const revision = Number(m[1]) + 1;
  const { epoch, ak } = writeContext(keys);
  const plain = new Uint8Array(await request.arrayBuffer());
  const blob = await sealBlob(ak, { artifact: keys.artifact, version: keys.version, kind: 'database', name: String(revision) }, plain);
  const [record] = await sign(ctx, 'revision', [
    { artifact: keys.artifact, version: keys.version, revision, epoch, sha256: await sha256Hex(blob) },
  ]);
  const form = new FormData();
  form.append('record', JSON.stringify(record));
  form.append('blob', new Blob([blob]), 'blob');
  const res = await server(ctx, 'db', { method: 'PUT', headers: { 'If-Match': ifMatch }, body: form });
  if (!res.ok) {
    const etag = res.headers.get('ETag');
    return passOn(res, res.status === 412 && etag ? { ETag: etag } : undefined);
  }
  if ((ctx.seen.get(keys.version) ?? 0) < revision) ctx.seen.set(keys.version, revision);
  return json(200, { revision }, { ETag: `"${revision}"` });
}

// epochsDown lists the epochs a file may be stored under, newest first: the
// current one down to the version's, those the keys hold an AK for.
function epochsDown(keys) {
  const out = [];
  for (let e = keys.currentEpoch; e >= keys.epoch; e--) if (Object.hasOwn(keys.aks, String(e))) out.push(e);
  return out;
}

async function addressAt(keys, ak, epoch, path) {
  return fileAddress(await fileKey(ak, keys.artifact, epoch), path);
}

// openEntry checks one entry of the server's file list and opens its
// metadata, steps 1 to 5. It throws on any failure.
async function openEntry(keys, item) {
  if (typeof item !== 'object' || item === null) throw new ContentError('not an object');
  const address = item.address;
  if (typeof address !== 'string' || !ADDRESS_RE.test(address)) throw new ContentError('the address is not 64 hex characters');
  if (!Number.isSafeInteger(item.epoch)) throw new ContentError('the epoch is not a number');
  const epoch = item.epoch;
  const recordEnv = decodeEnvelope(JSON.stringify(item.record));
  const metaEnv = decodeEnvelope(JSON.stringify(item.metaRecord));
  const meta = unb64(item.meta);
  await checkSigned(keys, 'record', recordEnv, item.signerKey, { epoch, kind: 'file', name: address });
  const { ak } = await checkSigned(keys, 'record', metaEnv, item.signerKey, { epoch, kind: 'file-meta', name: address, blob: meta });
  const plain = await openBlob(ak, { artifact: keys.artifact, version: keys.version, kind: 'file-meta', name: address }, meta);
  const m = decodeStrict(plain, FILE_META_SCHEMA);
  if (m.v !== 1) throw new ContentError('metadata version unsupported');
  if (!validPath(m.path)) throw new ContentError('the path is not valid');
  if (!Number.isSafeInteger(m.size) || m.size < 0) throw new ContentError('the size is not valid');
  if ((await addressAt(keys, ak, epoch, m.path)) !== address) throw new ContentError('the metadata belongs to another file');
  return { path: m.path, size: m.size, modifiedAt: m.modifiedAt, epoch };
}

async function listFiles(ctx) {
  const res = await server(ctx, 'files');
  if (!res.ok) return passOn(res);
  const items = await res.json();
  if (!Array.isArray(items)) throw new ContentError('the file list is not a list');
  const byPath = new Map();
  for (const item of items) {
    let f;
    try {
      f = await openEntry(ctx.keys, item);
    } catch (err) {
      ctx.warn(`[cairn] a stored file was left out: ${err.message}`);
      continue;
    }
    const held = byPath.get(f.path);
    if (!held || held.epoch < f.epoch) byPath.set(f.path, f);
  }
  const out = [...byPath.values()]
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
    .map(({ path, size, modifiedAt }) => ({ path, size, modifiedAt }));
  return json(200, out);
}

async function getFile(ctx, path) {
  const { keys } = ctx;
  for (const epoch of epochsDown(keys)) {
    const ak = akFor(keys, epoch);
    const address = await addressAt(keys, ak, epoch, path);
    const res = await server(ctx, `files/${address}`);
    if (res.status === 404) continue;
    if (!res.ok) return passOn(res);
    const blob = new Uint8Array(await res.arrayBuffer());
    const env = envelopeHeader(res.headers.get('X-Cairn-Record'));
    const named = parseEpoch(res.headers.get('X-Cairn-Epoch'));
    if (named !== epoch) throw new ContentError('the file is stored under another epoch than its address');
    await checkSigned(keys, 'record', env, res.headers.get('X-Cairn-Signer-Key'), { epoch, kind: 'file', name: address, blob });
    const plain = await openBlob(ak, { artifact: keys.artifact, version: keys.version, kind: 'file', name: address }, blob);
    return new Response(plain, { status: 200, headers: headers(mediaType(path)) });
  }
  return fail(404, 'file not found');
}

// removeOlder deletes path's addresses under the epochs before the current
// one. A failure is left: the newer copy is the one a reader takes.
async function removeOlder(ctx, path) {
  const { keys } = ctx;
  for (const epoch of epochsDown(keys)) {
    if (epoch === keys.currentEpoch) continue;
    const address = await addressAt(keys, akFor(keys, epoch), epoch, path);
    await server(ctx, `files/${address}`, { method: 'DELETE' }).catch(() => null);
  }
}

async function putFile(ctx, path, request) {
  const { keys } = ctx;
  const { epoch, ak } = writeContext(keys);
  const address = await addressAt(keys, ak, epoch, path);
  const plain = new Uint8Array(await request.arrayBuffer());
  const modifiedAt = ctx.now().toISOString();
  const ctxOf = (kind) => ({ artifact: keys.artifact, version: keys.version, kind, name: address });
  const blob = await sealBlob(ak, ctxOf('file'), plain);
  const meta = await sealBlob(ak, ctxOf('file-meta'), enc.encode(JSON.stringify({ v: 1, path, size: plain.length, modifiedAt })));
  const body = async (kind, b) => ({ artifact: keys.artifact, version: keys.version, kind, name: address, epoch, sha256: await sha256Hex(b) });
  const [record, metaRecord] = await sign(ctx, 'record', [await body('file', blob), await body('file-meta', meta)]);
  const form = new FormData();
  form.append('record', JSON.stringify(record));
  form.append('blob', new Blob([blob]), 'blob');
  form.append('metaRecord', JSON.stringify(metaRecord));
  form.append('meta', new Blob([meta]), 'meta');
  const res = await server(ctx, `files/${address}`, { method: 'PUT', body: form });
  if (!res.ok) return passOn(res);
  await removeOlder(ctx, path);
  return json(200, { path, size: plain.length, modifiedAt });
}

async function deleteFile(ctx, path) {
  const { keys } = ctx;
  let found = false;
  for (const epoch of epochsDown(keys)) {
    const address = await addressAt(keys, akFor(keys, epoch), epoch, path);
    const res = await server(ctx, `files/${address}`, { method: 'DELETE' });
    if (res.ok) found = true;
    else if (res.status !== 404) return passOn(res);
  }
  return found ? new Response(null, { status: 204, headers: headers('text/plain; charset=utf-8') }) : fail(404, 'file not found');
}

const ROUTES = {
  db: { GET: (ctx, req) => getDb(ctx, req, false), PUT: putDb },
  download: { GET: (ctx, req) => getDb(ctx, req, true) },
  files: { GET: listFiles },
  file: {
    GET: (ctx, req, path) => getFile(ctx, path),
    PUT: (ctx, req, path) => putFile(ctx, path, req),
    DELETE: (ctx, req, path) => deleteFile(ctx, path),
  },
};

// handleData answers one data request. ctx holds the version's keys message
// (keys), the origin, fetchFn, sign(purpose, bodies), seen (the highest
// revision read per version), now, and warn. A check that fails is a 502
// that names it, and a write the worker cannot make a 403; nothing unchecked
// reaches the artifact.
export async function handleData(ctx, route, request) {
  const handler = Object.hasOwn(ROUTES[route.route], request.method) ? ROUTES[route.route][request.method] : null;
  if (!handler) return fail(405, 'method not allowed');
  try {
    return await handler(ctx, request, route.path);
  } catch (err) {
    if (err instanceof WriteRefused) return fail(403, err.message);
    return fail(502, `could not be verified: ${err.message}`);
  }
}
