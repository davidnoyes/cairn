// content.mjs — the pure half of the content-origin service worker (sw.js):
// path parsing, manifest verification, lookup, media types, headers, the
// handshake's message check, and API request rewriting. Nothing here reads a
// global except WebCrypto and the Request/Response classes, so node --test
// exercises every refusal. The rules are in design/e2e-api.md ("The service
// worker") and design/e2e-wire-formats.md ("Blobs", "Signatures").
import {
  BODY_SCHEMAS,
  bodyHash,
  decodeEnvelope,
  decodeStrict,
  openBlob,
  toHex,
  unb64,
  verifyEnvelope,
} from './e2e.mjs';

export class ContentError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ContentError';
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BLOB_ID_RE = /^[0-9a-f]{32}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;

// bytesOf accepts the b64 string a keys message carries or bytes already
// decoded.
function bytesOf(v) {
  return typeof v === 'string' ? unb64(v) : v;
}

// validPath mirrors the upload rules: relative, no empty, "." or ".."
// segments, no NUL, no backslash.
function validPath(p) {
  if (typeof p !== 'string' || p === '') return false;
  if (p.includes('\0') || p.includes('\\')) return false;
  return p.split('/').every((s) => s !== '' && s !== '.' && s !== '..');
}

// parseContentPath splits /<version>/<path> as serving.go does: the version
// is a lowercase UUID, a trailing slash maps to index.html in that
// directory, and anything that could climb out of the version is refused.
export function parseContentPath(pathname) {
  if (typeof pathname !== 'string' || !pathname.startsWith('/')) return null;
  const segs = pathname.slice(1).split('/');
  const version = segs[0];
  if (!UUID_RE.test(version)) return null;
  const rest = segs.slice(1);
  if (rest.length === 0) return null;
  const dir = rest[rest.length - 1] === '';
  if (dir) rest.pop();
  const decoded = [];
  for (const raw of rest) {
    let s;
    try {
      s = decodeURIComponent(raw);
    } catch {
      return null;
    }
    if (s === '' || s === '.' || s === '..' || s.includes('\0') || s.includes('\\') || s.includes('/')) return null;
    decoded.push(s);
  }
  if (dir) decoded.push('index.html');
  return { version, path: decoded.join('/') };
}

// classifyRequest says which handler a same-origin pathname belongs to.
export function classifyRequest(pathname) {
  if (pathname === '/_cairn' || pathname.startsWith('/_cairn/')) return { kind: 'cairn' };
  if (pathname.startsWith('/api/')) return { kind: 'api' };
  const parsed = parseContentPath(pathname);
  if (parsed) return { kind: 'content', ...parsed };
  return { kind: 'none' };
}

// openManifest opens and checks a version's manifest blob. Any failure
// throws; nothing from an unchecked manifest is returned.
export async function openManifest({ ak, artifact, version, epoch, signer, manifestHash, blob }) {
  const plain = await openBlob(bytesOf(ak), { artifact, version, kind: 'manifest', name: '' }, blob);
  const env = decodeEnvelope(plain);
  const body = unb64(env.body);
  if ((await bodyHash(body)) !== manifestHash) throw new ContentError('manifest hash mismatch');
  if (signer !== null) {
    if (env.signer !== signer.user) throw new ContentError('manifest signer mismatch');
    if (!(await verifyEnvelope(bytesOf(signer.ed25519), 'manifest', env))) {
      throw new ContentError('manifest signature does not verify');
    }
  }
  const m = decodeStrict(body, BODY_SCHEMAS.manifest);
  if (m.v !== 1) throw new ContentError('manifest version unsupported');
  if (m.artifact !== artifact) throw new ContentError('manifest artifact mismatch');
  if (m.version !== version) throw new ContentError('manifest version mismatch');
  if (m.epoch !== epoch) throw new ContentError('manifest epoch mismatch');
  const seen = new Set();
  for (const f of m.files) {
    if (!validPath(f.path)) throw new ContentError('manifest path invalid');
    if (seen.has(f.path)) throw new ContentError('manifest path duplicated');
    seen.add(f.path);
    if (!BLOB_ID_RE.test(f.blob)) throw new ContentError('manifest blob id invalid');
    if (!SHA256_RE.test(f.sha256)) throw new ContentError('manifest sha256 invalid');
    if (!Number.isSafeInteger(f.size) || f.size < 0) throw new ContentError('manifest size invalid');
  }
  return m;
}

const HELPERS = new Set(['cairn.js', 'mermaid.js', 'sql-wasm.js', 'sql-wasm.wasm']);

const indexes = new WeakMap();

function indexOf(manifest) {
  let idx = indexes.get(manifest);
  if (!idx) {
    idx = new Map(manifest.files.map((f) => [f.path, f]));
    indexes.set(manifest, idx);
  }
  return idx;
}

function hasExtension(path) {
  return path.slice(path.lastIndexOf('/') + 1).includes('.');
}

// lookup resolves a path against a manifest: a file, a helper the worker
// serves from /_cairn/, a directory that needs its trailing slash, or the
// SPA fallback for a navigation.
export function lookup(manifest, path, { navigation } = {}) {
  const idx = indexOf(manifest);
  const entry = idx.get(path);
  if (entry) return { kind: 'file', entry };
  if (HELPERS.has(path)) return { kind: 'helper', name: path };
  if (idx.has(`${path}/index.html`)) return { kind: 'directory' };
  if (navigation && !hasExtension(path)) {
    const index = idx.get('index.html');
    if (index) return { kind: 'file', entry: index };
  }
  return null;
}

// openFile checks a file blob against the manifest's hash, opens it, and
// checks its size.
export async function openFile({ ak, artifact, version, entry, blob }) {
  const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', blob)));
  if (digest !== entry.sha256) throw new ContentError('blob sha256 mismatch');
  const plain = await openBlob(bytesOf(ak), { artifact, version, kind: 'content', name: entry.path }, blob);
  if (plain.length !== entry.size) throw new ContentError('file size mismatch');
  return plain;
}

const TYPES = {
  html: 'text/html; charset=utf-8',
  htm: 'text/html; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8',
  json: 'application/json',
  map: 'application/json',
  svg: 'image/svg+xml',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  avif: 'image/avif',
  ico: 'image/x-icon',
  wasm: 'application/wasm',
  txt: 'text/plain; charset=utf-8',
  md: 'text/markdown; charset=utf-8',
  csv: 'text/csv; charset=utf-8',
  xml: 'application/xml',
  pdf: 'application/pdf',
  woff: 'font/woff',
  woff2: 'font/woff2',
  ttf: 'font/ttf',
  otf: 'font/otf',
  mp3: 'audio/mpeg',
  mp4: 'video/mp4',
  webm: 'video/webm',
  ogg: 'audio/ogg',
  wav: 'audio/wav',
};

export function mediaType(path) {
  const base = path.slice(path.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  if (dot < 0) return 'application/octet-stream';
  return Object.hasOwn(TYPES, base.slice(dot + 1).toLowerCase())
    ? TYPES[base.slice(dot + 1).toLowerCase()]
    : 'application/octet-stream';
}

const FRAME_SCRIPT = new TextEncoder().encode('<script src="/_cairn/frame.js"></script>');

function isSpace(b) {
  return b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0c || b === 0x0d;
}

// injectFrameScript puts the frame script at the start of an HTML document,
// after a byte-order mark, and after leading whitespace and a doctype when
// there is one, so the page does not fall into quirks mode.
export function injectFrameScript(bytes) {
  let at = 0;
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) at = 3;
  let i = at;
  while (i < bytes.length && isSpace(bytes[i])) i++;
  const probe = String.fromCharCode(...bytes.subarray(i, i + 9)).toLowerCase();
  if (probe === '<!doctype') {
    const end = bytes.indexOf(0x3e, i);
    if (end >= 0) at = end + 1;
  }
  const out = new Uint8Array(bytes.length + FRAME_SCRIPT.length);
  out.set(bytes.subarray(0, at), 0);
  out.set(FRAME_SCRIPT, at);
  out.set(bytes.subarray(at), at + FRAME_SCRIPT.length);
  return out;
}

export function contentHeaders(type, { appOrigin }) {
  const h = {
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    'Content-Type': type,
  };
  if (type.startsWith('text/html')) h['Content-Security-Policy'] = `frame-ancestors ${appOrigin}`;
  return h;
}

const KEYS_FIELDS = [
  'cairn',
  'artifact',
  'version',
  'epoch',
  'ak',
  'signer',
  'manifestHash',
  'token',
  'tokenExpires',
  'linkToken',
  'context',
  'path',
];

function isObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function exactFields(o, fields, what) {
  if (!isObject(o)) throw new ContentError(`${what} must be an object`);
  const keys = Object.keys(o);
  if (keys.length !== fields.length || !fields.every((f) => Object.hasOwn(o, f))) {
    throw new ContentError(`${what} has the wrong fields`);
  }
}

function checkB64(v, len, what) {
  let b;
  try {
    b = unb64(v);
  } catch {
    throw new ContentError(`${what} is not base64url`);
  }
  if (len !== undefined && b.length !== len) throw new ContentError(`${what} has the wrong length`);
}

function checkUuid(v, what) {
  if (typeof v !== 'string' || !UUID_RE.test(v)) throw new ContentError(`${what} is not a lowercase UUID`);
}

function checkString(v, what) {
  if (typeof v !== 'string') throw new ContentError(`${what} must be a string`);
}

function checkExpires(v) {
  if (v !== null && typeof v !== 'string' && !(typeof v === 'number' && Number.isFinite(v))) {
    throw new ContentError('tokenExpires must be null, a string, or a number');
  }
}

// checkKeysMessage validates the shell's keys message field by field and
// returns it. Unknown and missing fields are refused.
export function checkKeysMessage(msg) {
  exactFields(msg, KEYS_FIELDS, 'keys message');
  if (msg.cairn !== 'keys') throw new ContentError('not a keys message');
  checkUuid(msg.artifact, 'artifact');
  checkUuid(msg.version, 'version');
  if (!Number.isSafeInteger(msg.epoch) || msg.epoch < 0) throw new ContentError('epoch must be a non-negative integer');
  checkB64(msg.ak, 32, 'ak');
  if (msg.signer !== null) {
    exactFields(msg.signer, ['user', 'ed25519'], 'signer');
    checkUuid(msg.signer.user, 'signer user');
    checkB64(msg.signer.ed25519, 32, 'signer key');
  }
  if (typeof msg.manifestHash !== 'string' || !SHA256_RE.test(msg.manifestHash)) {
    throw new ContentError('manifestHash must be 64 lowercase hex characters');
  }
  if (msg.token !== null) checkString(msg.token, 'token');
  checkExpires(msg.tokenExpires);
  if (msg.linkToken !== null) checkB64(msg.linkToken, undefined, 'linkToken');
  exactFields(msg.context, ['artifact', 'users'], 'context');
  exactFields(msg.context.artifact, ['id', 'name', 'description'], 'context artifact');
  checkUuid(msg.context.artifact.id, 'context artifact id');
  if (msg.context.artifact.id !== msg.artifact) throw new ContentError('context artifact is not the keys artifact');
  checkString(msg.context.artifact.name, 'context artifact name');
  checkString(msg.context.artifact.description, 'context artifact description');
  if (!Array.isArray(msg.context.users)) throw new ContentError('context users must be an array');
  for (const u of msg.context.users) {
    exactFields(u, ['id', 'name', 'email'], 'context user');
    checkUuid(u.id, 'context user id');
    checkString(u.name, 'context user name');
    checkString(u.email, 'context user email');
  }
  checkString(msg.path, 'path');
  if (!msg.path.startsWith('/')) throw new ContentError('path must start with a slash');
  return msg;
}

// checkTokenMessage validates {cairn: 'token', token, tokenExpires}.
export function checkTokenMessage(msg) {
  exactFields(msg, ['cairn', 'token', 'tokenExpires'], 'token message');
  if (msg.cairn !== 'token') throw new ContentError('not a token message');
  if (msg.token !== null) checkString(msg.token, 'token');
  checkExpires(msg.tokenExpires);
  return msg;
}

function jsonResponse(value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

// apiRequest answers the two reads the worker serves from context, or
// returns the request with credentials set from keys. A credential header
// the caller supplied is always dropped, so a page cannot choose its own.
export function apiRequest(request, keys) {
  const url = new URL(request.url);
  if (request.method === 'GET' && keys) {
    if (url.pathname === `/api/artifacts/${keys.artifact}`) return jsonResponse(keys.context.artifact);
    if (url.pathname === '/api/users') return jsonResponse(keys.context.users);
  }
  const headers = new Headers(request.headers);
  headers.delete('Authorization');
  headers.delete('X-Cairn-Link-Token');
  if (keys?.token) headers.set('Authorization', `Bearer ${keys.token}`);
  if (keys?.linkToken) headers.set('X-Cairn-Link-Token', keys.linkToken);
  return new Request(request, { headers });
}

// errorPage is what any verification failure shows: fixed text, nothing
// from the version.
export function errorPage(status = 500) {
  const body = '<!DOCTYPE html><title>Cannot open</title><p>This version could not be verified, so it was not shown.</p>';
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  });
}

function notFound() {
  return new Response('not found', {
    status: 404,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  });
}

// fetchManifest fetches and opens a version's manifest.
export async function fetchManifest({ keys, origin, fetchFn }) {
  const url = `${origin}/api/artifacts/${keys.artifact}/versions/${keys.version}/manifest`;
  const res = await fetchFn(apiRequest(new Request(url), keys));
  if (!res.ok) throw new ContentError(`manifest fetch failed: ${res.status}`);
  return openManifest({
    ak: keys.ak,
    artifact: keys.artifact,
    version: keys.version,
    epoch: keys.epoch,
    signer: keys.signer,
    manifestHash: keys.manifestHash,
    blob: new Uint8Array(await res.arrayBuffer()),
  });
}

// serveFile answers one /<version>/<path> request from an opened manifest.
// Every failure to verify becomes the error page.
export async function serveFile({ keys, manifest, path, navigation, origin, appOrigin, fetchFn }) {
  const hit = lookup(manifest, path, { navigation });
  if (!hit) return notFound();
  if (hit.kind === 'directory') {
    // Directories need a trailing slash for relative paths, as serving.go does.
    const enc = path.split('/').map(encodeURIComponent).join('/');
    return Response.redirect(`${origin}/${keys.version}/${enc}/`, 301);
  }
  try {
    if (hit.kind === 'helper') {
      const res = await fetchFn(`${origin}/_cairn/${hit.name}`);
      if (!res.ok) return errorPage(502);
      return new Response(await res.arrayBuffer(), {
        headers: contentHeaders(mediaType(hit.name), { appOrigin }),
      });
    }
    const { entry } = hit;
    const url = `${origin}/api/artifacts/${keys.artifact}/versions/${keys.version}/blobs/${entry.blob}`;
    const res = await fetchFn(apiRequest(new Request(url), keys));
    if (!res.ok) return errorPage(502);
    let plain = await openFile({
      ak: keys.ak,
      artifact: keys.artifact,
      version: keys.version,
      entry,
      blob: new Uint8Array(await res.arrayBuffer()),
    });
    const type = mediaType(entry.path);
    if (type.startsWith('text/html')) plain = injectFrameScript(plain);
    return new Response(plain, { headers: contentHeaders(type, { appOrigin }) });
  } catch {
    return errorPage();
  }
}
