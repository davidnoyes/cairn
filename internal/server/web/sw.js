// sw.js — the content origin's service worker, registered as a module at
// /_cairn/sw.js?app=<app origin>. It holds the keys the shell hands over,
// opens each version's manifest, and answers requests under /<version>/ by
// decrypting blobs. The checks live in content.mjs; this file only wires
// them to the worker's events. It touches no storage: keys live in memory
// and are gone when the browser stops the worker. See design/e2e-api.md,
// "The service worker".
import {
  apiRequest,
  checkKeysMessage,
  checkTokenMessage,
  classifyRequest,
  ContentError,
  fetchManifest,
  parseContentPath,
  serveFile,
} from './content.mjs';
import { handleData, parseDataPath } from './data.mjs';

const KEYS_WAIT_MS = 10000;
const SIGN_WAIT_MS = 30000;

const origin = self.location.origin;
// Artifact code shares this origin and could register this script at a
// narrower scope, such as /_cairn/, where it would control the boot page.
// Throwing here fails that registration.
if (self.registration.scope !== origin + '/') throw new Error('sw.js must be registered at the origin root, not at scope ' + self.registration.scope);
// Every artifact has its own host, <artifact ID>.<content domain>.
const artifact = self.location.hostname.split('.')[0];

// The boot page registers this script with the app origin in the query. A
// missing or malformed one fails closed: no page may frame an HTML response.
function appOriginFrom(href) {
  try {
    const u = new URL(new URL(href).searchParams.get('app'));
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : "'none'";
  } catch {
    return "'none'";
  }
}
const appOrigin = appOriginFrom(self.location.href);

// versions maps a version ID to {keys, manifest, seq}, stored only once its
// manifest has opened. latest is the keys the /api/ requests use.
const versions = new Map();
const waiters = new Map();
let latest = null;
// Every keys and token message takes the next number on arrival. A keys
// message is slow to store (it opens the manifest first), so the numbers
// settle which message is newer: latestSeq is the one behind `latest`, and
// latestToken is the newest renewal, which a keys message that began before
// it must not undo.
let seqCounter = 0;
let latestSeq = 0;
let latestToken = null;
// seen is the highest database revision read or written for each version,
// which a later read may not go below. It lasts as long as the worker.
const seen = new Map();

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

async function onKeys(event, msg) {
  const seq = ++seqCounter;
  const reply = (m) => event.source.postMessage(m);
  try {
    checkKeysMessage(msg);
    if (msg.artifact !== artifact) throw new ContentError('keys are for another artifact');
    const manifest = await fetchManifest({ keys: msg, origin, fetchFn: (r) => fetch(r) });
    const entry = { keys: msg, manifest, seq };
    if (latestToken && latestToken.seq > seq) msg.token = latestToken.token;
    const held = versions.get(msg.version);
    if (!held || held.seq < seq) versions.set(msg.version, entry);
    if (seq > latestSeq) {
      latest = msg;
      latestSeq = seq;
    }
    for (const done of [...(waiters.get(msg.version) ?? [])]) done(versions.get(msg.version));
    reply({ cairn: 'keys-ok', version: msg.version });
  } catch (err) {
    reply({ cairn: 'keys-error', version: typeof msg?.version === 'string' ? msg.version : null, error: err.message });
  }
}

function onToken(msg) {
  try {
    checkTokenMessage(msg);
  } catch {
    return;
  }
  latestToken = { token: msg.token, seq: ++seqCounter };
  for (const { keys } of versions.values()) keys.token = msg.token;
}

// Messages come from any same-origin window client: the artifact frame is
// same-origin by design, and every route to the worker passes through such a
// window, so artifact code can send whatever the boot page can. It holds the
// AKs the shell hands over, so it can replace the token, or install keys
// with no signer for any version whose manifest opens under one of them, such
// as a version the shell refused as untrusted, and this worker then serves it
// until it stops. That code already runs on this origin, so it gains no new
// reach; design/e2e-trust-model.md lists this as a limit.
self.addEventListener('message', (event) => {
  if (!event.source || event.origin !== origin) return;
  const msg = event.data;
  if (msg?.cairn === 'keys') event.waitUntil(onKeys(event, msg));
  else if (msg?.cairn === 'token') onToken(msg);
});

// requestKeys asks the pages for a version's keys and waits for them. The
// waiter is registered before any await, so keys that land while the pages
// are being listed are not missed.
async function requestKeys(version) {
  let done;
  const waiting = new Promise((resolve) => {
    const set = waiters.get(version) ?? new Set();
    waiters.set(version, set);
    const timer = setTimeout(() => done(null), KEYS_WAIT_MS);
    done = (entry) => {
      clearTimeout(timer);
      set.delete(done);
      if (set.size === 0) waiters.delete(version);
      resolve(entry);
    };
    set.add(done);
  });
  const held = versions.get(version);
  if (held) {
    done(held);
    return waiting;
  }
  for (const w of await self.clients.matchAll({ type: 'window' })) w.postMessage({ cairn: 'need-keys', version });
  return waiting;
}

const unavailable = () => new Response('keys unavailable', { status: 503, headers: { 'Cache-Control': 'no-store' } });

async function clientVersion(clientId) {
  const client = clientId ? await self.clients.get(clientId) : null;
  return client ? (parseContentPath(new URL(client.url).pathname)?.version ?? null) : null;
}

// handleApi sends a page's API request on with the viewer's credentials. A
// navigation (a download link) is sent the same way: every /api/ response
// carries a CSP that sandboxes it and refuses framing, so none can run as a
// document with the token behind it. Only a GET navigation is: any page on
// any site can start one, and a form could otherwise write as the viewer.
async function handleApi(event) {
  if (event.request.mode === 'navigate' && event.request.method !== 'GET') {
    return new Response('method not allowed', { status: 405 });
  }
  if (!latest) {
    const version = await clientVersion(event.clientId);
    if (!version || !(await requestKeys(version))) return unavailable();
  }
  const out = apiRequest(event.request, latest);
  return out instanceof Response ? out : fetch(out);
}

async function handleContent(event, { version, path }) {
  const req = event.request;
  if (req.method !== 'GET' && req.method !== 'HEAD') return new Response('method not allowed', { status: 405 });
  const navigation = req.mode === 'navigate';
  let entry = versions.get(version);
  if (!entry) {
    // The browser stopped the worker: a navigation runs the handshake again.
    if (navigation) return fetch(`${origin}/_cairn/boot`);
    entry = await requestKeys(version);
    if (!entry) return unavailable();
  }
  return serveFile({ keys: entry.keys, manifest: entry.manifest, path, navigation, origin, appOrigin, fetchFn: (r) => fetch(r) });
}

// signVia asks the shell, through the page that made the request, to sign
// bodies, and waits for the envelopes on a port of its own.
async function signVia(clientId, purpose, bodies) {
  const client = clientId ? await self.clients.get(clientId) : null;
  if (!client) throw new ContentError('no page to sign through');
  const { port1, port2 } = new MessageChannel();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      port1.close();
      reject(new ContentError('the shell did not answer'));
    }, SIGN_WAIT_MS);
    port1.onmessage = (event) => {
      clearTimeout(timer);
      port1.close();
      const m = event.data;
      if (m?.cairn === 'signed') resolve(m.envelopes);
      else reject(new ContentError(m?.cairn === 'sign-error' && typeof m.error === 'string' ? m.error : 'the shell did not sign'));
    };
    client.postMessage({ cairn: 'sign', purpose, bodies }, [port2]);
  });
}

// handleDataRequest answers a database or stored-file request with the keys
// of the version it names, which may not be the page's own.
async function handleDataRequest(event, route) {
  const req = event.request;
  if (route.artifact !== artifact) return new Response('not found', { status: 404 });
  if (req.mode === 'navigate' && req.method !== 'GET') return new Response('method not allowed', { status: 405 });
  const entry = versions.get(route.version) ?? (await requestKeys(route.version));
  if (!entry) return unavailable();
  const ctx = {
    keys: entry.keys,
    origin,
    fetchFn: (r) => fetch(r),
    sign: (purpose, bodies) => signVia(event.clientId, purpose, bodies),
    seen,
    now: () => new Date(),
    warn: (m) => console.warn(m),
  };
  return handleData(ctx, route, req);
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== origin) return;
  const data = parseDataPath(url.pathname);
  if (data) {
    event.respondWith(handleDataRequest(event, data));
    return;
  }
  const route = classifyRequest(url.pathname);
  if (route.kind === 'api') event.respondWith(handleApi(event));
  else if (route.kind === 'content') event.respondWith(handleContent(event, route));
});
