// boot.js — the content origin's boot page script (/_cairn/boot.js), loaded
// as a module by boot.html. It registers the service worker, tells the shell
// it is ready, hands the worker the keys the shell answers with, and then
// replaces its own location with the version's page, which the worker now
// serves. Any failure is shown on the page as text. See design/e2e-api.md,
// "The handshake".
import { contentTarget, parseContentPath } from './content.mjs';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// appOriginFromMeta reads the app origin the server wrote into the page, or
// returns null when it is missing or is not an http(s) origin.
export function appOriginFromMeta(doc) {
  const el = doc.querySelector('meta[name="cairn-app-origin"]');
  try {
    const u = new URL(el ? el.getAttribute('content') : '');
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : null;
  } catch {
    return null;
  }
}

// readyMessage names the version and path the page was loaded for: both are
// null at /_cairn/boot, and set when the worker served this page for a
// navigation to /<version><path> after it had stopped.
export function readyMessage(pathname) {
  const parsed = parseContentPath(pathname);
  return { cairn: 'ready', version: parsed ? parsed.version : null, path: parsed ? '/' + parsed.path : null };
}

// checkKeysTarget refuses a keys message whose version or path could send
// the page anywhere but into a version, and returns the address to go to. The
// worker checks the rest.
export function checkKeysTarget(msg) {
  if (typeof msg.version !== 'string' || !UUID_RE.test(msg.version)) throw new Error('the keys name no valid version');
  const target = contentTarget(msg.version, msg.path);
  if (!target) throw new Error('the keys name no valid path');
  return target;
}

function showError(doc, message) {
  const p = doc.createElement('p');
  p.textContent = 'Cairn error: ' + message;
  doc.body.appendChild(p);
}

// activeWorker resolves to the registration's active worker, waiting for an
// installing one to activate, and rejects if it fails to install.
function activeWorker(reg) {
  if (reg.active) return Promise.resolve(reg.active);
  const pending = reg.installing || reg.waiting;
  if (!pending) return Promise.reject(new Error('the service worker failed to install'));
  return new Promise((resolve, reject) => {
    pending.addEventListener('statechange', () => {
      if (reg.active) resolve(reg.active);
      else if (pending.state === 'redundant') reject(new Error('the service worker failed to install'));
    });
  });
}

// run does the handshake. It resolves when the page has moved on or shown an
// error.
export async function run({ doc, win, loc, nav }) {
  try {
    const appOrigin = appOriginFromMeta(doc);
    if (!appOrigin) throw new Error('the page has no valid app origin');
    const sw = nav.serviceWorker;

    const reg = await sw.register(`/_cairn/sw.js?app=${encodeURIComponent(appOrigin)}`, { type: 'module', scope: '/', updateViaCache: 'none' });
    // Only the registration made here, never sw.ready: artifact code shares
    // this origin and can register at a narrower scope, which sw.ready would
    // resolve to. Every other registration is removed.
    const others = (await sw.getRegistrations()).filter((r) => r.scope !== reg.scope);
    await Promise.all(others.map((r) => r.unregister()));
    // The active worker, not the controller: Firefox leaves this page
    // uncontrolled on a repeat visit, and the worker serves the navigation to
    // the version whether or not it controls this page.
    const worker = await activeWorker(reg);

    // Listen before saying ready, so the answer cannot be missed.
    const answer = new Promise((resolve) => {
      win.addEventListener('message', (event) => {
        if (event.source !== win.parent || event.origin !== appOrigin) return;
        if (!event.data || event.data.cairn !== 'keys') return;
        resolve(event.data);
      });
    });
    win.parent.postMessage(readyMessage(loc.pathname), appOrigin);

    const keys = await answer;
    const target = checkKeysTarget(keys);
    const confirmed = new Promise((resolve, reject) => {
      sw.addEventListener('message', (event) => {
        const m = event.data;
        if (event.source !== worker || !m || m.version !== keys.version) return;
        if (m.cairn === 'keys-ok') resolve();
        else if (m.cairn === 'keys-error') reject(new Error(typeof m.error === 'string' ? m.error : 'the keys were refused'));
      });
    });
    worker.postMessage(keys);
    await confirmed;
    loc.replace(target);
  } catch (err) {
    showError(doc, err.message);
  }
}

if (typeof document !== 'undefined') {
  run({ doc: document, win: window, loc: location, nav: navigator });
}
