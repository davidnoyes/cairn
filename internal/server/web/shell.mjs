// shell.mjs — the shell page at /shared/{id}[/{vid}[/{path}]] and /full/...
// It verifies the artifact's membership chain and the version (viewer.mjs),
// and only then frames the content origin's boot page and answers its
// handshake. The page carries no artifact data; everything shown comes from
// answers this module checked. It writes text with textContent and builds
// elements with createElement only, because the page enforces Trusted Types.
import { ApiError } from './account.mjs';
import { contentTarget } from './content.mjs';
import { createKeyStore } from './keystore.mjs';
import { readMeta } from './meta.mjs';
import {
  KeyringBusyError, LinkError, LockedError, NoAccessError, UntrustedVersionError, apiGet, keepToken, keysMessage,
  VersionGoneError, listVersions, loadContext, mintToken, navigateTarget, openArtifact, prepareVersion, signBodies, takeLink,
  writerKeys,
} from './viewer.mjs';

const SANDBOX = 'allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-downloads';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// describe is a message a person can act on for a failure.
function describe(err) {
  if (
    err instanceof UntrustedVersionError || err instanceof NoAccessError || err instanceof LinkError || err instanceof KeyringBusyError
    || err instanceof VersionGoneError
  ) {
    return err.message;
  }
  if (err instanceof ApiError && err.status === 401) return 'Your session has ended. Sign in again.';
  return `This artifact could not be verified, so it is not shown. ${err.message}`;
}

// unreadableMessage names the epochs the owner's wrap did not open, in the
// singular for one and with a serial comma for three or more.
function unreadableMessage(epochs) {
  if (epochs.length === 1) {
    return `Your key for epoch ${epochs[0]} could not be read, so what was sealed under it will not open. Remove the manager who started it to start a new epoch.`;
  }
  const list = epochs.length === 2 ? epochs.join(' and ') : `${epochs.slice(0, -1).join(', ')}, and ${epochs.at(-1)}`;
  return `Your keys for epochs ${list} could not be read, so what was sealed under them will not open. Remove the managers who started them to start a new epoch.`;
}

function versionLabel(seq, name) {
  return name ? `#${seq} ${name}` : `#${seq}`;
}

// REVEAL_MS is how long the frame stays hidden when the shell is never asked
// for keys, or the document never loads, so a boot page that shows an error is
// still seen.
export const REVEAL_MS = 4000;

// revealGate decides when the hidden frame is shown, by calling show() once:
// on the first load after answered(), which is the version's page, since the
// boot page loads before the shell answers; or on timeout(). Nothing hides it
// again.
export function revealGate(show) {
  let answered = false;
  let shown = false;
  const reveal = () => {
    if (shown) return;
    shown = true;
    show();
  };
  return {
    answered: () => { answered = true; },
    loaded: () => { if (answered) reveal(); },
    timeout: reveal,
  };
}

// WATCH_MS is how often an open page asks for the artifact's versions, to
// reload when the one it shows has changed.
export const WATCH_MS = 5000;

// viewKey identifies what a page shows: the newest version, or the pinned
// one, with its manifest hash, which an overwrite in place changes. A pinned
// version that is gone is ''.
export function viewKey(versions, pinned) {
  const v = pinned ? versions.find((x) => x.id === pinned) : versions[0];
  return v ? `${v.id}:${v.manifestHash}` : '';
}

// watchVersions polls list() every WATCH_MS while document is visible, and
// at once when it becomes visible again, and calls onChange once when the
// answer's viewKey is not that of versions. One poll waits for the one
// before it. A failed poll is tried again on the next; a 401, an ended
// session, stops the watch.
export function watchVersions({ versions, pinned, list, onChange, document, setTimeout }) {
  const key = viewKey(versions, pinned);
  let busy = false;
  let done = false;
  const poll = async () => {
    if (busy || done) return;
    busy = true;
    try {
      if (viewKey(await list(), pinned) !== key) {
        done = true;
        onChange();
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) done = true;
    } finally {
      busy = false;
    }
  };
  const tick = async () => {
    if (document.visibilityState === 'visible') await poll();
    if (!done) setTimeout(tick, WATCH_MS);
  };
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') return poll();
  });
  setTimeout(tick, WATCH_MS);
}

const MAX_NAME = 200;
const REVOKE_MS = 60000;

// downloadName is the last segment of the name the frame asked for, without
// control characters, or "download".
export function downloadName(name) {
  const last = typeof name === 'string' ? name.split(/[/\\]/).pop() : '';
  const clean = [...last].filter((ch) => ch.charCodeAt(0) >= 0x20 && ch !== '\x7f').join('').trim().slice(0, MAX_NAME);
  return clean === '' || clean === '.' || clean === '..' ? 'download' : clean;
}

// download saves bytes the frame sent as a file. The sandboxed frame cannot
// save a response its worker built in every browser, so it hands the bytes
// to the shell. They are typed application/octet-stream, so nothing is
// rendered on this origin.
function download(window, document, msg) {
  const bytes = msg.bytes;
  if (!(bytes instanceof ArrayBuffer) && !ArrayBuffer.isView(bytes)) return;
  const url = window.URL.createObjectURL(new window.Blob([bytes], { type: 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = downloadName(msg.name);
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => window.URL.revokeObjectURL(url), REVOKE_MS);
}

// run starts the shell on window and document. keyStore is the signed-in
// user's keys; it defaults to the one in IndexedDB.
export async function run(window, document, keyStore = createKeyStore(window.indexedDB)) {
  const { artifact, version: pageVersion, path: pagePath, mode: pageMode, contentOrigin } = document.body.dataset;
  const mode = pageMode === 'full' ? 'full' : 'shared';
  const $ = (id) => document.getElementById(id);
  const status = $('status');
  const showStatus = (text) => {
    status.textContent = text;
    status.hidden = false;
  };
  const deps = { fetch: (...args) => window.fetch(...args), keyStore, storage: window.localStorage, origin: window.location.origin };

  let frame = null;
  const send = (msg) => frame.contentWindow.postMessage(msg, contentOrigin);
  // A reload for a new version leaves the reading position here, for this
  // page to scroll back to once the frame is shown.
  const scrollKey = `cairn-scroll:${artifact}`;
  const saved = window.sessionStorage.getItem(scrollKey);
  window.sessionStorage.removeItem(scrollKey);
  let scrollY = null;

  try {
    let link = null;
    let linkError = null;
    // A public link's fragment is carried to the other version and full
    // screen pages, which take it from the address bar again. A member who
    // followed the link opens as a member and needs no key carried on.
    const hash = window.location.hash;
    try {
      link = takeLink(window.location, window.history, artifact);
    } catch (err) {
      if (!(err instanceof LinkError)) throw err;
      linkError = err;
    }
    const opened = await openArtifact(deps, { artifact, link, linkError });
    // The owner's wrap of an epoch a manager started did not open: what was
    // sealed under it stays unreadable until a new epoch replaces it.
    if (opened.unreadable?.length) showStatus(unreadableMessage(opened.unreadable));
    const verify = (versionId) => prepareVersion(deps, opened, versionId);
    const info = await apiGet(deps, opened, `/api/artifacts/${artifact}`);
    // A folder holds no content, and the server refuses its versions. It is
    // shown by name, with the way to the Artifacts tab, where it opens.
    if (info.kind === 'folder') {
      const { values: fields } = await readMeta(deps, opened, info.meta);
      $('name').textContent = fields.name || artifact;
      document.title = fields.name || artifact;
      const tab = document.createElement('a');
      tab.href = '/app';
      tab.textContent = 'Open it on the Artifacts tab';
      showStatus('This is a folder, so it has nothing to show here. ');
      status.appendChild(tab);
      return;
    }
    const versions = (await listVersions(deps, opened)).filter((v) => UUID_RE.test(v.id));

    // The name and description are sealed fields: one that fails a check,
    // or that nobody wrote, leaves the artifact shown under its ID.
    const { values } = await readMeta(deps, opened, info.meta);
    const name = values.name || artifact;
    const description = values.description ?? '';
    $('name').textContent = name;
    $('desc').textContent = description;
    document.title = name;
    const chosen = pageVersion || versions[0]?.id;
    if (!chosen) throw new Error('This artifact has no versions yet.');
    const picker = $('version');
    const listed = [];
    for (const v of versions) {
      const { values: fields } = await readMeta(deps, opened, v.meta, v.id);
      listed.push({ id: v.id, seq: v.seq, name: fields.name ?? '', changelog: fields.changelog ?? '', createdAt: v.createdAt });
      const option = document.createElement('option');
      option.value = v.id;
      option.textContent = versionLabel(v.seq, fields.name);
      option.selected = v.id === chosen;
      picker.appendChild(option);
    }
    const keep = opened.mode === 'link' ? hash : '';
    picker.addEventListener('change', () => window.location.assign(`/shared/${artifact}/${picker.value}${keep}`));
    $('fullscreen').href = `/full/${artifact}/${chosen}${keep}`;

    // Only a trusted version is framed.
    await verify(chosen);
    const context = await loadContext(deps, opened, { name, description, versions: listed });
    const writers = await writerKeys(deps, opened);
    const keeper = keepToken({
      mint: () => mintToken(deps, opened),
      onToken: ({ token, tokenExpires }) => send({ cairn: 'token', token, tokenExpires }),
      onError: () => showStatus('Your access could not be renewed. Reload the page, or sign in again.'),
      setTimeout: (fn, ms) => window.setTimeout(fn, ms),
      clearTimeout: (id) => window.clearTimeout(id),
    });
    await keeper.start();

    // answer verifies a version of this artifact, then sends its keys. A
    // version the frame names that the server does not have shows nothing:
    // the frame runs the artifact's code, and it could name any version.
    const answer = async (versionId, path) => {
      try {
        const { version, signer } = await verify(versionId);
        const { token, tokenExpires } = keeper.current();
        send(keysMessage(opened, version, { signer, token, tokenExpires, path, context, writers }));
        gate.answered();
      } catch (err) {
        if (err instanceof VersionGoneError && versionId !== chosen) return;
        showStatus(describe(err));
      }
    };
    // The frame is white until its document has loaded, against the dark page,
    // so it stays out of sight until then.
    const gate = revealGate(() => {
      frame.className = '';
      if (saved !== null) send({ cairn: 'scroll-to', y: Number(saved) });
    });
    const validVersion = (v) => typeof v === 'string' && UUID_RE.test(v);

    window.addEventListener('message', (event) => {
      if (event.source !== frame.contentWindow || event.origin !== contentOrigin) return;
      const msg = event.data;
      if (typeof msg !== 'object' || msg === null) return;
      if (msg.cairn === 'ready') {
        // A path that would take the frame out of the version gets no keys.
        if (msg.version === null) {
          if (contentTarget(chosen, pagePath)) answer(chosen, pagePath);
        } else if (validVersion(msg.version) && contentTarget(msg.version, msg.path)) answer(msg.version, msg.path);
      } else if (msg.cairn === 'need-keys') {
        if (validVersion(msg.version)) answer(msg.version, '/');
      } else if (msg.cairn === 'login') {
        // A public link's key rides on the sign-in page's fragment, which
        // never reaches the server, and comes back with the person.
        window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}${keep}`);
      } else if (msg.cairn === 'navigate') {
        const target = typeof msg.href === 'string' ? navigateTarget(msg.href, { origin: window.location.origin, mode }) : null;
        if (target) window.location.assign(target);
      } else if (msg.cairn === 'sign') {
        // The worker asks, through the frame, for data records to be signed;
        // the answer goes back on the port it sent.
        const port = event.ports?.[0];
        if (!port) return;
        signBodies(opened, msg.purpose, msg.bodies).then(
          (envelopes) => port.postMessage({ cairn: 'signed', envelopes }),
          (err) => port.postMessage({ cairn: 'sign-error', error: err.message }),
        );
      } else if (msg.cairn === 'download') {
        download(window, document, msg);
      } else if (msg.cairn === 'scroll') {
        if (Number.isFinite(msg.y) && msg.y >= 0) scrollY = msg.y;
      }
    });

    frame = document.createElement('iframe');
    frame.setAttribute('src', `${contentOrigin}/_cairn/boot`);
    frame.setAttribute('title', name);
    frame.setAttribute('sandbox', SANDBOX);
    frame.className = 'pending';
    frame.addEventListener('load', gate.loaded);
    window.setTimeout(gate.timeout, REVEAL_MS);
    $('frame-host').appendChild(frame);

    // A page with no version in its address follows the newest; one that
    // names a version stays on it, and reloads only if it is overwritten.
    watchVersions({
      versions,
      pinned: pageVersion,
      list: async () => (await listVersions(deps, opened)).filter((v) => UUID_RE.test(v.id)),
      onChange: () => {
        if (scrollY !== null) window.sessionStorage.setItem(scrollKey, String(scrollY));
        window.location.replace(window.location.pathname + keep);
      },
      document,
      setTimeout: (fn, ms) => window.setTimeout(fn, ms),
    });
  } catch (err) {
    if (err instanceof LockedError) {
      window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
      return;
    }
    showStatus(describe(err));
  }
}

if (typeof document !== 'undefined' && document.body?.dataset?.artifact) run(window, document);
