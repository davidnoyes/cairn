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
// boot page loads before the shell answers; or on timeout(), as show(true),
// when the version may never have loaded. Nothing hides it again.
export function revealGate(show) {
  let answered = false;
  let shown = false;
  const reveal = (late) => {
    if (shown) return;
    shown = true;
    show(late);
  };
  return {
    answered: () => { answered = true; },
    loaded: () => { if (answered) reveal(false); },
    timeout: () => reveal(true),
  };
}

// SCROLL_WAIT_MS is how long a frame stays hidden for frame.js to scroll it,
// a little longer than frame.js tries for.
export const SCROLL_WAIT_MS = 2500;

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
// at once when it becomes visible again, and calls onChange, and waits for
// it, when the answer's viewKey is not that of versions. It then stops until
// resume(versions) gives it the versions now shown. One poll waits for the
// one before it. A failed poll is tried again on the next; a 401, an ended
// session, stops the watch.
export function watchVersions({ versions, pinned, list, onChange, document, setTimeout }) {
  let key = viewKey(versions, pinned);
  let busy = false;
  let done = false;
  const poll = async () => {
    if (busy || done) return;
    busy = true;
    try {
      if (viewKey(await list(), pinned) !== key) {
        done = true;
        await onChange();
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) done = true;
    } finally {
      busy = false;
    }
  };
  // Each schedule starts a new generation, and a tick of an older one ends:
  // resume() may schedule while a tick from before the change is pending.
  let generation = 0;
  const schedule = () => {
    const mine = ++generation;
    setTimeout(() => tick(mine), WATCH_MS);
  };
  const tick = async (mine) => {
    if (mine !== generation) return;
    if (document.visibilityState === 'visible') await poll();
    if (!done) schedule();
  };
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') return poll();
  });
  schedule();
  return {
    resume: (shown) => {
      key = viewKey(shown, pinned);
      done = false;
      schedule();
    },
  };
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

  // visible is the frame in view. While a new version's frame loads hidden
  // over it, both are served, until it goes. mounts holds each frame's
  // version, its reveal gate, and the step to run once frame.js has scrolled
  // it.
  let visible = null;
  const mounts = new Map();
  const post = (f, msg) => f.contentWindow.postMessage(msg, contentOrigin);
  // positions holds each frame's last scroll position, until it loads
  // another page. A reload the update falls back to leaves the position in
  // sessionStorage, for the next page to scroll back to.
  const positions = new Map();
  const scrollKey = `cairn-scroll:${artifact}`;
  const saved = window.sessionStorage.getItem(scrollKey);
  window.sessionStorage.removeItem(scrollKey);
  const validY = (y) => Number.isFinite(y) && y >= 0;

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
    let opened = await openArtifact(deps, { artifact, link, linkError });
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
    const keep = opened.mode === 'link' ? hash : '';

    // prepare reads what the page shows from the artifact as current gives
    // it: the versions, their sealed names, and the version to frame. It
    // changes nothing on the page, so an update can prepare out of sight.
    const prepare = async (current) => {
      const versions = (await listVersions(deps, opened)).filter((v) => UUID_RE.test(v.id));
      // The name and description are sealed fields: one that fails a check,
      // or that nobody wrote, leaves the artifact shown under its ID.
      const { values } = await readMeta(deps, opened, current.meta);
      const name = values.name || artifact;
      const description = values.description ?? '';
      const listed = [];
      for (const v of versions) {
        const { values: fields } = await readMeta(deps, opened, v.meta, v.id);
        listed.push({ id: v.id, seq: v.seq, name: fields.name ?? '', changelog: fields.changelog ?? '', createdAt: v.createdAt });
      }
      return { versions, listed, name, description, chosen: pageVersion || versions[0]?.id };
    };
    const contextFor = ({ name, description, listed }) => loadContext(deps, opened, { name, description, versions: listed });

    // show puts a prepared view in the header, the version list in one step.
    const picker = $('version');
    const show = (view) => {
      $('name').textContent = view.name;
      $('desc').textContent = view.description;
      document.title = view.name;
      picker.replaceChildren(...view.listed.map((v) => {
        const option = document.createElement('option');
        option.value = v.id;
        option.textContent = versionLabel(v.seq, v.name);
        option.selected = v.id === view.chosen;
        return option;
      }));
      $('fullscreen').href = `/full/${artifact}/${view.chosen}${keep}`;
    };

    let view = await prepare(info);
    show(view);
    let chosen = view.chosen;
    if (!chosen) throw new Error('This artifact has no versions yet.');
    picker.addEventListener('change', () => window.location.assign(`/shared/${artifact}/${picker.value}${keep}`));

    // Only a trusted version is framed.
    await verify(chosen);
    let context = await contextFor(view);
    let writers = await writerKeys(deps, opened);
    const keeper = keepToken({
      mint: () => mintToken(deps, opened),
      onToken: ({ token, tokenExpires }) => {
        for (const f of mounts.keys()) post(f, { cairn: 'token', token, tokenExpires });
      },
      onError: () => showStatus('Your access could not be renewed. Reload the page, or sign in again.'),
      setTimeout: (fn, ms) => window.setTimeout(fn, ms),
      clearTimeout: (id) => window.clearTimeout(id),
    });
    await keeper.start();

    // answer verifies a version of this artifact, then sends its keys to
    // frame f, which asked, unless f has gone meanwhile. A version the frame
    // names that the server does not have shows nothing: the frame runs the
    // artifact's code, and it could name any version.
    const answer = async (f, versionId, path) => {
      try {
        const { version, signer } = await verify(versionId);
        const { token, tokenExpires } = keeper.current();
        if (!mounts.has(f)) return;
        post(f, keysMessage(opened, version, { signer, token, tokenExpires, path, context, writers }));
        mounts.get(f).gate.answered();
      } catch (err) {
        if (err instanceof VersionGoneError && versionId !== mounts.get(f)?.version) return;
        showStatus(describe(err));
      }
    };
    const validVersion = (v) => typeof v === 'string' && UUID_RE.test(v);

    window.addEventListener('message', (event) => {
      const f = [...mounts.keys()].find((m) => event.source === m.contentWindow);
      if (!f || event.origin !== contentOrigin) return;
      const msg = event.data;
      if (typeof msg !== 'object' || msg === null) return;
      const mounted = mounts.get(f);
      // The old frame, during a swap, is answered with the new context and
      // writers: the same artifact and members, so nothing it may not see.
      if (msg.cairn === 'ready') {
        // A path that would take the frame out of the version gets no keys.
        if (msg.version === null) {
          if (contentTarget(mounted.version, pagePath)) answer(f, mounted.version, pagePath);
        } else if (validVersion(msg.version) && contentTarget(msg.version, msg.path)) answer(f, msg.version, msg.path);
      } else if (msg.cairn === 'need-keys') {
        if (validVersion(msg.version)) answer(f, msg.version, '/');
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
        if (validY(msg.y)) positions.set(f, msg.y);
      } else if (msg.cairn === 'scrolled') {
        mounted.scrolled?.();
      }
    });

    // reload is the update's fallback: the whole page again, which shows
    // what went wrong.
    const reload = () => {
      try {
        const y = positions.get(visible);
        if (y !== undefined) window.sessionStorage.setItem(scrollKey, String(y));
      } catch {
        // The position is a convenience; the new version still loads.
      }
      window.location.replace(window.location.pathname + keep);
    };

    // mount frames the content origin's boot page for the chosen version,
    // hidden over the frame in view, which stays until it is replaced. The
    // new frame is shown once its version has loaded, scrolled first to
    // restore(old)'s position when that is not null; the old frame goes, and
    // shown() runs, in the same step. A new version that never loads leaves
    // the old one in view, and the page reloads. The frame is white until its
    // document has loaded, against the dark page, so a first frame is out of
    // sight until then too.
    const mount = (restore, shown) => {
      const old = visible;
      const f = document.createElement('iframe');
      // reveal runs on scrolled, or on the wait, whichever comes first.
      const reveal = () => {
        if (visible === f) return;
        visible = f;
        f.className = '';
        if (old) {
          if (document.activeElement === old) f.focus();
          old.remove();
          mounts.delete(old);
          positions.delete(old);
        }
        shown();
      };
      const gate = revealGate((late) => {
        if (late && old) return reload();
        const y = late ? null : restore(old);
        if (y === null) return reveal();
        mounts.get(f).scrolled = reveal;
        post(f, { cairn: 'scroll-to', y });
        window.setTimeout(reveal, SCROLL_WAIT_MS);
      });
      mounts.set(f, { version: chosen, gate, scrolled: null });
      f.setAttribute('src', `${contentOrigin}/_cairn/boot`);
      f.setAttribute('title', view.name);
      f.setAttribute('sandbox', SANDBOX);
      f.className = 'pending';
      // A load is a new page, and the position kept belonged to the last one.
      f.addEventListener('load', () => {
        positions.delete(f);
        gate.loaded();
      });
      window.setTimeout(gate.timeout, REVEAL_MS);
      $('frame-host').appendChild(f);
    };

    // A page with no version in its address follows the newest; one that
    // names a version stays on it, and updates only if it is overwritten.
    // An update opens the artifact again and checks the version out of
    // sight, then swaps it in. The watch waits while a swap is in flight, and
    // resumes once the new frame is shown, so one swap runs at a time.
    let watch = null;
    const watching = () => {
      if (watch) {
        watch.resume(view.versions);
        return;
      }
      watch = watchVersions({
        versions: view.versions,
        pinned: pageVersion,
        list: async () => (await listVersions(deps, opened)).filter((v) => UUID_RE.test(v.id)),
        onChange: async () => {
          try {
            opened = await openArtifact(deps, { artifact, link, linkError });
            const next = await prepare(await apiGet(deps, opened, `/api/artifacts/${artifact}`));
            await verify(next.chosen);
            context = await contextFor(next);
            writers = await writerKeys(deps, opened);
            view = next;
            chosen = next.chosen;
            mount((old) => positions.get(old) ?? null, () => {
              show(next);
              watching();
            });
          } catch {
            reload();
          }
        },
        document,
        setTimeout: (fn, ms) => window.setTimeout(fn, ms),
      });
    };
    // A position this page cannot read is no position.
    mount(() => (saved !== null && validY(Number(saved)) ? Number(saved) : null), watching);
  } catch (err) {
    if (err instanceof LockedError) {
      window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
      return;
    }
    showStatus(describe(err));
  }
}

if (typeof document !== 'undefined' && document.body?.dataset?.artifact) run(window, document);
