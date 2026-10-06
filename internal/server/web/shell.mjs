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

function versionLabel(seq, name) {
  return name ? `#${seq} ${name}` : `#${seq}`;
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
    const verify = (versionId) => prepareVersion(deps, opened, versionId);
    const info = await apiGet(deps, opened, `/api/artifacts/${artifact}`);
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
      } catch (err) {
        if (err instanceof VersionGoneError && versionId !== chosen) return;
        showStatus(describe(err));
      }
    };
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
      }
    });

    frame = document.createElement('iframe');
    frame.setAttribute('src', `${contentOrigin}/_cairn/boot`);
    frame.setAttribute('title', name);
    frame.setAttribute('sandbox', SANDBOX);
    $('frame-host').appendChild(frame);
  } catch (err) {
    if (err instanceof LockedError) {
      window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
      return;
    }
    showStatus(describe(err));
  }
}

if (typeof document !== 'undefined' && document.body?.dataset?.artifact) run(window, document);
