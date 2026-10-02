// shell.mjs — the shell page at /shared/{id}[/{vid}[/{path}]] and /full/...
// It verifies the artifact's membership chain and the version (viewer.mjs),
// and only then frames the content origin's boot page and answers its
// handshake. The page carries no artifact data; everything shown comes from
// answers this module checked. It writes text with textContent and builds
// elements with createElement only, because the page enforces Trusted Types.
import { ApiError } from './account.mjs';
import { createKeyStore } from './keystore.mjs';
import {
  KeyringBusyError, LinkError, NoAccessError, UntrustedVersionError, apiGet, keepToken, keysMessage,
  listVersions, loadContext, mintToken, navigateTarget, openArtifact, prepareVersion, takeLink,
} from './viewer.mjs';

const SANDBOX = 'allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-downloads';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// describe is a message a person can act on for a failure.
function describe(err) {
  if (err instanceof UntrustedVersionError || err instanceof NoAccessError || err instanceof LinkError || err instanceof KeyringBusyError) {
    return err.message;
  }
  if (err instanceof ApiError && err.status === 401) return 'Your session has ended. Sign in again.';
  return `This artifact could not be verified, so it is not shown. ${err.message}`;
}

function versionLabel(v) {
  return v.name ? `#${v.seq} ${v.name}` : `#${v.seq}`;
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
    const link = takeLink(window.location, window.history, artifact);
    const opened = await openArtifact(deps, { artifact, link });
    const info = await apiGet(deps, opened, `/api/artifacts/${artifact}`);
    const versions = (await listVersions(deps, opened)).filter((v) => UUID_RE.test(v.id));

    $('name').textContent = info.name;
    $('desc').textContent = info.description ?? '';
    document.title = info.name;
    const chosen = pageVersion || versions[0]?.id;
    if (!chosen) throw new Error('This artifact has no versions yet.');
    const picker = $('version');
    for (const v of versions) {
      const option = document.createElement('option');
      option.value = v.id;
      option.textContent = versionLabel(v);
      option.selected = v.id === chosen;
      picker.appendChild(option);
    }
    picker.addEventListener('change', () => window.location.assign(`/shared/${artifact}/${picker.value}`));
    $('fullscreen').href = `/full/${artifact}/${chosen}`;

    // Only a trusted version is framed.
    await prepareVersion(deps, opened, chosen);
    const context = await loadContext(deps, opened, info);
    const keeper = keepToken({
      mint: () => mintToken(deps, opened),
      onToken: ({ token, tokenExpires }) => send({ cairn: 'token', token, tokenExpires }),
      onError: () => showStatus('Your access could not be renewed. Reload the page, or sign in again.'),
      setTimeout: (fn, ms) => window.setTimeout(fn, ms),
      clearTimeout: (id) => window.clearTimeout(id),
    });
    await keeper.start();

    // answer verifies a version of this artifact, then sends its keys. A
    // version the server does not know for this artifact is ignored.
    const answer = async (versionId, path) => {
      try {
        const { version, signer } = await prepareVersion(deps, opened, versionId);
        const { token, tokenExpires } = keeper.current();
        send(keysMessage(opened, version, { signer, token, tokenExpires, path, context }));
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) return;
        showStatus(describe(err));
      }
    };
    const validVersion = (v) => typeof v === 'string' && UUID_RE.test(v);

    window.addEventListener('message', (event) => {
      if (event.source !== frame.contentWindow || event.origin !== contentOrigin) return;
      const msg = event.data;
      if (typeof msg !== 'object' || msg === null) return;
      if (msg.cairn === 'ready') {
        if (msg.version === null) answer(chosen, pagePath);
        else if (validVersion(msg.version) && typeof msg.path === 'string' && msg.path.startsWith('/')) answer(msg.version, msg.path);
      } else if (msg.cairn === 'need-keys') {
        if (validVersion(msg.version)) answer(msg.version, '/');
      } else if (msg.cairn === 'navigate') {
        const target = typeof msg.href === 'string' ? navigateTarget(msg.href, { origin: window.location.origin, mode }) : null;
        if (target) window.location.assign(target);
      }
    });

    frame = document.createElement('iframe');
    frame.setAttribute('src', `${contentOrigin}/_cairn/boot`);
    frame.setAttribute('title', info.name);
    frame.setAttribute('sandbox', SANDBOX);
    $('frame-host').appendChild(frame);
  } catch (err) {
    showStatus(describe(err));
  }
}

if (typeof document !== 'undefined' && document.body?.dataset?.artifact) run(window, document);
