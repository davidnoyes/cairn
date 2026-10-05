// app.mjs — the signed-in home page: artifacts, API keys, account settings,
// and users for an administrator. It talks to the JSON APIs and builds every
// element with createElement and textContent: the app CSP's Trusted Types
// rule refuses a string assigned to innerHTML. It never opens a native
// dialog: a destructive action asks again in its own button.
import { changePassword, createApiKey, newRecoveryCode, signOut } from './account.mjs';
import { UnauthenticatedError, startApp } from './app-init.mjs';
import { describeArtifact } from './meta.mjs';
import { KeyChangedError, members, pin, publicLinkFor, setPublic, share, unshare } from './sharing.mjs';
import { describeError, pageDeps, watchStrength } from './ui.mjs';

const $ = (id) => document.getElementById(id);
// viewer.mjs and sharing.mjs also need the keyring anchor's storage and the
// origin a public link names.
const deps = { ...pageDeps(), storage: localStorage, origin: location.origin };
const toLogin = () => { location.href = '/login?next=/app'; };

async function api(path, options) {
  const resp = await fetch(path, options);
  if (resp.status === 401) { toLogin(); throw new UnauthenticatedError(); }
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
  return data;
}
const send = (method, path, body) => api(path, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const del = (path) => api(path, { method: 'DELETE' });

// status shows one line in a role=status element. A redirect to sign in
// needs none: the page is leaving.
function status(id, msg, bad = false) {
  const el = $(id);
  el.textContent = msg;
  el.classList.toggle('bad', bad);
}
function failIn(id) {
  return (err) => { if (!(err instanceof UnauthenticatedError)) status(id, describeError(err), true); };
}

const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};
const td = (content, cls) => {
  const e = el('td', cls);
  if (content instanceof Node) e.appendChild(content); else e.textContent = content;
  return e;
};
const btn = (label, cls, fn) => {
  const e = el('button', 'btn ' + (cls || ''), label);
  e.type = 'button';
  e.addEventListener('click', fn);
  return e;
};
const pill = (label, cls) => el('span', 'pill ' + (cls || ''), label);
const day = (ts) => (ts || '').slice(0, 10);
function emptyRow(body, cols, text) {
  const cell = td(text, 'empty');
  cell.colSpan = cols;
  const tr = el('tr');
  tr.appendChild(cell);
  body.replaceChildren(tr);
}

// confirmButton asks again in the button itself: the first click relabels
// it, a second within a few seconds runs action.
function confirmButton(label, again, action) {
  let timer;
  const b = btn(label, 'danger', async () => {
    if (!b.classList.contains('armed')) {
      b.classList.add('armed');
      b.textContent = again;
      timer = setTimeout(() => { b.classList.remove('armed'); b.textContent = label; }, 4000);
      return;
    }
    clearTimeout(timer);
    b.disabled = true;
    try { await action(); } finally { b.disabled = false; }
  });
  return b;
}

// ------------------------------------------------------------------ tabs
const tabs = [...document.querySelectorAll('[role=tab]')];
function selectTab(tab) {
  for (const t of tabs) {
    const on = t === tab;
    t.setAttribute('aria-selected', String(on));
    t.tabIndex = on ? 0 : -1;
    $(t.getAttribute('aria-controls')).classList.toggle('active', on);
  }
}
for (const t of tabs) t.addEventListener('click', () => selectTab(t));
selectTab(tabs[0]);

$('signout').addEventListener('click', async (event) => {
  event.preventDefault();
  try {
    await signOut(deps);
  } finally {
    location.href = '/logout';
  }
});

// ------------------------------------------------------------- artifacts
// The server holds each name and description sealed, so a row shows the
// artifact's ID until its own keys open them.
async function listArtifacts({ me }) {
  const list = await api('/api/artifacts');
  const rows = new Map(list.map((a) => [a.id, artifactRow(a, a.owner === me.id)]));
  const fill = (body, mine, empty) => {
    const trs = list.filter((a) => (a.owner === me.id) === mine).map((a) => rows.get(a.id).tr);
    if (trs.length === 0) emptyRow(body, 6, empty); else body.replaceChildren(...trs);
  };
  fill($('own'), true, 'No artifacts yet.');
  fill($('shared'), false, 'Nothing is shared with you yet.');
  // One at a time: opening an artifact for the first time pins its owner in
  // the keyring, and each pin is a write at the keyring's next revision.
  for (const a of list) {
    const row = rows.get(a.id);
    const got = await describeArtifact(deps, a);
    row.name = got.name;
    row.nameText.textContent = got.name;
    row.descText.textContent = got.description;
    // Said in the row, not only in a tooltip, so a keyboard or screen reader
    // user learns why the row shows an ID.
    row.reasonText.textContent = got.error ? describeError(got.error) : '';
    // The share dialog may have opened on this row before its name was read.
    if (sharing?.id === a.id) {
      sharing.name = got.name;
      $('share-title').textContent = got.name;
    }
  }
}

// One load at a time: two loads opening the same artifact for the first time
// would both pin its owner at the keyring's next revision.
let artifactsLoad = Promise.resolve();
function loadArtifacts(ctx) {
  const run = artifactsLoad.then(() => listArtifacts(ctx));
  artifactsLoad = run.catch(() => {});
  return run;
}

function artifactRow(a, mine) {
  const row = { name: a.id, nameText: el('div', 'clamp', a.id), descText: el('div', 'clamp', '') };
  const tr = el('tr');
  tr.dataset.id = a.id;
  row.reasonText = el('div', 'unreadable', '');
  const nameCell = td(row.nameText, 'name');
  nameCell.appendChild(row.reasonText);
  tr.append(
    nameCell,
    td(row.descText, 'desc'),
    td(a.access, 'access'),
    td(a.public ? 'public' : 'private', 'public'),
    td(day(a.updatedAt), 'mono'),
  );
  const actions = el('div', 'actions');
  const open = el('a', 'btn', 'Open');
  open.href = '/shared/' + a.id;
  actions.appendChild(open);
  if (mine) {
    actions.append(
      btn('Share', '', () => openShare(a.id, row.name)),
      confirmButton('Delete', 'Delete for good?', () => del('/api/artifacts/' + a.id)
        .then(() => { status('artifacts-status', 'Artifact deleted.'); return reloadArtifacts(); })
        .catch(failIn('artifacts-status'))),
    );
  }
  tr.appendChild(td(actions));
  row.tr = tr;
  return row;
}

const reloadArtifacts = () => loadArtifacts({ me }).catch(failIn('artifacts-status'));

// ----------------------------------------------------------------- share
// The dialog works on one artifact at a time. The public link carries the
// artifact's key, so it lives only in this variable until the owner copies it.
let sharing = null;

async function openShare(id, name) {
  sharing = { id, name, link: null, changed: false };
  $('share-title').textContent = name;
  status('share-status', '');
  $('accept-warning').hidden = true;
  $('share').showModal();
  await act(() => 'Loading the members…', async () => null);
}

// act runs one change with the dialog's controls disabled, shows what it did,
// and lists the members again. A member whose keys changed gets the warning
// first; accepting runs the same change again with acceptNewKey.
async function act(working, change, retry) {
  const s = sharing;
  const controls = [...$('share').querySelectorAll('button, input, select')].filter((c) => c.id !== 'share-close');
  for (const c of controls) c.disabled = true;
  status('share-status', working());
  let said = null;
  let failed = null;
  try {
    said = await change();
    if (said !== null) s.changed = true;
  } catch (err) {
    failed = err;
  }
  // The owner may have closed the dialog while the change ran, or opened it
  // again on another artifact: the controls and status are that dialog's now.
  if (s !== sharing) {
    if (s.changed) reloadArtifacts();
    if (failed && !(failed instanceof UnauthenticatedError)) {
      status('artifacts-status', `A change to how ${s.name} is shared did not go through: ${describeError(failed)}`, true);
    }
    return;
  }
  if (failed instanceof KeyChangedError && retry) {
    warnKeyChanged(failed.message, retry);
    status('share-status', '');
  } else if (failed && !(failed instanceof UnauthenticatedError)) {
    status('share-status', describeError(failed), true);
  }
  try {
    // A refused change leaves the switches as the owner set them, not as the
    // server has them, so the members are listed again either way.
    await listMembers(s);
    if (!failed && s === sharing) status('share-status', said ?? '');
  } catch (err) {
    if (!failed && s === sharing && !(err instanceof UnauthenticatedError)) {
      const listed = `The members could not be listed: ${describeError(err)}`;
      status('share-status', said === null ? listed : `${said} ${listed}`, true);
    }
  } finally {
    if (s === sharing) {
      for (const c of controls) c.disabled = false;
      $('public-writes').disabled = !$('public').checked;
      $('copy-link').disabled = !$('public').checked;
    }
  }
}

let accept = null;
function warnKeyChanged(message, retry) {
  $('accept-text').textContent = message;
  $('accept-warning').hidden = false;
  accept = retry;
}
$('accept-confirm').addEventListener('click', () => {
  $('accept-warning').hidden = true;
  const run = accept;
  accept = null;
  if (run) run();
});
$('accept-cancel').addEventListener('click', () => { $('accept-warning').hidden = true; accept = null; });

async function listMembers(s) {
  const res = await members(deps, s.id);
  if (s !== sharing) return;
  $('public').checked = res.public;
  $('public-writes').checked = res.publicWrites;
  $('members').replaceChildren(...res.members.map((m) => memberRow(s, m)));
}

function memberRow(s, m) {
  const who = m.email || m.user;
  const tr = el('tr');
  tr.dataset.email = m.email;
  tr.append(
    td(m.name, 'name'),
    td(m.email, 'email'),
    td(m.role, 'role'),
    td(m.currentFp || m.fp, 'fp mono'),
    td(m.state, 'pin'),
  );
  const actions = el('div', 'actions');
  if (m.role !== 'owner') {
    const role = el('select', 'role');
    role.setAttribute('aria-label', 'Role of ' + who);
    for (const r of ['viewer', 'editor']) {
      const o = el('option', '', r);
      o.value = r;
      o.selected = r === m.role;
      role.appendChild(o);
    }
    const setRole = (acceptNewKey) => act(() => 'Changing the role…', async () => {
      const res = await share(deps, s.id, who, role.value, { acceptNewKey });
      return `${who} is now ${role.value}.` + epochNote(res);
    }, acceptNewKey ? undefined : () => setRole(true));
    role.addEventListener('change', () => setRole(false));
    actions.appendChild(role);
    if (m.state === 'changed') {
      // share with the same role lists their new keys; without acceptNewKey
      // it refuses, and the refusal is the warning.
      const acceptKey = (acceptNewKey) => act(() => 'Checking the new key…', async () => {
        const res = await share(deps, s.id, who, m.role, { acceptNewKey });
        return `Accepted the new key of ${who}.` + epochNote(res);
      }, acceptNewKey ? undefined : () => acceptKey(true));
      actions.appendChild(btn('Accept new key', 'danger', () => acceptKey(false)));
    } else if (m.state !== 'verified' && m.state !== '-' && m.state !== 'conflict') {
      actions.appendChild(btn('Verify', '', () => act(() => 'Marking the key verified…', async () => {
        await pin(deps, who, { verified: true });
        return `Marked the key of ${who} verified.`;
      })));
    }
    actions.appendChild(btn('Remove', 'danger', () => act(() => 'Removing the member and re-sealing…', async () => {
      const res = await unshare(deps, s.id, who);
      return `Removed ${who}.` + epochNote(res);
    })));
  }
  tr.appendChild(td(actions));
  return tr;
}

// epochNote says what a change that started a new epoch re-sealed, and what
// it left alone and why.
function epochNote(res) {
  if (!res.reseal) return '';
  const { resealed = [], skipped = [], error } = res.reseal;
  let note = ` Started key epoch ${res.epoch}; re-sealed ${resealed.length} item${resealed.length === 1 ? '' : 's'}.`;
  if (skipped.length > 0) note += ' Left alone: ' + skipped.map((x) => `${x.what} (${x.reason})`).join('; ') + '.';
  if (error) note += ' Re-sealing stopped: ' + describeError(error) + ' Run cairn reseal to finish.';
  return note;
}

$('share-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const email = $('share-email');
  const s = sharing;
  const send = (acceptNewKey) => act(() => 'Sharing…', async () => {
    const res = await share(deps, s.id, email.value, $('share-role').value, { acceptNewKey });
    const said = `Shared with ${res.user.email} as ${res.role}.` + epochNote(res);
    if (s === sharing) email.value = '';
    return said;
  }, acceptNewKey ? undefined : () => send(true));
  send(false);
});

$('public').addEventListener('change', () => {
  const on = $('public').checked;
  const s = sharing;
  act(() => (on ? 'Making the artifact public…' : 'Making the artifact private and re-sealing…'), async () => {
    const res = await setPublic(deps, s.id, on, on ? { writes: $('public-writes').checked } : {});
    s.link = res.link;
    return on
      ? 'The artifact is public: anyone with the link can read it.'
      : 'The artifact is private: the old link no longer opens it.' + epochNote(res);
  });
});

$('public-writes').addEventListener('change', () => {
  const writes = $('public-writes').checked;
  const s = sharing;
  act(() => 'Changing public writes…', async () => {
    const res = await setPublic(deps, s.id, true, { writes });
    s.link = res.link;
    return writes ? 'Anyone with the link can now write to the artifact.' : 'Only members can write to the artifact now.';
  });
});

$('copy-link').addEventListener('click', async () => {
  const s = sharing;
  try {
    s.link ??= await publicLinkFor(deps, s.id);
    if (!s.link) { status('share-status', 'The artifact is not public, so it has no link.', true); return; }
    await navigator.clipboard.writeText(s.link);
    status('share-status', 'Link copied.');
  } catch (err) {
    status('share-status', describeError(err), true);
  }
});

$('share-close').addEventListener('click', () => $('share').close());
$('share').addEventListener('close', () => {
  const changed = sharing?.changed;
  sharing = null;
  $('members').replaceChildren();
  if (changed) reloadArtifacts();
});

// ------------------------------------------------------------------ keys
async function loadKeys() {
  const body = $('keys');
  const keys = await api('/api/keys');
  body.replaceChildren(...keys.map((k) => {
    const tr = el('tr');
    tr.dataset.key = k.id;
    tr.append(
      td(k.name || '(unnamed)', 'name'),
      td(day(k.createdAt), 'mono'),
      td(day(k.lastUsedAt), 'mono'),
      td(pill(k.device ? 'device' : 'key')),
    );
    const actions = el('div', 'actions');
    actions.appendChild(btn('Revoke', 'danger', () => del('/api/keys/' + k.id)
      .then(() => { status('keys-status', 'Key revoked.'); return loadKeys(); })
      .catch(failIn('keys-status'))));
    tr.appendChild(td(actions));
    return tr;
  }));
}

$('key-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  const password = $('key-password');
  button.disabled = true;
  $('key-new').textContent = '';
  status('keys-status', 'Creating the key…');
  try {
    const { key } = await createApiKey(deps, { name: $('key-name').value, password: password.value });
    $('key-new').textContent = key;
    $('key-name').value = '';
    status('keys-status', 'Copy the key now: it is not shown again.');
    await loadKeys();
  } catch (err) {
    failIn('keys-status')(err);
  } finally {
    password.value = '';
    button.disabled = false;
  }
});

// --------------------------------------------------------------- account
let me;
watchStrength(deps, $('pw-new'), $('pw-strength'), () => [me?.email, me?.name]);

$('pw-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  const fields = ['pw-current', 'pw-new', 'pw-confirm'].map($);
  button.disabled = true;
  status('account-status', 'Changing the password…');
  try {
    await changePassword(deps, { current: fields[0].value, next: fields[1].value, confirm: fields[2].value });
    for (const f of fields) f.value = '';
    $('pw-strength').textContent = '';
    status('account-status', 'Password changed.');
  } catch (err) {
    failIn('account-status')(err);
  } finally {
    button.disabled = false;
  }
});

$('rc-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  const password = $('rc-password');
  button.disabled = true;
  $('rc-new').textContent = '';
  status('account-status', 'Making a new recovery code…');
  try {
    const { recoveryCode } = await newRecoveryCode(deps, { password: password.value });
    $('rc-new').textContent = recoveryCode;
    status('account-status', 'Write the new recovery code down now: it is not shown again, and the old one no longer works.');
  } catch (err) {
    failIn('account-status')(err);
  } finally {
    password.value = '';
    button.disabled = false;
  }
});

// ----------------------------------------------------------------- users
async function loadUsers() {
  const users = await api('/api/admin/users');
  const reload = () => loadUsers().catch(failIn('users-status'));
  $('users').replaceChildren(...users.map((u) => {
    const tr = el('tr');
    tr.dataset.user = u.id;
    const who = el('div', 'name', u.email);
    if (u.name) who.appendChild(el('div', 'sub', u.name));
    tr.append(td(who), td(u.id, 'mono'));
    const flags = el('div', 'status');
    if (u.isAdmin) flags.appendChild(pill('admin', 'admin'));
    if (!u.verified) flags.appendChild(pill('unverified'));
    if (u.disabled) flags.appendChild(pill('disabled', 'off'));
    tr.appendChild(td(flags));
    const actions = el('div', 'actions');
    actions.append(
      btn(u.isAdmin ? 'Revoke admin' : 'Make admin', '', () => send('PATCH', '/api/admin/users/' + u.id, { isAdmin: !u.isAdmin }).then(reload, failIn('users-status'))),
      btn(u.disabled ? 'Enable' : 'Disable', '', () => send('PATCH', '/api/admin/users/' + u.id, { disabled: !u.disabled }).then(reload, failIn('users-status'))),
      confirmButton('Delete', 'Delete for good?', () => del('/api/admin/users/' + u.id).then(reload, failIn('users-status'))),
    );
    tr.appendChild(td(actions));
    return tr;
  }));
}

// ------------------------------------------------------------------ init
const lists = [
  { name: 'artifacts', status: 'artifacts-status', load: loadArtifacts },
  { name: 'API keys', status: 'keys-status', load: loadKeys },
  { name: 'users', status: 'users-status', load: loadUsers, admin: true },
];
await startApp({
  api,
  keyStore: deps.keyStore,
  toLogin,
  lists,
  setUser(user) {
    me = user;
    $('who').textContent = user.email;
    $('tab-users').hidden = !user.isAdmin;
  },
  listFailed(name, err) {
    status(lists.find((l) => l.name === name)?.status ?? 'app-status', 'Could not load ' + name + ': ' + describeError(err), true);
  },
  fail(err) {
    $('app-status').hidden = false;
    status('app-status', describeError(err), true);
  },
});
