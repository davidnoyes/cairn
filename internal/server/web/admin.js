// admin.js — the admin page. It talks to the JSON APIs and builds every
// element with createElement and textContent: the app CSP's Trusted Types
// rule refuses a string assigned to innerHTML.
import { signOut } from './account.mjs';
import { createKeyStore } from './keystore.mjs';

const $ = (s, el) => (el || document).querySelector(s);
const $$ = (s, el) => [...(el || document).querySelectorAll(s)];

async function api(path, options) {
  const resp = await fetch(path, options);
  if (resp.status === 401) { location.href = '/login?next=/admin'; throw new Error('unauthenticated'); }
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
  return data;
}
const patch = (p, body) => api(p, {method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
const del = (p) => api(p, {method: 'DELETE'});

let flashTimer;
function flash(msg) {
  const el = $('#flash');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => { el.hidden = true; }, 4000);
}
function fail(err) { flash('✗ ' + err.message); }

// Sign out clears the unwrapped keys first, then ends the session. The
// keyring anchor in localStorage stays.
$('#signout').addEventListener('click', async (event) => {
  event.preventDefault();
  try {
    await signOut({ keyStore: createKeyStore(indexedDB) });
  } finally {
    location.href = '/logout';
  }
});

// Tabs
$$('nav button').forEach(btn => btn.addEventListener('click', () => {
  $$('nav button').forEach(b => b.classList.toggle('active', b === btn));
  $$('main section').forEach(s => s.classList.toggle('active', s.id === btn.dataset.tab));
}));

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
  e.addEventListener('click', fn);
  return e;
};
const pill = (label, cls) => el('span', 'pill ' + (cls || ''), label);
function table(headers) {
  const t = document.createElement('table');
  const tr = document.createElement('tr');
  headers.forEach(h => tr.appendChild(el('th', '', h)));
  t.appendChild(tr);
  return t;
}
const empty = (box, text) => box.replaceChildren(el('p', 'empty', text));

// ------------------------------------------------------------- artifacts
async function loadArtifacts() {
  const box = $('#artifactList');
  const artifacts = await api('/api/artifacts');
  if (!artifacts.length) { empty(box, 'No artifacts yet — push one with the CLI.'); return; }
  const t = table(['name', 'id', 'visibility', 'updated', '']);
  for (const a of artifacts) {
    const tr = document.createElement('tr');
    const name = document.createElement('div');
    const link = el('a', '', a.name);
    link.href = '/shared/' + a.id;
    name.appendChild(link);
    if (a.description) name.appendChild(el('div', 'sub', a.description));
    tr.appendChild(td(name));
    tr.appendChild(td(a.id, 'mono'));
    tr.appendChild(td(pill(a.public ? 'public' : 'private', a.public ? 'public' : '')));
    tr.appendChild(td((a.updatedAt || '').slice(0, 10), 'mono'));
    const actions = el('div', 'actions');
    actions.append(
      btn('versions', '', () => toggleVersions(tr, a)),
      btn(a.public ? 'make private' : 'make public', '', async () => {
        try { await patch('/api/artifacts/' + a.id, {public: !a.public}); loadArtifacts(); } catch (e) { fail(e); }
      }),
      btn('delete', 'danger', async () => {
        if (!confirm('Delete artifact "' + a.name + '" and all its versions and data?')) return;
        try { await del('/api/artifacts/' + a.id); flash('artifact deleted'); loadArtifacts(); } catch (e) { fail(e); }
      }),
    );
    tr.appendChild(td(actions));
    t.appendChild(tr);
  }
  box.replaceChildren(t);
}

async function toggleVersions(row, artifact) {
  const existing = row.parentElement.querySelector('tr.versions[data-for="' + artifact.id + '"]');
  if (existing) { existing.remove(); return; }
  const versions = await api('/api/artifacts/' + artifact.id + '/versions');
  const tr = el('tr', 'versions');
  tr.dataset.for = artifact.id;
  const cell = document.createElement('td');
  cell.colSpan = 5;
  if (!versions.length) cell.appendChild(el('span', 'empty', 'no versions'));
  for (const v of versions) {
    const line = el('div', 'mono vline');
    const open = el('a', '', '#' + v.seq);
    open.href = '/shared/' + artifact.id + '/' + v.id;
    line.append(open, document.createTextNode(
      '  ' + v.id + '  ' + (v.name || '—') + '  ' + (v.createdAt || '').slice(0, 16).replace('T', ' ') +
      (v.changelog ? '  · ' + v.changelog : '')));
    line.appendChild(btn('delete', 'danger', async () => {
      if (!confirm('Delete version #' + v.seq + ' and its database?')) return;
      try { await del('/api/artifacts/' + artifact.id + '/versions/' + v.id); tr.remove(); flash('version deleted'); } catch (e) { fail(e); }
    }));
    cell.appendChild(line);
  }
  tr.appendChild(cell);
  row.after(tr);
}

// ----------------------------------------------------------------- users
async function loadUsers() {
  const box = $('#userList');
  const users = await api('/api/admin/users');
  const t = table(['user', 'id', 'status', '']);
  for (const u of users) {
    const tr = document.createElement('tr');
    const who = el('div', '', u.email);
    if (u.name) who.appendChild(el('div', 'sub', u.name));
    tr.appendChild(td(who));
    tr.appendChild(td(u.id, 'mono'));
    const status = el('div', 'status');
    if (u.isAdmin) status.appendChild(pill('admin', 'admin'));
    if (!u.verified) status.appendChild(pill('unverified', ''));
    if (u.disabled) status.appendChild(pill('disabled', 'off'));
    tr.appendChild(td(status));
    const actions = el('div', 'actions');
    actions.append(
      btn(u.isAdmin ? 'revoke admin' : 'make admin', '', async () => {
        try { await patch('/api/admin/users/' + u.id, {isAdmin: !u.isAdmin}); loadUsers(); } catch (e) { fail(e); }
      }),
      btn(u.disabled ? 'enable' : 'disable', '', async () => {
        try { await patch('/api/admin/users/' + u.id, {disabled: !u.disabled}); loadUsers(); } catch (e) { fail(e); }
      }),
      btn('delete', 'danger', async () => {
        if (!confirm('Delete ' + u.email + '?')) return;
        try { await del('/api/admin/users/' + u.id); loadUsers(); } catch (e) { fail(e); }
      }),
    );
    tr.appendChild(td(actions));
    t.appendChild(tr);
  }
  box.replaceChildren(t);
}

// ------------------------------------------------------------------ keys
async function loadKeys() {
  const box = $('#keyList');
  const keys = await api('/api/keys');
  if (!keys.length) { empty(box, 'No API keys yet.'); return; }
  const t = table(['key', 'created', 'last used', 'type', '']);
  for (const k of keys) {
    const tr = document.createElement('tr');
    const label = el('div', '', k.name || '(unnamed)');
    label.appendChild(el('div', 'sub mono', 'cairn_' + k.id + '_…'));
    tr.appendChild(td(label));
    tr.appendChild(td((k.createdAt || '').slice(0, 10), 'mono'));
    tr.appendChild(td((k.lastUsedAt || '').slice(0, 10), 'mono'));
    tr.appendChild(td(pill(k.device ? 'device' : 'key', '')));
    const actions = el('div', 'actions');
    actions.appendChild(btn('revoke', 'danger', async () => {
      if (!confirm('Revoke this key?')) return;
      try { await del('/api/keys/' + k.id); loadKeys(); } catch (e) { fail(e); }
    }));
    tr.appendChild(td(actions));
    t.appendChild(tr);
  }
  box.replaceChildren(t);
}

// ------------------------------------------------------------------ init
try {
  const me = await api('/api/me');
  $('#who').textContent = me.email;
  await Promise.all([loadArtifacts(), loadUsers(), loadKeys()]);
} catch (e) { /* redirected to login */ }
