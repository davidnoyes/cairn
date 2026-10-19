// app.mjs — the signed-in home page: artifacts, API keys, account settings,
// and users for an administrator. It talks to the JSON APIs and builds every
// element with createElement and textContent: the app CSP's Trusted Types
// rule refuses a string assigned to innerHTML. It never opens a native
// dialog: a destructive action asks again in its own button.
import { changePassword, createApiKey, enrollPasskey, listPasskeys, newRecoveryCode, passkeysAvailable, removePasskey, signOut } from './account.mjs';
import { UnauthenticatedError, startApp } from './app-init.mjs';
import { createGroupsTab } from './groups-tab.mjs';
import { FolderError, breadcrumb, childrenOf, createFolder, deleteTree, makeDraggable, makeDropTarget, moveItem, moveTargets, renameFolder, subtree } from './folders.mjs';
import { listGroups, verifiedGroup } from './groups.mjs';
import { describeArtifact } from './meta.mjs';
import { GroupKeyChangedError, KeyChangedError, approvableCount, approve, canShare, memberControls, members, pin, publicLinkFor, setPublic, setTeam, share, shareGroup, unshare, unshareGroup, waiting } from './sharing.mjs';
import { bannerView, myCode, nominate, refuse, remove, requestAccess, setNoticeEmail, status as successorStatus, successions, who } from './successor.mjs';
import { confirmRecoveryCode, describeError, describePasskeyError, pageDeps, watchStrength } from './ui.mjs';

const $ = (id) => document.getElementById(id);
// viewer.mjs and sharing.mjs also need the keyring anchor's storage and the
// origin a public link names.
const deps = { ...pageDeps(), storage: localStorage, origin: location.origin };
const toLogin = () => { location.href = '/login?next=/app'; };

async function api(path, options) {
  const resp = await fetch(path, options);
  if (resp.status === 401) { toLogin(); throw new UnauthenticatedError(); }
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw Object.assign(new Error(data.error || ('HTTP ' + resp.status)), { status: resp.status });
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
  // A message can sit below the fold of a long tab; bring it into view.
  if (msg) el.scrollIntoView({ block: 'nearest' });
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
// minute shows a time in the browser's own zone, as 2006-01-02 15:04.
const minute = (ts) => {
  if (!ts) return '';
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
};
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
      b.textContent = typeof again === 'function' ? again() : again;
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
// The arrow keys, Home, and End move between the tabs a user can see, and
// select the one they land on.
const moves = { ArrowLeft: -1, ArrowRight: 1 };
for (const t of tabs) {
  t.addEventListener('click', () => {
    selectTab(t);
    if (me) refreshBanners();
  });
  t.addEventListener('keydown', (event) => {
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    const shown = tabs.filter((x) => !x.hidden);
    const i = shown.indexOf(t);
    const to = event.key === 'Home' ? shown[0]
      : event.key === 'End' ? shown[shown.length - 1]
      : Object.hasOwn(moves, event.key) ? shown[(i + moves[event.key] + shown.length) % shown.length]
      : null;
    if (!to) return;
    event.preventDefault();
    to.focus();
    to.click();
  });
}
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
// Your own items show as a tree, one folder at a time: own is every item of
// the caller's, as {id, kind, parent, name} for folders.mjs, ownRows the table
// row of each, and viewFolder the folder in view (null for the top level).
// Shared with you stays flat.
let own = [];
let ownRows = new Map();
let viewFolder = null;

// The server holds each name and description sealed, so a row shows the
// artifact's ID until its own keys open them.
async function listArtifacts({ me }) {
  const list = await api('/api/artifacts');
  const rows = new Map(list.map((a) => [a.id, artifactRow(a, a.owner === me.id)]));
  const mine = list.filter((a) => a.owner === me.id);
  ownRows = new Map(mine.map((a) => [a.id, rows.get(a.id)]));
  own = mine.map((a) => ({ id: a.id, kind: a.kind ?? 'artifact', parent: a.parent ?? null, name: a.id }));
  const ownItem = new Map(own.map((i) => [i.id, i]));
  renderOwn();
  const trs = list.filter((a) => a.owner !== me.id).map((a) => rows.get(a.id).tr);
  if (trs.length === 0) emptyRow($('shared'), 6, 'Nothing is shared with you yet.'); else $('shared').replaceChildren(...trs);
  // One at a time: opening an artifact for the first time pins its owner in
  // the keyring, and each pin is a write at the keyring's next revision.
  for (const a of list) {
    const row = rows.get(a.id);
    const got = await describeArtifact(deps, a);
    row.name = got.name;
    row.nameText.textContent = got.name;
    row.descText.textContent = got.description;
    if (ownItem.has(a.id)) ownItem.get(a.id).name = got.name;
    // Said in the row, not only in a tooltip, so a keyboard or screen reader
    // user learns why the row shows an ID.
    row.reasonText.textContent = got.error ? describeError(got.error) : '';
    // The share dialog may have opened on this row before its name was read.
    if (sharing?.id === a.id) {
      sharing.name = got.name;
      $('share-title').textContent = got.name;
    }
    // How many newcomers the caller can approve, where they may: one request
    // each, in turn, like the names.
    if (!row.folder && APPROVERS.includes(a.access)) await showWaiting(row);
  }
  // Names sort the tree, so it is laid out again once they are all read.
  renderOwn();
}

// One load at a time: two loads opening the same artifact for the first time
// would both pin its owner at the keyring's next revision.
// While any load is queued or running, both lists are marked busy, so
// assistive technology, and a test, knows the rows may still be replaced.
let artifactsLoad = Promise.resolve();
let artifactsLoading = 0;
function setArtifactsBusy(busy) {
  for (const id of ['own', 'shared']) {
    if (busy) $(id).setAttribute('aria-busy', 'true'); else $(id).removeAttribute('aria-busy');
  }
}
function loadArtifacts(ctx) {
  artifactsLoading++;
  setArtifactsBusy(true);
  const run = artifactsLoad.then(() => listArtifacts(ctx));
  artifactsLoad = run.catch(() => {}).finally(() => {
    artifactsLoading--;
    if (artifactsLoading === 0) setArtifactsBusy(false);
  });
  return run;
}

// APPROVERS are the access levels that may approve people the artifact is
// shared with through Everyone or a group.
const APPROVERS = ['owner', 'manager', 'editor'];

// showWaiting marks a row with the newcomers waiting for the caller to approve,
// and gives an editor, who has no Share, a button for them. It is a hint: a
// failed request marks nothing.
async function showWaiting(row) {
  let n = 0;
  try {
    n = await approvableCount(deps, row.id);
  } catch (err) {
    if (err instanceof UnauthenticatedError) return;
  }
  // No text while nobody waits, so the row's cells read as they did.
  row.waitingPill.textContent = n === 0 ? '' : `${n} waiting for approval`;
  row.waitingPill.hidden = n === 0;
  if (row.approveButton) row.approveButton.hidden = n === 0;
}

function artifactRow(a, mine) {
  const folder = a.kind === 'folder';
  const row = { id: a.id, folder, name: a.id, nameText: el(folder ? 'button' : 'a', 'clamp', a.id), descText: el('div', 'clamp', ''), actions: el('div', 'actions') };
  row.waitingPill = pill('', 'waiting');
  row.waitingPill.hidden = true;
  const tr = el('tr');
  tr.dataset.id = a.id;
  if (folder) {
    // Opening a folder shows what is in it; its own address has nothing to show.
    row.nameText.type = 'button';
    row.nameText.classList.add('link');
    row.nameText.addEventListener('click', () => openFolder(a.id));
    tr.addEventListener('click', (event) => {
      if (!event.target.closest('button, a, input, select, form')) openFolder(a.id);
    });
  } else {
    row.nameText.href = '/shared/' + a.id;
  }
  row.reasonText = el('div', 'unreadable', '');
  const nameCell = td(row.nameText, 'name');
  if (folder) nameCell.prepend(pill('folder'), ' ');
  nameCell.append(row.reasonText);
  tr.append(
    nameCell,
    td(row.descText, 'desc'),
    td(a.access, 'access'),
    td(a.public ? 'public' : 'private', 'public'),
    td(minute(a.updatedAt), 'mono updated'),
  );
  if (mine) {
    makeDraggable(tr, a.id);
    if (folder) makeDropTarget(tr, a.id, moveTo);
  } else if (a.access === 'manager') {
    // A manager shares too, and the dialog verifies they are one.
    row.actions.append(btn('Share', '', () => openShare(a.id, row.name)));
  } else if (a.access === 'editor') {
    // An editor approves the people waiting, and changes nothing else.
    row.approveButton = btn('Approve', '', () => openShare(a.id, row.name, { approveOnly: true }));
    row.approveButton.hidden = true;
    row.actions.append(row.approveButton);
  }
  // The pill sits in the actions cell, not the name cell: fillOwnActions
  // replaces what is in row.actions, and the name cell is the row's name.
  const actionsCell = td(row.actions);
  actionsCell.prepend(row.waitingPill);
  tr.appendChild(actionsCell);
  row.tr = tr;
  return row;
}

const reloadArtifacts = () => loadArtifacts({ me }).catch(failIn('artifacts-status'));

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// renderOwn lays out the folder in view: its breadcrumb, and its items as
// rows, folders first. A folder in view that is gone shows the top level.
function renderOwn() {
  if (viewFolder !== null && !own.some((i) => i.id === viewFolder && i.kind === 'folder')) viewFolder = null;
  renderCrumbs();
  const kids = childrenOf(own, viewFolder);
  if (kids.length === 0) {
    emptyRow($('own'), 6, viewFolder === null ? 'No artifacts yet.' : 'This folder is empty.');
    return;
  }
  $('own').replaceChildren(...kids.map((i) => {
    const row = ownRows.get(i.id);
    if (!row.filled) {
      fillOwnActions(row);
      row.filled = true;
    }
    return row.tr;
  }));
}

function openFolder(id) {
  viewFolder = id;
  renderOwn();
}

// renderCrumbs shows Top, then each folder down to the one in view. Each
// segment but the last opens that folder, and takes a dropped row.
function renderCrumbs() {
  const segs = breadcrumb(own, viewFolder);
  const nodes = [];
  segs.forEach((s, i) => {
    if (i > 0) nodes.push(el('span', 'sep', '›'));
    if (i === segs.length - 1) {
      const here = el('span', '', s.name);
      here.setAttribute('aria-current', 'page');
      nodes.push(here);
      return;
    }
    const b = btn(s.name, '', () => openFolder(s.id));
    makeDropTarget(b, s.id, moveTo);
    nodes.push(b);
  });
  $('crumbs').replaceChildren(...nodes);
}

// fillOwnActions sets the buttons of one own row, once per load: laying the
// tree out again keeps them, so a Delete armed while names are still being
// read stays armed. A folder's Delete counts what it removes when clicked.
function fillOwnActions(row) {
  const { id } = row;
  const actions = [];
  // A folder is private in this release, so it has no Share.
  if (row.folder) actions.push(btn('Rename', '', () => startRename(row)));
  else actions.push(btn('Share', '', () => openShare(id, row.name)));
  actions.push(moveButton(row));
  if (row.folder) {
    const again = () => {
      const t = subtree(own, id);
      return `Delete ${plural(t.folders.length, 'folder', 'folders')} and ${plural(t.artifacts.length, 'artifact', 'artifacts')}?`;
    };
    actions.push(confirmButton('Delete', again, () => removeFolder(id)));
  } else {
    actions.push(confirmButton('Delete', 'Delete for good?', () => del('/api/artifacts/' + id)
      .then(() => { status('artifacts-status', 'Artifact deleted.'); return reloadArtifacts(); })
      .catch(failIn('artifacts-status'))));
  }
  row.actions.replaceChildren(...actions);
}

// moveButton is Move to…, which turns into a select of the places the item
// may go: the top level and each folder that is not the item or inside it.
function moveButton(row) {
  const b = btn('Move to…', '', () => {
    const select = el('select');
    select.setAttribute('aria-label', 'Move ' + row.name + ' to');
    const prompt = el('option', '', 'Move to…');
    prompt.value = '';
    prompt.disabled = true;
    prompt.selected = true;
    select.appendChild(prompt);
    for (const t of moveTargets(own, row.id)) {
      const o = el('option', '', t.label);
      o.value = t.id ?? 'top';
      select.appendChild(o);
    }
    select.addEventListener('change', () => moveTo(row.id, select.value === 'top' ? null : select.value));
    select.addEventListener('blur', () => select.replaceWith(b));
    select.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') { select.replaceWith(b); b.focus(); }
    });
    b.replaceWith(select);
    select.focus();
  });
  return b;
}

async function moveTo(id, target) {
  try {
    if (await moveItem(send, own, id, target)) {
      status('artifacts-status', 'Moved.');
      await reloadArtifacts();
    }
  } catch (err) {
    failIn('artifacts-status')(err);
  }
}

// startRename swaps a folder's name for a field holding it.
function startRename(row) {
  const form = el('form', 'rename');
  const input = el('input');
  input.value = row.name;
  input.setAttribute('aria-label', 'New name of ' + row.name);
  input.autocomplete = 'off';
  const save = btn('Save', '', () => {});
  save.type = 'submit';
  const cancel = btn('Cancel', '', () => { form.replaceWith(row.nameText); row.nameText.focus(); });
  form.append(input, save, cancel);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      await renameFolder(deps, row.id, input.value);
      status('artifacts-status', 'Folder renamed.');
      await reloadArtifacts();
    } catch (err) {
      failIn('artifacts-status')(err);
      save.disabled = false;
    }
  });
  row.nameText.replaceWith(form);
  input.focus();
  input.select();
}

// removeFolder deletes what is in a folder, then the folder, and shows how far
// it got. A failure stops it with the rest in place: deleting again finishes.
async function removeFolder(id) {
  try {
    await deleteTree((x) => del('/api/artifacts/' + x), own, id, (done, total) => status('artifacts-status', `Deleting… ${done} of ${total}.`));
    status('artifacts-status', 'Folder deleted.');
  } catch (err) {
    failIn('artifacts-status')(err);
  }
  await reloadArtifacts();
}

$('folder-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = $('folder-name');
  const button = $('folder-form').querySelector('button');
  button.disabled = true;
  try {
    await createFolder(deps, { name: name.value, parent: viewFolder });
    name.value = '';
    status('artifacts-status', 'Folder created.');
    await reloadArtifacts();
  } catch (err) {
    failIn('artifacts-status')(err);
    // The folder exists even though its name did not write: clear the name so
    // a retry does not make a second one.
    if (err instanceof FolderError && err.created) {
      name.value = '';
      await reloadArtifacts();
    }
  } finally {
    button.disabled = false;
  }
});

// ----------------------------------------------------------------- share
// The dialog works on one artifact at a time. The public link carries the
// artifact's key, so it lives only in this variable until the owner copies it.
let sharing = null;

// openShare opens the dialog on an artifact. approveOnly is the editor's: the
// waiting newcomers and Approve, and nothing else.
async function openShare(id, name, { approveOnly = false } = {}) {
  sharing = { id, name, link: null, changed: false, approveOnly, callerRole: '', hasGroups: false, verifiedGroup: null };
  $('share-group-check').textContent = '';
  $('share-title').textContent = name;
  status('share-status', '');
  $('accept-warning').hidden = true;
  $('approve-only-note').hidden = !approveOnly;
  for (const part of ['share-members-list', 'share-form', 'share-public']) $(part).hidden = approveOnly;
  $('waiting-section').hidden = true;
  $('waiting').replaceChildren();
  $('share-kind').value = 'user';
  syncShareForm();
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
  if ((failed instanceof KeyChangedError || failed instanceof GroupKeyChangedError) && retry) {
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
      syncShareSubmit();
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

// syncShareForm shows the field the kind of share needs, and the roles it may
// take: only the owner makes a manager, and only of a person.
function syncShareForm() {
  const kind = $('share-kind').value;
  $('share-email').hidden = kind !== 'user';
  $('share-group').hidden = kind !== 'group';
  const manager = $('share-role').querySelector('option[value=manager]');
  manager.hidden = manager.disabled = kind !== 'user' || sharing?.callerRole !== 'owner';
  if (manager.disabled && $('share-role').value === 'manager') $('share-role').value = 'viewer';
  $('share-group-check').hidden = kind !== 'group' || $('share-group-check').textContent === '';
  syncShareSubmit();
}

// syncShareSubmit keeps Share off for a group until the group chosen verified.
function syncShareSubmit() {
  $('share-submit').disabled = !canShare($('share-kind').value, sharing?.verifiedGroup ?? null, $('share-group').value);
}

// checkChosenGroup verifies the group chosen in the share form and shows its
// verified name and member count beside it: the list the server serves names
// groups by its own word. Share stays off until it verifies; a group that does
// not says so and stays off.
async function checkChosenGroup(s) {
  const id = $('share-group').value;
  const hint = $('share-group-check');
  s.verifiedGroup = null;
  hint.textContent = id ? 'Verifying the group…' : '';
  hint.hidden = !id;
  syncShareSubmit();
  if (!id) return;
  let text;
  let ok = false;
  try {
    const g = await verifiedGroup(deps, id);
    text = `Verified: ${g.name}, ${plural(g.members, 'member', 'members')}.`;
    ok = true;
  } catch (err) {
    if (err instanceof UnauthenticatedError) return;
    text = `This group could not be verified, so it cannot be shared: ${describeError(err)}`;
    // A signer's changed key is accepted where the group is shown in full.
    if (err instanceof KeyChangedError) text += ' Open the group on the Groups tab to review the change.';
  }
  if (s !== sharing || $('share-group').value !== id) return;
  if (ok) s.verifiedGroup = id;
  hint.textContent = text;
  syncShareSubmit();
}

async function listMembers(s) {
  if (!s.approveOnly) {
    const res = await members(deps, s.id);
    if (s !== sharing) return;
    $('public').checked = res.public;
    $('public-writes').checked = res.publicWrites;
    s.callerRole = res.callerRole;
    s.hasGroups = res.groups.length > 0;
    syncShareForm();
    $('members').replaceChildren(...res.members.map((m) => memberRow(s, m)), ...res.groups.map((g) => groupRow(s, g)), ...(res.team === 'none' ? [] : [everyoneRow(s, res.team)]));
  }
  await listWaiting(s);
}

// listWaiting shows the newcomers waiting for approval, and the users who left
// every group but still hold the key. An owner or manager sees both, an editor
// the newcomers. The section is left out when nobody could be waiting.
async function listWaiting(s) {
  const w = await waiting(deps, s.id);
  if (s !== sharing) return;
  const rows = [...w.newcomers.map((n) => waitingRow(s, n)), ...w.left.map((l) => leftRow(s, l))];
  $('waiting-section').hidden = !w.canApprove || (rows.length === 0 && !s.approveOnly && w.team === 'none' && !s.hasGroups);
  if (rows.length === 0) emptyRow($('waiting'), 6, 'Nobody is waiting for approval.'); else $('waiting').replaceChildren(...rows);
}

// waitingRow is a newcomer: Approve checks them and gives them the keys.
function waitingRow(s, n) {
  const tr = el('tr');
  tr.dataset.email = n.email;
  tr.dataset.state = 'new';
  const heldBy = [...(n.everyone ? ['Everyone'] : []), ...n.groups.map((g) => g.name || g.id)].join(', ');
  tr.append(td(n.name, 'name'), td(n.email, 'email'), td(n.fp, 'fp mono'), td(heldBy, 'held'), td('waiting', 'pin'));
  const approveUser = (acceptNewKey) => act(() => 'Approving…', async () => {
    await approve(deps, s.id, n.user, { acceptNewKey });
    return `Approved ${n.email}.`;
  }, acceptNewKey ? undefined : () => approveUser(true));
  const actions = el('div', 'actions');
  actions.appendChild(btn('Approve', '', () => approveUser(false)));
  tr.appendChild(td(actions));
  return tr;
}

// leftRow is a user who left every group they were held by, and still holds
// the key until a new epoch: Remove starts one that excludes them.
function leftRow(s, l) {
  const tr = el('tr');
  tr.dataset.email = l.email;
  tr.dataset.state = 'left';
  tr.append(td(l.name, 'name'), td(l.email, 'email'), td(l.fp, 'fp mono'), td('', 'held'), td('left the group, still holds the key', 'pin'));
  const actions = el('div', 'actions');
  actions.appendChild(btn('Remove', 'danger', () => act(() => 'Removing the user and re-sealing…', async () => {
    const res = await unshare(deps, s.id, l.user);
    return `Removed ${l.email}.` + epochNote(res);
  })));
  tr.appendChild(td(actions));
  return tr;
}

// roleSelect is the role of a group or Everyone, which is viewer or editor.
function roleSelect(label, current, change) {
  const role = el('select', 'role');
  role.setAttribute('aria-label', label);
  for (const r of ['viewer', 'editor']) {
    const o = el('option', '', r);
    o.value = r;
    o.selected = r === current;
    role.appendChild(o);
  }
  role.addEventListener('change', () => change(role.value));
  return role;
}

// groupRow is a group the artifact is shared with. A deleted group has no
// name, and grants nothing: Remove drops it from the list.
function groupRow(s, g) {
  const label = g.deleted ? g.id : g.name;
  const tr = el('tr');
  tr.dataset.group = g.id;
  const name = td(g.deleted ? '(deleted group)' : g.name, 'name');
  name.append(' ', pill('group'));
  const roleCell = td(g.role, 'role');
  if (!g.deleted) {
    const setRole = (role, acceptSignerKey) => act(() => 'Changing the role…', async () => {
      const res = await shareGroup(deps, s.id, g.id, role, { acceptSignerKey });
      return `${g.name} is now shared as ${role}.` + groupNote(res) + epochNote(res);
    }, acceptSignerKey ? undefined : () => setRole(role, true));
    roleCell.replaceChildren(roleSelect('Role of group ' + label, g.role, (role) => setRole(role, false)));
  }
  tr.append(name, td(g.deleted ? g.id : '', 'email mono'), roleCell, td('', 'fp mono'), td('', 'pin'));
  const actions = el('div', 'actions');
  actions.appendChild(btn('Remove', 'danger', () => act(() => 'Removing the group…', async () => {
    const res = await unshareGroup(deps, s.id, g.id);
    return `Removed the group ${g.deleted ? g.id : g.name}.` + epochNote(res);
  })));
  tr.appendChild(td(actions));
  return tr;
}

// everyoneRow is the team share, which gives every user a way in once someone
// approves them.
function everyoneRow(s, team) {
  const tr = el('tr');
  tr.dataset.everyone = 'true';
  const name = td('Everyone', 'name');
  name.append(' ', pill('team'));
  const setRole = (role) => act(() => 'Changing the role…', async () => {
    const res = await setTeam(deps, s.id, role);
    return `Everyone is now ${role}.` + epochNote(res);
  });
  tr.append(name, td('', 'email'), td(roleSelect('Role of Everyone', team, setRole), 'role'), td('', 'fp mono'), td('', 'pin'));
  const actions = el('div', 'actions');
  actions.appendChild(btn('Remove', 'danger', () => act(() => 'Removing Everyone…', async () => {
    const res = await setTeam(deps, s.id, 'none');
    return 'Everyone no longer has a way in.' + epochNote(res);
  })));
  tr.appendChild(td(actions));
  return tr;
}

// groupNote says whom sharing with a group approved, and who still waits and why.
function groupNote(res) {
  let note = '';
  if (res.approved.length > 0) note += ` Approved ${plural(res.approved.length, 'person', 'people')}: ${res.approved.map((u) => u.email).join(', ')}.`;
  if (res.pending.length > 0) note += ` ${res.pending.length} waiting: ${res.pending.map((p) => `${p.user.email} (${describeError(p.error)})`).join('; ')}.`;
  return note;
}

function memberRow(s, m) {
  const who = m.email || m.user;
  const tr = el('tr');
  tr.dataset.email = m.email;
  const roleCell = td(m.role, 'role');
  if (m.account === 'viewer') roleCell.appendChild(pill('viewer account'));
  tr.append(
    td(m.name, 'name'),
    td(m.email, 'email'),
    roleCell,
    td(m.currentFp || m.fp, 'fp mono'),
    td(m.state, 'pin'),
  );
  const actions = el('div', 'actions');
  const { roles, removable } = memberControls(s.callerRole, m);
  if (m.role !== 'owner') {
    const role = el('select', 'role');
    role.setAttribute('aria-label', 'Role of ' + who);
    for (const r of roles) {
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
    // A manager's entry is the owner's to change: a manager sees it, with no
    // select, no Make viewer, no Accept new key, and no Remove.
    if (roles.length > 0) actions.appendChild(role);
    if (roles.length > 0 && m.account === 'viewer' && (m.role === 'editor' || m.role === 'manager')) {
      // Their account became a viewer account, so the entry promises writes
      // the server refuses. Offer to make it match.
      actions.appendChild(btn('Make viewer', '', () => {
        role.value = 'viewer';
        setRole(false);
      }));
    }
    if (m.state === 'changed' && roles.length > 0) {
      // share with the same role lists their new keys; without acceptNewKey
      // it refuses, and the refusal is the warning.
      const acceptKey = (acceptNewKey) => act(() => 'Checking the new key…', async () => {
        const res = await share(deps, s.id, who, m.role, { acceptNewKey });
        return `Accepted the new key of ${who}.` + epochNote(res);
      }, acceptNewKey ? undefined : () => acceptKey(true));
      actions.appendChild(btn('Accept new key', 'danger', () => acceptKey(false)));
    } else if (m.state !== 'changed' && m.state !== 'verified' && m.state !== '-' && m.state !== 'conflict') {
      actions.appendChild(btn('Verify', '', () => act(() => 'Marking the key verified…', async () => {
        await pin(deps, who, { verified: true });
        return `Marked the key of ${who} verified.`;
      })));
    }
    if (removable) actions.appendChild(btn('Remove', 'danger', () => act(() => 'Removing the member and re-sealing…', async () => {
      const res = await unshare(deps, s.id, who);
      return `Removed ${who}.` + epochNote(res);
    })));
  }
  tr.appendChild(td(actions));
  return tr;
}

// epochNote says what a change did beyond what the caller reports: which
// approved people the record listed or left out, which deleted groups it
// dropped, who it excluded besides the user removed, and, for a new epoch, what
// it re-sealed and what it left alone and why.
function epochNote(res) {
  let note = '';
  if (res.listed?.length > 0) note += ` Listed ${plural(res.listed.length, 'approved person', 'approved people')}: ${res.listed.map((u) => u.email).join(', ')}.`;
  if (res.unlisted?.length > 0) note += ` Not listed, because their approval does not check out: ${res.unlisted.map((x) => `${x.user.email} (${describeError(x.error)})`).join('; ')}.`;
  if (res.droppedGroups?.length > 0) note += ` Dropped ${plural(res.droppedGroups.length, 'deleted group', 'deleted groups')}: ${res.droppedGroups.join(', ')}.`;
  const others = (res.excluded ?? []).filter((x) => x.reason !== 'removed');
  if (others.length > 0) note += ` Excluded: ${others.map((x) => `${x.user.email || x.user.id} (${x.reason})`).join('; ')}.`;
  if (!res.reseal) return note;
  const { resealed = [], skipped = [], error } = res.reseal;
  note += ` Started key epoch ${res.epoch}; re-sealed ${resealed.length} item${resealed.length === 1 ? '' : 's'}.`;
  if (skipped.length > 0) note += ' Left alone: ' + skipped.map((x) => `${x.what} (${x.reason})`).join('; ') + '.';
  if (error) note += ' Re-sealing stopped: ' + describeError(error) + ' Run cairn reseal to finish.';
  return note;
}

// loadGroupOptions lists the groups the server holds, by name. Two groups of
// one name tell apart by the start of their IDs. Sharing verifies the group.
async function loadGroupOptions(s) {
  let groups;
  try {
    groups = await listGroups(deps);
  } catch (err) {
    failIn('share-status')(err);
    return;
  }
  if (s !== sharing) return;
  const options = groups.map((g) => {
    const o = el('option', '', groups.filter((x) => x.name === g.name).length > 1 ? `${g.name} (${g.id.slice(0, 8)})` : g.name);
    o.value = g.id;
    return o;
  });
  if (options.length === 0) {
    const none = el('option', '', 'No groups yet');
    none.value = '';
    none.disabled = true;
    options.push(none);
  }
  $('share-group').replaceChildren(...options);
  checkChosenGroup(s);
}

$('share-group').addEventListener('change', () => checkChosenGroup(sharing));

$('share-kind').addEventListener('change', () => {
  syncShareForm();
  if ($('share-kind').value === 'group') loadGroupOptions(sharing);
});

$('share-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const email = $('share-email');
  const s = sharing;
  const kind = $('share-kind').value;
  const role = $('share-role').value;
  if (kind === 'everyone') {
    act(() => 'Sharing with Everyone…', async () => {
      const res = await setTeam(deps, s.id, role);
      return (res.unchanged ? `Everyone is already ${role}.` : `Shared with Everyone as ${role}: anyone who is waiting can be approved.`) + epochNote(res);
    });
    return;
  }
  if (kind === 'group') {
    const group = $('share-group').value;
    if (!group) { status('share-status', 'Choose a group.', true); return; }
    if (!canShare(kind, s.verifiedGroup, group)) { status('share-status', 'The group has not been verified.', true); return; }
    const sendGroup = (acceptSignerKey) => act(() => 'Sharing with the group…', async () => {
      const res = await shareGroup(deps, s.id, group, role, { acceptSignerKey });
      const name = res.group.name;
      return (res.unchanged ? `The group ${name} is already shared as ${role}.` : `Shared with the group ${name} as ${role}.`) + groupNote(res) + epochNote(res);
    }, acceptSignerKey ? undefined : () => sendGroup(true));
    sendGroup(false);
    return;
  }
  const send = (acceptNewKey) => act(() => 'Sharing…', async () => {
    const res = await share(deps, s.id, email.value, role, { acceptNewKey });
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
  $('waiting').replaceChildren();
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

// -------------------------------------------------------------- passkeys
// loadPasskeys shows the section only on a server where a passkey can sign
// in: one with a public URL.
async function loadPasskeys() {
  if (!(await passkeysAvailable(deps))) return;
  $('passkey-section').hidden = false;
  const passkeys = await listPasskeys(deps);
  $('passkeys').replaceChildren(...passkeys.map((p) => {
    const tr = el('tr');
    tr.dataset.passkey = p.id;
    tr.append(td(p.name || '(unnamed)', 'name'), td(day(p.createdAt), 'mono'), td(day(p.lastUsedAt), 'mono'));
    const actions = el('div', 'actions');
    actions.appendChild(confirmButton('Remove', 'Remove this passkey?', () => removePasskey(deps, p.id)
      .then(() => { status('passkeys-status', 'Passkey removed. Delete it from your password manager too.'); return loadPasskeys(); })
      .catch(failIn('passkeys-status'))));
    tr.appendChild(td(actions));
    return tr;
  }));
}

$('passkey-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  const password = $('passkey-password');
  if (!deps.credentials || !globalThis.PublicKeyCredential) {
    status('passkeys-status', 'This browser cannot use passkeys.', true);
    return;
  }
  button.disabled = true;
  status('passkeys-status', 'Adding the passkey…');
  try {
    await enrollPasskey(deps, { name: $('passkey-name').value, password: password.value });
    $('passkey-name').value = '';
    status('passkeys-status', 'Passkey added. You can sign in with it next time.');
    await loadPasskeys();
  } catch (err) {
    status('passkeys-status', describePasskeyError(err), true);
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
  status('account-status', 'Making a new recovery code…');
  // While a new code waits to be saved, the form stays off: another would
  // replace it unseen.
  let showing = false;
  try {
    const { recoveryCode } = await newRecoveryCode(deps, { password: password.value });
    status('account-status', 'Save the new recovery code now: it is not shown again, and the old one no longer works.');
    confirmRecoveryCode($('rc-panel'), recoveryCode, () => {
      password.disabled = false;
      button.disabled = false;
      password.focus();
      status('account-status', 'New recovery code saved.');
    });
    showing = true; // only once the panel is up, or nothing could turn the form back on
    password.disabled = true;
  } catch (err) {
    failIn('account-status')(err);
  } finally {
    password.value = '';
    button.disabled = showing;
  }
});

// ------------------------------------------------------------- successor
// showBanners shows what me says about a successor's request, on every tab.
function showBanners() {
  const viewerAccount = me?.role === 'viewer';
  $('viewer-note').hidden = !viewerAccount;
  $('create-hint').hidden = viewerAccount;
  $('folder-form').hidden = viewerAccount;
  const v = bannerView(me);
  $('succession-banner').hidden = !v.banner;
  $('refuse-succession').hidden = !v.refuse;
  $('rotate-banner').hidden = !v.rotate;
  $('succession-text').textContent = v.text;
}

// bannerGen counts the changes to me's request, so a reread that started
// before a later change does not undo it.
let bannerGen = 0;

// refreshBanners rereads me, so a request made, refused or released since the
// page loaded shows. It keeps what it had when the read fails.
async function refreshBanners() {
  const gen = ++bannerGen;
  const fresh = await api('/api/me').catch(() => null);
  if (fresh && gen === bannerGen) me = fresh;
  showBanners();
}

$('refuse-succession').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await refuse(deps);
  } catch (err) {
    failIn('app-status')(err);
    $('app-status').hidden = false;
    // The banner may be stale: another device refused, or the request was
    // released. Show what the server holds now.
    await refreshBanners();
    return;
  } finally {
    button.disabled = false;
  }
  bannerGen++;
  me.succession = null;
  showBanners();
  $('app-status').hidden = false;
  status('app-status', 'You refused the request. Your successor stays named, and was told.');
  await refreshSuccessor().catch(failIn('successor-status'));
});

const removeSuccessor = confirmButton('Remove successor', 'Remove for good?', () => remove(deps)
  .then((u) => { status('successor-status', `${u.email} is no longer your successor.`); return refreshSuccessor(); })
  .catch(failIn('successor-status')));
removeSuccessor.id = 'remove-successor';
removeSuccessor.hidden = true;
$('successor-actions').appendChild(removeSuccessor);

async function loadSuccessor({ keys }) {
  $('my-code').textContent = await myCode(keys);
  await refreshSuccessor();
}

async function refreshSuccessor() {
  const [mine, named] = await Promise.all([successorStatus(deps), successions(deps)]);
  removeSuccessor.hidden = !mine.successor;
  $('current-successor').textContent = mine.successor ? `Your successor is ${who(mine.successor)}.` : 'You have not named a successor.';
  const released = named.filter((n) => n.released);
  const artifacts = released.length > 0 ? await api('/api/artifacts') : [];
  const body = $('successions');
  if (named.length === 0) { emptyRow(body, 3, 'Nobody has named you.'); return; }
  body.replaceChildren(...named.map((n) => successionRow(n, artifacts.filter((a) => a.access === 'successor' && a.owner === n.user.id))));
}

function successionRow(n, owned) {
  const tr = el('tr');
  tr.dataset.user = n.user.id;
  const person = el('div', 'name', n.user.name || n.user.email);
  person.appendChild(el('div', 'sub', n.user.email));
  if (n.released) {
    const links = el('div', 'sub');
    for (const a of owned) {
      const link = el('a', 'mono', a.id);
      link.href = '/shared/' + a.id;
      links.append(link, el('br'));
    }
    person.appendChild(links);
  }
  const state = n.released ? 'released' : n.requestedAt ? `requested, released on ${day(n.releaseAt)}` : 'named';
  const actions = el('div', 'actions');
  if (!n.requestedAt) {
    actions.appendChild(btn('Request access', '', () => requestAccess(deps, n.user.id)
      .then((r) => { status('successor-status', `Asked for access to the artifacts ${n.user.email} owns. They were told, and can refuse. Access starts on ${day(r.releaseAt)} unless they do.`); return refreshSuccessor(); })
      .catch(failIn('successor-status'))));
  }
  tr.append(td(person), td(state), td(actions));
  return tr;
}

$('nominate-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  const password = $('nominate-password');
  button.disabled = true;
  status('successor-status', 'Naming the successor…');
  try {
    const { user } = await nominate(deps, { who: $('nominate-user').value, code: $('nominate-code').value, password: password.value });
    $('nominate-user').value = '';
    $('nominate-code').value = '';
    status('successor-status', `${user.email} is your successor. They can read your artifacts 14 days after they ask, unless you refuse.`);
    await refreshSuccessor();
  } catch (err) {
    failIn('successor-status')(err);
  } finally {
    password.value = '';
    button.disabled = false;
  }
});

$('notice-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  try {
    const address = $('notice-email').value.trim();
    const pending = await setNoticeEmail(deps, address);
    status('successor-status', address === '' ? 'Cleared your notice address.' : pending ? `Check ${address} for a link that verifies it. Notices go there once you follow it.` : `Notices go to ${address}.`);
  } catch (err) {
    failIn('successor-status')(err);
  } finally {
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
    const accountRole = u.role ?? (u.isAdmin ? 'admin' : 'member');
    if (accountRole === 'admin') flags.appendChild(pill('admin', 'admin'));
    if (accountRole === 'viewer') flags.appendChild(pill('viewer account'));
    if (!u.verified) flags.appendChild(pill('unverified'));
    if (u.disabled) flags.appendChild(pill('disabled', 'off'));
    tr.appendChild(td(flags));
    const actions = el('div', 'actions');
    const role = el('select', 'role');
    role.setAttribute('aria-label', 'Account of ' + u.email);
    for (const [value, label] of [['admin', 'administrator'], ['member', 'member'], ['viewer', 'viewer account']]) {
      const o = el('option', '', label);
      o.value = value;
      o.selected = value === accountRole;
      role.appendChild(o);
    }
    // The server refuses an administrator removing their own role, so the
    // page does not offer it.
    if (u.id === me?.id) {
      role.disabled = true;
      role.title = 'You cannot change your own account role.';
    }
    role.addEventListener('change', () => send('PATCH', '/api/admin/users/' + u.id, { role: role.value }).then(reload, (err) => {
      role.value = accountRole;
      failIn('users-status')(err);
    }));
    actions.append(
      role,
      btn(u.disabled ? 'Enable' : 'Disable', '', () => send('PATCH', '/api/admin/users/' + u.id, { disabled: !u.disabled }).then(reload, failIn('users-status'))),
      confirmButton('Delete', 'Delete for good?', () => del('/api/admin/users/' + u.id).then(reload, failIn('users-status'))),
    );
    tr.appendChild(td(actions));
    return tr;
  }));
}

// ---------------------------------------------------------------- groups
const groupsTab = createGroupsTab({ doc: document, deps });

// ------------------------------------------------------------------ init
const lists = [
  { name: 'artifacts', status: 'artifacts-status', load: loadArtifacts },
  { name: 'groups', status: 'groups-status', load: (ctx) => groupsTab.load(ctx) },
  { name: 'API keys', status: 'keys-status', load: loadKeys },
  { name: 'passkeys', status: 'passkeys-status', load: loadPasskeys },
  { name: 'successor', status: 'successor-status', load: loadSuccessor },
  { name: 'users', status: 'users-status', load: loadUsers, admin: true },
];
await startApp({
  api,
  keyStore: deps.keyStore,
  toLogin,
  lists,
  setUser(user) {
    me = user;
    showBanners();
    $('who').textContent = user.email;
    $('tab-admin').hidden = !user.isAdmin;
  },
  listFailed(name, err) {
    status(lists.find((l) => l.name === name)?.status ?? 'app-status', 'Could not load ' + name + ': ' + describeError(err), true);
  },
  fail(err) {
    $('app-status').hidden = false;
    status('app-status', describeError(err), true);
  },
});
