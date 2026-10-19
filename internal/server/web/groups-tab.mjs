// groups-tab.mjs — the Groups tab of the app page: every group, the caller's
// own first, and one group open at a time with its members. A group's members
// show only from a chain groups.mjs accepted. A manager changes the group
// here, and an administrator deletes any group. Like app.mjs it builds every
// element with createElement and textContent, and never opens a native
// dialog: a destructive action asks again in its own button.
//
// createGroupsTab takes the document and the `deps` groups.mjs takes, and
// finds its elements by id (see the groups section of app.html):
//
//   groups-body, groups-status, group-new-form, group-new-name
//   group-detail, group-title, group-close, group-members, group-status,
//   group-rename-form, group-rename, group-add-form, group-add-email,
//   group-add-role, group-actions, group-accept, group-accept-text,
//   group-accept-confirm, group-accept-cancel
//
// It returns {load({me})}, the entry app-init.mjs's startApp calls.
import { addMember, createGroup, deleteGroup, groupMembers, listGroups, removeMember, renameGroup } from './groups.mjs';
import { KeyChangedError } from './sharing.mjs';
import { describeError } from './ui.mjs';

export function createGroupsTab({ doc, deps }) {
  const $ = (id) => doc.getElementById(id);

  const status = (id, msg, bad = false) => {
    const e = $(id);
    e.textContent = msg;
    e.classList.toggle('bad', bad);
    if (msg) e.scrollIntoView({ block: 'nearest' });
  };
  const failIn = (id) => (err) => status(id, describeError(err), true);

  const el = (tag, cls, text) => {
    const e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  };
  const td = (content, cls) => {
    const e = el('td', cls);
    if (typeof content === 'string') e.textContent = content; else e.appendChild(content);
    return e;
  };
  const btn = (label, cls, fn) => {
    const e = el('button', 'btn ' + (cls || ''), label);
    e.type = 'button';
    e.addEventListener('click', fn);
    return e;
  };
  // confirmButton asks again in the button itself: the first click relabels
  // it, a second within a few seconds runs action.
  const confirmButton = (label, again, action) => {
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
  };

  let me = null;
  // open is the group in the detail panel, or null: {id, name, callerRole}.
  let open = null;

  // ---- the list ----

  const canDelete = (role) => role === 'manager' || Boolean(me?.isAdmin);

  async function load(ctx) {
    me = ctx.me;
    $('group-new-form').hidden = me.role === 'viewer';
    const groups = await listGroups(deps);
    const body = $('groups-body');
    if (groups.length === 0) {
      const cell = td('No groups yet.', 'empty');
      cell.colSpan = 4;
      const tr = el('tr');
      tr.appendChild(cell);
      body.replaceChildren(tr);
    } else {
      body.replaceChildren(...groups.map(groupRow));
    }
  }

  const reload = () => load({ me }).catch(failIn('groups-status'));

  function groupRow(g) {
    const tr = el('tr');
    tr.dataset.id = g.id;
    const actions = el('div', 'actions');
    actions.appendChild(btn('Open', '', () => openGroup(g)));
    if (canDelete(g.role)) {
      actions.appendChild(confirmButton('Delete', 'Delete for good?', () => deleteGroup(deps, g.id)
        .then(() => {
          if (open?.id === g.id) closeGroup();
          status('groups-status', `Deleted ${g.name}.`);
          return reload();
        })
        .catch(failIn('groups-status'))));
    }
    tr.append(td(g.name, 'name'), td(String(g.members), 'count'), td(g.role, 'role'), td(actions));
    return tr;
  }

  $('group-new-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = event.submitter;
    const name = $('group-new-name');
    if (button) button.disabled = true;
    status('groups-status', 'Creating the group…');
    try {
      const made = await createGroup(deps, name.value);
      name.value = '';
      status('groups-status', `Created ${made.name}.`);
      await reload();
      await openGroup({ id: made.id, name: made.name, role: 'manager' });
    } catch (err) {
      failIn('groups-status')(err);
    } finally {
      if (button) button.disabled = false;
    }
  });

  // ---- one group ----

  async function openGroup(g) {
    open = { id: g.id, name: g.name, callerRole: '' };
    $('group-title').textContent = g.name;
    status('group-status', '');
    $('group-accept').hidden = true;
    $('group-detail').hidden = false;
    await act(() => 'Reading the group…', async () => null);
  }

  function closeGroup() {
    open = null;
    $('group-detail').hidden = true;
    $('group-members').replaceChildren();
  }

  $('group-close').addEventListener('click', closeGroup);

  // refreshDetail lists the open group's members from its accepted chain. A
  // chain that is refused shows no members and no controls, and says why.
  async function refreshDetail(s) {
    let res;
    try {
      res = await groupMembers(deps, s.id);
    } catch (err) {
      if (s !== open) return;
      s.callerRole = '';
      $('group-members').replaceChildren();
      showControls(s);
      throw err;
    }
    if (s !== open) return;
    s.name = res.name;
    s.callerRole = res.callerRole;
    $('group-title').textContent = res.name;
    $('group-rename').value = res.name;
    showControls(s);
    $('group-members').replaceChildren(...res.members.map((m) => memberRow(s, m)));
  }

  // showControls offers a manager the forms that change the group, and
  // whoever may delete it the Delete button.
  function showControls(s) {
    const manager = s.callerRole === 'manager';
    $('group-rename-form').hidden = !manager;
    $('group-add-form').hidden = !manager;
    $('group-actions').hidden = !canDelete(s.callerRole);
  }

  const deleteOpen = confirmButton('Delete group', 'Delete for good?', async () => {
    const s = open;
    try {
      await deleteGroup(deps, s.id);
    } catch (err) {
      failIn('group-status')(err);
      return;
    }
    if (s === open) closeGroup();
    status('groups-status', `Deleted ${s.name}.`);
    await reload();
  });
  $('group-actions').appendChild(deleteOpen);

  // act runs one change with the detail's controls disabled, shows what it
  // did, and lists the members again. A member whose keys changed gets the
  // warning first; accepting runs the same change again with acceptNewKey.
  async function act(working, change, retry) {
    const s = open;
    const controls = [...$('group-detail').querySelectorAll('button, input, select')].filter((c) => c.id !== 'group-close');
    for (const c of controls) c.disabled = true;
    status('group-status', working());
    let said = null;
    let failed = null;
    try {
      said = await change();
    } catch (err) {
      failed = err;
    }
    // The person may have closed the group while the change ran, or opened
    // another: the controls and status are that one's now.
    if (s !== open) {
      if (failed) status('groups-status', `A change to ${s.name} did not go through: ${describeError(failed)}`, true);
      if (said !== null) reload();
      return;
    }
    if (failed instanceof KeyChangedError && retry) {
      warnKeyChanged(failed.message, retry);
      status('group-status', '');
    } else if (failed) {
      status('group-status', describeError(failed), true);
    }
    try {
      await refreshDetail(s);
      if (!failed && s === open) status('group-status', said ?? '');
    } catch (err) {
      if (!failed && s === open) {
        const listed = `The group could not be read: ${describeError(err)}`;
        status('group-status', said === null ? listed : `${said} ${listed}`, true);
      }
    } finally {
      if (s === open) for (const c of controls) c.disabled = false;
    }
    if (said !== null) reload();
  }

  let accept = null;
  function warnKeyChanged(message, retry) {
    $('group-accept-text').textContent = message;
    $('group-accept').hidden = false;
    accept = retry;
  }
  $('group-accept-confirm').addEventListener('click', () => {
    $('group-accept').hidden = true;
    const run = accept;
    accept = null;
    if (run) run();
  });
  $('group-accept-cancel').addEventListener('click', () => { $('group-accept').hidden = true; accept = null; });

  function memberRow(s, m) {
    const who = m.email || m.user;
    const tr = el('tr');
    tr.dataset.user = m.user;
    tr.append(td(m.name, 'name'), td(m.email, 'email'), td(m.role, 'role'), td(m.currentFp || m.fp, 'fp mono'), td(m.state, 'pin'));
    const actions = el('div', 'actions');
    if (s.callerRole === 'manager') {
      const role = el('select', 'role');
      role.setAttribute('aria-label', 'Role of ' + who);
      // A viewer account is never a manager, so it is offered member only.
      for (const r of m.account === 'viewer' && m.role === 'member' ? ['member'] : ['member', 'manager']) {
        const o = el('option', '', r);
        o.value = r;
        o.selected = r === m.role;
        role.appendChild(o);
      }
      const setRole = (acceptNewKey) => act(() => 'Changing the role…', async () => {
        const res = await addMember(deps, s.id, who, role.value, { acceptNewKey });
        return `${who} is now ${res.role}.`;
      }, acceptNewKey ? undefined : () => setRole(true));
      role.addEventListener('change', () => setRole(false));
      actions.append(role, btn('Remove', 'danger', () => act(() => 'Removing the member…', async () => {
        await removeMember(deps, s.id, who);
        return `Removed ${who}.`;
      })));
    }
    tr.appendChild(td(actions));
    return tr;
  }

  $('group-rename-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const s = open;
    const name = $('group-rename').value;
    act(() => 'Renaming the group…', async () => {
      await renameGroup(deps, s.id, name);
      return `Renamed the group to ${name}.`;
    });
  });

  $('group-add-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const s = open;
    const email = $('group-add-email');
    const asked = email.value;
    const role = $('group-add-role').value;
    const send = (acceptNewKey) => act(() => 'Adding the member…', async () => {
      const res = await addMember(deps, s.id, asked, role, { acceptNewKey });
      if (s === open) email.value = '';
      return res.unchanged ? `${res.user.email} is already ${role}.` : `Added ${res.user.email} as ${role}.`;
    }, acceptNewKey ? undefined : () => send(true));
    send(false);
  });

  return { load };
}
