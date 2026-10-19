// Tests for groups-tab.mjs against a fake DOM built from the real markup of
// the Groups section of app.html, over the real groups.mjs and a stateful
// fake of the server (groups_fixture.mjs). Run with:
// node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as e2e from './e2e.mjs';
import { createGroupsTab } from './groups-tab.mjs';
import { depsFor, extraUser, groupRecord, keyStoreRecord, makeGroupServer, makeUser, seedKeyring } from './groups_fixture.mjs';

const HTML = readFileSync(new URL('./app.html', import.meta.url), 'utf8');
const SECTION = HTML.slice(HTML.indexOf('<section id="groups"'), HTML.indexOf('</section>', HTML.indexOf('<section id="groups"')) + '</section>'.length);

// ---- a fake DOM: just what groups-tab.mjs touches ----

class FakeEl {
  constructor(tag, attrs = {}) {
    this.tagName = tag;
    this.attrs = { ...attrs };
    this.children = [];
    this.listeners = new Map();
    this.dataset = {};
    this.hidden = 'hidden' in attrs;
    this.disabled = false;
    this.selected = false;
    this.type = attrs.type ?? '';
    this._text = '';
    this._value = attrs.value;
    const classes = new Set((attrs.class ?? '').split(/\s+/).filter(Boolean));
    this.classList = {
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      contains: (c) => classes.has(c),
      toggle: (c, force) => (force ?? !classes.has(c) ? classes.add(c) : classes.delete(c)),
    };
    Object.defineProperty(this, 'className', { get: () => [...classes].join(' '), set: (v) => { classes.clear(); for (const c of v.split(/\s+/).filter(Boolean)) classes.add(c); } });
  }

  get id() { return this.attrs.id ?? ''; }
  get value() {
    if (this._value !== undefined) return this._value;
    if (this.tagName !== 'select') return '';
    return (this.children.find((c) => c.selected) ?? this.children[0])?.value ?? '';
  }
  set value(v) { this._value = v; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this._text = String(v); this.children = []; }
  set innerHTML(_) { throw new Error('innerHTML is refused by Trusted Types'); }
  appendChild(c) { this.children.push(c); return c; }
  append(...cs) { for (const c of cs) this.children.push(c); }
  replaceChildren(...cs) { this._text = ''; this.children = [...cs]; }
  setAttribute(name, value) { this.attrs[name] = String(value); }
  getAttribute(name) { return this.attrs[name] ?? null; }
  addEventListener(type, fn) { (this.listeners.get(type) ?? this.listeners.set(type, []).get(type)).push(fn); }
  scrollIntoView() {}
  descendants() { return this.children.flatMap((c) => [c, ...c.descendants()]); }
  querySelectorAll(selector) {
    const tags = selector.split(',').map((t) => t.trim());
    return this.descendants().filter((d) => tags.includes(d.tagName));
  }
  async fire(type, event = {}) {
    const e = { preventDefault() {}, currentTarget: this, ...event };
    for (const fn of this.listeners.get(type) ?? []) await fn(e);
  }
}

const VOID = new Set(['input', 'br', 'hr', 'img', 'meta', 'link']);

// parseMarkup builds the tree of html, with its attributes and the text of
// each element that holds only text.
function parseMarkup(html) {
  const root = new FakeEl('root');
  const stack = [root];
  const byId = new Map();
  for (const m of html.matchAll(/<(\/)?([a-z0-9]+)([^>]*)>|([^<]+)/g)) {
    const top = stack.at(-1);
    if (m[4] !== undefined) {
      if (m[4].trim() && top.children.length === 0) top._text = m[4].trim();
      continue;
    }
    if (m[1]) {
      stack.pop();
      continue;
    }
    const attrs = {};
    for (const a of m[3].matchAll(/([a-zA-Z-]+)(?:="([^"]*)")?/g)) attrs[a[1]] = a[2] ?? '';
    const node = new FakeEl(m[2], attrs);
    if (node.tagName === 'option') {
      node._value = attrs.value;
    }
    top.children.push(node);
    if (attrs.id) byId.set(attrs.id, node);
    if (!VOID.has(m[2])) stack.push(node);
  }
  return { root, byId };
}

function fakeDocument() {
  const { root, byId } = parseMarkup(SECTION);
  const asked = new Set();
  return {
    root,
    byId,
    asked,
    getElementById(id) {
      asked.add(id);
      const e = byId.get(id);
      if (!e) throw new Error(`no element with id ${id}`);
      return e;
    },
    createElement: (tag) => new FakeEl(tag),
  };
}

// ---- the scene ----

const U = {};
for (const name of ['owner', 'editor', 'viewer', 'outsider', 'manager']) U[name] = await makeUser(name);
U.other = await extraUser('other', '88888888-8888-4888-8888-888888888888');
const records = {};
for (const name of Object.keys(U)) records[name] = await keyStoreRecord(U[name]);
const entry = (u, role = 'member') => ({ user: u.id, fp: u.fp, role });
const GROUP = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

// page is the Groups tab for `who` over a server that holds GROUP, made by
// the owner with the members given, and loaded.
async function page({ who = 'owner', members = [], roles = {}, isAdmin = false, seeded = true } = {}) {
  const server = makeGroupServer({ who: U[who], users: Object.values(U), roles, isAdmin });
  if (seeded) server.groups.set(GROUP, [await groupRecord(U.owner, { group: GROUP, members: [entry(U.owner, 'manager'), ...members] })]);
  const doc = fakeDocument();
  const deps = depsFor(server, records[who]);
  const tab = createGroupsTab({ doc, deps });
  const me = { id: U[who].id, role: roles[who] ?? 'member', isAdmin };
  const p = { server, doc, deps, tab, me, $: (id) => doc.byId.get(id) };
  await tab.load({ me });
  return p;
}

async function until(fn, what, ms = 5000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (fn()) return;
    await new Promise((r) => setTimeout(r, 2));
  }
  assert.fail(`timed out waiting for ${what}`);
}

const text = (e) => e.textContent;
const rowsOf = (p, id) => p.$(id).children;
const cells = (tr) => tr.children.filter((c) => c.tagName === 'td').map(text);
const find = (root, pred) => root.descendants().find(pred);
const button = (root, label) => find(root, (d) => d.tagName === 'button' && d.textContent === label);
const groupRow = (p, id = GROUP) => rowsOf(p, 'groups-body').find((tr) => tr.dataset.id === id);
const memberRowOf = (p, u) => rowsOf(p, 'group-members').find((tr) => tr.dataset.user === u.id);
const submit = (form, submitter) => form.fire('submit', { submitter });
const serverRecords = (p) => p.server.groups.get(GROUP).map((r) => JSON.parse(new TextDecoder().decode(e2e.unb64(r.body))));
const groupStatus = (p) => text(p.$('group-status'));

async function openFirst(p) {
  await button(groupRow(p), 'Open').fire('click');
  await until(() => rowsOf(p, 'group-members').length > 0 || text(p.$('group-status')) !== '', 'the group to open');
}

// press clicks a button twice, as a destructive one asks.
async function press(btn) {
  await btn.fire('click');
  await btn.fire('click');
}

// ---- the markup ----

test('the Groups section is a tab and a panel, and every id the module asks for is in the markup once', async () => {
  const p = await page();
  await openFirst(p);
  const ids = [...SECTION.matchAll(/ id="([^"]+)"/g)].map((m) => m[1]);
  assert.equal(new Set(ids).size, ids.length, 'an id appears twice');
  for (const id of p.doc.asked) assert.ok(ids.includes(id), `${id} is not in the markup`);
  assert.match(HTML, /<button role="tab" id="tab-groups" aria-controls="groups" aria-selected="false">Groups<\/button>/);
  assert.match(SECTION, /^<section id="groups" role="tabpanel" aria-labelledby="tab-groups">/);
});

test('every control of the Groups section has a label, and nothing is inline', () => {
  const doc = fakeDocument();
  for (const c of doc.root.querySelectorAll('input, select')) assert.ok(c.attrs['aria-label'], `${c.id} has no aria-label`);
  assert.doesNotMatch(SECTION, /<script|\sstyle=|\son[a-z]+=/);
  for (const id of ['group-detail', 'group-add-form', 'group-rename-form', 'group-actions', 'group-accept']) {
    assert.equal(doc.byId.get(id).hidden, true, `${id} starts hidden`);
  }
  assert.equal(doc.byId.get('group-add-role').children.map((o) => o.value).join(), 'member,manager');
});

// ---- the list ----

test('the list shows every group, the caller\'s own first, with the caller\'s role', async () => {
  const p = await page({ members: [] });
  p.server.groups.set('b', [await groupRecord(U.editor, { group: 'b', name: 'Alpha' })]);
  p.server.groups.set('c', [await groupRecord(U.editor, { group: 'c', name: 'Beta', members: [entry(U.editor, 'manager'), entry(U.owner)] })]);
  await p.tab.load({ me: p.me });
  const rows = rowsOf(p, 'groups-body');
  assert.deepEqual(rows.map(cells).map((c) => c.slice(0, 3)), [['Beta', '2', 'member'], ['Team', '1', 'manager'], ['Alpha', '1', '']]);
});

test('with no groups the list says so', async () => {
  const p = await page({ seeded: false });
  assert.deepEqual(rowsOf(p, 'groups-body').map(cells), [['No groups yet.']]);
});

test('Delete is offered to a manager and an administrator, and to no one else', async () => {
  const labels = async (opts) => {
    const p = await page(opts);
    return groupRow(p).descendants().filter((d) => d.tagName === 'button').map(text);
  };
  assert.deepEqual(await labels({}), ['Open', 'Delete']);
  assert.deepEqual(await labels({ who: 'editor', members: [entry(U.editor)] }), ['Open']);
  assert.deepEqual(await labels({ who: 'outsider' }), ['Open']);
  assert.deepEqual(await labels({ who: 'outsider', isAdmin: true }), ['Open', 'Delete']);
});

test('New group is not offered to a viewer account', async () => {
  assert.equal((await page()).$('group-new-form').hidden, false);
  assert.equal((await page({ roles: { owner: 'viewer' } })).$('group-new-form').hidden, true);
});

test('deleting from the list asks twice, then lists again without the group', async () => {
  const p = await page();
  const del = button(groupRow(p), 'Delete');
  await del.fire('click');
  assert.equal(text(del), 'Delete for good?');
  assert.deepEqual(p.server.deleted, [], 'one click deletes nothing');
  await del.fire('click');
  await until(() => p.server.deleted.length === 1, 'the delete');
  await until(() => text(p.$('groups-status')) === 'Deleted Team.', 'the status');
  await until(() => rowsOf(p, 'groups-body').map(cells).flat().includes('No groups yet.'), 'the list to reload');
});

test('deleting the open group from the list closes it', async () => {
  const p = await page();
  await openFirst(p);
  await press(button(groupRow(p), 'Delete'));
  await until(() => p.server.deleted.length === 1, 'the delete');
  assert.equal(p.$('group-detail').hidden, true);
});

test('a failed delete says why, and leaves the list', async () => {
  const p = await page();
  const real = p.deps.fetch;
  p.deps.fetch = async (path, init) => (init?.method === 'DELETE' ? new Response(JSON.stringify({ error: 'not allowed' }), { status: 403 }) : real(path, init));
  await press(button(groupRow(p), 'Delete'));
  await until(() => text(p.$('groups-status')) === 'not allowed', 'the error');
  assert.equal(p.$('groups-status').classList.contains('bad'), true);
  assert.ok(groupRow(p));
});

// ---- new group ----

test('New group creates the group, lists it, and opens it with the caller as manager', async () => {
  const p = await page({ seeded: false });
  p.$('group-new-name').value = 'Design';
  await submit(p.$('group-new-form'), button(p.$('group-new-form'), 'New group'));
  await until(() => rowsOf(p, 'group-members').length === 1, 'the group to open');
  assert.equal(p.$('group-new-name').value, '');
  assert.equal(text(p.$('group-title')), 'Design');
  assert.equal(p.$('group-detail').hidden, false);
  assert.deepEqual(cells(rowsOf(p, 'group-members')[0]).slice(0, 5), ['owner', 'owner@example.com', 'manager', U.owner.fp, 'self']);
  assert.deepEqual(rowsOf(p, 'groups-body').map(cells).map((c) => c.slice(0, 3)), [['Design', '1', 'manager']]);
  assert.equal(text(p.$('groups-status')), 'Created Design.');
});

test('New group with a bad name says why and sends nothing', async () => {
  const p = await page({ seeded: false });
  p.$('group-new-name').value = 'a\nb';
  const b = button(p.$('group-new-form'), 'New group');
  await submit(p.$('group-new-form'), b);
  assert.match(text(p.$('groups-status')), /1 to 100 characters/);
  assert.equal(p.$('groups-status').classList.contains('bad'), true);
  assert.equal(b.disabled, false, 'the button works again');
  assert.deepEqual(p.server.calls.filter((c) => c.method === 'POST'), []);
});

// ---- opening ----

test('opening a group lists its members from the accepted chain, and offers a manager the controls', async () => {
  const p = await page({ members: [entry(U.editor)] });
  await openFirst(p);
  assert.equal(text(p.$('group-title')), 'Team');
  const editor = memberRowOf(p, U.editor);
  assert.deepEqual(cells(editor).slice(0, 5), ['editor', 'editor@example.com', 'member', U.editor.fp, 'new']);
  assert.deepEqual(cells(memberRowOf(p, U.owner)).slice(0, 5), ['owner', 'owner@example.com', 'manager', U.owner.fp, 'self']);
  assert.equal(p.$('group-add-form').hidden, false);
  assert.equal(p.$('group-rename-form').hidden, false);
  assert.equal(p.$('group-actions').hidden, false);
  assert.equal(p.$('group-rename').value, 'Team');
  const select = find(editor, (d) => d.tagName === 'select');
  assert.equal(select.attrs['aria-label'], 'Role of editor@example.com');
  assert.deepEqual(select.children.map((o) => [o.value, o.selected]), [['member', true], ['manager', false]]);
  assert.ok(button(editor, 'Remove'));
  const keyring = JSON.parse(new TextDecoder().decode(await e2e.open(await e2e.mkSealCryptoKey(U.owner.mk), [new TextEncoder().encode('keyring')], e2e.unb64(p.server.keyring.keyring))));
  assert.equal(keyring.groups[GROUP].seq, 1, 'the chain was accepted into the keyring');
});

test('a member who is not a manager sees the members and none of the controls', async () => {
  const p = await page({ who: 'editor', members: [entry(U.editor)] });
  await openFirst(p);
  assert.equal(rowsOf(p, 'group-members').length, 2);
  for (const id of ['group-add-form', 'group-rename-form', 'group-actions']) assert.equal(p.$(id).hidden, true, id);
  assert.equal(find(p.$('group-members'), (d) => d.tagName === 'select' || d.tagName === 'button'), undefined);
});

test('an administrator outside the group sees its members and can delete it, and nothing else', async () => {
  const p = await page({ who: 'outsider', isAdmin: true });
  await openFirst(p);
  assert.equal(rowsOf(p, 'group-members').length, 1);
  assert.equal(p.$('group-actions').hidden, false);
  assert.equal(p.$('group-add-form').hidden, true);
  assert.equal(p.$('group-rename-form').hidden, true);
});

test('a group whose chain is refused shows no members, no controls, and the reason', async () => {
  const p = await page({ members: [entry(U.editor)] });
  await openFirst(p);
  p.server.groups.set(GROUP, [await groupRecord(U.owner, { group: GROUP, name: 'Forked' })]);
  await button(groupRow(p), 'Open').fire('click');
  await until(() => rowsOf(p, 'group-members').length === 0 && text(p.$('group-status')) !== '', 'the refusal');
  assert.match(groupStatus(p), /could not be read/);
  assert.equal(p.$('group-status').classList.contains('bad'), true);
  for (const id of ['group-add-form', 'group-rename-form', 'group-actions']) assert.equal(p.$(id).hidden, true, id);
});

test('a group that stops verifying after it was open loses its members and its controls', async () => {
  const p = await page({ members: [entry(U.editor)] });
  await openFirst(p);
  assert.equal(p.$('group-add-form').hidden, false);
  p.server.groups.set(GROUP, [await groupRecord(U.owner, { group: GROUP, name: 'Forked' })]);
  p.$('group-rename').value = 'Other';
  await submit(p.$('group-rename-form'), null);
  await until(() => /group record 1/.test(groupStatus(p)) && rowsOf(p, 'group-members').length === 0, 'the refusal');
  for (const id of ['group-add-form', 'group-rename-form', 'group-actions']) assert.equal(p.$(id).hidden, true, id);
});

test('Close hides the group and clears its members', async () => {
  const p = await page({ members: [entry(U.editor)] });
  await openFirst(p);
  await p.$('group-close').fire('click');
  assert.equal(p.$('group-detail').hidden, true);
  assert.deepEqual(rowsOf(p, 'group-members'), []);
});

// ---- changing ----

test('adding a member by email, as manager, signs a record and lists them', async () => {
  const p = await page();
  await openFirst(p);
  p.$('group-add-email').value = 'editor@example.com';
  p.$('group-add-role').value = 'manager';
  await submit(p.$('group-add-form'), button(p.$('group-add-form'), 'Add member'));
  await until(() => text(p.$('group-status')) === 'Added editor@example.com as manager.', 'the member to be added');
  assert.equal(p.$('group-add-email').value, '');
  assert.equal(serverRecords(p).at(-1).members.find((m) => m.user === U.editor.id).role, 'manager');
  assert.deepEqual(cells(memberRowOf(p, U.editor)).slice(2, 5), ['manager', U.editor.fp, 'unverified']);
  assert.equal(button(p.$('group-detail'), 'Add member').disabled, false, 'the controls work again');
  await until(() => cells(groupRow(p))[1] === '2', 'the list to count them');
});

test('adding someone the directory does not list says so, and keeps what was typed', async () => {
  const p = await page();
  await openFirst(p);
  p.$('group-add-email').value = 'nobody@example.com';
  await submit(p.$('group-add-form'), null);
  await until(() => /No user with that email/.test(groupStatus(p)), 'the refusal');
  assert.equal(p.$('group-add-email').value, 'nobody@example.com');
  assert.equal(serverRecords(p).length, 1);
});

async function pinChanged(p, user) {
  const k = e2e.newKeyring();
  k.pins[user.id] = { fp: 'a'.repeat(64), state: 'verified', rotSeq: 0, rotHead: '' };
  await seedKeyring(p.server, U.owner, k);
}

test('adding someone whose key changed warns first, and Accept adds them', async () => {
  const p = await page();
  await pinChanged(p, U.editor);
  await openFirst(p);
  p.$('group-add-email').value = 'editor@example.com';
  await submit(p.$('group-add-form'), null);
  await until(() => p.$('group-accept').hidden === false, 'the warning');
  assert.match(text(p.$('group-accept-text')), /keys of editor@example.com .* changed/);
  assert.equal(serverRecords(p).length, 1, 'nothing is signed before it is accepted');
  await p.$('group-accept-confirm').fire('click');
  assert.equal(p.$('group-accept').hidden, true);
  await until(() => serverRecords(p).length === 2, 'the record');
  await until(() => text(p.$('group-status')) === 'Added editor@example.com as member.', 'the status');
});

test('Cancel on the key-change warning adds nobody', async () => {
  const p = await page();
  await pinChanged(p, U.editor);
  await openFirst(p);
  p.$('group-add-email').value = 'editor@example.com';
  await submit(p.$('group-add-form'), null);
  await until(() => p.$('group-accept').hidden === false, 'the warning');
  await p.$('group-accept-cancel').fire('click');
  assert.equal(p.$('group-accept').hidden, true);
  await p.$('group-accept-confirm').fire('click');
  assert.equal(serverRecords(p).length, 1);
});

test('changing a role from the select signs a record', async () => {
  const p = await page({ members: [entry(U.editor)] });
  await openFirst(p);
  const select = find(memberRowOf(p, U.editor), (d) => d.tagName === 'select');
  select.value = 'manager';
  await select.fire('change');
  await until(() => text(p.$('group-status')) === 'editor@example.com is now manager.', 'the role change');
  assert.equal(serverRecords(p).at(-1).members.find((m) => m.user === U.editor.id).role, 'manager');
  assert.equal(cells(memberRowOf(p, U.editor))[2], 'manager');
});

test('a viewer account is offered the member role only', async () => {
  const p = await page({ members: [entry(U.viewer)], roles: { viewer: 'viewer' } });
  await openFirst(p);
  const select = find(memberRowOf(p, U.viewer), (d) => d.tagName === 'select');
  assert.deepEqual(select.children.map((o) => o.value), ['member']);
});

test('Remove signs a record without the member', async () => {
  const p = await page({ members: [entry(U.editor)] });
  await openFirst(p);
  await button(memberRowOf(p, U.editor), 'Remove').fire('click');
  await until(() => text(p.$('group-status')) === 'Removed editor@example.com.', 'the removal');
  assert.equal(memberRowOf(p, U.editor), undefined);
  assert.equal(serverRecords(p).at(-1).members.length, 1);
});

test('removing the last manager is refused, with the reason, and the group stays', async () => {
  const p = await page({ members: [entry(U.editor)] });
  await openFirst(p);
  await button(memberRowOf(p, U.owner), 'Remove').fire('click');
  await until(() => /keeps at least one manager/.test(groupStatus(p)), 'the refusal');
  assert.equal(p.$('group-status').classList.contains('bad'), true);
  assert.equal(serverRecords(p).length, 1);
  assert.ok(memberRowOf(p, U.owner));
});

test('Rename signs a record with the new name and shows it', async () => {
  const p = await page();
  await openFirst(p);
  p.$('group-rename').value = 'Renamed';
  await submit(p.$('group-rename-form'), null);
  await until(() => text(p.$('group-status')) === 'Renamed the group to Renamed.', 'the rename');
  assert.equal(text(p.$('group-title')), 'Renamed');
  assert.equal(serverRecords(p).at(-1).name, 'Renamed');
  await until(() => cells(groupRow(p))[0] === 'Renamed', 'the list to show it');
});

test('a record that lost a race says to try again, and the members are read again', async () => {
  const p = await page();
  await openFirst(p);
  p.server.failPut = () => new Response(JSON.stringify({ error: 'the group changed' }), { status: 409 });
  p.$('group-rename').value = 'Late';
  await submit(p.$('group-rename-form'), null);
  await until(() => /try the change again/.test(groupStatus(p)), 'the message');
  assert.equal(p.$('group-status').classList.contains('bad'), true);
  assert.equal(text(p.$('group-title')), 'Team');
});

// ---- deleting ----

test('Delete group asks twice, closes the group, and lists again', async () => {
  const p = await page();
  await openFirst(p);
  const del = button(p.$('group-actions'), 'Delete group');
  await del.fire('click');
  assert.equal(text(del), 'Delete for good?');
  assert.deepEqual(p.server.deleted, []);
  await del.fire('click');
  await until(() => p.server.deleted.length === 1, 'the delete');
  assert.equal(p.$('group-detail').hidden, true);
  await until(() => text(p.$('groups-status')) === 'Deleted Team.', 'the status');
});

test('a change that finishes after the group was closed reports in the list, not the detail', async () => {
  const p = await page();
  await openFirst(p);
  let release;
  const real = p.deps.fetch;
  p.deps.fetch = async (path, init) => {
    if (init?.method === 'PUT' && path.startsWith('/api/groups/')) await new Promise((r) => { release = r; });
    return real(path, init);
  };
  p.$('group-rename').value = 'Slow';
  await submit(p.$('group-rename-form'), null);
  await until(() => release, 'the write to start');
  await p.$('group-close').fire('click');
  release();
  await until(() => p.server.groups.get(GROUP).length === 2, 'the write');
  await until(() => cells(groupRow(p))[0] === 'Slow', 'the list to reload');
  assert.equal(p.$('group-detail').hidden, true);
});

test('a change that fails after the group was closed says so in the list, and leaves the detail alone', async () => {
  const p = await page();
  await openFirst(p);
  let release;
  const real = p.deps.fetch;
  p.deps.fetch = async (path, init) => {
    if (init?.method === 'PUT' && path.startsWith('/api/groups/')) await new Promise((r) => { release = r; });
    return real(path, init);
  };
  p.server.failPut = () => new Response(JSON.stringify({ error: 'not a manager' }), { status: 403 });
  p.$('group-rename').value = 'Slow';
  await submit(p.$('group-rename-form'), null);
  await until(() => release, 'the write to start');
  await p.$('group-close').fire('click');
  release();
  await until(() => text(p.$('groups-status')) === 'A change to Team did not go through: not a manager', 'the message in the list');
  assert.doesNotMatch(groupStatus(p), /not a manager/);
  assert.equal(p.$('group-detail').hidden, true);
});

test('a destructive button that is not confirmed relabels itself back', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const p = await page();
  const del = button(groupRow(p), 'Delete');
  await del.fire('click');
  assert.equal(text(del), 'Delete for good?');
  t.mock.timers.tick(4000);
  assert.equal(text(del), 'Delete');
  assert.equal(del.classList.contains('armed'), false);
});

test('the tab builds its elements with textContent only', async () => {
  const p = await page({ members: [entry(U.editor)] });
  await openFirst(p);
  assert.throws(() => { p.$('group-title').innerHTML = 'x'; }, /Trusted Types/);
  const hostile = await groupRecord(U.owner, { group: GROUP, name: '<img src=x onerror=alert(1)>', members: [entry(U.owner, 'manager')] });
  p.server.groups.set(GROUP, [hostile]);
  await p.tab.load({ me: p.me });
  assert.equal(cells(groupRow(p))[0], '<img src=x onerror=alert(1)>');
});
