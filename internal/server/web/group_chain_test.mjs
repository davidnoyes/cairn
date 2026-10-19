// Tests for the group record rules of e2e.mjs: verifyGroupChain, checkGroupName,
// and the keyring's groups map. The Go vectors are checked in e2e_test.mjs;
// these build records with the test signing helpers, one broken rule at a
// time. Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { makeUser, rotationRecord } from './viewer_fixture.mjs';

const enc = new TextEncoder();
const dec = new TextDecoder();
const GROUP = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const OTHER_GROUP = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const U = {};
for (const name of ['owner', 'editor', 'viewer', 'outsider', 'manager']) U[name] = await makeUser(name);

const entry = (u, role = 'member') => ({ user: u.id, fp: u.fp, role });
const sorted = (ms) => [...ms].sort((a, b) => (a.user < b.user ? -1 : 1));

// bodyFor is a group body signed by signer's fingerprint, with any key of it
// overridden by over.
function bodyFor(signer, { seq = 1, prev = '', members, over = {} } = {}) {
  return {
    v: 1, group: GROUP, seq, prev, name: 'Team', members: sorted(members ?? [entry(signer, 'manager')]),
    signer: signer.id, signerFp: signer.fp, ...over,
  };
}

// sealBody signs a body as given, with signAs's key, naming envSigner.
function sealBody(body, { signAs, envSigner } = {}) {
  return e2e.newEnvelope((signAs ?? U.owner).ed.seed, envSigner ?? body.signer, 'group', enc.encode(JSON.stringify(body)));
}

// recordFor is a group record signed by signer.
function recordFor(signer, opts = {}) {
  return sealBody(bodyFor(signer, opts), { signAs: opts.signAs ?? signer, envSigner: opts.envSigner });
}

const hashOf = (env) => e2e.bodyHash(e2e.unb64(env.body));

// buildChain signs each step in turn, filling seq and prev from the one before.
async function buildChain(steps) {
  const records = [];
  for (const [i, step] of steps.entries()) {
    const { signer, ...rest } = step;
    records.push(await recordFor(signer, { seq: i + 1, prev: i === 0 ? '' : await hashOf(records[i - 1]), ...rest }));
  }
  return records;
}

const keysOf = (...users) => Object.fromEntries(users.map((u) => [u.fp, { user: u.id, ...u.pair }]));
const ALL = keysOf(...Object.values(U));
const verify = (records, extra = {}) => e2e.verifyGroupChain({ group: GROUP, records, keys: ALL, pin: null, ...extra });
const MGRS = [entry(U.owner, 'manager'), entry(U.editor)];
const refused = (cls, re) => (err) => err instanceof cls && (!re || re.test(err.message));

test('a one-record group verifies, and its head is the hash of the body', async () => {
  const records = await buildChain([{ signer: U.owner }]);
  const got = await verify(records);
  assert.equal(got.seq, 1);
  assert.equal(got.head, await hashOf(records[0]));
  assert.equal(got.latest.name, 'Team');
  assert.equal(got.bodies.length, 1);
});

test('a chain a manager extends by adding, promoting, renaming, and removing verifies', async () => {
  const records = await buildChain([
    { signer: U.owner },
    { signer: U.owner, members: MGRS },
    { signer: U.owner, members: [entry(U.owner, 'manager'), entry(U.editor, 'manager')], over: { name: 'Renamed' } },
    { signer: U.editor, members: [entry(U.editor, 'manager')] },
  ]);
  const got = await verify(records);
  assert.equal(got.seq, 4);
  assert.equal(got.head, await hashOf(records[3]));
  assert.deepEqual(got.latest.members, [entry(U.editor, 'manager')]);
});

test('no records is refused', async () => {
  await assert.rejects(() => verify([]), e2e.ChainError);
  await assert.rejects(() => e2e.verifyGroupChain({ group: GROUP, keys: ALL }), e2e.ChainError);
});

// ---- the first record ----

test('the first record must have seq 1', async () => {
  await assert.rejects(() => recordFor(U.owner, { seq: 2 }).then((r) => verify([r])), refused(e2e.ChainError, /seq 2/));
});

test('the first record must have no prev', async () => {
  await assert.rejects(() => recordFor(U.owner, { prev: 'a'.repeat(64) }).then((r) => verify([r])), refused(e2e.ChainError, /prev/));
});

test('the first record must list its signer as manager, under signerFp', async () => {
  const cases = {
    'not listed': [entry(U.editor, 'manager')],
    'listed as member': [entry(U.owner), entry(U.editor, 'manager')],
    'listed under another fp': [{ user: U.owner.id, fp: U.editor.fp, role: 'manager' }],
    'another user manager under the signer fp': [{ user: U.editor.id, fp: U.owner.fp, role: 'manager' }, entry(U.owner)],
  };
  for (const [what, members] of Object.entries(cases)) {
    await assert.rejects(() => recordFor(U.owner, { members }).then((r) => verify([r])), refused(e2e.ChainError, /signer (as manager|under another fp)/), what);
  }
});

// ---- later records ----

test('a later record must follow the one before by seq', async () => {
  const [first] = await buildChain([{ signer: U.owner }]);
  const gap = await recordFor(U.owner, { seq: 3, prev: await hashOf(first) });
  await assert.rejects(() => verify([first, gap]), refused(e2e.ChainError, /seq 3 follows 1/));
  const again = await recordFor(U.owner, { seq: 1, prev: await hashOf(first) });
  await assert.rejects(() => verify([first, again]), e2e.ChainError);
});

test("a later record's prev must be the hash of the record before", async () => {
  const [first] = await buildChain([{ signer: U.owner }]);
  const wrong = await recordFor(U.owner, { seq: 2, prev: 'b'.repeat(64) });
  await assert.rejects(() => verify([first, wrong]), refused(e2e.ChainError, /prev/));
  const empty = await recordFor(U.owner, { seq: 2, prev: '' });
  await assert.rejects(() => verify([first, empty]), e2e.ChainError);
});

test('a later record must be signed by a manager the record before lists', async () => {
  const member = await buildChain([
    { signer: U.owner, members: MGRS },
    { signer: U.editor, members: [...MGRS, entry(U.viewer)] },
  ]);
  await assert.rejects(() => verify(member), refused(e2e.ChainError, /does not list .* as a manager/));
  const stranger = await buildChain([
    { signer: U.owner },
    { signer: U.outsider, members: [entry(U.outsider, 'manager')] },
  ]);
  await assert.rejects(() => verify(stranger), e2e.ChainError);
});

test('a manager a record adds signs the next record, and not the one that adds them', async () => {
  const both = [entry(U.owner, 'manager'), entry(U.editor, 'manager')];
  const records = await buildChain([
    { signer: U.owner },
    { signer: U.owner, members: both },
    { signer: U.editor, members: [...both, entry(U.viewer)] },
  ]);
  assert.equal((await verify(records)).seq, 3);
  const selfPromote = await buildChain([{ signer: U.owner, members: MGRS }, { signer: U.editor, members: both }]);
  await assert.rejects(() => verify(selfPromote), e2e.ChainError);
});

test('a later record must be signed under the listed fp, or one linked to it', async () => {
  const rotated = await makeUser('owner');
  const records = await buildChain([
    { signer: U.owner },
    { signer: rotated, members: [{ user: U.owner.id, fp: rotated.fp, role: 'manager' }], over: { signer: U.owner.id }, signAs: rotated },
  ]);
  const keys = keysOf(U.owner, rotated);
  await assert.rejects(() => verify(records, { keys }), refused(e2e.ChainError, /signerFp does not follow/));
  const rotation = await rotationRecord(U.owner, rotated);
  const linked = e2e.rotationLinker({ [U.owner.id]: [rotation] });
  assert.equal((await verify(records, { keys, linked })).seq, 2);
  const wrongUser = e2e.rotationLinker({ [U.editor.id]: [rotation] });
  await assert.rejects(() => verify(records, { keys, linked: wrongUser }), e2e.ChainError);
});

test('linked is asked about the manager, the fp the record lists, and the fp that signed', async () => {
  const records = await buildChain([{ signer: U.owner }, { signer: U.owner }]);
  const asked = [];
  await verify(records, { linked: async (...args) => { asked.push(args); return true; } });
  assert.deepEqual(asked, [[U.owner.id, U.owner.fp, U.owner.fp]]);
  await assert.rejects(() => verify(records, { linked: async () => false }), e2e.ChainError);
});

// ---- every record ----

test('every record is for the same group', async () => {
  const wrong = await recordFor(U.owner, { over: { group: OTHER_GROUP } });
  await assert.rejects(() => verify([wrong]), refused(e2e.ChainError, /for group/));
  const [first] = await buildChain([{ signer: U.owner }]);
  const second = await recordFor(U.owner, { seq: 2, prev: await hashOf(first), over: { group: OTHER_GROUP } });
  await assert.rejects(() => verify([first, second]), e2e.ChainError);
});

test('members must be sorted by user ID and unique', async () => {
  const a = entry(U.owner, 'manager');
  const b = entry(U.editor);
  const [lo, hi] = a.user < b.user ? [a, b] : [b, a];
  const unsorted = await sealBody({ ...bodyFor(U.owner), members: [hi, lo] });
  await assert.rejects(() => verify([unsorted]), refused(e2e.ChainError, /sorted/));
  const dup = await sealBody({ ...bodyFor(U.owner), members: [a, a] });
  await assert.rejects(() => verify([dup]), refused(e2e.ChainError, /twice/));
});

test('members are compared by UTF-8 bytes, as Go compares strings', async () => {
  // U+FF5E (EF BD 9E) sorts before U+1F600 (F0 9F 98 80) by bytes, and after it by UTF-16 code units.
  const high = { user: '～', fp: 'a'.repeat(64), role: 'member' };
  const astral = { user: '\u{1f600}', fp: 'b'.repeat(64), role: 'member' };
  const mgr = entry(U.owner, 'manager');
  const good = await sealBody({ ...bodyFor(U.owner), members: [mgr, high, astral] });
  assert.equal((await verify([good])).seq, 1);
  const bad = await sealBody({ ...bodyFor(U.owner), members: [mgr, astral, high] });
  await assert.rejects(() => verify([bad]), e2e.ChainError);
});

test('a group lists 1 to 1000 members', async () => {
  const filler = (n) => Array.from({ length: n }, (_, i) => ({ user: `u-${String(i).padStart(5, '0')}`, fp: 'e'.repeat(64), role: 'member' }));
  const mgr = { user: 'a-manager', fp: U.owner.fp, role: 'manager' };
  const sign = (members) => sealBody({ ...bodyFor(U.owner), members, signer: 'a-manager' });
  const keys = { [U.owner.fp]: { user: 'a-manager', ...U.owner.pair } };
  assert.equal((await verify([await sign([mgr, ...filler(999)])], { keys })).seq, 1);
  await assert.rejects(() => sign([mgr, ...filler(1000)]).then((r) => verify([r], { keys })), refused(e2e.ChainError, /1001 members/));
  await assert.rejects(() => sign([]).then((r) => verify([r], { keys })), refused(e2e.ChainError, /0 members/));
});

test('members that is null is refused', async () => {
  const env = await sealBody({ ...bodyFor(U.owner), members: null });
  await assert.rejects(() => verify([env]), refused(e2e.ChainError, /array/));
});

test('a group keeps at least one manager', async () => {
  const records = await buildChain([
    { signer: U.owner, members: MGRS },
    { signer: U.owner, members: [entry(U.editor), entry(U.viewer)] },
  ]);
  await assert.rejects(() => verify(records), refused(e2e.ChainError, /no manager/));
});

test('a member holds the role member or manager', async () => {
  for (const role of ['owner', 'viewer', 'editor', '', 'Manager']) {
    const r = await recordFor(U.owner, { members: [entry(U.owner, 'manager'), entry(U.editor, role)] });
    await assert.rejects(() => verify([r]), refused(e2e.ChainError, /has role/), JSON.stringify(role));
  }
});

const withName = (name) => recordFor(U.owner, { over: { name } }).then((r) => verify([r]));

test('the name is 1 to 100 code points', async () => {
  assert.equal((await withName('x')).latest.name, 'x');
  assert.equal((await withName('x'.repeat(100))).seq, 1);
  assert.equal((await withName('\u{1f600}'.repeat(100))).seq, 1, 'code points, not UTF-16 units or bytes');
  await assert.rejects(() => withName(''), refused(e2e.ChainError, /code points/));
  await assert.rejects(() => withName('x'.repeat(101)), refused(e2e.ChainError, /code points/));
  await assert.rejects(() => withName('\u{1f600}'.repeat(101)), e2e.ChainError);
});

test('the name has no control character, C0 or C1', async () => {
  for (const c of ['\u0000', '\u0009', '\u000a', '\u001f', '\u007f', '\u0080', '\u0085', '\u009f']) {
    await assert.rejects(() => withName(`a${c}b`), refused(e2e.ChainError, /control/), JSON.stringify(c));
  }
  for (const ok of [' ', '~', '\u00a0', '\u00a1', 'café', '\u2028']) {
    assert.equal((await withName(`a${ok}b`)).seq, 1, JSON.stringify(ok));
  }
});

test('checkGroupName is the name rule on its own', () => {
  e2e.checkGroupName('Design team');
  for (const bad of ['', 'x'.repeat(101), 'a\nb']) assert.throws(() => e2e.checkGroupName(bad), e2e.ChainError, JSON.stringify(bad));
});

// ---- the signature ----

test("the body's signer must be the envelope's signer", async () => {
  const r = await recordFor(U.owner, { envSigner: U.editor.id });
  await assert.rejects(() => verify([r]), refused(e2e.ChainError, /signer/));
});

test('the signature must verify under the key signerFp names', async () => {
  const wrongKey = await recordFor(U.owner, { signAs: U.editor });
  await assert.rejects(() => verify([wrongKey]), e2e.DecryptError);
  const [good] = await buildChain([{ signer: U.owner }]);
  const sig = e2e.unb64(good.sig);
  sig[0] ^= 1;
  await assert.rejects(() => verify([{ ...good, sig: e2e.b64(sig) }]), e2e.DecryptError);
});

test('a signer with no key for signerFp, or a key that does not hash to it, is refused', async () => {
  const records = await buildChain([{ signer: U.owner }]);
  await assert.rejects(() => verify(records, { keys: {} }), refused(e2e.ChainError, /no signer key/));
  await assert.rejects(() => verify(records, { keys: { [U.owner.fp]: { user: U.owner.id, ...U.editor.pair } } }), e2e.ChainError);
});

test('a key signs only for the user it belongs to', async () => {
  const records = await buildChain([{ signer: U.owner }]);
  const mislabelled = { [U.owner.fp]: { user: U.editor.id, ...U.owner.pair } };
  await assert.rejects(
    () => verify(records, { keys: mislabelled }),
    (err) => err instanceof e2e.ChainError && err.rule === 'signer-key-of-another-user',
  );
  const claimsEditor = [await recordFor(U.owner, { over: { signer: U.editor.id }, members: [entry(U.editor, 'manager')] })];
  await assert.rejects(
    () => verify(claimsEditor),
    (err) => err instanceof e2e.ChainError && err.rule === 'signer-key-of-another-user',
  );
});

test('a refusal names its rule', async () => {
  const records = await buildChain([{ signer: U.owner }]);
  await assert.rejects(() => verify(records, { keys: {} }), (err) => err.rule === 'signer-key-missing');
  await assert.rejects(() => verify([]), (err) => err.rule === 'no-records');
  const unnamed = [await recordFor(U.owner, { over: { name: '' } })];
  await assert.rejects(() => verify(unnamed), (err) => err.rule === 'name-empty');
});

test('the body must be a version 1 group body with exactly its keys', async () => {
  const body = bodyFor(U.owner);
  await assert.rejects(() => sealBody({ ...body, v: 2 }).then((r) => verify([r])), e2e.FormatError);
  await assert.rejects(() => sealBody({ ...body, extra: 1 }).then((r) => verify([r])), e2e.FormatError);
  const { signerFp, ...missing } = body;
  assert.ok(signerFp);
  await assert.rejects(() => sealBody(missing).then((r) => verify([r])), e2e.FormatError);
  const extraMemberKey = { ...body, members: [{ ...body.members[0], x: 1 }] };
  await assert.rejects(() => sealBody(extraMemberKey).then((r) => verify([r])), e2e.FormatError);
});

// ---- the keyring's pin ----

test('a pin the chain meets is accepted, and none is first sight', async () => {
  const records = await buildChain([{ signer: U.owner }, { signer: U.owner, members: MGRS }]);
  const head1 = await hashOf(records[0]);
  const head2 = await hashOf(records[1]);
  assert.equal((await verify(records, { pin: { seq: 1, head: head1 } })).head, head2);
  assert.equal((await verify(records, { pin: { seq: 2, head: head2 } })).head, head2);
  for (const none of [null, undefined]) assert.equal((await verify(records, { pin: none })).seq, 2);
});

test('a chain shorter than the pinned seq is a rollback', async () => {
  const records = await buildChain([{ signer: U.owner }]);
  const head = await hashOf(records[0]);
  await assert.rejects(() => verify(records, { pin: { seq: 2, head } }), e2e.RollbackError);
});

test('a chain whose record at the pinned seq has another hash is a fork', async () => {
  const records = await buildChain([{ signer: U.owner }, { signer: U.owner, members: MGRS }]);
  await assert.rejects(() => verify(records, { pin: { seq: 1, head: 'f'.repeat(64) } }), e2e.ForkError);
  const first = await hashOf(records[0]);
  await assert.rejects(() => verify(records, { pin: { seq: 2, head: first } }), e2e.ForkError);
});

test('a malformed pin is a format error', async () => {
  const records = await buildChain([{ signer: U.owner }]);
  const head = await hashOf(records[0]);
  for (const bad of [{ seq: 0, head }, { seq: 1.5, head }, { seq: '1', head }, { seq: 1, head: 7 }, { seq: 1 }, { head }]) {
    await assert.rejects(() => verify(records, { pin: bad }), e2e.FormatError, JSON.stringify(bad));
  }
});

// ---- the keyring's groups map ----

const mkKey = () => e2e.mkSealKey(new Uint8Array(32).fill(9));
const KEYRING_FIELDS = [enc.encode('keyring')];
const plainOf = async (key, sealed) => dec.decode(await e2e.open(key, KEYRING_FIELDS, sealed));

test('a keyring with groups seals and opens, and one without leaves the key out', async () => {
  const key = await mkKey();
  const k = e2e.newKeyring();
  k.rev = 1;
  const plain = await e2e.sealKeyring(key, k);
  assert.ok(!(await plainOf(key, plain)).includes('groups'));
  k.groups = {};
  assert.ok(!(await plainOf(key, await e2e.sealKeyring(key, k))).includes('groups'), 'an empty map is left out');
  k.groups[GROUP] = { seq: 3, head: 'a'.repeat(64) };
  const sealed = await e2e.sealKeyring(key, k);
  assert.ok((await plainOf(key, sealed)).includes(`"groups":{"${GROUP}":{"seq":3,"head":"${'a'.repeat(64)}"}}`));
  const got = await e2e.openKeyring(key, 1, sealed, null);
  assert.deepEqual(got.keyring.groups, { [GROUP]: { seq: 3, head: 'a'.repeat(64) } });
  const none = await e2e.openKeyring(key, 1, plain, null);
  assert.ok(!('groups' in none.keyring), 'a keyring without groups reads as it did before');
});

test('a keyring that spells out an empty or null groups map is refused, as Go refuses it', async () => {
  const key = await mkKey();
  for (const groups of ['{}', 'null']) {
    const sealed = await e2e.seal(key, KEYRING_FIELDS, `{"v":1,"rev":1,"pins":{},"epochs":{},"groups":${groups}}`);
    await assert.rejects(() => e2e.openKeyring(key, 1, sealed, null), e2e.FormatError, groups);
  }
});

test('a malformed groups entry is refused when sealing and when opening', async () => {
  const key = await mkKey();
  const head = 'a'.repeat(64);
  for (const bad of [{ seq: 0, head }, { seq: 1.5, head }, { seq: 1, head: 'A'.repeat(64) }, { seq: 1, head: 'abc' }]) {
    const k = { ...e2e.newKeyring(), groups: { [GROUP]: bad } };
    await assert.rejects(() => e2e.sealKeyring(key, k), e2e.FormatError, JSON.stringify(bad));
    const sealed = await e2e.seal(key, KEYRING_FIELDS, JSON.stringify(k));
    await assert.rejects(() => e2e.openKeyring(key, 0, sealed, null), e2e.FormatError, JSON.stringify(bad));
  }
  await assert.rejects(() => e2e.sealKeyring(key, { ...e2e.newKeyring(), groups: [] }), e2e.FormatError);
  const extra = await e2e.seal(key, KEYRING_FIELDS, JSON.stringify({ ...e2e.newKeyring(), groups: { [GROUP]: { seq: 1, head, x: 1 } } }));
  await assert.rejects(() => e2e.openKeyring(key, 0, extra, null), e2e.FormatError);
});
