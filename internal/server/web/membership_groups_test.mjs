// Tests that verifyChain refuses a membership record whose groups is null or
// not an array, as Go's DecodeStrict does, and still accepts one with none or
// with groups listed. Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { ARTIFACT, makeUser } from './viewer_fixture.mjs';

const enc = new TextEncoder();
const owner = await makeUser('owner');
const GROUP = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

// firstRecord is the owner's first record, with groups as given: undefined
// leaves the key out, as a record that lists none does.
async function firstRecord(groups) {
  const body = {
    v: 1, artifact: ARTIFACT, epoch: 1, seq: 1, owner: owner.id, ownerFp: owner.fp, akCommit: 'a'.repeat(64),
    members: [], excluded: [], team: 'none', public: false, publicWrites: false, prev: '', transfer: '', handover: '',
  };
  if (groups !== undefined) body.groups = groups;
  return e2e.newEnvelope(owner.ed.seed, owner.id, 'membership', enc.encode(JSON.stringify(body)));
}

const verify = (record) => e2e.verifyChain({
  artifact: ARTIFACT, records: [record], owners: { [owner.fp]: owner.pair }, offers: {}, successors: {}, anchor: owner.fp,
  currentOwnerFp: '', pin: null, linked: e2e.rotationLinker({}),
});

test('a record with no groups key, or a sorted list of them, verifies', async () => {
  assert.deepEqual((await verify(await firstRecord())).latest.groups ?? [], []);
  const chain = await verify(await firstRecord([{ group: GROUP, role: 'viewer' }]));
  assert.deepEqual(chain.latest.groups, [{ group: GROUP, role: 'viewer' }]);
});

test('a record whose groups is null or not an array is refused', async () => {
  for (const groups of [null, {}, 'viewer', 7, true, [], [null], [[]], ['x']]) {
    await assert.rejects(async () => verify(await firstRecord(groups)), e2e.FormatError, JSON.stringify(groups));
  }
});
