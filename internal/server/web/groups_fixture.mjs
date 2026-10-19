// Fixtures for groups_test.mjs and groups-tab_test.mjs: a stateful fake of the
// server's group routes, the directory, rotations, and the keyring. It stores
// the group records it is sent and serves them back, so a record the code
// under test wrote is the one its read-back verifies. Keys, records, and
// keyrings are real, built with e2e.mjs.
import * as e2e from './e2e.mjs';
import { ORIGIN, fakeKeyStore, fakeStorage, keyStoreRecord, makeUser } from './viewer_fixture.mjs';

export { keyStoreRecord, makeUser };

const enc = new TextEncoder();
const dec = new TextDecoder();
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

export const emailOf = (u) => `${u.name}@example.com`;

// extraUser is a user the base fixture has no id for.
export async function extraUser(name, id) {
  const u = await makeUser('outsider');
  u.name = name;
  u.id = id;
  return u;
}

const wireUser = (u, role) => ({ id: u.id, name: u.name, email: emailOf(u), role, x25519Pub: u.pair.x25519, ed25519Pub: u.pair.ed25519 });

export const bodyOf = (env) => JSON.parse(dec.decode(e2e.unb64(env.body)));

// groupRecord signs a group body: the members sorted by user, the signer's
// own fingerprint, and over replacing any key of the body.
export function groupRecord(signer, { group, seq = 1, prev = '', name = 'Team', members, over = {} }) {
  const body = {
    v: 1, group, seq, prev, name,
    members: [...(members ?? [{ user: signer.id, fp: signer.fp, role: 'manager' }])].sort((a, b) => (a.user < b.user ? -1 : 1)),
    signer: signer.id, signerFp: signer.fp, ...over,
  };
  return e2e.newEnvelope(signer.ed.seed, body.signer, 'group', enc.encode(JSON.stringify(body)));
}

// makeGroupServer serves the groups with `who` signed in, in a directory of
// users. roles maps a user's name to an account role other than member.
// Fields a test may read or change: groups (id to its records), directory,
// deactivated (the wire users the directory no longer lists), rotations,
// keyring, calls, deleted, failPut (a function returning a Response, or
// null), onKeyringGet. signersOf(records) is the signers a group view serves
// for records: each signer's keys, from the directory or else the deactivated
// accounts, and their rotation records.
export function makeGroupServer({ who, users, roles = {}, isAdmin = false }) {
  const s = {
    who,
    isAdmin,
    calls: [],
    groups: new Map(),
    directory: new Map(users.map((u) => [u.id, wireUser(u, roles[u.name] ?? 'member')])),
    deactivated: new Map(),
    rotations: {},
    keyring: { rev: 0, keyring: '' },
    deleted: [],
    failPut: null,
    onKeyringGet: null,
  };
  const latest = (id) => bodyOf(s.groups.get(id).at(-1));
  s.signersOf = (records) => {
    const out = {};
    for (const env of records) {
      const w = s.directory.get(env.signer) ?? s.deactivated.get(env.signer);
      out[env.signer] = { x25519: w.x25519Pub, ed25519: w.ed25519Pub, rotations: s.rotations[env.signer] ?? [] };
    }
    return out;
  };
  const view = (id, withRecords) => {
    const b = latest(id);
    const mine = b.members.find((m) => m.user === s.who.id);
    const records = s.groups.get(id);
    return { id, name: b.name, seq: b.seq, members: b.members.length, role: mine?.role ?? '', ...(withRecords ? { records, signers: s.signersOf(records) } : {}) };
  };

  s.fetch = async (path, init = {}) => {
    const method = init.method ?? 'GET';
    s.calls.push({ method, path });
    const p = new URL(path, ORIGIN).pathname;
    if (p === '/api/me') return json(200, { id: s.who.id, email: emailOf(s.who), name: s.who.name, role: roles[s.who.name] ?? 'member', isAdmin: s.isAdmin });
    if (p === '/api/me/keyring' && method === 'GET') {
      if (s.onKeyringGet) await s.onKeyringGet();
      return json(200, s.keyring);
    }
    if (p === '/api/me/keyring' && method === 'PUT') {
      const body = JSON.parse(init.body);
      if (body.rev !== s.keyring.rev + 1) return json(409, { error: 'conflict' });
      s.keyring = { rev: body.rev, keyring: body.keyring };
      return json(200, {});
    }
    if (p === '/api/users') return json(200, [...s.directory.values()]);
    const rot = /^\/api\/users\/([^/]+)\/rotations$/.exec(p);
    if (rot) return json(200, { records: s.rotations[rot[1]] ?? [] });
    if (p === '/api/groups' && method === 'GET') return json(200, [...s.groups.keys()].map((id) => view(id, false)));
    if (p === '/api/groups' && method === 'POST') {
      const failed = s.failPut?.('create');
      if (failed) return failed;
      const { record } = JSON.parse(init.body);
      const id = bodyOf(record).group;
      s.groups.set(id, [record]);
      return json(201, view(id, true));
    }
    const g = /^\/api\/groups\/([^/]+)$/.exec(p);
    if (g && s.groups.has(g[1])) {
      const id = g[1];
      if (method === 'GET') return json(200, view(id, true));
      if (method === 'PUT') {
        const failed = s.failPut?.('append');
        if (failed) return failed;
        const { record } = JSON.parse(init.body);
        if (bodyOf(record).seq !== latest(id).seq + 1) return json(409, { error: 'the group changed' });
        s.groups.get(id).push(record);
        return json(200, view(id, true));
      }
      if (method === 'DELETE') {
        s.groups.delete(id);
        s.deleted.push(id);
        return new Response(null, { status: 204 });
      }
    }
    return json(404, { error: `no route ${method} ${p}` });
  };
  return s;
}

// depsFor is what groups.mjs takes, for the user whose key-store record is
// record.
export function depsFor(server, record, extra = {}) {
  return { fetch: server.fetch, keyStore: fakeKeyStore(record), storage: fakeStorage(), origin: ORIGIN, ...extra };
}

// readServerKeyring opens the keyring the server holds, as the user would.
export async function readKeyring(server, user) {
  const { keyring } = await e2e.openKeyring(await e2e.mkSealCryptoKey(user.mk), server.keyring.rev, e2e.unb64(server.keyring.keyring), null);
  return keyring;
}

// seedKeyring serves keyring k, sealed under the user's MK, at rev k.rev.
export async function seedKeyring(server, user, k) {
  const sealed = await e2e.sealKeyring(await e2e.mkSealCryptoKey(user.mk), k);
  server.keyring = { rev: k.rev, keyring: e2e.b64(sealed) };
}
