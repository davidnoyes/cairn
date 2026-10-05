// Fixtures shared by viewer_test.mjs and shell_page_test.mjs: real users,
// membership chains, wraps, estate copies, keyrings, manifests, and vouches
// built with e2e.mjs, behind a fake fetch that serves them like the server.
import * as e2e from './e2e.mjs';

export const enc = new TextEncoder();
export const ARTIFACT = '11111111-1111-4111-8111-111111111111';
export const OTHER_ARTIFACT = '99999999-9999-4999-8999-999999999999';
export const V1 = '22222222-2222-4222-8222-222222222222';
export const V2 = '55555555-5555-4555-8555-555555555555';
export const ORIGIN = 'http://localhost:8080';

const ids = {
  owner: '33333333-3333-4333-8333-333333333333',
  editor: '44444444-4444-4444-8444-444444444444',
  viewer: '66666666-6666-4666-8666-666666666666',
  outsider: '77777777-7777-4777-8777-777777777777',
};

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// makeUser is a user with fresh X25519 and Ed25519 keys and the fingerprint
// those keys hash to.
export async function makeUser(name) {
  const x = await e2e.generateX25519();
  const ed = await e2e.generateEd25519();
  const user = { name, id: ids[name], x, ed, mk: randomBytes(32), ek: randomBytes(32) };
  user.fp = e2e.toHex(await e2e.fingerprint(x.pub, ed.pub));
  user.pair = { x25519: e2e.b64(x.pub), ed25519: e2e.b64(ed.pub) };
  return user;
}

// keyStoreRecord is what keystore.mjs holds for a signed-in user.
export async function keyStoreRecord(user) {
  return {
    userId: user.id,
    email: `${user.name}@example.com`,
    mk: await e2e.importHKDFKey(user.mk),
    mkSeal: await e2e.mkSealCryptoKey(user.mk),
    ek: await e2e.importHKDFKey(user.ek),
    x25519: await e2e.importX25519PrivateKey(user.x.priv),
    ed25519: await e2e.importEd25519SigningKey(user.ed.seed),
    ed25519Pub: user.ed.pub,
  };
}

export function fakeKeyStore(record) {
  return { load: async () => record };
}

export function fakeStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
  };
}

function membershipBody(o) {
  return enc.encode(JSON.stringify({
    v: 1,
    artifact: ARTIFACT,
    epoch: o.epoch,
    seq: o.seq,
    owner: o.owner.id,
    ownerFp: o.owner.fp,
    akCommit: o.akCommit,
    members: [...o.members].sort((a, b) => (a.user < b.user ? -1 : 1)),
    excluded: [],
    team: 'none',
    public: o.public,
    publicWrites: o.publicWrites ?? false,
    prev: o.prev,
    transfer: '',
    handover: '',
  }));
}

// buildWorld is an artifact with a chain of two records at epoch 1: the
// owner's first, with no members, and a second that lists members (each
// {user, role}, with fp defaulting to the user's) and sets public. epoch2
// adds a third record that starts epoch 2 under a new AK. It also holds each
// epoch's estate copy and every member's wrap.
export async function buildWorld({ owner, members = [], isPublic = false, epoch2 = false, publicWrites = false }) {
  const aks = { 1: randomBytes(32), 2: randomBytes(32) };
  const commits = {
    1: await e2e.akCommit(aks[1], ARTIFACT, 1),
    2: await e2e.akCommit(aks[2], ARTIFACT, 2),
  };
  const listed = members.map((m) => ({ user: m.user.id, role: m.role, fp: m.fp ?? m.user.fp }));
  const specs = [
    { epoch: 1, seq: 1, members: [], public: false },
    { epoch: 1, seq: 2, members: listed, public: isPublic, publicWrites },
  ];
  if (epoch2) specs.push({ epoch: 2, seq: 3, members: listed, public: isPublic, publicWrites });
  const records = [];
  let prev = '';
  for (const s of specs) {
    const body = membershipBody({ ...s, owner, prev, akCommit: commits[s.epoch] });
    records.push(await e2e.newEnvelope(owner.ed.seed, owner.id, 'membership', body));
    prev = await e2e.bodyHash(body);
  }
  const top = specs.at(-1).epoch;
  const estate = [];
  for (let e = 1; e <= top; e++) {
    const ekKey = await e2e.ekSealCryptoKey(owner.ek);
    estate.push({ epoch: e, sealed: e2e.b64(await e2e.seal(ekKey, ['estate', ARTIFACT, String(e)], aks[e])) });
  }
  const wraps = {};
  for (const m of members) {
    wraps[m.user.id] = [];
    for (let e = 1; e <= top; e++) {
      const wrapped = await e2e.wrap({ purpose: 'ak', artifact: ARTIFACT, epoch: e, recipientId: m.user.id, recipientPub: m.user.x.pub }, aks[e]);
      wraps[m.user.id].push({ epoch: e, wrapped: e2e.b64(wrapped), fp: m.user.fp });
    }
  }
  return { owner, aks, commits, records, estate, wraps, members, top, isPublic };
}

// manifestFor seals a manifest for version vid at epoch under the world's
// AK. signer {user, seed} signs it; over lets a test change the signed body.
export async function manifestFor(world, vid, { epoch = 1, signer, over = {} } = {}) {
  const files = [{ path: 'index.html', blob: e2e.toHex(randomBytes(16)), size: 1, sha256: '0'.repeat(64) }];
  const body = enc.encode(JSON.stringify({ v: 1, artifact: ARTIFACT, version: vid, epoch, files, ...over }));
  const env = await e2e.newEnvelope(signer.seed, signer.user, 'manifest', body);
  const blob = await e2e.sealBlob(world.aks[epoch], { artifact: ARTIFACT, version: vid, kind: 'manifest', name: '' }, enc.encode(JSON.stringify(env)));
  return { env, blob, manifestHash: await e2e.bodyHash(body) };
}

// vouchFor is the owner's vouch envelope; over changes the body, and seed or
// signer the key or the signer field.
export async function vouchFor(owner, vid, manifestHash, { over = {}, seed = owner.ed.seed, signer = owner.id, purpose = 'vouch' } = {}) {
  const body = enc.encode(JSON.stringify({ v: 1, artifact: ARTIFACT, version: vid, manifest: manifestHash, ...over }));
  return e2e.newEnvelope(seed, signer, purpose, body);
}

// makeVersion is manifestFor, plus the JSON GET .../versions/{vid} serves.
export async function makeVersion(world, vid, { epoch = 1, signer, over, vouch, seq = 1, hash } = {}) {
  const m = await manifestFor(world, vid, { epoch, signer, over });
  return {
    json: { id: vid, artifactId: ARTIFACT, name: '', seq, epoch, manifestHash: hash ?? m.manifestHash, vouch: vouch ?? null },
    blob: m.blob,
    manifestHash: m.manifestHash,
  };
}

// makeServer is a fake fetch for the routes the viewer calls. Its fields are
// state a test may change; calls logs every request. who is the signed-in
// user, or null; linkTokenB64 is the token a request must carry to read as a
// link holder, or '*' for any token.
export function makeServer(world, { who = null, linkTokenB64 = null, keyring } = {}) {
  const server = {
    world,
    who,
    calls: [],
    putCount: 0,
    conflicts: 0,
    onPut: null,
    keyring: keyring ?? { rev: 0, keyring: '' },
    membershipOverride: null,
    openMembership: false,
    keysOverride: null,
    directory: new Map(),
    notFound: new Set(),
    rotations: {},
    versions: new Map(),
    artifact: { id: ARTIFACT, name: 'Guestbook', description: 'Sign here' },
    tokenExpiresAt: 2000000000,
    isMember: (id) => id === world.owner.id || world.members.some((m) => m.user.id === id),
    // successor is the owner's released successor, whom the server serves
    // the owner's estate copies; successions is GET /api/successions.
    successor: null,
    successions: [],
  };
  for (const u of [world.owner, ...world.members.map((m) => m.user)]) {
    server.directory.set(u.id, { id: u.id, name: u.name, email: `${u.name}@example.com`, x25519Pub: u.pair.x25519, ed25519Pub: u.pair.ed25519 });
  }
  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  server.fetch = async (path, init = {}) => {
    const method = init.method ?? 'GET';
    const headers = init.headers ?? {};
    server.calls.push({ method, path, headers, body: init.body });
    const link = headers['X-Cairn-Link-Token'];
    const linkOk = linkTokenB64 === '*' ? Boolean(link) : linkTokenB64 !== null && link === linkTokenB64;
    const url = new URL(path, ORIGIN);
    const p = url.pathname;
    if (p === '/api/me') {
      return server.who ? json(200, { id: server.who.id, email: `${server.who.name}@example.com`, name: server.who.name }) : json(401, { error: 'unauthorized' });
    }
    if (p === '/api/me/keyring' && method === 'GET') {
      return server.who ? json(200, server.keyring) : json(401, { error: 'unauthorized' });
    }
    if (p === '/api/me/keyring' && method === 'PUT') {
      server.putCount++;
      if (server.onPut) server.onPut();
      if (server.conflicts > 0) {
        server.conflicts--;
        return json(409, { error: 'conflict' });
      }
      const body = JSON.parse(init.body);
      if (body.rev !== server.keyring.rev + 1) return json(409, { error: 'conflict' });
      server.keyring = { rev: body.rev, keyring: body.keyring };
      return json(200, {});
    }
    const m = /^\/api\/artifacts\/([^/]+)(?:\/(.*))?$/.exec(p);
    if (m) {
      if (m[1] !== ARTIFACT) return json(404, { error: 'not found' });
      const rest = m[2] ?? '';
      const heir = server.who && server.successor?.id === server.who.id;
      const member = server.who && (server.isMember(server.who.id) || heir);
      if (rest === 'membership') {
        if (!member && !linkOk && !server.openMembership) return json(404, { error: 'not found' });
        if (server.membershipOverride) return json(200, server.membershipOverride(linkOk && !member));
        const owners = { [world.owner.fp]: world.owner.pair };
        const keys = {};
        for (const mm of world.members) if (mm.role === 'editor') keys[mm.user.id] = mm.user.pair;
        return json(200, {
          records: world.records,
          offers: {},
          owners,
          rotations: server.rotations,
          successors: {},
          ownerChanges: {},
          ...(linkOk && !member ? { keys } : {}),
        });
      }
      if (rest === 'keys') {
        if (!member) return json(404, { error: 'not found' });
        if (server.keysOverride) return json(200, server.keysOverride);
        if (server.who.id === world.owner.id || heir) return json(200, { wraps: [], estate: world.estate });
        return json(200, { wraps: world.wraps[server.who.id] ?? [], estate: [] });
      }
      if (rest === '') {
        return member || linkOk ? json(200, server.artifact) : json(404, { error: 'not found' });
      }
      if (rest === 'versions') {
        if (!member && !linkOk) return json(404, { error: 'not found' });
        return json(200, [...server.versions.values()].map((v) => v.json).sort((a, b) => b.seq - a.seq));
      }
      if (rest === 'content-token' && method === 'POST') {
        if (!server.who) return json(401, { error: 'unauthorized' });
        if (!member && !linkOk) return json(404, { error: 'not found' });
        return json(200, { token: `tok-${server.calls.length}`, expiresAt: server.tokenExpiresAt });
      }
      const v = /^versions\/([^/]+)(\/manifest)?$/.exec(rest);
      if (v) {
        if (!member && !linkOk) return json(404, { error: 'not found' });
        const ver = server.versions.get(v[1]);
        if (!ver) return json(404, { error: 'not found' });
        return v[2] ? new Response(ver.blob, { status: 200, headers: { 'Content-Type': 'application/octet-stream' } }) : json(200, ver.json);
      }
    }
    if (p === '/api/successions') return json(200, server.successions);
    const u = /^\/api\/users\/([^/]+)$/.exec(p);
    if (u) {
      if (!server.who) return json(401, { error: 'unauthorized' });
      if (server.notFound.has(u[1]) || !server.directory.has(u[1])) return json(404, { error: 'user not found' });
      return json(200, server.directory.get(u[1]));
    }
    return json(404, { error: `no route ${method} ${p}` });
  };
  return server;
}

// seedKeyring serves keyring k, sealed under the user's MK, at rev k.rev.
export async function seedKeyring(server, user, k) {
  const sealed = await e2e.sealKeyring(await e2e.mkSealCryptoKey(user.mk), k);
  server.keyring = { rev: k.rev, keyring: e2e.b64(sealed) };
  return sealed;
}

// readServerKeyring opens the keyring the server holds, as the user would.
export async function readServerKeyring(server, user) {
  const { keyring } = await e2e.openKeyring(await e2e.mkSealCryptoKey(user.mk), server.keyring.rev, e2e.unb64(server.keyring.keyring), null);
  return keyring;
}

// rotationRecord is user's rotation from oldKeys to a new X25519 and Ed25519
// pair, signed under both.
export async function rotationRecord(user, newUser, seq = 1) {
  const body = enc.encode(JSON.stringify({ v: 1, user: user.id, seq, old: user.pair, new: newUser.pair }));
  return e2e.signRotation(user.ed.seed, newUser.ed.seed, user.id, body);
}

// succession is owner's entry in heir's GET /api/successions: the signed
// nomination, and once released the owner's EK wrapped to heir. over changes
// the signed body; seed signs with another key.
export async function succession(owner, heir, { released = true, over = {}, seed = owner.ed.seed } = {}) {
  const body = enc.encode(JSON.stringify({ v: 1, seq: 1, user: owner.id, successor: heir.id, successorFp: heir.fp, action: 'nominate', ...over }));
  const wrapped = await e2e.wrap({ purpose: 'ek', artifact: owner.id, epoch: 0, recipientId: heir.id, recipientPub: heir.x.pub }, owner.ek);
  return {
    user: { id: owner.id, name: owner.name, email: `${owner.name}@example.com`, x25519Pub: owner.pair.x25519, ed25519Pub: owner.pair.ed25519 },
    record: await e2e.newEnvelope(seed, owner.id, 'successor', body),
    nominatedAt: '2026-10-01T09:00:00Z',
    requestedAt: '2026-10-01T10:00:00Z',
    releaseAt: '2026-10-15T10:00:00Z',
    released,
    wrapped: released ? e2e.b64(wrapped) : '',
  };
}
