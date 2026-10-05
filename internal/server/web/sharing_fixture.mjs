// Fixtures for sharing_test.mjs: a stateful fake of the server routes the
// owner's browser calls to share, unshare, publish and re-seal an artifact.
// It stores what it is sent and serves it back, so a record the code under
// test wrote is the one its read-back verifies. Chains, wraps, estate copies,
// databases, files, versions, and metadata are real, built with e2e.mjs.
import * as e2e from './e2e.mjs';
import { ARTIFACT, ORIGIN, enc, fakeKeyStore, fakeStorage, keyStoreRecord, makeUser } from './viewer_fixture.mjs';

export { ARTIFACT, ORIGIN };

const jsonResponse = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const bytesResponse = (bytes, headers = {}) => new Response(bytes, { status: 200, headers: { 'Content-Type': 'application/octet-stream', ...headers } });

// extraUser is a user the base fixture has no name for, under id.
export async function extraUser(name, id) {
  const u = await makeUser('outsider');
  u.name = name;
  u.id = id;
  return u;
}

const emailOf = (u) => `${u.name}@example.com`;

function wireUser(u) {
  return { id: u.id, name: u.name, email: emailOf(u), x25519Pub: u.pair.x25519, ed25519Pub: u.pair.ed25519 };
}

// makeShareServer serves the world's artifact with `who` signed in. users are
// directory users beyond the owner and the world's members. Fields a test may
// change or read: directory, rotations, owners, keyring, puts (every write the server
// accepted, by kind), failPut (a function (kind) => Response|null that fails
// a write), onKeyringGet.
export function makeShareServer(world, { who, users = [] }) {
  const s = {
    world,
    who,
    calls: [],
    directory: new Map(),
    rotations: {},
    owners: { [world.owner.fp]: world.owner.pair },
    keyring: { rev: 0, keyring: '' },
    onKeyringGet: null,
    failPut: null,
    records: [...world.records],
    estate: [...world.estate],
    wraps: Object.fromEntries(Object.entries(world.wraps).map(([k, v]) => [k, [...v]])),
    artifactMeta: {},
    versions: new Map(),
    dbs: new Map(),
    files: new Map(),
    blobs: new Map(),
    manifests: new Map(),
    puts: { membership: [], meta: [], db: [], file: [], version: [] },
    deleted: [],
  };
  for (const u of [world.owner, ...world.members.map((m) => m.user), ...users]) s.directory.set(u.id, wireUser(u));
  const userById = new Map([[world.owner.id, world.owner], ...world.members.map((m) => [m.user.id, m.user]), ...users.map((u) => [u.id, u])]);

  const formOf = async (init) => init.body;
  const bytesOf = async (blob) => new Uint8Array(await blob.arrayBuffer());

  s.fetch = async (path, init = {}) => {
    const method = init.method ?? 'GET';
    s.calls.push({ method, path });
    const url = new URL(path, ORIGIN);
    const p = url.pathname;
    if (p === '/api/me') return s.who ? jsonResponse(200, { id: s.who.id, email: emailOf(s.who), name: s.who.name }) : jsonResponse(401, { error: 'unauthorized' });
    if (p === '/api/me/keyring' && method === 'GET') {
      if (s.onKeyringGet) await s.onKeyringGet();
      return jsonResponse(200, s.keyring);
    }
    if (p === '/api/me/keyring' && method === 'PUT') {
      const body = JSON.parse(init.body);
      if (body.rev !== s.keyring.rev + 1) return jsonResponse(409, { error: 'conflict' });
      s.keyring = { rev: body.rev, keyring: body.keyring };
      return jsonResponse(200, {});
    }
    if (p === '/api/users') return jsonResponse(200, [...s.directory.values()]);
    const rot = /^\/api\/users\/([^/]+)\/rotations$/.exec(p);
    if (rot) return jsonResponse(200, { records: s.rotations[rot[1]] ?? [] });
    const usr = /^\/api\/users\/([^/]+)$/.exec(p);
    if (usr) return s.directory.has(usr[1]) ? jsonResponse(200, s.directory.get(usr[1])) : jsonResponse(404, { error: 'user not found' });

    const m = /^\/api\/artifacts\/([^/]+)(?:\/(.*))?$/.exec(p);
    if (!m || m[1] !== ARTIFACT) return jsonResponse(404, { error: `no route ${method} ${p}` });
    const rest = m[2] ?? '';
    const fail = (kind) => s.failPut?.(kind) ?? null;

    if (rest === 'membership' && method === 'GET') {
      return jsonResponse(200, { records: s.records, offers: {}, owners: s.owners, rotations: s.rotations, successors: {}, ownerChanges: {} });
    }
    if (rest === 'membership' && method === 'PUT') {
      const failed = fail('membership');
      if (failed) return failed;
      const body = JSON.parse(init.body);
      s.puts.membership.push(body);
      s.records.push(body.membership);
      for (const w of body.wraps) {
        const fp = e2e.toHex(await e2e.fingerprint(e2e.unb64(s.directory.get(w.user).x25519Pub), e2e.unb64(s.directory.get(w.user).ed25519Pub)));
        s.wraps[w.user] = [...(s.wraps[w.user] ?? []).filter((x) => x.epoch !== w.epoch), { epoch: w.epoch, wrapped: w.wrapped, fp }];
      }
      s.estate.push(...body.estate);
      return jsonResponse(200, {});
    }
    if (rest === 'keys') {
      if (s.who.id === world.owner.id) return jsonResponse(200, { wraps: [], estate: s.estate });
      return jsonResponse(200, { wraps: s.wraps[s.who.id] ?? [], estate: [] });
    }
    if (rest === '') return jsonResponse(200, { id: ARTIFACT, meta: s.artifactMeta });
    if (rest === 'versions') return jsonResponse(200, [...s.versions.values()].map((v) => ({ ...v.json, meta: v.meta })));

    const meta = /^(?:versions\/([^/]+)\/)?meta\/([^/]+)$/.exec(rest);
    if (meta && method === 'PUT') {
      const failed = fail('meta');
      if (failed) return failed;
      const body = JSON.parse(init.body);
      const item = { record: body.record, signerKey: e2e.b64(s.who.ed.pub), blob: body.blob };
      s.puts.meta.push({ version: meta[1] ?? '', field: meta[2], item });
      (meta[1] ? s.versions.get(meta[1]).meta : s.artifactMeta)[meta[2]] = item;
      return jsonResponse(200, { ok: true });
    }

    const v = /^versions\/([^/]+)(?:\/(.*))?$/.exec(rest);
    if (v) {
      const vid = v[1];
      const sub = v[2] ?? '';
      if (sub === '' && method === 'PUT') {
        const failed = fail('version');
        if (failed) return failed;
        const form = await formOf(init);
        const blobs = new Map();
        for (const f of form.getAll('blob')) blobs.set(f.name, await bytesOf(f));
        const manifest = await bytesOf(form.get('manifest'));
        const part = JSON.parse(form.get('version'));
        s.puts.version.push({ version: vid, part, blobs, manifest });
        s.blobs.set(vid, blobs);
        s.manifests.set(vid, manifest);
        const old = s.versions.get(vid);
        s.versions.set(vid, { ...old, json: { ...old.json, epoch: part.epoch, manifestHash: part.manifestHash, vouch: null } });
        return jsonResponse(200, {});
      }
      if (sub === '') return s.versions.has(vid) ? jsonResponse(200, s.versions.get(vid).json) : jsonResponse(404, { error: 'not found' });
      if (sub === 'manifest') return bytesResponse(s.manifests.get(vid));
      const blob = /^blobs\/([0-9a-f]{32})$/.exec(sub);
      if (blob) return s.blobs.get(vid)?.has(blob[1]) ? bytesResponse(s.blobs.get(vid).get(blob[1])) : jsonResponse(404, { error: 'not found' });
      if (sub === 'db' && method === 'GET') {
        const d = s.dbs.get(vid);
        if (!d) return jsonResponse(404, { error: 'no database yet' });
        return bytesResponse(d.blob, { 'X-Cairn-Revision': String(d.revision), 'X-Cairn-Epoch': String(d.epoch), 'X-Cairn-Record': e2e.b64(enc.encode(JSON.stringify(d.env))), 'X-Cairn-Signer-Key': d.signerKey });
      }
      if (sub === 'db' && method === 'PUT') {
        const failed = fail('db');
        if (failed) return failed;
        const form = await formOf(init);
        const env = JSON.parse(form.get('record'));
        const body = JSON.parse(new TextDecoder().decode(e2e.unb64(env.body)));
        const d = { revision: body.revision, epoch: body.epoch, blob: await bytesOf(form.get('blob')), env, signerKey: e2e.b64(s.who.ed.pub) };
        s.puts.db.push({ version: vid, ifMatch: init.headers['If-Match'], ...d });
        s.dbs.set(vid, d);
        return jsonResponse(200, { revision: d.revision });
      }
      if (sub === 'files' && method === 'GET') {
        return jsonResponse(200, [...(s.files.get(vid)?.values() ?? [])].map((f) => ({ address: f.address, epoch: f.epoch, size: f.size, record: f.record, meta: e2e.b64(f.meta), metaRecord: f.metaRecord, signerKey: f.signerKey })));
      }
      const file = /^files\/([0-9a-f]{64})$/.exec(sub);
      if (file) {
        const f = s.files.get(vid)?.get(file[1]);
        if (method === 'GET') {
          if (!f) return jsonResponse(404, { error: 'not found' });
          return bytesResponse(f.blob, { 'X-Cairn-Epoch': String(f.epoch), 'X-Cairn-Record': e2e.b64(enc.encode(JSON.stringify(f.record))), 'X-Cairn-Signer-Key': f.signerKey });
        }
        if (method === 'DELETE') {
          s.deleted.push(file[1]);
          if (!f) return jsonResponse(404, { error: 'not found' });
          s.files.get(vid).delete(file[1]);
          return new Response(null, { status: 204 });
        }
        if (method === 'PUT') {
          const failed = fail('file');
          if (failed) return failed;
          const form = await formOf(init);
          const record = JSON.parse(form.get('record'));
          const body = JSON.parse(new TextDecoder().decode(e2e.unb64(record.body)));
          const entry = {
            address: file[1], epoch: body.epoch, record, blob: await bytesOf(form.get('blob')), metaRecord: JSON.parse(form.get('metaRecord')),
            meta: await bytesOf(form.get('meta')), signerKey: e2e.b64(s.who.ed.pub),
          };
          entry.size = entry.blob.length;
          s.puts.file.push({ version: vid, ...entry });
          if (!s.files.has(vid)) s.files.set(vid, new Map());
          s.files.get(vid).set(file[1], entry);
          return jsonResponse(200, {});
        }
      }
    }
    return jsonResponse(404, { error: `no route ${method} ${p}` });
  };
  s.userById = userById;
  return s;
}

// deps is what sharing.mjs takes, for the user whose key-store record is in
// records.
export function depsFor(server, record, extra = {}) {
  return { fetch: server.fetch, keyStore: fakeKeyStore(record), storage: fakeStorage(), origin: ORIGIN, ...extra };
}

export { keyStoreRecord };

const sha256 = (bytes) => e2e.bodyHash(bytes);

// seedDatabase stores the latest revision of version's database: sealed under
// the world's AK of epoch and signed by signer.
export async function seedDatabase(s, { version, revision = 1, epoch = 1, signer = s.world.owner, plain = enc.encode('db') }) {
  const blob = await e2e.sealBlob(s.world.aks[epoch], { artifact: ARTIFACT, version, kind: 'database', name: String(revision) }, plain);
  const body = enc.encode(JSON.stringify({ v: 1, artifact: ARTIFACT, version, revision, epoch, sha256: await sha256(blob) }));
  const env = await e2e.newEnvelope(signer.ed.seed, signer.id, 'revision', body);
  s.dbs.set(version, { revision, epoch, blob, env, signerKey: e2e.b64(signer.ed.pub) });
}

// seedFile stores a file of version at path under epoch, signed by signer.
export async function seedFile(s, { version, path, plain = enc.encode('file'), epoch = 1, signer = s.world.owner }) {
  const ak = s.world.aks[epoch];
  const address = await e2e.fileAddress(await e2e.fileKey(ak, ARTIFACT, epoch), path);
  const ctx = (kind) => ({ artifact: ARTIFACT, version, kind, name: address });
  const blob = await e2e.sealBlob(ak, ctx('file'), plain);
  const meta = await e2e.sealBlob(ak, ctx('file-meta'), enc.encode(JSON.stringify({ v: 1, path, size: plain.length, modifiedAt: '2026-01-01T00:00:00.000Z' })));
  const sign = async (kind, b) => e2e.newEnvelope(signer.ed.seed, signer.id, 'record', enc.encode(JSON.stringify({ v: 1, artifact: ARTIFACT, version, kind, name: address, epoch, sha256: await sha256(b) })));
  const entry = { address, epoch, size: plain.length, record: await sign('file', blob), blob, metaRecord: await sign('file-meta', meta), meta, signerKey: e2e.b64(signer.ed.pub) };
  if (!s.files.has(version)) s.files.set(version, new Map());
  s.files.get(version).set(address, entry);
  return address;
}

// seedVersion stores a version with real content blobs and a manifest signed by
// signer. over changes the signed manifest body, and badBlob the stored bytes of
// the named path's blob.
export async function seedVersion(s, { id, seq = 1, epoch = 1, signer = s.world.owner, files = { 'index.html': '<p>hi</p>' }, vouch = null, badBlob = null }) {
  const ak = s.world.aks[epoch];
  const blobs = new Map();
  const entries = [];
  for (const [path, text] of Object.entries(files)) {
    const blobId = e2e.toHex(crypto.getRandomValues(new Uint8Array(16)));
    const plain = enc.encode(text);
    const blob = await e2e.sealBlob(ak, { artifact: ARTIFACT, version: id, kind: 'content', name: path }, plain);
    entries.push({ path, blob: blobId, size: plain.length, sha256: await sha256(blob) });
    blobs.set(blobId, badBlob === path ? await e2e.sealBlob(ak, { artifact: ARTIFACT, version: id, kind: 'content', name: path }, enc.encode('tampered')) : blob);
  }
  const body = enc.encode(JSON.stringify({ v: 1, artifact: ARTIFACT, version: id, epoch, files: entries }));
  const env = await e2e.newEnvelope(signer.ed.seed, signer.id, 'manifest', body);
  const manifest = await e2e.sealBlob(ak, { artifact: ARTIFACT, version: id, kind: 'manifest', name: '' }, enc.encode(JSON.stringify(env)));
  s.blobs.set(id, blobs);
  s.manifests.set(id, manifest);
  s.versions.set(id, { json: { id, artifactId: ARTIFACT, name: '', seq, epoch, manifestHash: await sha256(body), vouch }, meta: {} });
}

// metaItem is a meta item as the server serves it: value sealed under the
// world's AK of epoch, signed by signer.
export async function metaItem(s, { version = '', field, value, epoch = 1, signer = s.world.owner }) {
  const blob = await e2e.sealBlob(s.world.aks[epoch], { artifact: ARTIFACT, version, kind: 'meta', name: field }, enc.encode(value));
  const body = enc.encode(JSON.stringify({ v: 1, artifact: ARTIFACT, version, kind: 'meta', name: field, epoch, sha256: await sha256(blob) }));
  return { record: await e2e.newEnvelope(signer.ed.seed, signer.id, 'record', body), signerKey: e2e.b64(signer.ed.pub), blob: e2e.b64(blob) };
}

export async function seedMeta(s, { version = '', field, value, epoch = 1, signer = s.world.owner }) {
  const item = await metaItem(s, { version, field, value, epoch, signer });
  (version ? s.versions.get(version).meta : s.artifactMeta)[field] = item;
}
