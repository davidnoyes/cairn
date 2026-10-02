// Tests for keystore.mjs against a minimal fake IndexedDB: one database, one
// object store, and requests and transactions that complete asynchronously.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createKeyStore, wrapX25519 } from './keystore.mjs';
import * as e2e from './e2e.mjs';

// fakeIndexedDB drops any put whose value drop(value) accepts, as WebKit does
// for a record holding an X25519 CryptoKey: the transaction still completes.
function fakeIndexedDB(drop = () => false) {
  const dbs = new Map(); // name -> {stores: Map(name -> Map)}
  return {
    dbs,
    open(name, version) {
      const req = {};
      queueMicrotask(() => {
        let data = dbs.get(name);
        const fresh = !data;
        if (fresh) dbs.set(name, (data = { version, stores: new Map() }));
        const db = {
          createObjectStore: (store) => data.stores.set(store, new Map()),
          transaction(storeName) {
            const tx = {
              objectStore() {
                const map = data.stores.get(storeName);
                const request = (fn) => {
                  const r = {};
                  queueMicrotask(() => { r.result = fn(); queueMicrotask(() => tx.oncomplete()); });
                  return r;
                };
                return {
                  put: (value, key) => request(() => { if (!drop(value)) map.set(key, value); return key; }),
                  get: (key) => request(() => map.get(key)),
                  clear: () => request(() => { map.clear(); }),
                };
              },
            };
            return tx;
          },
        };
        req.result = db;
        if (fresh) req.onupgradeneeded();
        req.onsuccess();
      });
      return req;
    },
  };
}

test('save then load returns the record, and clear empties it', async () => {
  const idb = fakeIndexedDB();
  const store = createKeyStore(idb);
  const record = { userId: 'u1', mk: { fake: 'CryptoKey' } };
  await store.save(record);
  assert.equal(await store.load(), record);
  await store.clear();
  assert.equal(await store.load(), undefined);
  assert.equal(idb.dbs.get('cairn-keys').stores.get('keys').size, 0);
});

test('a second store on the same database sees the saved record', async () => {
  const idb = fakeIndexedDB();
  await createKeyStore(idb).save({ userId: 'u1' });
  assert.deepEqual(await createKeyStore(idb).load(), { userId: 'u1' });
});

// cryptoKeysIn lists every CryptoKey reachable from value.
function cryptoKeysIn(value) {
  if (value instanceof CryptoKey) return [value];
  if (value === null || typeof value !== 'object' || ArrayBuffer.isView(value)) return [];
  return Object.values(value).flatMap(cryptoKeysIn);
}

test('the X25519 key is stored wrapped, and load opens it into a working non-extractable key', async () => {
  const idb = fakeIndexedDB();
  const x = await e2e.generateX25519();
  const record = { userId: 'u1', x25519Wrapped: await wrapX25519(x.priv) };

  const stored = record.x25519Wrapped;
  assert.ok(stored.wrapKey instanceof CryptoKey && stored.wrapKey.extractable === false, 'the wrapping key is non-extractable');
  assert.deepEqual(cryptoKeysIn(record).map((k) => k.algorithm.name), ['AES-GCM'], 'no X25519 CryptoKey in what is stored');

  await createKeyStore(idb).save(record);
  const loaded = await createKeyStore(idb).load();
  assert.equal(loaded.userId, 'u1');
  assert.equal(loaded.x25519Wrapped, undefined, 'load hands back the opened key, not the wrapped form');
  assert.ok(loaded.x25519.privateKey instanceof CryptoKey);
  assert.equal(loaded.x25519.privateKey.algorithm.name, 'X25519');
  assert.equal(loaded.x25519.privateKey.extractable, false);
  assert.deepEqual(loaded.x25519.publicKey, x.pub);

  // It is the same key: a message sealed to x.pub opens with it.
  const info = { purpose: 'ak', artifact: 'a1', epoch: 1, recipientId: 'u1', recipientPub: x.pub };
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const sealed = await e2e.wrap(info, secret);
  assert.deepEqual(await e2e.unwrap(loaded.x25519, info, sealed), secret);
});

test('save rejects when the browser silently drops the record', async () => {
  const store = createKeyStore(fakeIndexedDB((v) => v.userId === 'dropped'));
  await assert.rejects(store.save({ userId: 'dropped' }), /did not store/);
  await store.save({ userId: 'kept' });
  assert.deepEqual(await store.load(), { userId: 'kept' });
});
