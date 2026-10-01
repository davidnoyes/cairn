// Tests for keystore.mjs against a minimal fake IndexedDB: one database, one
// object store, and requests and transactions that complete asynchronously.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createKeyStore } from './keystore.mjs';

function fakeIndexedDB() {
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
                  put: (value, key) => request(() => { map.set(key, value); return key; }),
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
