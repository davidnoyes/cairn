// Tests for keystore.mjs against a minimal fake IndexedDB: one database, one
// object store, and requests and transactions that complete asynchronously.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createKeyStore, wrapX25519 } from './keystore.mjs';
import * as e2e from './e2e.mjs';

// fakeIndexedDB drops any put whose value drop(value) accepts, as WebKit does
// for a record holding an X25519 CryptoKey: the transaction still completes,
// and the key then reads back as null, not undefined. When drop returns
// 'nothing', the put changes nothing at all, and an older record stays.
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
                  put: (value, key) => request(() => {
                    const dropped = drop(value);
                    if (dropped !== 'nothing') map.set(key, dropped ? null : value);
                    return key;
                  }),
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
  assert.deepEqual(await store.load(), record);
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

// dropsX25519 accepts a value holding an X25519 CryptoKey, as WebKit drops it.
const dropsX25519 = (v) => cryptoKeysIn(v).some((k) => k.algorithm.name === 'X25519');

// x25519Record is a record as account.mjs saves it: the X25519 key both as
// a non-extractable CryptoKey and wrapped.
async function x25519Record() {
  const x = await e2e.generateX25519();
  const x25519 = await e2e.importX25519PrivateKey(x.priv);
  return { x, record: { userId: 'u1', x25519, x25519Wrapped: await wrapX25519(x.priv) } };
}

// checkWorks checks that pair is a non-extractable X25519 key for x.
async function checkWorks(pair, x) {
  assert.ok(pair.privateKey instanceof CryptoKey);
  assert.equal(pair.privateKey.algorithm.name, 'X25519');
  assert.equal(pair.privateKey.extractable, false);
  assert.deepEqual(pair.publicKey, x.pub);
  // It is the same key: a message sealed to x.pub opens with it.
  const info = { purpose: 'ak', artifact: 'a1', epoch: 1, recipientId: 'u1', recipientPub: x.pub };
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const sealed = await e2e.wrap(info, secret);
  assert.deepEqual(await e2e.unwrap(pair, info, sealed), secret);
}

test('a browser that stores X25519 keys keeps the non-extractable key, and no wrapped copy', async () => {
  const idb = fakeIndexedDB();
  const { x, record } = await x25519Record();
  await createKeyStore(idb).save(record);
  const stored = idb.dbs.get('cairn-keys').stores.get('keys').get('session');
  assert.equal(stored.x25519Wrapped, undefined, 'no wrapped copy is stored');
  assert.equal(stored.x25519, record.x25519);
  const loaded = await createKeyStore(idb).load();
  assert.equal(loaded.x25519Wrapped, undefined);
  await checkWorks(loaded.x25519, x);
});

test('a browser that drops X25519 keys stores the wrapped copy, and load opens it into a working non-extractable key', async () => {
  const idb = fakeIndexedDB(dropsX25519);
  const { x, record } = await x25519Record();
  const wrapped = record.x25519Wrapped;
  assert.ok(wrapped.wrapKey instanceof CryptoKey && wrapped.wrapKey.extractable === false, 'the wrapping key is non-extractable');
  assert.deepEqual(cryptoKeysIn(wrapped).map((k) => k.algorithm.name), ['AES-GCM'], 'no X25519 CryptoKey in the wrapped copy');

  await createKeyStore(idb).save(record);
  const stored = idb.dbs.get('cairn-keys').stores.get('keys').get('session');
  assert.equal(stored.x25519, undefined);
  assert.equal(stored.x25519Wrapped, wrapped);
  const loaded = await createKeyStore(idb).load();
  assert.equal(loaded.userId, 'u1');
  assert.equal(loaded.x25519Wrapped, undefined, 'load hands back the opened key, not the wrapped form');
  await checkWorks(loaded.x25519, x);
});

test('save rejects when the browser silently drops the record', async () => {
  const store = createKeyStore(fakeIndexedDB((v) => v.userId === 'dropped'));
  await assert.rejects(store.save({ userId: 'dropped' }), /did not store/);
  await assert.rejects(store.save({ userId: 'dropped', x25519Wrapped: {} }), /did not store/, 'and when it drops the wrapped copy too');
  assert.equal(await store.load(), undefined, 'and leaves no null record behind');
  await store.save({ userId: 'kept' });
  assert.deepEqual(await store.load(), { userId: 'kept' });
});

test('a dropped save never leaves the previous record in place', async () => {
  const store = createKeyStore(fakeIndexedDB((v) => v.userId === 'dropped' && 'nothing'));
  await store.save({ userId: 'before' });
  await assert.rejects(store.save({ userId: 'dropped' }), /did not store/);
  assert.equal(await store.load(), undefined);
});

// Linux WebKit refuses a PKCS#8 X25519 key whose scalar starts with a zero
// byte, which one key in 256 does, so the wrapped copy holds x25519Pkcs8's
// form, whose first scalar byte is never zero. It is wiped once encrypted.
test('the wrapped copy holds the PKCS#8 form with no leading zero, and wipes it', async () => {
  const priv = crypto.getRandomValues(new Uint8Array(32));
  priv[0] = 0;
  const { subtle } = crypto;
  const realEncrypt = subtle.encrypt.bind(subtle);
  let plaintext;
  let seen;
  subtle.encrypt = (algorithm, key, data) => {
    plaintext = data;
    seen = Uint8Array.from(data);
    return realEncrypt(algorithm, key, data);
  };
  try {
    await wrapX25519(priv);
  } finally {
    delete subtle.encrypt;
  }
  assert.deepEqual(seen, e2e.x25519Pkcs8(priv));
  assert.equal(seen[16], 1);
  assert.ok(plaintext.every((b) => b === 0), 'the PKCS#8 copy is wiped');
});
