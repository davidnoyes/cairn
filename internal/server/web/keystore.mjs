// keystore.mjs — the unwrapped keys of the signed-in user, in IndexedDB. The
// records hold non-extractable CryptoKey objects (see account.mjs), which
// IndexedDB stores by structured clone without ever exposing their bytes.
// clear() runs at sign-out. The keyring anchor lives in localStorage instead,
// so it survives it.
const DB_NAME = 'cairn-keys';
const STORE = 'keys';
const RECORD = 'session';

// createKeyStore takes the IndexedDB factory (window.indexedDB) so a test can
// pass a fake.
export function createKeyStore(indexedDB) {
  let opened;
  const open = () => {
    opened ??= new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return opened;
  };

  // run performs one request in a transaction and resolves with its result
  // once the transaction has committed.
  const run = async (mode, makeRequest) => {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = makeRequest(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  };

  return {
    save: (record) => run('readwrite', (store) => store.put(record, RECORD)),
    load: () => run('readonly', (store) => store.get(RECORD)),
    clear: () => run('readwrite', (store) => store.clear()),
  };
}
