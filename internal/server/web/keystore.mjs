// keystore.mjs — the unwrapped keys of the signed-in user, in IndexedDB. The
// records hold non-extractable CryptoKey objects (see account.mjs), which
// IndexedDB stores by structured clone without ever exposing their bytes.
// clear() runs at sign-out. The keyring anchor lives in localStorage instead,
// so it survives it.
//
// WebKit silently drops a record that holds an X25519 CryptoKey: the put's
// transaction completes and nothing is stored. So the X25519 private key is
// stored as x25519Wrapped, encrypted under a non-extractable AES-GCM key, and
// load() unwraps it straight into a non-extractable CryptoKey, so its bytes
// never return to JS memory.
import { importX25519PrivateKey } from './e2e.mjs';

const DB_NAME = 'cairn-keys';
const STORE = 'keys';
const RECORD = 'session';

const X25519_PKCS8_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

// wrapX25519 encrypts the raw private scalar priv under a fresh
// non-extractable AES-GCM key, for storage. The public key is derived from
// priv, never taken from the server.
export async function wrapX25519(priv) {
  const { publicKey } = await importX25519PrivateKey(priv);
  const wrapKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'unwrapKey']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + priv.length);
  pkcs8.set(X25519_PKCS8_PREFIX);
  pkcs8.set(priv, X25519_PKCS8_PREFIX.length);
  try {
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, pkcs8));
    return { wrapKey, iv, ct, publicKey };
  } finally {
    pkcs8.fill(0);
  }
}

// openX25519 unwraps what wrapX25519 returned into the {privateKey,
// publicKey} object e2e.unwrap takes.
export async function openX25519({ wrapKey, iv, ct, publicKey }) {
  const privateKey = await crypto.subtle.unwrapKey('pkcs8', ct, wrapKey, { name: 'AES-GCM', iv }, 'X25519', false, ['deriveBits']);
  return { privateKey, publicKey };
}

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

  const get = () => run('readonly', (store) => store.get(RECORD));

  return {
    // save reads the record back, so a browser that drops it fails sign-in
    // instead of leaving it half done.
    save: async (record) => {
      await run('readwrite', (store) => store.put(record, RECORD));
      if ((await get()) === undefined) throw new Error('This browser did not store your keys.');
    },
    load: async () => {
      const record = await get();
      if (!record?.x25519Wrapped) return record;
      const { x25519Wrapped, ...rest } = record;
      return { ...rest, x25519: await openX25519(x25519Wrapped) };
    },
    clear: () => run('readwrite', (store) => store.clear()),
  };
}
