// keystore.mjs — the unwrapped keys of the signed-in user, in IndexedDB. The
// records hold non-extractable CryptoKey objects (see account.mjs), which
// IndexedDB stores by structured clone without ever exposing their bytes.
// clear() runs at sign-out. The keyring anchor lives in localStorage instead,
// so it survives it.
//
// WebKit silently drops a record that holds an X25519 CryptoKey: the put's
// transaction completes and nothing is stored. So account.mjs hands save()
// the X25519 key twice: as x25519, a non-extractable CryptoKey, and as
// x25519Wrapped, encrypted under a non-extractable AES-GCM key. save() stores
// x25519 where the browser keeps it, and x25519Wrapped only where it does
// not. The wrapped form is weaker: script on the app origin can unwrap it as
// extractable and export the private key, which it cannot do with x25519.
// load() unwraps it into a non-extractable CryptoKey.
import { importX25519PrivateKey, x25519Pkcs8 } from './e2e.mjs';

const DB_NAME = 'cairn-keys';
const STORE = 'keys';
const RECORD = 'session';

// wrapX25519 encrypts the raw private scalar priv under a fresh
// non-extractable AES-GCM key, for storage. The public key is derived from
// priv, never taken from the server.
export async function wrapX25519(priv) {
  const { publicKey } = await importX25519PrivateKey(priv);
  const wrapKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'unwrapKey']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pkcs8 = x25519Pkcs8(priv);
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
  const clear = () => run('readwrite', (store) => store.clear());
  // put stores record in place of whatever was there, and reports whether
  // the browser kept it. WebKit reads a dropped record back as null.
  const put = async (record) => {
    await clear(); // first, so a dropped put cannot leave the old record
    await run('readwrite', (store) => store.put(record, RECORD));
    return (await get()) != null;
  };

  return {
    // save reads the record back, so a browser that drops it fails sign-in
    // instead of leaving it half done.
    save: async (record) => {
      const { x25519Wrapped, ...direct } = record;
      if (await put(direct)) return;
      const wrapped = { ...record };
      delete wrapped.x25519;
      if (x25519Wrapped && (await put(wrapped))) return;
      await clear(); // so load() finds nothing, not a null record
      throw new Error('This browser did not store your keys.');
    },
    load: async () => {
      const record = await get();
      if (!record?.x25519Wrapped) return record;
      const { x25519Wrapped, ...rest } = record;
      return { ...rest, x25519: await openX25519(x25519Wrapped) };
    },
    clear,
  };
}
