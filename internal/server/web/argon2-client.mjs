// argon2-client.mjs — the page side of argon2-worker.js: returns a function
// with the same signature as argon2.mjs's, (password, salt, t, m, p) =>
// Promise<Uint8Array>, that runs Argon2id in a worker so the page stays
// responsive.
//
// The app CSP has require-trusted-types-for 'script', and a worker's script
// URL is one of those sinks, so the URL goes through a policy that accepts
// exactly one value.
const WORKER_URL = '/argon2-worker.js';

// createWorkerArgon2 takes the global scope so a test can pass a fake Worker
// and a fake trustedTypes.
export function createWorkerArgon2(scope = globalThis) {
  let url = WORKER_URL;
  if (scope.trustedTypes) {
    const policy = scope.trustedTypes.createPolicy('cairn-argon2-worker', {
      createScriptURL(candidate) {
        if (candidate !== WORKER_URL) throw new TypeError(`refusing worker URL ${candidate}`);
        return candidate;
      },
    });
    url = policy.createScriptURL(WORKER_URL);
  }

  let worker;
  let nextId = 0;
  const pending = new Map();
  const failAll = (message) => {
    for (const { reject } of pending.values()) reject(new Error(message));
    pending.clear();
  };
  const start = () => {
    worker = new scope.Worker(url);
    worker.onmessage = ({ data }) => {
      const call = pending.get(data.id);
      if (!call) return;
      pending.delete(data.id);
      if (data.error) call.reject(new Error(data.error));
      else call.resolve(data.key);
    };
    worker.onerror = () => failAll('the password worker failed');
  };

  return (password, salt, t, m, p) =>
    new Promise((resolve, reject) => {
      if (!worker) start();
      const id = nextId++;
      pending.set(id, { resolve, reject });
      worker.postMessage({ id, password, salt, t, m, p });
    });
}
