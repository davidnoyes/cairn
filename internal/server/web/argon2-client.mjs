// argon2-client.mjs — the page side of argon2-worker.js: returns a function
// with the same signature as argon2.mjs's, (password, salt, t, m, p) =>
// Promise<Uint8Array>, that runs Argon2id in a worker so the page stays
// responsive.
//
// The app CSP has require-trusted-types-for 'script', and a worker's script
// URL is one of those sinks, so the URL goes through a policy. The policy
// returns only the worker URL and throws for any other value. The CSP has no
// trusted-types allowlist, so any script on the page may create policies of
// its own: this policy does not stop one. It makes sure this module never
// passes the worker constructor anything else, and the CSP catches an
// accidental sink elsewhere.
//
// The worker's wasm heap holds the password, the 64 MiB matrix, and the
// stretched key, so a worker lives only while a request is pending: it is
// terminated after the last reply and a later call starts a fresh one.
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
  const stop = () => {
    worker?.terminate();
    worker = undefined;
  };
  const start = () => {
    worker = new scope.Worker(url);
    worker.onmessage = ({ data }) => {
      const call = pending.get(data.id);
      if (!call) return;
      pending.delete(data.id);
      if (pending.size === 0) stop();
      if (data.error) call.reject(new Error(data.error));
      else call.resolve(data.key);
    };
    worker.onerror = () => {
      const calls = [...pending.values()];
      pending.clear();
      stop();
      for (const { reject } of calls) {
        reject(new Error('the password worker failed to load or run. Reload the page and try again.'));
      }
    };
  };

  return (password, salt, t, m, p) =>
    new Promise((resolve, reject) => {
      if (!worker) start();
      const id = nextId++;
      pending.set(id, { resolve, reject });
      worker.postMessage({ id, password, salt, t, m, p });
    });
}
