// argon2.mjs — loads the vendored Argon2id WebAssembly module (see
// vendor/README.md) and wraps the global function it registers in a
// promise-based API. No DOM dependency, so this also runs under Node: see
// argon2_test.mjs. argon2-worker.js is the version the browser app actually
// calls, so this work happens off the UI thread.

/**
 * loadArgon2 boots the Go WebAssembly module behind cairnArgon2id and
 * returns a function that calls it.
 *
 * @param {{wasmBytes: BufferSource, goClass: Function}} opts - the compiled
 *   module's bytes, and the `Go` class that vendor/wasm_exec.js defines.
 * @returns {Promise<(password: Uint8Array, salt: Uint8Array, t: number, m: number, p: number) => Promise<Uint8Array>>}
 */
export async function loadArgon2({ wasmBytes, goClass }) {
  const go = new goClass();
  const { instance } = await WebAssembly.instantiate(wasmBytes, go.importObject);
  go.run(instance); // Blocks forever (main is `select {}`); do not await it.

  // main() registers cairnArgon2id after go.run starts the program.
  while (typeof globalThis.cairnArgon2id !== 'function') {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  return async function argon2id(password, salt, t, m, p) {
    const result = globalThis.cairnArgon2id(password, salt, t, m, p);
    if (result instanceof Error) throw result;
    return result;
  };
}
