/*
 * argon2-worker.js — runs Argon2id password stretching off the UI thread.
 *
 * A classic worker script (not a module, so it uses importScripts rather
 * than argon2.mjs's loader): loads wasm_exec.js, fetches argon2.wasm, and
 * boots the Go program once. Each posted message is
 * {id, password, salt, t, m, p}; the reply is {id, key} on success or
 * {id, error} on failure, matched back to the caller by id.
 */
/* global Go, cairnArgon2id */
importScripts('/wasm_exec.js');

var ready = (async function () {
  var go = new Go();
  var bytes = await (await fetch('/argon2.wasm')).arrayBuffer();
  var result = await WebAssembly.instantiate(bytes, go.importObject);
  go.run(result.instance); // Blocks forever (main is `select {}`); do not await it.
  while (typeof cairnArgon2id !== 'function') {
    await new Promise(function (resolve) { setTimeout(resolve, 0); });
  }
})();

self.onmessage = async function (event) {
  var msg = event.data;
  try {
    await ready;
    var key = cairnArgon2id(msg.password, msg.salt, msg.t, msg.m, msg.p);
    if (key instanceof Error) throw key;
    self.postMessage({ id: msg.id, key: key });
  } catch (err) {
    self.postMessage({ id: msg.id, error: err.message });
  }
};
