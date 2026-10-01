// Tests for argon2-client.mjs with a fake Worker and a fake trustedTypes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createWorkerArgon2 } from './argon2-client.mjs';

class FakeWorker {
  static made = [];
  constructor(url) {
    this.url = url;
    FakeWorker.made.push(this);
  }
  postMessage(msg) {
    this.last = msg;
    queueMicrotask(() => {
      if (this.fail) this.onerror(new Error('boom'));
      else if (msg.m === 0) this.onmessage({ data: { id: msg.id, error: 'memory too small' } });
      else this.onmessage({ data: { id: msg.id, key: new Uint8Array([msg.t, msg.p]) } });
    });
  }
}

function fakeTrustedTypes() {
  const tt = {
    created: [],
    createPolicy(name, rules) {
      tt.created.push(name);
      return { createScriptURL: (s) => ({ trusted: rules.createScriptURL(s) }) };
    },
  };
  return tt;
}

test('runs Argon2id in a worker started through a Trusted Types policy', async () => {
  FakeWorker.made.length = 0;
  const trustedTypes = fakeTrustedTypes();
  const argon2id = createWorkerArgon2({ Worker: FakeWorker, trustedTypes });
  assert.equal(FakeWorker.made.length, 0, 'the worker starts on first use');
  const key = await argon2id(new Uint8Array([1]), new Uint8Array(16), 3, 65536, 1);
  assert.deepEqual([...key], [3, 1]);
  assert.deepEqual(trustedTypes.created, ['cairn-argon2-worker']);
  assert.deepEqual(FakeWorker.made[0].url, { trusted: '/argon2-worker.js' });
  assert.deepEqual(Object.keys(FakeWorker.made[0].last).sort(), ['id', 'm', 'p', 'password', 'salt', 't']);
  await argon2id(new Uint8Array([1]), new Uint8Array(16), 3, 65536, 1);
  assert.equal(FakeWorker.made.length, 1, 'one worker serves every call');
});

test('the policy refuses any other worker URL', () => {
  const trustedTypes = fakeTrustedTypes();
  let rules;
  trustedTypes.createPolicy = (name, r) => { rules = r; return { createScriptURL: (s) => s }; };
  createWorkerArgon2({ Worker: FakeWorker, trustedTypes });
  assert.throws(() => rules.createScriptURL('/evil.js'), TypeError);
});

test('works without Trusted Types, with a plain URL', async () => {
  FakeWorker.made.length = 0;
  await createWorkerArgon2({ Worker: FakeWorker })(new Uint8Array(), new Uint8Array(16), 3, 65536, 1);
  assert.equal(FakeWorker.made[0].url, '/argon2-worker.js');
});

test('a worker error message rejects that call', async () => {
  const argon2id = createWorkerArgon2({ Worker: FakeWorker });
  await assert.rejects(argon2id(new Uint8Array(), new Uint8Array(16), 3, 0, 1), /memory too small/);
});

test('a worker crash rejects every call in flight', async () => {
  FakeWorker.made.length = 0;
  const argon2id = createWorkerArgon2({ Worker: class extends FakeWorker { fail = true; } });
  await assert.rejects(argon2id(new Uint8Array(), new Uint8Array(16), 3, 65536, 1), /worker failed/);
});
