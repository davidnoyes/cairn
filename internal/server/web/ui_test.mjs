// Tests for ui.mjs against a minimal fake DOM: just the properties and
// methods ui.mjs touches, and nothing global. Run with:
// node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as e2e from './e2e.mjs';
import { ApiError, WeakPasswordError, takeToken } from './account.mjs';
import {
  NetworkError, UNSUPPORTED_MESSAGE, VERIFY_LINK_MESSAGE, browserCanRunCairn, confirmRecoveryCode, describeError,
  describeVerifyError, networkFetch, onSubmit, startPage,
} from './ui.mjs';

// fakeEl is an element with listeners, the way ui.mjs uses one.
function fakeEl(props = {}) {
  const el = {
    hidden: false, disabled: false, textContent: '', value: '', focused: 0, listeners: new Map(), ...props,
    addEventListener(type, fn) { (el.listeners.get(type) ?? el.listeners.set(type, []).get(type)).push(fn); },
    removeEventListener(type, fn) { el.listeners.set(type, (el.listeners.get(type) ?? []).filter((f) => f !== fn)); },
    focus() { el.focused++; },
    count: (type) => (el.listeners.get(type) ?? []).length,
    async fire(type, event = {}) {
      const e = { preventDefault() { e.prevented = true; }, ...event };
      for (const fn of el.listeners.get(type) ?? []) await fn(e);
      return e;
    },
  };
  return el;
}

// ------------------------------------------------------------- describeError

test('describeError explains a refused Argon2id floor', () => {
  const err = new e2e.FloorError('memory 1 below floor');
  assert.match(describeError(err), /weaker password protection.*administrator/);
});

test('describeError joins a weak password message with the estimator feedback', () => {
  const err = new WeakPasswordError({ warning: 'This is a common password', suggestions: ['Add a word.'] });
  assert.equal(describeError(err), `${err.message} This is a common password Add a word.`);
  assert.equal(describeError(new WeakPasswordError()), new WeakPasswordError().message);
});

test('describeError calls only a failed fetch a network error', () => {
  assert.match(describeError(new NetworkError('Failed to fetch')), /Could not reach the server/);
  const bug = new TypeError("Cannot read properties of undefined (reading 'x')");
  assert.equal(describeError(bug), bug.message, 'a TypeError from a bug is not a network error');
});

test('describeError shows the server message of an API error and any other message as is', () => {
  assert.equal(describeError(new ApiError('invalid email or password', 401)), 'invalid email or password');
  assert.equal(describeError(new Error('The passwords do not match.')), 'The passwords do not match.');
});

test('describeVerifyError says an incomplete link may already have been used', () => {
  const incomplete = (() => {
    try { return takeToken({ hash: '', pathname: '/verify', search: '' }, { replaceState() {} }); } catch (e) { return e; }
  })();
  assert.equal(describeVerifyError(incomplete), VERIFY_LINK_MESSAGE);
  assert.match(VERIFY_LINK_MESSAGE, /already.*used/);
  assert.match(VERIFY_LINK_MESSAGE, /sign in/i);
  assert.equal(describeVerifyError(new ApiError('link expired', 400)), 'link expired');
});

// ------------------------------------------------------------- networkFetch

test('networkFetch turns a failed fetch into a NetworkError, and passes responses through', async () => {
  const resp = { ok: false, status: 500 };
  assert.equal(await networkFetch(async () => resp)('/x', {}), resp, 'an HTTP error is not a network error');
  await assert.rejects(
    networkFetch(async () => { throw new TypeError('Failed to fetch'); })('/x'),
    (err) => err instanceof NetworkError && /Failed to fetch/.test(err.message),
  );
});

// ------------------------------------------------------------------ onSubmit

test('onSubmit disables the button while the action runs and re-enables it after an error', async () => {
  const form = fakeEl();
  const button = fakeEl();
  const errorEl = fakeEl({ hidden: true });
  let duringAction;
  onSubmit(form, button, errorEl, async () => {
    duringAction = button.disabled;
    throw new Error('nope');
  });
  const event = await form.fire('submit');
  assert.equal(event.prevented, true);
  assert.equal(duringAction, true);
  assert.equal(button.disabled, false, 'the button must work again after a failure');
  assert.equal(errorEl.textContent, 'nope');
  assert.equal(errorEl.hidden, false);
});

test('onSubmit re-enables the button after success and clears an earlier error', async () => {
  const form = fakeEl();
  const button = fakeEl();
  const errorEl = fakeEl({ hidden: false, textContent: 'old' });
  onSubmit(form, button, errorEl, async () => {});
  await form.fire('submit');
  assert.equal(button.disabled, false);
  assert.equal(errorEl.hidden, true);
});

// ------------------------------------------------- recovery-code confirm

function confirmPage() {
  const els = {
    form: fakeEl(), panel: fakeEl({ hidden: true }), codeEl: fakeEl(), promptEl: fakeEl(),
    input: fakeEl(), errorEl: fakeEl({ hidden: true }),
  };
  return { els, win: fakeEl() };
}
const CODE = 'ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ';

test('confirmRecoveryCode shows the code and panel, and warns before the page unloads', () => {
  const { els, win } = confirmPage();
  confirmRecoveryCode(els, CODE, () => {}, win);
  assert.equal(els.codeEl.textContent, CODE);
  assert.equal(els.panel.hidden, false);
  assert.equal(els.input.focused, 1);
  assert.equal(win.count('beforeunload'), 1);
  const event = { preventDefault() { this.prevented = true; } };
  win.listeners.get('beforeunload')[0](event);
  assert.equal(event.prevented, true, 'the warning asks the browser to confirm leaving');
});

test('a wrong group shows an error and keeps the code and the warning', async () => {
  const { els, win } = confirmPage();
  let confirmed = 0;
  confirmRecoveryCode(els, CODE, () => confirmed++, win);
  els.input.value = 'ZZZZ';
  const event = await els.form.fire('submit');
  assert.equal(event.prevented, true);
  assert.equal(els.errorEl.hidden, false);
  assert.match(els.errorEl.textContent, /not the group shown/);
  assert.equal(els.codeEl.textContent, CODE);
  assert.equal(win.count('beforeunload'), 1);
  assert.equal(confirmed, 0);
});

test('the right group clears the code field, hides the panel, drops the warning, and continues', async () => {
  const { els, win } = confirmPage();
  let confirmed = 0;
  confirmRecoveryCode(els, CODE, () => confirmed++, win);
  const group = els.promptEl.textContent.match(/group (\d+) of/)[1] - 1;
  els.input.value = CODE.split('-')[group].toLowerCase();
  await els.form.fire('submit');
  assert.equal(els.codeEl.textContent, '', 'the code does not stay in the page');
  assert.equal(els.panel.hidden, true);
  assert.equal(win.count('beforeunload'), 0);
  assert.equal(confirmed, 1);
});

test('the right group after a wrong one hides the earlier error', async () => {
  const { els, win } = confirmPage();
  confirmRecoveryCode(els, CODE, () => {}, win);
  els.input.value = 'ZZZZ';
  await els.form.fire('submit');
  assert.equal(els.errorEl.hidden, false);
  const group = els.promptEl.textContent.match(/group (\d+) of/)[1] - 1;
  els.input.value = CODE.split('-')[group];
  await els.form.fire('submit');
  assert.equal(els.errorEl.hidden, true);
});

test('wiring the confirmation again leaves one submit listener and one warning', async () => {
  const { els, win } = confirmPage();
  let confirmed = 0;
  confirmRecoveryCode(els, CODE, () => confirmed++, win);
  confirmRecoveryCode(els, CODE, () => confirmed++, win);
  assert.equal(els.form.count('submit'), 1);
  assert.equal(win.count('beforeunload'), 1);
  const group = els.promptEl.textContent.match(/group (\d+) of/)[1] - 1;
  els.input.value = CODE.split('-')[group];
  await els.form.fire('submit');
  assert.equal(confirmed, 1);
});

// ------------------------------------------------------------ capability check

const subtleThat = (refuse = []) => ({
  generateKey: async (alg) => { if (refuse.includes(alg)) throw new Error(`${alg} unsupported`); return {}; },
});

test('browserCanRunCairn accepts a secure context with X25519 and Ed25519', async () => {
  assert.equal(await browserCanRunCairn({ isSecureContext: true, crypto: { subtle: subtleThat() } }), true);
});

test('browserCanRunCairn runs against the real WebCrypto of this runtime', async () => {
  assert.equal(await browserCanRunCairn({ isSecureContext: true, crypto: globalThis.crypto }), true);
});

test('browserCanRunCairn refuses an insecure context, no crypto.subtle, or a missing curve', async () => {
  assert.equal(await browserCanRunCairn({ isSecureContext: false, crypto: { subtle: subtleThat() } }), false);
  assert.equal(await browserCanRunCairn({ crypto: { subtle: subtleThat() } }), false);
  assert.equal(await browserCanRunCairn({ isSecureContext: true, crypto: {} }), false);
  assert.equal(await browserCanRunCairn({ isSecureContext: true }), false);
  assert.equal(await browserCanRunCairn({ isSecureContext: true, crypto: { subtle: subtleThat(['X25519']) } }), false);
  assert.equal(await browserCanRunCairn({ isSecureContext: true, crypto: { subtle: subtleThat(['Ed25519']) } }), false);
});

function startPageEls() {
  const input = fakeEl();
  const form = fakeEl({ elements: [input, fakeEl()] });
  return { form, input, errorEl: fakeEl({ hidden: true }) };
}

test('startPage returns the dependencies of a capable browser and leaves the form alone', async () => {
  const { form, errorEl } = startPageEls();
  const deps = { marker: 1 };
  const got = await startPage({ form, errorEl, scope: { isSecureContext: true, crypto: globalThis.crypto }, makeDeps: () => deps });
  assert.equal(got, deps);
  assert.equal(errorEl.hidden, true);
  assert.deepEqual(form.elements.map((c) => c.disabled), [false, false]);
});

test('startPage on an unsupported browser shows one clear message, disables the form, and builds nothing', async () => {
  const { form, errorEl } = startPageEls();
  let built = 0;
  const got = await startPage({ form, errorEl, scope: { isSecureContext: false, crypto: globalThis.crypto }, makeDeps: () => { built++; } });
  assert.equal(got, null);
  assert.equal(built, 0);
  assert.equal(errorEl.textContent, UNSUPPORTED_MESSAGE);
  assert.equal(UNSUPPORTED_MESSAGE, "This browser or connection can't run Cairn's encryption. Use HTTPS (or localhost) and a current browser.");
  assert.equal(errorEl.hidden, false);
  assert.deepEqual(form.elements.map((c) => c.disabled), [true, true]);
});

test('startPage shows a setup failure in the error element instead of dying silently', async () => {
  const { form, errorEl } = startPageEls();
  const got = await startPage({
    form, errorEl, scope: { isSecureContext: true, crypto: globalThis.crypto },
    makeDeps: () => { throw new TypeError('Policy with name "cairn-argon2-worker" already exists'); },
  });
  assert.equal(got, null);
  assert.match(errorEl.textContent, /could not start.*already exists.*Reload/i);
  assert.equal(errorEl.hidden, false);
});
