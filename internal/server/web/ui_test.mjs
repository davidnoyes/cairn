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
    addEventListener(type, fn, options) {
      if (options?.signal?.aborted) return;
      (el.listeners.get(type) ?? el.listeners.set(type, []).get(type)).push(fn);
      options?.signal?.addEventListener('abort', () => el.removeEventListener(type, fn));
    },
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

test('onSubmit enables a button the page shipped disabled, once it is listening', () => {
  const button = fakeEl({ disabled: true });
  onSubmit(fakeEl(), button, fakeEl(), async () => {});
  assert.equal(button.disabled, false, 'a click before the listener would be lost, so the page ships it disabled');
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

// confirmPage is a recovery-code panel: its parts are found by data-part, the
// way the three pages mark them. win stands in for the window.
function confirmPage({ clipboard } = {}) {
  const parts = {
    save: fakeEl(), code: fakeEl(), copy: fakeEl(), download: fakeEl(), copied: fakeEl(), next: fakeEl(),
    confirm: fakeEl({ hidden: true }), masked: fakeEl(), group: fakeEl(), error: fakeEl({ hidden: true }), again: fakeEl(),
  };
  const panel = fakeEl({ hidden: true, querySelector: (sel) => parts[sel.match(/^\[data-part="(\w+)"\]$/)[1]] });
  const appended = [];
  const selected = [];
  const win = fakeEl({
    navigator: clipboard === undefined ? {} : { clipboard },
    location: { origin: 'https://cairn.example' },
    getSelection: () => ({ selectAllChildren: (el) => selected.push(el) }),
    document: {
      body: { append: (el) => appended.push(el) },
      createElement: (tag) => {
        const el = { tag, clicked: 0, removed: 0, click() { el.clicked++; }, remove() { el.removed++; } };
        return el;
      },
    },
  });
  return { panel, parts, win, appended, selected };
}
const CODE = 'ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ';

// missingGroup reads which group step two blanked out.
function missingGroup(parts) {
  return parts.masked.textContent.split('-').findIndex((g) => /^_+$/.test(g));
}

test('confirmRecoveryCode shows the code with its buttons, and warns before the page unloads', () => {
  const { panel, parts, win } = confirmPage();
  confirmRecoveryCode(panel, CODE, () => {}, win);
  assert.equal(parts.code.textContent, CODE);
  assert.equal(panel.hidden, false);
  assert.equal(parts.save.hidden, false);
  assert.equal(parts.confirm.hidden, true, 'step two waits for Next');
  assert.equal(parts.copy.focused, 1);
  assert.equal(win.count('beforeunload'), 1);
  const event = { preventDefault() { this.prevented = true; } };
  win.listeners.get('beforeunload')[0](event);
  assert.equal(event.prevented, true, 'the warning asks the browser to confirm leaving');
});

test('Copy puts the code on the clipboard and says so', async () => {
  const written = [];
  const { panel, parts, win, selected } = confirmPage({ clipboard: { writeText: async (t) => { written.push(t); } } });
  confirmRecoveryCode(panel, CODE, () => {}, win);
  await parts.copy.fire('click');
  assert.deepEqual(written, [CODE]);
  assert.equal(parts.copied.textContent, 'Copied.');
  assert.deepEqual(selected, []);
});

test('Copy without a clipboard selects the code and says how to copy it', async () => {
  for (const clipboard of [undefined, { writeText: async () => { throw new Error('denied'); } }]) {
    const { panel, parts, win, selected } = confirmPage({ clipboard });
    confirmRecoveryCode(panel, CODE, () => {}, win);
    await parts.copy.fire('click');
    assert.deepEqual(selected, [parts.code]);
    assert.match(parts.copied.textContent, /selected.*Ctrl\+C/);
  }
});

test('Download saves the code, with the server it belongs to, as a text file', async () => {
  const { panel, parts, win, appended } = confirmPage();
  confirmRecoveryCode(panel, CODE, () => {}, win);
  await parts.download.fire('click');
  assert.equal(appended.length, 1);
  const [a] = appended;
  assert.equal(a.tag, 'a');
  assert.equal(a.download, 'cairn-recovery-code.txt');
  assert.equal(a.clicked, 1);
  assert.equal(a.removed, 1, 'the link does not stay in the page');
  const prefix = 'data:text/plain;charset=utf-8,';
  assert.ok(a.href.startsWith(prefix));
  const text = decodeURIComponent(a.href.slice(prefix.length));
  assert.match(text, /^Cairn recovery code for https:\/\/cairn\.example\n/);
  assert.ok(text.includes(`\n${CODE}\n`));
  assert.match(parts.copied.textContent, /cairn-recovery-code\.txt/);
});

test('Next hides the code and asks for one blanked-out group', async () => {
  const { panel, parts, win } = confirmPage();
  confirmRecoveryCode(panel, CODE, () => {}, win);
  parts.copied.textContent = 'Copied.';
  parts.group.value = 'left over';
  await parts.next.fire('click');
  assert.equal(parts.code.textContent, '', 'the code leaves the page');
  assert.equal(parts.copied.textContent, '');
  assert.equal(parts.save.hidden, true);
  assert.equal(parts.confirm.hidden, false);
  assert.equal(parts.group.value, '');
  assert.equal(parts.group.focused, 1);
  const index = missingGroup(parts);
  assert.ok(index >= 0, 'one group is blanked');
  assert.equal(parts.masked.textContent, CODE.split('-').map((g, i) => (i === index ? '_'.repeat(g.length) : g)).join('-'));
});

test('Show the code again goes back to step one', async () => {
  const { panel, parts, win } = confirmPage();
  confirmRecoveryCode(panel, CODE, () => {}, win);
  await parts.next.fire('click');
  parts.group.value = 'ZZZZ';
  await parts.confirm.fire('submit');
  await parts.again.fire('click');
  assert.equal(parts.code.textContent, CODE);
  assert.equal(parts.save.hidden, false);
  assert.equal(parts.confirm.hidden, true);
  assert.equal(parts.next.focused, 1);
  await parts.next.fire('click');
  assert.equal(parts.error.hidden, true, 'a wrong answer from before does not greet the next try');
});

test('a wrong group shows an error and keeps the warning', async () => {
  const { panel, parts, win } = confirmPage();
  let confirmed = 0;
  confirmRecoveryCode(panel, CODE, () => confirmed++, win);
  await parts.next.fire('click');
  parts.group.value = 'ZZZZ';
  const event = await parts.confirm.fire('submit');
  assert.equal(event.prevented, true);
  assert.equal(parts.error.hidden, false);
  assert.match(parts.error.textContent, /does not match/);
  assert.equal(panel.hidden, false);
  assert.equal(win.count('beforeunload'), 1);
  assert.equal(confirmed, 0);
});

test('the right group clears the code, hides the panel, drops the warning, and continues', async () => {
  const { panel, parts, win } = confirmPage();
  let confirmed = 0;
  confirmRecoveryCode(panel, CODE, () => confirmed++, win);
  await parts.next.fire('click');
  parts.group.value = ` ${CODE.split('-')[missingGroup(parts)].toLowerCase()} `;
  await parts.confirm.fire('submit');
  assert.equal(parts.code.textContent, '', 'the code does not stay in the page');
  assert.equal(parts.masked.textContent, '');
  assert.equal(panel.hidden, true);
  assert.equal(win.count('beforeunload'), 0);
  assert.equal(confirmed, 1);
  for (const name of ['copy', 'download', 'next', 'again']) assert.equal(parts[name].count('click'), 0, name);
  assert.equal(parts.confirm.count('submit'), 0);
});

test('the right group after a wrong one hides the earlier error', async () => {
  const { panel, parts, win } = confirmPage();
  confirmRecoveryCode(panel, CODE, () => {}, win);
  await parts.next.fire('click');
  parts.group.value = 'ZZZZ';
  await parts.confirm.fire('submit');
  assert.equal(parts.error.hidden, false);
  parts.group.value = CODE.split('-')[missingGroup(parts)];
  await parts.confirm.fire('submit');
  assert.equal(parts.error.hidden, true);
});

test('wiring the panel again leaves one listener of each kind, for the new code', async () => {
  const { panel, parts, win } = confirmPage();
  let confirmed = 0;
  const OTHER = 'QQQQ-RRRR-SSSS-TTTT-UUUU-VVVV-WW';
  confirmRecoveryCode(panel, CODE, () => confirmed++, win);
  confirmRecoveryCode(panel, OTHER, () => confirmed++, win);
  assert.equal(parts.code.textContent, OTHER);
  assert.equal(win.count('beforeunload'), 1);
  assert.equal(parts.confirm.count('submit'), 1);
  for (const name of ['copy', 'download', 'next', 'again']) assert.equal(parts[name].count('click'), 1, name);
  await parts.next.fire('click');
  parts.group.value = OTHER.split('-')[missingGroup(parts)];
  await parts.confirm.fire('submit');
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

// flakySubtle fails the first `failures` generateKey calls, as WebKit
// occasionally does under load, and counts every call.
const flakySubtle = (failures) => {
  const subtle = { calls: 0 };
  subtle.generateKey = async () => {
    subtle.calls += 1;
    if (subtle.calls <= failures) throw new Error('transient');
    return {};
  };
  return subtle;
};

test('browserCanRunCairn retries a probe that fails once before calling the browser unsupported', async () => {
  const subtle = flakySubtle(1);
  assert.equal(await browserCanRunCairn({ isSecureContext: true, crypto: { subtle } }), true);
  assert.equal(subtle.calls, 3);
});

test('browserCanRunCairn gives up after three failed probes', async () => {
  const subtle = flakySubtle(Infinity);
  assert.equal(await browserCanRunCairn({ isSecureContext: true, crypto: { subtle } }), false);
  assert.equal(subtle.calls, 3);
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
