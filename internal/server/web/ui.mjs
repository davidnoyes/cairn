// ui.mjs — small helpers shared by the account page scripts: the real
// dependencies account.mjs takes, and form wiring. Pages build their DOM with
// textContent and createElement only: the app CSP's Trusted Types rule
// refuses a string assigned to innerHTML.
import { stretch } from './e2e.mjs';
import { createWorkerArgon2 } from './argon2-client.mjs';
import { createKeyStore } from './keystore.mjs';
import { MIN_SCORE, recoveryCodeMasked, recoveryGroupIndex, recoveryGroupMatches } from './account.mjs';

// NetworkError is a fetch that never got an answer. networkFetch throws it so
// describeError can tell a lost connection from a bug that happens to throw
// a TypeError.
export class NetworkError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NetworkError';
  }
}

// networkFetch wraps a fetch function so a failed request throws NetworkError.
// An HTTP error status is an answer, and passes through.
export function networkFetch(fetchImpl) {
  return async (path, options) => {
    try {
      return await fetchImpl(path, options);
    } catch (err) {
      throw new NetworkError(err.message);
    }
  };
}

export const UNSUPPORTED_MESSAGE =
  "This browser or connection can't run Cairn's encryption. Use HTTPS (or localhost) and a current browser.";
export const VERIFY_LINK_MESSAGE =
  'This link is incomplete, or it was already used. If you already verified your address, sign in.';

export const $ = (id) => document.getElementById(id);

// pageDeps returns the dependencies of account.mjs for a real page. Pages
// that score passwords load /zxcvbn.js first, which defines globalThis.zxcvbn.
export function pageDeps() {
  const argon2id = createWorkerArgon2();
  return {
    fetch: networkFetch((path, options) => fetch(path, options)),
    stretch: (password, email, params) => stretch(password, email, params, argon2id),
    strength(password, userInputs) {
      const { score, feedback } = globalThis.zxcvbn(password, userInputs);
      return { score, feedback };
    },
    keyStore: createKeyStore(indexedDB),
  };
}

// browserCanRunCairn reports whether the page can run Cairn's encryption: a
// secure context, WebCrypto, and working X25519 and Ed25519 key generation,
// which older browsers lack. scope is the global object, so a test can pass a
// fake one. WebKit occasionally fails a generateKey it supports, so the probe
// runs up to PROBE_ATTEMPTS times before the browser is called unsupported.
const PROBE_ATTEMPTS = 3;

export async function browserCanRunCairn(scope = globalThis) {
  const subtle = scope.crypto && scope.crypto.subtle;
  if (!scope.isSecureContext || !subtle) return false;
  for (let attempt = 0; attempt < PROBE_ATTEMPTS; attempt++) {
    try {
      await subtle.generateKey('X25519', false, ['deriveBits']);
      await subtle.generateKey('Ed25519', false, ['sign']);
      return true;
    } catch {
      // Try again: one failure is not proof the algorithm is missing.
    }
  }
  return false;
}

// startPage prepares a page that does cryptography before it does anything
// else. It returns the page's dependencies, or null after showing why the
// page cannot run in errorEl: an unsupported browser also gets its form
// disabled, and a failure to build the dependencies (a Trusted Types policy
// the browser refuses, say) is shown rather than left as a dead page.
export async function startPage({ form, errorEl, scope = globalThis, makeDeps = pageDeps }) {
  const show = (message) => {
    errorEl.textContent = message;
    errorEl.hidden = false;
  };
  if (!(await browserCanRunCairn(scope))) {
    show(UNSUPPORTED_MESSAGE);
    for (const control of form.elements) control.disabled = true;
    return null;
  }
  try {
    return makeDeps();
  } catch (err) {
    show(`This page could not start: ${err.message}. Reload the page and try again.`);
    return null;
  }
}

// describeStrength is the line shown under a new-password field.
export function describeStrength(result) {
  const parts = [`Strength ${result.score} of 4.`];
  if (result.score < MIN_SCORE) parts.push(`You need ${MIN_SCORE}.`);
  if (result.feedback.warning) parts.push(result.feedback.warning + '.');
  parts.push(...(result.feedback.suggestions || []));
  return parts.join(' ');
}

// describeError turns what a flow throws into one line for the page.
export function describeError(err) {
  if (err.name === 'FloorError') {
    return 'This server asks for weaker password protection than Cairn allows, so the page stopped. Tell the server administrator.';
  }
  if (err.name === 'WeakPasswordError') {
    return [err.message, err.feedback.warning, ...(err.feedback.suggestions || [])].filter(Boolean).join(' ');
  }
  if (err.name === 'NetworkError') return `Could not reach the server (${err.message}). Check your connection and try again.`;
  return err.message;
}

// describeVerifyError is describeError for the verification page, where a
// link with no token usually means the link was already used: opening it
// removes the token, so a reload finds none.
export function describeVerifyError(err) {
  return err.name === 'IncompleteLinkError' ? VERIFY_LINK_MESSAGE : describeError(err);
}

// onSubmit runs action when the form is submitted. It disables the button
// while the action runs, and shows what the action throws in errorEl. The
// page ships the button disabled, because a click before this listener exists
// submits a method="dialog" form to nowhere, so it is enabled here.
export function onSubmit(form, button, errorEl, action) {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorEl.hidden = true;
    button.disabled = true;
    try {
      await action();
    } catch (err) {
      errorEl.textContent = describeError(err);
      errorEl.hidden = false;
    } finally {
      button.disabled = false;
    }
  });
  button.disabled = false; // listening now
}

// watchStrength shows a live strength line under a password field.
export function watchStrength(deps, passwordInput, line, userInputs) {
  passwordInput.addEventListener('input', () => {
    if (passwordInput.value === '') {
      line.textContent = '';
      return;
    }
    const result = deps.strength(passwordInput.value, userInputs());
    line.textContent = describeStrength(result);
    line.className = 'strength ' + (result.score >= MIN_SCORE ? 'ok' : 'bad');
  });
}

// RECOVERY_FILE is the name Download gives the recovery code's text file.
const RECOVERY_FILE = 'cairn-recovery-code.txt';

// panelWiring remembers the listeners confirmRecoveryCode attached for a
// panel, so wiring the same panel again replaces them rather than adding more.
const panelWiring = new WeakMap();

// confirmRecoveryCode walks the user through saving a new recovery code, in
// the panel whose parts are marked data-part. Step one ("save") shows the
// code, with Copy, Download, and Next. Step two ("confirm") hides it and asks
// for one blanked-out group from the user's saved copy, with a way back
// ("again"). Until they get it right, leaving the page asks for confirmation:
// the code is shown once. A right answer clears the code from the page, hides
// the panel, and calls onConfirmed. win is the window, for a test to replace.
export function confirmRecoveryCode(panel, display, onConfirmed, win = globalThis) {
  const part = (name) => panel.querySelector(`[data-part="${name}"]`);
  const [save, codeEl, copy, download, copied, next, form, masked, input, errorEl, again] = [
    'save', 'code', 'copy', 'download', 'copied', 'next', 'confirm', 'masked', 'group', 'error', 'again',
  ].map(part);
  panelWiring.get(panel)?.abort();
  const wiring = new AbortController();
  panelWiring.set(panel, wiring);
  const on = (target, type, fn) => target.addEventListener(type, fn, { signal: wiring.signal });
  const index = recoveryGroupIndex(display);

  const showCode = () => {
    codeEl.textContent = display;
    copied.textContent = '';
    form.hidden = true;
    save.hidden = false;
  };
  on(copy, 'click', async () => {
    try {
      // No clipboard outside a secure context: a plain-HTTP server.
      await win.navigator.clipboard.writeText(display);
      copied.textContent = 'Copied.';
    } catch {
      win.getSelection().selectAllChildren(codeEl);
      copied.textContent = 'This browser blocked the copy. The code is selected: copy it with Ctrl+C, or ⌘C on a Mac.';
    }
  });
  on(download, 'click', () => {
    const text = `Cairn recovery code for ${win.location.origin}\n\n${display}\n\n`
      + 'It resets a forgotten password without losing your keys. Keep it somewhere safe and private.\n';
    const a = win.document.createElement('a');
    a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(text);
    a.download = RECOVERY_FILE;
    win.document.body.append(a);
    a.click();
    a.remove();
    copied.textContent = `Downloading ${RECOVERY_FILE}.`;
  });
  on(next, 'click', () => {
    codeEl.textContent = '';
    copied.textContent = '';
    save.hidden = true;
    masked.textContent = recoveryCodeMasked(display, index);
    input.value = '';
    errorEl.hidden = true; // a wrong group's error, from before Show the code again
    form.hidden = false;
    input.focus();
  });
  on(again, 'click', () => {
    showCode();
    next.focus();
  });
  on(form, 'submit', (event) => {
    event.preventDefault();
    if (!recoveryGroupMatches(display, index, input.value)) {
      errorEl.textContent = 'That does not match the code. Check your saved copy, or show the code again.';
      errorEl.hidden = false;
      return;
    }
    errorEl.hidden = true; // a wrong group's error, from an earlier try
    masked.textContent = '';
    panel.hidden = true;
    wiring.abort();
    onConfirmed();
  });
  on(win, 'beforeunload', (event) => {
    event.preventDefault();
    event.returnValue = '';
  });
  showCode();
  panel.hidden = false;
  copy.focus();
}
