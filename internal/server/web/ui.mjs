// ui.mjs — small helpers shared by the account page scripts: the real
// dependencies account.mjs takes, and form wiring. Pages build their DOM with
// textContent and createElement only: the app CSP's Trusted Types rule
// refuses a string assigned to innerHTML.
import { stretch } from './e2e.mjs';
import { createWorkerArgon2 } from './argon2-client.mjs';
import { createKeyStore } from './keystore.mjs';
import { MIN_SCORE, recoveryGroupIndex, recoveryGroupMatches } from './account.mjs';

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
// fake one.
export async function browserCanRunCairn(scope = globalThis) {
  const subtle = scope.crypto && scope.crypto.subtle;
  if (!scope.isSecureContext || !subtle) return false;
  try {
    await subtle.generateKey('X25519', false, ['deriveBits']);
    await subtle.generateKey('Ed25519', false, ['sign']);
    return true;
  } catch {
    return false;
  }
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
// while the action runs, and shows what the action throws in errorEl.
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

// showRecoveryCode fills the recovery-code panel and returns a function that
// checks the group the user retypes. The caller reveals the panel.
export function showRecoveryCode({ codeEl, promptEl, input }, display) {
  codeEl.textContent = display;
  const index = recoveryGroupIndex(display);
  promptEl.textContent = `To confirm you saved it, type group ${index + 1} of ${display.split('-').length}.`;
  input.value = '';
  return () => recoveryGroupMatches(display, index, input.value);
}

// confirmHandlers remembers the listeners confirmRecoveryCode attached to a
// form, so wiring the same form again replaces them rather than adding more.
const confirmHandlers = new WeakMap();

// confirmRecoveryCode shows the recovery code and its panel, and asks the user
// to retype one group. Until they do, leaving the page asks for confirmation:
// the code is shown once. A right answer clears the code from the page, hides
// the panel, and calls onConfirmed. win is the window, for a test to replace.
export function confirmRecoveryCode({ form, panel, codeEl, promptEl, input, errorEl }, display, onConfirmed, win = globalThis) {
  const confirmed = showRecoveryCode({ codeEl, promptEl, input }, display);
  const previous = confirmHandlers.get(form);
  if (previous) {
    form.removeEventListener('submit', previous.submit);
    win.removeEventListener('beforeunload', previous.warn);
  }
  const warn = (event) => {
    event.preventDefault();
    event.returnValue = '';
  };
  const submit = (event) => {
    event.preventDefault();
    if (!confirmed()) {
      errorEl.textContent = 'That is not the group shown above. Check the code and try again.';
      errorEl.hidden = false;
      return;
    }
    codeEl.textContent = '';
    panel.hidden = true;
    win.removeEventListener('beforeunload', warn);
    onConfirmed();
  };
  confirmHandlers.set(form, { submit, warn });
  form.addEventListener('submit', submit);
  win.addEventListener('beforeunload', warn);
  panel.hidden = false;
  input.focus();
}
