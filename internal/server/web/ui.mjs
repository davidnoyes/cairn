// ui.mjs — small helpers shared by the account page scripts: the real
// dependencies account.mjs takes, and form wiring. Pages build their DOM with
// textContent and createElement only: the app CSP's Trusted Types rule
// refuses a string assigned to innerHTML.
import { stretch } from './e2e.mjs';
import { createWorkerArgon2 } from './argon2-client.mjs';
import { createKeyStore } from './keystore.mjs';
import { MIN_SCORE, recoveryGroupIndex, recoveryGroupMatches } from './account.mjs';

export const $ = (id) => document.getElementById(id);

// pageDeps returns the dependencies of account.mjs for a real page. Pages
// that score passwords load /zxcvbn.js first, which defines globalThis.zxcvbn.
export function pageDeps() {
  const argon2id = createWorkerArgon2();
  return {
    fetch: (path, options) => fetch(path, options),
    stretch: (password, email, params) => stretch(password, email, params, argon2id),
    strength(password, userInputs) {
      const { score, feedback } = globalThis.zxcvbn(password, userInputs);
      return { score, feedback };
    },
    keyStore: createKeyStore(indexedDB),
  };
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
  if (err instanceof TypeError) return `Network error: ${err.message}`;
  return err.message;
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
