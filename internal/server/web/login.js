// login.js — wires the sign-in page to account.mjs. The server already ran
// ?next= through its safe-next rule and put the result in data-next. On a
// Google server data-google is set: the page sends the browser through Google
// first, then asks for the password, or a passkey, to unlock the keys.
import { afterSignIn, googleIdentity, signIn, signInWithPasskey } from './account.mjs';
import { $, describeError, describePasskeyError, googleStartURL, keepFragment, onSubmit, startPage, takeFragment } from './ui.mjs';
import { signedInCaller } from './viewer.mjs';

const form = $('form');
const errorEl = $('error');
const data = document.body.dataset;
const fragment = takeFragment(sessionStorage, location.hash);
const next = afterSignIn(data.next, fragment);

function showError(message) {
  errorEl.textContent = message;
  errorEl.hidden = false;
}

if (data.error) showError(data.error);
for (const link of [$('google-start'), $('google-again')]) {
  link.href = googleStartURL('/login', data.next);
  link.addEventListener('click', () => keepFragment(sessionStorage, fragment));
}

const deps = await startPage({ form, errorEl });

if (deps) {
  // A session whose keys this browser holds goes straight through. With no
  // session, any keys left in IndexedDB are stale: from a session that
  // expired, or a /logout link. A session without its keys signs in again.
  // A failed check proves nothing, so it leaves the keys alone.
  const found = await signedInCaller(deps).catch(() => undefined);
  if (found?.record) location.replace(next);
  else if (found === null) deps.keyStore.clear().catch(() => {});

  // On a Google server the form appears only once Google has vouched for an
  // address, which the form then uses as it is.
  let who = true;
  if (data.google === '1') {
    who = await googleIdentity(deps).catch((err) => {
      showError(describeError(err));
      return null;
    });
    if (who) {
      form.email.value = who.email;
      form.email.readOnly = true;
      $('google-email').textContent = who.email;
      $('google-who').hidden = false;
      $('google-switch').hidden = false;
      form.password.focus();
    } else {
      form.hidden = true;
      $('google').hidden = false;
    }
  }

  if (who) {
    onSubmit(form, $('submit'), errorEl, async () => {
      await signIn(deps, { email: form.email.value, password: form.password.value });
      location.href = next;
    });
    const passkey = $('passkey');
    if (deps.credentials && globalThis.PublicKeyCredential) {
      passkey.hidden = false;
      passkey.addEventListener('click', async () => {
        errorEl.hidden = true;
        passkey.disabled = true;
        try {
          await signInWithPasskey(deps);
          location.href = next;
        } catch (err) {
          showError(describePasskeyError(err));
        } finally {
          passkey.disabled = false;
        }
      });
      passkey.disabled = false; // listening now
    }
  }
}
