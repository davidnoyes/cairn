// login.js — wires the sign-in page to account.mjs. The server already ran
// ?next= through its safe-next rule and put the result in data-next.
import { signIn } from './account.mjs';
import { $, startPage, onSubmit } from './ui.mjs';
import { signedInCaller } from './viewer.mjs';

const form = $('form');
const deps = await startPage({ form, errorEl: $('error') });
const next = document.body.dataset.next || '/';

if (deps) {
  // A session whose keys this browser holds goes straight through. With no
  // session, any keys left in IndexedDB are stale: from a session that
  // expired, or a /logout link. A session without its keys signs in again.
  const found = await signedInCaller(deps).catch(() => null);
  if (found?.record) location.replace(next);
  else if (!found) deps.keyStore.clear().catch(() => {});

  onSubmit(form, $('submit'), $('error'), async () => {
    await signIn(deps, { email: form.email.value, password: form.password.value });
    location.href = next;
  });
}
