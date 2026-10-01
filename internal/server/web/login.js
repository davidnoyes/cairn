// login.js — wires the sign-in page to account.mjs. The server already ran
// ?next= through its safe-next rule and put the result in data-next.
import { signIn } from './account.mjs';
import { $, startPage, onSubmit } from './ui.mjs';

const form = $('form');
const deps = await startPage({ form, errorEl: $('error') });

if (deps) {
  // A visitor who reaches this page has no session, so any keys left in
  // IndexedDB are stale: from a session that expired, or a /logout link.
  deps.keyStore.clear().catch(() => {});

  onSubmit(form, $('submit'), $('error'), async () => {
    await signIn(deps, { email: form.email.value, password: form.password.value });
    location.href = document.body.dataset.next || '/';
  });
}
