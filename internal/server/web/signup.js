// signup.js — wires the sign-up page to account.mjs. Generating the keys and
// stretching the password take a moment, so the button stays disabled. On a
// Google server the address comes from the Google sign-in, the account is
// active at once, and the page signs straight in.
import { googleIdentity, signIn, signUp } from './account.mjs';
import { $, startPage, onSubmit, watchStrength, confirmRecoveryCode, googleStartURL } from './ui.mjs';

const form = $('form');
const deps = await startPage({ form, errorEl: $('error') });

if (deps) {
  let ready = true;
  if (document.body.dataset.google === '1') {
    $('google-start').href = googleStartURL('/signup', '');
    const who = await googleIdentity(deps).catch(() => null);
    if (who) {
      form.email.value = who.email;
      form.email.readOnly = true;
      if (!form.name.value) form.name.value = who.name || '';
      form.password.focus();
    } else {
      form.hidden = true;
      $('google').hidden = false;
      ready = false;
    }
  }

  if (ready) {
    const userInputs = () => [form.email.value, form.name.value];
    watchStrength(deps, form.password, $('strength'), userInputs);

    onSubmit(form, $('submit'), $('error'), async () => {
      const email = form.email.value;
      const password = form.password.value;
      const { recoveryCode, active } = await signUp(deps, {
        email,
        name: form.name.value.trim(),
        password,
        confirm: form.confirm.value,
      });
      // The account exists now, so the recovery code is shown whatever
      // happens next: a failed sign-in only sends the person to /login.
      let signedIn = false;
      if (active) signedIn = await signIn(deps, { email, password }).then(() => true, () => false);
      form.password.value = '';
      form.confirm.value = '';
      form.hidden = true;
      confirmRecoveryCode($('recovery'), recoveryCode, () => {
        if (active) {
          location.href = signedIn ? '/app' : '/login';
          return;
        }
        $('check').hidden = false;
        $('check').querySelector('a').focus(); // the Confirm button that had focus is gone
      });
    });
  }
}
