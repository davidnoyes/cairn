// signup.js — wires the sign-up page to account.mjs. Generating the keys and
// stretching the password take a moment, so the button stays disabled.
import { signUp } from './account.mjs';
import { $, startPage, onSubmit, watchStrength, confirmRecoveryCode } from './ui.mjs';

const form = $('form');
const deps = await startPage({ form, errorEl: $('error') });

if (deps) {
  const userInputs = () => [form.email.value, form.name.value];
  watchStrength(deps, form.password, $('strength'), userInputs);

  onSubmit(form, $('submit'), $('error'), async () => {
    const { recoveryCode } = await signUp(deps, {
      email: form.email.value,
      name: form.name.value.trim(),
      password: form.password.value,
      confirm: form.confirm.value,
    });
    form.password.value = '';
    form.confirm.value = '';
    form.hidden = true;
    confirmRecoveryCode($('recovery'), recoveryCode, () => {
      $('check').hidden = false;
      $('check').querySelector('a').focus(); // the Confirm button that had focus is gone
    });
  });
}
