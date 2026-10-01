// signup.js — wires the sign-up page to account.mjs. Generating the keys and
// stretching the password take a moment, so the button stays disabled.
import { signUp } from './account.mjs';
import { $, pageDeps, onSubmit, watchStrength, showRecoveryCode } from './ui.mjs';

const deps = pageDeps();
const form = $('form');
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
  const confirmed = showRecoveryCode(
    { codeEl: $('code'), promptEl: $('groupPrompt'), input: $('group') },
    recoveryCode,
  );
  $('recovery').hidden = false;
  $('group').focus();
  $('confirmForm').addEventListener('submit', (event) => {
    event.preventDefault();
    if (!confirmed()) {
      $('confirmError').textContent = 'That is not the group shown above. Check the code and try again.';
      $('confirmError').hidden = false;
      return;
    }
    $('code').textContent = '';
    $('recovery').hidden = true;
    $('check').hidden = false;
  });
});
