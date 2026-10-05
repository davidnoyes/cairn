// refuse.js — refuses a successor's request for access. It needs no session,
// so it works for a deactivated account: the password or the recovery code
// proves who is asking.
import { refuseWithPassword, refuseWithRecovery } from './account.mjs';
import { refusalView } from './successor.mjs';
import { $, startPage, onSubmit } from './ui.mjs';

const form = $('form');
const deps = await startPage({ form, errorEl: $('error') });

if (deps) {
  const mode = () => form.mode.value;
  const syncMode = () => {
    $('passwordRow').hidden = mode() !== 'password';
    $('codeRow').hidden = mode() !== 'recovery';
  };
  for (const radio of form.querySelectorAll('input[name=mode]')) radio.addEventListener('change', syncMode);
  syncMode(); // Firefox restores the choice on a reload, with no change event

  onSubmit(form, $('submit'), $('error'), async () => {
    const email = form.email.value;
    const answer = mode() === 'password'
      ? await refuseWithPassword(deps, { email, password: form.password.value })
      : await refuseWithRecovery(deps, { email, recoveryCode: form.code.value });
    const view = refusalView(answer);
    $('done-text').textContent = view.done;
    $('deactivated').textContent = view.deactivated;
    $('deactivated').hidden = !view.deactivated;
    form.hidden = true;
    $('done').hidden = false;
  });
}
