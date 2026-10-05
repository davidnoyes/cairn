// refuse.js — refuses a successor's request for access. It needs no session,
// so it works for a deactivated account: the password or the recovery code
// proves who is asking.
import { refuseWithPassword, refuseWithRecovery } from './account.mjs';
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

  // date is the day of an RFC 3339 time.
  const date = (time) => time.slice(0, 10);

  onSubmit(form, $('submit'), $('error'), async () => {
    const email = form.email.value;
    const answer = mode() === 'password'
      ? await refuseWithPassword(deps, { email, password: form.password.value })
      : await refuseWithRecovery(deps, { email, recoveryCode: form.code.value });
    const { name, email: theirs } = answer.successor;
    const who = name ? `${name} (${theirs})` : theirs;
    $('done-text').textContent = `You refused the request that ${who} made on ${date(answer.requestedAt)}. ` +
      'They stay your successor; to remove them, use the Successor tab or run cairn successor remove.';
    if (answer.deactivatedAt) {
      $('deactivated').textContent = `An administrator deactivated your account on ${date(answer.deactivatedAt)}, while the request was pending.`;
      $('deactivated').hidden = false;
    }
    form.hidden = true;
    $('done').hidden = false;
  });
}
