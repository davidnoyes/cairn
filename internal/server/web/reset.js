// reset.js — finishes an emailed password reset. The token comes from the URL
// fragment and leaves the address bar before the first request. With the
// recovery code the account keeps its keys; without it, it gets new ones.
import { resetBeginFromLink, resetWithRecovery, resetWithoutRecovery } from './account.mjs';
import { $, startPage, onSubmit, watchStrength, confirmRecoveryCode, describeError } from './ui.mjs';

const form = $('form');
const deps = await startPage({ form, errorEl: $('linkError') });

let session; // {token, info}, held in memory because the address bar no longer has it
if (deps) {
  try {
    session = await resetBeginFromLink(deps, { location, history });
  } catch (err) {
    $('linkError').textContent = describeError(err);
    $('linkError').hidden = false;
    $('linkLinks').hidden = false;
  }
}
$('working').hidden = true;

if (session) {
  $('account').textContent = `Resetting the password for ${session.info.email}.`;
  form.hidden = false;
  watchStrength(deps, form.password, $('strength'), () => [session.info.email]);

  const mode = () => form.mode.value;
  const syncMode = () => {
    $('codeRow').hidden = mode() !== 'recovery';
    $('warning').hidden = mode() !== 'new';
  };
  for (const radio of form.querySelectorAll('input[name=mode]')) radio.addEventListener('change', syncMode);

  onSubmit(form, $('submit'), $('error'), async () => {
    const { token, info } = session;
    const fields = { token, info, password: form.password.value, confirm: form.confirm.value };
    if (mode() === 'recovery') {
      await resetWithRecovery(deps, { ...fields, recoveryCode: form.code.value });
      form.hidden = true;
      $('done').hidden = false;
      return;
    }
    const { recoveryCode } = await resetWithoutRecovery(deps, fields);
    form.hidden = true;
    confirmRecoveryCode(
      {
        form: $('confirmForm'), panel: $('recovery'), codeEl: $('newCode'), promptEl: $('groupPrompt'),
        input: $('group'), errorEl: $('confirmError'),
      },
      recoveryCode,
      () => { $('done').hidden = false; },
    );
  });
}
