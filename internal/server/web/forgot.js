// forgot.js — asks for a reset link. The answer is the same for every
// address, so this page cannot reveal which have accounts. On a Google server
// the Google sign-in stands in for the mailed link: the server answers with
// the link's token, and the page carries on to /reset with it.
import { forgot, forgotWithGoogle, googleIdentity } from './account.mjs';
import { $, googleStartURL, networkFetch, onSubmit } from './ui.mjs';

const deps = { fetch: networkFetch((path, options) => fetch(path, options)) };
const form = $('form');

if (document.body.dataset.google === '1') {
  form.hidden = true;
  $('google-start').href = googleStartURL('/forgot', '');
  const who = await googleIdentity(deps).catch(() => null);
  if (who) {
    $('google-email').textContent = who.email;
    const googleForm = $('google-form');
    googleForm.hidden = false;
    onSubmit(googleForm, $('google-submit'), $('google-error'), async () => {
      const token = await forgotWithGoogle(deps);
      location.href = '/reset#token=' + token;
    });
  } else {
    $('google').hidden = false;
  }
} else {
  onSubmit(form, $('submit'), $('error'), async () => {
    $('message').textContent = await forgot(deps, { email: form.email.value });
    form.hidden = true;
    $('sent').hidden = false;
  });
}
