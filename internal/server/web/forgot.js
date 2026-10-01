// forgot.js — asks for a reset link. The answer is the same for every
// address, so this page cannot reveal which have accounts.
import { forgot } from './account.mjs';
import { $, onSubmit } from './ui.mjs';

const deps = { fetch: (path, options) => fetch(path, options) };
const form = $('form');

onSubmit(form, $('submit'), $('error'), async () => {
  $('message').textContent = await forgot(deps, { email: form.email.value });
  form.hidden = true;
  $('sent').hidden = false;
});
