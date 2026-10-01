// verify.js — follows an emailed verification link: the token comes from the
// URL fragment, leaves the address bar, and is then posted.
import { verifyFromLink } from './account.mjs';
import { $, describeError } from './ui.mjs';

const deps = { fetch: (path, options) => fetch(path, options) };

try {
  await verifyFromLink(deps, { location, history });
  $('ok').hidden = false;
  $('signin').hidden = false;
} catch (err) {
  $('error').textContent = describeError(err);
  $('error').hidden = false;
  $('again').hidden = false;
} finally {
  $('working').hidden = true;
}
