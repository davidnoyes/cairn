// cli.js — the page that hands a Google proof to the command-line tool. The
// server put the tool's port and state in the body's data attributes.
import { googleIdentity } from './account.mjs';
import { googleSignInURL, handOver } from './cli.mjs';
import { $, networkFetch, onSubmit } from './ui.mjs';

const deps = { fetch: networkFetch((path, options) => fetch(path, options)) };
const port = Number(document.body.dataset.port);
const state = document.body.dataset.state;

const who = await googleIdentity(deps).catch((err) => {
  $('error').textContent = err.message;
  $('error').hidden = false;
});
if (who === null) {
  location.assign(googleSignInURL(location));
} else if (who) {
  $('email').textContent = who.email;
  $('form').hidden = false;
  onSubmit($('form'), $('submit'), $('error'), async () => {
    location.assign(await handOver(deps, { port, state }));
  });
}
