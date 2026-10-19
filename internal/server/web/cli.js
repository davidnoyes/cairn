// cli.js — the page that hands a Google proof to the command-line tool. The
// server put the tool's port and state in the body's data attributes.
import { googleIdentity } from './account.mjs';
import { googleSignInURL, handOver } from './cli.mjs';
import { $, networkFetch, onSubmit } from './ui.mjs';

const deps = { fetch: networkFetch((path, options) => fetch(path, options)) };
const port = Number(document.body.dataset.port);
const state = document.body.dataset.state;
// TRIED marks a trip through Google this tab already made. Coming back still
// without a proof means the browser did not keep the proof cookie, so the
// page says so rather than sending the person round again.
const TRIED = 'cairn-cli-google-tried';

function showError(message) {
  $('error').textContent = message;
  $('error').hidden = false;
}

// offerRestart shows a link back through Google: a failed hand-over has
// already used the proof, so trying again needs a new one.
function offerRestart() {
  $('again-link').href = googleSignInURL(location);
  $('again').hidden = false;
}

const who = await googleIdentity(deps).catch((err) => {
  showError(err.message);
});
if (who === null) {
  if (sessionStorage.getItem(TRIED)) {
    sessionStorage.removeItem(TRIED);
    showError('Your browser did not keep the Google sign-in. Allow cookies for this site, then try again.');
    offerRestart();
  } else {
    sessionStorage.setItem(TRIED, '1');
    location.assign(googleSignInURL(location));
  }
} else if (who) {
  sessionStorage.removeItem(TRIED);
  $('email').textContent = who.email;
  $('form').hidden = false;
  onSubmit($('form'), $('submit'), $('error'), async () => {
    try {
      location.assign(await handOver(deps, { port, state }));
    } catch (err) {
      offerRestart();
      throw err;
    }
  });
}
