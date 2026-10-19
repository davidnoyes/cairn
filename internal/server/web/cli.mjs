// cli.mjs — the logic of the command-line sign-in page: where to send the
// browser for Google, and the hand-over of a proof to the tool's loopback
// listener. cli.js wires it to the page.
import { ApiError } from './account.mjs';

// googleSignInURL is where to send a browser with no Google proof: through
// Google and back to this same page, query included.
export function googleSignInURL(location) {
  return '/auth/google?next=' + encodeURIComponent(location.pathname + location.search);
}

// isLoopbackRedirect reports whether redirect is the tool's callback on this
// port, and nothing else. The page must not follow an address the server
// sent that points anywhere but the tool.
export function isLoopbackRedirect(redirect, port) {
  return typeof redirect === 'string' && redirect.startsWith(`http://127.0.0.1:${port}/callback?`);
}

// handOver asks the server for a proof the tool can carry and returns the
// loopback address to open, which carries it. It throws when the server
// refuses, or answers with an address that is not the tool's.
export async function handOver(deps, { port, state }) {
  const resp = await deps.fetch('/api/auth/cli', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ port, state }),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new ApiError(data.error || `request failed (${resp.status})`, resp.status);
  if (!isLoopbackRedirect(data.redirect, port)) throw new Error('The server named an address that is not the command-line tool. Nothing was sent.');
  return data.redirect;
}
