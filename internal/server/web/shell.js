/*
 * shell.js — external-link handling for the shared shell page.
 *
 * shell.html embeds an artifact in a same-origin <iframe> with no `target`
 * set. When a click inside the artifact hits a link to another site, the
 * iframe itself navigates there, and most sites refuse to be framed
 * (X-Frame-Options / frame-ancestors) — the click looks like it did nothing.
 * This script re-attaches a click listener to the iframe document on every
 * `load` (in-artifact navigation replaces the document, so the listener
 * needs reinstalling each time) and reroutes external links to a new tab.
 */
(function (global) {
  'use strict';

  // externalLinkTarget decides whether a clicked anchor should be opened in a
  // new tab instead of letting the iframe navigate. Returns the absolute URL
  // to open, or null when the click should be left alone (native handling
  // already works, or the link isn't a same-window external navigation).
  function externalLinkTarget(href, target, baseTarget, origin) {
    var effectiveTarget = target || baseTarget || '';
    // Anything other than empty/_self already opens correctly on its own.
    if (effectiveTarget && effectiveTarget !== '_self') return null;

    var url;
    try {
      url = new URL(href, origin);
    } catch (e) {
      return null;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (url.origin === origin) return null;
    return url.href;
  }

  // install attaches the external-link click handler to an iframe's document.
  // Installing twice on one document is harmless: the first handler calls
  // preventDefault, so the second sees defaultPrevented and stands down.
  function install(frame, origin, open) {
    var doc = frame.contentDocument;
    if (!doc) return; // cross-origin (shouldn't happen; iframe is same-origin)

    doc.addEventListener('click', function (event) {
      // Bubble phase: let the artifact's own handlers run first.
      if (event.defaultPrevented) return;
      if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;

      var anchor = event.target.closest('a[href], area[href]');
      if (!anchor || anchor.hasAttribute('download')) return;

      var base = doc.querySelector('base[target]');
      var url = externalLinkTarget(
        anchor.getAttribute('href'),
        anchor.getAttribute('target') || '',
        base ? base.getAttribute('target') || '' : '',
        origin
      );
      if (!url) return;

      event.preventDefault();
      open(url);
    });
  }

  // attach installs on every iframe load, and right away if the artifact
  // finished loading before this script ran (a single-file artifact often
  // does, since the iframe starts loading before deferred scripts execute).
  function attach(frame, origin, open) {
    frame.addEventListener('load', function () { install(frame, origin, open); });
    var doc = frame.contentDocument;
    if (doc && doc.readyState === 'complete') install(frame, origin, open);
  }

  // No `document` under Node (required from the test suite): only wire up
  // the browser behavior when actually running in a browser. The script is
  // loaded with `defer`, so the DOM is already parsed here.
  if (typeof document !== 'undefined') {
    var frame = document.querySelector('iframe');
    if (frame) {
      attach(frame, location.origin, function (url) {
        global.open(url, '_blank', 'noopener,noreferrer');
      });
    }
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { externalLinkTarget: externalLinkTarget, attach: attach };
  }
})(typeof window !== 'undefined' ? window : this);
