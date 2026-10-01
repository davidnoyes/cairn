/*
 * shell.js — link handling and Mermaid loading for the shared shell page.
 *
 * shell.html embeds an artifact in a same-origin <iframe> with no `target`
 * set, so every plain link click navigates the iframe. That is right for
 * links within the artifact, and wrong for the rest:
 *
 *  - another site: most refuse to be framed (X-Frame-Options /
 *    frame-ancestors), so the click looks like it did nothing. These open
 *    in a new tab.
 *  - another Cairn page (another artifact, /shared/…, /admin): it would load
 *    a second shell inside this one. These replace the whole page, so Back
 *    and the header's home link keep working.
 *
 * This script re-attaches a click listener to the iframe document on every
 * `load` (in-artifact navigation replaces the document, so the listener
 * needs reinstalling each time). On the same `load` it adds mermaid.js to a
 * document with Mermaid diagrams, so they render without the artifact
 * including it.
 */
(function (global) {
  'use strict';

  // linkAction decides what a click on an anchor in the artifact does.
  // href resolves against baseURI (the artifact document's); framePrefix is
  // the path of the artifact version in the frame. Returns {open: url} for a
  // new tab, {navigate: url} to replace the whole page, or null to let the
  // frame navigate (a link within this artifact version, or one whose
  // target already opens correctly on its own).
  function linkAction(href, target, baseTarget, baseURI, origin, framePrefix) {
    var effectiveTarget = target || baseTarget || '';
    if (effectiveTarget && effectiveTarget !== '_self') return null;

    var url;
    try {
      url = new URL(href, baseURI);
    } catch (e) {
      return null;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (url.origin !== origin) return { open: url.href };
    if (url.pathname.indexOf(framePrefix) === 0) return null;

    // An artifact's root opens in the shell, so its header stays. A deeper
    // path, query, or fragment has no shell equivalent: go as written.
    var root = /^\/artifacts\/([^/]+)(?:\/([^/]+))?\/?$/.exec(url.pathname);
    if (root && !url.search && !url.hash) {
      return { navigate: origin + '/shared/' + root[1] + (root[2] ? '/' + root[2] : '') };
    }
    return { navigate: url.href };
  }

  // install attaches the link click handler to an iframe's document.
  // Installing twice on one document is harmless: the first handler calls
  // preventDefault, so the second sees defaultPrevented and stands down.
  function install(frame, origin, open, navigate) {
    var doc = frame.contentDocument;
    if (!doc) return; // cross-origin (shouldn't happen; iframe is same-origin)
    addMermaid(frame, doc);

    doc.addEventListener('click', function (event) {
      // Bubble phase: let the artifact's own handlers run first.
      if (event.defaultPrevented) return;
      if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;

      var anchor = event.target.closest('a[href], area[href]');
      if (!anchor || anchor.hasAttribute('download')) return;

      var base = doc.querySelector('base[target]');
      var action = linkAction(
        anchor.getAttribute('href'),
        anchor.getAttribute('target') || '',
        base ? base.getAttribute('target') || '' : '',
        doc.baseURI,
        origin,
        new URL(frame.getAttribute('src'), origin).pathname
      );
      if (!action) return;

      event.preventDefault();
      if (action.open) open(action.open);
      else navigate(action.navigate);
    });
  }

  // addMermaid loads this version's mermaid.js into the artifact document
  // when it has diagrams and hasn't loaded Mermaid itself. The script is
  // served from the version's URL space, so an artifact's own mermaid.js
  // wins; a flag on the document stops a repeat install adding it twice.
  function addMermaid(frame, doc) {
    if (doc.__cairnMermaid || (frame.contentWindow && frame.contentWindow.mermaid)) return;
    if (!doc.querySelector('pre.mermaid, code.language-mermaid, code.mermaid')) return;
    doc.__cairnMermaid = true;
    var script = doc.createElement('script');
    script.src = frame.getAttribute('src') + 'mermaid.js';
    doc.body.appendChild(script);
  }

  // attach installs on every iframe load, and right away if the artifact
  // finished loading before this script ran (a single-file artifact often
  // does, since the iframe starts loading before deferred scripts execute).
  function attach(frame, origin, open, navigate) {
    frame.addEventListener('load', function () { install(frame, origin, open, navigate); });
    var doc = frame.contentDocument;
    if (doc && doc.readyState === 'complete') install(frame, origin, open, navigate);
  }

  // No `document` under Node (required from the test suite): only wire up
  // the browser behavior when actually running in a browser. The script is
  // loaded with `defer`, so the DOM is already parsed here.
  if (typeof document !== 'undefined') {
    var frame = document.querySelector('iframe');
    if (frame) {
      attach(frame, location.origin, function (url) {
        global.open(url, '_blank', 'noopener,noreferrer');
      }, function (url) {
        location.assign(url);
      });
    }
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { linkAction: linkAction, attach: attach };
  }
})(typeof window !== 'undefined' ? window : this);
