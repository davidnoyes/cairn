/*
 * frame.js — the script the service worker adds at the start of every HTML
 * page of an artifact, on the content origin (/_cairn/frame.js).
 *
 * The page runs inside the shell's sandboxed iframe, so it cannot navigate
 * the top page and most sites refuse to be framed. This script:
 *
 *  - sends link clicks where they belong: another site opens in a new tab,
 *    a Cairn shell page (/shared/…) or the app origin goes to the shell as a
 *    `navigate` message (the shell decides), and anything else on this
 *    origin navigates the frame as usual;
 *  - adds mermaid.js to a page with Mermaid diagrams, so they render
 *    without the artifact including it;
 *  - carries `keys` and `token` messages from the shell to the worker, and
 *    the worker's `need-keys` requests to the shell.
 *
 * The app origin comes from the controlling worker's script URL
 * (?app=<origin>), which the boot page set. With none, nothing is posted to
 * the shell and nothing is relayed.
 */
(function (global) {
  'use strict';

  var UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
  var SHELL_PATH = new RegExp('^/shared/' + UUID + '(?:/' + UUID + ')?/?$');

  // appOriginFrom reads the app origin from a worker script URL, as sw.js
  // does, or returns null when it is missing or is not an http(s) origin.
  function appOriginFrom(href) {
    try {
      var u = new URL(new URL(href).searchParams.get('app'));
      return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : null;
    } catch (e) {
      return null;
    }
  }

  // linkAction decides what a click on a link does. href resolves against
  // baseURI. Returns {open: url} for a new tab, {navigate: href} to tell the
  // shell, or null to let the frame navigate. appOrigin may be null, which
  // leaves nothing to tell the shell.
  function linkAction(href, baseURI, contentOrigin, appOrigin) {
    var url;
    try {
      url = new URL(href, baseURI);
    } catch (e) {
      return null;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (url.origin === contentOrigin) {
      if (appOrigin && SHELL_PATH.test(url.pathname)) return { navigate: url.pathname };
      return null;
    }
    if (appOrigin && url.origin === appOrigin) return { navigate: url.href };
    return { open: url.href };
  }

  // addMermaid adds /_cairn/mermaid.js to a page with diagrams that has not
  // loaded Mermaid itself. mermaid-boot.js guards against running twice.
  function addMermaid(win, doc) {
    if (win.mermaid || doc.querySelector('script[src$="mermaid.js"]')) return;
    if (!doc.querySelector('pre.mermaid, code.language-mermaid, code.mermaid')) return;
    var script = doc.createElement('script');
    script.src = '/_cairn/mermaid.js';
    doc.body.appendChild(script);
  }

  // install wires the page. The controller and its app origin are read at
  // each use: the page may be controlled only after this script has run.
  function install(win, doc, nav) {
    var sw = nav.serviceWorker;
    var appOrigin = function () {
      return sw && sw.controller ? appOriginFrom(sw.controller.scriptURL) : null;
    };

    doc.addEventListener('click', function (event) {
      if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      var anchor = event.target.closest && event.target.closest('a[href], area[href]');
      if (!anchor || anchor.hasAttribute('download')) return;
      var base = doc.querySelector('base[target]');
      var target = anchor.getAttribute('target') || (base && base.getAttribute('target')) || '';
      if (target && target !== '_self') return;

      var action = linkAction(anchor.getAttribute('href'), doc.baseURI, win.location.origin, appOrigin());
      if (!action) return;
      event.preventDefault();
      if (action.open) win.open(action.open, '_blank', 'noopener,noreferrer');
      else win.parent.postMessage({ cairn: 'navigate', href: action.navigate }, appOrigin());
    }, true);

    win.addEventListener('message', function (event) {
      var origin = appOrigin();
      if (!origin || event.source !== win.parent || event.origin !== origin) return;
      var data = event.data;
      if (!data || (data.cairn !== 'keys' && data.cairn !== 'token')) return;
      sw.controller.postMessage(data);
    });

    if (sw) {
      sw.addEventListener('message', function (event) {
        var origin = appOrigin();
        var data = event.data;
        if (!origin || event.source !== sw.controller) return;
        if (!data || data.cairn !== 'need-keys' || typeof data.version !== 'string') return;
        win.parent.postMessage({ cairn: 'need-keys', version: data.version }, origin);
      });
    }

    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', function () { addMermaid(win, doc); }, { once: true });
    } else {
      addMermaid(win, doc);
    }
  }

  if (typeof document !== 'undefined') install(global, document, navigator);

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { appOriginFrom: appOriginFrom, linkAction: linkAction, install: install };
  }
})(typeof window !== 'undefined' ? window : this);
