/*
 * mermaid-boot.js — auto-render bootstrap appended to the vendored Mermaid
 * bundle to make /mermaid.js.
 *
 * Normalizes the markup common diagram-generating tools emit for a mermaid
 * code fence, then renders every diagram once the DOM is ready:
 *
 *  - pandoc:                 <pre class="mermaid"><code>graph TD; ...</code></pre>
 *  - marked / markdown-it:   <pre><code class="language-mermaid">graph TD; ...</code></pre>
 *
 * Both end up as <pre class="mermaid">graph TD; ...</pre>. The unwrapping is
 * required, not cosmetic: mermaid.run reads each block's innerHTML, so a
 * leftover <code> tag reaches the diagram parser as text and fails. Safe to
 * include from more than one place (the shell frame and an artifact's own
 * <script> tag): a window-level flag makes the second run a no-op.
 */
(function (global) {
  "use strict";

  // normalizeMermaidBlocks replaces each mermaid <code> — classed itself, or
  // inside a <pre class="mermaid"> — and its wrapping <pre> with a
  // <pre class="mermaid"> holding only the code's text.
  function normalizeMermaidBlocks(doc) {
    var codes = Array.prototype.slice.call(doc.getElementsByTagName("code"));
    for (var i = 0; i < codes.length; i++) {
      var code = codes[i];
      var parent = code.parentNode;
      var inPre = parent && parent.tagName === "PRE";
      var isMermaid = code.classList.contains("mermaid") ||
        code.classList.contains("language-mermaid") ||
        (inPre && parent.classList.contains("mermaid"));
      if (!isMermaid) continue;
      var block = doc.createElement("pre");
      block.className = "mermaid";
      block.textContent = code.textContent;
      (inPre ? parent : code).replaceWith(block);
    }
  }

  // parseColor reads a computed "rgb(…)" or "rgba(…)" value as [r, g, b, a].
  // Anything else (oklch(), color(), …) returns null and is skipped.
  function parseColor(s) {
    var m = /^rgba?\(([^)]*)\)$/.exec(s || "");
    if (!m) return null;
    var v = m[1].split(/[\s,/]+/).map(Number);
    return [v[0], v[1], v[2], v.length > 3 ? v[3] : 1];
  }

  // gradientColor averages the rgb()/rgba() stops of a computed
  // background-image gradient, or returns null when it has none. An image
  // url() cannot be read, so it is ignored.
  function gradientColor(s) {
    var stops = (s || "").match(/rgba?\([^)]*\)/g);
    if (!stops) return null;
    var sum = [0, 0, 0, 0];
    for (var i = 0; i < stops.length; i++) {
      var c = parseColor(stops[i]);
      for (var k = 0; k < 4; k++) sum[k] += c[k] / stops.length;
    }
    return sum;
  }

  // canvasColor approximates the page canvas behind a transparent <html>:
  // dark only when the page opts into a dark color-scheme (CSS or <meta>)
  // and that scheme is in use; browsers draw white otherwise.
  function canvasColor(win, doc) {
    var scheme = win.getComputedStyle(doc.documentElement).colorScheme || "normal";
    var meta = doc.querySelector('meta[name="color-scheme"]');
    if (scheme === "normal" && meta) scheme = meta.getAttribute("content") || "";
    var dark = /\bdark\b/.test(scheme) &&
      (!/\blight\b/.test(scheme) || win.matchMedia("(prefers-color-scheme: dark)").matches);
    return dark ? [18, 18, 18, 1] : [255, 255, 255, 1];
  }

  // backgroundIsDark composites the background colors (a gradient over its
  // element's background-color) from el up to the first opaque one (or the
  // canvas) and reports whether the result is closer to black than white,
  // by WCAG relative luminance.
  function backgroundIsDark(win, doc, el) {
    var layers = [];
    walk: for (var node = el; node && node.nodeType === 1; node = node.parentNode) {
      var style = win.getComputedStyle(node);
      var own = [gradientColor(style.backgroundImage), parseColor(style.backgroundColor)];
      for (var j = 0; j < own.length; j++) {
        var c = own[j];
        if (!c || c[3] === 0) continue;
        layers.push(c);
        if (c[3] >= 1) break walk;
      }
    }
    var base = layers.length && layers[layers.length - 1][3] >= 1 ? layers.pop() : canvasColor(win, doc);
    for (var i = layers.length - 1; i >= 0; i--) {
      for (var k = 0; k < 3; k++) base[k] = layers[i][k] * layers[i][3] + base[k] * (1 - layers[i][3]);
    }
    var lum = [0.2126, 0.7152, 0.0722].reduce(function (sum, w, k) {
      var c = base[k] / 255;
      return sum + w * (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
    }, 0);
    return lum < 0.179;
  }

  // render normalizes doc and draws its diagrams with win.mermaid, in
  // Mermaid's dark theme where the diagram sits on a dark background. The
  // theme is global, so each group is initialized and run in turn. A syntax
  // error still shows Mermaid's error box in place of that one diagram;
  // suppressErrors only stops run() rejecting for the whole page.
  async function render(win, doc) {
    normalizeMermaidBlocks(doc);
    if (!win.mermaid) return;
    var groups = { default: [], dark: [] };
    var pres = doc.getElementsByTagName("pre");
    for (var i = 0; i < pres.length; i++) {
      if (!pres[i].classList.contains("mermaid")) continue;
      groups[backgroundIsDark(win, doc, pres[i]) ? "dark" : "default"].push(pres[i]);
    }
    for (var theme in groups) {
      if (!groups[theme].length) continue;
      win.mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: theme });
      await win.mermaid.run({ nodes: groups[theme], suppressErrors: true });
    }
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { normalizeMermaidBlocks: normalizeMermaidBlocks, render: render };
  }

  // The bundle renders every .mermaid block on load by itself, before render
  // has unwrapped the <code>, which it then shows as a syntax error. Turn
  // that off on each copy of the bundle, even a second one, so render is the
  // only one to draw.
  if (global.mermaid) global.mermaid.startOnLoad = false;

  if (typeof document === "undefined" || global.__cairnMermaidBooted) return;
  global.__cairnMermaidBooted = true;

  // Wait for load, as Mermaid's own startOnLoad does, so every stylesheet
  // has applied before backgrounds are read.
  var boot = function () { render(global, document); };
  if (document.readyState === "complete") {
    boot();
  } else {
    global.addEventListener("load", boot);
  }
})(this);
