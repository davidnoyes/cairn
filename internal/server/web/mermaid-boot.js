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

  function hasDiagrams(doc) {
    var pres = doc.getElementsByTagName("pre");
    for (var i = 0; i < pres.length; i++) {
      if (pres[i].classList.contains("mermaid")) return true;
    }
    return false;
  }

  // render normalizes doc and draws its diagrams with win.mermaid. A syntax
  // error still shows Mermaid's error box in place of that one diagram;
  // suppressErrors only stops run() rejecting for the whole page.
  function render(win, doc) {
    normalizeMermaidBlocks(doc);
    if (!hasDiagrams(doc) || !win.mermaid) return;
    win.mermaid.initialize({ startOnLoad: false, securityLevel: "strict" });
    win.mermaid.run({ querySelector: ".mermaid", suppressErrors: true });
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { normalizeMermaidBlocks: normalizeMermaidBlocks, render: render };
  }

  if (typeof document === "undefined" || global.__cairnMermaidBooted) return;
  global.__cairnMermaidBooted = true;

  var boot = function () { render(global, document); };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})(this);
