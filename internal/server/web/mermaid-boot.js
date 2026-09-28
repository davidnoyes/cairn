/*
 * mermaid-boot.js — auto-render bootstrap appended to the vendored Mermaid
 * bundle to make /mermaid.js.
 *
 * Normalizes the markup common diagram-generating tools emit for a
 * ```mermaid fence, then renders every diagram once the DOM is ready:
 *
 *  - pandoc:                 <pre class="mermaid"><code>graph TD; ...</code></pre>
 *  - marked / markdown-it:   <pre><code class="language-mermaid">graph TD; ...</code></pre>
 *
 * Both end up as <pre class="mermaid">graph TD; ...</pre>, which is what
 * mermaid.run({querySelector: '.mermaid'}) expects. Safe to include from more
 * than one place (the shell frame and an artifact's own <script> tag): a
 * window-level flag makes the second run a no-op.
 */
(function () {
  "use strict";

  // normalizeMermaidBlocks turns <code class="language-mermaid"> or
  // <code class="mermaid"> (not already wrapped in <pre class="mermaid">)
  // into a <pre class="mermaid"> holding the code's text.
  function normalizeMermaidBlocks(doc) {
    var codes = doc.querySelectorAll("code.language-mermaid, code.mermaid");
    for (var i = 0; i < codes.length; i++) {
      var code = codes[i];
      var pre = code.closest("pre");
      if (code.classList.contains("mermaid") && pre && pre.classList.contains("mermaid")) {
        continue; // already normalized (pandoc-style)
      }
      var block = doc.createElement("pre");
      block.className = "mermaid";
      block.textContent = code.textContent;
      if (pre) {
        pre.replaceWith(block);
      } else {
        code.replaceWith(block);
      }
    }
  }

  function render() {
    normalizeMermaidBlocks(document);
    if (!document.querySelector(".mermaid")) return;
    if (typeof window.mermaid === "undefined") return;
    window.mermaid.initialize({ startOnLoad: false, securityLevel: "strict" });
    window.mermaid.run({ querySelector: ".mermaid" });
  }

  if (window.__cairnMermaidBooted) return;
  window.__cairnMermaidBooted = true;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", render);
  } else {
    render();
  }
})();
