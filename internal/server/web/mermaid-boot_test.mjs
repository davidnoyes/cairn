// Tests for mermaid-boot.js against a minimal fake element tree. Fixtures
// mirror real generator output; the pandoc one is captured from pandoc 3.11
// (`pandoc -f gfm -t html` on a ```mermaid fence).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeMermaidBlocks, render } from './mermaid-boot.js';

const TRANSPARENT = 'rgba(0, 0, 0, 0)';

class El {
  constructor(tagName, className = '', children = [], bg = TRANSPARENT) {
    this.nodeType = 1;
    this.tagName = tagName.toUpperCase();
    this.className = className;
    this.bg = bg;
    this.colorScheme = 'normal';
    this.parentNode = null;
    this.children = [];
    for (const c of children) this.append(c);
  }
  get classList() {
    return { contains: (c) => this.className.split(/\s+/).includes(c) };
  }
  append(c) {
    if (c instanceof El) c.parentNode = this;
    this.children.push(c);
  }
  get textContent() {
    return this.children.map((c) => (c instanceof El ? c.textContent : c)).join('');
  }
  set textContent(s) {
    this.children = [s];
  }
  replaceWith(el) {
    const siblings = this.parentNode.children;
    siblings[siblings.indexOf(this)] = el;
    el.parentNode = this.parentNode;
  }
}

// fakeDoc builds <html><body>…</body></html>. metaScheme is the content of a
// <meta name="color-scheme">, if any.
function fakeDoc(bodyChildren, { bodyBg = TRANSPARENT, metaScheme = null } = {}) {
  const body = new El('body', '', bodyChildren, bodyBg);
  const html = new El('html', '', [body]);
  const all = (el, tag) => el.children.filter((c) => c instanceof El)
    .flatMap((c) => (c.tagName === tag ? [c] : []).concat(all(c, tag)));
  return {
    body,
    documentElement: html,
    createElement: (tag) => new El(tag),
    getElementsByTagName: (tag) => all(html, tag.toUpperCase()),
    querySelector: (sel) => (sel === 'meta[name="color-scheme"]' && metaScheme !== null
      ? { getAttribute: () => metaScheme } : null),
  };
}

// fakeWin records mermaid calls. osDark is the prefers-color-scheme answer.
function fakeWin({ osDark = false } = {}) {
  const calls = [];
  return {
    calls,
    getComputedStyle: (el) => ({ backgroundColor: el.bg, colorScheme: el.colorScheme }),
    matchMedia: (q) => ({ matches: osDark && q === '(prefers-color-scheme: dark)' }),
    mermaid: {
      initialize: (c) => calls.push(['init', c.theme, c]),
      run: async (c) => { calls.push(['run', c.nodes.map((n) => n.textContent), c]); },
    },
  };
}

// themes returns the theme each run was rendered with, and its diagrams.
const themes = (win) => win.calls.filter((c) => c[0] === 'init')
  .map((c, i) => [c[1], win.calls.filter((r) => r[0] === 'run')[i][1]]);

// only returns the single child of body, asserting it is a plain-text
// <pre class="mermaid"> — the shape mermaid.run parses via innerHTML.
function only(doc) {
  assert.equal(doc.body.children.length, 1);
  const el = doc.body.children[0];
  assert.equal(el.tagName, 'PRE');
  return el;
}

function assertDiagram(el, text) {
  assert.equal(el.className, 'mermaid');
  assert.deepEqual(el.children, [text], 'no element children left for innerHTML to carry');
}

const diagram = (text, bg) => new El('pre', 'mermaid', [text], bg);

test('pandoc: unwraps the unclassed <code> inside <pre class="mermaid">', () => {
  const doc = fakeDoc([new El('pre', 'mermaid', [new El('code', '', ['graph TD\n  A --> B'])])]);
  normalizeMermaidBlocks(doc);
  assertDiagram(only(doc), 'graph TD\n  A --> B');
});

test('markdown-it / marked: <pre><code class="language-mermaid">', () => {
  const doc = fakeDoc([new El('pre', '', [new El('code', 'language-mermaid', ['graph LR'])])]);
  normalizeMermaidBlocks(doc);
  assertDiagram(only(doc), 'graph LR');
});

test('both classed: <pre class="mermaid"><code class="mermaid">', () => {
  const doc = fakeDoc([new El('pre', 'mermaid', [new El('code', 'mermaid', ['pie'])])]);
  normalizeMermaidBlocks(doc);
  assertDiagram(only(doc), 'pie');
});

test('bare <code class="mermaid"> outside a <pre> becomes a block', () => {
  const doc = fakeDoc([new El('code', 'mermaid', ['graph TD'])]);
  normalizeMermaidBlocks(doc);
  assertDiagram(only(doc), 'graph TD');
});

test('leaves already-plain <pre class="mermaid"> and other code alone', () => {
  const plain = diagram('graph TD');
  const js = new El('pre', 'sourceCode js', [new El('code', 'sourceCode javascript', ['x()'])]);
  const doc = fakeDoc([plain, js]);
  normalizeMermaidBlocks(doc);
  assert.equal(doc.body.children[0], plain);
  assert.equal(doc.body.children[1], js);
});

test('render keeps strict security and suppresses the aggregate error', async () => {
  const win = fakeWin();
  const doc = fakeDoc([diagram('graph TD')]);
  await render(win, doc);
  assert.deepEqual(win.calls[0][2], { startOnLoad: false, securityLevel: 'strict', theme: 'default' });
  assert.equal(win.calls[1][2].suppressErrors, true);
  assert.deepEqual(win.calls[1][2].nodes, [doc.body.children[0]]);
});

test('render does nothing without mermaid blocks', async () => {
  const win = fakeWin();
  await render(win, fakeDoc([new El('p', '', ['hi'])]));
  assert.deepEqual(win.calls, []);
});

test('a dark page background renders with the dark theme', async () => {
  const win = fakeWin();
  await render(win, fakeDoc([diagram('graph TD')], { bodyBg: 'rgb(11, 14, 19)' }));
  assert.deepEqual(themes(win), [['dark', ['graph TD']]]);
});

test('a light page background renders with the default theme, whatever the OS says', async () => {
  const win = fakeWin({ osDark: true });
  await render(win, fakeDoc([diagram('graph TD')], { bodyBg: 'rgb(255, 255, 255)' }));
  assert.deepEqual(themes(win), [['default', ['graph TD']]]);
});

test("the diagram's own background wins over the page's", async () => {
  const win = fakeWin();
  const doc = fakeDoc([diagram('light card', 'rgb(246, 248, 250)')], { bodyBg: 'rgb(11, 14, 19)' });
  await render(win, doc);
  assert.deepEqual(themes(win), [['default', ['light card']]]);
});

test('a fully transparent tree ignores the OS unless the page opts into dark', async () => {
  const win = fakeWin({ osDark: true });
  await render(win, fakeDoc([diagram('graph TD')]));
  assert.deepEqual(themes(win), [['default', ['graph TD']]]);
});

test('color-scheme "light dark" follows the OS on a transparent tree', async () => {
  for (const [osDark, want] of [[true, 'dark'], [false, 'default']]) {
    const win = fakeWin({ osDark });
    const doc = fakeDoc([diagram('graph TD')]);
    doc.documentElement.colorScheme = 'light dark';
    await render(win, doc);
    assert.deepEqual(themes(win), [[want, ['graph TD']]], `osDark=${osDark}`);
  }
});

test('color-scheme "dark" alone is dark, and a <meta name="color-scheme"> counts', async () => {
  const css = fakeWin();
  const doc = fakeDoc([diagram('css')]);
  doc.documentElement.colorScheme = 'dark';
  await render(css, doc);
  assert.deepEqual(themes(css), [['dark', ['css']]]);

  const meta = fakeWin({ osDark: true });
  await render(meta, fakeDoc([diagram('meta')], { metaScheme: 'light dark' }));
  assert.deepEqual(themes(meta), [['dark', ['meta']]]);
});

test('a semi-transparent background is blended over what is behind it', async () => {
  for (const [tint, want] of [['rgba(255, 255, 255, 0.9)', 'default'], ['rgba(255, 255, 255, 0.05)', 'dark']]) {
    const win = fakeWin();
    await render(win, fakeDoc([diagram('tint', tint)], { bodyBg: 'rgb(0, 0, 0)' }));
    assert.deepEqual(themes(win), [[want, ['tint']]], tint);
  }
});

test('an unparseable colour is skipped, not guessed', async () => {
  const win = fakeWin();
  await render(win, fakeDoc([diagram('graph TD', 'oklch(0.2 0 0)')], { bodyBg: 'rgb(11, 14, 19)' }));
  assert.deepEqual(themes(win), [['dark', ['graph TD']]]);
});

test('mixed backgrounds render each group with its theme, one run at a time', async () => {
  const win = fakeWin();
  let running = 0;
  const run = win.mermaid.run;
  win.mermaid.run = async (c) => {
    assert.equal(running++, 0, 'initialize must not change the theme under a running render');
    await new Promise((r) => setTimeout(r, 5));
    await run(c);
    running--;
  };
  const doc = fakeDoc([diagram('on page'), diagram('on card', 'rgb(246, 248, 250)'), diagram('also page')],
    { bodyBg: 'rgb(11, 14, 19)' });
  await render(win, doc);
  assert.deepEqual(themes(win), [['default', ['on card']], ['dark', ['on page', 'also page']]]);
});
