// Tests for mermaid-boot.js against a minimal fake element tree. Fixtures
// mirror real generator output; the pandoc one is captured from pandoc 3.11
// (`pandoc -f gfm -t html` on a ```mermaid fence).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeMermaidBlocks, render } from './mermaid-boot.js';

class El {
  constructor(tagName, className = '', children = []) {
    this.tagName = tagName.toUpperCase();
    this.className = className;
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

function fakeDoc(...bodyChildren) {
  const body = new El('body', '', bodyChildren);
  const all = (el, tag) => el.children.filter((c) => c instanceof El)
    .flatMap((c) => (c.tagName === tag ? [c] : []).concat(all(c, tag)));
  return {
    body,
    createElement: (tag) => new El(tag),
    getElementsByTagName: (tag) => all(body, tag.toUpperCase()),
  };
}

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

test('pandoc: unwraps the unclassed <code> inside <pre class="mermaid">', () => {
  const doc = fakeDoc(new El('pre', 'mermaid', [new El('code', '', ['graph TD\n  A --> B'])]));
  normalizeMermaidBlocks(doc);
  assertDiagram(only(doc), 'graph TD\n  A --> B');
});

test('markdown-it / marked: <pre><code class="language-mermaid">', () => {
  const doc = fakeDoc(new El('pre', '', [new El('code', 'language-mermaid', ['graph LR'])]));
  normalizeMermaidBlocks(doc);
  assertDiagram(only(doc), 'graph LR');
});

test('both classed: <pre class="mermaid"><code class="mermaid">', () => {
  const doc = fakeDoc(new El('pre', 'mermaid', [new El('code', 'mermaid', ['pie'])]));
  normalizeMermaidBlocks(doc);
  assertDiagram(only(doc), 'pie');
});

test('bare <code class="mermaid"> outside a <pre> becomes a block', () => {
  const doc = fakeDoc(new El('code', 'mermaid', ['graph TD']));
  normalizeMermaidBlocks(doc);
  assertDiagram(only(doc), 'graph TD');
});

test('leaves already-plain <pre class="mermaid"> and other code alone', () => {
  const plain = new El('pre', 'mermaid', ['graph TD']);
  const js = new El('pre', 'sourceCode js', [new El('code', 'sourceCode javascript', ['x()'])]);
  const doc = fakeDoc(plain, js);
  normalizeMermaidBlocks(doc);
  assert.equal(doc.body.children[0], plain);
  assert.equal(doc.body.children[1], js);
});

test('render suppresses the aggregate error so one bad diagram does not reject', () => {
  const calls = [];
  const mermaid = { initialize: (c) => calls.push(['init', c]), run: (c) => calls.push(['run', c]) };
  const doc = fakeDoc(new El('pre', 'mermaid', ['graph TD']));
  render({ mermaid }, doc);
  assert.deepEqual(calls, [
    ['init', { startOnLoad: false, securityLevel: 'strict' }],
    ['run', { querySelector: '.mermaid', suppressErrors: true }],
  ]);
});

test('render does nothing without mermaid blocks', () => {
  const calls = [];
  const mermaid = { initialize: () => calls.push('init'), run: () => calls.push('run') };
  render({ mermaid }, fakeDoc(new El('p', '', ['hi'])));
  assert.deepEqual(calls, []);
});
