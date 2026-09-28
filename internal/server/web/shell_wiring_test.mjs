// Wiring tests for shell.js: attach/install against a minimal fake DOM, so
// the click handling is exercised without a browser.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { attach } from './shell.js';

const ORIGIN = 'https://cairn.example';

function fakeDoc({ readyState = 'complete', baseTarget = null } = {}) {
  const doc = new EventTarget();
  doc.readyState = readyState;
  doc.querySelector = (sel) =>
    sel === 'base[target]' && baseTarget ? { getAttribute: () => baseTarget } : null;
  return doc;
}

function fakeAnchor(attrs) {
  return {
    getAttribute: (k) => (k in attrs ? attrs[k] : null),
    hasAttribute: (k) => k in attrs,
    closest() { return this; },
  };
}

// click dispatches a cancelable click whose target is (inside) the anchor.
function click(doc, anchor, init = {}) {
  const ev = new Event('click', { cancelable: true });
  Object.assign(ev, { button: 0, metaKey: false, ctrlKey: false, shiftKey: false, altKey: false }, init);
  Object.defineProperty(ev, 'target', { value: anchor });
  doc.dispatchEvent(ev);
  return ev;
}

function setup(docOpts) {
  const frame = new EventTarget();
  frame.contentDocument = fakeDoc(docOpts);
  const opened = [];
  attach(frame, ORIGIN, (url) => opened.push(url));
  return { frame, opened };
}

test('installs immediately when the iframe already finished loading', () => {
  const { frame, opened } = setup();
  const ev = click(frame.contentDocument, fakeAnchor({ href: 'https://example.com/' }));
  assert.deepEqual(opened, ['https://example.com/']);
  assert.equal(ev.defaultPrevented, true);
});

test('a later load on the same document still opens only one tab', () => {
  const { frame, opened } = setup();
  frame.dispatchEvent(new Event('load'));
  click(frame.contentDocument, fakeAnchor({ href: 'https://example.com/' }));
  assert.equal(opened.length, 1);
});

test('reinstalls on the new document after in-frame navigation', () => {
  const { frame, opened } = setup({ readyState: 'loading' });
  frame.contentDocument = fakeDoc();
  frame.dispatchEvent(new Event('load'));
  click(frame.contentDocument, fakeAnchor({ href: 'https://example.com/' }));
  assert.deepEqual(opened, ['https://example.com/']);
});

test('leaves same-origin, modified, download and handled clicks alone', () => {
  const { frame, opened } = setup();
  const doc = frame.contentDocument;
  const ext = { href: 'https://example.com/' };
  const cases = [
    click(doc, fakeAnchor({ href: './page.html' })),
    click(doc, fakeAnchor(ext), { metaKey: true }),
    click(doc, fakeAnchor(ext), { button: 1 }),
    click(doc, fakeAnchor({ ...ext, download: '' })),
    click(doc, fakeAnchor({ ...ext, target: '_blank' })),
  ];
  assert.deepEqual(opened, []);
  assert.ok(cases.every((ev) => !ev.defaultPrevented));

  const handled = new Event('click', { cancelable: true });
  handled.preventDefault();
  Object.assign(handled, { button: 0 });
  Object.defineProperty(handled, 'target', { value: fakeAnchor(ext) });
  doc.dispatchEvent(handled);
  assert.deepEqual(opened, []);
});

test('honors <base target="_blank"> in the artifact document', () => {
  const { frame, opened } = setup({ baseTarget: '_blank' });
  click(frame.contentDocument, fakeAnchor({ href: 'https://example.com/' }));
  assert.deepEqual(opened, []);
});
