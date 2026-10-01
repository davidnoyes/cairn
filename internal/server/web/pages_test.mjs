// A source scan of the account pages' scripts for what the app CSP refuses:
// require-trusted-types-for 'script' blocks string assignments to HTML sinks,
// eval, new Function, and string timers. The CSP only fails in a browser, and
// no test here drives one, so this is a backstop: the behavior tests in
// account_test.mjs are the real coverage. The HTML half of the scan is in
// internal/server/pages_test.go.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const PAGE_SCRIPTS = [
  'signup.js', 'verify.js', 'login.js', 'forgot.js', 'reset.js', 'admin.js',
  'account.mjs', 'keystore.mjs', 'argon2-client.mjs', 'ui.mjs', 'e2e.mjs', 'argon2-worker.js',
];

const SINKS = [
  [/\.innerHTML\b/, 'innerHTML'],
  [/\.outerHTML\b/, 'outerHTML'],
  [/\binsertAdjacentHTML\b/, 'insertAdjacentHTML'],
  [/\bdocument\.write(ln)?\b/, 'document.write'],
  [/\beval\s*\(/, 'eval'],
  [/\bnew\s+Function\b|\bFunction\s*\(/, 'Function constructor'],
  [/\b(setTimeout|setInterval)\s*\(\s*['"`]/, 'string timer'],
  [/\.srcdoc\b/, 'srcdoc'],
  [/\bcreateContextualFragment\b/, 'createContextualFragment'],
  [/\bDOMParser\b/, 'DOMParser'],
  [/\.setAttribute\s*\(\s*['"](src|href|on\w+|srcdoc)['"]/i, 'setAttribute on a URL or handler'],
  [/\.src\s*=/, 'script src assignment'],
];

// stripComments removes comments, so prose that names a sink is not flagged.
function stripComments(source) {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');
}

function findSinks(source) {
  const code = stripComments(source);
  return SINKS.filter(([re]) => re.test(code)).map(([, name]) => name);
}

test('the scan flags each sink in a sample', () => {
  const samples = {
    innerHTML: 'el.innerHTML = x;',
    outerHTML: 'el.outerHTML = x;',
    insertAdjacentHTML: 'el.insertAdjacentHTML("beforeend", x);',
    'document.write': 'document.write(x);',
    eval: 'eval(x);',
    'Function constructor': 'new Function("return 1");',
    'string timer': 'setTimeout("go()", 10);',
    srcdoc: 'frame.srcdoc = x;',
    'script src assignment': 's.src = "/x.js";',
    'setAttribute on a URL or handler': 'a.setAttribute("onclick", "x()");',
  };
  for (const [name, source] of Object.entries(samples)) {
    assert.ok(findSinks(source).includes(name), name);
  }
  assert.deepEqual(findSinks('// uses innerHTML never\nel.textContent = x; setTimeout(fn, 5);'), []);
});

for (const file of PAGE_SCRIPTS) {
  test(`${file} has no Trusted Types sink`, () => {
    const source = readFileSync(new URL(`./${file}`, import.meta.url), 'utf8');
    assert.deepEqual(findSinks(source), []);
  });
}
