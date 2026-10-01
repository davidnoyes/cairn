// ESLint for the browser assets embedded in the binary. Vendored files are
// third-party and stay byte-identical to upstream, so they are not linted.
import js from '@eslint/js';
import globals from 'globals';

export default [
  { ignores: ['internal/server/web/vendor/**', 'examples/**', 'docs/**', 'node_modules/**'] },
  js.configs.recommended,
  {
    files: ['internal/server/web/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      // module is read only to export helpers to the Node tests.
      globals: { ...globals.browser, ...globals.serviceworker, module: 'readonly' },
    },
    rules: {
      // Callbacks often take arguments they do not use, for their position.
      'no-unused-vars': ['error', { args: 'none', caughtErrors: 'none' }],
    },
  },
  {
    files: ['**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.node, ...globals.browser },
    },
  },
];
