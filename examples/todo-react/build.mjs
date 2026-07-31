// Bundles the app into dist/ — the directory you `cairn push`.
import { build } from 'esbuild';
import { cpSync, mkdirSync } from 'node:fs';

mkdirSync('dist', { recursive: true });

await build({
  entryPoints: ['src/main.tsx'],
  bundle: true,
  minify: true,
  format: 'iife',
  target: 'es2020',
  outfile: 'dist/main.js',
  logLevel: 'info',
});

// index.html references ./cairn.js (injected by the server at serve time,
// emulated in-browser during local dev) and the bundle above.
cpSync('public/index.html', 'dist/index.html');
