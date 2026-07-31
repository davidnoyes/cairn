# Shared Todos — TypeScript + React + esbuild

A bundled Cairn artifact: the app is written in TypeScript with React, esbuild
bundles it into `dist/`, and `dist/` is what you push. The interesting part is
`src/store.ts` — a `TodoStore` interface that hides every cairn.js detail
(the `cairn` global, migrations, SQL, rows-as-arrays) from the UI; the React
components never touch cairn.js directly.

```
src/
  store.ts     TodoStore — the only module that talks to cairn.js
  cairn.d.ts   typings for the cairn.js global
  App.tsx      UI — depends on the TodoStore interface, not on Cairn
  main.tsx     entry point
public/
  index.html   loads ./cairn.js (relative), then the bundle
```

```sh
cd examples/todo-react
npm install
npm run build        # bundle into dist/
npm run typecheck    # tsc --noEmit

# develop locally — cairn.js falls back to an in-browser SQLite
npm run dev          # build + serve dist/ on http://localhost:8000

# publish (push the built dist/, not the source)
cairn push dist --artifact todos --create --public
# iterate: rebuild, then re-push in place — the shared database survives
npm run build && cairn push dist --artifact todos --overwrite latest
```
