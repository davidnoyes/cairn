# cairn.js API reference

Include with `<script src="./cairn.js"></script>` (relative path — the server
injects the file into every version's URL space; a copy dropped next to
`index.html` takes precedence and enables fully-offline debug mode).

All functions return promises. The library picks its backend automatically:

- **remote** — page served by Cairn under `/artifacts/{id}/{vid}/`; calls hit
  the server APIs, authentication travels with the session cookie.
- **debug** — page served anywhere else (local dev server, `file://`);
  data lives in an in-browser SQLite (sql.js/WASM) persisted to IndexedDB.
  First load fetches sql.js from a CDN and caches it for offline reuse.

## Context

```js
cairn.mode        // 'remote' | 'debug'
cairn.artifactId  // from the URL; 'debug-artifact' in debug mode
cairn.versionId   // from the URL; 'debug-version' in debug mode
await cairn.ready()   // resolves when the backend is usable; call first
```

## Users

```js
const me = await cairn.me();
// remote: {id, email, name, isAdmin, ...} or null when anonymous
// debug:  {id: 0, name: 'Debug', email: 'debug@localhost', isAdmin: true}

const users = await cairn.users();   // [{id, name, email}] — whole directory,
                                     // any authenticated user may read it
cairn.login();                       // redirect to /login and back
```

Anonymous visitors (public artifacts) can read but not write. Gate write UI on
`me !== null` and call `cairn.login()` when an anonymous user tries to write.

## Metadata

```js
await cairn.artifact();   // {id, name, description, public, resources: [{type, value}]}
await cairn.versions();   // [{id, seq, name, changelog, createdAt}], newest first
```

## Shared database

```js
const res = await cairn.db.query(sql, params);
// res = {columns: [...], types: [...], rows: [[...], ...],
//        rowsAffected, lastInsertId, truncated?}
// rows are arrays in column order; BLOBs arrive base64-encoded.

await cairn.db.query('SELECT * FROM t WHERE id = ?', [42]);
await cairn.db.query(sql, params, {version: otherVersionId});  // read-only
                                                               // sibling-version access
await cairn.db.batch([{sql, params}, ...]);   // one atomic transaction
cairn.db.downloadURL;                          // raw .db download (remote only)
```

Constraints (server-enforced): exactly one statement per `query` call;
per-query timeout; row cap (`truncated: true` when hit); writes require
authentication.

## Migrations

```js
const applied = await cairn.db.migrate('002-add-votes', [
  {sql: 'ALTER TABLE items ADD COLUMN votes INTEGER NOT NULL DEFAULT 0'},
]);
// true  → this client applied it
// false → another client already had; safe to continue either way
```

The claim insert and the statements run in one transaction, so concurrent
viewers cannot double-apply. Use ascending prefixed names ('001-…', '002-…')
and never edit a shipped migration — add a new one.

Cross-version data migration pattern (new version pulling from the old).
Read the old data first, then create schema and import in a single guarded
migration so exactly one client performs the copy, atomically:

```js
const old = await cairn.db.query('SELECT body FROM items', [], {version: OLD_VID});
await cairn.db.migrate('001-import-v1', [
  {sql: 'CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT NOT NULL)'},
  ...old.rows.map(([body]) => (
    {sql: 'INSERT INTO items (body) VALUES (?)', params: [body]})),
]);
```
