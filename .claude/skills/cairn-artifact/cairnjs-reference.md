# cairn.js API reference

Include with `<script src="./cairn.js"></script>` (relative path). The server
provides the file in every version's URL space. A copy dropped next to
`index.html` takes precedence and enables fully-offline debug mode.

All functions return promises. The library picks its backend automatically:

- **remote** — the page is served by Cairn on its own content origin
  (`<artifactId>.<content-domain>/<versionId>/`, inside the shell at
  `/shared/<id>`). A service worker adds credentials, decrypts what the page
  reads, and encrypts what it writes. The database runs in the page, on the
  `sql.js` that Cairn bundles. `cairn.js` loads the latest revision of the
  version's database, runs each query or batch on that copy in a transaction,
  and uploads the whole file as a new revision when a statement changed it.
  The upload carries `If-Match`. On a 412 (another page wrote first),
  `cairn.js` fetches the newer revision and runs the statements again, up to
  five times.
- **debug** — the page is served anywhere else (local dev server, `file://`).
  Data lives in an in-browser SQLite (`sql.js`/WASM) persisted to IndexedDB.
  The first load fetches `sql.js` from a CDN and caches it for offline reuse.

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
// remote: {id, email, name, isAdmin, ...} or null when not signed in
// debug:  {id: 0, name: 'Debug', email: 'debug@localhost', isAdmin: true}

const users = await cairn.users();   // [{id, name, email}] — only the people
                                     // who can open this artifact
cairn.login();                       // sign in, then come back to this page
```

A visitor who opens a public link without signing in has `me === null` and
can read only. Gate write UI on `me !== null`, and call `cairn.login()` when
such a visitor tries to write. They come back to the artifact through the same
link. Even a signed-in link holder can write only when the owner turned public
writes on.

## Metadata

```js
await cairn.artifact();   // {id, name, description}
await cairn.versions();   // [{id, seq, name, changelog, createdAt}], newest first
```

`cairn.artifact()` has no `public` or `resources` field in remote mode.

## Shared database

```js
const res = await cairn.db.query(sql, params);
// res = {columns: [...], types: [...], rows: [[...], ...],
//        rowsAffected, lastInsertId}
// rows are arrays in column order; BLOBs arrive base64-encoded;
// types are empty strings (sql.js does not report declared types).

await cairn.db.query('SELECT * FROM t WHERE id = ?', [42]);
await cairn.db.query(sql, params, {version: otherVersionId});  // read-only
                                                               // sibling-version access
await cairn.db.batch([{sql, params}, ...]);   // one atomic transaction
cairn.db.downloadURL;   // '/api/artifacts/<id>/versions/<vid>/db/download';
                        // null in debug mode
```

Constraints:

- Exactly one statement per `query` call. A `batch` error names the failing
  statement, counting from 1.
- A query that changes another version's database fails with "another
  version's database is read-only".
- There is no per-query timeout or row cap: the query runs in the page.
- The database is one file uploaded whole on every change. The server refuses
  a revision over its limit (50 MiB by default), and the change does not land.
  Keep the database small and put large data in file storage.
- The server keeps the newest 10 revisions. Use `cairn db revisions` and
  `cairn db restore` to recover one.
- Writing needs the owner or an editor, or a signed-in holder of the public
  link while public writes are on.

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
and never edit a shipped migration. Add a new one.

## File storage

Each version also owns a file storage for binary data that does not belong in
SQLite (images, exports, attachments). Like the database it is per-version,
survives re-uploads, and is stored encrypted. Anyone who can open the artifact
can read it. Writes need the same access as database writes.

```js
await cairn.files.upload('photos/cat.png', blob);  // Blob/File/string
                                                   // → {path, size, modifiedAt}
await cairn.files.list();                          // [{path, size, modifiedAt}]
const blob = await cairn.files.download('photos/cat.png');  // null when absent
await cairn.files.remove('photos/cat.png');        // throws when absent

img.src = cairn.files.url('photos/cat.png');
// '/api/artifacts/<id>/versions/<vid>/files/<path>' in remote mode, null in
// debug mode. The service worker serves it, so it works for <img> and similar
// embedded resources. It does not work in an <iframe> or <object>.
```

Paths are relative slash-separated names (`a/b/c.png` — no leading `/`, no
`..`). Uploading to an existing path overwrites it. `list`, `download` and
`url` accept `{version: otherVersionId}` for read-only access to a sibling
version's files. In debug mode files persist to IndexedDB.

To save a file, click an `<a download>` whose `href` is a `blob:` URL (from
`download()`) or an address on the content origin (`url()`). The shell starts
the download. Use `download()` and `URL.createObjectURL(blob)` to work in both
modes.

Cross-version data migration pattern (new version pulling from the old). Read
the old data first, then create the schema and import in a single guarded
migration so exactly one client performs the copy, atomically:

```js
const old = await cairn.db.query('SELECT body FROM items', [], {version: OLD_VID});
await cairn.db.migrate('001-import-v1', [
  {sql: 'CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT NOT NULL)'},
  ...old.rows.map(([body]) => (
    {sql: 'INSERT INTO items (body) VALUES (?)', params: [body]})),
]);
```
