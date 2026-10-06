// Tests for cairn.js's remote database: sql.js runs the statements on the
// version's latest revision, fetched through the worker's data routes, and
// a write goes back as the whole file under If-Match. The fake worker below
// keeps one revision and answers as data.mjs does; the vendored sql.js runs
// under Node. Run with: node --test internal/server/web/*_test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const initSqlJs = require('./vendor/sql-wasm.js');
const VENDOR = new URL('./vendor/', import.meta.url).pathname;
const source = readFileSync(new URL('./cairn.js', import.meta.url), 'utf8');

const A = '0123abcd-0123-4abc-8abc-0123456789ab';
const V = '89abcdef-89ab-4def-8def-89abcdef0123';
const V2 = '11111111-2222-4333-8444-555555555555';
const DB = (v = V) => `/api/artifacts/${A}/versions/${v}/db`;

const SQL = await initSqlJs({ locateFile: (f) => VENDOR + f });

// worker is a fake of the worker's database routes for every version: each
// keeps its latest revision as plaintext bytes. hook(req) may answer first.
function worker() {
  const w = { dbs: {}, requests: [], hook: null };
  w.revision = (v = V) => w.dbs[v]?.revision ?? 0;
  // land runs sql on the server's copy as another client would, as a new revision.
  w.land = (sql, v = V) => {
    const cur = w.dbs[v];
    const db = cur ? new SQL.Database(cur.bytes) : new SQL.Database();
    db.run(sql);
    w.dbs[v] = { revision: (cur?.revision ?? 0) + 1, bytes: db.export() };
    db.close();
  };
  w.rows = (sql, v = V) => {
    const db = new SQL.Database(w.dbs[v].bytes);
    try {
      return db.exec(sql)[0]?.values ?? [];
    } finally {
      db.close();
    }
  };
  w.fetch = async (url, opts = {}) => {
    const method = opts.method ?? 'GET';
    const headers = opts.headers ?? {};
    const req = { url, method, headers, body: opts.body };
    w.requests.push(req);
    const hooked = w.hook && (await w.hook(req));
    if (hooked) return hooked;
    const m = /^\/api\/artifacts\/[^/]+\/versions\/([^/]+)\/db$/.exec(url);
    if (!m) return Response.json({ error: 'not found' }, { status: 404 });
    const cur = w.dbs[m[1]];
    if (method === 'GET') {
      if (!cur) return Response.json({ error: 'no database yet' }, { status: 404 });
      if (headers['If-None-Match'] === `"${cur.revision}"`) return new Response(null, { status: 304 });
      return new Response(cur.bytes.slice(), { headers: { ETag: `"${cur.revision}"` } });
    }
    if (method === 'PUT') {
      const latest = cur?.revision ?? 0;
      if (headers['If-Match'] !== `"${latest}"`) {
        return Response.json({ error: 'If-Match does not name the latest revision' }, { status: 412, headers: { ETag: `"${latest}"` } });
      }
      w.dbs[m[1]] = { revision: latest + 1, bytes: new Uint8Array(opts.body) };
      return Response.json({ revision: latest + 1 });
    }
    return Response.json({ error: 'method not allowed' }, { status: 405 });
  };
  w.gets = () => w.requests.filter((r) => r.method === 'GET');
  w.puts = () => w.requests.filter((r) => r.method === 'PUT');
  return w;
}

// load runs cairn.js as a page on the artifact's content origin. Loading a
// script tag defines initSqlJs, which records where it was told the wasm is.
// failLoads is how many script loads fail before one succeeds.
function load(w = worker(), failLoads = 0, window = {}, location = { protocol: 'http:', hostname: `${A}.localhost`, pathname: `/${V}/index.html` }) {
  const scripts = [];
  const located = [];
  const document = {
    createElement: () => ({}),
    head: {
      appendChild: (el) => {
        scripts.push(el.src);
        if (failLoads-- > 0) {
          el.onerror();
          return;
        }
        window.initSqlJs = (cfg) => {
          located.push(cfg.locateFile('sql-wasm.wasm'));
          return initSqlJs({ locateFile: (f) => VENDOR + f });
        };
        el.onload();
      },
    },
  };
  vm.runInNewContext(source, {
    window,
    document,
    location,
    fetch: w.fetch,
    URL,
    Blob,
    btoa,
    console,
    setTimeout,
    clearTimeout,
  });
  // Results are built in the page's realm, which deepEqual tells apart from
  // this one's; a JSON round trip brings them across unchanged.
  const plain = (p) => p.then((v) => JSON.parse(JSON.stringify(v)));
  const { db } = window.cairn;
  const cairn = {
    ...window.cairn,
    db: { ...db, query: (...a) => plain(db.query(...a)), batch: (...a) => plain(db.batch(...a)) },
  };
  return { cairn, w, scripts, located };
}

test('login asks the shell to sign in, since the frame cannot reach the sign-in page', () => {
  const posted = [];
  const { cairn } = load(worker(), 0, { parent: { postMessage: (msg, origin) => posted.push([msg, origin]) } });
  cairn.login();
  assert.deepEqual(JSON.parse(JSON.stringify(posted)), [[{ cairn: 'login' }, '*']]);
});

test('login on the app origin goes to the sign-in page itself, and back to this page', () => {
  const posted = [];
  const location = { protocol: 'http:', hostname: 'localhost', pathname: `/artifacts/${A}/${V}/index.html`, search: '?tab=2' };
  const { cairn } = load(worker(), 0, { parent: { postMessage: (msg) => posted.push(msg) } }, location);
  cairn.login();
  assert.equal(location.href, `/login?next=${encodeURIComponent(`/artifacts/${A}/${V}/index.html?tab=2`)}`);
  assert.deepEqual(posted, []);
});

test('sql.js loads once, from /_cairn/ on the same origin', async () => {
  const { cairn, scripts, located } = load();
  await cairn.db.query('SELECT 1');
  await cairn.db.query('SELECT 2');
  assert.deepEqual(scripts, ['/_cairn/sql-wasm.js']);
  assert.deepEqual(located, ['/_cairn/sql-wasm.wasm']);
});

test('a failed sql.js load is tried again on the next call', async () => {
  const { cairn, scripts } = load(worker(), 1);
  await assert.rejects(cairn.db.query('SELECT 1'), /failed to load \/_cairn\/sql-wasm.js/);
  assert.deepEqual((await cairn.db.query('SELECT 1')).rows, [[1]]);
  assert.equal(scripts.length, 2);
});

test('with no database a query runs on an empty one, and a write uploads it as revision 1', async () => {
  const { cairn, w } = load();
  const res = await cairn.db.query('CREATE TABLE t (a INTEGER)');
  assert.deepEqual(res, { columns: [], types: [], rows: [], rowsAffected: 0, lastInsertId: 0 });
  assert.equal(w.gets()[0].url, DB());
  assert.equal(w.gets()[0].headers['If-None-Match'], undefined);
  assert.equal(w.puts().length, 1);
  assert.equal(w.puts()[0].url, DB());
  assert.equal(w.puts()[0].headers['If-Match'], '"0"');
  assert.equal(w.revision(), 1);
  assert.deepEqual(w.rows("SELECT name FROM sqlite_master WHERE type = 'table'"), [['t']]);
  await cairn.db.query('SELECT 1');
  assert.equal(w.gets()[1].headers['If-None-Match'], '"1"', 'the copy took the new revision number');
});

test('each query revalidates its copy with If-None-Match, and a 304 reuses it', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER); INSERT INTO t VALUES (7)');
  const { cairn } = load(w);
  assert.deepEqual((await cairn.db.query('SELECT a FROM t')).rows, [[7]]);
  assert.deepEqual((await cairn.db.query('SELECT a FROM t')).rows, [[7]]);
  assert.deepEqual(w.gets().map((r) => r.headers['If-None-Match']), [undefined, '"1"']);
  assert.equal(w.puts().length, 0);
});

test('a newer revision on the server replaces the copy', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER)');
  const { cairn } = load(w);
  assert.deepEqual((await cairn.db.query('SELECT a FROM t')).rows, []);
  w.land('INSERT INTO t VALUES (1)');
  assert.deepEqual((await cairn.db.query('SELECT a FROM t')).rows, [[1]]);
});

test('a statement that changes nothing sends nothing', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER)');
  const { cairn } = load(w);
  await cairn.db.query('SELECT * FROM t');
  await cairn.db.query('UPDATE t SET a = 1 WHERE a = 2');
  await cairn.db.query('CREATE TABLE IF NOT EXISTS t (a INTEGER)');
  await cairn.db.query('PRAGMA user_version');
  assert.equal(w.puts().length, 0);
});

test('a write is seen by row changes, a schema change, or a user_version change', async () => {
  for (const sql of ['INSERT INTO t VALUES (1)', 'CREATE INDEX i ON t (a)', 'PRAGMA user_version = 5']) {
    const w = worker();
    w.land('CREATE TABLE t (a INTEGER)');
    const { cairn } = load(w);
    await cairn.db.query(sql);
    assert.equal(w.puts().length, 1, sql);
    assert.equal(w.puts()[0].headers['If-Match'], '"1"', sql);
    assert.equal(w.revision(), 2, sql);
  }
});

test('the upload is the whole file, sent as octet-stream', async () => {
  const { cairn, w } = load();
  await cairn.db.query('CREATE TABLE t (a TEXT)');
  await cairn.db.query("INSERT INTO t VALUES ('x')");
  assert.equal(w.puts()[1].headers['Content-Type'], 'application/octet-stream');
  assert.deepEqual(w.rows('SELECT a FROM t'), [['x']]);
});

test('on 412 it reloads the latest revision and runs the statements again', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER)');
  const { cairn } = load(w);
  await cairn.db.query('SELECT 1');
  let raced = false;
  w.hook = (req) => {
    if (req.method === 'PUT' && !raced) {
      raced = true;
      w.land('INSERT INTO t VALUES (1)'); // another writer lands first
    }
  };
  await cairn.db.query('INSERT INTO t VALUES (2)');
  assert.deepEqual(w.rows('SELECT a FROM t ORDER BY a'), [[1], [2]]);
  assert.deepEqual(w.puts().map((r) => r.headers['If-Match']), ['"1"', '"2"']);
  assert.equal(w.revision(), 3);
});

test('after five retries it gives up and says so', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER)');
  const { cairn } = load(w);
  w.hook = (req) => {
    if (req.method === 'PUT') w.land('INSERT INTO t VALUES (0)');
  };
  await assert.rejects(cairn.db.query('INSERT INTO t VALUES (2)'), /kept changing/);
  assert.equal(w.puts().length, 6);
  assert.deepEqual(w.rows('SELECT count(*) FROM t WHERE a = 2'), [[0]]);
});

test('a string with more than one statement is refused, and nothing runs', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER)');
  const { cairn } = load(w);
  for (const sql of ['INSERT INTO t VALUES (1); INSERT INTO t VALUES (2)', 'CREATE TABLE u (a); INSERT INTO u VALUES (1)', 'SELECT 1; nonsense']) {
    await assert.rejects(cairn.db.query(sql), /only one SQL statement/, sql);
  }
  assert.equal(w.puts().length, 0);
  assert.deepEqual((await cairn.db.query('SELECT 1; -- a trailing comment\n')).rows, [[1]]);
});

test('an empty statement answers an empty result', async () => {
  const { cairn, w } = load();
  for (const sql of ['', '  -- only a comment']) {
    assert.deepEqual(await cairn.db.query(sql), { columns: [], types: [], rows: [], rowsAffected: 0, lastInsertId: 0 });
  }
  assert.equal(w.puts().length, 0);
});

test('results keep the server shape: rows affected, last insert id, and blobs as base64', async () => {
  const { cairn } = load();
  await cairn.db.query('CREATE TABLE t (id INTEGER PRIMARY KEY, b BLOB, n TEXT)');
  const ins = await cairn.db.query('INSERT INTO t (b, n) VALUES (?, ?)', [new Uint8Array([1, 2, 255]), null]);
  assert.equal(ins.rowsAffected, 1);
  assert.equal(ins.lastInsertId, 1);
  await cairn.db.query('INSERT INTO t (b, n) VALUES (?, ?)', [null, 'x']);
  const upd = await cairn.db.query('UPDATE t SET n = ?', ['y']);
  assert.equal(upd.rowsAffected, 2);
  const sel = await cairn.db.query('SELECT id, b, n FROM t ORDER BY id');
  assert.deepEqual(sel.columns, ['id', 'b', 'n']);
  assert.deepEqual(sel.types, ['', '', '']);
  assert.deepEqual(sel.rows, [[1, 'AQL/', 'y'], [2, null, 'y']]);
  assert.equal(sel.rowsAffected, 0, 'a read changed no rows, whatever the statement before it did');
});

test('a batch is one transaction: one failure rolls it all back, and names the statement', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER UNIQUE)');
  const { cairn } = load(w);
  await assert.rejects(cairn.db.batch([
    { sql: 'INSERT INTO t VALUES (?)', params: [1] },
    { sql: 'INSERT INTO t VALUES (?)', params: [1] },
  ]), /statement 2: .*UNIQUE/);
  assert.equal(w.puts().length, 0);
  assert.deepEqual((await cairn.db.query('SELECT count(*) FROM t')).rows, [[0]]);
  const results = await cairn.db.batch([
    { sql: 'INSERT INTO t VALUES (?)', params: [1] },
    { sql: 'INSERT INTO t VALUES (2)' },
  ]);
  assert.deepEqual(results.map((r) => r.rowsAffected), [1, 1]);
  assert.equal(w.puts().length, 1);
  const mixed = await cairn.db.batch([{ sql: 'UPDATE t SET a = a + 10' }, { sql: 'SELECT a FROM t' }]);
  assert.deepEqual(mixed.map((r) => r.rowsAffected), [2, 0], 'the read reports none of the update\'s rows');
});

test('a batch that commits early and then fails leaves no change behind', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER)');
  const { cairn } = load(w);
  await assert.rejects(cairn.db.batch([
    { sql: 'INSERT INTO t VALUES (1)' },
    { sql: 'COMMIT' },
    { sql: 'SELECT * FROM missing' },
  ]), /statement 3: no such table/);
  assert.equal(w.puts().length, 0);
  assert.deepEqual((await cairn.db.query('SELECT count(*) FROM t')).rows, [[0]]);
});

test('batch refuses anything but a list of statements', async () => {
  const { cairn } = load();
  for (const bad of [null, 'SELECT 1', {}, [{ params: [] }], [null]]) {
    await assert.rejects(cairn.db.batch(bad), /statements/, JSON.stringify(bad));
  }
});

test('migrate runs once: a second run changes nothing and sends nothing', async () => {
  const { cairn, w } = load();
  assert.equal(await cairn.db.migrate('001', [{ sql: 'CREATE TABLE t (a INTEGER)' }]), true);
  const puts = w.puts().length;
  assert.equal(await cairn.db.migrate('001', [{ sql: 'CREATE TABLE t (a INTEGER)' }]), false);
  assert.equal(w.puts().length, puts);
});

test('a write the worker refuses carries its reason, and the change is dropped', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER)');
  const { cairn } = load(w);
  w.hook = (req) => (req.method === 'PUT'
    ? Response.json({ error: 'You cannot change the data of this artifact.' }, { status: 403 })
    : undefined);
  await assert.rejects(cairn.db.query('INSERT INTO t VALUES (1)'), /You cannot change the data/);
  w.hook = null;
  assert.deepEqual((await cairn.db.query('SELECT count(*) FROM t')).rows, [[0]]);
  assert.equal(w.gets().at(-1).headers['If-None-Match'], undefined, 'the copy was dropped');
});

test('a revision the worker cannot verify is an error, not an empty database', async () => {
  const w = worker();
  w.hook = (req) => (req.method === 'GET'
    ? Response.json({ error: 'could not be verified: bad signature' }, { status: 502 })
    : undefined);
  const { cairn } = load(w);
  await assert.rejects(cairn.db.query('SELECT 1'), /could not be verified: bad signature/);
  assert.equal(w.puts().length, 0);
});

test('a revision without an ETag is refused', async () => {
  const w = worker();
  w.hook = (req) => (req.method === 'GET' ? new Response(new Uint8Array(0)) : undefined);
  const { cairn } = load(w);
  await assert.rejects(cairn.db.query('SELECT 1'), /revision/);
});

test('a query for another version reads that version\'s database', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER); INSERT INTO t VALUES (9)', V2);
  const { cairn } = load(w);
  assert.deepEqual((await cairn.db.query('SELECT a FROM t', [], { version: V2 })).rows, [[9]]);
  assert.equal(w.gets()[0].url, DB(V2));
});

test('a write to another version\'s database is refused, and nothing is uploaded', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER); INSERT INTO t VALUES (9)', V2);
  const { cairn } = load(w);
  await assert.rejects(cairn.db.query('INSERT INTO t VALUES (10)', [], { version: V2 }), /another version's database is read-only/);
  assert.equal(w.puts().length, 0);
  assert.deepEqual((await cairn.db.query('SELECT a FROM t', [], { version: V2 })).rows, [[9]], 'the refused change is not kept');
});

test('operations run one at a time, so two writes from one page both land without a retry', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER)');
  const { cairn } = load(w);
  await Promise.all([cairn.db.query('INSERT INTO t VALUES (1)'), cairn.db.query('INSERT INTO t VALUES (2)')]);
  assert.deepEqual(w.rows('SELECT a FROM t ORDER BY a'), [[1], [2]]);
  assert.deepEqual(w.puts().map((r) => r.headers['If-Match']), ['"1"', '"2"']);
});

test('a failed operation does not stop the next one', async () => {
  const w = worker();
  w.land('CREATE TABLE t (a INTEGER)');
  const { cairn } = load(w);
  const bad = cairn.db.query('SELECT * FROM missing');
  const good = cairn.db.query('SELECT count(*) FROM t');
  await assert.rejects(bad, /no such table/);
  assert.deepEqual((await good).rows, [[0]]);
});
