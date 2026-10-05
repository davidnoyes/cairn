/*
 * cairn.js — client library for artifacts hosted on a Cairn server.
 *
 * Served at /cairn.js and inside every version's URL space, so artifacts can
 * load it with a relative <script src="./cairn.js"></script>.
 *
 * Two backends, same API:
 *  - remote: the page is served by Cairn on the artifact's content origin and
 *    calls go through the shell's service worker, which decrypts what it
 *    reads and seals what it writes. The database runs here, in the bundled
 *    sql.js from /_cairn/, on a copy of the version's latest revision.
 *  - debug: the page runs outside a Cairn server (local dev server, file://).
 *    Data lives in an in-browser SQLite (sql.js/WebAssembly) persisted to
 *    browser storage (IndexedDB), and the user is {id: 0, name: "Debug"}.
 *
 * API:
 *   cairn.mode                    'remote' | 'debug'
 *   await cairn.ready()           wait for the backend to be usable
 *   await cairn.me()              current user or null (anonymous)
 *   await cairn.users()           global user directory [{id,name,email}]
 *   await cairn.artifact()        artifact metadata
 *   await cairn.versions()        version list (newest first)
 *   await cairn.db.query(sql, params?, {version}?)  → {columns,types,rows,...}
 *   await cairn.db.batch([{sql,params}...])         atomic transaction
 *   await cairn.db.migrate(name, [{sql,params}...]) run-once schema migration
 *   await cairn.files.list({version}?)        [{path, size, modifiedAt}]
 *   await cairn.files.upload(path, data)      store a file (Blob/File/string)
 *   await cairn.files.download(path, {version}?)  → Blob, or null when absent
 *   await cairn.files.remove(path)            delete a file
 *   cairn.files.url(path, {version}?)         direct URL (remote; null in debug)
 *   cairn.login()                 redirect to the login page and back
 */
(function (global) {
  'use strict';

  // On a content origin (<artifact>.<domain>/<version>/...) the artifact is
  // the host's first label; on the app origin both are in the path.
  var UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
  var host = new RegExp('^(' + UUID + ')\\.').exec(location.hostname || '');
  var content = host && new RegExp('^/(' + UUID + ')/').exec(location.pathname);
  var match = content ? [null, host[1], content[1]]
    : location.pathname.match(/^\/(?:artifacts|shared)\/([^/]+)\/([^/]+)\/?/);
  var isRemote = location.protocol !== 'file:' && !!match;
  var artifactId = isRemote ? match[1] : 'debug-artifact';
  var versionId = isRemote ? match[2] : 'debug-version';

  // ------------------------------------------------------------------ remote
  function api(path, options) {
    return fetch(path, options).then(function (resp) {
      if (resp.status === 401) return null;
      if (!resp.ok) return failure(resp);
      return resp.json();
    });
  }

  // failure rejects with the error a JSON answer carries, else the status.
  function failure(resp) {
    return resp.json().catch(function () { return {}; }).then(function (body) {
      throw new Error(body.error || ('HTTP ' + resp.status));
    });
  }

  // fileURL builds the storage URL for a file path, encoding each segment.
  function fileURL(path, vid) {
    return '/api/artifacts/' + artifactId + '/versions/' + (vid || versionId) +
      '/files/' + String(path).split('/').map(encodeURIComponent).join('/');
  }

  var remote = {
    ready: function () { return Promise.resolve(); },
    me: function () { return api('/api/me'); },
    users: function () { return api('/api/users') || []; },
    artifact: function () { return api('/api/artifacts/' + artifactId); },
    versions: function () { return api('/api/artifacts/' + artifactId + '/versions'); },
    query: function (sql, params, opts) {
      var vid = (opts && opts.version) || versionId;
      return serial(function () {
        return runAll(vid, [{ sql: sql, params: params }], false, 0).then(function (r) { return r[0]; });
      });
    },
    batch: function (statements) {
      var ok = Array.isArray(statements) && statements.every(function (s) {
        return s && typeof s.sql === 'string';
      });
      if (!ok) return Promise.reject(new Error('batch takes a list of statements: [{sql, params}]'));
      return serial(function () { return runAll(versionId, statements, true, 0); });
    },
    listFiles: function (opts) {
      var vid = (opts && opts.version) || versionId;
      return api('/api/artifacts/' + artifactId + '/versions/' + vid + '/files');
    },
    downloadFile: function (path, opts) {
      return fetch(fileURL(path, opts && opts.version)).then(function (resp) {
        if (resp.status === 404) return null;
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        return resp.blob();
      });
    },
    uploadFile: function (path, data) {
      // The server ignores the type; octet-stream is one its cross-site
      // request protection accepts, unlike a Blob's own type.
      return api(fileURL(path), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: data,
      });
    },
    removeFile: function (path) {
      return fetch(fileURL(path), { method: 'DELETE' }).then(function (resp) {
        return resp.ok ? true : failure(resp);
      });
    },
  };

  // --------------------------------------------------------- remote database
  // The worker answers the version's latest database revision as plaintext,
  // tagged with its number. Statements run here, on a cached copy, inside one
  // transaction; when they change anything, the whole file goes back under
  // If-Match. A 412 means another writer landed first: reload the newer
  // revision and run the statements again on it.
  var RETRIES = 5;
  var sqlReady = null;
  var dbCache = {};
  var dbQueue = Promise.resolve();

  // remoteSql loads the sql.js Cairn bundles, never a copy from elsewhere.
  function remoteSql() {
    if (!sqlReady) {
      sqlReady = loadScript('/_cairn/sql-wasm.js').then(function () {
        return global.initSqlJs({ locateFile: function (f) { return '/_cairn/' + f; } });
      });
      sqlReady.catch(function () { sqlReady = null; });
    }
    return sqlReady;
  }

  // serial runs database operations one at a time, so two calls from one
  // page never race each other for the same revision.
  function serial(fn) {
    var run = dbQueue.then(fn);
    dbQueue = run.catch(function () { /* the caller has it */ });
    return run;
  }

  function dbURL(vid) {
    return '/api/artifacts/' + artifactId + '/versions/' + vid + '/db';
  }

  function forget(vid) {
    if (dbCache[vid]) dbCache[vid].db.close();
    delete dbCache[vid];
  }

  function hold(vid, db, revision) {
    forget(vid);
    dbCache[vid] = { db: db, revision: revision };
    return dbCache[vid];
  }

  // latestDb brings the cached copy up to the latest revision; with no
  // database yet it is an empty one at revision 0.
  function latestDb(vid) {
    return remoteSql().then(function (SQL) {
      var held = dbCache[vid];
      var headers = {};
      if (held && held.revision > 0) headers['If-None-Match'] = '"' + held.revision + '"';
      return fetch(dbURL(vid), { headers: headers }).then(function (resp) {
        if (resp.status === 304 && held) return held;
        if (resp.status === 404) return hold(vid, new SQL.Database(), 0);
        if (!resp.ok) return failure(resp);
        var tag = /^"(\d+)"$/.exec(resp.headers.get('ETag') || '');
        if (!tag) throw new Error('the database answer carries no revision');
        return resp.arrayBuffer().then(function (buf) {
          return hold(vid, new SQL.Database(new Uint8Array(buf)), Number(tag[1]));
        });
      });
    });
  }

  function scalar(db, sql) { return db.exec(sql)[0].values[0][0]; }

  // counters move whenever a statement changed rows, the schema, or
  // user_version: the three ways a write can leave its mark on the file.
  function counters(db) {
    return [scalar(db, 'SELECT total_changes()'), scalar(db, 'PRAGMA schema_version'),
      scalar(db, 'PRAGMA user_version')].join(':');
  }

  function base64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  // runOne runs a single statement and answers in the server's old result
  // shape. sql.js does not expose declared column types, so types are ''.
  function runOne(db, sql, params) {
    var it = db.iterateStatements(sql);
    if (it.next().done) return { columns: [], types: [], rows: [], rowsAffected: 0, lastInsertId: 0 };
    var more;
    try { more = !it.next().done; } catch (e) { more = true; }
    if (more) throw new Error('only one SQL statement per call is allowed; use batch for scripts');
    var before = scalar(db, 'SELECT total_changes()');
    var stmt = db.prepare(sql);
    try {
      stmt.bind(params || []);
      var rows = [];
      while (stmt.step()) {
        rows.push(stmt.get().map(function (v) { return ArrayBuffer.isView(v) ? base64(v) : v; }));
      }
      var columns = stmt.getColumnNames();
      return {
        columns: columns,
        types: columns.map(function () { return ''; }),
        rows: rows,
        rowsAffected: scalar(db, 'SELECT total_changes()') > before ? db.getRowsModified() : 0,
        lastInsertId: scalar(db, 'SELECT last_insert_rowid()'),
      };
    } finally {
      stmt.free();
    }
  }

  // runAll runs statements as one transaction on the latest revision, and
  // uploads the result when they changed anything. A batch error names the
  // statement, counting from 1.
  function runAll(vid, statements, batch, attempt) {
    return latestDb(vid).then(function (held) {
      var db = held.db;
      var before = counters(db);
      var results;
      try {
        db.exec('BEGIN');
        results = statements.map(function (s, i) {
          try { return runOne(db, s.sql, s.params); } catch (e) {
            throw batch ? new Error('statement ' + (i + 1) + ': ' + e.message) : e;
          }
        });
        db.exec('COMMIT');
      } catch (e) {
        try { db.exec('ROLLBACK'); } catch (_) { /* no transaction open */ }
        if (counters(db) !== before) forget(vid);
        throw e;
      }
      if (counters(db) === before) return results;
      return fetch(dbURL(vid), {
        method: 'PUT',
        headers: { 'If-Match': '"' + held.revision + '"', 'Content-Type': 'application/octet-stream' },
        body: db.export(),
      }).then(function (resp) {
        if (resp.ok) {
          return resp.json().then(function (body) { held.revision = body.revision; return results; });
        }
        forget(vid); // the change did not land: drop it with its copy
        if (resp.status !== 412) return failure(resp);
        if (attempt >= RETRIES) {
          throw new Error('the database kept changing under this write; gave up after ' +
            RETRIES + ' retries');
        }
        return runAll(vid, statements, batch, attempt + 1);
      });
    });
  }

  // ------------------------------------------------------------------- debug
  var DEBUG_USER = { id: 0, name: 'Debug', email: 'debug@localhost', isAdmin: true };
  var SQLJS_CDN = 'https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.14.2/';
  var dbKey = 'db:' + location.pathname;

  function idb() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open('cairn-debug', 1);
      req.onupgradeneeded = function () { req.result.createObjectStore('kv'); };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }
  function idbGet(key) {
    return idb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction('kv').objectStore('kv').get(key);
        tx.onsuccess = function () { resolve(tx.result); };
        tx.onerror = function () { reject(tx.error); };
      });
    });
  }
  function idbSet(key, value) {
    return idb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction('kv', 'readwrite').objectStore('kv').put(value, key);
        tx.onsuccess = function () { resolve(); };
        tx.onerror = function () { reject(tx.error); };
      });
    });
  }
  function idbDel(key) {
    return idb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction('kv', 'readwrite').objectStore('kv').delete(key);
        tx.onsuccess = function () { resolve(); };
        tx.onerror = function () { reject(tx.error); };
      });
    });
  }
  // idbPrefix lists keys and values under a key prefix (both in key order).
  function idbPrefix(prefix) {
    return idb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var store = db.transaction('kv').objectStore('kv');
        var range = IDBKeyRange.bound(prefix, prefix + '\uffff');
        var keysReq = store.getAllKeys(range);
        var valsReq = store.getAll(range);
        var done = 0;
        function step() { if (++done === 2) resolve({ keys: keysReq.result, values: valsReq.result }); }
        keysReq.onsuccess = valsReq.onsuccess = step;
        keysReq.onerror = valsReq.onerror = function (e) { reject(e.target.error); };
      });
    });
  }

  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      var el = document.createElement('script');
      el.src = src;
      el.onload = resolve;
      el.onerror = function () { reject(new Error('failed to load ' + src)); };
      document.head.appendChild(el);
    });
  }

  // Locates sql.js: already present > next to cairn.js > IndexedDB cache >
  // CDN (cached for offline reuse afterwards).
  function loadSqlJs() {
    if (global.initSqlJs) return Promise.resolve(global.initSqlJs);
    var localJs = new URL('sql-wasm.js', location.href).href;
    var localWasm = new URL('sql-wasm.wasm', location.href).href;
    return loadScript(localJs)
      .then(function () {
        loadSqlJs.locate = function () { return localWasm; };
        return global.initSqlJs;
      })
      .catch(function () {
        return Promise.all([idbGet('asset:sql-wasm.js'), idbGet('asset:sql-wasm.wasm')])
          .then(function (cached) {
            if (cached[0] && cached[1]) {
              var jsURL = URL.createObjectURL(new Blob([cached[0]], { type: 'text/javascript' }));
              var wasmURL = URL.createObjectURL(new Blob([cached[1]], { type: 'application/wasm' }));
              loadSqlJs.locate = function () { return wasmURL; };
              return loadScript(jsURL).then(function () { return global.initSqlJs; });
            }
            // Fetch from CDN and cache both assets for offline use.
            return Promise.all([
              fetch(SQLJS_CDN + 'sql-wasm.js').then(function (r) { return r.text(); }),
              fetch(SQLJS_CDN + 'sql-wasm.wasm').then(function (r) { return r.arrayBuffer(); }),
            ]).then(function (assets) {
              idbSet('asset:sql-wasm.js', assets[0]);
              idbSet('asset:sql-wasm.wasm', assets[1]);
              var jsURL = URL.createObjectURL(new Blob([assets[0]], { type: 'text/javascript' }));
              var wasmURL = URL.createObjectURL(new Blob([assets[1]], { type: 'application/wasm' }));
              loadSqlJs.locate = function () { return wasmURL; };
              return loadScript(jsURL).then(function () { return global.initSqlJs; });
            });
          });
      });
  }

  var debugDb = null;
  var debugReady = null;
  var persistTimer = null;

  function debugInit() {
    if (debugReady) return debugReady;
    debugReady = loadSqlJs()
      .then(function (initSqlJs) {
        return initSqlJs({ locateFile: loadSqlJs.locate || function (f) { return SQLJS_CDN + f; } });
      })
      .then(function (SQL) {
        return idbGet(dbKey).then(function (saved) {
          debugDb = saved ? new SQL.Database(new Uint8Array(saved)) : new SQL.Database();
          console.info('[cairn] debug mode: local SQLite, user ' + JSON.stringify(DEBUG_USER.name));
        });
      })
      .catch(function (err) {
        throw new Error('[cairn] debug mode needs sql.js: serve sql-wasm.js/.wasm ' +
          'next to cairn.js, or be online once so it can be cached. (' + err.message + ')');
      });
    return debugReady;
  }

  function debugPersist() {
    clearTimeout(persistTimer);
    persistTimer = setTimeout(function () {
      try {
        var bytes = debugDb.export();
        idbSet(dbKey, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
      } catch (e) { console.warn('[cairn] persist failed', e); }
    }, 200);
  }

  function debugRun(sql, params) {
    var stmt = debugDb.prepare(sql);
    try {
      stmt.bind(params || []);
      var rows = [];
      while (stmt.step()) rows.push(stmt.get());
      var columns = [];
      try { columns = stmt.getColumnNames(); } catch (e) { /* non-SELECT */ }
      var rowsAffected = debugDb.getRowsModified();
      var last = debugDb.exec('SELECT last_insert_rowid()');
      return {
        columns: columns,
        types: columns.map(function () { return ''; }),
        rows: rows,
        rowsAffected: rowsAffected,
        lastInsertId: last.length ? last[0].values[0][0] : 0,
      };
    } finally {
      stmt.free();
    }
  }

  var debug = {
    ready: debugInit,
    me: function () { return debugInit().then(function () { return DEBUG_USER; }); },
    users: function () { return debugInit().then(function () { return [DEBUG_USER]; }); },
    artifact: function () {
      return Promise.resolve({
        id: artifactId, name: document.title || 'debug artifact',
        description: 'local debug artifact', public: false, resources: [],
      });
    },
    versions: function () {
      return Promise.resolve([{ id: versionId, artifactId: artifactId, seq: 1, name: 'debug' }]);
    },
    query: function (sql, params, opts) {
      return debugInit().then(function () {
        // Cross-version reads have no meaning locally: same database.
        var res = debugRun(sql, params);
        debugPersist();
        return res;
      });
    },
    batch: function (statements) {
      return debugInit().then(function () {
        debugDb.exec('BEGIN');
        try {
          var results = statements.map(function (s) { return debugRun(s.sql, s.params); });
          debugDb.exec('COMMIT');
          debugPersist();
          return results;
        } catch (e) {
          try { debugDb.exec('ROLLBACK'); } catch (_) { /* no transaction open */ }
          throw e;
        }
      });
    },
    listFiles: function () {
      return idbPrefix(fileKeyPrefix).then(function (r) {
        return r.keys.map(function (k, i) {
          var v = r.values[i] || {};
          return {
            path: String(k).slice(fileKeyPrefix.length),
            size: v.data ? v.data.byteLength : 0,
            modifiedAt: v.modifiedAt || '',
          };
        });
      });
    },
    downloadFile: function (path) {
      return idbGet(fileKeyPrefix + path).then(function (v) {
        return v ? new Blob([v.data], { type: v.type || '' }) : null;
      });
    },
    uploadFile: function (path, data) {
      if (!validFilePath(path)) return Promise.reject(new Error('invalid file path'));
      return fileBytes(data).then(function (b) {
        var entry = { data: b.buf, type: b.type, modifiedAt: new Date().toISOString() };
        return idbSet(fileKeyPrefix + path, entry).then(function () {
          return { path: path, size: b.buf.byteLength, modifiedAt: entry.modifiedAt };
        });
      });
    },
    removeFile: function (path) {
      return idbGet(fileKeyPrefix + path).then(function (v) {
        if (v === undefined) throw new Error('file not found');
        return idbDel(fileKeyPrefix + path).then(function () { return true; });
      });
    },
  };

  var fileKeyPrefix = 'file:' + location.pathname + ':';

  // validFilePath mirrors the server rule: clean, relative, slash-separated.
  function validFilePath(p) {
    if (typeof p !== 'string' || !p || p.indexOf('\\') !== -1) return false;
    var parts = p.split('/');
    for (var i = 0; i < parts.length; i++) {
      if (!parts[i] || parts[i] === '.' || parts[i] === '..') return false;
    }
    return true;
  }

  // fileBytes normalizes upload input (Blob/File/ArrayBuffer/string) to bytes.
  function fileBytes(data) {
    var blob = (data instanceof Blob) ? data : new Blob([data]);
    return new Promise(function (resolve, reject) {
      var fr = new FileReader();
      fr.onload = function () { resolve({ buf: fr.result, type: blob.type }); };
      fr.onerror = function () { reject(fr.error); };
      fr.readAsArrayBuffer(blob);
    });
  }

  // ------------------------------------------------------------------ facade
  var backend = isRemote ? remote : debug;

  function migrate(name, statements) {
    var claim = [{
      sql: 'INSERT INTO _migrations (name, applied_at) VALUES (?, ?)',
      params: [name, new Date().toISOString()],
    }].concat(statements);
    return backend.batch([{
      sql: 'CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)',
    }]).then(function () {
      // The claim insert and the migration run in ONE transaction: if another
      // client applied it first, the unique constraint rolls everything back.
      return backend.batch(claim).then(
        function () { return true; },
        function (err) {
          if (/UNIQUE|constraint/i.test(err.message)) return false;
          throw err;
        });
    });
  }

  global.cairn = {
    mode: isRemote ? 'remote' : 'debug',
    artifactId: artifactId,
    versionId: versionId,
    ready: function () { return backend.ready(); },
    me: function () { return backend.me(); },
    users: function () { return backend.users(); },
    artifact: function () { return backend.artifact(); },
    versions: function () { return backend.versions(); },
    login: function () {
      location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search);
    },
    db: {
      query: function (sql, params, opts) { return backend.query(sql, params, opts); },
      batch: function (statements) { return backend.batch(statements); },
      migrate: migrate,
      downloadURL: isRemote
        ? '/api/artifacts/' + artifactId + '/versions/' + versionId + '/db/download'
        : null,
    },
    files: {
      list: function (opts) { return backend.listFiles(opts); },
      download: function (path, opts) { return backend.downloadFile(path, opts); },
      upload: function (path, data) { return backend.uploadFile(path, data); },
      remove: function (path) { return backend.removeFile(path); },
      url: function (path, opts) {
        return isRemote ? fileURL(path, opts && opts.version) : null;
      },
    },
  };
})(window);
