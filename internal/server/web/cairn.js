/*
 * cairn.js — client library for artifacts hosted on a Cairn server.
 *
 * Served at /cairn.js and inside every version's URL space, so artifacts can
 * load it with a relative <script src="./cairn.js"></script>.
 *
 * Two backends, same API:
 *  - remote: the page is served by Cairn under /artifacts/{id}/{vid}/ and all
 *    calls proxy to the server APIs (auth travels with the session cookie).
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

  var match = location.pathname.match(/^\/(?:artifacts|shared)\/([^/]+)\/([^/]+)\/?/);
  var isRemote = location.protocol !== 'file:' && !!match;
  var artifactId = isRemote ? match[1] : 'debug-artifact';
  var versionId = isRemote ? match[2] : 'debug-version';

  // ------------------------------------------------------------------ remote
  function api(path, options) {
    return fetch(path, options).then(function (resp) {
      if (resp.status === 401) return null;
      if (!resp.ok) {
        return resp.json().catch(function () { return {}; }).then(function (body) {
          throw new Error(body.error || ('HTTP ' + resp.status));
        });
      }
      return resp.json();
    });
  }

  function post(path, body) {
    return api(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
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
      return post('/api/artifacts/' + artifactId + '/versions/' + vid + '/db/query',
        { sql: sql, params: params || [] });
    },
    batch: function (statements) {
      return post('/api/artifacts/' + artifactId + '/versions/' + versionId + '/db/batch',
        { statements: statements });
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
      return api(fileURL(path), { method: 'PUT', body: data });
    },
    removeFile: function (path) {
      return api(fileURL(path), { method: 'DELETE' }).then(function () { return true; });
    },
  };

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
