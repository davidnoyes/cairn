-- api_keys is dropped before users because it references users(id).
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name          TEXT NOT NULL DEFAULT '',
    auth_hash     TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    token_version INTEGER NOT NULL DEFAULT 1,
    disabled      INTEGER NOT NULL DEFAULT 0,
    verified_at   TEXT,
    reset_at      TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE key_bundles (
    user_id       TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    kdf           TEXT NOT NULL,
    mk_password   BLOB NOT NULL,
    mk_recovery   BLOB NOT NULL,
    x25519_pub    BLOB NOT NULL,
    x25519_priv   BLOB NOT NULL,
    ed25519_pub   BLOB NOT NULL,
    ed25519_priv  BLOB NOT NULL,
    ek            BLOB NOT NULL
);

CREATE TABLE bundle_archives (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    archived_at  TEXT NOT NULL,
    bundle       TEXT NOT NULL,
    api_keys     TEXT NOT NULL
);

CREATE INDEX bundle_archives_user ON bundle_archives(user_id);

CREATE TABLE api_keys (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL DEFAULT '',
    device        INTEGER NOT NULL DEFAULT 0,
    secret_hash   TEXT NOT NULL,
    mk            BLOB NOT NULL,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT,
    revoked_at    TEXT
);

CREATE INDEX api_keys_user ON api_keys(user_id);

CREATE TABLE tokens (
    hash        TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT
);
