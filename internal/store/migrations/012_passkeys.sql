-- Passkeys. A passkey signs a user in and opens its own sealed copy of MK, as
-- an API key does. The credential ID is the primary key, so one credential
-- belongs to one account. public_key is the SPKI the browser reports, alg its
-- COSE algorithm, and sign_count the last authenticator counter seen. The
-- cascade removes a user's passkeys with the user.

CREATE TABLE passkeys (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    public_key   BLOB NOT NULL,
    alg          INTEGER NOT NULL,
    sign_count   INTEGER NOT NULL DEFAULT 0,
    mk           BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT
);

CREATE INDEX passkeys_user ON passkeys(user_id);

-- The credential IDs and sealed MKs of passkeys a reset without the recovery
-- code removed, as a JSON list, like api_keys.
ALTER TABLE bundle_archives ADD COLUMN passkeys TEXT NOT NULL DEFAULT '[]';
