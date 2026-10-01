-- Each user's sealed keyring: pins and epoch records, sealed under MK, so
-- the server stores it without reading it. rev goes up by one on every
-- write; a user with no row has rev 0 and no keyring.
CREATE TABLE user_keyrings (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    rev        INTEGER NOT NULL CHECK (rev >= 1),
    keyring    BLOB NOT NULL,
    updated_at TEXT NOT NULL
);
