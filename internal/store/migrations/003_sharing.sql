-- Ownership, membership records, wrapped keys. Fresh databases only: Open
-- refuses to apply this to a data directory that already holds artifacts,
-- because those artifacts have no owner.

-- owner_id is nullable only because SQLite cannot add a NOT NULL column
-- without a default; every artifact created by the sharing code sets it.
-- epoch is 0 until the first membership record lands.
ALTER TABLE artifacts ADD COLUMN owner_id TEXT REFERENCES users(id);
ALTER TABLE artifacts ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE artifacts ADD COLUMN team TEXT NOT NULL DEFAULT 'none';
ALTER TABLE artifacts ADD COLUMN public_writes INTEGER NOT NULL DEFAULT 0;
-- hex(SHA-256(linkToken)) and its epoch; both NULL unless public.
ALTER TABLE artifacts ADD COLUMN public_token_hash TEXT;
ALTER TABLE artifacts ADD COLUMN public_epoch INTEGER;

CREATE INDEX artifacts_owner ON artifacts(owner_id);

-- The signed membership chain, envelopes stored verbatim. The other columns
-- are copies of fields inside body, kept for queries; body is authoritative.
CREATE TABLE artifact_records (
    artifact_id   TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    prev          TEXT NOT NULL,
    body_hash     TEXT NOT NULL,
    epoch         INTEGER NOT NULL,
    owner_id      TEXT NOT NULL,
    owner_fp      TEXT NOT NULL,
    ak_commit     BLOB NOT NULL,
    team          TEXT NOT NULL CHECK (team IN ('none', 'viewer', 'editor')),
    public        INTEGER NOT NULL,
    public_writes INTEGER NOT NULL,
    transfer      TEXT NOT NULL DEFAULT '',
    handover      TEXT NOT NULL DEFAULT '',
    body          BLOB NOT NULL,
    sig           BLOB NOT NULL,
    signer        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (artifact_id, seq)
);

-- Members as listed by the latest record, replaced whenever a record lands.
CREATE TABLE artifact_members (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK (role IN ('viewer', 'editor')),
    fp          TEXT NOT NULL,
    PRIMARY KEY (artifact_id, user_id)
);

CREATE INDEX artifact_members_user ON artifact_members(user_id);

-- The latest record's excluded list. user_id has no foreign key: an entry
-- outlives the account it names.
CREATE TABLE artifact_excluded (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL,
    fp          TEXT NOT NULL,
    email       TEXT NOT NULL,
    PRIMARY KEY (artifact_id, user_id)
);

-- AK wrapped to a user, one row per epoch. fp is the recipient's fingerprint
-- when the wrap was stored.
CREATE TABLE artifact_keys (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    epoch       INTEGER NOT NULL,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped     BLOB NOT NULL,
    fp          TEXT NOT NULL,
    PRIMARY KEY (artifact_id, epoch, user_id)
);

CREATE INDEX artifact_keys_user ON artifact_keys(user_id);

-- The owner's copy of each epoch's AK, sealed under the owner's EK.
CREATE TABLE artifact_estate_keys (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    epoch       INTEGER NOT NULL,
    sealed      BLOB NOT NULL,
    PRIMARY KEY (artifact_id, epoch)
);

-- A signed approval of a team member, stored with the wraps it enabled.
CREATE TABLE team_approvals (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fp          TEXT NOT NULL,
    epoch       INTEGER NOT NULL,
    body        BLOB NOT NULL,
    sig         BLOB NOT NULL,
    signer      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (artifact_id, user_id)
);

-- Ownership offers. state is open, accepted, or closed. An offer by the
-- owner carries its envelope and its body hash; an administrator's offer has
-- neither. An accepted owner offer stays so clients can verify the chain.
CREATE TABLE artifact_offers (
    id          TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    to_user     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    offered_by  TEXT NOT NULL CHECK (offered_by IN ('owner', 'admin')),
    hash        TEXT NOT NULL DEFAULT '',
    body        BLOB,
    sig         BLOB,
    signer      TEXT,
    state       TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'accepted', 'closed')),
    created_at  TEXT NOT NULL
);

CREATE UNIQUE INDEX artifact_offers_open ON artifact_offers(artifact_id) WHERE state = 'open';

ALTER TABLE versions ADD COLUMN pushed_by TEXT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE versions ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0;

-- The epoch each database revision (kind 'db', key '') or file (kind 'file',
-- key = path) of a version was last written under.
CREATE TABLE version_writes (
    version_id TEXT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('db', 'file')),
    key        TEXT NOT NULL,
    epoch      INTEGER NOT NULL,
    writer     TEXT,
    written_at TEXT NOT NULL,
    PRIMARY KEY (version_id, kind, key)
);
