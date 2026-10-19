-- Groups. A group is a named set of users, kept as a signed chain of group
-- records. Fresh databases only need the tables; nothing here converts data.

CREATE TABLE groups (
    id         TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);

-- Every group record, envelopes stored verbatim, oldest first by seq. The
-- cascade removes them with the group.
CREATE TABLE group_records (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    seq      INTEGER NOT NULL,
    body     BLOB NOT NULL,
    sig      BLOB NOT NULL,
    signer   TEXT NOT NULL,
    PRIMARY KEY (group_id, seq)
);

-- The members the latest record lists, copied out of its body so access
-- checks need not parse one. The role is 'member' or 'manager', and fp is
-- the fingerprint the record lists.
CREATE TABLE group_members (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role     TEXT NOT NULL CHECK (role IN ('member', 'manager')),
    fp       TEXT NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX group_members_user ON group_members(user_id);
