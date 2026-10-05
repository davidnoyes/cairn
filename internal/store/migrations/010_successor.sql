-- The successor. A user nominates one other user, who can read what the user
-- owns 14 days after asking unless the user refuses first. Fresh databases
-- only need the tables; nothing here converts data.

-- Every successor record a user signed, envelopes stored verbatim, so seq
-- survives removal, replacement, and rotation, and the membership view can
-- serve the user's latest record. The cascade removes them with the user.
CREATE TABLE successor_records (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    body       BLOB NOT NULL,
    sig        BLOB NOT NULL,
    signer     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, seq)
);

-- The current nomination, one per user. record_seq names the row of
-- successor_records that nominated; wrapped is EK for the successor's X25519
-- key. requested_at is set while a request is pending or after a release, and
-- release is computed from it, never stored. deactivated_at is when an
-- administrator deactivated the user during the request. Deleting either user
-- deletes the nomination.
CREATE TABLE successors (
    user_id        TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    successor_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    record_seq     INTEGER NOT NULL,
    wrapped        BLOB NOT NULL,
    nominated_at   TEXT NOT NULL,
    requested_at   TEXT,
    deactivated_at TEXT
);

CREATE INDEX successors_successor ON successors(successor_id);

-- A personal address for notices. notice_email is verified and used;
-- notice_email_pending waits for its link, a token of kind 'notice'.
ALTER TABLE users ADD COLUMN notice_email TEXT;
ALTER TABLE users ADD COLUMN notice_email_pending TEXT;

-- The nomination a reset without the recovery code archived with the bundle,
-- as JSON; empty when there was none.
ALTER TABLE bundle_archives ADD COLUMN successor TEXT NOT NULL DEFAULT '';
