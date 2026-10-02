-- A user's key rotation records, envelopes stored verbatim: body, the old
-- key's signature, and the new key's. seq starts at 1 and goes up by one
-- with each rotation. old_fp and new_fp are copies of the fingerprints the
-- keys in body hash to, kept so the server can tell whether a chain of
-- records leads from one fingerprint to another without parsing. A
-- password-only reset changes keys with no record, so a gap between one
-- row's new_fp and the next row's old_fp is meaningful. The cascade removes
-- them with the user.
CREATE TABLE user_rotations (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    old_fp     TEXT NOT NULL,
    new_fp     TEXT NOT NULL,
    body       BLOB NOT NULL,
    sig        BLOB NOT NULL,
    new_sig    BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, seq)
);
