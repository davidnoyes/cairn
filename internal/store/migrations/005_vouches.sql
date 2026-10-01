-- The owner's signed vouch for a version pushed by someone who is no longer
-- an editor. Envelope stored verbatim; one per version, a later one replaces
-- it. The cascade removes it with its version.
CREATE TABLE version_vouches (
    version_id  TEXT PRIMARY KEY REFERENCES versions(id) ON DELETE CASCADE,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    body        BLOB NOT NULL,
    sig         BLOB NOT NULL,
    signer      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX version_vouches_artifact ON version_vouches(artifact_id);
