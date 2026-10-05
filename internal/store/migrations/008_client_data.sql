-- A version's database and files as client-encrypted blobs. The server keeps
-- no file path: a stored file is known by its address, and its path is inside
-- the sealed meta blob. The blobs themselves are files under dbs/ and files/
-- named by revision and address; these rows hold the signed records and the
-- key each was checked against. The cascade removes them with their version.
CREATE TABLE db_revisions (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    version_id  TEXT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    revision    INTEGER NOT NULL,
    epoch       INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    record      BLOB NOT NULL,
    signer_key  BLOB NOT NULL,
    written_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (version_id, revision)
);

CREATE INDEX db_revisions_artifact ON db_revisions(artifact_id);

CREATE TABLE stored_files (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    version_id  TEXT NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    address     TEXT NOT NULL,
    epoch       INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    record      BLOB NOT NULL,
    meta        BLOB NOT NULL,
    meta_record BLOB NOT NULL,
    signer_key  BLOB NOT NULL,
    written_by  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (version_id, address)
);

CREATE INDEX stored_files_artifact ON stored_files(artifact_id);
