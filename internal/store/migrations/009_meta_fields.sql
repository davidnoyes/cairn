-- An artifact's name and description, and a version's name and changelog, as
-- client-encrypted fields. The server holds each as a sealed blob and the
-- signed record that covers it, and no plaintext of any of them: the four
-- plaintext columns go. version_id is empty for an artifact's own fields, so
-- it cannot reference versions; the trigger removes a version's fields with
-- it, as the cascade does for the artifact's.
ALTER TABLE artifacts DROP COLUMN name;
ALTER TABLE artifacts DROP COLUMN description;
ALTER TABLE versions DROP COLUMN name;
ALTER TABLE versions DROP COLUMN changelog;

CREATE TABLE meta_fields (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    version_id  TEXT NOT NULL,
    field       TEXT NOT NULL,
    record      BLOB NOT NULL,
    signer_key  BLOB NOT NULL,
    blob        BLOB NOT NULL,
    PRIMARY KEY (artifact_id, version_id, field)
);

CREATE TRIGGER meta_fields_version_delete AFTER DELETE ON versions
BEGIN
    DELETE FROM meta_fields WHERE artifact_id = OLD.artifact_id AND version_id = OLD.id;
END;
