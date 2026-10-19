-- The manager role. A listed member's role is 'viewer', 'editor', or
-- 'manager'. SQLite cannot change a CHECK constraint in place, so the table
-- is rebuilt with the wider one; no other table refers to it.

CREATE TABLE artifact_members_new (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK (role IN ('viewer', 'editor', 'manager')),
    fp          TEXT NOT NULL,
    PRIMARY KEY (artifact_id, user_id)
);

INSERT INTO artifact_members_new (artifact_id, user_id, role, fp)
    SELECT artifact_id, user_id, role, fp FROM artifact_members;

DROP TABLE artifact_members;

ALTER TABLE artifact_members_new RENAME TO artifact_members;

CREATE INDEX artifact_members_user ON artifact_members(user_id);
