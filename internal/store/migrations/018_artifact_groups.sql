-- The groups an artifact's latest membership record lists, replaced whenever
-- a record lands. group_id has no foreign key: a record may keep listing a
-- group that was deleted, and a deleted group has no members to grant
-- anything. Fresh databases only need the table; nothing here converts data.

CREATE TABLE artifact_groups (
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    group_id    TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('viewer', 'editor')),
    PRIMARY KEY (artifact_id, group_id)
);

CREATE INDEX artifact_groups_group ON artifact_groups(group_id);
