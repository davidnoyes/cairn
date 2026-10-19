-- Folders. A folder is an artifact with no content, and parent_id names the
-- folder an item sits in, or is null at the top level. A folder row that
-- disappears sets its items' parent to null, so they land at the top level
-- rather than being lost.

ALTER TABLE artifacts ADD COLUMN kind TEXT NOT NULL DEFAULT 'artifact' CHECK (kind IN ('artifact', 'folder'));

ALTER TABLE artifacts ADD COLUMN parent_id TEXT REFERENCES artifacts(id) ON DELETE SET NULL;

CREATE INDEX artifacts_parent ON artifacts(parent_id);
