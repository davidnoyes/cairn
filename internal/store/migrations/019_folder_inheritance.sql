-- The folder an entry of an artifact's latest membership record comes from:
-- the record's "via", empty for a direct grant. Access reads it on every
-- request, so an entry whose folder no longer contains the artifact or no
-- longer lists the user or group grants nothing. Existing rows are direct
-- grants.

ALTER TABLE artifact_members ADD COLUMN via TEXT NOT NULL DEFAULT '';

ALTER TABLE artifact_groups ADD COLUMN via TEXT NOT NULL DEFAULT '';
