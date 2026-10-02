-- A version's content is client-encrypted blobs and a signed manifest.
-- manifest_hash is hex(SHA-256) of the manifest envelope's body, as the
-- pusher declared it; the owner's vouch must name the same value. It is
-- empty only for a row that predates encrypted content.
ALTER TABLE versions ADD COLUMN manifest_hash TEXT NOT NULL DEFAULT '';
