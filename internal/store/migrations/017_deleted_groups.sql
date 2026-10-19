-- The ID of every group that was deleted, kept so a first record can never
-- reuse one: a client that holds a deleted group's head must not meet a new
-- chain under the same ID. Nothing here converts data.

CREATE TABLE deleted_groups (
    id         TEXT PRIMARY KEY,
    deleted_at TEXT NOT NULL
);
