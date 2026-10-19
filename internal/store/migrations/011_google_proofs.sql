-- Google proofs. A proof says a browser finished Google sign-in for an
-- address a few minutes ago. The table holds the SHA-256 of the token, never
-- the token. It has no user ID, because a proof can come before the account
-- exists. Expiry and use are checked in the queries, as for tokens.

CREATE TABLE google_proofs (
    hash       TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    used_at    TEXT
);
