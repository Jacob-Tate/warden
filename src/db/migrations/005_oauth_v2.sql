-- v5: reshape the (never populated) OAuth tables for the Phase 2b authorization server.
-- Adds RFC 8707 resource binding, a consumer label, token families (reuse detection)
-- and rotation marks. All timestamps are `strftime('%Y-%m-%dT%H:%M:%SZ')` text so
-- they compare lexicographically; the server compares against the database clock.

DROP TABLE oauth_tokens;
DROP TABLE oauth_codes;
DROP TABLE oauth_clients;

CREATE TABLE oauth_clients (
    client_id     TEXT PRIMARY KEY,
    client_name   TEXT,
    redirect_uris TEXT NOT NULL DEFAULT '[]',   -- JSON array
    created_at    TEXT NOT NULL,
    last_used_at  TEXT
) STRICT;

CREATE TABLE oauth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,               -- PKCE S256
    resource       TEXT NOT NULL,
    consumer       TEXT NOT NULL,
    scope          TEXT,
    family_id      TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    used_at        TEXT
) STRICT;
CREATE INDEX idx_oauth_codes_expiry ON oauth_codes (expires_at);

CREATE TABLE oauth_tokens (
    token_hash TEXT PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    client_id  TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    family_id  TEXT NOT NULL,
    resource   TEXT NOT NULL,
    consumer   TEXT NOT NULL,
    scope      TEXT,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    rotated_at TEXT,                            -- refresh tokens: set when exchanged
    created_at TEXT NOT NULL
) STRICT;
CREATE INDEX idx_oauth_tokens_expiry ON oauth_tokens (expires_at);
CREATE INDEX idx_oauth_tokens_family ON oauth_tokens (family_id);
