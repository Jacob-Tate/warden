-- v2: storage for the single-user OAuth authorization server (Phase 2).
-- Secrets (codes, tokens, client secrets) are stored hashed.

CREATE TABLE oauth_clients (
    client_id     TEXT PRIMARY KEY,
    client_secret_hash TEXT,
    client_name   TEXT,
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL
) STRICT;

CREATE TABLE oauth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,                          -- PKCE S256
    scope          TEXT,
    expires_at     TEXT NOT NULL,
    used_at        TEXT
) STRICT;

CREATE TABLE oauth_tokens (
    token_hash TEXT PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
    client_id  TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    scope      TEXT,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL
) STRICT;
CREATE INDEX idx_oauth_tokens_expiry ON oauth_tokens (expires_at);
