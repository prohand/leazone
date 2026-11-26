-- Phase 1: metadata, settings, accounts, authentication, audit, certificates.
-- Times are Unix milliseconds (INTEGER). IDs are random text.

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Runtime settings edited from the UI (JSON per section).
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE users (
    id                 TEXT PRIMARY KEY,
    username           TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role               TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'readonly')),
    password_hash      TEXT NOT NULL,
    webauthn_handle    BLOB NOT NULL UNIQUE,
    disabled           INTEGER NOT NULL DEFAULT 0,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    last_login_at      INTEGER,
    password_changed_at INTEGER NOT NULL
);

CREATE TABLE webauthn_credentials (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    credential_id  BLOB NOT NULL UNIQUE,
    data           TEXT NOT NULL, -- go-webauthn Credential as JSON (public key, flags, aaguid...)
    created_at     INTEGER NOT NULL
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials(user_id);

-- Usage counters are state (merged with max() between nodes in HA).
CREATE TABLE webauthn_usage (
    credential_id BLOB PRIMARY KEY,
    sign_count    INTEGER NOT NULL DEFAULT 0,
    last_used_at  INTEGER
);

CREATE TABLE totp (
    user_id      TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc   TEXT NOT NULL,
    confirmed_at INTEGER, -- NULL while the setup is pending
    created_at   INTEGER NOT NULL
);

CREATE TABLE totp_usage (
    user_id      TEXT PRIMARY KEY,
    last_counter INTEGER NOT NULL
);

CREATE TABLE recovery_codes (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX recovery_codes_user ON recovery_codes(user_id);

CREATE TABLE recovery_usage (
    code_id TEXT PRIMARY KEY,
    used_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    id_hash        TEXT PRIMARY KEY,
    public_id      TEXT NOT NULL UNIQUE, -- shown in the UI, never usable as a cookie
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_level     TEXT NOT NULL,
    csrf_token     TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    last_seen_at   INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    elevated_until INTEGER,
    ip             TEXT NOT NULL,
    user_agent     TEXT NOT NULL,
    revoked_at     INTEGER
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL UNIQUE,
    secret_hash  TEXT NOT NULL,
    scope        TEXT NOT NULL CHECK (scope IN ('read', 'write')),
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    last_used_at INTEGER,
    revoked_at   INTEGER
);
CREATE INDEX api_tokens_user ON api_tokens(user_id);

-- Brute force protection: key is "ip:<addr>" or "user:<name>".
CREATE TABLE login_guard (
    key          TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL,
    locked_until INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL
);

-- Append-only, hash-chained audit log.
CREATE TABLE audit_log (
    seq       INTEGER PRIMARY KEY AUTOINCREMENT,
    id        TEXT NOT NULL UNIQUE,
    ts        INTEGER NOT NULL,
    node_id   TEXT NOT NULL,
    actor     TEXT NOT NULL,
    ip        TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT NOT NULL,
    result    TEXT NOT NULL,
    details   TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
CREATE INDEX audit_log_ts ON audit_log(ts);
CREATE INDEX audit_log_action ON audit_log(action);

CREATE TABLE certificates (
    id         TEXT PRIMARY KEY,
    source     TEXT NOT NULL CHECK (source IN ('selfsigned', 'import')),
    active     INTEGER NOT NULL DEFAULT 0,
    cert_pem   TEXT NOT NULL,
    key_enc    TEXT NOT NULL,
    not_after  INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
