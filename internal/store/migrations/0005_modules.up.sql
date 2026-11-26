-- Phase 5: optional modules (ad blocking, DNSSEC).

-- Blocking configuration (replicated).
CREATE TABLE block_lists (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    url        TEXT NOT NULL UNIQUE,
    format     TEXT NOT NULL DEFAULT 'auto' CHECK (format IN ('auto', 'hosts', 'domains', 'adblock')),
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE block_rules (
    id         TEXT PRIMARY KEY,
    domain     TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('allow', 'deny')),
    comment    TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE (domain, kind)
);

CREATE TABLE block_policies (
    id          TEXT PRIMARY KEY,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('interface', 'vlan', 'network')),
    target      TEXT NOT NULL,
    enabled     INTEGER NOT NULL,
    comment     TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE (target_kind, target)
);

-- Download state of each list (local: each node downloads on its own).
CREATE TABLE block_list_state (
    list_id    TEXT PRIMARY KEY,
    fetched_at INTEGER,
    entries    INTEGER NOT NULL DEFAULT 0,
    error      TEXT NOT NULL DEFAULT ''
);

-- DNSSEC (replicated, private keys encrypted with the data key).
ALTER TABLE zones ADD COLUMN dnssec_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE zones ADD COLUMN dnssec_algorithm INTEGER NOT NULL DEFAULT 13;
ALTER TABLE zones ADD COLUMN nsec_mode TEXT NOT NULL DEFAULT 'nsec3';

CREATE TABLE dnssec_keys (
    id          TEXT PRIMARY KEY,
    zone_id     TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK (role IN ('ksk', 'zsk')),
    algorithm   INTEGER NOT NULL,
    key_tag     INTEGER NOT NULL,
    public      TEXT NOT NULL, -- DNSKEY record, presentation format
    private_enc TEXT NOT NULL, -- PKCS#8, encrypted (AAD "dnssec:<id>")
    state       TEXT NOT NULL CHECK (state IN ('published', 'active', 'retired', 'ds-pending')),
    created_at  INTEGER NOT NULL,
    active_at   INTEGER,       -- when it starts (or started) signing
    retire_at   INTEGER        -- retired keys are removed at this time
);
CREATE INDEX dnssec_keys_zone ON dnssec_keys(zone_id);
