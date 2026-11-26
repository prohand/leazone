-- Phase 2: interface settings, DNS zones, records and forwarders.

CREATE TABLE interface_settings (
    if_name      TEXT PRIMARY KEY,
    dns_enabled  INTEGER NOT NULL DEFAULT 0,
    dhcp_enabled INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL
);

CREATE TABLE zones (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL CHECK (kind IN ('primary', 'reverse')),
    auto            INTEGER NOT NULL DEFAULT 0,
    ttl             INTEGER NOT NULL,
    soa_primary_ns  TEXT NOT NULL,
    soa_admin_email TEXT NOT NULL,
    soa_refresh     INTEGER NOT NULL,
    soa_retry       INTEGER NOT NULL,
    soa_expire      INTEGER NOT NULL,
    soa_minimum     INTEGER NOT NULL,
    serial          INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE records (
    id         TEXT PRIMARY KEY,
    zone_id    TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name       TEXT NOT NULL, -- relative to the zone, "@" for the apex
    type       TEXT NOT NULL,
    ttl        INTEGER,       -- NULL = zone default
    data       TEXT NOT NULL, -- JSON, fields depend on type
    source     TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'dhcp')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX records_zone_name ON records(zone_id, name);

CREATE TABLE forwarders (
    id              TEXT PRIMARY KEY,
    domain          TEXT NOT NULL DEFAULT '', -- '' = global
    position        INTEGER NOT NULL,
    protocol        TEXT NOT NULL CHECK (protocol IN ('udp', 'tcp', 'dot', 'doh')),
    address         TEXT NOT NULL,
    port            INTEGER NOT NULL,
    tls_server_name TEXT NOT NULL DEFAULT '',
    tls_verify      INTEGER NOT NULL DEFAULT 1,
    doh_url         TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);
CREATE INDEX forwarders_domain ON forwarders(domain, position);
