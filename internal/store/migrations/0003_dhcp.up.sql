-- Phase 3: VLAN labels, DHCP scopes, reservations and leases.

CREATE TABLE vlans (
    id         TEXT PRIMARY KEY,
    vlan_id    INTEGER NOT NULL UNIQUE CHECK (vlan_id BETWEEN 1 AND 4094),
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE dhcp_scopes (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    vlan_id         INTEGER,
    enabled         INTEGER NOT NULL DEFAULT 1,
    network         TEXT NOT NULL,
    range_start     TEXT NOT NULL,
    range_end       TEXT NOT NULL,
    exclusions      TEXT NOT NULL DEFAULT '[]', -- JSON [{start,end}]
    lease_time      INTEGER NOT NULL,
    gateway         TEXT NOT NULL DEFAULT '',
    dns_servers     TEXT NOT NULL DEFAULT '[]',
    domain          TEXT NOT NULL DEFAULT '',
    ntp_servers     TEXT NOT NULL DEFAULT '[]',
    options         TEXT NOT NULL DEFAULT '[]', -- JSON [{code,type,value}]
    if_name         TEXT,                       -- direct mode
    relay           INTEGER NOT NULL DEFAULT 0, -- relay mode
    relay_agents    TEXT NOT NULL DEFAULT '[]',
    ddns_enabled    INTEGER NOT NULL DEFAULT 1,
    ddns_domain     TEXT NOT NULL DEFAULT '',
    ping_check      INTEGER NOT NULL DEFAULT 0,
    alert_threshold INTEGER NOT NULL DEFAULT 80,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE dhcp_reservations (
    id          TEXT PRIMARY KEY,
    scope_id    TEXT NOT NULL REFERENCES dhcp_scopes(id) ON DELETE CASCADE,
    mac         TEXT NOT NULL DEFAULT '',
    client_id   TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL,
    hostname    TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    UNIQUE (scope_id, ip)
);

-- Leases are state (synchronized in real time between nodes in phase 4).
CREATE TABLE dhcp_leases (
    scope_id   TEXT NOT NULL REFERENCES dhcp_scopes(id) ON DELETE CASCADE,
    ip         TEXT NOT NULL,
    mac        TEXT NOT NULL DEFAULT '',
    client_id  TEXT NOT NULL DEFAULT '',
    hostname   TEXT NOT NULL DEFAULT '',
    state      TEXT NOT NULL CHECK (state IN ('offered', 'bound', 'released', 'expired', 'declined')),
    starts     INTEGER NOT NULL,
    ends       INTEGER NOT NULL,
    circuit_id TEXT NOT NULL DEFAULT '',
    remote_id  TEXT NOT NULL DEFAULT '',
    giaddr     TEXT NOT NULL DEFAULT '',
    dns_name   TEXT NOT NULL DEFAULT '',
    owner_node TEXT NOT NULL DEFAULT '',
    hlc        INTEGER NOT NULL DEFAULT 0, -- hybrid logical clock (HA merge)
    updated_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scope_id, ip)
);
CREATE INDEX dhcp_leases_mac ON dhcp_leases(scope_id, mac);

-- DNS records created from a lease remember which client owns them.
ALTER TABLE records ADD COLUMN dhcp_owner TEXT NOT NULL DEFAULT '';
