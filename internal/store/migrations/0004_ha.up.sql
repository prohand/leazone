-- Phase 4: replication journal, epochs, conflicts, state outbox.

-- Replication switches read by the triggers (one row).
CREATE TABLE repl_state (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    applying INTEGER NOT NULL DEFAULT 0, -- 1 while applying changes received from the primary
    record   INTEGER NOT NULL DEFAULT 1, -- 1 on the primary (or a single node): journal config changes
    epoch    INTEGER NOT NULL DEFAULT 0
);
INSERT INTO repl_state(id) VALUES (1);

-- Config change journal (filled by triggers, generated at startup).
CREATE TABLE changelog (
    seq   INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch INTEGER NOT NULL,
    tbl   TEXT NOT NULL,
    pk    TEXT NOT NULL,
    op    TEXT NOT NULL CHECK (op IN ('upsert', 'delete')),
    row   TEXT,
    ts    INTEGER NOT NULL
);

-- One row per primary term (replicated like the config).
CREATE TABLE epochs (
    epoch     INTEGER PRIMARY KEY,
    start_seq INTEGER NOT NULL,
    node_id   TEXT NOT NULL,
    name      TEXT NOT NULL,
    at        INTEGER NOT NULL,
    reason    TEXT NOT NULL
);

-- Changes made on a primary that were not replicated before it lost its
-- role. Kept for the admin ("Réappliquer"), never applied automatically.
CREATE TABLE conflicts (
    id          TEXT PRIMARY KEY,
    epoch       INTEGER NOT NULL,
    seq         INTEGER NOT NULL,
    tbl         TEXT NOT NULL,
    pk          TEXT NOT NULL,
    op          TEXT NOT NULL,
    row         TEXT,
    detected_at INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending'
);

-- State rows (sessions, counters, audit...) waiting to be sent to the peer.
CREATE TABLE state_outbox (
    id  INTEGER PRIMARY KEY AUTOINCREMENT,
    tbl TEXT NOT NULL,
    op  TEXT NOT NULL,
    row TEXT NOT NULL
);

-- Last login is state (written on any node), not config.
CREATE TABLE user_activity (
    user_id       TEXT PRIMARY KEY,
    last_login_at INTEGER NOT NULL
);
INSERT INTO user_activity(user_id, last_login_at) SELECT id, last_login_at FROM users WHERE last_login_at IS NOT NULL;
ALTER TABLE users DROP COLUMN last_login_at;
