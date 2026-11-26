ALTER TABLE users ADD COLUMN last_login_at INTEGER;
UPDATE users SET last_login_at = (SELECT last_login_at FROM user_activity WHERE user_id = users.id);
DROP TABLE user_activity;
DROP TABLE state_outbox;
DROP TABLE conflicts;
DROP TABLE epochs;
DROP TABLE changelog;
DROP TABLE repl_state;
