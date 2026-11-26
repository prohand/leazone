-- Replication triggers name the zones columns; they are recreated at start.
DROP TRIGGER IF EXISTS repl_zones_i;
DROP TRIGGER IF EXISTS repl_zones_u;
DROP TRIGGER IF EXISTS repl_zones_d;
DROP TABLE dnssec_keys;
ALTER TABLE zones DROP COLUMN nsec_mode;
ALTER TABLE zones DROP COLUMN dnssec_algorithm;
ALTER TABLE zones DROP COLUMN dnssec_enabled;
DROP TABLE block_list_state;
DROP TABLE block_policies;
DROP TABLE block_rules;
DROP TABLE block_lists;
