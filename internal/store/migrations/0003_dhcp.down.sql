DELETE FROM records WHERE source = 'dhcp';
ALTER TABLE records DROP COLUMN dhcp_owner;
DROP TABLE dhcp_leases;
DROP TABLE dhcp_reservations;
DROP TABLE dhcp_scopes;
DROP TABLE vlans;
