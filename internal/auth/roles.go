package auth

// Role is a user role.
type Role string

// Roles.
const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleReadonly Role = "readonly"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	return r == RoleAdmin || r == RoleOperator || r == RoleReadonly
}

// Permission is an action family checked on every API route.
type Permission string

// Permissions. Keep this list small: each route declares exactly one.
const (
	PermRead         Permission = "read"          // read everything except secrets
	PermRecordsWrite Permission = "records.write" // DNS records
	PermLeasesWrite  Permission = "leases.write"  // DHCP leases and reservations
	PermConfigWrite  Permission = "config.write"  // zones, forwarders, scopes, interfaces, modules
	PermAdmin        Permission = "admin"         // users, HA, settings, backups, DNSSEC keys, audit
	PermSelf         Permission = "self"          // own account (password, MFA, sessions, tokens)
)

var rolePerms = map[Role]map[Permission]bool{
	RoleAdmin: {PermRead: true, PermRecordsWrite: true, PermLeasesWrite: true, PermConfigWrite: true,
		PermAdmin: true, PermSelf: true},
	RoleOperator: {PermRead: true, PermRecordsWrite: true, PermLeasesWrite: true, PermSelf: true},
	RoleReadonly: {PermRead: true, PermSelf: true},
}

// Allowed reports whether a principal may use permission p. write tells
// whether the request changes state (POST/PUT/PATCH/DELETE).
// A token never grants more than the role of its owner: a "read" token only
// performs reads, and tokens never manage the account itself (PermSelf).
func Allowed(role Role, tokenScope string, p Permission, write bool) bool {
	if !rolePerms[role][p] {
		return false
	}
	switch tokenScope {
	case "": // browser session
		return true
	case "read":
		return !write && p != PermSelf
	case "write":
		return p != PermSelf
	}
	return false
}
