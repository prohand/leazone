// Package version holds build-time version information.
package version

// These values are overridden at build time with -ldflags "-X ...".
var (
	// Version is the Leazone release version (semver, without "v").
	Version = "0.1.0-dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// BuildDate is the UTC build timestamp (RFC 3339).
	BuildDate = "unknown"
)

// ClusterProtocol is the version of the node-to-node protocol.
// Nodes refuse to sync when the major part differs.
const ClusterProtocol = "2.0"
