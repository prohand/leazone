// Package modules stores which optional modules are turned on. The value is
// a replicated setting, so both nodes of a cluster follow it.
package modules

import (
	"context"

	"github.com/prohand/leazone/internal/store"
)

// Key is the settings table key.
const Key = "modules"

// Modules lists the optional modules. All are off by default.
type Modules struct {
	Blocking         bool `json:"blocking"`
	DNSSEC           bool `json:"dnssec"`
	DNSSECValidation bool `json:"dnssecValidation"`
}

// Get returns the stored state (all off when never set).
func Get(ctx context.Context, db *store.DB) (Modules, error) {
	var m Modules
	_, err := db.GetSetting(ctx, Key, &m)
	return m, err
}

// Put stores the state.
func Put(ctx context.Context, db *store.DB, m Modules) error { return db.PutSetting(ctx, Key, m) }
