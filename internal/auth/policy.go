package auth

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/prohand/leazone/internal/config"
)

// SecuritySettings are the admin-editable security rules (settings key "security").
type SecuritySettings struct {
	MFARequiredFor     string   `json:"mfaRequiredFor"` // all | admins
	MFAMethods         string   `json:"mfaMethods"`     // passkey | passkey_or_totp
	SessionMaxHours    int      `json:"sessionMaxHours"`
	SessionIdleMinutes int      `json:"sessionIdleMinutes"`
	UIAllowedNetworks  []string `json:"uiAllowedNetworks"`
	WebAuthnRPID       string   `json:"webauthnRpId"`
	// AuditRetentionDays: audit entries older than this are deleted.
	AuditRetentionDays int `json:"auditRetentionDays"`
}

// Audit retention bounds (days).
const (
	DefaultAuditRetentionDays = 365
	MinAuditRetentionDays     = 30
	MaxAuditRetentionDays     = 3650
)

// SettingsKey is the settings table key for SecuritySettings.
const SettingsKey = "security"

// DefaultSecurity is used until an admin changes the settings.
func DefaultSecurity() SecuritySettings {
	return SecuritySettings{
		MFARequiredFor:     "all",
		MFAMethods:         "passkey_or_totp",
		SessionMaxHours:    12,
		SessionIdleMinutes: 30,
		UIAllowedNetworks:  []string{},
		AuditRetentionDays: DefaultAuditRetentionDays,
	}
}

// Validate checks and normalizes the settings. It returns field -> message.
func (s *SecuritySettings) Validate() map[string]string {
	errs := map[string]string{}
	if s.MFARequiredFor != "all" && s.MFARequiredFor != "admins" {
		errs["mfaRequiredFor"] = "valeur attendue : all ou admins"
	}
	if s.MFAMethods != "passkey" && s.MFAMethods != "passkey_or_totp" {
		errs["mfaMethods"] = "valeur attendue : passkey ou passkey_or_totp"
	}
	if s.SessionMaxHours < 1 || s.SessionMaxHours > 720 {
		errs["sessionMaxHours"] = "entre 1 et 720 heures"
	}
	if s.SessionIdleMinutes < 5 || s.SessionIdleMinutes > 1440 {
		errs["sessionIdleMinutes"] = "entre 5 et 1440 minutes"
	}
	if s.AuditRetentionDays == 0 { // field missing (older clients): default
		s.AuditRetentionDays = DefaultAuditRetentionDays
	}
	if s.AuditRetentionDays < MinAuditRetentionDays || s.AuditRetentionDays > MaxAuditRetentionDays {
		errs["auditRetentionDays"] = "entre 30 et 3650 jours"
	}
	nets := make([]string, 0, len(s.UIAllowedNetworks))
	for _, n := range s.UIAllowedNetworks {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		p, err := config.ParsePrefixOrAddr(n)
		if err != nil {
			errs["uiAllowedNetworks"] = "réseau invalide : " + n
			continue
		}
		nets = append(nets, p.String())
	}
	s.UIAllowedNetworks = nets
	s.WebAuthnRPID = strings.ToLower(strings.TrimSpace(s.WebAuthnRPID))
	if s.WebAuthnRPID != "" {
		if _, err := netip.ParseAddr(s.WebAuthnRPID); err == nil {
			errs["webauthnRpId"] = "les passkeys exigent un nom de domaine, pas une adresse IP"
		} else if strings.ContainsAny(s.WebAuthnRPID, "/: ") {
			errs["webauthnRpId"] = "nom de domaine seul, sans https:// ni port"
		}
	}
	return errs
}

// AllowedNetworks returns the parsed UI allow-list (empty = everyone).
func (s SecuritySettings) AllowedNetworks() []netip.Prefix {
	var out []netip.Prefix
	for _, n := range s.UIAllowedNetworks {
		if p, err := config.ParsePrefixOrAddr(n); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// MFARequired tells whether the policy forces MFA for this role.
func (s SecuritySettings) MFARequired(r Role) bool {
	return s.MFARequiredFor == "all" || r == RoleAdmin
}

// TOTPAllowed tells whether TOTP is an accepted second factor.
func (s SecuritySettings) TOTPAllowed() bool { return s.MFAMethods == "passkey_or_totp" }

// FactorUsable tells whether the user has a second factor the policy accepts.
func (s SecuritySettings) FactorUsable(m MFAStatus) bool {
	return m.PasskeyCount > 0 || (m.TOTPEnabled && s.TOTPAllowed())
}

// EnrollableMethods lists methods a user may enroll under this policy.
func (s SecuritySettings) EnrollableMethods() []string {
	if s.TOTPAllowed() {
		return []string{"passkey", "totp"}
	}
	return []string{"passkey"}
}

// ErrValidation carries per-field messages.
type ErrValidation map[string]string

func (e ErrValidation) Error() string { return "validation failed" }

// ErrInvalidCredentials is returned for any login failure (same message
// whether the account exists or not).
var ErrInvalidCredentials = errors.New("identifiants invalides")
