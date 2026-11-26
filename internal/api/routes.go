package api

import (
	"net/http"

	"github.com/prohand/leazone/internal/auth"
)

func (s *Server) registerRoutes() {
	self := auth.PermSelf

	// System
	s.handle("GET /system/info", pub, s.systemInfo)
	s.mux.HandleFunc("GET /health", s.health)
	s.mux.HandleFunc("GET /api/v1/openapi.json", s.openapi)

	// Login flow
	s.handle("GET /auth/session", pub, s.getSession)
	s.handle("POST /auth/login", pub, s.login)
	s.handle("POST /auth/logout", anyLevel, s.logout)
	s.handle("POST /auth/passkey/begin", pub, s.passkeyLoginBegin)
	s.handle("POST /auth/passkey/finish", pub, s.passkeyLoginFinish)
	s.handle("POST /auth/mfa/passkey/begin", mfaStep, s.mfaPasskeyBegin)
	s.handle("POST /auth/mfa/passkey/finish", mfaStep, s.mfaPasskeyFinish)
	s.handle("POST /auth/mfa/totp", mfaStep, s.mfaTOTP)
	s.handle("POST /auth/mfa/recovery", mfaStep, s.mfaRecovery)
	s.handle("POST /auth/step-up/passkey/begin", need(self), s.stepUpPasskeyBegin)
	s.handle("POST /auth/step-up/passkey/finish", need(self), s.stepUpPasskeyFinish)
	s.handle("POST /auth/step-up/totp", need(self), s.stepUpTOTP)

	// Own account
	s.handle("GET /me", enrolling, s.getMe)
	s.handle("POST /me/password", need(self), s.changePassword)
	s.handle("GET /me/passkeys", enrolling, s.listPasskeys)
	s.handle("POST /me/passkeys/begin", enrolling, s.passkeyRegisterBegin)
	s.handle("POST /me/passkeys/finish", enrolling, s.passkeyRegisterFinish)
	s.handle("PATCH /me/passkeys/{id}", need(self), s.renamePasskey)
	s.handle("DELETE /me/passkeys/{id}", needStepUp(self), s.deletePasskey)
	s.handle("GET /me/totp", enrolling, s.getTOTP)
	s.handle("DELETE /me/totp", needStepUp(self), s.deleteTOTP)
	s.handle("POST /me/totp/setup", enrolling, s.totpSetup)
	s.handle("POST /me/totp/confirm", enrolling, s.totpConfirm)
	s.handle("GET /me/recovery-codes", need(self), s.getRecovery)
	s.handle("POST /me/recovery-codes", needStepUp(self), s.regenRecovery)
	s.handle("GET /me/sessions", need(self), s.listSessions)
	s.handle("DELETE /me/sessions/{id}", need(self), s.revokeSession)
	s.handle("GET /me/tokens", need(self), s.listTokens)
	s.handle("POST /me/tokens", need(self), s.createToken)
	s.handle("DELETE /me/tokens/{id}", need(self), s.revokeToken)

	// Users (admin)
	s.handle("GET /users", need(auth.PermAdmin), s.listUsers)
	s.handle("POST /users", needStepUp(auth.PermAdmin), s.createUser)
	s.handle("PATCH /users/{id}", needStepUp(auth.PermAdmin), s.updateUser)
	s.handle("DELETE /users/{id}", needStepUp(auth.PermAdmin), s.deleteUser)
	s.handle("POST /users/{id}/reset-mfa", needStepUp(auth.PermAdmin), s.resetUserMFA)
	s.handle("POST /users/{id}/reset-password", needStepUp(auth.PermAdmin), s.resetUserPassword)

	// Settings (admin)
	s.handle("GET /settings/security", need(auth.PermAdmin), s.getSecurity)
	s.handle("PUT /settings/security", needStepUp(auth.PermAdmin), s.putSecurity)
	s.handle("GET /settings/tls", need(auth.PermAdmin), s.getTLS)
	s.handle("POST /settings/tls", needStepUp(auth.PermAdmin), s.importTLS)

	// Audit (admin)
	s.handle("GET /audit", need(auth.PermAdmin), s.listAudit)

	s.registerDNSRoutes()
	s.registerDHCPRoutes()
	s.registerImportRoutes()

	// Unknown API paths answer JSON 404 instead of the SPA.
	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		problem(w, http.StatusNotFound, TNotFound, "Route inconnue.")
	})
	// Single-page application.
	s.mux.Handle("/", s.spa())
}
