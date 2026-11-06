package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"time"

	"passmanager/internal/auth"
	"passmanager/internal/backup"
	"passmanager/internal/config"
	"passmanager/internal/crypto"
	"passmanager/internal/db"
	"passmanager/internal/keys"
	"passmanager/internal/middleware"
	"passmanager/web"
)

type Server struct {
	cfg       *config.Config
	db        *db.DB
	sealMgr   *crypto.SealManager
	authSvc   *auth.AuthService
	devMgr    *auth.DeviceManager
	keySvc    *keys.KeyService
	backupMgr *backup.BackupManager
	sessions  *auth.SessionManager
	limiter   *middleware.RateLimiter
}

func NewServer(
	cfg *config.Config,
	database *db.DB,
	sm *crypto.SealManager,
	as *auth.AuthService,
	dm *auth.DeviceManager,
	ks *keys.KeyService,
	bm *backup.BackupManager,
	sessions *auth.SessionManager,
) *Server {
	return &Server{
		cfg:       cfg,
		db:        database,
		sealMgr:   sm,
		authSvc:   as,
		devMgr:    dm,
		keySvc:    ks,
		backupMgr: bm,
		sessions:  sessions,
		limiter:   middleware.NewRateLimiter(),
	}
}

func (s *Server) SetupHandler() http.Handler {
	mux := http.NewServeMux()

	// Static web assets from embed.FS
	staticSub, err := fs.Sub(web.StaticFS, "static")
	if err == nil {
		fileServer := http.FileServer(http.FS(staticSub))
		mux.Handle("/", fileServer)
	}

	// 1. Admin seal endpoints (Rate limit: 3/min/IP for unseal, 30/min/IP for status)
	mux.HandleFunc("GET /api/v1/admin/seal-status", s.handleSealStatus)
	mux.HandleFunc("POST /api/v1/admin/unseal", s.limiter.Limit(3, time.Minute, middleware.GetIP)(http.HandlerFunc(s.handleUnseal)).ServeHTTP)
	mux.HandleFunc("POST /api/v1/admin/rotate-passphrase", s.limiter.Limit(3, time.Minute, middleware.GetIP)(http.HandlerFunc(s.handleRotatePassphrase)).ServeHTTP)

	// 2. Auth endpoints
	mux.HandleFunc("POST /api/v1/auth/register/begin", s.limiter.Limit(5, time.Minute, middleware.GetIP)(http.HandlerFunc(s.handleRegisterBegin)).ServeHTTP)
	mux.HandleFunc("POST /api/v1/auth/register/finish", s.limiter.Limit(5, time.Minute, middleware.GetIP)(http.HandlerFunc(s.handleRegisterFinish)).ServeHTTP)
	mux.HandleFunc("POST /api/v1/auth/login/begin", s.limiter.Limit(10, time.Minute, middleware.GetIP)(http.HandlerFunc(s.handleLoginBegin)).ServeHTTP)
	mux.HandleFunc("POST /api/v1/auth/login/finish", s.limiter.Limit(10, time.Minute, middleware.GetIP)(http.HandlerFunc(s.handleLoginFinish)).ServeHTTP)
	mux.HandleFunc("POST /api/v1/auth/logout", s.limiter.Limit(20, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handleLogout)).ServeHTTP)

	// 3. Current User & Devices (Authenticated)
	authMiddleware := middleware.RequireAuth(s.sessions)
	mux.Handle("GET /api/v1/auth/me", authMiddleware(http.HandlerFunc(s.handleGetMe)))

	// 4. Device verification / Add & Change phone
	mux.HandleFunc("POST /api/v1/devices/request", s.limiter.Limit(3, time.Minute, middleware.GetIP)(http.HandlerFunc(s.handleDeviceRequestInitiate)).ServeHTTP)
	mux.HandleFunc("GET /api/v1/devices/requests/{id}/status", s.limiter.Limit(20, time.Minute, middleware.GetIP)(http.HandlerFunc(s.handleDeviceRequestStatus)).ServeHTTP)
	mux.HandleFunc("POST /api/v1/devices/requests/{id}/complete", s.limiter.Limit(5, time.Minute, middleware.GetIP)(http.HandlerFunc(s.handleDeviceRequestComplete)).ServeHTTP)

	mux.Handle("GET /api/v1/devices/requests/pending", authMiddleware(s.limiter.Limit(30, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handlePendingDeviceRequests))))
	mux.Handle("POST /api/v1/devices/requests/{id}/approve", authMiddleware(s.limiter.Limit(5, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handleDeviceRequestApprove))))
	mux.Handle("GET /api/v1/devices", authMiddleware(s.limiter.Limit(30, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handleListDevices))))
	mux.Handle("DELETE /api/v1/devices/{id}", authMiddleware(s.limiter.Limit(5, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handleRevokeDevice))))

	// 5. Key Management
	mux.Handle("GET /api/v1/keys", authMiddleware(s.limiter.Limit(60, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handleListKeys))))
	mux.Handle("POST /api/v1/keys", authMiddleware(s.limiter.Limit(20, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handleCreateKey))))
	mux.Handle("POST /api/v1/keys/new/challenge", authMiddleware(s.limiter.Limit(15, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handleKeyChallenge))))
	mux.Handle("POST /api/v1/keys/{id}/challenge", authMiddleware(s.limiter.Limit(15, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handleKeyChallenge))))
	mux.Handle("POST /api/v1/keys/{id}/retrieve", authMiddleware(s.limiter.Limit(10, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handleRetrieveKey))))
	mux.Handle("PUT /api/v1/keys/{id}", authMiddleware(s.limiter.Limit(10, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handleUpdateKey))))
	mux.Handle("DELETE /api/v1/keys/{id}", authMiddleware(s.limiter.Limit(10, time.Minute, s.userKeyFunc)(http.HandlerFunc(s.handleDeleteKey))))

	// 6. Backup Trigger
	mux.Handle("POST /api/v1/admin/backup", authMiddleware(http.HandlerFunc(s.handleRunBackup)))

	// Chain middlewares: SecurityHeaders -> SealGuard -> mux
	handler := middleware.SecurityHeaders(middleware.SealGuard(s.sealMgr)(mux))
	return handler
}

func (s *Server) userKeyFunc(r *http.Request) string {
	sess := middleware.GetSession(r.Context())
	if sess != nil {
		return "user:" + sess.UserID
	}
	return middleware.GetIP(r)
}

func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// Write JSON helper
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, errCode, msg string) {
	writeJSON(w, status, map[string]string{
		"error":   errCode,
		"message": msg,
	})
}

// ---------------- Admin Handlers ----------------

func (s *Server) handleSealStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"initialized": s.sealMgr.IsInitialized(),
		"unsealed":    s.sealMgr.IsUnsealed(),
	})
}

func (s *Server) handleUnseal(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase        string `json:"passphrase"`
		ConfirmPassphrase string `json:"confirm_passphrase,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	if !s.sealMgr.IsInitialized() {
		if body.Passphrase != body.ConfirmPassphrase {
			writeError(w, http.StatusBadRequest, "passphrase_mismatch", "Passphrases do not match")
			return
		}
		if err := s.sealMgr.InitSMK(body.Passphrase); err != nil {
			writeError(w, http.StatusBadRequest, "init_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "initialized_and_unsealed"})
		return
	}

	if err := s.sealMgr.Unseal(body.Passphrase); err != nil {
		writeError(w, http.StatusUnauthorized, "unseal_failed", "Incorrect Admin Startup Passphrase")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "unsealed"})
}

func (s *Server) handleRotatePassphrase(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPassphrase string `json:"old_passphrase"`
		NewPassphrase string `json:"new_passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	if err := s.sealMgr.RotatePassphrase(body.OldPassphrase, body.NewPassphrase); err != nil {
		writeError(w, http.StatusBadRequest, "rotate_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "passphrase_rotated"})
}

// ---------------- Auth Handlers ----------------

func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	options, regID, prfSaltB64, err := s.authSvc.BeginRegistration(r.Context(), body.Username, body.DisplayName)
	if err != nil {
		writeError(w, http.StatusBadRequest, "register_begin_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"options":  options,
		"reg_id":   regID,
		"prf_salt": prfSaltB64,
	})
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RegID        string          `json:"reg_id"`
		Attestation  json.RawMessage `json:"attestation"`
		WrappedMEK   string          `json:"wrapped_mek"`
		WrappedMEKIV string          `json:"wrapped_mek_iv"`
		DeviceName   string          `json:"device_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	mekBytes, err := base64.RawURLEncoding.DecodeString(body.WrappedMEK)
	if err != nil {
		mekBytes, err = base64.StdEncoding.DecodeString(body.WrappedMEK)
	}
	if err != nil || len(mekBytes) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_wrapped_mek", "Invalid wrapped_mek base64")
		return
	}

	ivBytes, err := base64.RawURLEncoding.DecodeString(body.WrappedMEKIV)
	if err != nil {
		ivBytes, err = base64.StdEncoding.DecodeString(body.WrappedMEKIV)
	}
	if err != nil || len(ivBytes) != 12 {
		writeError(w, http.StatusBadRequest, "invalid_wrapped_mek_iv", "Invalid wrapped_mek_iv base64")
		return
	}

	sess, user, err := s.authSvc.FinishRegistration(
		r.Context(),
		body.RegID,
		body.Attestation,
		mekBytes,
		ivBytes,
		body.DeviceName,
		middleware.GetIP(r),
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, "register_finish_failed", err.Error())
		return
	}

	s.sessions.SetCookie(w, sess.ID, isSecureRequest(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "registered",
		"csrf_token": sess.CSRFToken,
		"user":       user,
	})
}

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	options, loginID, prfSalts, err := s.authSvc.BeginLogin(r.Context(), body.Username)
	if err != nil {
		writeError(w, http.StatusBadRequest, "login_begin_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"options":   options,
		"login_id":  loginID,
		"prf_salts": prfSalts,
	})
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		LoginID   string          `json:"login_id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	sess, user, err := s.authSvc.FinishLogin(r.Context(), body.LoginID, body.Assertion, middleware.GetIP(r))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "login_failed", err.Error())
		return
	}

	s.sessions.SetCookie(w, sess.ID, isSecureRequest(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "logged_in",
		"csrf_token": sess.CSRFToken,
		"user":       user,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(auth.SessionCookieName)
	if err == nil && cookie.Value != "" {
		s.sessions.InvalidateSession(cookie.Value)
	}
	s.sessions.ClearCookie(w, isSecureRequest(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	user, err := s.db.GetUserByID(r.Context(), sess.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusNotFound, "user_not_found", "User not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":          user,
		"credential_id": base64.RawURLEncoding.EncodeToString(sess.CredentialID),
		"csrf_token":    sess.CSRFToken,
	})
}

// ---------------- Device Verification Handlers ----------------

func (s *Server) handleDeviceRequestInitiate(w http.ResponseWriter, r *http.Request) {
	var payload auth.RequestInitiatePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	reqID, expiresIn, err := s.devMgr.InitiateRequest(r.Context(), &payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, "initiate_request_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"request_id": reqID,
		"expires_in": expiresIn,
	})
}

func (s *Server) handlePendingDeviceRequests(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	reqs, err := s.devMgr.GetPendingRequests(r.Context(), sess.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"requests": reqs,
	})
}

func (s *Server) handleDeviceRequestApprove(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	reqID := r.PathValue("id")

	var body struct {
		StepUpID             string          `json:"step_up_id"`
		Assertion            json.RawMessage `json:"assertion"`
		ApproverECDHPub      string          `json:"approver_ecdh_pub"`
		EncryptedMEKTransfer string          `json:"encrypted_mek_transfer"`
		TransferIV           string          `json:"transfer_iv"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	appPub, err := base64.RawURLEncoding.DecodeString(body.ApproverECDHPub)
	if err != nil {
		appPub, err = base64.StdEncoding.DecodeString(body.ApproverECDHPub)
	}
	encMEK, err := base64.RawURLEncoding.DecodeString(body.EncryptedMEKTransfer)
	if err != nil {
		encMEK, err = base64.StdEncoding.DecodeString(body.EncryptedMEKTransfer)
	}
	tIV, err := base64.RawURLEncoding.DecodeString(body.TransferIV)
	if err != nil {
		tIV, err = base64.StdEncoding.DecodeString(body.TransferIV)
	}

	err = s.devMgr.ApproveRequest(
		r.Context(),
		reqID,
		sess.UserID,
		sess.CredentialID,
		body.StepUpID,
		body.Assertion,
		appPub,
		encMEK,
		tIV,
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, "approve_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "approved"})
}

func (s *Server) handleDeviceRequestStatus(w http.ResponseWriter, r *http.Request) {
	reqID := r.PathValue("id")
	statusResp, err := s.devMgr.GetRequestStatus(r.Context(), reqID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "status_check_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, statusResp)
}

func (s *Server) handleDeviceRequestComplete(w http.ResponseWriter, r *http.Request) {
	reqID := r.PathValue("id")
	var body struct {
		Attestation  json.RawMessage `json:"attestation"`
		WrappedMEK   string          `json:"wrapped_mek"`
		WrappedMEKIV string          `json:"wrapped_mek_iv"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	mekBytes, err := base64.RawURLEncoding.DecodeString(body.WrappedMEK)
	if err != nil {
		mekBytes, err = base64.StdEncoding.DecodeString(body.WrappedMEK)
	}
	ivBytes, err := base64.RawURLEncoding.DecodeString(body.WrappedMEKIV)
	if err != nil {
		ivBytes, err = base64.StdEncoding.DecodeString(body.WrappedMEKIV)
	}

	sess, err := s.devMgr.CompleteRequest(r.Context(), reqID, body.Attestation, mekBytes, ivBytes, middleware.GetIP(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, "complete_failed", err.Error())
		return
	}

	s.sessions.SetCookie(w, sess.ID, isSecureRequest(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "enrolled",
		"csrf_token": sess.CSRFToken,
	})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	creds, err := s.db.GetCredentialsByUserID(r.Context(), sess.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}

	var devices []map[string]any
	for _, c := range creds {
		devices = append(devices, map[string]any{
			"id":          base64.RawURLEncoding.EncodeToString(c.ID),
			"device_name": c.DeviceName,
			"status":      c.Status,
			"created_at":  c.CreatedAt,
			"last_used_at": c.LastUsedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	credIDB64 := r.PathValue("id")

	credID, err := base64.RawURLEncoding.DecodeString(credIDB64)
	if err != nil {
		credID, err = base64.StdEncoding.DecodeString(credIDB64)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid credential ID")
		return
	}

	var body struct {
		StepUpID  string          `json:"step_up_id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	if err := s.devMgr.RevokeDevice(r.Context(), sess.UserID, credID, body.StepUpID, body.Assertion); err != nil {
		writeError(w, http.StatusBadRequest, "revoke_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
}

// ---------------- Keys Handlers ----------------

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	query := r.URL.Query().Get("q")

	meta, err := s.keySvc.ListKeys(r.Context(), sess.UserID, query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"keys": meta})
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	var payload keys.CreateKeyPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	meta, err := s.keySvc.CreateKey(r.Context(), sess.UserID, &payload, middleware.GetIP(r))
	if err != nil {
		if errors.Is(err, keys.ErrKeyPayloadTooLarge) {
			writeError(w, http.StatusBadRequest, "key_payload_too_large", err.Error())
			return
		}
		if errors.Is(err, keys.ErrUserKeyLimitExceeded) {
			writeError(w, http.StatusBadRequest, "user_key_limit_exceeded", err.Error())
			return
		}
		if errors.Is(err, keys.ErrIPKeyLimitExceeded) {
			writeError(w, http.StatusBadRequest, "ip_key_limit_exceeded", err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "create_key_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":     meta.ID,
		"name":   meta.Name,
		"status": "created",
	})
}

func (s *Server) handleKeyChallenge(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	keyID := r.PathValue("id")

	// If a specific key ID is requested (not new key creation challenge), verify key exists
	if keyID != "" && keyID != "new" {
		k, err := s.db.GetKeyByID(r.Context(), keyID, sess.UserID)
		if err != nil || k == nil {
			writeError(w, http.StatusNotFound, "key_not_found", "Key not found")
			return
		}
	}

	options, stepUpID, prfSalt, err := s.authSvc.BeginStepUp(r.Context(), sess.UserID, sess.CredentialID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "challenge_failed", err.Error())
		return
	}

	// Fetch active credential wrapped_mek
	cred, err := s.db.GetCredentialByID(r.Context(), sess.CredentialID)
	if err != nil || cred == nil {
		writeError(w, http.StatusNotFound, "cred_not_found", "Active credential not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"options":        options,
		"step_up_id":     stepUpID,
		"prf_salt":       base64.RawURLEncoding.EncodeToString(prfSalt),
		"wrapped_mek":    base64.RawURLEncoding.EncodeToString(cred.WrappedMEK),
		"wrapped_mek_iv": base64.RawURLEncoding.EncodeToString(cred.WrappedMEKIV),
	})
}

func (s *Server) handleRetrieveKey(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	keyID := r.PathValue("id")

	var body struct {
		StepUpID  string          `json:"step_up_id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	singleKey, err := s.keySvc.RetrieveSingleKey(
		r.Context(),
		keyID,
		sess.UserID,
		sess.CredentialID,
		body.StepUpID,
		body.Assertion,
		middleware.GetIP(r),
	)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "retrieve_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, singleKey)
}

func (s *Server) handleUpdateKey(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	keyID := r.PathValue("id")

	var body struct {
		Name             string          `json:"name"`
		ClientCiphertext string          `json:"client_ciphertext"`
		ClientIV         string          `json:"client_iv"`
		ClientSalt       string          `json:"client_salt"`
		StepUpID         string          `json:"step_up_id"`
		Assertion        json.RawMessage `json:"assertion"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	cCT, err := base64.RawURLEncoding.DecodeString(body.ClientCiphertext)
	if err != nil {
		cCT, err = base64.StdEncoding.DecodeString(body.ClientCiphertext)
	}
	if err != nil || len(cCT) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_client_ciphertext", "Invalid client_ciphertext")
		return
	}
	cIV, err := base64.RawURLEncoding.DecodeString(body.ClientIV)
	if err != nil {
		cIV, err = base64.StdEncoding.DecodeString(body.ClientIV)
	}
	if err != nil || len(cIV) != 12 {
		writeError(w, http.StatusBadRequest, "invalid_client_iv", "Invalid client_iv: must be 12 bytes")
		return
	}
	cSalt, err := base64.RawURLEncoding.DecodeString(body.ClientSalt)
	if err != nil {
		cSalt, err = base64.StdEncoding.DecodeString(body.ClientSalt)
	}
	if err != nil || len(cSalt) != 32 {
		writeError(w, http.StatusBadRequest, "invalid_client_salt", "Invalid client_salt: must be 32 bytes")
		return
	}

	err = s.keySvc.UpdateKey(
		r.Context(),
		keyID,
		sess.UserID,
		body.Name,
		cCT,
		cIV,
		cSalt,
		body.StepUpID,
		body.Assertion,
		middleware.GetIP(r),
	)
	if err != nil {
		if errors.Is(err, keys.ErrKeyPayloadTooLarge) {
			writeError(w, http.StatusBadRequest, "key_payload_too_large", err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "update_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	sess := middleware.GetSession(r.Context())
	keyID := r.PathValue("id")

	var body struct {
		StepUpID  string          `json:"step_up_id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	err := s.keySvc.DeleteKey(
		r.Context(),
		keyID,
		sess.UserID,
		body.StepUpID,
		body.Assertion,
		middleware.GetIP(r),
	)
	if err != nil {
		writeError(w, http.StatusBadRequest, "delete_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func (s *Server) handleRunBackup(w http.ResponseWriter, r *http.Request) {
	backupPath, err := s.backupMgr.RunBackup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "backup_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "backup_success",
		"backup_path": backupPath,
	})
}
