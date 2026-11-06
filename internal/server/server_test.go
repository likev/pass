package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"passmanager/internal/auth"
	"passmanager/internal/backup"
	"passmanager/internal/config"
	"passmanager/internal/crypto"
	"passmanager/internal/db"
	"passmanager/internal/keys"
)

func setupTestServer(t *testing.T) (*Server, http.Handler, *db.DB, *crypto.SealManager, *auth.SessionManager, string) {
	tempDir, err := os.MkdirTemp("", "server-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tempDir, "test.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	cfg := &config.Config{
		Port:                "8443",
		Host:                "127.0.0.1",
		DBPath:              dbPath,
		SealedSMKPath:       filepath.Join(tempDir, "server_master.key.enc"),
		BackupDir:           filepath.Join(tempDir, "backups"),
		BackupRetentionDays: 30,
		RPID:                "localhost",
		RPDisplayName:       "Test RP",
		RPOrigins:           []string{"http://localhost:8080", "https://localhost:8443"},
	}

	sealMgr := crypto.NewSealManager(cfg.SealedSMKPath)
	sessionMgr := auth.NewSessionManager()
	authSvc, err := auth.NewAuthService(database, cfg, sessionMgr)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	devMgr := auth.NewDeviceManager(database, authSvc, sessionMgr)
	keySvc := keys.NewKeyService(database, authSvc, sealMgr)
	backupMgr := backup.NewBackupManager(database, sealMgr, cfg.BackupDir, cfg.BackupRetentionDays)

	srv := NewServer(cfg, database, sealMgr, authSvc, devMgr, keySvc, backupMgr, sessionMgr)
	handler := srv.SetupHandler()

	return srv, handler, database, sealMgr, sessionMgr, tempDir
}

func TestServerSealedGuardAndUnseal(t *testing.T) {
	_, handler, database, sealMgr, _, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer database.Close()

	// 1. Initial seal status
	req := httptest.NewRequest("GET", "/api/v1/admin/seal-status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var statusResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &statusResp)
	if statusResp["unsealed"] != false || statusResp["initialized"] != false {
		t.Fatalf("expected unsealed=false and initialized=false, got %+v", statusResp)
	}

	// 2. Protected endpoints return 503 while sealed
	req2 := httptest.NewRequest("GET", "/api/v1/keys", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable, got %d", w2.Code)
	}

	// 3. Short passphrase rejected
	shortPayload := `{"passphrase": "short", "confirm_passphrase": "short"}`
	req3 := httptest.NewRequest("POST", "/api/v1/admin/unseal", bytes.NewBufferString(shortPayload))
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", w3.Code)
	}

	// 4. Mismatched confirm passphrase rejected
	mismatchPayload := `{"passphrase": "valid-passphrase-1234", "confirm_passphrase": "different-passphrase"}`
	req4 := httptest.NewRequest("POST", "/api/v1/admin/unseal", bytes.NewBufferString(mismatchPayload))
	w4 := httptest.NewRecorder()
	handler.ServeHTTP(w4, req4)
	if w4.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", w4.Code)
	}

	// 5. Successful init and unseal
	validPayload := `{"passphrase": "valid-passphrase-1234", "confirm_passphrase": "valid-passphrase-1234"}`
	req5 := httptest.NewRequest("POST", "/api/v1/admin/unseal", bytes.NewBufferString(validPayload))
	w5 := httptest.NewRecorder()
	handler.ServeHTTP(w5, req5)
	if w5.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w5.Code, w5.Body.String())
	}

	if !sealMgr.IsUnsealed() {
		t.Fatalf("expected seal manager to be unsealed")
	}

	// 6. Seal status now reports unsealed
	req6 := httptest.NewRequest("GET", "/api/v1/admin/seal-status", nil)
	w6 := httptest.NewRecorder()
	handler.ServeHTTP(w6, req6)
	var statusResp2 map[string]any
	_ = json.Unmarshal(w6.Body.Bytes(), &statusResp2)
	if statusResp2["unsealed"] != true || statusResp2["initialized"] != true {
		t.Fatalf("expected unsealed=true, got %+v", statusResp2)
	}
}

func TestKeysAndBackupAPI(t *testing.T) {
	srv, handler, database, sealMgr, sessionMgr, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer database.Close()

	ctx := context.Background()

	// 1. Unseal SMK
	if err := sealMgr.InitSMK("my-admin-passphrase-9999"); err != nil {
		t.Fatalf("InitSMK failed: %v", err)
	}

	// 2. Create User and Credential in DB
	userID := uuid.NewString()
	username := "elena"
	if err := database.CreateUser(ctx, userID, username, "Elena"); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	credID := []byte("elena-cred-device-1")
	cred := &db.Credential{
		ID:              credID,
		UserID:          userID,
		DeviceName:      "Elena Phone",
		PublicKey:       []byte("dummy-key"),
		AttestationType: "none",
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("wrapped-mek-sample"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	}
	if err := database.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}

	// 3. Create Session
	session, err := sessionMgr.CreateSession(userID, credID)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// 4. Test CSRF Protection: mutating POST without CSRF token returns 403
	keyPayload := map[string]string{
		"name":              "github-token",
		"client_ciphertext": base64.RawURLEncoding.EncodeToString([]byte("client-enc-token")),
		"client_iv":         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		"client_salt":       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	bodyBytes, _ := json.Marshal(keyPayload)

	req := httptest.NewRequest("POST", "/api/v1/keys", bytes.NewBuffer(bodyBytes))
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden without CSRF token, got %d", w.Code)
	}

	// 5. With CSRF token: successful key creation
	req2 := httptest.NewRequest("POST", "/api/v1/keys", bytes.NewBuffer(bodyBytes))
	req2.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	req2.Header.Set("X-CSRF-Token", session.CSRFToken)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w2.Code, w2.Body.String())
	}

	// 6. List keys returns metadata only (no ciphertexts)
	req3 := httptest.NewRequest("GET", "/api/v1/keys?q=github", nil)
	req3.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w3.Code)
	}

	var listResp struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.Unmarshal(w3.Body.Bytes(), &listResp)
	if len(listResp.Keys) != 1 {
		t.Fatalf("expected 1 key metadata, got %d", len(listResp.Keys))
	}
	keyMeta := listResp.Keys[0]
	if keyMeta["name"] != "github-token" {
		t.Fatalf("unexpected name: %v", keyMeta["name"])
	}
	// Verify NO ciphertext in list metadata
	if _, hasCT := keyMeta["client_ciphertext"]; hasCT {
		t.Fatalf("list endpoint leaked client_ciphertext!")
	}
	if _, hasSCT := keyMeta["server_ciphertext"]; hasSCT {
		t.Fatalf("list endpoint leaked server_ciphertext!")
	}
	createdKeyID := keyMeta["id"].(string)

	// 6a. Key challenge for non-existent key returns 404
	reqNonExistent := httptest.NewRequest("POST", "/api/v1/keys/non-existent-uuid/challenge", nil)
	reqNonExistent.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqNonExistent.Header.Set("X-CSRF-Token", session.CSRFToken)
	wNonExistent := httptest.NewRecorder()
	handler.ServeHTTP(wNonExistent, reqNonExistent)
	if wNonExistent.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for nonexistent key challenge, got %d", wNonExistent.Code)
	}

	// 6b. Key challenge for valid key returns 200 with step-up challenge
	reqChal := httptest.NewRequest("POST", "/api/v1/keys/"+createdKeyID+"/challenge", nil)
	reqChal.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqChal.Header.Set("X-CSRF-Token", session.CSRFToken)
	wChal := httptest.NewRecorder()
	handler.ServeHTTP(wChal, reqChal)
	if wChal.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for key challenge, got %d: %s", wChal.Code, wChal.Body.String())
	}
	var chalResp struct {
		StepUpID   string `json:"step_up_id"`
		PRFSalt    string `json:"prf_salt"`
		WrappedMEK string `json:"wrapped_mek"`
	}
	_ = json.Unmarshal(wChal.Body.Bytes(), &chalResp)
	if chalResp.StepUpID == "" || chalResp.WrappedMEK == "" {
		t.Fatalf("unexpected challenge response: %+v", chalResp)
	}

	// 6c. Key retrieve with invalid assertion fails with 401
	badRetrieveBody, _ := json.Marshal(map[string]any{
		"step_up_id": "invalid-step-up",
		"assertion":  map[string]any{},
	})
	reqBadRet := httptest.NewRequest("POST", "/api/v1/keys/"+createdKeyID+"/retrieve", bytes.NewBuffer(badRetrieveBody))
	reqBadRet.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqBadRet.Header.Set("X-CSRF-Token", session.CSRFToken)
	wBadRet := httptest.NewRecorder()
	handler.ServeHTTP(wBadRet, reqBadRet)
	if wBadRet.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for invalid step-up, got %d", wBadRet.Code)
	}

	// 6d. Key retrieve with simulated step-up succeeds with 200
	simulatedStepUpID := "simulated-stepup-ret-key"
	srv.authSvc.AddTestStepUpSession(simulatedStepUpID, userID, credID)
	validRetrieveBody, _ := json.Marshal(map[string]any{
		"step_up_id": simulatedStepUpID,
		"assertion":  map[string]any{"simulated": true},
	})
	reqValidRet := httptest.NewRequest("POST", "/api/v1/keys/"+createdKeyID+"/retrieve", bytes.NewBuffer(validRetrieveBody))
	reqValidRet.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqValidRet.Header.Set("X-CSRF-Token", session.CSRFToken)
	wValidRet := httptest.NewRecorder()
	handler.ServeHTTP(wValidRet, reqValidRet)
	if wValidRet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid retrieve, got %d: %s", wValidRet.Code, wValidRet.Body.String())
	}
	var retResp struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		ClientCiphertext string `json:"client_ciphertext"`
		WrappedMEK       string `json:"wrapped_mek"`
	}
	_ = json.Unmarshal(wValidRet.Body.Bytes(), &retResp)
	if retResp.ID != createdKeyID || retResp.Name != "github-token" || retResp.ClientCiphertext == "" {
		t.Fatalf("unexpected retrieve response: %+v", retResp)
	}
	decCT, _ := base64.RawURLEncoding.DecodeString(retResp.ClientCiphertext)
	if string(decCT) != "client-enc-token" {
		t.Fatalf("retrieved ciphertext mismatch: expected 'client-enc-token', got %q", string(decCT))
	}

	// 6e. Key update with simulated step-up succeeds with 200
	simulatedStepUpUpd := "simulated-stepup-upd-key"
	srv.authSvc.AddTestStepUpSession(simulatedStepUpUpd, userID, credID)
	updateBody, _ := json.Marshal(map[string]any{
		"name":              "github-token-v2",
		"client_ciphertext": base64.RawURLEncoding.EncodeToString([]byte("client-enc-token-v2")),
		"client_iv":         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		"client_salt":       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"step_up_id":        simulatedStepUpUpd,
		"assertion":         map[string]any{"simulated": true},
	})
	reqUpd := httptest.NewRequest("PUT", "/api/v1/keys/"+createdKeyID, bytes.NewBuffer(updateBody))
	reqUpd.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqUpd.Header.Set("X-CSRF-Token", session.CSRFToken)
	wUpd := httptest.NewRecorder()
	handler.ServeHTTP(wUpd, reqUpd)
	if wUpd.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for update, got %d: %s", wUpd.Code, wUpd.Body.String())
	}

	// 6f. Key delete with simulated step-up succeeds with 200
	simulatedStepUpDel := "simulated-stepup-del-key"
	srv.authSvc.AddTestStepUpSession(simulatedStepUpDel, userID, credID)
	delBody, _ := json.Marshal(map[string]any{
		"step_up_id": simulatedStepUpDel,
		"assertion":  map[string]any{"simulated": true},
	})
	reqDel := httptest.NewRequest("DELETE", "/api/v1/keys/"+createdKeyID, bytes.NewBuffer(delBody))
	reqDel.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqDel.Header.Set("X-CSRF-Token", session.CSRFToken)
	wDel := httptest.NewRecorder()
	handler.ServeHTTP(wDel, reqDel)
	if wDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for delete, got %d: %s", wDel.Code, wDel.Body.String())
	}

	// 6g. Follow-up challenge for deleted key returns 404
	reqChalDeleted := httptest.NewRequest("POST", "/api/v1/keys/"+createdKeyID+"/challenge", nil)
	reqChalDeleted.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqChalDeleted.Header.Set("X-CSRF-Token", session.CSRFToken)
	wChalDeleted := httptest.NewRecorder()
	handler.ServeHTTP(wChalDeleted, reqChalDeleted)
	if wChalDeleted.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found after deletion, got %d", wChalDeleted.Code)
	}

	// 7. Test Automated/Manual Backup Trigger
	reqBackup := httptest.NewRequest("POST", "/api/v1/admin/backup", nil)
	reqBackup.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqBackup.Header.Set("X-CSRF-Token", session.CSRFToken)
	wBackup := httptest.NewRecorder()
	handler.ServeHTTP(wBackup, reqBackup)
	if wBackup.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for backup, got %d: %s", wBackup.Code, wBackup.Body.String())
	}

	var backupResp struct {
		Status     string `json:"status"`
		BackupPath string `json:"backup_path"`
	}
	_ = json.Unmarshal(wBackup.Body.Bytes(), &backupResp)
	if backupResp.Status != "backup_success" || backupResp.BackupPath == "" {
		t.Fatalf("unexpected backup response: %+v", backupResp)
	}
	if _, err := os.Stat(backupResp.BackupPath); err != nil {
		t.Fatalf("backup file not created at %s", backupResp.BackupPath)
	}
	if _, err := os.Stat(backupResp.BackupPath + ".sha256"); err != nil {
		t.Fatalf("checksum file not created at %s.sha256", backupResp.BackupPath)
	}
}

func TestDeviceRequestAPI(t *testing.T) {
	_, handler, database, sealMgr, sessionMgr, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer database.Close()

	ctx := context.Background()
	_ = sealMgr.InitSMK("my-admin-passphrase-8888")

	userID := uuid.NewString()
	username := "frank"
	_ = database.CreateUser(ctx, userID, username, "Frank")

	credID := []byte("frank-cred-1")
	_ = database.CreateCredential(ctx, &db.Credential{
		ID:              credID,
		UserID:          userID,
		DeviceName:      "Frank Old Phone",
		PublicKey:       []byte("frank-key"),
		AttestationType: "none",
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("wrapped-mek"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	})

	session, _ := sessionMgr.CreateSession(userID, credID)

	// 1. New Phone initiates add_phone request
	initPayload := map[string]string{
		"username":               username,
		"action_type":            "add_phone",
		"device_name":            "Frank New Phone",
		"new_device_ecdh_pub":    base64.RawURLEncoding.EncodeToString([]byte("ephemeral-ecdh-pub")),
		"verification_code_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
	}
	initBytes, _ := json.Marshal(initPayload)
	reqInit := httptest.NewRequest("POST", "/api/v1/devices/request", bytes.NewBuffer(initBytes))
	wInit := httptest.NewRecorder()
	handler.ServeHTTP(wInit, reqInit)

	if wInit.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", wInit.Code, wInit.Body.String())
	}
	var initResp struct {
		RequestID string `json:"request_id"`
		ExpiresIn int    `json:"expires_in"`
	}
	_ = json.Unmarshal(wInit.Body.Bytes(), &initResp)
	if initResp.RequestID == "" || initResp.ExpiresIn != 300 {
		t.Fatalf("unexpected init response: %+v", initResp)
	}

	// 2. Verified Device lists pending requests
	reqPending := httptest.NewRequest("GET", "/api/v1/devices/requests/pending", nil)
	reqPending.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	wPending := httptest.NewRecorder()
	handler.ServeHTTP(wPending, reqPending)

	if wPending.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", wPending.Code)
	}
	var pendingResp struct {
		Requests []db.DeviceRequest `json:"requests"`
	}
	_ = json.Unmarshal(wPending.Body.Bytes(), &pendingResp)
	if len(pendingResp.Requests) != 1 || pendingResp.Requests[0].NewDeviceName != "Frank New Phone" {
		t.Fatalf("unexpected pending requests: %+v", pendingResp)
	}

	// 3. New phone checks status
	reqStatus := httptest.NewRequest("GET", "/api/v1/devices/requests/"+initResp.RequestID+"/status", nil)
	wStatus := httptest.NewRecorder()
	handler.ServeHTTP(wStatus, reqStatus)
	if wStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", wStatus.Code)
	}
	var statusResp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(wStatus.Body.Bytes(), &statusResp)
	if statusResp.Status != "pending" {
		t.Fatalf("expected pending status, got %s", statusResp.Status)
	}
}

func TestRateLimiting(t *testing.T) {
	_, handler, database, sealMgr, _, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer database.Close()

	_ = sealMgr.InitSMK("my-admin-passphrase-8888")

	// The /api/v1/devices/request route has a limit of 3 requests/minute per IP
	makeReq := func() int {
		initPayload := map[string]string{
			"username":               "unknown-user",
			"action_type":            "add_phone",
			"device_name":            "Test Rate Limit Phone",
			"new_device_ecdh_pub":    base64.RawURLEncoding.EncodeToString([]byte("ephemeral-ecdh-pub")),
			"verification_code_hash": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		}
		initBytes, _ := json.Marshal(initPayload)
		req := httptest.NewRequest("POST", "/api/v1/devices/request", bytes.NewBuffer(initBytes))
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	// 1st request -> 400 (user not found, but passes rate limit)
	if code := makeReq(); code == http.StatusTooManyRequests {
		t.Fatalf("1st request was rate limited unexpectedly")
	}
	// 2nd request
	if code := makeReq(); code == http.StatusTooManyRequests {
		t.Fatalf("2nd request was rate limited unexpectedly")
	}
	// 3rd request
	if code := makeReq(); code == http.StatusTooManyRequests {
		t.Fatalf("3rd request was rate limited unexpectedly")
	}
	// 4th request MUST be 429 Too Many Requests
	if code := makeReq(); code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests on 4th call, got %d", code)
	}
}

func TestKeyCreationLimits(t *testing.T) {
	_, handler, database, sealMgr, sessionMgr, tempDir := setupTestServer(t)
	defer os.RemoveAll(tempDir)
	defer database.Close()

	if err := sealMgr.InitSMK("my-secure-startup-passphrase-1234"); err != nil {
		t.Fatalf("InitSMK failed: %v", err)
	}

	ctx := context.Background()
	userID := uuid.NewString()
	username := "limituser"
	if err := database.CreateUser(ctx, userID, username, "Limit User"); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	session, err := sessionMgr.CreateSession(userID, []byte("cred-id"))
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// 1. Key payload exceeding 10KB (10,240 bytes) is rejected with 400 and key_payload_too_large
	largeCiphertext := make([]byte, 10*1024+1)
	largePayload := map[string]any{
		"name":              "too-large-key",
		"client_ciphertext": base64.RawURLEncoding.EncodeToString(largeCiphertext),
		"client_iv":         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		"client_salt":       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	bodyBytes, _ := json.Marshal(largePayload)

	req := httptest.NewRequest("POST", "/api/v1/keys", bytes.NewBuffer(bodyBytes))
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	req.Header.Set("X-CSRF-Token", session.CSRFToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for oversized key, got %d: %s", w.Code, w.Body.String())
	}
	var errResp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp["error"] != "key_payload_too_large" {
		t.Fatalf("expected error key_payload_too_large, got %+v", errResp)
	}

	// 2. Per-user key limit (1000 keys)
	// Pre-seed 1000 keys for userID in a single transaction
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx failed: %v", err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO keys (
		id, user_id, name, name_normalized, server_ciphertext,
		server_iv, server_salt, client_iv, client_salt, creator_ip, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatalf("PrepareContext failed: %v", err)
	}
	for i := 0; i < 1000; i++ {
		kID := fmt.Sprintf("lim-k-%04d", i)
		kName := fmt.Sprintf("lim-key-%04d", i)
		_, err := stmt.ExecContext(ctx, kID, userID, kName, strings.ToLower(kName), []byte("ct"), make([]byte, 12), make([]byte, 32), make([]byte, 12), make([]byte, 32), "192.0.2.1")
		if err != nil {
			t.Fatalf("insert failed: %v", err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	validPayload := map[string]any{
		"name":              "valid-size-key-overflow",
		"client_ciphertext": base64.RawURLEncoding.EncodeToString([]byte("safe-payload")),
		"client_iv":         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		"client_salt":       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	validBytes, _ := json.Marshal(validPayload)

	reqUserLimit := httptest.NewRequest("POST", "/api/v1/keys", bytes.NewBuffer(validBytes))
	reqUserLimit.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqUserLimit.Header.Set("X-CSRF-Token", session.CSRFToken)
	wUserLimit := httptest.NewRecorder()
	handler.ServeHTTP(wUserLimit, reqUserLimit)

	if wUserLimit.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for user key limit, got %d: %s", wUserLimit.Code, wUserLimit.Body.String())
	}
	var userErrResp map[string]string
	_ = json.Unmarshal(wUserLimit.Body.Bytes(), &userErrResp)
	if userErrResp["error"] != "user_key_limit_exceeded" {
		t.Fatalf("expected error user_key_limit_exceeded, got %+v", userErrResp)
	}

	// 3. Per-IP key limit (10,000 keys)
	// Create a new user with 0 keys
	user2ID := uuid.NewString()
	_ = database.CreateUser(ctx, user2ID, "user2ip", "User 2 IP")
	session2, _ := sessionMgr.CreateSession(user2ID, []byte("cred2-id"))

	// Pre-seed 10,000 keys for IP "203.0.113.55"
	targetIP := "203.0.113.55"
	txIP, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx failed: %v", err)
	}
	for u := 0; u < 11; u++ {
		dummyUID := fmt.Sprintf("dummy-u-%d", u)
		_, _ = txIP.ExecContext(ctx, `INSERT INTO users (id, username, display_name) VALUES (?, ?, ?)`, dummyUID, dummyUID, dummyUID)
	}
	stmtIP, err := txIP.PrepareContext(ctx, `INSERT INTO keys (
		id, user_id, name, name_normalized, server_ciphertext,
		server_iv, server_salt, client_iv, client_salt, creator_ip, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatalf("PrepareContext failed: %v", err)
	}
	for i := 0; i < 10000; i++ {
		dummyUID := fmt.Sprintf("dummy-u-%d", i/950)
		kID := fmt.Sprintf("ip10k-%05d", i)
		kName := fmt.Sprintf("ip10k-%05d", i)
		_, err := stmtIP.ExecContext(ctx, kID, dummyUID, kName, strings.ToLower(kName), []byte("ct"), make([]byte, 12), make([]byte, 32), make([]byte, 12), make([]byte, 32), targetIP)
		if err != nil {
			t.Fatalf("insert IP key failed: %v", err)
		}
	}
	stmtIP.Close()
	if err := txIP.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Attempt to create key from targetIP via X-Forwarded-For header
	reqIPLimit := httptest.NewRequest("POST", "/api/v1/keys", bytes.NewBuffer(validBytes))
	reqIPLimit.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session2.ID})
	reqIPLimit.Header.Set("X-CSRF-Token", session2.CSRFToken)
	reqIPLimit.Header.Set("X-Forwarded-For", targetIP)
	wIPLimit := httptest.NewRecorder()
	handler.ServeHTTP(wIPLimit, reqIPLimit)

	if wIPLimit.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for IP key limit, got %d: %s", wIPLimit.Code, wIPLimit.Body.String())
	}
	var ipErrResp map[string]string
	_ = json.Unmarshal(wIPLimit.Body.Bytes(), &ipErrResp)
	if ipErrResp["error"] != "ip_key_limit_exceeded" {
		t.Fatalf("expected error ip_key_limit_exceeded, got %+v", ipErrResp)
	}

	// Same user from a different IP succeeds
	reqDifferentIP := httptest.NewRequest("POST", "/api/v1/keys", bytes.NewBuffer(validBytes))
	reqDifferentIP.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session2.ID})
	reqDifferentIP.Header.Set("X-CSRF-Token", session2.CSRFToken)
	reqDifferentIP.Header.Set("X-Forwarded-For", "203.0.113.56")
	wDifferentIP := httptest.NewRecorder()
	handler.ServeHTTP(wDifferentIP, reqDifferentIP)

	if wDifferentIP.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for different IP, got %d: %s", wDifferentIP.Code, wDifferentIP.Body.String())
	}

	// 4. Malformed X-Forwarded-For fallback:
	// A request with malformed X-Forwarded-For (e.g. commas/spaces) must fall back to RemoteAddr
	reqMalformedXFF := httptest.NewRequest("POST", "/api/v1/keys", bytes.NewBuffer(validBytes))
	reqMalformedXFF.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session2.ID})
	reqMalformedXFF.Header.Set("X-CSRF-Token", session2.CSRFToken)
	reqMalformedXFF.Header.Set("X-Forwarded-For", "  ,  ,  ")
	reqMalformedXFF.RemoteAddr = targetIP + ":45678" // Points to targetIP which is maxed out
	wMalformedXFF := httptest.NewRecorder()
	handler.ServeHTTP(wMalformedXFF, reqMalformedXFF)

	if wMalformedXFF.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when falling back to maxed out RemoteAddr, got %d", wMalformedXFF.Code)
	}
	var malformedResp map[string]string
	_ = json.Unmarshal(wMalformedXFF.Body.Bytes(), &malformedResp)
	if malformedResp["error"] != "ip_key_limit_exceeded" {
		t.Fatalf("expected ip_key_limit_exceeded on fallback, got %+v", malformedResp)
	}

	// 5. Update key with >10KB payload returns 400 key_payload_too_large
	// Create a valid key to update
	newKeyPayload := map[string]any{
		"name":              "key-for-update-test",
		"client_ciphertext": base64.RawURLEncoding.EncodeToString([]byte("safe-payload")),
		"client_iv":         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		"client_salt":       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	newKeyBytes, _ := json.Marshal(newKeyPayload)
	reqCreate := httptest.NewRequest("POST", "/api/v1/keys", bytes.NewBuffer(newKeyBytes))
	reqCreate.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session2.ID})
	reqCreate.Header.Set("X-CSRF-Token", session2.CSRFToken)
	reqCreate.Header.Set("X-Forwarded-For", "203.0.113.99")
	wCreate := httptest.NewRecorder()
	handler.ServeHTTP(wCreate, reqCreate)
	if wCreate.Code != http.StatusOK {
		t.Fatalf("create key for update test failed: %d %s", wCreate.Code, wCreate.Body.String())
	}
	var createResp map[string]any
	_ = json.Unmarshal(wCreate.Body.Bytes(), &createResp)
	createdKeyID := createResp["id"].(string)

	updateOversized := map[string]any{
		"name":              "updated-name",
		"client_ciphertext": base64.RawURLEncoding.EncodeToString(make([]byte, keys.MaxKeySizeBytes+1)),
		"client_iv":         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		"client_salt":       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"stepUpID":          "test-stepup",
		"assertion":         map[string]any{},
	}
	upBytes, _ := json.Marshal(updateOversized)
	reqUp := httptest.NewRequest("PUT", "/api/v1/keys/"+createdKeyID, bytes.NewBuffer(upBytes))
	reqUp.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session2.ID})
	reqUp.Header.Set("X-CSRF-Token", session2.CSRFToken)
	wUp := httptest.NewRecorder()
	handler.ServeHTTP(wUp, reqUp)

	if wUp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for oversized key update, got %d: %s", wUp.Code, wUp.Body.String())
	}
	var upErrResp map[string]string
	_ = json.Unmarshal(wUp.Body.Bytes(), &upErrResp)
	if upErrResp["error"] != "key_payload_too_large" {
		t.Fatalf("expected key_payload_too_large for update, got %+v", upErrResp)
	}
}
