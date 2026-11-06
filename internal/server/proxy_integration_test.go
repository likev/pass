package server

import (
	"bytes"
	"context"
	"encoding/json"
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

func setupTestServerForProxy(t *testing.T) (*Server, http.Handler, *db.DB, *crypto.SealManager, *auth.SessionManager, string) {
	tempDir, err := os.MkdirTemp("", "proxy-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tempDir, "proxy_test.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	cfg := &config.Config{
		Port:                "8082",
		Host:                "localhost",
		DBPath:              dbPath,
		SealedSMKPath:       filepath.Join(tempDir, "server_master.key.enc"),
		BackupDir:           filepath.Join(tempDir, "backups"),
		BackupRetentionDays: 30,
		RPID:                "localhost",
		RPDisplayName:       "Test RP",
		RPOrigins:           []string{"http://localhost:8082", "https://localhost:8082"},
	}

	sealMgr := crypto.NewSealManager(cfg.SealedSMKPath)
	_ = sealMgr.InitSMK("my-test-startup-passphrase-1234")

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

func TestLocalHTTPVsProxyHTTPSCookiesAndHeaders(t *testing.T) {
	_, handler, database, _, sessionMgr, tempDir := setupTestServerForProxy(t)
	defer os.RemoveAll(tempDir)
	defer database.Close()

	ctx := context.Background()
	userID := uuid.NewString()
	username := "proxytester"
	_ = database.CreateUser(ctx, userID, username, "Proxy Tester")
	credID := []byte("proxy-cred-1")
	_ = database.CreateCredential(ctx, &db.Credential{
		ID:              credID,
		UserID:          userID,
		DeviceName:      "Test Device",
		PublicKey:       []byte("dummy-key"),
		AttestationType: "none",
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("wrapped-mek"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	})
	session, _ := sessionMgr.CreateSession(userID, credID)

	// 1. Local HTTP testing on localhost:8082
	// Verify:
	// - HSTS is NOT set
	// - WebAuthn registration begin returns rp.id == "localhost"
	regBody := `{"username": "newlocaluser", "display_name": "New Local User"}`
	reqHTTP := httptest.NewRequest("POST", "/api/v1/auth/register/begin", bytes.NewBufferString(regBody))
	reqHTTP.Host = "localhost:8082"
	wHTTP := httptest.NewRecorder()
	handler.ServeHTTP(wHTTP, reqHTTP)

	if wHTTP.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on local HTTP register/begin, got %d: %s", wHTTP.Code, wHTTP.Body.String())
	}
	if hsts := wHTTP.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Fatalf("expected no Strict-Transport-Security on local HTTP, got %s", hsts)
	}
	var regRespHTTP struct {
		Options struct {
			PublicKey struct {
				RelyingParty struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"rp"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	_ = json.Unmarshal(wHTTP.Body.Bytes(), &regRespHTTP)
	if regRespHTTP.Options.PublicKey.RelyingParty.ID != "localhost" {
		t.Fatalf("expected RP ID localhost on local HTTP, got %s (body: %s)", regRespHTTP.Options.PublicKey.RelyingParty.ID, wHTTP.Body.String())
	}

	// Local HTTP logout: cookie Secure attribute must be false
	reqLogoutHTTP := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	reqLogoutHTTP.Host = "localhost:8082"
	reqLogoutHTTP.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqLogoutHTTP.Header.Set("X-CSRF-Token", session.CSRFToken)
	wLogoutHTTP := httptest.NewRecorder()
	handler.ServeHTTP(wLogoutHTTP, reqLogoutHTTP)

	cookieHTTP := wLogoutHTTP.Header().Get("Set-Cookie")
	if strings.Contains(cookieHTTP, "Secure") {
		t.Fatalf("expected local HTTP Set-Cookie to NOT have Secure flag, got %s", cookieHTTP)
	}

	// 2. Behind Caddy Reverse Proxy (HTTPS termination, custom domain)
	// Headers: X-Forwarded-Proto: https, X-Forwarded-Host: vault.caddy-domain.local
	// Verify:
	// - HSTS IS set
	// - WebAuthn registration begin returns rp.id == "vault.caddy-domain.local"
	regBodyCaddy := `{"username": "caddyuser", "display_name": "Caddy User"}`
	reqCaddy := httptest.NewRequest("POST", "/api/v1/auth/register/begin", bytes.NewBufferString(regBodyCaddy))
	reqCaddy.Host = "localhost:8082" // Backend listening host
	reqCaddy.Header.Set("X-Forwarded-Proto", "https")
	reqCaddy.Header.Set("X-Forwarded-Host", "vault.caddy-domain.local")
	wCaddy := httptest.NewRecorder()
	handler.ServeHTTP(wCaddy, reqCaddy)

	if wCaddy.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on Caddy proxy register/begin, got %d: %s", wCaddy.Code, wCaddy.Body.String())
	}
	if hsts := wCaddy.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Fatalf("expected Strict-Transport-Security to be set behind HTTPS proxy")
	}
	var regRespCaddy struct {
		Options struct {
			PublicKey struct {
				RelyingParty struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"rp"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	_ = json.Unmarshal(wCaddy.Body.Bytes(), &regRespCaddy)
	if regRespCaddy.Options.PublicKey.RelyingParty.ID != "vault.caddy-domain.local" {
		t.Fatalf("expected RP ID vault.caddy-domain.local, got %s (body: %s)", regRespCaddy.Options.PublicKey.RelyingParty.ID, wCaddy.Body.String())
	}

	// Caddy proxy logout: cookie Secure attribute MUST be true
	reqLogoutCaddy := httptest.NewRequest("POST", "/api/v1/auth/logout", nil)
	reqLogoutCaddy.Header.Set("X-Forwarded-Proto", "https")
	reqLogoutCaddy.Header.Set("X-Forwarded-Host", "vault.caddy-domain.local")
	reqLogoutCaddy.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqLogoutCaddy.Header.Set("X-CSRF-Token", session.CSRFToken)
	wLogoutCaddy := httptest.NewRecorder()
	handler.ServeHTTP(wLogoutCaddy, reqLogoutCaddy)

	cookieCaddy := wLogoutCaddy.Header().Get("Set-Cookie")
	if !strings.Contains(cookieCaddy, "Secure") {
		t.Fatalf("expected Caddy HTTPS Set-Cookie to have Secure flag, got %s", cookieCaddy)
	}

	// 3. Behind Cloudflare (HTTPS termination, Host header set, Cf-Visitor, CF-Connecting-IP)
	regBodyCF := `{"username": "cfuser", "display_name": "Cloudflare User"}`
	reqCF := httptest.NewRequest("POST", "/api/v1/auth/register/begin", bytes.NewBufferString(regBodyCF))
	reqCF.Host = "pass.cloudflare-site.com"
	reqCF.Header.Set("X-Forwarded-Proto", "https")
	reqCF.Header.Set("Cf-Visitor", `{"scheme":"https"}`)
	reqCF.Header.Set("CF-Connecting-IP", "203.0.113.77")
	wCF := httptest.NewRecorder()
	handler.ServeHTTP(wCF, reqCF)

	if wCF.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on Cloudflare register/begin, got %d: %s", wCF.Code, wCF.Body.String())
	}
	var regRespCF struct {
		Options struct {
			PublicKey struct {
				RelyingParty struct {
					ID string `json:"id"`
				} `json:"rp"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	_ = json.Unmarshal(wCF.Body.Bytes(), &regRespCF)
	if regRespCF.Options.PublicKey.RelyingParty.ID != "pass.cloudflare-site.com" {
		t.Fatalf("expected RP ID pass.cloudflare-site.com, got %s (body: %s)", regRespCF.Options.PublicKey.RelyingParty.ID, wCF.Body.String())
	}
}

func TestWebAuthnLoginAndStepUpBehindProxy(t *testing.T) {
	srv, handler, database, _, sessionMgr, tempDir := setupTestServerForProxy(t)
	defer os.RemoveAll(tempDir)
	defer database.Close()

	ctx := context.Background()
	userID := uuid.NewString()
	username := "stepuptester"
	_ = database.CreateUser(ctx, userID, username, "StepUp Tester")
	credID := []byte("stepup-cred-1")
	_ = database.CreateCredential(ctx, &db.Credential{
		ID:              credID,
		UserID:          userID,
		DeviceName:      "Tester Phone",
		PublicKey:       []byte("dummy-key"),
		AttestationType: "none",
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("wrapped-mek"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	})
	session, _ := sessionMgr.CreateSession(userID, credID)

	// Add simulated key
	kMeta, err := srv.keySvc.CreateKey(ctx, userID, &keys.CreateKeyPayload{
		Name:             "my-secret-key",
		ClientCiphertext: "c2VjcmV0LWN0",
		ClientIV:         "AQEBAQEBAQEBAQEB",
		ClientSalt:       "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	// 1. Login begin behind reverse proxy respects RP ID
	loginBody := `{"username": "stepuptester"}`
	reqLogin := httptest.NewRequest("POST", "/api/v1/auth/login/begin", bytes.NewBufferString(loginBody))
	reqLogin.Header.Set("X-Forwarded-Proto", "https")
	reqLogin.Header.Set("X-Forwarded-Host", "vault.mycompany.com")
	wLogin := httptest.NewRecorder()
	handler.ServeHTTP(wLogin, reqLogin)

	if wLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for login begin, got %d: %s", wLogin.Code, wLogin.Body.String())
	}
	var loginResp struct {
		Options struct {
			PublicKey struct {
				RelyingPartyID string `json:"rpId"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	_ = json.Unmarshal(wLogin.Body.Bytes(), &loginResp)
	if loginResp.Options.PublicKey.RelyingPartyID != "vault.mycompany.com" {
		t.Fatalf("expected RelyingPartyID vault.mycompany.com, got %s (body: %s)", loginResp.Options.PublicKey.RelyingPartyID, wLogin.Body.String())
	}

	// 2. Step-up challenge behind reverse proxy respects RP ID
	reqChal := httptest.NewRequest("POST", "/api/v1/keys/"+kMeta.ID+"/challenge", nil)
	reqChal.Header.Set("X-Forwarded-Proto", "https")
	reqChal.Header.Set("X-Forwarded-Host", "vault.mycompany.com")
	reqChal.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqChal.Header.Set("X-CSRF-Token", session.CSRFToken)
	wChal := httptest.NewRecorder()
	handler.ServeHTTP(wChal, reqChal)

	if wChal.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for key challenge, got %d: %s", wChal.Code, wChal.Body.String())
	}
	var chalResp struct {
		Options struct {
			PublicKey struct {
				RelyingPartyID string `json:"rpId"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	_ = json.Unmarshal(wChal.Body.Bytes(), &chalResp)
	if chalResp.Options.PublicKey.RelyingPartyID != "vault.mycompany.com" {
		t.Fatalf("expected step-up rpId vault.mycompany.com, got %s (body: %s)", chalResp.Options.PublicKey.RelyingPartyID, wChal.Body.String())
	}
}

func TestDeviceRequestAndDynamicOriginProxy(t *testing.T) {
	srv, handler, database, _, sessionMgr, tempDir := setupTestServerForProxy(t)
	defer os.RemoveAll(tempDir)
	defer database.Close()

	ctx := context.Background()
	userID := uuid.NewString()
	username := "devicetester"
	_ = database.CreateUser(ctx, userID, username, "Device Tester")
	credID := []byte("device-cred-1")
	_ = database.CreateCredential(ctx, &db.Credential{
		ID:              credID,
		UserID:          userID,
		DeviceName:      "Old Phone",
		PublicKey:       []byte("dummy-key"),
		AttestationType: "none",
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("wrapped-mek"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	})
	session, _ := sessionMgr.CreateSession(userID, credID)

	// 1. Device request initiate behind Caddy reverse proxy
	initiateBody := `{"username": "devicetester", "action_type": "add_phone", "device_name": "New Tablet", "new_device_ecdh_pub": "ZHVtbXktcHVi", "verification_code_hash": "dummyhash"}`
	reqInit := httptest.NewRequest("POST", "/api/v1/devices/request", bytes.NewBufferString(initiateBody))
	reqInit.Header.Set("X-Forwarded-Proto", "https")
	reqInit.Header.Set("X-Forwarded-Host", "vault.proxydomain.net")
	wInit := httptest.NewRecorder()
	handler.ServeHTTP(wInit, reqInit)

	if wInit.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for device request initiate, got %d: %s", wInit.Code, wInit.Body.String())
	}
	var initResp struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(wInit.Body.Bytes(), &initResp)

	// 2. Approve device request behind proxy
	stepUpID := "approve-stepup-sim"
	srv.authSvc.AddTestStepUpSession(stepUpID, userID, credID)

	approveBody := `{"step_up_id": "approve-stepup-sim", "assertion": "", "approver_ecdh_pub": "YXBwcm92ZXItcHVi", "encrypted_mek_transfer": "ZW5jLW1law==", "transfer_iv": "MDEyMzQ1Njc4OTAx"}`
	reqApprove := httptest.NewRequest("POST", "/api/v1/devices/requests/"+initResp.RequestID+"/approve", bytes.NewBufferString(approveBody))
	reqApprove.Header.Set("X-Forwarded-Proto", "https")
	reqApprove.Header.Set("X-Forwarded-Host", "vault.proxydomain.net")
	reqApprove.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})
	reqApprove.Header.Set("X-CSRF-Token", session.CSRFToken)
	wApprove := httptest.NewRecorder()
	handler.ServeHTTP(wApprove, reqApprove)

	if wApprove.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for device approve, got %d: %s", wApprove.Code, wApprove.Body.String())
	}

	// 3. Status check returns approved with WebAuthn options having RP ID == "vault.proxydomain.net"
	reqStatus := httptest.NewRequest("GET", "/api/v1/devices/requests/"+initResp.RequestID+"/status", nil)
	reqStatus.Header.Set("X-Forwarded-Proto", "https")
	reqStatus.Header.Set("X-Forwarded-Host", "vault.proxydomain.net")
	wStatus := httptest.NewRecorder()
	handler.ServeHTTP(wStatus, reqStatus)

	if wStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for device status, got %d: %s", wStatus.Code, wStatus.Body.String())
	}
	var statusResp struct {
		Status     string `json:"status"`
		RegOptions *struct {
			PublicKey struct {
				RelyingParty struct {
					ID string `json:"id"`
				} `json:"rp"`
			} `json:"publicKey"`
		} `json:"reg_options"`
	}
	_ = json.Unmarshal(wStatus.Body.Bytes(), &statusResp)

	if statusResp.Status != "approved" {
		t.Fatalf("expected status approved, got %s", statusResp.Status)
	}
	if statusResp.RegOptions == nil || statusResp.RegOptions.PublicKey.RelyingParty.ID != "vault.proxydomain.net" {
		t.Fatalf("expected RP ID vault.proxydomain.net in approved options, got %+v", statusResp.RegOptions)
	}
}
