package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"passmanager/internal/config"
	"passmanager/internal/db"
)

func TestSessionManager(t *testing.T) {
	sm := NewSessionManager()
	userID := "user-123"
	credID := []byte("cred-123")

	sess, err := sm.CreateSession(userID, credID)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	retrieved, err := sm.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if retrieved.UserID != userID || retrieved.CSRFToken == "" {
		t.Fatalf("Retrieved session incorrect: %+v", retrieved)
	}

	sm.InvalidateSession(sess.ID)
	if _, err := sm.GetSession(sess.ID); err != ErrSessionNotFound {
		t.Fatalf("Expected ErrSessionNotFound after invalidation, got %v", err)
	}
}

func TestDeviceVerificationStateMachine(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "auth-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "auth.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer database.Close()

	cfg := &config.Config{
		RPID:          "localhost",
		RPDisplayName: "Test RP",
		RPOrigins:     []string{"http://localhost:8080"},
	}

	sm := NewSessionManager()
	authSvc, err := NewAuthService(database, cfg, sm)
	if err != nil {
		t.Fatalf("failed to create auth service: %v", err)
	}
	devMgr := NewDeviceManager(database, authSvc, sm)
	ctx := context.Background()

	// Create user
	userID := uuid.NewString()
	username := "bob"
	if err := database.CreateUser(ctx, userID, username, "Bob"); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Add primary credential
	cred1ID := []byte("cred-phone-primary")
	cred1 := &db.Credential{
		ID:              cred1ID,
		UserID:          userID,
		DeviceName:      "Bob Old Phone",
		PublicKey:       []byte("pubkey-1"),
		AttestationType: "none",
		AAGUID:          make([]byte, 16),
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("wrapped-mek-1"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	}
	if err := database.CreateCredential(ctx, cred1); err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}

	// 1. Strictly cannot revoke last verified device
	err = devMgr.RevokeDevice(ctx, userID, cred1ID, "dummy-stepup", nil)
	if !errors.Is(err, ErrCannotRevokeLastDevice) {
		t.Fatalf("Expected ErrCannotRevokeLastDevice when only 1 device exists, got %v", err)
	}

	// 2. Add a secondary device to verify revocation works when >1 device exists
	cred2ID := []byte("cred-phone-secondary")
	cred2 := &db.Credential{
		ID:              cred2ID,
		UserID:          userID,
		DeviceName:      "Bob Tablet",
		PublicKey:       []byte("pubkey-2"),
		AttestationType: "none",
		AAGUID:          make([]byte, 16),
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("wrapped-mek-2"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	}
	if err := database.CreateCredential(ctx, cred2); err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}

	// Revoke secondary device using simulated step-up
	stepUpID := "step-up-revoke-test"
	authSvc.AddTestStepUpSession(stepUpID, userID, cred1ID)
	if err := devMgr.RevokeDevice(ctx, userID, cred2ID, stepUpID, nil); err != nil {
		t.Fatalf("RevokeDevice failed when 2 devices exist: %v", err)
	}

	c2, _ := database.GetCredentialByID(ctx, cred2ID)
	if c2.Status != "revoked" {
		t.Fatalf("Expected cred2 to be revoked, got %s", c2.Status)
	}

	// 3. Initiate device request for change_phone
	reqPayload := &RequestInitiatePayload{
		Username:             username,
		ActionType:           "change_phone",
		ReplaceCredentialID:  "Y3JlZC1waG9uZS1wcmltYXJ5", // base64 of cred-phone-primary
		DeviceName:           "Bob New Phone",
		NewDeviceECDHPub:     "ZHVtbXktZWNkaC1wdWI=",      // dummy-ecdh-pub
		VerificationCodeHash: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
	}

	reqID, expiresIn, err := devMgr.InitiateRequest(ctx, reqPayload)
	if err != nil {
		t.Fatalf("InitiateRequest failed: %v", err)
	}
	if expiresIn != 300 || reqID == "" {
		t.Fatalf("Unexpected reqID or expiresIn: id=%s, exp=%d", reqID, expiresIn)
	}

	// 4. Pending requests can be queried by verified user
	pending, err := devMgr.GetPendingRequests(ctx, userID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("GetPendingRequests failed: pending=%+v, err=%v", pending, err)
	}
	if pending[0].NewDeviceName != "Bob New Phone" {
		t.Fatalf("Unexpected device name: %s", pending[0].NewDeviceName)
	}

	// 5. Status check on new phone before approval
	statusResp, err := devMgr.GetRequestStatus(ctx, reqID)
	if err != nil {
		t.Fatalf("GetRequestStatus failed: %v", err)
	}
	if statusResp.Status != "pending" {
		t.Fatalf("Expected status pending, got %s", statusResp.Status)
	}

	// 6. Approve request via simulated step-up assertion
	approveStepUpID := "step-up-approve-test"
	authSvc.AddTestStepUpSession(approveStepUpID, userID, cred1ID)
	err = devMgr.ApproveRequest(
		ctx,
		reqID,
		userID,
		cred1ID,
		approveStepUpID,
		nil,
		[]byte("approver-ecdh-pub"),
		[]byte("encrypted-mek-transfer"),
		[]byte("transfer-iv-12b"),
	)
	if err != nil {
		t.Fatalf("ApproveRequest failed: %v", err)
	}

	statusRespApproved, err := devMgr.GetRequestStatus(ctx, reqID)
	if err != nil || statusRespApproved.Status != "approved" {
		t.Fatalf("Expected status approved, got %+v", statusRespApproved)
	}

	// 7. Expiry handling
	// Manually set expires_at in the past
	_, err = database.ExecContext(ctx, `UPDATE device_verification_requests SET expires_at = ? WHERE id = ?`,
		time.Now().Add(-1*time.Minute), reqID)
	if err != nil {
		t.Fatalf("Failed to update expires_at: %v", err)
	}

	statusRespAfterExpiry, err := devMgr.GetRequestStatus(ctx, reqID)
	if err != nil {
		t.Fatalf("GetRequestStatus failed: %v", err)
	}
	if statusRespAfterExpiry.Status != "expired" {
		t.Fatalf("Expected status expired, got %s", statusRespAfterExpiry.Status)
	}
}
