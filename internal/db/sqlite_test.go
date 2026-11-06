package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDBLifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "testdb-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")
	database, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	// 0. Verify secure_delete is enabled
	var secureDelete int
	if err := database.QueryRowContext(ctx, "PRAGMA secure_delete;").Scan(&secureDelete); err != nil {
		t.Fatalf("failed to query secure_delete pragma: %v", err)
	}
	if secureDelete != 1 {
		t.Fatalf("expected PRAGMA secure_delete=1 (ON), got %d", secureDelete)
	}

	// 1. Create User
	userID := uuid.NewString()
	username := "alice"
	displayName := "Alice Wonderland"
	if err := database.CreateUser(ctx, userID, username, displayName); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	user, err := database.GetUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("GetUserByUsername failed: %v", err)
	}
	if user.ID != userID || user.DisplayName != displayName {
		t.Fatalf("User mismatch: got %+v", user)
	}

	// 2. Create Credential
	credID := []byte("cred-1234567890123456")
	cred := &Credential{
		ID:              credID,
		UserID:          userID,
		DeviceName:      "Alice MacBook",
		PublicKey:       []byte("dummy-cose-pubkey"),
		AttestationType: "none",
		AAGUID:          []byte("0000000000000000"),
		SignCount:       0,
		Transports:      `["internal"]`,
		BackupEligible:  true,
		BackupState:     true,
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("wrapped-mek-bytes"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	}
	if err := database.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}

	creds, err := database.GetCredentialsByUserID(ctx, userID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("GetCredentialsByUserID failed: creds=%+v, err=%v", creds, err)
	}

	// 3. Create Key
	keyID := uuid.NewString()
	keyRecord := &Key{
		ID:               keyID,
		UserID:           userID,
		Name:             "prod-db-password",
		NameNormalized:   "prod-db-password",
		ServerCiphertext: []byte("server-encrypted-data"),
		ServerIV:         make([]byte, 12),
		ServerSalt:       make([]byte, 32),
		ClientIV:         make([]byte, 12),
		ClientSalt:       make([]byte, 32),
	}
	if err := database.CreateKey(ctx, keyRecord); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	// 4. List keys metadata
	metas, err := database.ListKeysMetadata(ctx, userID, "db")
	if err != nil || len(metas) != 1 {
		t.Fatalf("ListKeysMetadata failed: metas=%+v, err=%v", metas, err)
	}
	if metas[0].Name != "prod-db-password" {
		t.Fatalf("Unexpected key name in metadata: %s", metas[0].Name)
	}

	// 5. Get Single Key
	k, err := database.GetKeyByID(ctx, keyID, userID)
	if err != nil {
		t.Fatalf("GetKeyByID failed: %v", err)
	}
	if string(k.ServerCiphertext) != "server-encrypted-data" {
		t.Fatalf("Ciphertext mismatch: got %s", string(k.ServerCiphertext))
	}

	// 6. Device Request
	devReqID := uuid.NewString()
	devReq := &DeviceRequest{
		ID:                   devReqID,
		UserID:               userID,
		ActionType:           "add_phone",
		NewDeviceName:        "Alice iPhone",
		VerificationCodeHash: "sha256hashcode",
		NewDeviceECDHPub:     []byte("new-ecdh-pub"),
		ExpiresAt:            time.Now().Add(5 * time.Minute),
	}
	if err := database.CreateDeviceRequest(ctx, devReq); err != nil {
		t.Fatalf("CreateDeviceRequest failed: %v", err)
	}

	pending, err := database.GetPendingDeviceRequests(ctx, userID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("GetPendingDeviceRequests failed: pending=%+v, err=%v", pending, err)
	}

	// 7. Test Atomic CompleteDeviceEnrollmentTx with phone change & revocation
	newPhoneCredID := []byte("cred-new-phone-999")
	newPhoneCred := &Credential{
		ID:              newPhoneCredID,
		UserID:          userID,
		DeviceName:      "Alice iPhone 16",
		PublicKey:       []byte("new-phone-pubkey"),
		AttestationType: "none",
		AAGUID:          make([]byte, 16),
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("new-wrapped-mek"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	}
	auditMsg := "completed enrollment of new device"
	if err := database.CompleteDeviceEnrollmentTx(ctx, newPhoneCred, devReqID, credID, &userID, "127.0.0.1", auditMsg); err != nil {
		t.Fatalf("CompleteDeviceEnrollmentTx failed: %v", err)
	}

	// Verify old device is revoked and new device is verified
	oldC, err := database.GetCredentialByID(ctx, credID)
	if err != nil || oldC.Status != "revoked" {
		t.Fatalf("expected old credential to be revoked, got status=%s, err=%v", oldC.Status, err)
	}
	newC, err := database.GetCredentialByID(ctx, newPhoneCredID)
	if err != nil || newC.Status != "verified" {
		t.Fatalf("expected new credential to be verified, got status=%s, err=%v", newC.Status, err)
	}

	// 8. Test nil context resilience across query methods
	uNil, err := database.GetUserByUsername(nil, username)
	if err != nil || uNil.ID != userID {
		t.Fatalf("GetUserByUsername with nil context failed: %v", err)
	}
	kNil, err := database.GetKeyByID(nil, keyID, userID)
	if err != nil || kNil.ID != keyID {
		t.Fatalf("GetKeyByID with nil context failed: %v", err)
	}

	// 9. Audit log
	if err := database.InsertAuditLog(ctx, &userID, "test_event", "127.0.0.1", "metadata"); err != nil {
		t.Fatalf("InsertAuditLog failed: %v", err)
	}
}
