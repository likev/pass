package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	// 10. Key count queries
	uCount, err := database.CountKeysByUserID(ctx, userID)
	if err != nil || uCount != 1 {
		t.Fatalf("expected CountKeysByUserID=1, got %d, err: %v", uCount, err)
	}
	ipKeyRecord := &Key{
		ID:               uuid.NewString(),
		UserID:           userID,
		Name:             "ip-key",
		NameNormalized:   "ip-key",
		ServerCiphertext: []byte("ct"),
		ServerIV:         make([]byte, 12),
		ServerSalt:       make([]byte, 32),
		ClientIV:         make([]byte, 12),
		ClientSalt:       make([]byte, 32),
		CreatorIP:        "198.51.100.99",
	}
	if err := database.CreateKey(ctx, ipKeyRecord); err != nil {
		t.Fatalf("CreateKey with CreatorIP failed: %v", err)
	}
	ipCount, err := database.CountKeysByIP(ctx, "198.51.100.99")
	if err != nil || ipCount != 1 {
		t.Fatalf("expected CountKeysByIP=1, got %d, err: %v", ipCount, err)
	}

	// 11. Test that SQLite trigger enforces per-user limit at DB level
	// User currently has 2 keys. Pre-seed up to 1000 keys.
	for i := 2; i < 1000; i++ {
		kID := fmt.Sprintf("trg-k-%04d", i)
		kName := fmt.Sprintf("trg-key-%04d", i)
		err := database.CreateKey(ctx, &Key{
			ID:               kID,
			UserID:           userID,
			Name:             kName,
			NameNormalized:   strings.ToLower(kName),
			ServerCiphertext: []byte("ct"),
			ServerIV:         make([]byte, 12),
			ServerSalt:       make([]byte, 32),
			ClientIV:         make([]byte, 12),
			ClientSalt:       make([]byte, 32),
			CreatorIP:        "198.51.100.99",
		})
		if err != nil {
			t.Fatalf("bulk insert failed at %d: %v", i, err)
		}
	}
	// The 1001st key must trigger SQLite abort
	err = database.CreateKey(ctx, &Key{
		ID:               "trg-overflow",
		UserID:           userID,
		Name:             "trg-overflow",
		NameNormalized:   "trg-overflow",
		ServerCiphertext: []byte("ct"),
		ServerIV:         make([]byte, 12),
		ServerSalt:       make([]byte, 32),
		ClientIV:         make([]byte, 12),
		ClientSalt:       make([]byte, 32),
		CreatorIP:        "198.51.100.99",
	})
	if err == nil || !strings.Contains(err.Error(), "per-user limit of 1000 keys exceeded") {
		t.Fatalf("expected SQLite trigger to reject 1001st key, got err: %v", err)
	}
}

func TestLikeWildcardEscapingAndAtomicUserTx(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "passmgr-like-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	database, err := Open(filepath.Join(tempDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer database.Close()

	ctx := context.Background()
	userID := uuid.NewString()
	cred := &Credential{
		ID:              []byte("atomic-cred-1"),
		UserID:          userID,
		DeviceName:      "Initial Phone",
		PublicKey:       []byte("pk"),
		AttestationType: "none",
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("wmek"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	}

	if err := database.CreateUserWithCredentialTx(ctx, userID, "atomic_user", "Atomic User", cred, "127.0.0.1", "registered"); err != nil {
		t.Fatalf("CreateUserWithCredentialTx failed: %v", err)
	}

	for _, name := range []string{"alpha_one", "alphaXone", "100%ers", "1000ers"} {
		err := database.CreateKey(ctx, &Key{
			ID:               uuid.NewString(),
			UserID:           userID,
			Name:             name,
			NameNormalized:   strings.ToLower(name),
			ServerCiphertext: []byte("ct"),
			ServerIV:         make([]byte, 12),
			ServerSalt:       make([]byte, 32),
			ClientIV:         make([]byte, 12),
			ClientSalt:       make([]byte, 32),
			CreatorIP:        "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("CreateKey(%s) failed: %v", name, err)
		}
	}

	// Searching for literal "_" should only match "alpha_one", not "alphaXone"
	underscoreMatches, err := database.ListKeysMetadata(ctx, userID, "alpha_one")
	if err != nil || len(underscoreMatches) != 1 || underscoreMatches[0].Name != "alpha_one" {
		t.Fatalf("expected literal underscore match only, got %+v (err=%v)", underscoreMatches, err)
	}

	// Searching for literal "%" should only match "100%ers", not all keys or "1000ers"
	percentMatches, err := database.ListKeysMetadata(ctx, userID, "%")
	if err != nil || len(percentMatches) != 1 || percentMatches[0].Name != "100%ers" {
		t.Fatalf("expected literal percent match only, got %+v (err=%v)", percentMatches, err)
	}
}
