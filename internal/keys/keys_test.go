package keys

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"passmanager/internal/auth"
	"passmanager/internal/config"
	"passmanager/internal/crypto"
	"passmanager/internal/db"
)

func TestKeyService(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keys-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "keys.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer database.Close()

	smkFile := filepath.Join(tempDir, "server_master.key.enc")
	sealMgr := crypto.NewSealManager(smkFile)
	if err := sealMgr.InitSMK("my-secure-startup-passphrase-1234"); err != nil {
		t.Fatalf("InitSMK failed: %v", err)
	}

	cfg := &config.Config{
		RPID:          "localhost",
		RPDisplayName: "Test RP",
		RPOrigins:     []string{"http://localhost:8080"},
	}
	sm := auth.NewSessionManager()
	authSvc, _ := auth.NewAuthService(database, cfg, sm)
	keySvc := NewKeyService(database, authSvc, sealMgr)

	ctx := context.Background()
	userID := uuid.NewString()
	username := "charlie"
	if err := database.CreateUser(ctx, userID, username, "Charlie"); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	credID := []byte("charlie-cred-123")
	cred := &db.Credential{
		ID:              credID,
		UserID:          userID,
		DeviceName:      "Charlie Laptop",
		PublicKey:       []byte("pubkey"),
		AttestationType: "none",
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("wrapped-mek-bytes"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	}
	if err := database.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}

	// 1. Create a Key
	clientPlaintextCT := []byte("inner-e2ee-encrypted-blob-123")
	clientIV := make([]byte, 12)
	clientSalt := make([]byte, 32)
	payload := &CreateKeyPayload{
		Name:             "prod-aws-token",
		ClientCiphertext: base64.RawURLEncoding.EncodeToString(clientPlaintextCT),
		ClientIV:         base64.RawURLEncoding.EncodeToString(clientIV),
		ClientSalt:       base64.RawURLEncoding.EncodeToString(clientSalt),
	}

	meta, err := keySvc.CreateKey(ctx, userID, payload, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}
	if meta.Name != "prod-aws-token" || meta.ID == "" {
		t.Fatalf("Unexpected metadata: %+v", meta)
	}

	// 2. Duplicate key name fails
	if _, err := keySvc.CreateKey(ctx, userID, payload, "127.0.0.1"); err != ErrDuplicateKey {
		t.Fatalf("Expected ErrDuplicateKey, got %v", err)
	}

	// 3. Metadata list returns key metadata without ciphertext
	keysList, err := keySvc.ListKeys(ctx, userID, "aws")
	if err != nil || len(keysList) != 1 {
		t.Fatalf("ListKeys failed: keys=%+v, err=%v", keysList, err)
	}
	if keysList[0].Name != "prod-aws-token" {
		t.Fatalf("Key name mismatch: %s", keysList[0].Name)
	}

	// 4. Verify in DB directly that server_ciphertext is not raw client ciphertext
	dbKey, err := database.GetKeyByID(ctx, meta.ID, userID)
	if err != nil {
		t.Fatalf("GetKeyByID from DB failed: %v", err)
	}
	if string(dbKey.ServerCiphertext) == string(clientPlaintextCT) {
		t.Fatalf("Server stored raw client ciphertext without envelope encryption!")
	}

	// 5. Gated Single-Key Retrieval: requires step-up passkey assertion
	stepUpID1 := "test-stepup-ret-1"
	authSvc.AddTestStepUpSession(stepUpID1, userID, credID)

	singleKey, err := keySvc.RetrieveSingleKey(ctx, meta.ID, userID, credID, stepUpID1, []byte("simulated-assertion"), "127.0.0.1")
	if err != nil {
		t.Fatalf("RetrieveSingleKey failed: %v", err)
	}
	if singleKey.ID != meta.ID || singleKey.Name != "prod-aws-token" {
		t.Fatalf("Unexpected single key payload: %+v", singleKey)
	}
	// Decrypt client ciphertext in test to confirm it matches original client plaintext CT
	decClientCT, err := base64.RawURLEncoding.DecodeString(singleKey.ClientCiphertext)
	if err != nil || string(decClientCT) != string(clientPlaintextCT) {
		t.Fatalf("Client ciphertext roundtrip mismatch: expected %q, got %q", string(clientPlaintextCT), string(decClientCT))
	}
	if singleKey.WrappedMEK != base64.RawURLEncoding.EncodeToString(cred.WrappedMEK) {
		t.Fatalf("Wrapped MEK mismatch in retrieval")
	}

	// 6. Step-up replay must fail (challenge is single-use)
	_, err = keySvc.RetrieveSingleKey(ctx, meta.ID, userID, credID, stepUpID1, []byte("simulated-assertion"), "127.0.0.1")
	if err == nil {
		t.Fatalf("Expected replay of step-up challenge to fail, but it succeeded")
	}

	// 7. Update Key with step-up assertion
	stepUpID2 := "test-stepup-upd-1"
	authSvc.AddTestStepUpSession(stepUpID2, userID, credID)
	updatedPlaintextCT := []byte("updated-e2ee-secret-456")
	err = keySvc.UpdateKey(
		ctx,
		meta.ID,
		userID,
		"prod-aws-token-updated",
		updatedPlaintextCT,
		clientIV,
		clientSalt,
		stepUpID2,
		[]byte("simulated-assertion"),
		"127.0.0.1",
	)
	if err != nil {
		t.Fatalf("UpdateKey failed: %v", err)
	}

	// Verify retrieval yields updated ciphertext
	stepUpID3 := "test-stepup-ret-2"
	authSvc.AddTestStepUpSession(stepUpID3, userID, credID)
	retrievedUpdated, err := keySvc.RetrieveSingleKey(ctx, meta.ID, userID, credID, stepUpID3, []byte("simulated-assertion"), "127.0.0.1")
	if err != nil {
		t.Fatalf("RetrieveSingleKey after update failed: %v", err)
	}
	if retrievedUpdated.Name != "prod-aws-token-updated" {
		t.Fatalf("Expected updated name, got %s", retrievedUpdated.Name)
	}
	decUpdatedCT, _ := base64.RawURLEncoding.DecodeString(retrievedUpdated.ClientCiphertext)
	if string(decUpdatedCT) != string(updatedPlaintextCT) {
		t.Fatalf("Updated client ciphertext mismatch: expected %q, got %q", string(updatedPlaintextCT), string(decUpdatedCT))
	}

	// 8. Delete Key with step-up assertion
	stepUpID4 := "test-stepup-del-1"
	authSvc.AddTestStepUpSession(stepUpID4, userID, credID)
	err = keySvc.DeleteKey(ctx, meta.ID, userID, stepUpID4, []byte("simulated-assertion"), "127.0.0.1")
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Deleted key should not be retrievable
	stepUpID5 := "test-stepup-ret-3"
	authSvc.AddTestStepUpSession(stepUpID5, userID, credID)
	_, err = keySvc.RetrieveSingleKey(ctx, meta.ID, userID, credID, stepUpID5, []byte("simulated-assertion"), "127.0.0.1")
	if err != ErrKeyNotFound {
		t.Fatalf("Expected ErrKeyNotFound after deletion, got %v", err)
	}

	// 9. Re-create key and verify Sealed SMK prevents retrieval
	stepUpID6 := "test-stepup-ret-4"
	meta2, err := keySvc.CreateKey(ctx, userID, payload, "127.0.0.1")
	if err != nil {
		t.Fatalf("CreateKey 2 failed: %v", err)
	}
	sealMgr.Seal()
	authSvc.AddTestStepUpSession(stepUpID6, userID, credID)
	_, err = keySvc.RetrieveSingleKey(ctx, meta2.ID, userID, credID, stepUpID6, []byte("simulated-assertion"), "127.0.0.1")
	if err != crypto.ErrServerSealed {
		t.Fatalf("Expected ErrServerSealed when sealed, got %v", err)
	}
}
