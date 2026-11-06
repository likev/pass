package keys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

func TestKeySizeLimit(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keys-size-*")
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
	if err := database.CreateUser(ctx, userID, "alice", "Alice"); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	credID := []byte("alice-cred-123")
	cred := &db.Credential{
		ID:              credID,
		UserID:          userID,
		DeviceName:      "Alice Phone",
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

	clientIV := make([]byte, 12)
	clientSalt := make([]byte, 32)

	// 1. Exact limit: 10,240 bytes (10KB) should succeed
	exact10KBCiphertext := make([]byte, MaxKeySizeBytes)
	for i := range exact10KBCiphertext {
		exact10KBCiphertext[i] = byte(i % 256)
	}
	payload10KB := &CreateKeyPayload{
		Name:             "exact-10kb-key",
		ClientCiphertext: base64.RawURLEncoding.EncodeToString(exact10KBCiphertext),
		ClientIV:         base64.RawURLEncoding.EncodeToString(clientIV),
		ClientSalt:       base64.RawURLEncoding.EncodeToString(clientSalt),
	}
	meta10KB, err := keySvc.CreateKey(ctx, userID, payload10KB, "127.0.0.1")
	if err != nil {
		t.Fatalf("Expected 10KB key to succeed, got: %v", err)
	}
	if meta10KB.Name != "exact-10kb-key" {
		t.Fatalf("Expected key name exact-10kb-key, got %s", meta10KB.Name)
	}

	// 2. Exceed limit by 1 byte: 10,241 bytes should fail with ErrKeyPayloadTooLarge
	exceededCiphertext := make([]byte, MaxKeySizeBytes+1)
	payloadExceeded := &CreateKeyPayload{
		Name:             "exceeded-key",
		ClientCiphertext: base64.RawURLEncoding.EncodeToString(exceededCiphertext),
		ClientIV:         base64.RawURLEncoding.EncodeToString(clientIV),
		ClientSalt:       base64.RawURLEncoding.EncodeToString(clientSalt),
	}
	_, err = keySvc.CreateKey(ctx, userID, payloadExceeded, "127.0.0.1")
	if err != ErrKeyPayloadTooLarge {
		t.Fatalf("Expected ErrKeyPayloadTooLarge, got %v", err)
	}

	// 3. UpdateKey with payload exceeding 10KB should also fail with ErrKeyPayloadTooLarge
	stepUpID := "test-stepup-update-size"
	authSvc.AddTestStepUpSession(stepUpID, userID, credID)
	err = keySvc.UpdateKey(
		ctx,
		meta10KB.ID,
		userID,
		"updated-key-too-large",
		exceededCiphertext,
		clientIV,
		clientSalt,
		stepUpID,
		[]byte("simulated-assertion"),
		"127.0.0.1",
	)
	if err != ErrKeyPayloadTooLarge {
		t.Fatalf("Expected ErrKeyPayloadTooLarge for UpdateKey, got %v", err)
	}
}

func TestPerUserKeyLimit(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keys-user-limit-*")
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
	user1 := uuid.NewString()
	user2 := uuid.NewString()
	_ = database.CreateUser(ctx, user1, "user1", "User One")
	_ = database.CreateUser(ctx, user2, "user2", "User Two")

	credID := []byte("user1-cred")
	_ = database.CreateCredential(ctx, &db.Credential{
		ID:              credID,
		UserID:          user1,
		DeviceName:      "User1 Device",
		PublicKey:       []byte("pubkey"),
		AttestationType: "none",
		PRFSalt:         make([]byte, 32),
		WrappedMEK:      []byte("wrapped-mek"),
		WrappedMEKIV:    make([]byte, 12),
		Status:          "verified",
	})

	// Pre-seed 1000 keys for user1 in a single transaction
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
	for i := 0; i < MaxKeysPerUser; i++ {
		kID := fmt.Sprintf("u1-key-%04d", i)
		kName := fmt.Sprintf("user1-key-%04d", i)
		_, err := stmt.ExecContext(ctx, kID, user1, kName, strings.ToLower(kName), []byte("ct"), make([]byte, 12), make([]byte, 32), make([]byte, 12), make([]byte, 32), "10.0.0.1")
		if err != nil {
			t.Fatalf("insert failed at %d: %v", i, err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Verify user1 count is exactly 1000
	count, err := database.CountKeysByUserID(ctx, user1)
	if err != nil || count != MaxKeysPerUser {
		t.Fatalf("expected count %d, got %d, err: %v", MaxKeysPerUser, count, err)
	}

	payload := &CreateKeyPayload{
		Name:             "attempt-key-1001",
		ClientCiphertext: base64.RawURLEncoding.EncodeToString([]byte("payload")),
		ClientIV:         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		ClientSalt:       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}

	// 1. Creating 1001st key for user1 must fail with ErrUserKeyLimitExceeded
	_, err = keySvc.CreateKey(ctx, user1, payload, "10.0.0.1")
	if err != ErrUserKeyLimitExceeded {
		t.Fatalf("Expected ErrUserKeyLimitExceeded, got %v", err)
	}

	// 2. User2 (with 0 keys) can still create keys successfully
	metaU2, err := keySvc.CreateKey(ctx, user2, payload, "10.0.0.1")
	if err != nil {
		t.Fatalf("Expected user2 key creation to succeed, got %v", err)
	}
	if metaU2.Name != "attempt-key-1001" {
		t.Fatalf("Unexpected key name for user2: %s", metaU2.Name)
	}

	// 3. Delete 1 key for user1 -> count becomes 999
	stepUpID := "test-stepup-del-user1"
	authSvc.AddTestStepUpSession(stepUpID, user1, credID)
	if err := keySvc.DeleteKey(ctx, "u1-key-0000", user1, stepUpID, []byte("assertion"), "10.0.0.1"); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	countAfterDel, err := database.CountKeysByUserID(ctx, user1)
	if err != nil || countAfterDel != 999 {
		t.Fatalf("expected count 999 after delete, got %d", countAfterDel)
	}

	// 4. Now user1 can create 1 new key to reach 1000 again
	metaNew, err := keySvc.CreateKey(ctx, user1, payload, "10.0.0.1")
	if err != nil {
		t.Fatalf("Expected user1 key creation to succeed after delete, got %v", err)
	}
	if metaNew.ID == "" {
		t.Fatalf("Expected valid key ID")
	}

	// 5. Creating another key for user1 is rejected again
	payload2 := &CreateKeyPayload{
		Name:             "attempt-key-again",
		ClientCiphertext: base64.RawURLEncoding.EncodeToString([]byte("payload")),
		ClientIV:         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		ClientSalt:       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	_, err = keySvc.CreateKey(ctx, user1, payload2, "10.0.0.1")
	if err != ErrUserKeyLimitExceeded {
		t.Fatalf("Expected ErrUserKeyLimitExceeded after reaching 1000, got %v", err)
	}
}

func TestPerIPKeyLimit(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keys-ip-limit-*")
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

	// Seed 10,000 keys across 11 users for IPv6 IP "2001:db8::1"
	testIP := "2001:db8::1"
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx failed: %v", err)
	}

	// Create 11 users so each user has < 1000 keys
	for u := 0; u < 11; u++ {
		uID := fmt.Sprintf("ip-user-%d", u)
		_, err := tx.ExecContext(ctx, `INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`, uID, fmt.Sprintf("ipuser%d", u), fmt.Sprintf("IP User %d", u))
		if err != nil {
			t.Fatalf("insert user failed: %v", err)
		}
	}

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO keys (
		id, user_id, name, name_normalized, server_ciphertext,
		server_iv, server_salt, client_iv, client_salt, creator_ip, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatalf("PrepareContext failed: %v", err)
	}

	for i := 0; i < MaxKeysPerIP; i++ {
		uID := fmt.Sprintf("ip-user-%d", i/950) // distributes across the 11 users (<950 per user)
		kID := fmt.Sprintf("ip-key-%05d", i)
		kName := fmt.Sprintf("key-%05d", i)
		_, err := stmt.ExecContext(ctx, kID, uID, kName, strings.ToLower(kName), []byte("ct"), make([]byte, 12), make([]byte, 32), make([]byte, 12), make([]byte, 32), testIP)
		if err != nil {
			t.Fatalf("insert key failed at %d: %v", i, err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Verify IP count is exactly 10,000
	ipCount, err := database.CountKeysByIP(ctx, testIP)
	if err != nil || ipCount != MaxKeysPerIP {
		t.Fatalf("expected IP count %d, got %d, err: %v", MaxKeysPerIP, ipCount, err)
	}

	// User 10 has few keys (< 950), so user limit is NOT reached
	u10ID := "ip-user-10"
	u10Count, err := database.CountKeysByUserID(ctx, u10ID)
	if err != nil || u10Count >= MaxKeysPerUser {
		t.Fatalf("expected user 10 count < 1000, got %d", u10Count)
	}

	payload := &CreateKeyPayload{
		Name:             "ip-overflow-key",
		ClientCiphertext: base64.RawURLEncoding.EncodeToString([]byte("payload")),
		ClientIV:         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		ClientSalt:       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}

	// 1. Creating key from testIP (2001:db8::1) must fail with ErrIPKeyLimitExceeded
	_, err = keySvc.CreateKey(ctx, u10ID, payload, testIP)
	if err != ErrIPKeyLimitExceeded {
		t.Fatalf("Expected ErrIPKeyLimitExceeded, got %v", err)
	}

	// 2. IPv6 canonicalization limit enforcement:
	// Any format of that IPv6 (with brackets, with port, expanded zero form, uppercase) must be recognized as 2001:db8::1 and rejected
	ipv6Variations := []string{
		"[2001:db8::1]",
		"[2001:db8::1]:8080",
		"2001:0db8:0000:0000:0000:0000:0000:0001",
		"2001:DB8::1",
	}
	for _, ipVar := range ipv6Variations {
		payloadVar := &CreateKeyPayload{
			Name:             "ip6-attempt-" + uuid.NewString()[:8],
			ClientCiphertext: base64.RawURLEncoding.EncodeToString([]byte("payload")),
			ClientIV:         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
			ClientSalt:       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		}
		_, err = keySvc.CreateKey(ctx, u10ID, payloadVar, ipVar)
		if err != ErrIPKeyLimitExceeded {
			t.Fatalf("Expected ErrIPKeyLimitExceeded for IPv6 variation %q, got %v", ipVar, err)
		}
	}

	// 3. Creating key from different IP ("192.0.2.200") succeeds
	metaDiffIP, err := keySvc.CreateKey(ctx, u10ID, payload, "192.0.2.200")
	if err != nil {
		t.Fatalf("Expected key creation from different IP to succeed, got %v", err)
	}
	if metaDiffIP.Name != "ip-overflow-key" {
		t.Fatalf("Unexpected key name: %s", metaDiffIP.Name)
	}

	// Verify stored creator_ip
	kRecord, err := database.GetKeyByID(ctx, metaDiffIP.ID, u10ID)
	if err != nil {
		t.Fatalf("GetKeyByID failed: %v", err)
	}
	if kRecord.CreatorIP != "192.0.2.200" {
		t.Fatalf("Expected CreatorIP to be 192.0.2.200, got %s", kRecord.CreatorIP)
	}
}

func TestConcurrentKeyCreationLimit(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "keys-concurrency-*")
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
	if err := database.CreateUser(ctx, userID, "raceuser", "Race User"); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Pre-seed exactly 999 keys
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
	for i := 0; i < 999; i++ {
		kID := fmt.Sprintf("race-k-%04d", i)
		kName := fmt.Sprintf("race-key-%04d", i)
		_, err := stmt.ExecContext(ctx, kID, userID, kName, strings.ToLower(kName), []byte("ct"), make([]byte, 12), make([]byte, 32), make([]byte, 12), make([]byte, 32), "127.0.0.1")
		if err != nil {
			t.Fatalf("insert failed: %v", err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Launch 10 concurrent goroutines trying to insert the 1000th key
	const numGoroutines = 10
	var wg sync.WaitGroup
	var successCount int64
	var rejectedCount int64

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := &CreateKeyPayload{
				Name:             fmt.Sprintf("race-candidate-%d", idx),
				ClientCiphertext: base64.RawURLEncoding.EncodeToString([]byte("payload")),
				ClientIV:         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
				ClientSalt:       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			}
			_, err := keySvc.CreateKey(ctx, userID, payload, "127.0.0.1")
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			} else if errors.Is(err, ErrUserKeyLimitExceeded) {
				atomic.AddInt64(&rejectedCount, 1)
			}
		}(i)
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("Expected exactly 1 success out of %d concurrent requests, got %d", numGoroutines, successCount)
	}
	if rejectedCount != numGoroutines-1 {
		t.Fatalf("Expected %d rejections, got %d", numGoroutines-1, rejectedCount)
	}

	// Total keys must be exactly 1000
	totalKeys, err := database.CountKeysByUserID(ctx, userID)
	if err != nil || totalKeys != 1000 {
		t.Fatalf("Expected total keys = 1000, got %d (err: %v)", totalKeys, err)
	}
}
