package keys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"passmanager/internal/auth"
	"passmanager/internal/crypto"
	"passmanager/internal/db"
)

var (
	ErrKeyNotFound     = errors.New("key not found")
	ErrDuplicateKey    = errors.New("a key with this name already exists")
	ErrInvalidKeyData  = errors.New("invalid key payload data")
	ErrRateLimitExceeded = errors.New("rate limit exceeded for single-key retrieval")
)

type KeyService struct {
	db       *db.DB
	authSvc  *auth.AuthService
	sealMgr  *crypto.SealManager
}

func NewKeyService(database *db.DB, as *auth.AuthService, sm *crypto.SealManager) *KeyService {
	return &KeyService{
		db:      database,
		authSvc: as,
		sealMgr: sm,
	}
}

// ListKeys returns metadata only (no ciphertexts)
func (ks *KeyService) ListKeys(ctx context.Context, userID, query string) ([]db.KeyMetadata, error) {
	return ks.db.ListKeysMetadata(ctx, userID, query)
}

type CreateKeyPayload struct {
	Name             string `json:"name"`
	ClientCiphertext string `json:"client_ciphertext"` // base64
	ClientIV         string `json:"client_iv"`         // base64
	ClientSalt       string `json:"client_salt"`       // base64
}

// CreateKey saves a new key encrypted with Server-DEK
func (ks *KeyService) CreateKey(ctx context.Context, userID string, payload *CreateKeyPayload, ipAddr string) (*db.KeyMetadata, error) {
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		return nil, errors.New("key name is required")
	}
	nameNorm := strings.ToLower(name)

	cCT, err := base64.RawURLEncoding.DecodeString(payload.ClientCiphertext)
	if err != nil {
		cCT, err = base64.StdEncoding.DecodeString(payload.ClientCiphertext)
	}
	if err != nil || len(cCT) == 0 {
		return nil, errors.New("invalid client_ciphertext")
	}

	cIV, err := base64.RawURLEncoding.DecodeString(payload.ClientIV)
	if err != nil {
		cIV, err = base64.StdEncoding.DecodeString(payload.ClientIV)
	}
	if err != nil || len(cIV) != 12 {
		return nil, errors.New("invalid client_iv: must be 12 bytes")
	}

	cSalt, err := base64.RawURLEncoding.DecodeString(payload.ClientSalt)
	if err != nil {
		cSalt, err = base64.StdEncoding.DecodeString(payload.ClientSalt)
	}
	if err != nil || len(cSalt) != 32 {
		return nil, errors.New("invalid client_salt: must be 32 bytes")
	}

	// Get unsealed SMK
	smk, err := ks.sealMgr.GetSMK()
	if err != nil {
		return nil, err
	}
	defer clear(smk)

	envSvc, err := crypto.NewEnvelopeService(smk)
	if err != nil {
		return nil, err
	}

	keyID := uuid.NewString()

	sCT, sIV, sSalt, err := envSvc.Encrypt(cCT, keyID, userID)
	if err != nil {
		return nil, fmt.Errorf("server envelope encryption failed: %w", err)
	}

	record := &db.Key{
		ID:               keyID,
		UserID:           userID,
		Name:             name,
		NameNormalized:   nameNorm,
		ServerCiphertext: sCT,
		ServerIV:         sIV,
		ServerSalt:       sSalt,
		ClientIV:         cIV,
		ClientSalt:       cSalt,
	}

	if err := ks.db.CreateKey(ctx, record); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrDuplicateKey
		}
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	_ = ks.db.InsertAuditLog(ctx, &userID, "key_created", ipAddr, fmt.Sprintf("created key %s", name))

	return &db.KeyMetadata{
		ID:   keyID,
		Name: name,
	}, nil
}

// SingleKeyPayload contains ciphertext and wrapped MEK for exactly ONE key
type SingleKeyPayload struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ClientCiphertext string `json:"client_ciphertext"` // base64
	ClientIV         string `json:"client_iv"`         // base64
	ClientSalt       string `json:"client_salt"`       // base64
	WrappedMEK       string `json:"wrapped_mek"`       // base64
	WrappedMEKIV     string `json:"wrapped_mek_iv"`   // base64
}

// RetrieveSingleKey decrypts outer server layer and returns exactly ONE key
func (ks *KeyService) RetrieveSingleKey(
	ctx context.Context,
	keyID string,
	userID string,
	credID []byte,
	stepUpID string,
	assertionBytes []byte,
	ipAddr string,
) (*SingleKeyPayload, error) {
	// 1. Verify Passkey assertion
	verifiedCred, err := ks.authSvc.VerifyStepUp(ctx, stepUpID, assertionBytes)
	if err != nil {
		return nil, fmt.Errorf("passkey step-up verification failed: %w", err)
	}

	// 2. Fetch the single key
	keyRecord, err := ks.db.GetKeyByID(ctx, keyID, userID)
	if err != nil || keyRecord == nil {
		return nil, ErrKeyNotFound
	}

	// 3. Decrypt server envelope layer
	smk, err := ks.sealMgr.GetSMK()
	if err != nil {
		return nil, err
	}
	defer clear(smk)

	envSvc, err := crypto.NewEnvelopeService(smk)
	if err != nil {
		return nil, err
	}

	clientCiphertext, err := envSvc.Decrypt(keyRecord.ServerCiphertext, keyRecord.ServerIV, keyRecord.ServerSalt, keyRecord.ID, userID)
	if err != nil {
		return nil, fmt.Errorf("server envelope decryption failed: %w", err)
	}

	// 4. Use the active verified credential's wrapped_mek
	activeCred := verifiedCred
	if len(activeCred.WrappedMEK) == 0 {
		c, err := ks.db.GetCredentialByID(ctx, credID)
		if err == nil && c != nil {
			activeCred = c
		}
	}

	_ = ks.db.InsertAuditLog(ctx, &userID, "key_retrieve", ipAddr, fmt.Sprintf("retrieved key %s", keyRecord.Name))

	return &SingleKeyPayload{
		ID:               keyRecord.ID,
		Name:             keyRecord.Name,
		ClientCiphertext: base64.RawURLEncoding.EncodeToString(clientCiphertext),
		ClientIV:         base64.RawURLEncoding.EncodeToString(keyRecord.ClientIV),
		ClientSalt:       base64.RawURLEncoding.EncodeToString(keyRecord.ClientSalt),
		WrappedMEK:       base64.RawURLEncoding.EncodeToString(activeCred.WrappedMEK),
		WrappedMEKIV:     base64.RawURLEncoding.EncodeToString(activeCred.WrappedMEKIV),
	}, nil
}

// UpdateKey updates an existing key's encrypted data
func (ks *KeyService) UpdateKey(
	ctx context.Context,
	keyID string,
	userID string,
	name string,
	clientCT, clientIV, clientSalt []byte,
	stepUpID string,
	assertionBytes []byte,
	ipAddr string,
) error {
	if _, err := ks.authSvc.VerifyStepUp(ctx, stepUpID, assertionBytes); err != nil {
		return fmt.Errorf("passkey step-up verification failed: %w", err)
	}

	existing, err := ks.db.GetKeyByID(ctx, keyID, userID)
	if err != nil || existing == nil {
		return ErrKeyNotFound
	}

	if name == "" {
		name = existing.Name
	}
	nameNorm := strings.ToLower(name)

	smk, err := ks.sealMgr.GetSMK()
	if err != nil {
		return err
	}
	defer clear(smk)

	envSvc, err := crypto.NewEnvelopeService(smk)
	if err != nil {
		return err
	}

	sCT, sIV, sSalt, err := envSvc.Encrypt(clientCT, keyID, userID)
	if err != nil {
		return fmt.Errorf("envelope encryption failed: %w", err)
	}

	if err := ks.db.UpdateKey(ctx, keyID, userID, name, nameNorm, sCT, sIV, sSalt, clientIV, clientSalt); err != nil {
		return fmt.Errorf("failed to update key: %w", err)
	}

	_ = ks.db.InsertAuditLog(ctx, &userID, "key_updated", ipAddr, fmt.Sprintf("updated key %s", name))
	return nil
}

// DeleteKey deletes a single key
func (ks *KeyService) DeleteKey(
	ctx context.Context,
	keyID string,
	userID string,
	stepUpID string,
	assertionBytes []byte,
	ipAddr string,
) error {
	if _, err := ks.authSvc.VerifyStepUp(ctx, stepUpID, assertionBytes); err != nil {
		return fmt.Errorf("passkey step-up verification failed: %w", err)
	}

	existing, err := ks.db.GetKeyByID(ctx, keyID, userID)
	if err != nil || existing == nil {
		return ErrKeyNotFound
	}

	if err := ks.db.DeleteKey(ctx, keyID, userID); err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	_ = ks.db.InsertAuditLog(ctx, &userID, "key_deleted", ipAddr, fmt.Sprintf("deleted key %s", existing.Name))
	return nil
}
