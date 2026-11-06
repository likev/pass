package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

var (
	ErrDecryptionFailed = errors.New("server envelope decryption failed: invalid ciphertext or authentication tag")
	ErrInvalidKeySize   = errors.New("invalid master key size: must be 32 bytes")
)

type EnvelopeService struct {
	smk []byte
}

func NewEnvelopeService(smk []byte) (*EnvelopeService, error) {
	if len(smk) != 32 {
		return nil, ErrInvalidKeySize
	}
	// Defensive copy
	k := make([]byte, 32)
	copy(k, smk)
	return &EnvelopeService{smk: k}, nil
}

// DeriveServerDEK derives a 32-byte per-key DEK using HKDF-SHA256 bound to keyID and userID
func (e *EnvelopeService) deriveServerDEK(serverSalt []byte, keyID, userID string) ([]byte, error) {
	info := []byte(fmt.Sprintf("%s:%s", keyID, userID))
	hkdfReader := hkdf.New(sha256.New, e.smk, serverSalt, info)
	dek := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, dek); err != nil {
		return nil, fmt.Errorf("failed to derive server DEK: %w", err)
	}
	return dek, nil
}

// Encrypt encrypts the client-side ciphertext using a freshly derived Server-DEK and AES-256-GCM.
// Returns serverCiphertext, serverIV, serverSalt, error.
func (e *EnvelopeService) Encrypt(clientCiphertext []byte, keyID, userID string) (serverCiphertext, serverIV, serverSalt []byte, err error) {
	serverSalt = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, serverSalt); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate server salt: %w", err)
	}

	dek, err := e.deriveServerDEK(serverSalt, keyID, userID)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	serverIV = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, serverIV); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate server IV: %w", err)
	}

	aad := []byte(fmt.Sprintf("%s:%s", keyID, userID))
	serverCiphertext = gcm.Seal(nil, serverIV, clientCiphertext, aad)

	return serverCiphertext, serverIV, serverSalt, nil
}

// Decrypt decrypts the serverCiphertext back to clientCiphertext.
func (e *EnvelopeService) Decrypt(serverCiphertext, serverIV, serverSalt []byte, keyID, userID string) ([]byte, error) {
	dek, err := e.deriveServerDEK(serverSalt, keyID, userID)
	if err != nil {
		return nil, err
	}
	defer clear(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(serverIV) != gcm.NonceSize() {
		return nil, ErrDecryptionFailed
	}

	aad := []byte(fmt.Sprintf("%s:%s", keyID, userID))
	clientCiphertext, err := gcm.Open(nil, serverIV, serverCiphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return clientCiphertext, nil
}
