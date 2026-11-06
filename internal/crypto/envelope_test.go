package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestEnvelopeService(t *testing.T) {
	smk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, smk); err != nil {
		t.Fatalf("failed to generate random SMK: %v", err)
	}

	env, err := NewEnvelopeService(smk)
	if err != nil {
		t.Fatalf("failed to create envelope service: %v", err)
	}

	keyID := "key-uuid-1"
	userID := "user-uuid-1"
	clientPlaintext := []byte("client-super-secret-e2ee-ciphertext-blob")

	// 1. Successful encrypt and decrypt
	sCT, sIV, sSalt, err := env.Encrypt(clientPlaintext, keyID, userID)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := env.Decrypt(sCT, sIV, sSalt, keyID, userID)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, clientPlaintext) {
		t.Fatalf("Decrypted does not match original: got %q, want %q", decrypted, clientPlaintext)
	}

	// 2. Tampered ciphertext fails
	corruptedCT := append([]byte(nil), sCT...)
	corruptedCT[len(corruptedCT)-1] ^= 0x01
	if _, err := env.Decrypt(corruptedCT, sIV, sSalt, keyID, userID); err == nil {
		t.Fatalf("Expected error on corrupted ciphertext, got nil")
	}

	// 3. Tampered IV fails
	corruptedIV := append([]byte(nil), sIV...)
	corruptedIV[0] ^= 0x01
	if _, err := env.Decrypt(sCT, corruptedIV, sSalt, keyID, userID); err == nil {
		t.Fatalf("Expected error on corrupted IV, got nil")
	}

	// 4. Tampered Salt fails
	corruptedSalt := append([]byte(nil), sSalt...)
	corruptedSalt[0] ^= 0x01
	if _, err := env.Decrypt(sCT, sIV, corruptedSalt, keyID, userID); err == nil {
		t.Fatalf("Expected error on corrupted salt, got nil")
	}

	// 5. Wrong keyID fails (AAD mismatch)
	if _, err := env.Decrypt(sCT, sIV, sSalt, "wrong-key-id", userID); err == nil {
		t.Fatalf("Expected error on wrong keyID, got nil")
	}

	// 6. Wrong userID fails (AAD mismatch)
	if _, err := env.Decrypt(sCT, sIV, sSalt, keyID, "wrong-user-id"); err == nil {
		t.Fatalf("Expected error on wrong userID, got nil")
	}

	// 7. Wrong SMK fails
	smk2 := make([]byte, 32)
	copy(smk2, smk)
	smk2[0] ^= 0xFF
	env2, _ := NewEnvelopeService(smk2)
	if _, err := env2.Decrypt(sCT, sIV, sSalt, keyID, userID); err == nil {
		t.Fatalf("Expected error on wrong SMK, got nil")
	}
}
