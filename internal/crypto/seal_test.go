package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSealManager(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "smk-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	keyFile := filepath.Join(tempDir, "server_master.key.enc")
	sm := NewSealManager(keyFile)

	if sm.IsInitialized() {
		t.Fatalf("expected uninitialized initially")
	}
	if sm.IsUnsealed() {
		t.Fatalf("expected sealed initially")
	}

	// 1. Short passphrase fails
	if err := sm.InitSMK("short"); err != ErrInvalidPassphrase {
		t.Fatalf("expected ErrInvalidPassphrase, got %v", err)
	}

	// 2. Valid init
	pass1 := "correct-horse-battery-staple-1234"
	if err := sm.InitSMK(pass1); err != nil {
		t.Fatalf("InitSMK failed: %v", err)
	}

	if !sm.IsInitialized() {
		t.Fatalf("expected initialized after InitSMK")
	}
	if !sm.IsUnsealed() {
		t.Fatalf("expected unsealed after InitSMK")
	}

	origSMK, err := sm.GetSMK()
	if err != nil || len(origSMK) != 32 {
		t.Fatalf("GetSMK failed: %v", err)
	}

	// 3. Double init fails
	if err := sm.InitSMK(pass1); err != ErrAlreadyInitialized {
		t.Fatalf("expected ErrAlreadyInitialized, got %v", err)
	}

	// 4. Create new seal manager instance simulating server restart
	smRestart := NewSealManager(keyFile)
	if !smRestart.IsInitialized() {
		t.Fatalf("expected initialized after restart")
	}
	if smRestart.IsUnsealed() {
		t.Fatalf("expected sealed upon fresh restart")
	}
	if _, err := smRestart.GetSMK(); err != ErrServerSealed {
		t.Fatalf("expected ErrServerSealed, got %v", err)
	}

	// 5. Wrong passphrase fails
	if err := smRestart.Unseal("wrong-passphrase-attempt-123"); err != ErrAuthentication {
		t.Fatalf("expected ErrAuthentication, got %v", err)
	}
	if smRestart.IsUnsealed() {
		t.Fatalf("still should be sealed after failed attempt")
	}

	// 6. Correct passphrase succeeds
	if err := smRestart.Unseal(pass1); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if !smRestart.IsUnsealed() {
		t.Fatalf("expected unsealed")
	}
	unsealedSMK, err := smRestart.GetSMK()
	if err != nil {
		t.Fatalf("GetSMK failed: %v", err)
	}
	if !bytes.Equal(origSMK, unsealedSMK) {
		t.Fatalf("SMK changed after unseal!")
	}

	// 7. Already unsealed returns ErrAlreadyUnsealed
	if err := smRestart.Unseal(pass1); err != ErrAlreadyUnsealed {
		t.Fatalf("expected ErrAlreadyUnsealed, got %v", err)
	}

	// 8. Rotate Passphrase
	pass2 := "a-brand-new-secure-passphrase-5678"
	if err := smRestart.RotatePassphrase(pass1, pass2); err != nil {
		t.Fatalf("RotatePassphrase failed: %v", err)
	}

	// 9. Verify unseal with new passphrase after restart
	smRestart2 := NewSealManager(keyFile)
	if err := smRestart2.Unseal(pass1); err != ErrAuthentication {
		t.Fatalf("old passphrase should fail after rotation, got %v", err)
	}
	if err := smRestart2.Unseal(pass2); err != nil {
		t.Fatalf("Unseal with new passphrase failed: %v", err)
	}
	rotatedSMK, err := smRestart2.GetSMK()
	if err != nil || !bytes.Equal(origSMK, rotatedSMK) {
		t.Fatalf("SMK changed or error after passphrase rotation: %v", err)
	}

	// 10. Test TryAutoUnseal via env
	smAuto := NewSealManager(keyFile)
	if smAuto.IsUnsealed() {
		t.Fatalf("expected sealed before auto-unseal")
	}
	os.Setenv("ADMIN_PASSPHRASE", pass2)
	if err := smAuto.TryAutoUnseal(); err != nil {
		t.Fatalf("TryAutoUnseal failed: %v", err)
	}
	if !smAuto.IsUnsealed() {
		t.Fatalf("expected unsealed after TryAutoUnseal")
	}
}
