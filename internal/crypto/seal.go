package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

var (
	ErrServerSealed       = errors.New("server is sealed: admin startup passphrase required")
	ErrAlreadyUnsealed    = errors.New("server is already unsealed")
	ErrAlreadyInitialized = errors.New("server master key already initialized")
	ErrInvalidPassphrase  = errors.New("passphrase must be at least 12 characters")
	ErrPassphraseMismatch = errors.New("passphrases do not match")
	ErrInvalidKeyFile     = errors.New("invalid or corrupted sealed key file")
	ErrAuthentication     = errors.New("invalid passphrase or corrupt key file")
)

const (
	smkMagic       = "SMK1"
	smkAAD         = "keymanager-smk-v1"
	saltLen        = 32
	ivLen          = 12
	smkLen         = 32
	argonTime      = 3
	argonMemory    = 64 * 1024 // 64 MB
	argonThreads   = 4
	minPassLen     = 12
	sealedFileSize = len(smkMagic) + saltLen + ivLen + smkLen + 16 // 96 bytes
)

type SealManager struct {
	mu       sync.RWMutex
	filePath string
	smk      []byte
	unsealed bool
}

func NewSealManager(filePath string) *SealManager {
	return &SealManager{
		filePath: filePath,
	}
}

func (s *SealManager) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := os.Stat(s.filePath)
	return err == nil
}

func (s *SealManager) IsUnsealed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unsealed && len(s.smk) == smkLen
}

// GetSMK returns a defensive copy of the unsealed Server Master Key, or error if sealed.
func (s *SealManager) GetSMK() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.unsealed || len(s.smk) != smkLen {
		return nil, ErrServerSealed
	}
	copySMK := make([]byte, smkLen)
	copy(copySMK, s.smk)
	return copySMK, nil
}

func deriveAUK(passphrase []byte, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, smkLen)
}

func lockMemory(b []byte) {
	// Attempt to lock memory so OS kernel does not swap it to disk
	_ = unix.Mlock(b)
}

func unlockMemory(b []byte) {
	_ = unix.Munlock(b)
}

// InitSMK generates a new random SMK, seals it with passphrase, and stores it in s.filePath.
func (s *SealManager) InitSMK(passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(s.filePath); err == nil {
		return ErrAlreadyInitialized
	}
	if len(passphrase) < minPassLen {
		return ErrInvalidPassphrase
	}

	passBytes := []byte(passphrase)
	defer clear(passBytes)

	// 1. Generate 32-byte SMK, 32-byte salt, 12-byte IV
	newSMK := make([]byte, smkLen)
	if _, err := io.ReadFull(rand.Reader, newSMK); err != nil {
		return fmt.Errorf("failed to generate SMK: %w", err)
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		clear(newSMK)
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	iv := make([]byte, ivLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		clear(newSMK)
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	// 2. Derive AUK
	auk := deriveAUK(passBytes, salt)
	defer clear(auk)

	// 3. Encrypt SMK with AES-256-GCM
	block, err := aes.NewCipher(auk)
	if err != nil {
		clear(newSMK)
		return fmt.Errorf("failed to init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		clear(newSMK)
		return fmt.Errorf("failed to init gcm: %w", err)
	}

	ciphertext := gcm.Seal(nil, iv, newSMK, []byte(smkAAD))

	// 4. Assemble sealed file contents
	payload := make([]byte, 0, sealedFileSize)
	payload = append(payload, []byte(smkMagic)...)
	payload = append(payload, salt...)
	payload = append(payload, iv...)
	payload = append(payload, ciphertext...)

	// Ensure directory exists
	if dir := filepath.Dir(s.filePath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0700)
	}

	// Write atomically with chmod 0600
	tmpFile := s.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, payload, 0600); err != nil {
		clear(newSMK)
		return fmt.Errorf("failed to write sealed key file: %w", err)
	}
	if err := os.Rename(tmpFile, s.filePath); err != nil {
		_ = os.Remove(tmpFile)
		clear(newSMK)
		return fmt.Errorf("failed to commit sealed key file: %w", err)
	}

	lockMemory(newSMK)
	s.smk = newSMK
	s.unsealed = true
	return nil
}

// Unseal decrypts the sealed key file using the provided passphrase and loads SMK into RAM.
func (s *SealManager) Unseal(passphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.unsealed && len(s.smk) == smkLen {
		return ErrAlreadyUnsealed
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("failed to read sealed key file: %w", err)
	}

	if len(data) != sealedFileSize || string(data[:len(smkMagic)]) != smkMagic {
		return ErrInvalidKeyFile
	}

	offset := len(smkMagic)
	salt := data[offset : offset+saltLen]
	offset += saltLen
	iv := data[offset : offset+ivLen]
	offset += ivLen
	ciphertext := data[offset:]

	passBytes := []byte(passphrase)
	defer clear(passBytes)

	auk := deriveAUK(passBytes, salt)
	defer clear(auk)

	block, err := aes.NewCipher(auk)
	if err != nil {
		return fmt.Errorf("failed to init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to init gcm: %w", err)
	}

	decryptedSMK, err := gcm.Open(nil, iv, ciphertext, []byte(smkAAD))
	if err != nil {
		return ErrAuthentication
	}

	if len(decryptedSMK) != smkLen {
		clear(decryptedSMK)
		return ErrInvalidKeyFile
	}

	lockMemory(decryptedSMK)
	s.smk = decryptedSMK
	s.unsealed = true
	return nil
}

// Seal clears the unsealed SMK from memory, unlocks memory, and seals the server.
func (s *SealManager) Seal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.smk) > 0 {
		clear(s.smk)
		unlockMemory(s.smk)
		s.smk = nil
	}
	s.unsealed = false
}

// RotatePassphrase decrypts the sealed SMK with oldPassphrase and re-encrypts with newPassphrase.
func (s *SealManager) RotatePassphrase(oldPassphrase, newPassphrase string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(newPassphrase) < minPassLen {
		return ErrInvalidPassphrase
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return fmt.Errorf("failed to read sealed key file: %w", err)
	}

	if len(data) != sealedFileSize || string(data[:len(smkMagic)]) != smkMagic {
		return ErrInvalidKeyFile
	}

	offset := len(smkMagic)
	oldSalt := data[offset : offset+saltLen]
	offset += saltLen
	oldIV := data[offset : offset+ivLen]
	offset += ivLen
	oldCiphertext := data[offset:]

	oldPassBytes := []byte(oldPassphrase)
	defer clear(oldPassBytes)

	oldAUK := deriveAUK(oldPassBytes, oldSalt)
	defer clear(oldAUK)

	block, err := aes.NewCipher(oldAUK)
	if err != nil {
		return fmt.Errorf("failed to init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to init gcm: %w", err)
	}

	rawSMK, err := gcm.Open(nil, oldIV, oldCiphertext, []byte(smkAAD))
	if err != nil {
		return ErrAuthentication
	}
	defer clear(rawSMK)

	// Re-encrypt with new passphrase
	newPassBytes := []byte(newPassphrase)
	defer clear(newPassBytes)

	newSalt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}
	newIV := make([]byte, ivLen)
	if _, err := io.ReadFull(rand.Reader, newIV); err != nil {
		return fmt.Errorf("failed to generate new IV: %w", err)
	}

	newAUK := deriveAUK(newPassBytes, newSalt)
	defer clear(newAUK)

	newBlock, err := aes.NewCipher(newAUK)
	if err != nil {
		return fmt.Errorf("failed to init new cipher: %w", err)
	}
	newGCM, err := cipher.NewGCM(newBlock)
	if err != nil {
		return fmt.Errorf("failed to init new gcm: %w", err)
	}

	newCiphertext := newGCM.Seal(nil, newIV, rawSMK, []byte(smkAAD))

	payload := make([]byte, 0, sealedFileSize)
	payload = append(payload, []byte(smkMagic)...)
	payload = append(payload, newSalt...)
	payload = append(payload, newIV...)
	payload = append(payload, newCiphertext...)

	tmpFile := s.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, payload, 0600); err != nil {
		return fmt.Errorf("failed to write rotated key file: %w", err)
	}
	if err := os.Rename(tmpFile, s.filePath); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("failed to commit rotated key file: %w", err)
	}

	// Update in-memory SMK if already unsealed
	if s.unsealed {
		if len(s.smk) == smkLen {
			unlockMemory(s.smk)
			clear(s.smk)
		}
		newSMKCopy := make([]byte, smkLen)
		copy(newSMKCopy, rawSMK)
		lockMemory(newSMKCopy)
		s.smk = newSMKCopy
	}

	return nil
}

// TryAutoUnseal checks environment variables ADMIN_PASSPHRASE or ADMIN_PASSPHRASE_FILE.
// If provided, it automatically unseals the SMK (or initializes it if not initialized).
func (s *SealManager) TryAutoUnseal() error {
	pass := os.Getenv("ADMIN_PASSPHRASE")
	if pass == "" {
		if path := os.Getenv("ADMIN_PASSPHRASE_FILE"); path != "" {
			data, err := os.ReadFile(path)
			if err == nil {
				pass = strings.TrimSpace(string(data))
				clear(data)
			}
		}
	}
	if pass == "" {
		return nil
	}

	defer os.Unsetenv("ADMIN_PASSPHRASE")

	if !s.IsInitialized() {
		if len(pass) < minPassLen {
			return ErrInvalidPassphrase
		}
		if err := s.InitSMK(pass); err != nil {
			return fmt.Errorf("auto-init failed: %w", err)
		}
		return nil
	}

	if s.IsUnsealed() {
		return nil
	}

	if err := s.Unseal(pass); err != nil {
		return fmt.Errorf("auto-unseal failed: %w", err)
	}
	return nil
}

// PromptPassphraseIfTTY checks if stdin is an interactive terminal and prompts for the admin passphrase.
func (s *SealManager) PromptPassphraseIfTTY() error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil // Non-interactive mode, server will boot in sealed mode
	}

	if !s.IsInitialized() {
		fmt.Println("[Init] Sealed Server Master Key file does not exist.")
		fmt.Println("Please set up the Admin Startup Passphrase (min 12 chars).")
		for {
			fmt.Print("Enter Admin Startup Passphrase: ")
			pass1, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return err
			}
			if len(pass1) < minPassLen {
				fmt.Printf("Passphrase must be at least %d characters. Please try again.\n", minPassLen)
				clear(pass1)
				continue
			}
			fmt.Print("Confirm Admin Startup Passphrase: ")
			pass2, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				clear(pass1)
				return err
			}
			if string(pass1) != string(pass2) {
				fmt.Println("Passphrases do not match. Please try again.")
				clear(pass1)
				clear(pass2)
				continue
			}
			err = s.InitSMK(string(pass1))
			clear(pass1)
			clear(pass2)
			if err != nil {
				return fmt.Errorf("initialization failed: %w", err)
			}
			fmt.Println("[Init] Server Master Key successfully initialized and unsealed into RAM.")
			return nil
		}
	}

	// File exists, prompt to unseal
	fmt.Print("Enter Admin Startup Passphrase to unseal server: ")
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return err
	}
	defer clear(pass)

	if err := s.Unseal(string(pass)); err != nil {
		return fmt.Errorf("failed to unseal server: %w", err)
	}
	fmt.Println("[Unseal] Server successfully unsealed into RAM.")
	return nil
}
