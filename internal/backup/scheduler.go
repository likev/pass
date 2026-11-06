package backup

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"passmanager/internal/crypto"
	"passmanager/internal/db"
)

var (
	ErrIntegrityCheckFailed = errors.New("backup integrity check failed: corrupt SQLite snapshot")
	ErrCorruptBackupFile    = errors.New("corrupt or invalid backup file")
)

const (
	backupMagic = "BKP1"
	backupAAD   = "keymanager-sqlite-backup-v1"
	saltLen     = 32
	ivLen       = 12
)

type BackupManager struct {
	db            *db.DB
	sealMgr       *crypto.SealManager
	backupDir     string
	retentionDays int
	mu            sync.Mutex
}

func NewBackupManager(database *db.DB, sm *crypto.SealManager, backupDir string, retentionDays int) *BackupManager {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	return &BackupManager{
		db:            database,
		sealMgr:       sm,
		backupDir:     backupDir,
		retentionDays: retentionDays,
	}
}

// RunBackup creates an atomic, verified, compressed, and encrypted backup of the database
func (bm *BackupManager) RunBackup(ctx context.Context) (string, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// 1. Ensure backup directory exists
	if err := os.MkdirAll(bm.backupDir, 0700); err != nil {
		_ = bm.db.InsertAuditLog(ctx, nil, "backup_failure", "", fmt.Sprintf("failed to create backup dir: %v", err))
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// 2. Check SMK availability
	smk, err := bm.sealMgr.GetSMK()
	if err != nil {
		_ = bm.db.InsertAuditLog(ctx, nil, "backup_failure", "", "server is sealed; backup aborted")
		return "", fmt.Errorf("cannot run backup: %w", err)
	}
	defer clear(smk)

	// 3. Perform atomic online snapshot via VACUUM INTO
	tempSnapshotPath := filepath.Join(bm.backupDir, fmt.Sprintf("tmp-snapshot-%d.db", time.Now().UnixNano()))
	defer func() {
		// Securely wipe & delete temp snapshot
		if fi, err := os.Stat(tempSnapshotPath); err == nil {
			zeroes := make([]byte, fi.Size())
			_ = os.WriteFile(tempSnapshotPath, zeroes, 0600)
			_ = os.Remove(tempSnapshotPath)
		}
	}()

	vacuumSQL := fmt.Sprintf("VACUUM INTO '%s'", tempSnapshotPath)
	if _, err := bm.db.ExecContext(ctx, vacuumSQL); err != nil {
		_ = bm.db.InsertAuditLog(ctx, nil, "backup_failure", "", fmt.Sprintf("VACUUM INTO failed: %v", err))
		return "", fmt.Errorf("VACUUM INTO failed: %w", err)
	}

	// 4. Verify integrity of snapshot
	if err := verifySQLiteIntegrity(tempSnapshotPath); err != nil {
		_ = bm.db.InsertAuditLog(ctx, nil, "backup_failure", "", fmt.Sprintf("snapshot integrity check failed: %v", err))
		return "", err
	}

	// 5. Read and Gzip compress snapshot
	snapshotRaw, err := os.ReadFile(tempSnapshotPath)
	if err != nil {
		return "", fmt.Errorf("failed to read snapshot: %w", err)
	}

	var compressedBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&compressedBuf)
	if _, err := gzWriter.Write(snapshotRaw); err != nil {
		return "", fmt.Errorf("failed to compress snapshot: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return "", fmt.Errorf("failed to finish gzip compression: %w", err)
	}
	compressedData := compressedBuf.Bytes()

	// 6. Encrypt with AES-256-GCM using HKDF-derived backup key
	backupSalt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, backupSalt); err != nil {
		return "", fmt.Errorf("failed to generate backup salt: %w", err)
	}

	backupIV := make([]byte, ivLen)
	if _, err := io.ReadFull(rand.Reader, backupIV); err != nil {
		return "", fmt.Errorf("failed to generate backup IV: %w", err)
	}

	backupKey := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, smk, backupSalt, []byte("sqlite-daily-backup"))
	if _, err := io.ReadFull(hkdfReader, backupKey); err != nil {
		return "", fmt.Errorf("failed to derive backup key: %w", err)
	}
	defer clear(backupKey)

	block, err := aes.NewCipher(backupKey)
	if err != nil {
		return "", fmt.Errorf("failed to init backup cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to init backup gcm: %w", err)
	}

	encryptedData := gcm.Seal(nil, backupIV, compressedData, []byte(backupAAD))

	// 7. Write encrypted backup file: Magic || Salt || IV || Ciphertext
	timestamp := time.Now().UTC().Format("2006-01-02-150405")
	finalBackupFile := filepath.Join(bm.backupDir, fmt.Sprintf("keymanager-%s.db.gz.enc", timestamp))

	var out bytes.Buffer
	out.WriteString(backupMagic)
	out.Write(backupSalt)
	out.Write(backupIV)
	out.Write(encryptedData)

	if err := os.WriteFile(finalBackupFile, out.Bytes(), 0600); err != nil {
		_ = bm.db.InsertAuditLog(ctx, nil, "backup_failure", "", fmt.Sprintf("failed to write encrypted backup file: %v", err))
		return "", fmt.Errorf("failed to write backup file: %w", err)
	}

	// 8. Write SHA256 checksum file
	hash := sha256.Sum256(out.Bytes())
	checksumContent := fmt.Sprintf("%x  %s\n", hash, filepath.Base(finalBackupFile))
	checksumFile := finalBackupFile + ".sha256"
	_ = os.WriteFile(checksumFile, []byte(checksumContent), 0600)

	// 9. Prune old backups based on retention policy
	_ = bm.pruneOldBackups()

	_ = bm.db.InsertAuditLog(ctx, nil, "backup_success", "", fmt.Sprintf("created encrypted backup %s", filepath.Base(finalBackupFile)))

	return finalBackupFile, nil
}

func verifySQLiteIntegrity(dbPath string) error {
	checkDB, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return fmt.Errorf("failed to open snapshot for check: %w", err)
	}
	defer checkDB.Close()

	var result string
	row := checkDB.QueryRow("PRAGMA integrity_check;")
	if err := row.Scan(&result); err != nil {
		return fmt.Errorf("failed to run integrity check: %w", err)
	}
	if strings.ToLower(result) != "ok" {
		return fmt.Errorf("%w: %s", ErrIntegrityCheckFailed, result)
	}
	return nil
}

func (bm *BackupManager) pruneOldBackups() error {
	entries, err := os.ReadDir(bm.backupDir)
	if err != nil {
		return err
	}

	cutoff := time.Now().AddDate(0, 0, -bm.retentionDays)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".db.gz.enc") || strings.HasSuffix(name, ".db.gz.enc.sha256") {
			info, err := entry.Info()
			if err == nil && info.ModTime().Before(cutoff) {
				_ = os.Remove(filepath.Join(bm.backupDir, name))
			}
		}
	}
	return nil
}

// RestoreBackup decrypts, decompresses, and restores a backup to targetPath
func RestoreBackup(backupFilePath string, smk []byte, targetPath string) error {
	if len(smk) != 32 {
		return errors.New("invalid SMK length")
	}

	data, err := os.ReadFile(backupFilePath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	headerLen := len(backupMagic) + saltLen + ivLen
	if len(data) < headerLen+16 || string(data[:len(backupMagic)]) != backupMagic {
		return ErrCorruptBackupFile
	}

	offset := len(backupMagic)
	salt := data[offset : offset+saltLen]
	offset += saltLen
	iv := data[offset : offset+ivLen]
	offset += ivLen
	ciphertext := data[offset:]

	backupKey := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, smk, salt, []byte("sqlite-daily-backup"))
	if _, err := io.ReadFull(hkdfReader, backupKey); err != nil {
		return fmt.Errorf("failed to derive backup key: %w", err)
	}
	defer clear(backupKey)

	block, err := aes.NewCipher(backupKey)
	if err != nil {
		return fmt.Errorf("failed to init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to init gcm: %w", err)
	}

	compressedData, err := gcm.Open(nil, iv, ciphertext, []byte(backupAAD))
	if err != nil {
		return fmt.Errorf("backup decryption failed: %w", err)
	}

	gzReader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return fmt.Errorf("gzip reader init failed: %w", err)
	}
	defer gzReader.Close()

	var decompressed bytes.Buffer
	if _, err := io.Copy(&decompressed, gzReader); err != nil {
		return fmt.Errorf("gzip decompression failed: %w", err)
	}

	// Write restored DB
	if err := os.WriteFile(targetPath, decompressed.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write restored DB: %w", err)
	}

	// Verify restored DB integrity
	return verifySQLiteIntegrity(targetPath)
}

// Start runs the periodic daily backup scheduler
func (bm *BackupManager) Start(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		// Run initial backup check on startup after a 30-second delay
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
			if bm.sealMgr.IsUnsealed() {
				_, _ = bm.RunBackup(ctx)
			}
		}

		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				if bm.sealMgr.IsUnsealed() {
					_, _ = bm.RunBackup(ctx)
				}
			}
		}
	}()
}
