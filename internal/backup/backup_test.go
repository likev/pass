package backup

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"passmanager/internal/crypto"
	"passmanager/internal/db"
)

func TestBackupAndRestore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "backup-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "live.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer database.Close()

	ctx := context.Background()

	// Seed some data
	userID := uuid.NewString()
	if err := database.CreateUser(ctx, userID, "dave", "Dave"); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	smkFile := filepath.Join(tempDir, "server_master.key.enc")
	sealMgr := crypto.NewSealManager(smkFile)
	passphrase := "admin-backup-test-passphrase-999"
	if err := sealMgr.InitSMK(passphrase); err != nil {
		t.Fatalf("InitSMK failed: %v", err)
	}

	backupDir := filepath.Join(tempDir, "backups")
	bm := NewBackupManager(database, sealMgr, backupDir, 30)

	// 1. Run backup
	backupFile, err := bm.RunBackup(ctx)
	if err != nil {
		t.Fatalf("RunBackup failed: %v", err)
	}

	// 2. Check backup file and checksum
	data, err := os.ReadFile(backupFile)
	if err != nil {
		t.Fatalf("Failed to read backup file: %v", err)
	}
	checksumData, err := os.ReadFile(backupFile + ".sha256")
	if err != nil {
		t.Fatalf("Failed to read checksum file: %v", err)
	}

	expectedHash := fmt.Sprintf("%x", sha256.Sum256(data))
	if !strings.HasPrefix(string(checksumData), expectedHash) {
		t.Fatalf("Checksum mismatch: got %s, want %s", string(checksumData), expectedHash)
	}

	// 3. Restore backup to new DB
	restoredDBPath := filepath.Join(tempDir, "restored.db")
	smk, _ := sealMgr.GetSMK()
	if err := RestoreBackup(backupFile, smk, restoredDBPath); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}

	// 4. Verify data in restored DB
	restoredDB, err := db.Open(restoredDBPath)
	if err != nil {
		t.Fatalf("Failed to open restored DB: %v", err)
	}
	defer restoredDB.Close()

	u, err := restoredDB.GetUserByID(ctx, userID)
	if err != nil || u.Username != "dave" {
		t.Fatalf("Restored DB user verification failed: u=%+v, err=%v", u, err)
	}

	// 5. Corrupt backup file fails restore
	corruptedBackup := append([]byte(nil), data...)
	corruptedBackup[len(corruptedBackup)-1] ^= 0x01
	corruptFile := filepath.Join(backupDir, "corrupted.enc")
	_ = os.WriteFile(corruptFile, corruptedBackup, 0600)
	if err := RestoreBackup(corruptFile, smk, filepath.Join(tempDir, "corrupt_restored.db")); err == nil {
		t.Fatalf("Expected restore to fail on corrupted backup, got nil")
	}

	// 6. Test Retention Pruning
	// Create an old fake backup file with modtime 40 days ago
	oldBackupFile := filepath.Join(backupDir, "keymanager-old.db.gz.enc")
	_ = os.WriteFile(oldBackupFile, []byte("fake"), 0600)
	oldChecksumFile := oldBackupFile + ".sha256"
	_ = os.WriteFile(oldChecksumFile, []byte("fake"), 0600)

	pastTime := time.Now().AddDate(0, 0, -40)
	_ = os.Chtimes(oldBackupFile, pastTime, pastTime)
	_ = os.Chtimes(oldChecksumFile, pastTime, pastTime)

	if err := bm.pruneOldBackups(); err != nil {
		t.Fatalf("pruneOldBackups failed: %v", err)
	}

	if _, err := os.Stat(oldBackupFile); !os.IsNotExist(err) {
		t.Fatalf("Expected old backup file to be pruned, but it still exists")
	}
	if _, err := os.Stat(oldChecksumFile); !os.IsNotExist(err) {
		t.Fatalf("Expected old checksum file to be pruned, but it still exists")
	}
}
