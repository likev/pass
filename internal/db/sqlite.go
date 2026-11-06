package db

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/001_init.sql
var initSQL string

type DB struct {
	*sql.DB
	Path string
}

func Open(dbPath string) (*DB, error) {
	if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create db directory: %w", err)
		}
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=secure_delete(ON)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1) // modernc sqlite performs best with WAL and 1 writer or managed connections
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	// Apply pragmas explicitly
	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA foreign_keys = ON;",
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA secure_delete = ON;",
	}
	for _, p := range pragmas {
		if _, err := db.ExecContext(ctx, p); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to execute pragma %s: %w", p, err)
		}
	}

	// Run migration
	if _, err := db.ExecContext(ctx, initSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run database migration: %w", err)
	}

	// Ensure creator_ip and key_type columns, index, and triggers exist for upgraded databases
	_, _ = db.ExecContext(ctx, `ALTER TABLE keys ADD COLUMN creator_ip TEXT;`)
	_, _ = db.ExecContext(ctx, `ALTER TABLE keys ADD COLUMN key_type TEXT NOT NULL DEFAULT 'secret';`)
	_, _ = db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_keys_creator_ip ON keys(creator_ip);`)
	_, _ = db.ExecContext(ctx, `
CREATE TRIGGER IF NOT EXISTS trg_keys_user_limit
BEFORE INSERT ON keys
BEGIN
    SELECT CASE
        WHEN (SELECT COUNT(*) FROM keys WHERE user_id = NEW.user_id) >= 1000
        THEN RAISE(ABORT, 'per-user limit of 1000 keys exceeded')
    END;
END;`)
	_, _ = db.ExecContext(ctx, `
CREATE TRIGGER IF NOT EXISTS trg_keys_ip_limit
BEFORE INSERT ON keys
WHEN NEW.creator_ip IS NOT NULL AND NEW.creator_ip != ''
BEGIN
    SELECT CASE
        WHEN (SELECT COUNT(*) FROM keys WHERE creator_ip = NEW.creator_ip) >= 10000
        THEN RAISE(ABORT, 'per-IP limit of 10000 keys exceeded')
    END;
END;`)

	return &DB{DB: db, Path: dbPath}, nil
}
