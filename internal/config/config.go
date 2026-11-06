package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port                string
	Host                string
	DBPath              string
	SealedSMKPath       string
	BackupDir           string
	BackupRetentionDays int
	RPID                string
	RPDisplayName       string
	RPOrigins           []string
	TLSCertPath         string
	TLSKeyPath          string
	AutoTLS             bool
	TLSEnabled          bool
}

func Load() *Config {
	port := getEnv("PORT", "8082")
	host := getEnv("HOST", "localhost")
	dbPath := getEnv("DB_PATH", "./keymanager.db")
	smkPath := getEnv("SEALED_SMK_PATH", "./server_master.key.enc")
	backupDir := getEnv("BACKUP_DIR", "./backups")

	retentionDays := 30
	if daysStr := os.Getenv("BACKUP_RETENTION_DAYS"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			retentionDays = d
		}
	}

	rpID := getEnv("RP_ID", "localhost")
	rpDisplayName := getEnv("RP_DISPLAY_NAME", "Web Key Manager")

	originsStr := getEnv("RP_ORIGINS", "http://localhost:8082,http://127.0.0.1:8082,https://localhost:8082,https://127.0.0.1:8082,http://localhost,https://localhost,http://127.0.0.1,https://127.0.0.1,https://localhost:8443,http://localhost:8080,https://127.0.0.1:8443")
	origins := strings.Split(originsStr, ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}

	tlsCert := getEnv("TLS_CERT", getEnv("TLS_CERT_PATH", ""))
	tlsKey := getEnv("TLS_KEY", getEnv("TLS_KEY_PATH", ""))
	autoTLS := os.Getenv("AUTO_TLS") == "true" || os.Getenv("TLS_ENABLED") == "true"
	tlsEnabled := autoTLS || (tlsCert != "" && tlsKey != "")

	return &Config{
		Port:                port,
		Host:                host,
		DBPath:              dbPath,
		SealedSMKPath:       smkPath,
		BackupDir:           backupDir,
		BackupRetentionDays: retentionDays,
		RPID:                rpID,
		RPDisplayName:       rpDisplayName,
		RPOrigins:           origins,
		TLSCertPath:         tlsCert,
		TLSKeyPath:          tlsKey,
		AutoTLS:             autoTLS,
		TLSEnabled:          tlsEnabled,
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
