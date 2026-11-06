package config

import (
	"os"
	"slices"
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	// Clear any env vars that might interfere
	envKeys := []string{"PORT", "HOST", "DB_PATH", "SEALED_SMK_PATH", "BACKUP_DIR", "BACKUP_RETENTION_DAYS", "RP_ID", "RP_DISPLAY_NAME", "RP_ORIGINS", "TLS_CERT", "TLS_KEY", "TLS_CERT_PATH", "TLS_KEY_PATH", "AUTO_TLS", "TLS_ENABLED"}
	for _, k := range envKeys {
		orig := os.Getenv(k)
		defer os.Setenv(k, orig)
		os.Unsetenv(k)
	}

	cfg := Load()

	if cfg.Port != "8082" {
		t.Fatalf("expected default port 8082, got %s", cfg.Port)
	}
	if cfg.Host != "localhost" {
		t.Fatalf("expected default host localhost, got %s", cfg.Host)
	}
	if cfg.AutoTLS != false {
		t.Fatalf("expected default AutoTLS false, got %v", cfg.AutoTLS)
	}
	if cfg.TLSEnabled != false {
		t.Fatalf("expected default TLSEnabled false, got %v", cfg.TLSEnabled)
	}
	if cfg.TLSCertPath != "" || cfg.TLSKeyPath != "" {
		t.Fatalf("expected empty cert/key paths, got cert=%q, key=%q", cfg.TLSCertPath, cfg.TLSKeyPath)
	}
	if cfg.RPID != "localhost" {
		t.Fatalf("expected default RPID localhost, got %s", cfg.RPID)
	}

	// Verify default origins contain http://localhost:8082 and https://localhost:8082
	expectedOrigins := []string{
		"http://localhost:8082",
		"http://127.0.0.1:8082",
		"https://localhost:8082",
		"https://127.0.0.1:8082",
		"http://localhost",
		"https://localhost",
	}
	for _, expected := range expectedOrigins {
		if !slices.Contains(cfg.RPOrigins, expected) {
			t.Fatalf("expected RPOrigins to contain %q, but got %+v", expected, cfg.RPOrigins)
		}
	}
}

func TestConfigEnvOverrides(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("HOST", "0.0.0.0")
	t.Setenv("RP_ID", "custom.domain.com")
	t.Setenv("RP_ORIGINS", "https://custom.domain.com,https://sub.custom.domain.com")

	cfg := Load()

	if cfg.Port != "9090" {
		t.Fatalf("expected port 9090, got %s", cfg.Port)
	}
	if cfg.Host != "0.0.0.0" {
		t.Fatalf("expected host 0.0.0.0, got %s", cfg.Host)
	}
	if cfg.RPID != "custom.domain.com" {
		t.Fatalf("expected RPID custom.domain.com, got %s", cfg.RPID)
	}
	if len(cfg.RPOrigins) != 2 || cfg.RPOrigins[0] != "https://custom.domain.com" {
		t.Fatalf("unexpected RPOrigins: %+v", cfg.RPOrigins)
	}
}

func TestConfigTLSWithCertAndKey(t *testing.T) {
	t.Setenv("TLS_CERT", "/etc/ssl/cert.pem")
	t.Setenv("TLS_KEY", "/etc/ssl/key.pem")

	cfg := Load()

	if !cfg.TLSEnabled {
		t.Fatalf("expected TLSEnabled true when TLS_CERT and TLS_KEY are set")
	}
	if cfg.TLSCertPath != "/etc/ssl/cert.pem" {
		t.Fatalf("expected TLSCertPath /etc/ssl/cert.pem, got %s", cfg.TLSCertPath)
	}
	if cfg.TLSKeyPath != "/etc/ssl/key.pem" {
		t.Fatalf("expected TLSKeyPath /etc/ssl/key.pem, got %s", cfg.TLSKeyPath)
	}
}

func TestConfigTLSWithAliases(t *testing.T) {
	t.Setenv("TLS_CERT_PATH", "/etc/ssl/cert2.pem")
	t.Setenv("TLS_KEY_PATH", "/etc/ssl/key2.pem")

	cfg := Load()

	if !cfg.TLSEnabled {
		t.Fatalf("expected TLSEnabled true when TLS_CERT_PATH and TLS_KEY_PATH are set")
	}
	if cfg.TLSCertPath != "/etc/ssl/cert2.pem" {
		t.Fatalf("expected TLSCertPath /etc/ssl/cert2.pem, got %s", cfg.TLSCertPath)
	}
	if cfg.TLSKeyPath != "/etc/ssl/key2.pem" {
		t.Fatalf("expected TLSKeyPath /etc/ssl/key2.pem, got %s", cfg.TLSKeyPath)
	}
}

func TestConfigAutoTLSEnv(t *testing.T) {
	t.Setenv("AUTO_TLS", "true")

	cfg := Load()

	if !cfg.AutoTLS {
		t.Fatalf("expected AutoTLS true")
	}
	if !cfg.TLSEnabled {
		t.Fatalf("expected TLSEnabled true")
	}
}

func TestConfigTLSEnabledEnv(t *testing.T) {
	t.Setenv("TLS_ENABLED", "true")

	cfg := Load()

	if !cfg.AutoTLS {
		t.Fatalf("expected AutoTLS true")
	}
	if !cfg.TLSEnabled {
		t.Fatalf("expected TLSEnabled true")
	}
}

func TestConfigPartialTLSEnv(t *testing.T) {
	// Case 1: TLS_CERT only
	t.Setenv("TLS_CERT", "/etc/ssl/cert.pem")
	t.Setenv("TLS_KEY", "")

	cfg := Load()
	if cfg.TLSEnabled {
		t.Fatalf("expected TLSEnabled false when only cert is set")
	}
	if cfg.TLSCertPath != "/etc/ssl/cert.pem" {
		t.Fatalf("expected TLSCertPath set")
	}
	if cfg.TLSKeyPath != "" {
		t.Fatalf("expected TLSKeyPath empty")
	}

	// Case 2: TLS_KEY only
	t.Setenv("TLS_CERT", "")
	t.Setenv("TLS_KEY", "/etc/ssl/key.pem")

	cfg2 := Load()
	if cfg2.TLSEnabled {
		t.Fatalf("expected TLSEnabled false when only key is set")
	}
	if cfg2.TLSKeyPath != "/etc/ssl/key.pem" {
		t.Fatalf("expected TLSKeyPath set")
	}
	if cfg2.TLSCertPath != "" {
		t.Fatalf("expected TLSCertPath empty")
	}
}
