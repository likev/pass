package main

import (
	"crypto/tls"
	"os"
	"strings"
	"testing"

	"passmanager/internal/config"
)

func TestParseServerFlags(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		expectedStart bool
		expectedErr   string
		checkConfig   func(*testing.T, *config.Config)
	}{
		{
			name:          "default no flags",
			args:          []string{},
			expectedStart: true,
			checkConfig: func(t *testing.T, cfg *config.Config) {
				if cfg.Port != "8082" {
					t.Fatalf("expected port 8082, got %s", cfg.Port)
				}
				if cfg.Host != "localhost" {
					t.Fatalf("expected host localhost, got %s", cfg.Host)
				}
				if cfg.TLSEnabled {
					t.Fatalf("expected TLSEnabled false by default")
				}
				if cfg.AutoTLS {
					t.Fatalf("expected AutoTLS false by default")
				}
			},
		},
		{
			name:          "tls flag enabled",
			args:          []string{"--tls"},
			expectedStart: true,
			checkConfig: func(t *testing.T, cfg *config.Config) {
				if !cfg.TLSEnabled {
					t.Fatalf("expected TLSEnabled true with --tls")
				}
				if !cfg.AutoTLS {
					t.Fatalf("expected AutoTLS true with --tls")
				}
			},
		},
		{
			name:          "run subcommand before flags",
			args:          []string{"run", "--port", "9090", "--host", "0.0.0.0"},
			expectedStart: true,
			checkConfig: func(t *testing.T, cfg *config.Config) {
				if cfg.Port != "9090" {
					t.Fatalf("expected port 9090, got %s", cfg.Port)
				}
				if cfg.Host != "0.0.0.0" {
					t.Fatalf("expected host 0.0.0.0, got %s", cfg.Host)
				}
			},
		},
		{
			name:          "serve subcommand after flags",
			args:          []string{"--port", "9090", "serve"},
			expectedStart: true,
			checkConfig: func(t *testing.T, cfg *config.Config) {
				if cfg.Port != "9090" {
					t.Fatalf("expected port 9090, got %s", cfg.Port)
				}
			},
		},
		{
			name:          "custom tls cert and key flags",
			args:          []string{"--tls-cert", "/etc/ssl/cert.pem", "--tls-key", "/etc/ssl/key.pem"},
			expectedStart: true,
			checkConfig: func(t *testing.T, cfg *config.Config) {
				if !cfg.TLSEnabled {
					t.Fatalf("expected TLSEnabled true with cert/key")
				}
				if cfg.TLSCertPath != "/etc/ssl/cert.pem" {
					t.Fatalf("expected TLSCertPath /etc/ssl/cert.pem, got %s", cfg.TLSCertPath)
				}
				if cfg.TLSKeyPath != "/etc/ssl/key.pem" {
					t.Fatalf("expected TLSKeyPath /etc/ssl/key.pem, got %s", cfg.TLSKeyPath)
				}
			},
		},
		{
			name:          "tls cert without key returns error",
			args:          []string{"--tls-cert", "/etc/ssl/cert.pem"},
			expectedStart: false,
			expectedErr:   "both TLS certificate and private key must be provided",
		},
		{
			name:          "tls key without cert returns error",
			args:          []string{"--tls-key", "/etc/ssl/key.pem"},
			expectedStart: false,
			expectedErr:   "both TLS certificate and private key must be provided",
		},
		{
			name:          "unknown command returns error",
			args:          []string{"invalidcommand"},
			expectedStart: false,
			expectedErr:   "unknown command: invalidcommand",
		},
		{
			name:          "unknown trailing argument returns error",
			args:          []string{"--port", "8082", "bogus"},
			expectedStart: false,
			expectedErr:   "unknown command or argument: bogus",
		},
		{
			name:          "help command exits cleanly without starting server",
			args:          []string{"help"},
			expectedStart: false,
		},
		{
			name:          "help flag exits cleanly without starting server",
			args:          []string{"--help"},
			expectedStart: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				Port: "8082",
				Host: "localhost",
			}

			start, err := parseServerFlags(cfg, tc.args)
			if tc.expectedErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.expectedErr)
				}
				if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Fatalf("expected error containing %q, got %v", tc.expectedErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if start != tc.expectedStart {
				t.Fatalf("expected start=%v, got %v", tc.expectedStart, start)
			}

			if tc.checkConfig != nil {
				tc.checkConfig(t, cfg)
			}
		})
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatalf("expected non-empty certificate slice")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected MinVersion TLS 1.3")
	}
}

func TestPrintUsage(t *testing.T) {
	// Ensure printUsage runs without panic
	origStdout := os.Stdout
	defer func() { os.Stdout = origStdout }()
	os.Stdout = nil
	printUsage()
}
