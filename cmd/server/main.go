package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"passmanager/internal/auth"
	"passmanager/internal/backup"
	"passmanager/internal/config"
	"passmanager/internal/crypto"
	"passmanager/internal/db"
	"passmanager/internal/keys"
	"passmanager/internal/server"
)

func main() {
	cfg := config.Load()

	start, err := parseServerFlags(cfg, os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		printUsage()
		os.Exit(1)
	}
	if !start {
		return
	}

	log.Println("[Main] Initializing Web Password & Key Manager...")

	// 1. Open SQLite DB
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("[Main] Failed to open SQLite database: %v", err)
	}
	defer database.Close()
	log.Printf("[Main] SQLite database opened at %s (WAL mode, secure_delete enabled)", cfg.DBPath)

	// 2. Initialize Seal Manager
	sealMgr := crypto.NewSealManager(cfg.SealedSMKPath)
	if sealMgr.IsInitialized() {
		log.Printf("[Main] Sealed Server Master Key found at %s", cfg.SealedSMKPath)
	} else {
		log.Printf("[Main] No sealed key file at %s. Server will require initialization.", cfg.SealedSMKPath)
	}

	// 3. Prompt TTY passphrase if interactive
	if err := sealMgr.PromptPassphraseIfTTY(); err != nil {
		log.Printf("[Main] TTY unseal notice: %v", err)
	}

	// 4. Initialize Core Services
	sessionMgr := auth.NewSessionManager()
	authSvc, err := auth.NewAuthService(database, cfg, sessionMgr)
	if err != nil {
		log.Fatalf("[Main] Failed to initialize WebAuthn service: %v", err)
	}

	deviceMgr := auth.NewDeviceManager(database, authSvc, sessionMgr)
	keySvc := keys.NewKeyService(database, authSvc, sealMgr)
	backupMgr := backup.NewBackupManager(database, sealMgr, cfg.BackupDir, cfg.BackupRetentionDays)

	// 5. Start Daily Backup Scheduler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backupMgr.Start(ctx)
	log.Printf("[Main] Automated daily backup scheduler started (retention: %d days)", cfg.BackupRetentionDays)

	// 6. Setup HTTP Server
	srv := server.NewServer(
		cfg,
		database,
		sealMgr,
		authSvc,
		deviceMgr,
		keySvc,
		backupMgr,
		sessionMgr,
	)
	handler := srv.SetupHandler()

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// 7. TLS Configuration
	var tlsConfig *tls.Config
	if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
		if err != nil {
			log.Fatalf("[Main] Failed to load TLS cert/key: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	} else if cfg.TLSEnabled || cfg.AutoTLS {
		cert, err := GenerateSelfSignedCert()
		if err != nil {
			log.Fatalf("[Main] Failed to generate auto-TLS cert: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
		log.Println("[Main] Generated self-signed TLS certificate (TLS 1.3) for localhost/127.0.0.1")
	}

	// 8. Server Run & Graceful Shutdown
	go func() {
		if tlsConfig != nil {
			httpServer.TLSConfig = tlsConfig
			log.Printf("[Main] HTTPS Server listening on https://%s", addr)
			if err := httpServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("[Main] HTTPS Server error: %v", err)
			}
		} else {
			log.Printf("[Main] HTTP Server listening on http://%s", addr)
			if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("[Main] HTTP Server error: %v", err)
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("[Main] Gracefully shutting down server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("[Main] Server shutdown error: %v", err)
	}
	log.Println("[Main] Server stopped.")
}

var stdinReader = bufio.NewReader(os.Stdin)

func readSecretInput() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		return term.ReadPassword(fd)
	}
	// Fallback to shared reading from pipe / stdin stream
	line, err := stdinReader.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	for len(line) > 0 && (line[len(line)-1] == '\r' || line[len(line)-1] == '\n') {
		line = line[:len(line)-1]
	}
	return line, nil
}

func handleCLIInit(cfg *config.Config) {
	sealMgr := crypto.NewSealManager(cfg.SealedSMKPath)
	if sealMgr.IsInitialized() {
		fmt.Printf("Error: Sealed Server Master Key already exists at %s\n", cfg.SealedSMKPath)
		os.Exit(1)
	}
	fmt.Println("=== Web Key Manager — SMK Initialization ===")
	for {
		fmt.Print("Enter Admin Startup Passphrase (min 12 chars): ")
		p1, err := readSecretInput()
		fmt.Println()
		if err != nil {
			log.Fatalf("Failed to read passphrase: %v", err)
		}
		if len(p1) < 12 {
			fmt.Println("Error: Passphrase must be at least 12 characters.")
			clear(p1)
			continue
		}
		// If piped input, don't demand confirmation loop unless a second line is provided
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			err = sealMgr.InitSMK(string(p1))
			clear(p1)
			if err != nil {
				log.Fatalf("Failed to initialize SMK: %v", err)
			}
			fmt.Printf("Success! Server Master Key initialized and sealed to %s\n", cfg.SealedSMKPath)
			return
		}

		fmt.Print("Confirm Admin Startup Passphrase: ")
		p2, err := readSecretInput()
		fmt.Println()
		if err != nil {
			clear(p1)
			log.Fatalf("Failed to read confirmation: %v", err)
		}
		if string(p1) != string(p2) {
			fmt.Println("Error: Passphrases do not match. Please try again.")
			clear(p1)
			clear(p2)
			continue
		}
		err = sealMgr.InitSMK(string(p1))
		clear(p1)
		clear(p2)
		if err != nil {
			log.Fatalf("Failed to initialize SMK: %v", err)
		}
		fmt.Printf("Success! Server Master Key initialized and sealed to %s\n", cfg.SealedSMKPath)
		return
	}
}

func handleCLIUnseal(cfg *config.Config) {
	sealMgr := crypto.NewSealManager(cfg.SealedSMKPath)
	if !sealMgr.IsInitialized() {
		fmt.Printf("Error: No sealed key file found at %s. Please run 'keymanager init' first.\n", cfg.SealedSMKPath)
		os.Exit(1)
	}
	fmt.Print("Enter Admin Startup Passphrase: ")
	p, err := readSecretInput()
	fmt.Println()
	if err != nil {
		log.Fatalf("Failed to read passphrase: %v", err)
	}
	defer clear(p)
	if err := sealMgr.Unseal(string(p)); err != nil {
		fmt.Printf("Unseal failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Success! Server Master Key unsealed successfully.")
}

func handleCLIRotate(cfg *config.Config) {
	sealMgr := crypto.NewSealManager(cfg.SealedSMKPath)
	if !sealMgr.IsInitialized() {
		fmt.Printf("Error: No sealed key file found at %s. Please run 'keymanager init' first.\n", cfg.SealedSMKPath)
		os.Exit(1)
	}
	fmt.Println("=== Web Key Manager — Admin Passphrase Rotation ===")
	fmt.Print("Enter Current Admin Startup Passphrase: ")
	oldPass, err := readSecretInput()
	fmt.Println()
	if err != nil {
		log.Fatalf("Failed to read passphrase: %v", err)
	}
	defer clear(oldPass)

	for {
		fmt.Print("Enter New Admin Startup Passphrase (min 12 chars): ")
		p1, err := readSecretInput()
		fmt.Println()
		if err != nil {
			log.Fatalf("Failed to read new passphrase: %v", err)
		}
		if len(p1) < 12 {
			fmt.Println("Error: New passphrase must be at least 12 characters.")
			clear(p1)
			continue
		}

		if !term.IsTerminal(int(os.Stdin.Fd())) {
			err = sealMgr.RotatePassphrase(string(oldPass), string(p1))
			clear(p1)
			if err != nil {
				fmt.Printf("Rotation failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Success! Admin Startup Passphrase rotated. Server Master Key re-sealed with new key.")
			return
		}

		fmt.Print("Confirm New Admin Startup Passphrase: ")
		p2, err := readSecretInput()
		fmt.Println()
		if err != nil {
			clear(p1)
			log.Fatalf("Failed to read confirmation: %v", err)
		}
		if string(p1) != string(p2) {
			fmt.Println("Error: Passphrases do not match. Please try again.")
			clear(p1)
			clear(p2)
			continue
		}
		err = sealMgr.RotatePassphrase(string(oldPass), string(p1))
		clear(p1)
		clear(p2)
		if err != nil {
			fmt.Printf("Rotation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Success! Admin Startup Passphrase rotated. Server Master Key re-sealed with new key.")
		return
	}
}

func handleCLIBackup(cfg *config.Config) {
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	defer database.Close()

	sealMgr := crypto.NewSealManager(cfg.SealedSMKPath)
	if !sealMgr.IsInitialized() {
		log.Fatalf("No sealed key file found at %s", cfg.SealedSMKPath)
	}
	if !sealMgr.IsUnsealed() {
		fmt.Print("Enter Admin Startup Passphrase to unseal for backup: ")
		p, err := readSecretInput()
		fmt.Println()
		if err != nil {
			log.Fatalf("Failed to read passphrase: %v", err)
		}
		defer clear(p)
		if err := sealMgr.Unseal(string(p)); err != nil {
			log.Fatalf("Unseal failed: %v", err)
		}
	}

	bm := backup.NewBackupManager(database, sealMgr, cfg.BackupDir, cfg.BackupRetentionDays)
	path, err := bm.RunBackup(context.Background())
	if err != nil {
		log.Fatalf("Backup failed: %v", err)
	}
	fmt.Printf("Success! Encrypted backup written to: %s\n", path)
}

// parseServerFlags parses CLI arguments/flags and updates cfg.
// Returns (shouldStartServer, error).
func parseServerFlags(cfg *config.Config, args []string) (bool, error) {
	if len(args) > 0 {
		cmd := strings.ToLower(args[0])
		switch cmd {
		case "init":
			handleCLIInit(cfg)
			return false, nil
		case "unseal":
			handleCLIUnseal(cfg)
			return false, nil
		case "rotate-passphrase":
			handleCLIRotate(cfg)
			return false, nil
		case "backup":
			handleCLIBackup(cfg)
			return false, nil
		case "help", "-h", "--help":
			printUsage()
			return false, nil
		case "run", "serve", "start":
			args = args[1:]
		default:
			if !strings.HasPrefix(cmd, "-") {
				return false, fmt.Errorf("unknown command: %s", cmd)
			}
		}
	}

	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.Usage = printUsage
	tlsFlag := fs.Bool("tls", false, "Enable direct TLS (generates self-signed cert if cert/key not provided)")
	tlsCertFlag := fs.String("tls-cert", "", "Path to TLS certificate file")
	tlsKeyFlag := fs.String("tls-key", "", "Path to TLS private key file")
	portFlag := fs.String("port", "", "Server listen port (default: 8082)")
	hostFlag := fs.String("host", "", "Server listen host (default: localhost)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false, nil
		}
		return false, err
	}

	for _, extra := range fs.Args() {
		switch strings.ToLower(extra) {
		case "run", "serve", "start":
			// Allow trailing run/serve/start commands
		default:
			return false, fmt.Errorf("unknown command or argument: %s", extra)
		}
	}

	if *tlsFlag {
		cfg.TLSEnabled = true
		cfg.AutoTLS = true
	}
	if *tlsCertFlag != "" {
		cfg.TLSCertPath = *tlsCertFlag
	}
	if *tlsKeyFlag != "" {
		cfg.TLSKeyPath = *tlsKeyFlag
	}
	if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
		cfg.TLSEnabled = true
	}
	if *portFlag != "" {
		cfg.Port = *portFlag
	}
	if *hostFlag != "" {
		cfg.Host = *hostFlag
	}

	// Validate TLS certificate and key consistency
	if (cfg.TLSCertPath != "" && cfg.TLSKeyPath == "") || (cfg.TLSCertPath == "" && cfg.TLSKeyPath != "") {
		return false, fmt.Errorf("invalid TLS configuration: both TLS certificate and private key must be provided")
	}

	return true, nil
}

func printUsage() {
	fmt.Println(`Web Password & Key Manager

Usage:
  keymanager [command] [flags]

Commands:
  run, serve         Start the HTTP/HTTPS server (default: http://localhost:8082)
  init               Initialize Server Master Key with an Admin Startup Passphrase
  unseal             Prompt for Admin Startup Passphrase and verify unseal
  rotate-passphrase  Rotate the Admin Startup Passphrase on server_master.key.enc
  backup             Run immediate SQLite snapshot, integrity check, and encryption
  help, -h, --help   Show this help message

Flags:
  --tls              Enable direct TLS (auto-generates self-signed cert if none provided)
  --tls-cert <path>  Path to TLS certificate file (or TLS_CERT env var)
  --tls-key <path>   Path to TLS private key file (or TLS_KEY env var)
  --port <port>      Listen port (default: 8082, or PORT env var)
  --host <host>      Listen host (default: localhost, or HOST env var)`)
}
