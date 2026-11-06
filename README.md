# Web Password & Key Manager

A zero-knowledge, Passkey-native web password and key manager with a **Go** backend, **SQLite** database, and direct-to-clipboard decryption.

---

## Features

- **Passkey-Only Authentication**: WebAuthn / FIDO2 registration and login (`userVerification: "required"`).
- **Zero Plaintext Exposure**: Secrets are never sent to or stored on the server in plaintext, and are never rendered in the DOM.
- **Passkey-Bound E2EE**: Client encryption uses the WebAuthn PRF extension (`hmac-secret`) + WebCrypto (`AES-256-GCM`).
- **Server Envelope Encryption**: Every record is independently encrypted again by the Go backend using a Server Master Key (SMK).
- **Admin Startup Passphrase**: The SMK is sealed on disk (`server_master.key.enc`) with `Argon2id` + `AES-256-GCM` and unsealed into memory-locked (`mlock`) RAM on startup.
- **Add/Change Phone Handshake**: New phones require cryptographic verification on an existing verified device using ephemeral `ECDH P-256` and a 6-digit pairing code.
- **3-Mode Key Creation**:
  - **Type**: Input twice with masked fields and byte-level comparison before encryption.
  - **Paste**: Captures directly into memory and starts a 3-minute clipboard auto-clear timer.
  - **Auto-Generate**: Direct CSPRNG key generation into memory (`crypto.getRandomValues`).
- **Direct-to-Clipboard Decryption**: Copies decrypted keys directly to the system clipboard; automatically purges the clipboard after 3 minutes.
- **Enforced Quotas**: Max 10KB per key, max 1,000 keys per user, and max 10,000 keys per IP (enforced atomically via SQLite triggers).
- **Daily Automated Backups**: Atomic snapshots via SQLite `VACUUM INTO`, verified with `PRAGMA integrity_check`, compressed with gzip, and encrypted under SMK.

---

## Quick Start

### 1. Build the Binary
```bash
go build -o keymanager ./cmd/server
```

### 2. First-Time Setup: Initialize Server Master Key
Run `init` to set your **Admin Startup Passphrase** (minimum 12 characters). This generates and seals `server_master.key.enc`:
```bash
./keymanager init
```

### 3. Start the Server
Start the server (listens on `http://localhost:8082` by default):
```bash
./keymanager run
```
You will be prompted to enter your Admin Startup Passphrase to unseal the server into RAM.

Open your browser to:
```
http://localhost:8082
```

---

## CLI Commands & Flags

```text
Usage:
  keymanager [command] [flags]

Commands:
  run, serve         Start the HTTP server (default command)
  init               Initialize Server Master Key with an Admin Startup Passphrase
  unseal             Prompt for Admin Startup Passphrase and verify unsealing
  rotate-passphrase  Change the Admin Startup Passphrase on server_master.key.enc
  backup             Run immediate SQLite snapshot, integrity check, and encryption
  help, -h, --help   Show usage instructions

Flags:
  --port <port>      Listen port (default: 8082, or PORT env var)
  --host <host>      Listen host (default: localhost, or HOST env var)
  --tls              Enable direct TLS (auto-generates self-signed cert if none provided)
  --tls-cert <path>  Path to TLS certificate file (or TLS_CERT env var)
  --tls-key <path>   Path to TLS private key file (or TLS_KEY env var)
```

---

## Configuration & Environment Variables

All settings can be configured via environment variables or flags:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `8082` | HTTP listen port |
| `HOST` | `localhost` | HTTP listen host (`0.0.0.0` to listen on all interfaces) |
| `DB_PATH` | `keymanager.db` | Path to SQLite database file |
| `SEALED_SMK_PATH` | `server_master.key.enc` | Path to sealed Server Master Key file |
| `BACKUP_DIR` | `./backups` | Directory for automated daily encrypted backups |
| `BACKUP_RETENTION_DAYS` | `30` | Number of daily backups to retain |
| `RP_ID` | *(auto-detected)* | WebAuthn Relying Party ID (e.g. `vault.example.com`) |
| `RP_ORIGIN` | *(auto-detected)* | WebAuthn Relying Party Origin (e.g. `https://vault.example.com`) |
| `TLS_CERT` | *(none)* | Path to TLS certificate (optional) |
| `TLS_KEY` | *(none)* | Path to TLS private key (optional) |
| `ADMIN_PASSPHRASE` | *(none)* | Optional: Passphrase to auto-unseal the server on boot (e.g. in `/etc/keymanager/keymanager.env`). If omitted, the server boots in Sealed Mode and can be unsealed via the Web UI. |
| `ADMIN_PASSPHRASE_FILE` | *(none)* | Optional: Path to a file containing the Admin Startup Passphrase (useful for systemd credentials). |

---

## Running as a System Service (systemd)

The key manager can run as a background `systemd` service that starts automatically on boot.

### Service Installation

1. The service unit is installed at `/etc/systemd/system/keymanager.service`:
   ```ini
   [Unit]
   Description=Passkey Web Password & Key Manager
   After=network.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/root/pass
   ExecStart=/root/pass/keymanager run
   Restart=on-failure
   RestartSec=5s
   LimitMEMLOCK=infinity
   EnvironmentFile=-/etc/keymanager/keymanager.env
   StandardOutput=journal
   StandardError=journal

   [Install]
   WantedBy=multi-user.target
   ```

2. Environment configuration is managed in `/etc/keymanager/keymanager.env`:
   ```bash
   PORT=8082
   HOST=localhost
   DB_PATH=/root/pass/keymanager.db
   SEALED_SMK_PATH=/root/pass/server_master.key.enc
   BACKUP_DIR=/root/pass/backups
   # Optional: set ADMIN_PASSPHRASE if you want automated unsealing on service boot
   # ADMIN_PASSPHRASE=your-secure-passphrase-here
   ```

### Managing the Service

```bash
# Start the service
systemctl start keymanager

# Check service status
systemctl status keymanager

# View live service logs
journalctl -u keymanager -f

# Enable service to start on boot
systemctl enable keymanager

# Restart or stop the service
systemctl restart keymanager
systemctl stop keymanager
```

### Unsealing When Running as a Service

When running as a system service, the server starts safely in **Sealed Mode**:
- **Via Web UI**: Open `http://localhost:8082` (or your reverse proxy URL). The web interface will show the **Unseal Server** screen. Enter your Admin Startup Passphrase to unseal the server into RAM.
- **Via API / curl**:
  ```bash
  curl -X POST http://localhost:8082/api/v1/admin/unseal \
       -H "Content-Type: application/json" \
       -d '{"passphrase":"your-admin-passphrase"}'
  ```
- **Automated Unseal on Boot**: Uncomment `ADMIN_PASSPHRASE` in `/etc/keymanager/keymanager.env` (`chmod 600 /etc/keymanager/keymanager.env`). The server will automatically unseal into RAM when systemd starts the service.

---

## Deploying Behind Reverse Proxies (Caddy / Cloudflare)

The server is designed to run on `http://localhost:8082` behind a reverse proxy that terminates TLS.

### 1. Caddy (`Caddyfile`)
```caddy
vault.yourdomain.com {
    reverse_proxy localhost:8082
}
```
Caddy automatically handles HTTPS certificates and sets `X-Forwarded-Proto: https` and `X-Forwarded-Host`. The backend automatically detects the public domain and adjusts session cookies (`__Host-` prefix with `Secure; SameSite=Strict`) and WebAuthn RP origins.

### 2. Cloudflare Tunnel (`cloudflared`)
In `~/.cloudflared/config.yml`:
```yaml
tunnel: <TUNNEL_ID>
credentials-file: /root/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: vault.yourdomain.com
    service: http://localhost:8082
  - service: http_status:404
```
Run the tunnel:
```bash
cloudflared tunnel run
```

---

## Running Automated Tests

```bash
# Run all unit, concurrency, and integration tests
go test -v -count=1 ./...
```
