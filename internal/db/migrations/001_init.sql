-- 1. Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Passkey Credentials (Verified Devices)
CREATE TABLE IF NOT EXISTS credentials (
    id BLOB PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    public_key BLOB NOT NULL,
    attestation_type TEXT NOT NULL,
    aaguid BLOB,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    backup_eligible BOOLEAN NOT NULL DEFAULT 0,
    backup_state BOOLEAN NOT NULL DEFAULT 0,
    prf_salt BLOB NOT NULL,
    wrapped_mek BLOB NOT NULL,
    wrapped_mek_iv BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'verified',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);

-- 3. Device Addition / Phone Change Verification Requests
CREATE TABLE IF NOT EXISTS device_verification_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    replace_credential_id BLOB,
    new_device_name TEXT NOT NULL,
    verification_code_hash TEXT NOT NULL,
    new_device_ecdh_pub BLOB NOT NULL,
    approver_ecdh_pub BLOB,
    encrypted_mek_transfer BLOB,
    transfer_iv BLOB,
    approved_by_credential_id BLOB,
    status TEXT NOT NULL DEFAULT 'pending',
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_device_req_user_status ON device_verification_requests(user_id, status);

-- 4. Encrypted Keys Table
CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    name_normalized TEXT NOT NULL,
    server_ciphertext BLOB NOT NULL,
    server_iv BLOB NOT NULL,
    server_salt BLOB NOT NULL,
    client_iv BLOB NOT NULL,
    client_salt BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, name_normalized),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_keys_user_name ON keys(user_id, name_normalized);

-- 5. Audit & Backup Log Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    metadata TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
