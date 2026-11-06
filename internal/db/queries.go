package db

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Credential struct {
	ID              []byte     `json:"id"`
	UserID          string     `json:"user_id"`
	DeviceName      string     `json:"device_name"`
	PublicKey       []byte     `json:"public_key"`
	AttestationType string     `json:"attestation_type"`
	AAGUID          []byte     `json:"aaguid"`
	SignCount       uint32     `json:"sign_count"`
	Transports      string     `json:"transports"`
	BackupEligible  bool       `json:"backup_eligible"`
	BackupState     bool       `json:"backup_state"`
	PRFSalt         []byte     `json:"prf_salt"`
	WrappedMEK      []byte     `json:"wrapped_mek"`
	WrappedMEKIV    []byte     `json:"wrapped_mek_iv"`
	Status          string     `json:"status"` // 'verified' | 'revoked'
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at"`
}

type DeviceRequest struct {
	ID                     string    `json:"id"`
	UserID                 string    `json:"user_id"`
	ActionType             string    `json:"action_type"` // 'add_phone' | 'change_phone'
	ReplaceCredentialID    []byte    `json:"replace_credential_id,omitempty"`
	NewDeviceName          string    `json:"new_device_name"`
	VerificationCodeHash   string    `json:"verification_code_hash"`
	NewDeviceECDHPub       []byte    `json:"new_device_ecdh_pub"`
	ApproverECDHPub        []byte    `json:"approver_ecdh_pub,omitempty"`
	EncryptedMEKTransfer   []byte    `json:"encrypted_mek_transfer,omitempty"`
	TransferIV             []byte    `json:"transfer_iv,omitempty"`
	ApprovedByCredentialID []byte    `json:"approved_by_credential_id,omitempty"`
	Status                 string    `json:"status"` // 'pending' | 'approved' | 'completed' | 'expired' | 'rejected'
	ExpiresAt              time.Time `json:"expires_at"`
	CreatedAt              time.Time `json:"created_at"`
}

type Key struct {
	ID               string    `json:"id"`
	UserID           string    `json:"user_id"`
	Name             string    `json:"name"`
	NameNormalized   string    `json:"name_normalized"`
	ServerCiphertext []byte    `json:"server_ciphertext"`
	ServerIV         []byte    `json:"server_iv"`
	ServerSalt       []byte    `json:"server_salt"`
	ClientIV         []byte    `json:"client_iv"`
	ClientSalt       []byte    `json:"client_salt"`
	CreatorIP        string    `json:"creator_ip,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type KeyMetadata struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func ensureCtx(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (d *DB) CreateUser(ctx context.Context, id, username, displayName string) error {
	ctx = ensureCtx(ctx)
	_, err := d.ExecContext(ctx,
		`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		id, username, displayName)
	return err
}

func (d *DB) CreateUserWithCredentialTx(ctx context.Context, id, username, displayName string, cred *Credential, auditIP, auditMsg string) error {
	ctx = ensureCtx(ctx)
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`INSERT INTO users (id, username, display_name, created_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		id, username, displayName)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO credentials (
			id, user_id, device_name, public_key, attestation_type, aaguid,
			sign_count, transports, backup_eligible, backup_state,
			prf_salt, wrapped_mek, wrapped_mek_iv, status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		cred.ID, cred.UserID, cred.DeviceName, cred.PublicKey, cred.AttestationType, cred.AAGUID,
		cred.SignCount, cred.Transports, cred.BackupEligible, cred.BackupState,
		cred.PRFSalt, cred.WrappedMEK, cred.WrappedMEKIV, cred.Status,
	)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO audit_logs (user_id, event_type, ip_address, metadata, created_at) VALUES (?, 'register', ?, ?, CURRENT_TIMESTAMP)`,
		id, auditIP, auditMsg,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (d *DB) GetUserByID(ctx context.Context, id string) (*User, error) {
	ctx = ensureCtx(ctx)
	row := d.QueryRowContext(ctx, `SELECT id, username, display_name, created_at, updated_at FROM users WHERE id = ?`, id)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

func (d *DB) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	ctx = ensureCtx(ctx)
	row := d.QueryRowContext(ctx, `SELECT id, username, display_name, created_at, updated_at FROM users WHERE username = ?`, username)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

func (d *DB) CreateCredential(ctx context.Context, cred *Credential) error {
	ctx = ensureCtx(ctx)
	_, err := d.ExecContext(ctx,
		`INSERT INTO credentials (
			id, user_id, device_name, public_key, attestation_type, aaguid,
			sign_count, transports, backup_eligible, backup_state,
			prf_salt, wrapped_mek, wrapped_mek_iv, status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		cred.ID, cred.UserID, cred.DeviceName, cred.PublicKey, cred.AttestationType, cred.AAGUID,
		cred.SignCount, cred.Transports, cred.BackupEligible, cred.BackupState,
		cred.PRFSalt, cred.WrappedMEK, cred.WrappedMEKIV, cred.Status,
	)
	return err
}

func (d *DB) GetCredentialsByUserID(ctx context.Context, userID string) ([]Credential, error) {
	ctx = ensureCtx(ctx)
	rows, err := d.QueryContext(ctx,
		`SELECT id, user_id, device_name, public_key, attestation_type, aaguid,
			sign_count, transports, backup_eligible, backup_state,
			prf_salt, wrapped_mek, wrapped_mek_iv, status, created_at, last_used_at
		FROM credentials WHERE user_id = ? ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []Credential
	for rows.Next() {
		var c Credential
		var lastUsed sql.NullTime
		if err := rows.Scan(
			&c.ID, &c.UserID, &c.DeviceName, &c.PublicKey, &c.AttestationType, &c.AAGUID,
			&c.SignCount, &c.Transports, &c.BackupEligible, &c.BackupState,
			&c.PRFSalt, &c.WrappedMEK, &c.WrappedMEKIV, &c.Status, &c.CreatedAt, &lastUsed,
		); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			c.LastUsedAt = &lastUsed.Time
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

func (d *DB) GetCredentialByID(ctx context.Context, id []byte) (*Credential, error) {
	ctx = ensureCtx(ctx)
	row := d.QueryRowContext(ctx,
		`SELECT id, user_id, device_name, public_key, attestation_type, aaguid,
			sign_count, transports, backup_eligible, backup_state,
			prf_salt, wrapped_mek, wrapped_mek_iv, status, created_at, last_used_at
		FROM credentials WHERE id = ?`, id)
	var c Credential
	var lastUsed sql.NullTime
	if err := row.Scan(
		&c.ID, &c.UserID, &c.DeviceName, &c.PublicKey, &c.AttestationType, &c.AAGUID,
		&c.SignCount, &c.Transports, &c.BackupEligible, &c.BackupState,
		&c.PRFSalt, &c.WrappedMEK, &c.WrappedMEKIV, &c.Status, &c.CreatedAt, &lastUsed,
	); err != nil {
		return nil, err
	}
	if lastUsed.Valid {
		c.LastUsedAt = &lastUsed.Time
	}
	return &c, nil
}

func (d *DB) UpdateCredentialSignCount(ctx context.Context, id []byte, signCount uint32) error {
	ctx = ensureCtx(ctx)
	_, err := d.ExecContext(ctx,
		`UPDATE credentials SET sign_count = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ?`,
		signCount, id)
	return err
}

func (d *DB) RevokeCredential(ctx context.Context, id []byte, userID string) error {
	ctx = ensureCtx(ctx)
	_, err := d.ExecContext(ctx,
		`UPDATE credentials SET status = 'revoked', last_used_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?`,
		id, userID)
	return err
}

func (d *DB) CreateDeviceRequest(ctx context.Context, req *DeviceRequest) error {
	ctx = ensureCtx(ctx)
	_, err := d.ExecContext(ctx,
		`INSERT INTO device_verification_requests (
			id, user_id, action_type, replace_credential_id, new_device_name,
			verification_code_hash, new_device_ecdh_pub, status, expires_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, CURRENT_TIMESTAMP)`,
		req.ID, req.UserID, req.ActionType, req.ReplaceCredentialID, req.NewDeviceName,
		req.VerificationCodeHash, req.NewDeviceECDHPub, req.ExpiresAt,
	)
	return err
}

func (d *DB) GetDeviceRequestByID(ctx context.Context, id string) (*DeviceRequest, error) {
	ctx = ensureCtx(ctx)
	row := d.QueryRowContext(ctx,
		`SELECT id, user_id, action_type, replace_credential_id, new_device_name,
			verification_code_hash, new_device_ecdh_pub, approver_ecdh_pub,
			encrypted_mek_transfer, transfer_iv, approved_by_credential_id,
			status, expires_at, created_at
		FROM device_verification_requests WHERE id = ?`, id)
	var r DeviceRequest
	var replaceID, appECDH, encMEK, tIV, appCredID []byte
	if err := row.Scan(
		&r.ID, &r.UserID, &r.ActionType, &replaceID, &r.NewDeviceName,
		&r.VerificationCodeHash, &r.NewDeviceECDHPub, &appECDH,
		&encMEK, &tIV, &appCredID,
		&r.Status, &r.ExpiresAt, &r.CreatedAt,
	); err != nil {
		return nil, err
	}
	r.ReplaceCredentialID = replaceID
	r.ApproverECDHPub = appECDH
	r.EncryptedMEKTransfer = encMEK
	r.TransferIV = tIV
	r.ApprovedByCredentialID = appCredID
	return &r, nil
}

func (d *DB) GetPendingDeviceRequests(ctx context.Context, userID string) ([]DeviceRequest, error) {
	ctx = ensureCtx(ctx)
	now := time.Now().UTC()
	rows, err := d.QueryContext(ctx,
		`SELECT id, user_id, action_type, replace_credential_id, new_device_name,
			verification_code_hash, new_device_ecdh_pub, status, expires_at, created_at
		FROM device_verification_requests
		WHERE user_id = ? AND status = 'pending' AND expires_at > ?
		ORDER BY created_at DESC`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reqs []DeviceRequest
	for rows.Next() {
		var r DeviceRequest
		var replaceID []byte
		if err := rows.Scan(
			&r.ID, &r.UserID, &r.ActionType, &replaceID, &r.NewDeviceName,
			&r.VerificationCodeHash, &r.NewDeviceECDHPub,
			&r.Status, &r.ExpiresAt, &r.CreatedAt,
		); err != nil {
			return nil, err
		}
		r.ReplaceCredentialID = replaceID
		reqs = append(reqs, r)
	}
	return reqs, rows.Err()
}

func (d *DB) ApproveDeviceRequest(ctx context.Context, id string, approverECDHPub, encryptedMEKTransfer, transferIV, approverCredID []byte) error {
	ctx = ensureCtx(ctx)
	now := time.Now().UTC()
	res, err := d.ExecContext(ctx,
		`UPDATE device_verification_requests
		SET approver_ecdh_pub = ?, encrypted_mek_transfer = ?, transfer_iv = ?, approved_by_credential_id = ?, status = 'approved'
		WHERE id = ? AND status = 'pending' AND expires_at > ?`,
		approverECDHPub, encryptedMEKTransfer, transferIV, approverCredID, id, now)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (d *DB) CompleteDeviceRequest(ctx context.Context, id string) error {
	ctx = ensureCtx(ctx)
	_, err := d.ExecContext(ctx,
		`UPDATE device_verification_requests SET status = 'completed' WHERE id = ?`, id)
	return err
}

func (d *DB) CompleteDeviceEnrollmentTx(ctx context.Context, cred *Credential, reqID string, revokeCredID []byte, auditUserID *string, auditIP, auditMsg string) error {
	ctx = ensureCtx(ctx)
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Complete device request (must be pending or approved and not expired)
	res, err := tx.ExecContext(ctx,
		`UPDATE device_verification_requests SET status = 'completed' WHERE id = ? AND status IN ('pending', 'approved') AND expires_at > ?`,
		reqID, time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return sql.ErrNoRows
	}

	// 2. Insert credential
	_, err = tx.ExecContext(ctx,
		`INSERT INTO credentials (
			id, user_id, device_name, public_key, attestation_type, aaguid,
			sign_count, transports, backup_eligible, backup_state,
			prf_salt, wrapped_mek, wrapped_mek_iv, status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		cred.ID, cred.UserID, cred.DeviceName, cred.PublicKey, cred.AttestationType, cred.AAGUID,
		cred.SignCount, cred.Transports, cred.BackupEligible, cred.BackupState,
		cred.PRFSalt, cred.WrappedMEK, cred.WrappedMEKIV, cred.Status,
	)
	if err != nil {
		return err
	}

	// 3. If revokeCredID is provided, revoke old credential
	if len(revokeCredID) > 0 {
		_, err = tx.ExecContext(ctx,
			`UPDATE credentials SET status = 'revoked', last_used_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?`,
			revokeCredID, cred.UserID,
		)
		if err != nil {
			return err
		}
	}

	// 4. Audit log
	if auditUserID != nil {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO audit_logs (user_id, event_type, ip_address, metadata, created_at) VALUES (?, 'device_enrolled', ?, ?, CURRENT_TIMESTAMP)`,
			*auditUserID, auditIP, auditMsg,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (d *DB) RejectDeviceRequest(ctx context.Context, id, userID string) error {
	ctx = ensureCtx(ctx)
	_, err := d.ExecContext(ctx,
		`UPDATE device_verification_requests SET status = 'rejected' WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

func (d *DB) ExpireOldDeviceRequests(ctx context.Context) error {
	ctx = ensureCtx(ctx)
	now := time.Now().UTC()
	_, err := d.ExecContext(ctx,
		`UPDATE device_verification_requests SET status = 'expired' WHERE status IN ('pending', 'approved') AND expires_at <= ?`, now)
	return err
}

func (d *DB) CreateKey(ctx context.Context, k *Key) error {
	ctx = ensureCtx(ctx)
	_, err := d.ExecContext(ctx,
		`INSERT INTO keys (
			id, user_id, name, name_normalized, server_ciphertext,
			server_iv, server_salt, client_iv, client_salt, creator_ip, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		k.ID, k.UserID, k.Name, k.NameNormalized, k.ServerCiphertext,
		k.ServerIV, k.ServerSalt, k.ClientIV, k.ClientSalt, k.CreatorIP,
	)
	return err
}

func (d *DB) CountKeysByUserID(ctx context.Context, userID string) (int, error) {
	ctx = ensureCtx(ctx)
	var count int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM keys WHERE user_id = ?`, userID).Scan(&count)
	return count, err
}

func (d *DB) CountKeysByIP(ctx context.Context, ip string) (int, error) {
	ctx = ensureCtx(ctx)
	var count int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM keys WHERE creator_ip = ?`, ip).Scan(&count)
	return count, err
}

func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func (d *DB) ListKeysMetadata(ctx context.Context, userID, query string) ([]KeyMetadata, error) {
	ctx = ensureCtx(ctx)
	normQuery := strings.ToLower(strings.TrimSpace(query))
	likePattern := "%" + escapeLikePattern(normQuery) + "%"

	rows, err := d.QueryContext(ctx,
		`SELECT id, name, created_at, updated_at
		FROM keys
		WHERE user_id = ? AND name_normalized LIKE ? ESCAPE '\'
		ORDER BY name_normalized ASC
		LIMIT 100`, userID, likePattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]KeyMetadata, 0)
	for rows.Next() {
		var km KeyMetadata
		if err := rows.Scan(&km.ID, &km.Name, &km.CreatedAt, &km.UpdatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, km)
	}
	return keys, rows.Err()
}

func (d *DB) GetKeyByID(ctx context.Context, id, userID string) (*Key, error) {
	ctx = ensureCtx(ctx)
	row := d.QueryRowContext(ctx,
		`SELECT id, user_id, name, name_normalized, server_ciphertext,
			server_iv, server_salt, client_iv, client_salt, creator_ip, created_at, updated_at
		FROM keys WHERE id = ? AND user_id = ?`, id, userID)
	var k Key
	var creatorIP sql.NullString
	if err := row.Scan(
		&k.ID, &k.UserID, &k.Name, &k.NameNormalized, &k.ServerCiphertext,
		&k.ServerIV, &k.ServerSalt, &k.ClientIV, &k.ClientSalt, &creatorIP, &k.CreatedAt, &k.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if creatorIP.Valid {
		k.CreatorIP = creatorIP.String
	}
	return &k, nil
}

func (d *DB) UpdateKey(ctx context.Context, id, userID, name, nameNorm string, serverCT, serverIV, serverSalt, clientIV, clientSalt []byte) error {
	ctx = ensureCtx(ctx)
	res, err := d.ExecContext(ctx,
		`UPDATE keys
		SET name = ?, name_normalized = ?, server_ciphertext = ?,
			server_iv = ?, server_salt = ?, client_iv = ?, client_salt = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND user_id = ?`,
		name, nameNorm, serverCT, serverIV, serverSalt, clientIV, clientSalt, id, userID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (d *DB) DeleteKey(ctx context.Context, id, userID string) error {
	ctx = ensureCtx(ctx)
	res, err := d.ExecContext(ctx, `DELETE FROM keys WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (d *DB) InsertAuditLog(ctx context.Context, userID *string, eventType, ipAddress, metadata string) error {
	ctx = ensureCtx(ctx)
	_, err := d.ExecContext(ctx,
		`INSERT INTO audit_logs (user_id, event_type, ip_address, metadata, created_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		userID, eventType, ipAddress, metadata)
	return err
}
