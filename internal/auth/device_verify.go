package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"passmanager/internal/db"
)

var (
	ErrDeviceRequestNotFound = errors.New("device verification request not found")
	ErrDeviceRequestExpired  = errors.New("device verification request has expired")
	ErrInvalidRequestStatus  = errors.New("invalid status for device verification request")
	ErrCannotRevokeLastDevice= errors.New("cannot revoke the last remaining verified device")
)

type DeviceManager struct {
	db          *db.DB
	authSvc     *AuthService
	sessions    *SessionManager
	mu          sync.RWMutex
	regSessions map[string]*regSessionEntry
}

func NewDeviceManager(database *db.DB, as *AuthService, sm *SessionManager) *DeviceManager {
	dm := &DeviceManager{
		db:          database,
		authSvc:     as,
		sessions:    sm,
		regSessions: make(map[string]*regSessionEntry),
	}
	go dm.cleanExpiredSessions()
	return dm
}

func (dm *DeviceManager) cleanExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		dm.mu.Lock()
		for k, v := range dm.regSessions {
			if now.After(v.expiresAt) {
				delete(dm.regSessions, k)
			}
		}
		dm.mu.Unlock()
	}
}

// RequestInitiatePayload defines the incoming payload for POST /api/v1/devices/request
type RequestInitiatePayload struct {
	Username             string `json:"username"`
	ActionType           string `json:"action_type"` // 'add_phone' | 'change_phone'
	ReplaceCredentialID  string `json:"replace_credential_id,omitempty"` // base64
	DeviceName           string `json:"device_name"`
	NewDeviceECDHPub     string `json:"new_device_ecdh_pub"`     // base64
	VerificationCodeHash string `json:"verification_code_hash"`  // hex sha256
}

// InitiateRequest is called by the new phone to begin device verification
func (dm *DeviceManager) InitiateRequest(ctx context.Context, payload *RequestInitiatePayload) (string, int, error) {
	if payload == nil {
		return "", 0, ErrInvalidRequest
	}
	username := strings.TrimSpace(payload.Username)
	deviceName := strings.TrimSpace(payload.DeviceName)
	codeHash := strings.TrimSpace(payload.VerificationCodeHash)

	if username == "" || len(username) > 128 || deviceName == "" || len(deviceName) > 128 || payload.NewDeviceECDHPub == "" || codeHash == "" || len(codeHash) > 128 {
		return "", 0, ErrInvalidRequest
	}
	if payload.ActionType != "add_phone" && payload.ActionType != "change_phone" {
		return "", 0, errors.New("action_type must be add_phone or change_phone")
	}

	user, err := dm.db.GetUserByUsername(ctx, username)
	if err != nil || user == nil {
		return "", 0, ErrUserNotFound
	}

	// Ensure user has at least one active verified credential to approve the request
	creds, err := dm.db.GetCredentialsByUserID(ctx, user.ID)
	if err != nil {
		return "", 0, ErrUserNotFound
	}
	hasVerified := false
	for _, c := range creds {
		if c.Status == "verified" {
			hasVerified = true
			break
		}
	}
	if !hasVerified {
		return "", 0, ErrUserNotFound
	}

	var replaceCredID []byte
	if payload.ReplaceCredentialID != "" {
		replaceCredID, err = base64.RawURLEncoding.DecodeString(payload.ReplaceCredentialID)
		if err != nil {
			replaceCredID, err = base64.StdEncoding.DecodeString(payload.ReplaceCredentialID)
		}
		if err != nil || len(replaceCredID) == 0 {
			return "", 0, errors.New("invalid replace_credential_id base64")
		}
		// Verify old credential exists, belongs to user, and is currently verified
		c, err := dm.db.GetCredentialByID(ctx, replaceCredID)
		if err != nil || c == nil || c.UserID != user.ID || c.Status != "verified" {
			return "", 0, errors.New("replace_credential_id not found for this user")
		}
	}

	newECDHPub, err := base64.RawURLEncoding.DecodeString(payload.NewDeviceECDHPub)
	if err != nil {
		newECDHPub, err = base64.StdEncoding.DecodeString(payload.NewDeviceECDHPub)
	}
	if err != nil || len(newECDHPub) == 0 || len(newECDHPub) > 256 {
		return "", 0, errors.New("invalid new_device_ecdh_pub base64")
	}

	_ = dm.db.ExpireOldDeviceRequests(ctx)

	reqID := uuid.NewString()
	expiresAt := time.Now().Add(5 * time.Minute)

	req := &db.DeviceRequest{
		ID:                   reqID,
		UserID:               user.ID,
		ActionType:           payload.ActionType,
		ReplaceCredentialID:  replaceCredID,
		NewDeviceName:        deviceName,
		VerificationCodeHash: codeHash,
		NewDeviceECDHPub:     newECDHPub,
		ExpiresAt:            expiresAt,
	}

	if err := dm.db.CreateDeviceRequest(ctx, req); err != nil {
		return "", 0, fmt.Errorf("failed to create device verification request: %w", err)
	}

	return reqID, 300, nil
}

// GetPendingRequests lists all pending requests for an authenticated user
func (dm *DeviceManager) GetPendingRequests(ctx context.Context, userID string) ([]db.DeviceRequest, error) {
	_ = dm.db.ExpireOldDeviceRequests(ctx)
	return dm.db.GetPendingDeviceRequests(ctx, userID)
}

// ApproveRequest is called by the verified device to approve new phone
func (dm *DeviceManager) ApproveRequest(
	ctx context.Context,
	requestID string,
	userID string,
	approverCredID []byte,
	stepUpID string,
	assertionBytes []byte,
	approverECDHPub []byte,
	encryptedMEKTransfer []byte,
	transferIV []byte,
) error {
	if len(approverECDHPub) == 0 || len(encryptedMEKTransfer) == 0 || len(transferIV) == 0 {
		return ErrInvalidRequest
	}

	_ = dm.db.ExpireOldDeviceRequests(ctx)

	req, err := dm.db.GetDeviceRequestByID(ctx, requestID)
	if err != nil || req == nil {
		return ErrDeviceRequestNotFound
	}
	if req.UserID != userID {
		return errors.New("request does not belong to user")
	}
	if req.Status != "pending" {
		return ErrInvalidRequestStatus
	}
	if time.Now().After(req.ExpiresAt) {
		return ErrDeviceRequestExpired
	}

	// Verify step-up assertion and ensure the assertion belongs to the authenticated user
	verifiedCred, err := dm.authSvc.VerifyStepUp(ctx, stepUpID, assertionBytes)
	if err != nil {
		return fmt.Errorf("approval assertion failed: %w", err)
	}
	if verifiedCred.UserID != userID {
		return fmt.Errorf("approval assertion failed: %w", ErrInvalidCredential)
	}

	// Prepare WebAuthn registration options for the new device
	dbUser, err := dm.db.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	waUser, err := dm.authSvc.buildWebAuthnUser(ctx, dbUser)
	if err != nil {
		return err
	}

	options, sessionData, err := dm.authSvc.BeginRegistrationForUser(ctx, waUser)
	if err != nil {
		return fmt.Errorf("failed to prepare registration options for new device: %w", err)
	}

	newPRFSalt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newPRFSalt); err != nil {
		return fmt.Errorf("failed to generate new PRF salt: %w", err)
	}

	// Store registration session data for this request
	dm.mu.Lock()
	dm.regSessions[requestID] = &regSessionEntry{
		userID:          userID,
		username:        dbUser.Username,
		displayName:     dbUser.DisplayName,
		prfSalt:         newPRFSalt,
		creationOptions: options,
		sessionData:     sessionData,
		expiresAt:       req.ExpiresAt,
	}
	dm.mu.Unlock()

	// Update DB record
	if err := dm.db.ApproveDeviceRequest(ctx, requestID, approverECDHPub, encryptedMEKTransfer, transferIV, verifiedCred.ID); err != nil {
		return fmt.Errorf("failed to approve device request: %w", err)
	}

	_ = dm.db.InsertAuditLog(ctx, &userID, "device_approved", "", fmt.Sprintf("approved new device %s for action %s", req.NewDeviceName, req.ActionType))
	return nil
}

type DeviceStatusResponse struct {
	Status               string                        `json:"status"`
	ApproverECDHPub      string                        `json:"approver_ecdh_pub,omitempty"`
	EncryptedMEKTransfer string                        `json:"encrypted_mek_transfer,omitempty"`
	TransferIV           string                        `json:"transfer_iv,omitempty"`
	RegOptions           *protocol.CredentialCreation  `json:"reg_options,omitempty"`
	PRFSalt              string                        `json:"prf_salt,omitempty"`
}

// GetRequestStatus is polled by the new phone
func (dm *DeviceManager) GetRequestStatus(ctx context.Context, requestID string) (*DeviceStatusResponse, error) {
	_ = dm.db.ExpireOldDeviceRequests(ctx)

	req, err := dm.db.GetDeviceRequestByID(ctx, requestID)
	if err != nil || req == nil {
		return nil, ErrDeviceRequestNotFound
	}

	status := req.Status
	if (status == "pending" || status == "approved") && time.Now().After(req.ExpiresAt) {
		status = "expired"
		dm.mu.Lock()
		delete(dm.regSessions, requestID)
		dm.mu.Unlock()
	}

	resp := &DeviceStatusResponse{
		Status: status,
	}

	if status == "approved" {
		resp.ApproverECDHPub = base64.RawURLEncoding.EncodeToString(req.ApproverECDHPub)
		resp.EncryptedMEKTransfer = base64.RawURLEncoding.EncodeToString(req.EncryptedMEKTransfer)
		resp.TransferIV = base64.RawURLEncoding.EncodeToString(req.TransferIV)

		dm.mu.RLock()
		regSession, ok := dm.regSessions[requestID]
		dm.mu.RUnlock()

		if ok && regSession != nil {
			resp.PRFSalt = base64.RawURLEncoding.EncodeToString(regSession.prfSalt)
			resp.RegOptions = regSession.creationOptions
		}
	}

	return resp, nil
}

// CompleteRequest completes registration of the new device and optional revocation of old device
func (dm *DeviceManager) CompleteRequest(
	ctx context.Context,
	requestID string,
	attestationBytes []byte,
	wrappedMEK []byte,
	wrappedMEKIV []byte,
	ipAddr string,
) (*SessionInfo, error) {
	if len(wrappedMEK) == 0 || len(wrappedMEKIV) != 12 {
		return nil, ErrInvalidRequest
	}

	req, err := dm.db.GetDeviceRequestByID(ctx, requestID)
	if err != nil || req == nil {
		return nil, ErrDeviceRequestNotFound
	}
	if req.Status != "approved" {
		return nil, ErrInvalidRequestStatus
	}
	if time.Now().After(req.ExpiresAt) {
		return nil, ErrDeviceRequestExpired
	}

	dm.mu.Lock()
	regSession, ok := dm.regSessions[requestID]
	if ok {
		delete(dm.regSessions, requestID)
	}
	dm.mu.Unlock()

	if !ok || regSession == nil {
		return nil, errors.New("registration session not found or already completed")
	}

	dbUser, err := dm.db.GetUserByID(ctx, req.UserID)
	if err != nil || dbUser == nil {
		return nil, ErrUserNotFound
	}
	waUser, err := dm.authSvc.buildWebAuthnUser(ctx, dbUser)
	if err != nil {
		return nil, err
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(io.NopCloser(bytesReader(attestationBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation: %w", err)
	}

	cred, err := dm.authSvc.CreateCredential(ctx, waUser, *regSession.sessionData, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to verify new device credential: %w", err)
	}

	for _, existing := range waUser.WebAuthnCredentials() {
		if bytes.Equal(existing.ID, cred.ID) {
			return nil, errors.New("this credential is already registered as a verified device")
		}
	}

	transportsJSON, _ := json.Marshal(cred.Transport)
	dbCred := &db.Credential{
		ID:              cred.ID,
		UserID:          req.UserID,
		DeviceName:      req.NewDeviceName,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		Transports:      string(transportsJSON),
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
		PRFSalt:         regSession.prfSalt,
		WrappedMEK:      wrappedMEK,
		WrappedMEKIV:    wrappedMEKIV,
		Status:          "verified",
	}

	// If change_phone, atomically revoke old device in a single transaction
	var revokeCredID []byte
	if req.ActionType == "change_phone" {
		revokeCredID = req.ReplaceCredentialID
		if len(revokeCredID) == 0 {
			revokeCredID = req.ApprovedByCredentialID
		}
	}

	auditMsg := fmt.Sprintf("completed enrollment of device %s (action: %s)", req.NewDeviceName, req.ActionType)
	if err := dm.db.CompleteDeviceEnrollmentTx(ctx, dbCred, requestID, revokeCredID, &req.UserID, ipAddr, auditMsg); err != nil {
		return nil, fmt.Errorf("failed to atomically complete enrollment: %w", err)
	}

	if len(revokeCredID) > 0 && dm.sessions != nil {
		dm.sessions.InvalidateSessionsByCredentialID(revokeCredID)
	}

	// Issue session for the new device
	return dm.sessions.CreateSession(req.UserID, cred.ID)
}

// RevokeDevice revokes a verified credential, ensuring at least one remains
func (dm *DeviceManager) RevokeDevice(ctx context.Context, userID string, credID []byte, stepUpID string, assertionBytes []byte) error {
	creds, err := dm.db.GetCredentialsByUserID(ctx, userID)
	if err != nil {
		return err
	}

	verifiedCount := 0
	var targetExists bool
	for _, c := range creds {
		if c.Status == "verified" {
			verifiedCount++
			if bytes.Equal(c.ID, credID) {
				targetExists = true
			}
		}
	}

	if !targetExists {
		return errors.New("target credential not found or already revoked")
	}
	if verifiedCount <= 1 {
		return ErrCannotRevokeLastDevice
	}

	// Step-up verification and ownership check
	verifiedCred, err := dm.authSvc.VerifyStepUp(ctx, stepUpID, assertionBytes)
	if err != nil {
		return fmt.Errorf("revocation assertion failed: %w", err)
	}
	if verifiedCred.UserID != userID {
		return fmt.Errorf("revocation assertion failed: %w", ErrInvalidCredential)
	}

	if err := dm.db.RevokeCredential(ctx, credID, userID); err != nil {
		return fmt.Errorf("failed to revoke credential: %w", err)
	}

	if dm.sessions != nil {
		dm.sessions.InvalidateSessionsByCredentialID(credID)
	}

	logCredHex := fmt.Sprintf("%x", credID)
	if len(credID) >= 8 {
		logCredHex = fmt.Sprintf("%x", credID[:8])
	}
	_ = dm.db.InsertAuditLog(ctx, &userID, "device_revoked", "", fmt.Sprintf("revoked credential %s", logCredHex))
	return nil
}
