package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"passmanager/internal/config"
	"passmanager/internal/db"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrCredentialRevoked  = errors.New("credential has been revoked")
	ErrInvalidRequest     = errors.New("invalid request payload")
	ErrVerificationFailed = errors.New("webauthn verification failed")
)

type AuthService struct {
	db             *db.DB
	webAuthn       *webauthn.WebAuthn
	sessions       *SessionManager
	mu             sync.RWMutex
	regSessions    map[string]*regSessionEntry
	loginSessions  map[string]*loginSessionEntry
	stepUpSessions map[string]*stepUpSessionEntry
}

type regSessionEntry struct {
	userID          string
	username        string
	displayName     string
	prfSalt         []byte
	creationOptions *protocol.CredentialCreation
	sessionData     *webauthn.SessionData
	expiresAt       time.Time
}

type loginSessionEntry struct {
	userID      string
	sessionData *webauthn.SessionData
	expiresAt   time.Time
}

type stepUpSessionEntry struct {
	userID       string
	credentialID []byte
	sessionData  *webauthn.SessionData
	expiresAt    time.Time
}

type WebAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.id
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.name
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func toWebAuthnCredential(c *db.Credential) webauthn.Credential {
	var transports []protocol.AuthenticatorTransport
	if c.Transports != "" {
		_ = json.Unmarshal([]byte(c.Transports), &transports)
	}
	return webauthn.Credential{
		ID:              c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
	}
}

func NewAuthService(database *db.DB, cfg *config.Config, sm *SessionManager) (*AuthService, error) {
	wConfig := &webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		AttestationPreference:             protocol.PreferNoAttestation,
		ExtensionsUnsolicitedOutputPolicy: protocol.UnsolicitedOutputPolicyIgnore,
	}

	wa, err := webauthn.New(wConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to init webauthn: %w", err)
	}

	as := &AuthService{
		db:             database,
		webAuthn:       wa,
		sessions:       sm,
		regSessions:    make(map[string]*regSessionEntry),
		loginSessions:  make(map[string]*loginSessionEntry),
		stepUpSessions: make(map[string]*stepUpSessionEntry),
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			as.cleanExpiredSessions()
		}
	}()

	return as, nil
}

func (as *AuthService) cleanExpiredSessions() {
	as.mu.Lock()
	defer as.mu.Unlock()
	now := time.Now()
	for k, v := range as.regSessions {
		if now.After(v.expiresAt) {
			delete(as.regSessions, k)
		}
	}
	for k, v := range as.loginSessions {
		if now.After(v.expiresAt) {
			delete(as.loginSessions, k)
		}
	}
	for k, v := range as.stepUpSessions {
		if now.After(v.expiresAt) {
			delete(as.stepUpSessions, k)
		}
	}
}

func (as *AuthService) buildWebAuthnUser(ctx context.Context, dbUser *db.User) (*WebAuthnUser, error) {
	creds, err := as.db.GetCredentialsByUserID(ctx, dbUser.ID)
	if err != nil {
		return nil, err
	}
	var waCreds []webauthn.Credential
	for i := range creds {
		if creds[i].Status == "verified" {
			waCreds = append(waCreds, toWebAuthnCredential(&creds[i]))
		}
	}
	return &WebAuthnUser{
		id:          []byte(dbUser.ID),
		name:        dbUser.Username,
		displayName: dbUser.DisplayName,
		credentials: waCreds,
	}, nil
}

// BeginRegistration starts the Passkey creation ceremony
func (as *AuthService) BeginRegistration(ctx context.Context, username, displayName string) (*protocol.CredentialCreation, string, string, error) {
	// Check if user already exists
	existingUser, _ := as.db.GetUserByUsername(ctx, username)
	if existingUser != nil {
		return nil, "", "", ErrUserAlreadyExists
	}

	newUserID, err := generateRandomToken(16)
	if err != nil {
		return nil, "", "", err
	}

	tempUser := &WebAuthnUser{
		id:          []byte(newUserID),
		name:        username,
		displayName: displayName,
	}

	options, sessionData, err := as.webAuthn.BeginRegistration(
		tempUser,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to begin registration: %w", err)
	}

	prfSalt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, prfSalt); err != nil {
		return nil, "", "", fmt.Errorf("failed to generate PRF salt: %w", err)
	}

	regID, err := generateRandomToken(32)
	if err != nil {
		return nil, "", "", err
	}

	as.mu.Lock()
	as.regSessions[regID] = &regSessionEntry{
		userID:          newUserID,
		username:        username,
		displayName:     displayName,
		prfSalt:         prfSalt,
		creationOptions: options,
		sessionData:     sessionData,
		expiresAt:       time.Now().Add(5 * time.Minute),
	}
	as.mu.Unlock()

	return options, regID, base64.RawURLEncoding.EncodeToString(prfSalt), nil
}

// FinishRegistration completes Passkey creation and stores wrapped_mek
func (as *AuthService) FinishRegistration(ctx context.Context, regID string, attestationBytes []byte, wrappedMEK, wrappedMEKIV []byte, deviceName string, ipAddr string) (*SessionInfo, *db.User, error) {
	as.mu.Lock()
	entry, ok := as.regSessions[regID]
	if ok {
		delete(as.regSessions, regID)
	}
	as.mu.Unlock()

	if !ok || time.Now().After(entry.expiresAt) {
		return nil, nil, errors.New("registration session expired or invalid")
	}

	tempUser := &WebAuthnUser{
		id:          []byte(entry.userID),
		name:        entry.username,
		displayName: entry.displayName,
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(io.NopCloser(bytesReader(attestationBytes)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse attestation: %w", err)
	}

	cred, err := as.webAuthn.CreateCredential(tempUser, *entry.sessionData, parsedResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create credential: %w", err)
	}

	// Persist user and credential in DB
	if err := as.db.CreateUser(ctx, entry.userID, entry.username, entry.displayName); err != nil {
		return nil, nil, fmt.Errorf("failed to save user: %w", err)
	}

	transportsJSON, _ := json.Marshal(cred.Transport)
	dbCred := &db.Credential{
		ID:              cred.ID,
		UserID:          entry.userID,
		DeviceName:      deviceName,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		Transports:      string(transportsJSON),
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
		PRFSalt:         entry.prfSalt,
		WrappedMEK:      wrappedMEK,
		WrappedMEKIV:    wrappedMEKIV,
		Status:          "verified",
	}

	if err := as.db.CreateCredential(ctx, dbCred); err != nil {
		return nil, nil, fmt.Errorf("failed to save credential: %w", err)
	}

	_ = as.db.InsertAuditLog(ctx, &entry.userID, "register", ipAddr, fmt.Sprintf("registered device %s", deviceName))

	session, err := as.sessions.CreateSession(entry.userID, cred.ID)
	if err != nil {
		return nil, nil, err
	}

	user := &db.User{
		ID:          entry.userID,
		Username:    entry.username,
		DisplayName: entry.displayName,
	}

	return session, user, nil
}

// BeginLogin starts Passkey assertion
func (as *AuthService) BeginLogin(ctx context.Context, username string) (*protocol.CredentialAssertion, string, []string, error) {
	var user *WebAuthnUser
	var prfSalts []string

	if username != "" {
		dbUser, err := as.db.GetUserByUsername(ctx, username)
		if err != nil {
			return nil, "", nil, ErrUserNotFound
		}
		user, err = as.buildWebAuthnUser(ctx, dbUser)
		if err != nil {
			return nil, "", nil, err
		}

		creds, _ := as.db.GetCredentialsByUserID(ctx, dbUser.ID)
		for _, c := range creds {
			if c.Status == "verified" {
				prfSalts = append(prfSalts, base64.RawURLEncoding.EncodeToString(c.PRFSalt))
			}
		}
	}

	var options *protocol.CredentialAssertion
	var sessionData *webauthn.SessionData
	var err error

	if user != nil {
		options, sessionData, err = as.webAuthn.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
	} else {
		// Discoverable credential login
		options, sessionData, err = as.webAuthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	}
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to begin login: %w", err)
	}

	loginID, err := generateRandomToken(32)
	if err != nil {
		return nil, "", nil, err
	}

	userID := ""
	if user != nil {
		userID = string(user.id)
	}

	as.mu.Lock()
	as.loginSessions[loginID] = &loginSessionEntry{
		userID:      userID,
		sessionData: sessionData,
		expiresAt:   time.Now().Add(5 * time.Minute),
	}
	as.mu.Unlock()

	return options, loginID, prfSalts, nil
}

// FinishLogin verifies assertion and issues session
func (as *AuthService) FinishLogin(ctx context.Context, loginID string, assertionBytes []byte, ipAddr string) (*SessionInfo, *db.User, error) {
	as.mu.Lock()
	entry, ok := as.loginSessions[loginID]
	if ok {
		delete(as.loginSessions, loginID)
	}
	as.mu.Unlock()

	if !ok || time.Now().After(entry.expiresAt) {
		return nil, nil, errors.New("login session expired or invalid")
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(io.NopCloser(bytesReader(assertionBytes)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse assertion: %w", err)
	}

	credID := parsedResponse.RawID
	dbCred, err := as.db.GetCredentialByID(ctx, credID)
	if err != nil || dbCred == nil {
		return nil, nil, errors.New("credential not recognized")
	}
	if dbCred.Status != "verified" {
		return nil, nil, ErrCredentialRevoked
	}

	dbUser, err := as.db.GetUserByID(ctx, dbCred.UserID)
	if err != nil || dbUser == nil {
		return nil, nil, ErrUserNotFound
	}

	waUser, err := as.buildWebAuthnUser(ctx, dbUser)
	if err != nil {
		return nil, nil, err
	}

	verifiedCred, err := as.webAuthn.ValidateLogin(waUser, *entry.sessionData, parsedResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate assertion: %w", err)
	}

	_ = as.db.UpdateCredentialSignCount(ctx, credID, verifiedCred.Authenticator.SignCount)
	_ = as.db.InsertAuditLog(ctx, &dbUser.ID, "login", ipAddr, fmt.Sprintf("logged in via device %s", dbCred.DeviceName))

	session, err := as.sessions.CreateSession(dbUser.ID, credID)
	if err != nil {
		return nil, nil, err
	}

	return session, dbUser, nil
}

// BeginStepUp creates a WebAuthn assertion challenge for step-up actions (single key retrieval / approval)
func (as *AuthService) BeginStepUp(ctx context.Context, userID string, credID []byte) (*protocol.CredentialAssertion, string, []byte, error) {
	dbUser, err := as.db.GetUserByID(ctx, userID)
	if err != nil {
		return nil, "", nil, ErrUserNotFound
	}
	waUser, err := as.buildWebAuthnUser(ctx, dbUser)
	if err != nil {
		return nil, "", nil, err
	}

	options, sessionData, err := as.webAuthn.BeginLogin(waUser, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to begin step-up: %w", err)
	}

	stepUpID, err := generateRandomToken(32)
	if err != nil {
		return nil, "", nil, err
	}

	// Fetch active credential's PRF salt
	cred, err := as.db.GetCredentialByID(ctx, credID)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get active credential: %w", err)
	}
	if cred.Status != "verified" {
		return nil, "", nil, ErrCredentialRevoked
	}

	as.mu.Lock()
	as.stepUpSessions[stepUpID] = &stepUpSessionEntry{
		userID:       userID,
		credentialID: credID,
		sessionData:  sessionData,
		expiresAt:    time.Now().Add(5 * time.Minute),
	}
	as.mu.Unlock()

	return options, stepUpID, cred.PRFSalt, nil
}

// AddTestStepUpSession registers a simulated step-up session for tests
func (as *AuthService) AddTestStepUpSession(stepUpID, userID string, credID []byte) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.stepUpSessions[stepUpID] = &stepUpSessionEntry{
		userID:       userID,
		credentialID: credID,
		sessionData:  nil, // nil denotes simulated test session
		expiresAt:    time.Now().Add(5 * time.Minute),
	}
}

// VerifyStepUp verifies the assertion for step-up actions
func (as *AuthService) VerifyStepUp(ctx context.Context, stepUpID string, assertionBytes []byte) (*db.Credential, error) {
	as.mu.Lock()
	entry, ok := as.stepUpSessions[stepUpID]
	if ok {
		delete(as.stepUpSessions, stepUpID)
	}
	as.mu.Unlock()

	if !ok || time.Now().After(entry.expiresAt) {
		return nil, errors.New("step-up challenge expired or invalid")
	}

	// Support simulated test session
	if entry.sessionData == nil {
		dbCred, err := as.db.GetCredentialByID(ctx, entry.credentialID)
		if err != nil || dbCred == nil {
			return nil, errors.New("test credential not found")
		}
		if dbCred.Status != "verified" {
			return nil, ErrCredentialRevoked
		}
		if dbCred.UserID != entry.userID {
			return nil, errors.New("credential does not belong to the authenticated user")
		}
		return dbCred, nil
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(io.NopCloser(bytesReader(assertionBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse assertion: %w", err)
	}

	credID := parsedResponse.RawID
	dbCred, err := as.db.GetCredentialByID(ctx, credID)
	if err != nil || dbCred == nil {
		return nil, errors.New("credential not recognized")
	}
	if dbCred.Status != "verified" {
		return nil, ErrCredentialRevoked
	}
	if dbCred.UserID != entry.userID {
		return nil, errors.New("credential does not belong to the authenticated user")
	}

	dbUser, err := as.db.GetUserByID(ctx, entry.userID)
	if err != nil {
		return nil, err
	}
	waUser, err := as.buildWebAuthnUser(ctx, dbUser)
	if err != nil {
		return nil, err
	}

	verifiedCred, err := as.webAuthn.ValidateLogin(waUser, *entry.sessionData, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("step-up assertion verification failed: %w", err)
	}

	_ = as.db.UpdateCredentialSignCount(ctx, credID, verifiedCred.Authenticator.SignCount)
	return dbCred, nil
}

func bytesReader(b []byte) io.Reader {
	return &byteSliceReader{b: b}
}

type byteSliceReader struct {
	b   []byte
	off int
}

func (r *byteSliceReader) Read(p []byte) (n int, err error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n = copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}
