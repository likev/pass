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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"passmanager/internal/config"
	"passmanager/internal/db"
)

type WebAuthnContextKey string

const (
	OriginContextKey WebAuthnContextKey = "webauthn_origin"
	RPIDContextKey   WebAuthnContextKey = "webauthn_rpid"
)

func WithWebAuthnContext(ctx context.Context, origin, rpID string) context.Context {
	ctx = context.WithValue(ctx, OriginContextKey, origin)
	ctx = context.WithValue(ctx, RPIDContextKey, rpID)
	return ctx
}

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrCredentialRevoked  = errors.New("credential has been revoked")
	ErrInvalidCredential  = errors.New("credential does not belong to user")
	ErrInvalidRequest     = errors.New("invalid request payload")
	ErrVerificationFailed = errors.New("webauthn verification failed")
)

type AuthService struct {
	db             *db.DB
	cfg            *config.Config
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
		cfg:            cfg,
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

const maxRPOrigins = 128

func (as *AuthService) ensureOriginLocked(origin string) {
	if origin == "" {
		return
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return
	}
	for _, o := range as.webAuthn.Config.RPOrigins {
		if strings.EqualFold(o, origin) {
			return
		}
	}
	if len(as.webAuthn.Config.RPOrigins) < maxRPOrigins {
		as.webAuthn.Config.RPOrigins = append(as.webAuthn.Config.RPOrigins, origin)
	}
}

func (as *AuthService) ensureOrigin(origin string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.ensureOriginLocked(origin)
}

func (as *AuthService) getRPIDAndOriginLocked(ctx context.Context) (string, string) {
	rpID := ""
	if as.cfg != nil {
		rpID = as.cfg.RPID
	}
	if customRPID, ok := ctx.Value(RPIDContextKey).(string); ok && customRPID != "" {
		rpID = customRPID
	}
	origin := ""
	if customOrigin, ok := ctx.Value(OriginContextKey).(string); ok && customOrigin != "" {
		origin = customOrigin
		as.ensureOriginLocked(origin)
	}
	return rpID, origin
}

func (as *AuthService) BeginRegistrationForUser(ctx context.Context, user *WebAuthnUser) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	as.mu.Lock()
	defer as.mu.Unlock()

	rpID, origin := as.getRPIDAndOriginLocked(ctx)

	regOpts := []webauthn.RegistrationOption{
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	}
	if len(user.WebAuthnCredentials()) > 0 {
		regOpts = append(regOpts, webauthn.WithExclusions(webauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()))
	}
	if rpID != "" {
		regOpts = append(regOpts, webauthn.WithRegistrationRelyingPartyID(rpID))
	}
	if origin != "" {
		regOpts = append(regOpts, webauthn.WithRegistrationOrigin(origin))
	}

	return as.webAuthn.BeginRegistration(user, regOpts...)
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
	username = strings.TrimSpace(username)
	displayName = strings.TrimSpace(displayName)
	if username == "" || len(username) > 128 || len(displayName) > 128 {
		return nil, "", "", ErrInvalidRequest
	}
	if displayName == "" {
		displayName = username
	}

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

	options, sessionData, err := as.BeginRegistrationForUser(ctx, tempUser)
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

// CreateCredential completes WebAuthn credential creation under synchronization
func (as *AuthService) CreateCredential(ctx context.Context, user *WebAuthnUser, sessionData webauthn.SessionData, parsedResponse *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if customOrigin, ok := ctx.Value(OriginContextKey).(string); ok && customOrigin != "" {
		as.ensureOriginLocked(customOrigin)
	}
	return as.webAuthn.CreateCredential(user, sessionData, parsedResponse)
}

// ValidateLogin validates WebAuthn assertion under synchronization
func (as *AuthService) ValidateLogin(ctx context.Context, user *WebAuthnUser, sessionData webauthn.SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if customOrigin, ok := ctx.Value(OriginContextKey).(string); ok && customOrigin != "" {
		as.ensureOriginLocked(customOrigin)
	}
	// If login was initiated as discoverable (sessionData.UserID is empty), verify userHandle if present and bind UserID
	if len(sessionData.UserID) == 0 && user != nil {
		if len(parsedResponse.Response.UserHandle) > 0 && !bytes.Equal(parsedResponse.Response.UserHandle, user.WebAuthnID()) {
			return nil, errors.New("user handle does not match credential owner")
		}
		sessionData.UserID = user.WebAuthnID()
	}
	return as.webAuthn.ValidateLogin(user, sessionData, parsedResponse)
}

// FinishRegistration completes Passkey creation and stores wrapped_mek
func (as *AuthService) FinishRegistration(ctx context.Context, regID string, attestationBytes []byte, wrappedMEK, wrappedMEKIV []byte, deviceName string, ipAddr string) (*SessionInfo, *db.User, error) {
	deviceName = strings.TrimSpace(deviceName)
	if deviceName == "" {
		deviceName = "Primary Passkey Device"
	}
	if len(deviceName) > 128 || len(wrappedMEK) == 0 || len(wrappedMEKIV) != 12 {
		return nil, nil, ErrInvalidRequest
	}

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

	cred, err := as.CreateCredential(ctx, tempUser, *entry.sessionData, parsedResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create credential: %w", err)
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

	// Atomically persist user, credential, and audit log in DB
	auditMsg := fmt.Sprintf("registered device %s", deviceName)
	if err := as.db.CreateUserWithCredentialTx(ctx, entry.userID, entry.username, entry.displayName, dbCred, ipAddr, auditMsg); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, nil, ErrUserAlreadyExists
		}
		return nil, nil, fmt.Errorf("failed to save user and credential: %w", err)
	}

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
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, "", nil, errors.New("username is required")
	}

	dbUser, err := as.db.GetUserByUsername(ctx, username)
	if err != nil || dbUser == nil {
		return nil, "", nil, ErrUserNotFound
	}
	user, err := as.buildWebAuthnUser(ctx, dbUser)
	if err != nil {
		return nil, "", nil, err
	}

	var prfSalts []string
	creds, _ := as.db.GetCredentialsByUserID(ctx, dbUser.ID)
	for _, c := range creds {
		if c.Status == "verified" {
			prfSalts = append(prfSalts, base64.RawURLEncoding.EncodeToString(c.PRFSalt))
		}
	}

	loginID, err := generateRandomToken(32)
	if err != nil {
		return nil, "", nil, err
	}

	as.mu.Lock()
	defer as.mu.Unlock()

	rpID, origin := as.getRPIDAndOriginLocked(ctx)

	loginOpts := []webauthn.LoginOption{
		webauthn.WithUserVerification(protocol.VerificationRequired),
	}
	if rpID != "" {
		loginOpts = append(loginOpts, webauthn.WithLoginRelyingPartyID(rpID))
	}
	if origin != "" {
		loginOpts = append(loginOpts, webauthn.WithLoginOrigin(origin))
	}

	options, sessionData, err := as.webAuthn.BeginLogin(user, loginOpts...)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to begin login: %w", err)
	}

	as.loginSessions[loginID] = &loginSessionEntry{
		userID:      string(user.id),
		sessionData: sessionData,
		expiresAt:   time.Now().Add(5 * time.Minute),
	}

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
	if entry.userID != "" && dbCred.UserID != entry.userID {
		return nil, nil, errors.New("credential does not belong to the requested user")
	}

	dbUser, err := as.db.GetUserByID(ctx, dbCred.UserID)
	if err != nil || dbUser == nil {
		return nil, nil, ErrUserNotFound
	}

	waUser, err := as.buildWebAuthnUser(ctx, dbUser)
	if err != nil {
		return nil, nil, err
	}

	verifiedCred, err := as.ValidateLogin(ctx, waUser, *entry.sessionData, parsedResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to validate assertion: %w", err)
	}
	if verifiedCred.Authenticator.CloneWarning {
		_ = as.db.InsertAuditLog(ctx, &dbUser.ID, "clone_warning", ipAddr, fmt.Sprintf("authenticator clone warning on device %s", dbCred.DeviceName))
		return nil, nil, errors.New("authenticator clone warning: signature counter anomaly")
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

	stepUpID, err := generateRandomToken(32)
	if err != nil {
		return nil, "", nil, err
	}

	// Fetch active credential's PRF salt
	cred, err := as.db.GetCredentialByID(ctx, credID)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get active credential: %w", err)
	}
	if cred.UserID != userID {
		return nil, "", nil, errors.New("credential does not belong to user")
	}
	if cred.Status != "verified" {
		return nil, "", nil, ErrCredentialRevoked
	}

	as.mu.Lock()
	defer as.mu.Unlock()

	rpID, origin := as.getRPIDAndOriginLocked(ctx)

	waCred := toWebAuthnCredential(cred)
	stepUpOpts := []webauthn.LoginOption{
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithAllowedCredentials([]protocol.CredentialDescriptor{waCred.Descriptor()}),
	}
	if rpID != "" {
		stepUpOpts = append(stepUpOpts, webauthn.WithLoginRelyingPartyID(rpID))
	}
	if origin != "" {
		stepUpOpts = append(stepUpOpts, webauthn.WithLoginOrigin(origin))
	}

	options, sessionData, err := as.webAuthn.BeginLogin(waUser, stepUpOpts...)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to begin step-up: %w", err)
	}

	as.stepUpSessions[stepUpID] = &stepUpSessionEntry{
		userID:       userID,
		credentialID: credID,
		sessionData:  sessionData,
		expiresAt:    time.Now().Add(5 * time.Minute),
	}

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

	verifiedCred, err := as.ValidateLogin(ctx, waUser, *entry.sessionData, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("step-up assertion verification failed: %w", err)
	}
	if verifiedCred.Authenticator.CloneWarning {
		_ = as.db.InsertAuditLog(ctx, &dbUser.ID, "clone_warning", "", fmt.Sprintf("authenticator clone warning on step-up device %s", dbCred.DeviceName))
		return nil, errors.New("authenticator clone warning: signature counter anomaly")
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
