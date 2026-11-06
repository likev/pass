package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"
)

var (
	ErrSessionNotFound = errors.New("session not found or expired")
	ErrInvalidCSRF     = errors.New("invalid or missing CSRF token")
)

const (
	SessionCookieName = "km_session"
	SessionDuration   = 24 * time.Hour
)

type SessionInfo struct {
	ID           string
	UserID       string
	CredentialID []byte
	CSRFToken    string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*SessionInfo
}

func NewSessionManager() *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*SessionInfo),
	}
	// Background cleanup of expired sessions
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		for range ticker.C {
			sm.cleanExpired()
		}
	}()
	return sm
}

func (sm *SessionManager) cleanExpired() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	now := time.Now()
	for id, s := range sm.sessions {
		if now.After(s.ExpiresAt) {
			delete(sm.sessions, id)
		}
	}
}

func generateRandomToken(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func copySessionInfo(s *SessionInfo) *SessionInfo {
	if s == nil {
		return nil
	}
	credCopy := make([]byte, len(s.CredentialID))
	copy(credCopy, s.CredentialID)
	return &SessionInfo{
		ID:           s.ID,
		UserID:       s.UserID,
		CredentialID: credCopy,
		CSRFToken:    s.CSRFToken,
		CreatedAt:    s.CreatedAt,
		ExpiresAt:    s.ExpiresAt,
	}
}

func (sm *SessionManager) CreateSession(userID string, credentialID []byte) (*SessionInfo, error) {
	sessionID, err := generateRandomToken(32)
	if err != nil {
		return nil, err
	}
	csrfToken, err := generateRandomToken(32)
	if err != nil {
		return nil, err
	}

	credCopy := make([]byte, len(credentialID))
	copy(credCopy, credentialID)

	info := &SessionInfo{
		ID:           sessionID,
		UserID:       userID,
		CredentialID: credCopy,
		CSRFToken:    csrfToken,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(SessionDuration),
	}

	sm.mu.Lock()
	sm.sessions[sessionID] = info
	sm.mu.Unlock()

	return copySessionInfo(info), nil
}

func (sm *SessionManager) GetSession(sessionID string) (*SessionInfo, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	s, ok := sm.sessions[sessionID]
	if !ok || time.Now().After(s.ExpiresAt) {
		return nil, ErrSessionNotFound
	}
	return copySessionInfo(s), nil
}

func (sm *SessionManager) InvalidateSession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessionID)
}

func (sm *SessionManager) InvalidateSessionsByCredentialID(credID []byte) {
	if len(credID) == 0 {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for id, s := range sm.sessions {
		if bytes.Equal(s.CredentialID, credID) {
			delete(sm.sessions, id)
		}
	}
}

func (sm *SessionManager) InvalidateSessionsByUserID(userID string) {
	if userID == "" {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for id, s := range sm.sessions {
		if s.UserID == userID {
			delete(sm.sessions, id)
		}
	}
}

func (sm *SessionManager) SetCookie(w http.ResponseWriter, sessionID string, secure bool) {
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(SessionDuration),
		MaxAge:   int(SessionDuration.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

func (sm *SessionManager) ClearCookie(w http.ResponseWriter, secure bool) {
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}
