package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"passmanager/internal/auth"
)

type contextKey string

const (
	SessionContextKey contextKey = "session"
)

func RequireAuth(sm *auth.SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(auth.SessionCookieName)
			if err != nil || cookie.Value == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":   "unauthorized",
					"message": "Valid authentication session cookie required",
				})
				return
			}

			sess, err := sm.GetSession(cookie.Value)
			if err != nil || sess == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":   "session_expired",
					"message": "Session has expired. Please authenticate with your Passkey.",
				})
				return
			}

			// CSRF protection on all state-mutating methods
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
				csrfHeader := r.Header.Get("X-CSRF-Token")
				if csrfHeader == "" || subtle.ConstantTimeCompare([]byte(csrfHeader), []byte(sess.CSRFToken)) != 1 {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error":   "invalid_csrf_token",
						"message": "CSRF validation failed",
					})
					return
				}
			}

			ctx := context.WithValue(r.Context(), SessionContextKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetSession(ctx context.Context) *auth.SessionInfo {
	val := ctx.Value(SessionContextKey)
	if s, ok := val.(*auth.SessionInfo); ok {
		return s
	}
	return nil
}
