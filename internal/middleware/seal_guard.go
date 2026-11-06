package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"passmanager/internal/crypto"
)

func SealGuard(sm *crypto.SealManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// Allow unseal status, unseal action, and static assets regardless of seal status
			if strings.HasPrefix(path, "/api/v1/admin/seal-status") ||
				strings.HasPrefix(path, "/api/v1/admin/unseal") ||
				!strings.HasPrefix(path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}

			if !sm.IsUnsealed() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":       "server_sealed",
					"message":     "Server Master Key is sealed. Admin startup passphrase required.",
					"initialized": sm.IsInitialized(),
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
