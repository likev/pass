package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"passmanager/internal/auth"
)

// IsSecureRequest returns true if the connection is directly TLS or behind an HTTPS reverse proxy.
// It checks direct TLS, X-Forwarded-Proto, X-Forwarded-Scheme, X-Scheme, X-Forwarded-Ssl, Front-End-Https, and Cloudflare's Cf-Visitor header.
func IsSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		parts := strings.Split(proto, ",")
		if strings.EqualFold(strings.TrimSpace(parts[0]), "https") {
			return true
		}
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Scheme"), "https") ||
		strings.EqualFold(r.Header.Get("X-Scheme"), "https") ||
		strings.EqualFold(r.Header.Get("X-Forwarded-Ssl"), "on") ||
		strings.EqualFold(r.Header.Get("Front-End-Https"), "on") {
		return true
	}
	if cfVisitor := r.Header.Get("Cf-Visitor"); cfVisitor != "" {
		if strings.Contains(strings.ToLower(cfVisitor), `"scheme":"https"`) {
			return true
		}
	}
	return false
}

// GetRequestScheme returns "https" if secure, otherwise "http".
func GetRequestScheme(r *http.Request) string {
	if IsSecureRequest(r) {
		return "https"
	}
	return "http"
}

// NormalizeHost strips default ports (443 for https, 80 for http).
func NormalizeHost(host, scheme string) string {
	host = strings.TrimSpace(host)
	if scheme == "https" && strings.HasSuffix(host, ":443") {
		return strings.TrimSuffix(host, ":443")
	}
	if scheme == "http" && strings.HasSuffix(host, ":80") {
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

// GetRequestHost extracts the external host from X-Forwarded-Host or Host header.
// It also takes X-Forwarded-Port into account when host does not specify a port.
func GetRequestHost(r *http.Request) string {
	scheme := GetRequestScheme(r)
	host := ""
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		parts := strings.Split(xfh, ",")
		host = strings.TrimSpace(parts[0])
	}
	if host == "" && r.Host != "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		host = "localhost"
	}

	// If host does not specify a port, check X-Forwarded-Port
	if _, _, err := net.SplitHostPort(host); err != nil {
		if xfp := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); xfp != "" {
			if (scheme == "https" && xfp != "443") || (scheme == "http" && xfp != "80") {
				host = host + ":" + xfp
			}
		}
	}

	return NormalizeHost(host, scheme)
}

// GetRequestOrigin returns scheme://host respecting reverse proxy headers.
func GetRequestOrigin(r *http.Request) string {
	scheme := GetRequestScheme(r)
	host := GetRequestHost(r)
	return fmt.Sprintf("%s://%s", scheme, host)
}

// GetRequestRPID derives the WebAuthn Relying Party ID (effective domain).
// If defaultRPID is explicitly configured (and not "localhost"), that value takes precedence.
func GetRequestRPID(r *http.Request, defaultRPID string) string {
	if defaultRPID != "" && defaultRPID != "localhost" {
		return defaultRPID
	}
	host := GetRequestHost(r)
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	host = strings.TrimSuffix(host, ".")
	if host == "" || net.ParseIP(host) != nil {
		return "localhost"
	}
	return host
}

// ProxyHeaders middleware inspects reverse proxy headers (X-Forwarded-Proto, X-Forwarded-Host, Host)
// and injects the effective WebAuthn Origin and RPID into request context.
func ProxyHeaders(defaultRPID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := GetRequestOrigin(r)
			rpID := GetRequestRPID(r, defaultRPID)
			ctx := auth.WithWebAuthnContext(r.Context(), origin, rpID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
