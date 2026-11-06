package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"passmanager/internal/auth"
)

func TestIsSecureRequest(t *testing.T) {
	tests := []struct {
		name     string
		modify   func(*http.Request)
		expected bool
	}{
		{
			name:     "plain HTTP",
			modify:   func(r *http.Request) {},
			expected: false,
		},
		{
			name: "direct TLS",
			modify: func(r *http.Request) {
				r.TLS = &tls.ConnectionState{}
			},
			expected: true,
		},
		{
			name: "X-Forwarded-Proto https",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
			},
			expected: true,
		},
		{
			name: "X-Forwarded-Proto HTTPS uppercase",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "HTTPS")
			},
			expected: true,
		},
		{
			name: "X-Forwarded-Proto multi-hop https first",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https, http")
			},
			expected: true,
		},
		{
			name: "X-Forwarded-Proto http",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "http")
			},
			expected: false,
		},
		{
			name: "X-Forwarded-Ssl on",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Ssl", "on")
			},
			expected: true,
		},
		{
			name: "Front-End-Https on",
			modify: func(r *http.Request) {
				r.Header.Set("Front-End-Https", "on")
			},
			expected: true,
		},
		{
			name: "X-Forwarded-Scheme https",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Scheme", "https")
			},
			expected: true,
		},
		{
			name: "X-Scheme https",
			modify: func(r *http.Request) {
				r.Header.Set("X-Scheme", "https")
			},
			expected: true,
		},
		{
			name: "Cloudflare Cf-Visitor https",
			modify: func(r *http.Request) {
				r.Header.Set("Cf-Visitor", `{"scheme":"https"}`)
			},
			expected: true,
		},
		{
			name: "Cloudflare Cf-Visitor http",
			modify: func(r *http.Request) {
				r.Header.Set("Cf-Visitor", `{"scheme":"http"}`)
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost:8082/", nil)
			tc.modify(req)
			actual := IsSecureRequest(req)
			if actual != tc.expected {
				t.Fatalf("expected IsSecureRequest=%v, got %v", tc.expected, actual)
			}
		})
	}
}

func TestGetRequestHostAndOrigin(t *testing.T) {
	tests := []struct {
		name           string
		modify         func(*http.Request)
		expectedHost   string
		expectedOrigin string
		expectedRPID   string
		defaultRPID    string
	}{
		{
			name: "plain localhost:8082",
			modify: func(r *http.Request) {
				r.Host = "localhost:8082"
			},
			expectedHost:   "localhost:8082",
			expectedOrigin: "http://localhost:8082",
			expectedRPID:   "localhost",
			defaultRPID:    "localhost",
		},
		{
			name: "Caddy reverse proxy with X-Forwarded-Host",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "vault.example.com")
				r.Host = "localhost:8082"
			},
			expectedHost:   "vault.example.com",
			expectedOrigin: "https://vault.example.com",
			expectedRPID:   "vault.example.com",
			defaultRPID:    "localhost",
		},
		{
			name: "Caddy reverse proxy with default https port 443",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "vault.example.com:443")
			},
			expectedHost:   "vault.example.com",
			expectedOrigin: "https://vault.example.com",
			expectedRPID:   "vault.example.com",
			defaultRPID:    "localhost",
		},
		{
			name: "Caddy reverse proxy with non-default port",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "vault.example.com:8443")
			},
			expectedHost:   "vault.example.com:8443",
			expectedOrigin: "https://vault.example.com:8443",
			expectedRPID:   "vault.example.com",
			defaultRPID:    "localhost",
		},
		{
			name: "Cloudflare proxy with Host header",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Host = "keys.cloudflare-domain.org"
			},
			expectedHost:   "keys.cloudflare-domain.org",
			expectedOrigin: "https://keys.cloudflare-domain.org",
			expectedRPID:   "keys.cloudflare-domain.org",
			defaultRPID:    "localhost",
		},
		{
			name: "Custom configured defaultRPID takes precedence",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "sub.company.com")
			},
			expectedHost:   "sub.company.com",
			expectedOrigin: "https://sub.company.com",
			expectedRPID:   "company.com",
			defaultRPID:    "company.com",
		},
		{
			name: "IP address host falls back to localhost RPID",
			modify: func(r *http.Request) {
				r.Host = "127.0.0.1:8082"
			},
			expectedHost:   "127.0.0.1:8082",
			expectedOrigin: "http://127.0.0.1:8082",
			expectedRPID:   "localhost",
			defaultRPID:    "localhost",
		},
		{
			name: "Proxy with X-Forwarded-Host and separate X-Forwarded-Port non-default",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "vault.example.com")
				r.Header.Set("X-Forwarded-Port", "9443")
			},
			expectedHost:   "vault.example.com:9443",
			expectedOrigin: "https://vault.example.com:9443",
			expectedRPID:   "vault.example.com",
			defaultRPID:    "localhost",
		},
		{
			name: "Proxy with X-Forwarded-Host and separate X-Forwarded-Port default 443",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "vault.example.com")
				r.Header.Set("X-Forwarded-Port", "443")
			},
			expectedHost:   "vault.example.com",
			expectedOrigin: "https://vault.example.com",
			expectedRPID:   "vault.example.com",
			defaultRPID:    "localhost",
		},
		{
			name: "Host with trailing dot trims dot for RPID",
			modify: func(r *http.Request) {
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-Host", "vault.example.com.")
			},
			expectedHost:   "vault.example.com.",
			expectedOrigin: "https://vault.example.com.",
			expectedRPID:   "vault.example.com",
			defaultRPID:    "localhost",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://localhost:8082/", nil)
			tc.modify(req)

			host := GetRequestHost(req)
			if host != tc.expectedHost {
				t.Errorf("host: expected %s, got %s", tc.expectedHost, host)
			}

			origin := GetRequestOrigin(req)
			if origin != tc.expectedOrigin {
				t.Errorf("origin: expected %s, got %s", tc.expectedOrigin, origin)
			}

			rpid := GetRequestRPID(req, tc.defaultRPID)
			if rpid != tc.expectedRPID {
				t.Errorf("rpid: expected %s, got %s", tc.expectedRPID, rpid)
			}
		})
	}
}

func TestProxyHeadersMiddleware(t *testing.T) {
	middlewareFunc := ProxyHeaders("localhost")

	var capturedOrigin, capturedRPID string
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o, ok := r.Context().Value(auth.OriginContextKey).(string); ok {
			capturedOrigin = o
		}
		if id, ok := r.Context().Value(auth.RPIDContextKey).(string); ok {
			capturedRPID = id
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := middlewareFunc(nextHandler)

	// Test 1: Plain HTTP request
	req1 := httptest.NewRequest("GET", "http://localhost:8082/api/v1/keys", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if capturedOrigin != "http://localhost:8082" {
		t.Fatalf("expected origin http://localhost:8082, got %s", capturedOrigin)
	}
	if capturedRPID != "localhost" {
		t.Fatalf("expected rpid localhost, got %s", capturedRPID)
	}

	// Test 2: Caddy HTTPS reverse proxy
	req2 := httptest.NewRequest("GET", "http://localhost:8082/api/v1/keys", nil)
	req2.Header.Set("X-Forwarded-Proto", "https")
	req2.Header.Set("X-Forwarded-Host", "vault.company.local")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if capturedOrigin != "https://vault.company.local" {
		t.Fatalf("expected origin https://vault.company.local, got %s", capturedOrigin)
	}
	if capturedRPID != "vault.company.local" {
		t.Fatalf("expected rpid vault.company.local, got %s", capturedRPID)
	}
}

func TestSecurityHeadersHSTS(t *testing.T) {
	dummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := SecurityHeaders(dummy)

	// Case 1: Plain HTTP -> No Strict-Transport-Security
	reqHTTP := httptest.NewRequest("GET", "http://localhost:8082/", nil)
	wHTTP := httptest.NewRecorder()
	handler.ServeHTTP(wHTTP, reqHTTP)

	if hsts := wHTTP.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Fatalf("expected no Strict-Transport-Security over plain HTTP, got %s", hsts)
	}

	// Case 2: HTTPS reverse proxy -> Strict-Transport-Security present
	reqHTTPS := httptest.NewRequest("GET", "http://localhost:8082/", nil)
	reqHTTPS.Header.Set("X-Forwarded-Proto", "https")
	wHTTPS := httptest.NewRecorder()
	handler.ServeHTTP(wHTTPS, reqHTTPS)

	if hsts := wHTTPS.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Fatalf("expected Strict-Transport-Security over HTTPS proxy, got empty")
	}
}

func TestGetIPProxyHeaders(t *testing.T) {
	// Case 1: Cloudflare CF-Connecting-IP
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("CF-Connecting-IP", "198.51.100.25")
	req1.Header.Set("X-Forwarded-For", "10.0.0.1, 198.51.100.25")
	req1.RemoteAddr = "127.0.0.1:50000"
	if ip := GetIP(req1); ip != "198.51.100.25" {
		t.Fatalf("expected CF-Connecting-IP 198.51.100.25, got %s", ip)
	}

	// Case 2: X-Real-IP
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Real-IP", "198.51.100.26")
	req2.Header.Set("X-Forwarded-For", "10.0.0.1")
	req2.RemoteAddr = "127.0.0.1:50000"
	if ip := GetIP(req2); ip != "198.51.100.26" {
		t.Fatalf("expected X-Real-IP 198.51.100.26, got %s", ip)
	}

	// Case 3: X-Forwarded-For
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("X-Forwarded-For", "198.51.100.27, 10.0.0.2")
	req3.RemoteAddr = "127.0.0.1:50000"
	if ip := GetIP(req3); ip != "198.51.100.27" {
		t.Fatalf("expected first X-Forwarded-For 198.51.100.27, got %s", ip)
	}

	// Case 4: RemoteAddr fallback
	req4 := httptest.NewRequest("GET", "/", nil)
	req4.RemoteAddr = "192.0.2.1:12345"
	if ip := GetIP(req4); ip != "192.0.2.1" {
		t.Fatalf("expected RemoteAddr 192.0.2.1, got %s", ip)
	}
}
