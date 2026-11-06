package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type clientRecord struct {
	timestamps []time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	records map[string]*clientRecord
}

func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		records: make(map[string]*clientRecord),
	}
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		for range ticker.C {
			rl.cleanup()
		}
	}()
	return rl
}

const maxRateLimiterRecords = 50000

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.cleanupLocked(time.Now().Add(-5 * time.Minute))
}

func (rl *RateLimiter) cleanupLocked(cutoff time.Time) {
	for k, rec := range rl.records {
		var valid []time.Time
		for _, t := range rec.timestamps {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.records, k)
		} else {
			rec.timestamps = valid
		}
	}
}

func parseCandidateIP(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")
	if parsed := net.ParseIP(raw); parsed != nil {
		return parsed.String(), true
	}
	return "", false
}

func GetIP(r *http.Request) string {
	if cfIP, ok := parseCandidateIP(r.Header.Get("CF-Connecting-IP")); ok {
		return cfIP
	}
	if realIP, ok := parseCandidateIP(r.Header.Get("X-Real-IP")); ok {
		return realIP
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for _, part := range parts {
			if ip, ok := parseCandidateIP(part); ok {
				return ip
			}
		}
	}
	if remoteIP, ok := parseCandidateIP(r.RemoteAddr); ok {
		return remoteIP
	}
	return "unknown"
}

func (rl *RateLimiter) Limit(maxRequests int, window time.Duration, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)
			if key == "" {
				key = GetIP(r)
			}

			now := time.Now()
			cutoff := now.Add(-window)

			rl.mu.Lock()
			rec, exists := rl.records[key]
			if !exists {
				if len(rl.records) >= maxRateLimiterRecords {
					rl.cleanupLocked(cutoff)
				}
				if len(rl.records) >= maxRateLimiterRecords {
					rl.mu.Unlock()
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error":   "rate_limit_exceeded",
						"message": "Too many requests. Please slow down.",
					})
					return
				}
				rec = &clientRecord{}
				rl.records[key] = rec
			}

			// Prune out-of-window timestamps
			var fresh []time.Time
			for _, t := range rec.timestamps {
				if t.After(cutoff) {
					fresh = append(fresh, t)
				}
			}

			if len(fresh) >= maxRequests {
				rl.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":   "rate_limit_exceeded",
					"message": "Too many requests. Please slow down.",
				})
				return
			}

			fresh = append(fresh, now)
			rec.timestamps = fresh
			rl.mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}
