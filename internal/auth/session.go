package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

const sessionTTL = 7 * 24 * time.Hour

// SessionManager tracks logged-in sessions purely server-side (no JWTs
// or signed cookies) - simplest correct approach for a single-admin
// local dashboard: the cookie is an opaque random token, and validity
// is whatever this map says it is, which also makes revocation (e.g.
// logout) trivial.
type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]time.Time // token -> expires at
}

// NewSessionManager creates an empty session manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{sessions: make(map[string]time.Time)}
}

// Create generates a new session token and returns it.
func (sm *SessionManager) Create() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)

	sm.mu.Lock()
	sm.sessions[token] = time.Now().Add(sessionTTL)
	sm.mu.Unlock()

	return token, nil
}

// Valid reports whether token corresponds to a live, unexpired session.
func (sm *SessionManager) Valid(token string) bool {
	if token == "" {
		return false
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	expires, ok := sm.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expires) {
		delete(sm.sessions, token)
		return false
	}
	return true
}

// Revoke invalidates a session token immediately (logout).
func (sm *SessionManager) Revoke(token string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, token)
}

// LoginThrottle adds a small, increasing delay after repeated failed
// login attempts, to make online brute-forcing impractical without
// needing a full account-lockout UX. State is process-global and not
// tied to source IP - simple and sufficient for a single-admin local
// login rather than a public-facing service.
type LoginThrottle struct {
	mu          sync.Mutex
	failCount   int
	lastFailure time.Time
}

// NewLoginThrottle creates a throttle with no recorded failures.
func NewLoginThrottle() *LoginThrottle {
	return &LoginThrottle{}
}

// Delay returns how long the caller should wait before processing the
// next login attempt, based on recent failures. Failures older than 5
// minutes are forgotten, so a single mistyped password doesn't create
// a lasting penalty.
func (lt *LoginThrottle) Delay() time.Duration {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	if time.Since(lt.lastFailure) > 5*time.Minute {
		lt.failCount = 0
	}
	switch {
	case lt.failCount <= 2:
		return 0
	case lt.failCount <= 5:
		return 1 * time.Second
	default:
		return 5 * time.Second
	}
}

// RecordFailure registers a failed login attempt.
func (lt *LoginThrottle) RecordFailure() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.failCount++
	lt.lastFailure = time.Now()
}

// RecordSuccess clears the failure count after a successful login.
func (lt *LoginThrottle) RecordSuccess() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.failCount = 0
}
