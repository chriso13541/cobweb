// Package auth handles login for the cobweb dashboard: a single admin
// credential (username + PBKDF2-hashed password), server-side sessions,
// and basic brute-force throttling. It's deliberately simple - one
// admin account, no roles, no external identity provider - since this
// is a home-network gateway's local admin login, not a multi-tenant
// system.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

const (
	defaultUsername  = "admin"
	defaultPassword  = "admin"
	pbkdf2Iterations = 210000
	saltLen          = 16
	keyLen           = 32
)

// Credentials is the on-disk shape of the credential store.
type Credentials struct {
	Username   string `json:"username"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"` // base64
	Hash       string `json:"hash"` // base64
}

// Store manages the credential file, safe for concurrent access.
type Store struct {
	path  string
	mu    sync.RWMutex
	creds Credentials
}

// Load reads the credential store from path, creating it with the
// default admin/admin login (hashed, never stored in plaintext) if it
// doesn't exist yet.
func Load(path string) (*Store, error) {
	s := &Store{path: path}

	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if err := s.setPasswordLocked(defaultUsername, defaultPassword); err != nil {
			return nil, fmt.Errorf("auth: create default credentials: %w", err)
		}
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: read credentials: %w", err)
	}
	if err := json.Unmarshal(b, &s.creds); err != nil {
		return nil, fmt.Errorf("auth: parse credentials: %w", err)
	}
	return s, nil
}

// Verify checks a username/password pair against the stored hash using
// a constant-time comparison, so response timing doesn't leak whether
// the password was close to correct.
func (s *Store) Verify(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if username != s.creds.Username {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(s.creds.Salt)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(s.creds.Hash)
	if err != nil {
		return false
	}
	got := pbkdf2([]byte(password), salt, s.creds.Iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// SetPassword re-hashes and persists a new password for the given
// username. Used both for first-run default creation and for a
// person-initiated password change.
func (s *Store) SetPassword(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setPasswordLocked(username, password)
}

func (s *Store) setPasswordLocked(username, password string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	hash := pbkdf2([]byte(password), salt, pbkdf2Iterations, keyLen)

	s.creds = Credentials{
		Username:   username,
		Iterations: pbkdf2Iterations,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Hash:       base64.StdEncoding.EncodeToString(hash),
	}
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.creds, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	// 0600: only the owner (root, running the service) can read this
	// file - it's the whole security boundary for the dashboard login.
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Username returns the currently configured admin username.
func (s *Store) Username() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.creds.Username
}
