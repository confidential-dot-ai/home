package secretbroker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"
)

// tokenPrefix labels broker-minted tokens. Agents treat the token as opaque;
// the prefix only aids log/debug recognition. The token value itself is never
// logged.
const tokenPrefix = "c8sb."

// session is the authorization a token carries: who the caller is, which KV
// paths they may read, and the client certificate the token is bound to, until
// expiry. The certFP binding stops one attested workload from replaying
// another's bearer token: a read must arrive on the same client cert the token
// was minted for.
type session struct {
	identity PeerIdentity
	allow    []string
	certFP   string
	expiry   time.Time
}

// tokenStore maps tokens to sessions. Keys are SHA-256 of the token, so the
// raw token bytes are never retained in memory after issuance and lookups are
// not over attacker-chosen plaintext.
type tokenStore struct {
	mu     sync.Mutex
	byHash map[string]*session
	ttl    time.Duration
}

func newTokenStore(ttl time.Duration) *tokenStore {
	return &tokenStore{byHash: make(map[string]*session), ttl: ttl}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Issue mints a fresh high-entropy token bound to id, the allowed paths, and
// the caller's client-cert fingerprint, and returns the token string. The
// caller must treat allow as owned by the store.
func (s *tokenStore) Issue(id PeerIdentity, allow []string, certFP string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := tokenPrefix + base64.RawURLEncoding.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.byHash[hashToken(token)] = &session{
		identity: id,
		allow:    allow,
		certFP:   certFP,
		expiry:   time.Now().Add(s.ttl),
	}
	return token, nil
}

// Lookup returns the live session for a token, or false if the token is
// unknown or expired. Expired entries are dropped on access.
func (s *tokenStore) Lookup(token string) (*session, bool) {
	key := hashToken(token)

	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byHash[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.expiry) {
		delete(s.byHash, key)
		return nil, false
	}
	return sess, true
}

// reap evicts expired sessions on an interval until ctx is cancelled.
func (s *tokenStore) reap(ctx context.Context) {
	ticker := time.NewTicker(s.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for k, sess := range s.byHash {
				if now.After(sess.expiry) {
					delete(s.byHash, k)
				}
			}
			s.mu.Unlock()
		}
	}
}
