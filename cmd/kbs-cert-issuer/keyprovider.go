package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// KeyProvider resolves the ECDSA public key for verifying an EAR JWT.
// kid may be empty for tokens issued before the JWKS rollout.
type KeyProvider interface {
	PublicKey(kid string) (*ecdsa.PublicKey, error)
}

// certKeyProvider wraps a certificate-based public key (the legacy path).
// It ignores the kid and always returns the same key.
type certKeyProvider struct {
	pub *ecdsa.PublicKey
}

func newCertKeyProvider(cert *x509.Certificate) (*certKeyProvider, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("token-signer cert has non-ECDSA key: %T", cert.PublicKey)
	}
	return &certKeyProvider{pub: pub}, nil
}

func (p *certKeyProvider) PublicKey(_ string) (*ecdsa.PublicKey, error) {
	return p.pub, nil
}

// jwksKeyProvider fetches keys from a JWKS endpoint and caches them.
type jwksKeyProvider struct {
	url      string
	cacheTTL time.Duration
	client   *http.Client
	logger   *slog.Logger

	mu        sync.RWMutex
	keys      map[string]*ecdsa.PublicKey // kid → pubkey
	allKeys   []*ecdsa.PublicKey          // for empty-kid fallback
	fetchedAt time.Time
	lastForce time.Time // rate-limit force-refreshes to 1/sec
}

var jwksRefreshesTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "kbs_cert_issuer_jwks_refreshes_total",
	Help: "Total JWKS endpoint refreshes.",
})

func newJWKSKeyProvider(url string, cacheTTL time.Duration, logger *slog.Logger) *jwksKeyProvider {
	return &jwksKeyProvider{
		url:      url,
		cacheTTL: cacheTTL,
		client:   &http.Client{Timeout: 10 * time.Second},
		logger:   logger,
		keys:     make(map[string]*ecdsa.PublicKey),
	}
}

func (p *jwksKeyProvider) PublicKey(kid string) (*ecdsa.PublicKey, error) {
	if err := p.refreshIfStale(); err != nil {
		// Stale cache + fetch failure — if we have cached keys, try them.
		if key, ok := p.lookup(kid); ok {
			return key, nil
		}
		return nil, fmt.Errorf("JWKS fetch failed and no cached key for kid %q: %w", kid, err)
	}

	if key, ok := p.lookup(kid); ok {
		return key, nil
	}

	// Kid miss — force-refresh once (rate-limited).
	refreshed, err := p.forceRefresh()
	if err != nil {
		return nil, fmt.Errorf("JWKS force-refresh failed for kid %q: %w", kid, err)
	}

	if key, ok := p.lookup(kid); ok {
		return key, nil
	}
	if refreshed {
		return nil, fmt.Errorf("JWKS key not found for kid %q after refresh", kid)
	}
	return nil, fmt.Errorf("JWKS key not found for kid %q (refresh rate-limited)", kid)
}

// lookup resolves a key under read lock. Empty kid falls back to the first key.
func (p *jwksKeyProvider) lookup(kid string) (*ecdsa.PublicKey, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if kid != "" {
		key, ok := p.keys[kid]
		return key, ok
	}
	if len(p.allKeys) > 0 {
		p.logger.Debug("EAR token has no kid header, using first JWKS key")
		return p.allKeys[0], true
	}
	return nil, false
}

func (p *jwksKeyProvider) refreshIfStale() error {
	p.mu.RLock()
	fresh := time.Since(p.fetchedAt) < p.cacheTTL
	p.mu.RUnlock()
	if fresh {
		return nil
	}
	return p.fetch()
}

// forceRefresh fetches regardless of cache, rate-limited to 1/sec.
// Returns (true, nil) if a fetch was performed, (false, nil) if rate-limited.
func (p *jwksKeyProvider) forceRefresh() (bool, error) {
	p.mu.Lock()
	if time.Since(p.lastForce) < time.Second {
		p.mu.Unlock()
		return false, nil
	}
	p.lastForce = time.Now()
	p.mu.Unlock()
	return true, p.fetch()
}

func (p *jwksKeyProvider) fetch() error {
	req, err := http.NewRequest(http.MethodGet, p.url, nil)
	if err != nil {
		return fmt.Errorf("build JWKS request: %w", err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", p.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", p.url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB
	if err != nil {
		return fmt.Errorf("read JWKS body: %w", err)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	var allKeys []*ecdsa.PublicKey
	for _, jwk := range set.Keys {
		pub, ok := jwk.Key.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		if jwk.KeyID != "" {
			keys[jwk.KeyID] = pub
		}
		allKeys = append(allKeys, pub)
	}

	p.mu.Lock()
	p.keys = keys
	p.allKeys = allKeys
	p.fetchedAt = time.Now()
	p.mu.Unlock()

	jwksRefreshesTotal.Inc()
	p.logger.Info("JWKS refreshed", "keys", len(keys))
	return nil
}
