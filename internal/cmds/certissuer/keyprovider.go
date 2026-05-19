package certissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
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

var jwksRefreshesTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "cert_issuer_jwks_refreshes_total",
	Help: "Total JWKS endpoint refreshes.",
})

// jwksKeyProvider resolves EAR signing keys from a JWKS endpoint via
// jwx's background-refreshing cache. On a kid miss we force-refresh once
// per second to pick up an Assam key rotation between scheduled refreshes.
type jwksKeyProvider struct {
	url    string
	cache  *jwk.Cache
	logger *slog.Logger

	mu        sync.Mutex
	lastForce time.Time
}

func newJWKSKeyProvider(ctx context.Context, url string, cacheTTL time.Duration, client *http.Client, logger *slog.Logger) (*jwksKeyProvider, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	cache := jwk.NewCache(ctx, jwk.WithRefreshWindow(cacheTTL))
	if err := cache.Register(url,
		jwk.WithHTTPClient(client),
		jwk.WithMinRefreshInterval(cacheTTL),
		jwk.WithFetchWhitelist(jwk.NewMapWhitelist().Add(url)),
	); err != nil {
		return nil, fmt.Errorf("register JWKS url: %w", err)
	}
	if _, err := cache.Refresh(ctx, url); err != nil {
		logger.Warn("initial JWKS fetch failed; will retry on first verification", "url", url, "err", err)
	} else {
		jwksRefreshesTotal.Inc()
	}
	return &jwksKeyProvider{url: url, cache: cache, logger: logger}, nil
}

func (p *jwksKeyProvider) PublicKey(kid string) (*ecdsa.PublicKey, error) {
	ctx := context.Background()
	set, err := p.cache.Get(ctx, p.url)
	if err != nil {
		return nil, fmt.Errorf("JWKS cache lookup: %w", err)
	}
	if key, ok := lookupECDSA(set, kid, p.logger); ok {
		return key, nil
	}
	if !p.tryForceRefresh(ctx) {
		return nil, fmt.Errorf("JWKS key not found for kid %q (refresh rate-limited)", kid)
	}
	set, err = p.cache.Get(ctx, p.url)
	if err != nil {
		return nil, fmt.Errorf("JWKS cache lookup after refresh: %w", err)
	}
	if key, ok := lookupECDSA(set, kid, p.logger); ok {
		return key, nil
	}
	return nil, fmt.Errorf("JWKS key not found for kid %q after refresh", kid)
}

func (p *jwksKeyProvider) tryForceRefresh(ctx context.Context) bool {
	p.mu.Lock()
	if time.Since(p.lastForce) < time.Second {
		p.mu.Unlock()
		return false
	}
	p.lastForce = time.Now()
	p.mu.Unlock()
	if _, err := p.cache.Refresh(ctx, p.url); err != nil {
		p.logger.Warn("JWKS force-refresh failed", "err", err)
		return true
	}
	jwksRefreshesTotal.Inc()
	p.logger.Info("JWKS refreshed (kid miss)")
	return true
}

// lookupECDSA returns the ECDSA public key for kid, or the first ECDSA key
// in the set when kid is empty (legacy tokens issued before the JWKS rollout).
func lookupECDSA(set jwk.Set, kid string, logger *slog.Logger) (*ecdsa.PublicKey, bool) {
	if kid != "" {
		key, ok := set.LookupKeyID(kid)
		if !ok {
			return nil, false
		}
		return rawECDSA(key)
	}
	for i := 0; i < set.Len(); i++ {
		key, _ := set.Key(i)
		if pub, ok := rawECDSA(key); ok {
			logger.Debug("EAR token has no kid header, using first JWKS key")
			return pub, true
		}
	}
	return nil, false
}

func rawECDSA(key jwk.Key) (*ecdsa.PublicKey, bool) {
	var pub ecdsa.PublicKey
	if err := key.Raw(&pub); err != nil {
		return nil, false
	}
	return &pub, true
}
