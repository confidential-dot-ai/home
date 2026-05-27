// Package earsigner manages the EAR token-signing key lifecycle with
// overlap-based rotation and JWKS serving.
package earsigner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/jwks"
)

// RotatorConfig configures the key rotation loop.
type RotatorConfig struct {
	Interval time.Duration // rotation interval (default 720h)
	Overlap  time.Duration // how long retiring keys stay in JWKS (default 25h)
	Jitter   float64       // fraction of Interval to jitter first tick (default 0.1)
	Logger   *slog.Logger
}

// managedKey is a key with lifecycle metadata.
type managedKey struct {
	kid       string
	key       *ecdsa.PrivateKey
	notAfterT time.Time
}

// SwapKeyFunc is called when the active signing key changes.
type SwapKeyFunc func(key *ecdsa.PrivateKey, kid string)

// Rotator manages the token-signer key lifecycle with overlap-based
// rotation. Keys are ephemeral and live only in memory.
type Rotator struct {
	cfg     RotatorConfig
	swapKey SwapKeyFunc

	mu       sync.RWMutex
	active   *managedKey
	retiring []*managedKey

	jwksBody atomic.Pointer[[]byte]
}

// Generate creates a fresh P-256 private key and returns it as PEM bytes.
func Generate() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate P-256 key: %w", err)
	}
	return certutil.MarshalECKeyPEM(key)
}

// NewRotator creates a rotator from an initial key PEM.
func NewRotator(cfg RotatorConfig, initialKeyPEM []byte, swapKey SwapKeyFunc) (*Rotator, error) {
	key, err := certutil.ParseECPrivateKey(initialKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse initial key: %w", err)
	}
	kid, err := jwks.Thumbprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	r := &Rotator{
		cfg:     cfg,
		swapKey: swapKey,
		active: &managedKey{
			kid:       kid,
			key:       key,
			notAfterT: now.Add(cfg.Interval + cfg.Overlap),
		},
	}
	r.rebuildJWKS()

	return r, nil
}

// JWKSetJSON returns the current pre-serialized JWKS response body.
func (r *Rotator) JWKSetJSON() []byte {
	p := r.jwksBody.Load()
	if p == nil {
		return []byte(`{"keys":[]}`)
	}
	return *p
}

// PublicKey returns the ECDSA public key matching kid from the active or
// retiring set. A kid is always required: with an overlap window the active
// and retiring keys coexist, and routing every kid-less token to "active"
// would silently mis-verify tokens signed by a retiring key. Satisfies the
// issuer.KeyProvider interface so callers can verify EAR JWTs against the
// rotator's in-memory key state without an out-of-process JWKS fetch.
func (r *Rotator) PublicKey(kid string) (*ecdsa.PublicKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("token-signer lookup requires a kid header")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active != nil && r.active.kid == kid {
		return &r.active.key.PublicKey, nil
	}
	for _, k := range r.retiring {
		if k.kid == kid {
			return &k.key.PublicKey, nil
		}
	}
	return nil, fmt.Errorf("no token-signer key for kid %q", kid)
}

// Run starts the rotation loop. Blocks until ctx is cancelled.
func (r *Rotator) Run(ctx context.Context) {
	// Jitter the first tick to avoid thundering-herd after fleet restarts.
	jitter := time.Duration(float64(r.cfg.Interval) * r.cfg.Jitter * mathrand.Float64())
	first := r.cfg.Interval + jitter
	r.cfg.Logger.Info("rotation loop starting", "interval", r.cfg.Interval, "first_tick_in", first)

	timer := time.NewTimer(first)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			r.rotate()
			timer.Reset(r.cfg.Interval)
		}
	}
}

func (r *Rotator) rotate() {
	r.cfg.Logger.Info("rotating token-signer key")

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		r.cfg.Logger.Error("key generation failed", "error", err)
		return
	}
	newKid, err := jwks.Thumbprint(&newKey.PublicKey)
	if err != nil {
		r.cfg.Logger.Error("thumbprint failed", "error", err)
		return
	}

	r.mu.Lock()
	now := time.Now()
	if old := r.active; old != nil {
		old.notAfterT = now.Add(r.cfg.Overlap)
		r.retiring = append(r.retiring, old)
	}

	r.active = &managedKey{
		kid:       newKid,
		key:       newKey,
		notAfterT: now.Add(r.cfg.Interval + r.cfg.Overlap),
	}

	// Evict expired retiring keys.
	live := r.retiring[:0]
	for _, k := range r.retiring {
		if k.notAfterT.After(now) {
			live = append(live, k)
		} else {
			r.cfg.Logger.Info("evicted expired key", "kid", k.kid)
		}
	}
	// clear the obsolete elements to enable GC
	clear(r.retiring[len(live):])
	r.retiring = live
	r.mu.Unlock()

	// Swap the signing key in the Issuer.
	r.swapKey(newKey, newKid)

	r.rebuildJWKS()

	r.cfg.Logger.Info("rotation complete", "new_kid", newKid, "retiring_keys", len(r.retiring))
}

func (r *Rotator) rebuildJWKS() {
	r.mu.RLock()
	var keys []jose.JSONWebKey

	// Active key first.
	if r.active != nil {
		if jwk, err := jwks.FromPublicKey(&r.active.key.PublicKey); err == nil {
			keys = append(keys, jwk)
		}
	}
	for _, k := range r.retiring {
		if jwk, err := jwks.FromPublicKey(&k.key.PublicKey); err == nil {
			keys = append(keys, jwk)
		}
	}
	r.mu.RUnlock()

	body, err := jwks.MarshalSet(keys...)
	if err != nil {
		r.cfg.Logger.Error("failed to marshal JWKS", "error", err)
		return
	}
	r.jwksBody.Store(&body)
}
