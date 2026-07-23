package earsigner_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/earsigner"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestGenerate(t *testing.T) {
	pem1, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(pem1) == 0 {
		t.Fatal("Generate returned empty PEM")
	}
	// Generated PEM must be parseable by NewRotator.
	if _, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: time.Hour,
		Overlap:  time.Minute,
		Logger:   discardLogger(),
	}, pem1, func(*ecdsa.PrivateKey, string) {}); err != nil {
		t.Fatalf("NewRotator with generated key: %v", err)
	}

	// Two calls must produce distinct keys.
	pem2, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate (2): %v", err)
	}
	if string(pem1) == string(pem2) {
		t.Error("Generate produced identical keys on two calls")
	}
}

func TestNewRotator_InvalidPEM(t *testing.T) {
	cases := map[string][]byte{
		"empty":     nil,
		"garbage":   []byte("not a pem at all"),
		"bad-block": []byte("-----BEGIN EC PRIVATE KEY-----\nQUJD\n-----END EC PRIVATE KEY-----\n"),
	}
	for name, pem := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := earsigner.NewRotator(earsigner.RotatorConfig{
				Interval: time.Hour,
				Logger:   discardLogger(),
			}, pem, func(*ecdsa.PrivateKey, string) {})
			if err == nil {
				t.Fatal("expected error for invalid PEM, got nil")
			}
			if r != nil {
				t.Error("expected nil rotator on error")
			}
		})
	}
}

func TestPublicKey_ActiveMatch(t *testing.T) {
	r, _ := newTestRotator(t)

	// The kid for the active key is whatever appears in the JWKS.
	kid := firstKid(t, r)
	pub, err := r.PublicKey(kid)
	if err != nil {
		t.Fatalf("PublicKey(active kid): %v", err)
	}
	if pub == nil {
		t.Fatal("PublicKey returned nil public key")
	}
}

func TestJWKSetJSON_HasActiveKey(t *testing.T) {
	r, _ := newTestRotator(t)

	body := r.JWKSetJSON()
	keys := parseJWKS(t, body)
	if len(keys) != 1 {
		t.Fatalf("expected 1 key in fresh JWKS, got %d", len(keys))
	}
	if keys[0].Kid == "" {
		t.Error("active key has empty kid")
	}
	if keys[0].Crv != "P-256" {
		t.Errorf("crv = %q, want P-256", keys[0].Crv)
	}
}

// TestRun_Rotation drives the rotation loop with a tiny interval to exercise
// rotate(), the swap callback, and JWKS rebuild including a retiring key.
func TestRun_Rotation(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var (
		mu          sync.Mutex
		swappedKids []string
	)
	r, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: 5 * time.Millisecond,
		Overlap:  time.Hour, // keep retiring keys alive so JWKS grows
		Jitter:   0,
		Logger:   discardLogger(),
	}, keyPEM, func(_ *ecdsa.PrivateKey, kid string) {
		mu.Lock()
		swappedKids = append(swappedKids, kid)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}

	initialKid := firstKid(t, r)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()

	// Wait for at least one rotation by polling the swap callback.
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		n := len(swappedKids)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for rotation")
		case <-time.After(time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	mu.Lock()
	defer mu.Unlock()
	newKid := swappedKids[0]
	if newKid == initialKid {
		t.Error("rotation produced the same kid as the initial key")
	}

	// New active kid must be resolvable.
	if _, err := r.PublicKey(newKid); err != nil {
		t.Errorf("PublicKey(new active kid): %v", err)
	}
	// The original key should still resolve while in the overlap window.
	if _, err := r.PublicKey(initialKid); err != nil {
		t.Errorf("PublicKey(retiring kid): %v", err)
	}

	// JWKS must now contain at least the active + one retiring key.
	keys := parseJWKS(t, r.JWKSetJSON())
	if len(keys) < 2 {
		t.Errorf("expected >=2 keys in JWKS after rotation, got %d", len(keys))
	}
}

// TestPublicKey_RetiringKeyExpires proves that a retiring key is rejected once
// it passes its overlap deadline, even if a later rotation has not yet evicted
// it from the retiring set. Without the lookup-time deadline check a retired
// (possibly compromised) key would keep verifying tokens until the next
// rotation — with defaults ~720h, far beyond the ~25h overlap policy.
func TestPublicKey_RetiringKeyExpires(t *testing.T) {
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	swapped := make(chan struct{}, 1)
	r, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: 200 * time.Millisecond,
		Overlap:  10 * time.Millisecond,
		Jitter:   0,
		Logger:   discardLogger(),
	}, keyPEM, func(_ *ecdsa.PrivateKey, _ string) {
		select {
		case swapped <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	initialKid := firstKid(t, r)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	// Wait for the first rotation (which retires the initial key), then stop the
	// loop so no subsequent rotation can evict it — isolating the lookup-time
	// deadline check from eviction.
	select {
	case <-swapped:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first rotation")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	// The initial key was retired with a 10ms overlap; wait well past it.
	time.Sleep(100 * time.Millisecond)

	if _, err := r.PublicKey(initialKid); err == nil {
		t.Error("PublicKey accepted a retiring key past its overlap deadline")
	}
}

// --- helpers ---

type jwkEntry struct {
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	Kty string `json:"kty"`
}

func parseJWKS(t *testing.T, body []byte) []jwkEntry {
	t.Helper()
	var set struct {
		Keys []jwkEntry `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("unmarshal JWKS %q: %v", body, err)
	}
	return set.Keys
}

func firstKid(t *testing.T, r *earsigner.Rotator) string {
	t.Helper()
	keys := parseJWKS(t, r.JWKSetJSON())
	if len(keys) == 0 {
		t.Fatal("JWKS has no keys")
	}
	return keys[0].Kid
}
