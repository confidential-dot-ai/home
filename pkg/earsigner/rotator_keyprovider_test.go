package earsigner_test

import (
	"crypto/ecdsa"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/pkg/earsigner"
)

func newTestRotator(t *testing.T) (*earsigner.Rotator, *ecdsa.PrivateKey) {
	t.Helper()
	keyPEM, err := earsigner.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var swapped *ecdsa.PrivateKey
	r, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: time.Hour,
		Overlap:  time.Minute,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, keyPEM, func(k *ecdsa.PrivateKey, _ string) { swapped = k })
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	return r, swapped
}

func TestRotator_PublicKey(t *testing.T) {
	r, _ := newTestRotator(t)

	if _, err := r.PublicKey(""); err == nil {
		t.Error("empty kid: expected error, got nil")
	}

	if _, err := r.PublicKey("does-not-exist"); err == nil {
		t.Error("unknown kid: expected error, got nil")
	}
}
