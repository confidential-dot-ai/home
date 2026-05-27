package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ErrNoCertificateBundle is returned when CARotator.RotateCA is invoked before
// the issuer has loaded a CA bundle.
var ErrNoCertificateBundle = errors.New("no certificates loaded")

// CARotatorDeps carries the cert-issuer-side wiring that CARotator needs
// to mint a new CA and publish it. The fields/callbacks let CARotator stay
// free of certissuer's metrics, atomic-pointer bundle, and process-local
// token-signer plumbing.
type CARotatorDeps struct {
	Logger         *slog.Logger
	Bundle         *BundleManager // public bundle; nil disables /ca write-back
	CACertValidity time.Duration
	CACommonName   string

	// Snapshot returns the current CA cert+key (used as the parent of the
	// newly minted CA) plus the token-signer cert that the rotation must
	// carry forward. ok=false means no bundle is loaded.
	Snapshot func() (caCert *x509.Certificate, caKey *ecdsa.PrivateKey, tokenSignerCert *x509.Certificate, ok bool)

	// CommitRotation publishes the freshly minted CA: it atomically swaps the
	// in-memory bundle pointer and updates any caller-side fingerprint /
	// reload metrics. It returns the fingerprint of newCert for audit logs.
	CommitRotation func(newCert *x509.Certificate, newKey *ecdsa.PrivateKey, tokenSignerCert *x509.Certificate, parentCert *x509.Certificate) string
}

// CARotator periodically mints a new in-memory CA, retains the previous one
// as a parent (for chain-of-trust continuity), and updates the public bundle.
type CARotator struct {
	mu   sync.Mutex
	deps CARotatorDeps
}

// NewCARotator constructs a CARotator with the supplied dependencies.
// Snapshot and CommitRotation are required; otherwise the first scheduled
// rotation panics inside the loop goroutine rather than at boot. Logger
// defaults to slog.Default() when unset.
func NewCARotator(deps CARotatorDeps) (*CARotator, error) {
	if deps.Snapshot == nil {
		return nil, fmt.Errorf("CARotatorDeps.Snapshot is required")
	}
	if deps.CommitRotation == nil {
		return nil, fmt.Errorf("CARotatorDeps.CommitRotation is required")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return &CARotator{deps: deps}, nil
}

// Run drives RotateCA on a fixed interval until ctx is cancelled. interval <= 0
// disables the loop (useful for tests that want to call RotateCA manually).
func (cr *CARotator) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			newCert, fingerprint, err := cr.RotateCA()
			if err != nil {
				cr.deps.Logger.Error("scheduled CA rotation failed", "error", err)
				continue
			}
			cr.deps.Logger.Info("scheduled CA rotation completed",
				"audit", true,
				"new_fingerprint", fingerprint,
				"not_after", newCert.NotAfter.Format(time.RFC3339),
				"latency", time.Since(start).String(),
			)
		}
	}
}

// RotateCA mints a new CA signed by the current one, persists the new public
// bundle, and commits the rotation through deps.CommitRotation. It returns the
// new cert and its fingerprint for audit logging.
func (cr *CARotator) RotateCA() (*x509.Certificate, string, error) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	caCert, caKey, tokenSignerCert, ok := cr.deps.Snapshot()
	if !ok {
		return nil, "", ErrNoCertificateBundle
	}

	caCommonName := cr.deps.CACommonName
	if caCommonName == "" {
		caCommonName = DefaultCACommonName
	}
	ca, err := NewCAWithParent(caCommonName, cr.deps.CACertValidity, elliptic.P384(), caCert, caKey)
	if err != nil {
		return nil, "", fmt.Errorf("mint new CA: %w", err)
	}
	newKey, newCert := ca.Key, ca.Cert

	if cr.deps.Bundle != nil {
		if err := cr.deps.Bundle.Rotate(newCert); err != nil {
			return nil, "", fmt.Errorf("rotate public bundle: %w", err)
		}
	}

	fingerprint := cr.deps.CommitRotation(newCert, newKey, tokenSignerCert, caCert)
	return newCert, fingerprint, nil
}
