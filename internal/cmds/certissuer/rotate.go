package certissuer

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lunal-dev/c8s/internal/issuer"
)

var errNoCertificateBundle = errors.New("no certificates loaded")

type caRotator struct {
	mu             sync.Mutex
	issuer         *Issuer
	bundle         *bundleManager
	caCertValidity time.Duration
	caCommonName   string
}

func (cr *caRotator) run(ctx context.Context, interval time.Duration) {
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
			newCert, fingerprint, err := cr.rotateCA()
			if err != nil {
				cr.issuer.Logger.Error("scheduled CA rotation failed", "error", err)
				continue
			}
			cr.issuer.Logger.Info("scheduled CA rotation completed",
				"audit", true,
				"new_fingerprint", fingerprint,
				"not_after", newCert.NotAfter.Format(time.RFC3339),
				"latency", time.Since(start).String(),
			)
		}
	}
}

func (cr *caRotator) rotateCA() (*x509.Certificate, string, error) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	b := cr.issuer.getBundle()
	if b == nil {
		return nil, "", errNoCertificateBundle
	}

	caCommonName := cr.caCommonName
	if caCommonName == "" {
		caCommonName = issuer.DefaultCACommonName
	}
	ca, err := issuer.NewCAWithParent(caCommonName, cr.caCertValidity, elliptic.P384(), b.caCert, b.caKey)
	if err != nil {
		return nil, "", fmt.Errorf("mint new CA: %w", err)
	}
	newKey, newCert := ca.Key, ca.Cert

	if cr.bundle != nil {
		if err := cr.bundle.rotate(newCert); err != nil {
			return nil, "", fmt.Errorf("rotate public bundle: %w", err)
		}
	}

	cr.issuer.bundle.Store(&certBundle{
		caCert:          newCert,
		caKey:           newKey,
		tokenSignerCert: b.tokenSignerCert,
		parentCert:      b.caCert,
	})

	certReloadsTotal.Inc()
	fingerprint := updateCACertFingerprint(newCert.Raw)
	return newCert, fingerprint, nil
}
