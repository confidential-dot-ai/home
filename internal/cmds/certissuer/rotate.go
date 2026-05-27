package certissuer

import (
	"crypto/ecdsa"
	"crypto/x509"
	"time"

	"github.com/lunal-dev/c8s/internal/issuer"
)

// newCARotatorDeps wires an Issuer + public BundleManager into the
// dependency struct that issuer.CARotator drives. The Snapshot and
// CommitRotation closures keep certissuer's atomic bundle pointer and
// rotation metrics out of internal/issuer.
func newCARotatorDeps(iss *Issuer, bm *issuer.BundleManager, caCertValidity time.Duration, caCommonName string) issuer.CARotatorDeps {
	return issuer.CARotatorDeps{
		Logger:         iss.Logger,
		Bundle:         bm,
		CACertValidity: caCertValidity,
		CACommonName:   caCommonName,
		Snapshot: func() (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, bool) {
			b := iss.getBundle()
			if b == nil {
				return nil, nil, nil, false
			}
			return b.caCert, b.caKey, b.tokenSignerCert, true
		},
		CommitRotation: func(newCert *x509.Certificate, newKey *ecdsa.PrivateKey, tokenSignerCert *x509.Certificate, parentCert *x509.Certificate) string {
			iss.bundle.Store(&certBundle{
				caCert:          newCert,
				caKey:           newKey,
				tokenSignerCert: tokenSignerCert,
				parentCert:      parentCert,
			})
			certReloadsTotal.Inc()
			return updateCACertFingerprint(newCert.Raw)
		},
	}
}
