package issuer

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// SignCSRParams is the input to (*CA).SignCSR. The caller enforces all policy
// (measurement, key binding, SAN validation, TTL capping) before invoking.
type SignCSRParams struct {
	CSR      *x509.CertificateRequest
	TTL      time.Duration // pre-capped by caller; not clamped here
	Evidence []byte        // raw attestation evidence; SHA-256 embedded as audit extension

	// ConfigClaimsExt, when set, is the DER value of the RA-TLS config-claims
	// extension (ratls.OIDRATLSConfigClaims) to stamp on the leaf. The caller
	// MUST have verified the claims against the requester's evidence and (for
	// workload digests) the allowlist before passing them — SignCSR does not
	// re-verify (docs/ratls.md).
	ConfigClaimsExt []byte
}

// SignCSR signs csr against this CA, returning the leaf certificate PEM and
// serial number used.
//
// THREAT MODEL: this is the unguarded signing primitive at the root of the
// mesh trust chain. The caller MUST upstream-validate: (1) the EAR JWT
// signature and issuer claim, (2) the CSR public key matches the TEE-attested
// key in the EAR, (3) the launch measurement is in the policy allowlist,
// (4) DNS/IP SANs satisfy the per-deployment SAN policy, (5) the TTL is
// clamped to a policy maximum. Skipping any of these lets an attacker who
// controls the CSR mint a CA-signed leaf for any subject they choose.
func (c *CA) SignCSR(p SignCSRParams) (certPEM []byte, serial *big.Int, err error) {
	if c == nil || c.Cert == nil || c.Key == nil {
		return nil, nil, fmt.Errorf("sign csr: CA bundle not loaded")
	}
	if p.CSR == nil {
		return nil, nil, fmt.Errorf("sign csr: CSR is required")
	}

	template, err := certutil.NewLeafTemplate(p.CSR.Subject.CommonName, p.TTL)
	if err != nil {
		return nil, nil, err
	}
	template.DNSNames = p.CSR.DNSNames
	template.IPAddresses = p.CSR.IPAddresses

	digest := sha256.Sum256(p.Evidence)
	if err := certutil.AppendAttestationDigest(template, digest[:]); err != nil {
		return nil, nil, err
	}
	// The client's CSR-supplied RA-TLS extension is copied verbatim: only the
	// client can produce evidence bound to its bare key (no nonce), which is
	// what downstream ratls-mode verifiers re-verify. The extension is opaque
	// here — verifiers check it against the leaf's key via the attestation-api,
	// so a forged or stale extension fails closed at the consumer.
	copyRATLSExtension(template, p.CSR)
	if len(p.ConfigClaimsExt) > 0 {
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    ratls.OIDRATLSConfigClaims,
			Value: p.ConfigClaimsExt,
		})
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, c.Cert, p.CSR.PublicKey, c.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}

	return certutil.EncodeCertPEM(certDER), template.SerialNumber, nil
}

func copyRATLSExtension(template *x509.Certificate, csr *x509.CertificateRequest) {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(ratls.OIDRATLSAttestation) {
			template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
				Id:    ext.Id,
				Value: ext.Value,
			})
			return
		}
	}
}
