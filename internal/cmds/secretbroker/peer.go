package secretbroker

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// peerVerifier derives a CDS-rooted PeerIdentity from a verified caller TLS
// connection. CDS is the single trust root: the caller's mesh leaf is
// chain-verified against the CDS mesh CA, and identity is read from the leaf
// (SAN + CDS-vouched config-claims). CDS verified the caller's attestation at
// issuance, so the broker does not re-verify hardware evidence at the handshake.
type peerVerifier struct{}

// buildServerTLS constructs the broker's TLS config and the peerVerifier. The
// server certificate is always loaded from files (in-cluster: the injected
// get-cert sidecar's c8s-certs tmpfs; demo: a generated cert), so stock agents
// trust the broker via their configured CA bundle. Callers are verified by
// X.509 chain to the CDS mesh CA (--client-ca).
func buildServerTLS(cfg config) (*tls.Config, *peerVerifier, error) {
	srvCert, err := tls.LoadX509KeyPair(cfg.tlsCert, cfg.tlsKey)
	if err != nil {
		return nil, nil, fmt.Errorf("load server cert: %w", err)
	}

	pool, err := loadCAPool(cfg.clientCA)
	if err != nil {
		return nil, nil, err
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	return tlsCfg, &peerVerifier{}, nil
}

// Identity derives the caller's PeerIdentity from an already-handshaked request.
// It must only be called for requests that presented a verified client
// certificate (the TLS config guarantees this). RequireAndVerifyClientCert
// chain-verified the leaf against the mesh CA, so both the SAN and the
// config-claims extension are CDS-vouched.
func (v *peerVerifier) Identity(r *http.Request) (PeerIdentity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return PeerIdentity{}, fmt.Errorf("no client certificate")
	}
	cert := r.TLS.PeerCertificates[0]

	var id PeerIdentity
	id.WorkloadID = workloadIDFromCert(cert)
	claims, err := ratls.PeerConfigClaims(r.TLS)
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("read peer config-claims: %w", err)
	}
	id.WorkloadDigest = workloadDigestFromClaims(claims)
	return id, nil
}

// workloadDigestFromClaims returns the attested combined workload digest from a
// peer's config-claims, or nil when there are no claims or the workload digest
// is the unset (all-zero) sentinel — e.g. a CDS serving/governance leaf that
// carries operator/seed digests but no workload. nil never matches a
// digest-scoped rule, so a claimless caller fails closed.
func workloadDigestFromClaims(c *ratls.ConfigClaims) []byte {
	if c == nil || isZeroDigest(c.WorkloadDigest) {
		return nil
	}
	return c.WorkloadDigest
}

// isZeroDigest reports whether b is empty or all-zero (the unset-claim sentinel).
func isZeroDigest(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// peerCertFP returns a hex SHA-256 over the caller's leaf client certificate,
// used to bind a minted token to the exact cert it was issued for. Returns
// false when no client certificate is present.
func peerCertFP(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:]), true
}

func workloadIDFromCert(cert *x509.Certificate) string {
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return cert.Subject.CommonName
}

func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, fmt.Errorf("--client-ca is required (the CDS mesh CA)")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --client-ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("--client-ca: no certificates parsed")
	}
	return pool, nil
}
