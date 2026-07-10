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

// peerVerifier derives an attestation-rooted PeerIdentity from a verified TLS
// connection, according to the configured --peer-verify mode.
type peerVerifier struct {
	mode   string
	policy *ratls.VerifyPolicy // ratls mode only
}

// buildServerTLS constructs the broker's TLS config and the matching
// peerVerifier. The server certificate is always loaded from files (in-cluster:
// the injected get-cert sidecar's c8s-certs tmpfs; demo: a generated cert), so
// stock agents trust the broker via their configured CA bundle. The two modes
// differ only in how the *caller's* client cert is verified.
func buildServerTLS(cfg config) (*tls.Config, *peerVerifier, error) {
	srvCert, err := tls.LoadX509KeyPair(cfg.tlsCert, cfg.tlsKey)
	if err != nil {
		return nil, nil, fmt.Errorf("load server cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		MinVersion:   tls.VersionTLS13,
	}

	switch cfg.peerVerify {
	case peerVerifyCA:
		pool, err := loadCAPool(cfg.clientCA)
		if err != nil {
			return nil, nil, err
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		return tlsCfg, &peerVerifier{mode: peerVerifyCA}, nil

	case peerVerifyRATLS:
		ms, err := parseMeasurementsBytes(cfg.measurements)
		if err != nil {
			return nil, nil, fmt.Errorf("--measurements: %w", err)
		}
		policy := &ratls.VerifyPolicy{Measurements: ms, AttestationApiURL: cfg.attestationApiURL}
		// Enforce attestation at the handshake; the handler re-derives the
		// measurement value from the (already-verified) peer cert.
		tlsCfg.ClientAuth = tls.RequireAnyClientCert
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("secret-broker: no client certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("secret-broker: parse client cert: %w", err)
			}
			if _, err := ratls.VerifyCert(cert, policy, nil); err != nil {
				return fmt.Errorf("secret-broker: client attestation failed: %w", err)
			}
			return nil
		}
		return tlsCfg, &peerVerifier{mode: peerVerifyRATLS, policy: policy}, nil

	default:
		return nil, nil, fmt.Errorf("--peer-verify must be %q or %q, got %q", peerVerifyRATLS, peerVerifyCA, cfg.peerVerify)
	}
}

// Identity derives the caller's PeerIdentity from an already-handshaked
// request. It must only be called for requests that presented a verified
// client certificate (the TLS config guarantees this).
func (v *peerVerifier) Identity(r *http.Request) (PeerIdentity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return PeerIdentity{}, fmt.Errorf("no client certificate")
	}
	cert := r.TLS.PeerCertificates[0]

	id := PeerIdentity{WorkloadID: workloadIDFromCert(cert)}
	if v.mode == peerVerifyRATLS {
		res, err := ratls.VerifyCert(cert, v.policy, nil)
		if err != nil {
			return PeerIdentity{}, fmt.Errorf("verify client attestation: %w", err)
		}
		id.Measurement = hex.EncodeToString(res.Measurement[:])
	}
	return id, nil
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
		return nil, fmt.Errorf("--peer-verify=ca requires --client-ca")
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
