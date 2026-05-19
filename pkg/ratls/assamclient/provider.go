package assamclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/ratls"
)

// Logger is a type alias for [ratls.Logger] to avoid requiring callers
// to import both packages.
type Logger = ratls.Logger

// Provider implements ratls.CertProvider using assam attestation and the
// cert-issuer sidecar. Each Provision call performs:
// authenticate -> attest -> obtain cert and authenticated CA bundle -> return
// CA-signed certificate.
type Provider struct {
	client *Client
	logger Logger
}

// Ensure Provider implements CertProvider at compile time.
var _ ratls.CertProvider = (*Provider)(nil)

// NewProvider creates an assam-backed CertProvider.
func NewProvider(cfg *Config, logger Logger) (*Provider, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return NewProviderWithClient(NewClient(cfg), logger)
}

// NewProviderWithClient creates an assam-backed CertProvider using an existing
// Client. Reusing the client lets certificate provisioning seed the CA trust
// state that later /ca refreshes continuity-check.
func NewProviderWithClient(client *Client, logger Logger) (*Provider, error) {
	if client == nil || client.cfg == nil {
		return nil, fmt.Errorf("assamclient: client is required")
	}
	if err := validateConfig(client.cfg); err != nil {
		return nil, err
	}

	return &Provider{
		client: client,
		logger: logger,
	}, nil
}

func validateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("assamclient: Config is required")
	}
	if cfg.AssamURL == "" {
		return fmt.Errorf("assamclient: AssamURL is required")
	}
	if cfg.AttestationServiceURL == "" {
		return fmt.Errorf("assamclient: AttestationServiceURL is required")
	}
	if cfg.CertIssuerURL == "" {
		return fmt.Errorf("assamclient: CertIssuerURL is required")
	}
	if cfg.NodeIP == "" {
		return fmt.Errorf("assamclient: NodeIP is required")
	}
	if net.ParseIP(cfg.NodeIP) == nil {
		return fmt.Errorf("assamclient: NodeIP %q is not a valid IP address", cfg.NodeIP)
	}
	if _, err := cfg.teeType(); err != nil {
		return err
	}

	return nil
}

// Provision performs the full assam attestation flow and returns a CA-signed
// TLS certificate along with its effective TTL.
func (p *Provider) Provision(ctx context.Context) (*tls.Certificate, time.Duration, error) {
	if p.logger != nil {
		p.logger.Info("assamclient: requesting assam-issued certificate")
	}

	key, certPEM, caCertPEM, err := p.client.RequestCert(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("assamclient: request cert: %w", err)
	}

	cert, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, 0, fmt.Errorf("assamclient: parse issued cert: %w", err)
	}
	if !certificateMatchesPrivateKey(cert, key) {
		return nil, 0, fmt.Errorf("assamclient: issued cert public key does not match generated private key")
	}

	// Parse CA bundle from Assam's signed certificate response. This is the
	// authenticated trust seed; unauthenticated /ca polling only runs after
	// this bundle is established.
	caCerts, err := certutil.ParsePEMCertificates(caCertPEM)
	if err != nil {
		return nil, 0, fmt.Errorf("assamclient: parse CA cert: %w", err)
	}

	// Verify the issued certificate against the first CA in Assam's ordered
	// response before using it as a trust seed. Retained parents are accepted
	// only when they directly sign an accepted CA without reusing that child
	// CA's public key.
	now := time.Now()
	trustSeed, err := verifiedInitialCABundle(cert, caCerts, now)
	if err != nil {
		return nil, 0, fmt.Errorf("assamclient: issued cert does not chain to CA: %w", err)
	}

	trustedCAs := p.client.rememberVerifiedCABundle(trustSeed, caCerts, now)
	if len(trustedCAs) == 0 {
		return nil, 0, fmt.Errorf("assamclient: issued cert verification produced no trusted CA")
	}

	chain := [][]byte{cert.Raw}
	for _, ca := range trustedCAs {
		chain = append(chain, ca.Raw)
	}

	tlsCert := &tls.Certificate{
		Certificate: chain,
		PrivateKey:  key,
		Leaf:        cert,
	}

	ttl := time.Until(cert.NotAfter)
	if ttl <= 0 {
		return nil, 0, fmt.Errorf("assamclient: issued certificate already expired")
	}

	if p.logger != nil {
		p.logger.Info("assamclient: certificate provisioned",
			"subject", cert.Subject.CommonName,
			"ttl", ttl.Round(time.Second),
			"notAfter", cert.NotAfter,
		)
	}

	return tlsCert, ttl, nil
}

func verifiedInitialCABundle(cert *x509.Certificate, caCerts []*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("CA bundle is empty")
	}

	signer := caCerts[0]
	if !isUsableCA(signer, now) {
		return nil, fmt.Errorf("first CA in bundle is not usable")
	}
	if err := cert.CheckSignatureFrom(signer); err != nil {
		return nil, err
	}

	return growAcceptedByLink([]*x509.Certificate{signer}, caCerts[1:], nil, now, certSignsOther), nil
}

func certificateMatchesPrivateKey(cert *x509.Certificate, key *ecdsa.PrivateKey) bool {
	if cert == nil || key == nil {
		return false
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && key.PublicKey.Equal(pub)
}
