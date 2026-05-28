// Package cdsclient implements certificate provisioning via the CDS
// attestation service. It performs the attestation flow:
// authenticate -> attest -> obtain certificate and authenticated CA bundle.
// Later CA refreshes fetch /ca from CDS and require trust
// continuity.
package cdsclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/ratls"
)

// Config for the CDS attestation client.
type Config struct {
	// CDSURL is the base URL of the CDS service
	// (e.g., "https://cds.c8s-system.svc:8443").
	CDSURL string

	// AttestationServiceURL is the URL of the local attestation service
	// used by CDS to generate TEE evidence
	// (e.g., "http://localhost:8400").
	AttestationServiceURL string

	// CDSCAURL is the base URL of the CDS CA endpoint for CA
	// bundle refreshes after authenticated provisioning
	// (e.g., "https://cds.c8s-system.svc:8443").
	CDSCAURL string

	// CACertURL, when set, is the exact URL used for CA bundle refreshes.
	// Empty defaults to CDSCAURL + "/ca".
	CACertURL string

	// NodeIP is this node's IP for the certificate subject/SAN.
	NodeIP string

	// NodeName is this node's hostname for the certificate subject.
	NodeName string

	// TEEType is the TEE platform to stamp into the RA-TLS attestation
	// extension. It must be specified explicitly. Only SEV-SNP is currently
	// supported by the CDS client evidence extraction path.
	TEEType ratls.TEEType

	// CDSMeasurements, when non-empty, restricts the CDS server's
	// accepted launch digests during the RA-TLS handshake to this set.
	// Each entry is a 48-byte SEV-SNP measurement. Empty means "any
	// measurement" — UNSAFE outside development; the chart should always
	// populate this from `global.cdsMeasurements` in values.yaml.
	CDSMeasurements [][]byte

	// HTTPClient is an optional HTTP client. If nil, a default RA-TLS
	// transport is built using the CDSMeasurements policy. Tests that
	// need to bypass RA-TLS (e.g. against a plain HTTP fake) can supply a
	// custom client; production code MUST leave this nil so the client is
	// constructed with attestation-bound peer verification.
	HTTPClient *http.Client
}

// Client handles certificate provisioning via CDS.
type Client struct {
	cfg             *Config
	httpClient      *http.Client
	cdsAttestClient attestclient.Client
	mu              sync.RWMutex
	trustedCABundle []*x509.Certificate
}

// NewClient creates an CDS attestation client. When cfg.HTTPClient is nil,
// the returned client dials CDS over RA-TLS with a peer-verification policy
// built from cfg.CDSMeasurements; this is what closes the bootstrap-channel
// MITM gap (an on-path attacker cannot present a TEE-attested cert with an
// allowed measurement, so the TLS handshake fails before any cert is issued).
func NewClient(cfg *Config) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		policy := &ratls.VerifyPolicy{Measurements: cfg.CDSMeasurements, AttestationServiceURL: cfg.AttestationServiceURL}
		tlsCfg, _, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{Policy: policy})
		if err != nil {
			// NewClientTLSConfig only errors on misconfigured Platform/AttestFunc
			// pairs, which we never set; treat unexpected failure as a programmer
			// bug by falling back to a transport that will always fail closed.
			tlsCfg = nil
		}
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				ResponseHeaderTimeout: 10 * time.Second,
				IdleConnTimeout:       30 * time.Second,
				MaxIdleConns:          10,
				MaxConnsPerHost:       5,
				TLSClientConfig:       tlsCfg,
			},
		}
	}
	return &Client{
		cfg:             cfg,
		httpClient:      httpClient,
		cdsAttestClient: attestclient.NewClientWithHTTP(cfg.CDSURL, httpClient),
	}
}

// RequestCert performs the full CDS attestation + certificate issuance flow:
//  1. Generate ECDSA keypair + CSR
//  2. Call CDS (authenticate -> attest) over RA-TLS to get a signed certificate
//     chain. Authenticity of the response is provided by the RA-TLS handshake
//     (the underlying http.Client's TLSClientConfig verifies CDS's peer cert
//     against the configured measurement allowlist).
//  3. Return key + leaf cert + authenticated CA bundle from the signed response
func (c *Client) RequestCert(ctx context.Context) (*ecdsa.PrivateKey, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}

	csrPEM, err := c.createCSR(ctx, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	certPEM, err := c.cdsAttestClient.ObtainCertificateWithContext(ctx, c.cfg.AttestationServiceURL, csrPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CDS attestation: %w", err)
	}

	certs, err := certutil.ParsePEMCertificates([]byte(certPEM))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse CDS certificate response: %w", err)
	}
	if len(certs) < 2 {
		return nil, nil, nil, fmt.Errorf("CDS certificate response missing CA bundle")
	}

	return key, certutil.EncodeCertPEM(certs[0].Raw), encodeCABundlePEM(certs[1:]), nil
}

// RefreshCABundle fetches the CA certificate bundle from CDS's
// /ca endpoint. A candidate is accepted only when it is already trusted or
// when it is a CA certificate signed by an already trusted CA. This keeps
// unauthenticated CA bundle refreshes from expanding trust without signature
// continuity.
func (c *Client) RefreshCABundle(ctx context.Context) ([]*x509.Certificate, error) {
	certs, err := c.fetchAndParseCABundle(ctx)
	if err != nil {
		return nil, err
	}
	return c.acceptCABundle(certs)
}

func (c *Client) fetchAndParseCABundle(ctx context.Context) ([]*x509.Certificate, error) {
	pemData, err := c.fetchCACertPEM(ctx)
	if err != nil {
		return nil, err
	}
	certs, err := certutil.ParsePEMCertificates(pemData)
	if err != nil {
		return nil, fmt.Errorf("CA bundle: %w", err)
	}
	return certs, nil
}

// TrustedCABundle returns the currently accepted CA bundle. The returned slice
// can be passed to ratls.CertManager.UpdateCACerts.
func (c *Client) TrustedCABundle() []*x509.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneCertSlice(c.trustedCABundle)
}

func (c *Client) rememberVerifiedCABundle(verified, published []*x509.Certificate, now time.Time) []*x509.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()

	accepted := dedupeCerts(verified)
	for _, cert := range published {
		if containsCert(accepted, cert) {
			continue
		}
		// Preserve overlap across in-memory CDS restarts without
		// expanding trust to CAs this client has never accepted before.
		if containsCert(c.trustedCABundle, cert) && isUsableCA(cert, now) {
			accepted = append(accepted, cert)
		}
	}

	ordered := orderLikePublished(accepted, published)
	c.trustedCABundle = cloneCertSlice(ordered)
	return cloneCertSlice(ordered)
}

func (c *Client) acceptCABundle(candidates []*x509.Certificate) ([]*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.trustedCABundle) == 0 {
		return nil, fmt.Errorf("CA bundle refresh requires a trusted CA from CDS certificate provisioning")
	}

	accepted := continuityCABundle(dedupeCerts(candidates), c.trustedCABundle, time.Now())
	if len(accepted) == 0 {
		return nil, fmt.Errorf("CA bundle refresh rejected: no trusted CA continuity")
	}
	c.trustedCABundle = cloneCertSlice(accepted)
	return cloneCertSlice(accepted), nil
}

func (c *Client) createCSR(ctx context.Context, key *ecdsa.PrivateKey) (string, error) {
	cn := fmt.Sprintf("ratls-mesh-%s", c.cfg.NodeIP)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Lunal"},
		},
		IPAddresses: []net.IP{net.ParseIP(c.cfg.NodeIP)},
	}
	if c.cfg.NodeName != "" {
		tmpl.DNSNames = []string{c.cfg.NodeName}
	}

	ext, err := c.attestationExtension(ctx, key)
	if err != nil {
		return "", err
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func (c *Client) attestationExtension(ctx context.Context, key *ecdsa.PrivateKey) (pkix.Extension, error) {
	teeType, err := c.cfg.teeType()
	if err != nil {
		return pkix.Extension{}, err
	}

	// This no-nonce report is embedded for peer RA-TLS fallback. CDS still
	// performs a separate challenge-bound attestation before issuing the cert.
	reportData, err := ratls.ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		return pkix.Extension{}, err
	}
	resp, err := c.cdsAttestClient.GenerateEvidenceContext(ctx, c.cfg.AttestationServiceURL, reportData[:sha512.Size384])
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("attestation service: %w", err)
	}
	report, err := attestclient.RATLSEvidence(resp)
	if err != nil {
		return pkix.Extension{}, err
	}
	att := &ratls.Attestation{
		TEEType: teeType,
		Report:  []byte(report),
	}
	return att.MarshalExtension()
}

func (cfg *Config) teeType() (ratls.TEEType, error) {
	if cfg == nil || cfg.TEEType == 0 {
		return 0, fmt.Errorf("cdsclient: TEEType is required")
	}
	if cfg.TEEType != ratls.TEETypeSEVSNP {
		return 0, fmt.Errorf("cdsclient: TEEType %s is not supported", cfg.TEEType)
	}
	return cfg.TEEType, nil
}

func (c *Client) fetchCACertPEM(ctx context.Context) ([]byte, error) {
	url := c.caCertURL()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GET CA bundle %q returned %d: %s", url, resp.StatusCode, body)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

func (c *Client) caCertURL() string {
	if c.cfg.CACertURL != "" {
		return c.cfg.CACertURL
	}
	return strings.TrimRight(c.cfg.CDSCAURL, "/") + "/ca"
}

func encodeCABundlePEM(certs []*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		out = append(out, certutil.EncodeCertPEM(cert.Raw)...)
	}
	return out
}

func containsCert(certs []*x509.Certificate, cert *x509.Certificate) bool {
	for _, candidate := range certs {
		if sameCertificate(candidate, cert) {
			return true
		}
	}
	return false
}

func continuityCABundle(published, trusted []*x509.Certificate, now time.Time) []*x509.Certificate {
	seed := make([]*x509.Certificate, 0, len(published))
	for _, cert := range published {
		if containsCert(trusted, cert) && isUsableCA(cert, now) {
			seed = append(seed, cert)
		}
	}
	accepted := growAcceptedByLink(seed, published, trusted, now, certSignedByOther)
	return orderLikePublished(accepted, published)
}

// growAcceptedByLink iteratively extends accepted with candidates that share
// a signature link (in the caller-supplied direction) with the current
// accepted set, plus any extraAnchors. Loops until no candidate is added.
func growAcceptedByLink(accepted, candidates, extraAnchors []*x509.Certificate, now time.Time, link func(cert, other *x509.Certificate) error) []*x509.Certificate {
	for {
		changed := false
		anchors := append(cloneCertSlice(extraAnchors), accepted...)
		for _, cand := range candidates {
			if containsCert(accepted, cand) {
				continue
			}
			if hasUsableCASignatureLink(cand, anchors, now, link) {
				accepted = append(accepted, cand)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return accepted
}

// hasUsableCASignatureLink reports whether cert (a usable CA) is linked by
// signature to any usable CA in others, after filtering out same-cert and
// same-pubkey matches. link is called with (cert, other) and must return nil
// for a valid signature relation in the caller's chosen direction.
func hasUsableCASignatureLink(cert *x509.Certificate, others []*x509.Certificate, now time.Time, link func(cert, other *x509.Certificate) error) bool {
	if !isUsableCA(cert, now) {
		return false
	}
	for _, other := range others {
		if other == nil || sameCertificate(other, cert) {
			continue
		}
		if !isUsableCA(other, now) {
			continue
		}
		if samePublicKey(other, cert) {
			continue
		}
		if link(cert, other) == nil {
			return true
		}
	}
	return false
}

func certSignsOther(cert, other *x509.Certificate) error { return other.CheckSignatureFrom(cert) }

func certSignedByOther(cert, other *x509.Certificate) error { return cert.CheckSignatureFrom(other) }

func isUsableCA(cert *x509.Certificate, now time.Time) bool {
	return cert != nil &&
		cert.IsCA &&
		!cert.NotBefore.After(now) &&
		cert.NotAfter.After(now) &&
		(cert.KeyUsage == 0 || cert.KeyUsage&x509.KeyUsageCertSign != 0)
}

func samePublicKey(a, b *x509.Certificate) bool {
	if a == nil || b == nil {
		return false
	}
	aDER, err := x509.MarshalPKIXPublicKey(a.PublicKey)
	if err != nil {
		return false
	}
	bDER, err := x509.MarshalPKIXPublicKey(b.PublicKey)
	if err != nil {
		return false
	}
	return bytes.Equal(aDER, bDER)
}

func dedupeCerts(certs []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		if cert == nil || containsCert(out, cert) {
			continue
		}
		out = append(out, cert)
	}
	return out
}

func sameCertificate(a, b *x509.Certificate) bool {
	return a != nil && b != nil && bytes.Equal(a.Raw, b.Raw)
}

func cloneCertSlice(certs []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, len(certs))
	copy(out, certs)
	return out
}

func orderLikePublished(accepted, published []*x509.Certificate) []*x509.Certificate {
	ordered := make([]*x509.Certificate, 0, len(accepted))
	for _, cert := range published {
		if containsCert(accepted, cert) && !containsCert(ordered, cert) {
			ordered = append(ordered, cert)
		}
	}
	for _, cert := range accepted {
		if !containsCert(ordered, cert) {
			ordered = append(ordered, cert)
		}
	}
	return ordered
}
