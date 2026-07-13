package verify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// defaultDiscoveryPath is the path the tls-lb serves its discovery document on.
const defaultDiscoveryPath = "/v1/discovery"

// gatherFromDiscovery fetches the tls-lb discovery document and builds evidence
// from the embedded attestation, bound to the CDS cert key + the issuance
// challenge. The challenge is fixed at issuance time, so this is NOT a freshness
// proof (fresh=false) — but it ships the VCEK, so it verifies offline.
func gatherFromDiscovery(ctx context.Context, base, path, serverName string, timeout time.Duration) (*evidence, error) {
	data, src, err := fetchDiscoveryDoc(ctx, base, path, serverName, timeout)
	if err != nil {
		return nil, err
	}
	return evidenceFromDiscovery(data, src)
}

// fetchDiscoveryDoc GETs the discovery document from a component's
// (unauthenticated) discovery endpoint and returns the raw bytes plus a
// human-readable source string. PKI is intentionally not verified — the trust
// anchor is the hardware attestation inside the document, checked downstream.
func fetchDiscoveryDoc(ctx context.Context, base, path, serverName string, timeout time.Duration) ([]byte, string, error) {
	if path == "" {
		path = defaultDiscoveryPath
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, "", fmt.Errorf("parse url %q: %w", base, err)
	}
	u.Path = path
	u.RawQuery = ""

	client := &http.Client{Timeout: timeout, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: serverName}, //nolint:gosec
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", &connectError{err: fmt.Errorf("GET %s: %w", u.String(), err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, "", &connectError{err: fmt.Errorf("GET %s returned %d: %s", u.String(), resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", &connectError{err: fmt.Errorf("read discovery: %w", err)}
	}
	return data, fmt.Sprintf("discovery document %s", u.String()), nil
}

// evidenceFromDiscovery parses a discovery document into verifiable evidence.
// REPORTDATA = SHA-384(cert pubkey ‖ challenge), matching get-cert's issuance
// binding (reportDataForCSR → ratls.ReportDataForKey).
func evidenceFromDiscovery(data []byte, source string) (*evidence, error) {
	var d types.DiscoveryDocument
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}
	if len(d.Attestation.Evidence) == 0 {
		return nil, fmt.Errorf("discovery document carries no attestation.evidence")
	}
	block, _ := pem.Decode([]byte(d.CDSTLS.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("discovery cds_tls.certificate_pem is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cds cert: %w", err)
	}
	challenge, err := base64.StdEncoding.DecodeString(d.Attestation.Challenge)
	if err != nil {
		return nil, fmt.Errorf("decode challenge: %w", err)
	}
	rd, err := ratls.ReportDataForKey(cert.PublicKey, challenge)
	if err != nil {
		return nil, fmt.Errorf("compute expected REPORTDATA: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return &evidence{
		platform:    platformOrDefault(d.Attestation.Platform),
		rawEvidence: d.Attestation.Evidence,
		erd:         keyAnchor(rd),
		fresh:       false,
		source:      source,
		certSHA256:  hex.EncodeToString(sum[:]),
		bindingNote: "REPORTDATA binds the CDS cert key + issuance challenge from the discovery doc (ships the VCEK; not a per-request nonce)",
	}, nil
}
