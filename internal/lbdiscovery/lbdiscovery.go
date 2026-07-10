// Package lbdiscovery consumes the tls-lb front-door discovery contract
// (types.DiscoveryDocument, served at /v1/discovery, written by get-cert).
// The front door's serving cert carries no RA-TLS extension; its trust path is
// the discovery document instead: attestation evidence captured at issuance,
// with REPORTDATA binding the serving-cert key + issuance challenge
// (ratls.ReportDataForKey).
//
// Serving certs are per replica (each tls-lb pod provisions its own leaf into
// a pod-local emptyDir), so evidence fetched on one connection says nothing
// about the leaf a *different* connection would be served — a scaled-out or
// rolling Service can answer alternating handshakes with alternating certs.
// This package therefore dials the front door exactly once, fetches and
// verifies the document over that connection, requires the attested cert to
// be the leaf that same handshake presented, and returns an HTTP client bound
// to that one verified connection. The client never redials: a lost
// connection fails closed with a re-run hint. Per-connection re-verification
// is the eventual replacement for this single-connection model.
//
// `c8s verify` consumes the same contract with an in-process verifier
// (internal/cmds/verify/discovery.go).
package lbdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// DefaultPath is the path the tls-lb serves its discovery document on.
const DefaultPath = "/v1/discovery"

// maxDocumentBytes caps the discovery document read.
const maxDocumentBytes = 1 << 20

// ErrNoDiscovery reports that the target serves no discovery document
// (unreachable, or a non-200 on the discovery path). Callers use it to fall
// back to direct RA-TLS serving-cert verification
// (ratls.NewVerifyingHTTPClient). A document that is present but malformed or
// failing verification is NOT this error — those fail closed.
var ErrNoDiscovery = errors.New("lbdiscovery: target serves no discovery document")

// NewVerifiedHTTPClient returns an http.Client for a tls-lb front door: it
// dials base once, fetches the discovery document over that connection,
// verifies the embedded attestation evidence via the attestation-api (launch
// measurement checked against measurements — empty accepts any, UNSAFE), and
// requires the attested serving certificate to be the leaf the connection's
// handshake presented. The returned client is bound to that single verified
// connection (requests are serialized over it) and only for base's host; it
// never redials, so a lost connection fails closed — see the package comment
// for why (per-replica serving certs).
//
// Returns [ErrNoDiscovery] when base serves no discovery document, so callers
// can fall back to direct RA-TLS verification for a non-fronted endpoint.
//
// The issuance challenge is fixed, not a per-request nonce, so freshness is
// not proven — the same trade-off as `c8s verify` discovery mode.
func NewVerifiedHTTPClient(ctx context.Context, base string, measurements [][]byte, attestationApiURL string) (*http.Client, error) {
	if attestationApiURL == "" {
		return nil, fmt.Errorf("lbdiscovery: attestation-api URL is required")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse url %q: %w", base, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("lbdiscovery: URL scheme must be https, got %q", u.Scheme)
	}

	conn, err := dialFrontDoor(ctx, u.Host)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s: %v", ErrNoDiscovery, u.Host, err)
	}
	client := newSingleConnClient(conn)
	verified := false
	defer func() {
		if !verified {
			conn.Close()
		}
	}()

	data, err := fetchDocument(ctx, client, u)
	if err != nil {
		return nil, err
	}
	cert, err := verifyDocument(ctx, data, attestationclient.NewClient(attestationApiURL), measurements)
	if err != nil {
		return nil, fmt.Errorf("lbdiscovery: discovery document verification failed: %w", err)
	}

	// The evidence binds cert's key; require cert to be the leaf THIS
	// connection presented, or the attestation says nothing about the peer we
	// are talking to (a different replica may have answered the handshake).
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return nil, fmt.Errorf("lbdiscovery: connection presented no peer certificate")
	}
	if !bytes.Equal(peers[0].Raw, cert.Raw) {
		docSum := sha256.Sum256(cert.Raw)
		connSum := sha256.Sum256(peers[0].Raw)
		return nil, fmt.Errorf("lbdiscovery: discovery document attests serving cert sha256 %s but the connection presented %s — a different tls-lb replica may have answered; re-run the command",
			hex.EncodeToString(docSum[:]), hex.EncodeToString(connSum[:]))
	}

	verified = true
	return client, nil
}

// dialFrontDoor opens the one TLS connection the returned client will use.
// PKI is intentionally not verified — the trust anchor is the attestation in
// the discovery document, which NewVerifiedHTTPClient binds to this
// connection's leaf after the fetch.
func dialFrontDoor(ctx context.Context, host string) (*tls.Conn, error) {
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, //nolint:gosec // attestation, not PKI, authenticates the peer; see dialFrontDoor doc
		},
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

// fetchDocument GETs the discovery document through the connection-bound
// client. Fetch failures wrap [ErrNoDiscovery].
func fetchDocument(ctx context.Context, client *http.Client, base *url.URL) ([]byte, error) {
	u := *base
	u.Path = DefaultPath
	u.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: GET %s: %v", ErrNoDiscovery, u.String(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GET %s returned %d", ErrNoDiscovery, u.String(), resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return nil, fmt.Errorf("read discovery document: %w", err)
	}
	return data, nil
}

// verifyDocument parses a discovery document, verifies its attestation
// evidence via the attestation-api, and returns the attested serving
// certificate. REPORTDATA = SHA-384(cert pubkey ‖ challenge), matching
// get-cert's issuance binding (reportDataForCSR → ratls.ReportDataForKey).
func verifyDocument(ctx context.Context, data []byte, api attestationclient.Client, measurements [][]byte) (*x509.Certificate, error) {
	var d types.DiscoveryDocument
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}

	// Only a cds-mode front door serves the CDS-issued leaf the evidence
	// binds; empty means a pre-mode-field document (cds in practice). Anything
	// else fails closed here rather than returning a client whose handshakes
	// can never match the attested cert.
	switch d.PublicTLS.Mode {
	case "", "cds":
	case "webpki":
		return nil, fmt.Errorf("front door public_tls.mode=webpki is not supported: it serves an operator WebPKI certificate this client cannot yet bind to the attestation evidence; use a cds-mode front door or port-forward CDS directly")
	default:
		return nil, fmt.Errorf("unknown public_tls.mode %q in discovery document", d.PublicTLS.Mode)
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
		return nil, fmt.Errorf("parse serving cert: %w", err)
	}
	challenge, err := base64.StdEncoding.DecodeString(d.Attestation.Challenge)
	if err != nil {
		return nil, fmt.Errorf("decode challenge: %w", err)
	}
	erd, err := ratls.ReportDataForKey(cert.PublicKey, challenge)
	if err != nil {
		return nil, fmt.Errorf("compute expected REPORTDATA: %w", err)
	}

	// Empty platform defaults to bare-metal snp (pre-platform-field carriers);
	// a genuinely unknown platform fails closed in the verifier.
	envelope := types.AttestationEvidence{Platform: d.Attestation.Platform, Evidence: d.Attestation.Evidence}
	if envelope.Platform == "" {
		envelope.Platform = string(types.PlatformSnp)
	}
	if _, err := api.VerifyEvidence(ctx, envelope, attestationclient.EvidencePolicy{
		ExpectedReportData: erd,
		Measurements:       measurements,
	}); err != nil {
		return nil, err
	}
	return cert, nil
}

// newSingleConnClient returns an http.Client whose transport hands out exactly
// conn (MaxConnsPerHost=1 serializes requests over it) and never dials again:
// the attestation verified one handshake, and a new handshake could reach a
// different tls-lb replica whose leaf that evidence does not cover. A lost
// connection — server keepalive close, idle eviction, cert rotation — fails
// closed with a re-run hint. Timeout knobs mirror ratls.NewVerifyingHTTPClient.
func newSingleConnClient(conn *tls.Conn) *http.Client {
	var used atomic.Bool
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				if used.Swap(true) {
					return nil, errors.New("lbdiscovery: the attested connection was lost and redialing could reach a different tls-lb replica; re-run the command to attest a fresh connection")
				}
				return conn, nil
			},
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          1,
			MaxConnsPerHost:       1,
		},
	}
}
