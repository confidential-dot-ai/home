package attestclient

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/types"
)

// Client is a high-level client for the CDS attestation flow.
// It handles the full challenge-attest-certify flow in a single call.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// CertificateResult is the complete CDS challenge/attest/certify result.
// Certificate is the PEM chain issued by CDS. Challenge, Platform, and
// Evidence are the attestation material that authorized issuance.
//
// Authenticity of Certificate on the network path is provided by the RA-TLS
// handshake the caller performed against CDS (see pkg/ratls.NewClientTLSConfig);
// callers MUST construct this client over an RA-TLS-verified transport.
type CertificateResult struct {
	Certificate string
	Challenge   string
	Platform    string
	Evidence    json.RawMessage
}

// NewClient creates a new attestation flow client.
func NewClient(baseURL string) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
	}
}

// NewClientWithHTTP creates a new client with a custom HTTP client.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

// GenerateEvidence calls the local attestation service to generate TEE evidence
// for the given report data. This is the same attestation service call used
// internally by ObtainCertificate, exposed for callers that need evidence
// without the full CDS challenge-attest-certify flow.
func (c Client) GenerateEvidence(attestationServiceURL string, reportData []byte) (types.AttestResponse, error) {
	return c.GenerateEvidenceContext(context.Background(), attestationServiceURL, reportData)
}

// GenerateEvidenceContext is GenerateEvidence with caller-controlled
// cancellation.
func (c Client) GenerateEvidenceContext(ctx context.Context, attestationServiceURL string, reportData []byte) (types.AttestResponse, error) {
	asClient := attestationclient.NewClientWithHTTP(attestationServiceURL, c.httpClient)
	return asClient.Attest(contextOrBackground(ctx), types.AttestRequest{
		ReportData: types.NewBase64Bytes(reportData),
		Platform:   types.PlatformAuto,
	})
}

// ObtainCertificate performs the full attestation flow and returns a signed
// certificate chain.
//
// It:
//  1. Requests a challenge nonce from CDS (POST /authenticate)
//  2. Passes SHA-384(CSR public key || challenge) as report_data to the
//     local attestation service (POST /attest)
//  3. Submits the evidence and caller-provided CSR to CDS (POST /attest)
//     which verifies the evidence and returns a signed certificate chain
func (c Client) ObtainCertificate(attestationServiceURL, csrPEM string) (string, error) {
	return c.ObtainCertificateWithContext(context.Background(), attestationServiceURL, csrPEM)
}

// ObtainCertificateWithContext is ObtainCertificate with caller-controlled
// cancellation.
func (c Client) ObtainCertificateWithContext(ctx context.Context, attestationServiceURL, csrPEM string) (string, error) {
	result, err := c.ObtainCertificateWithEvidenceContext(ctx, attestationServiceURL, csrPEM)
	if err != nil {
		return "", err
	}
	return result.Certificate, nil
}

// ObtainCertificateWithEvidence performs the full attestation flow and returns
// both the issued certificate chain and the evidence used to obtain it.
func (c Client) ObtainCertificateWithEvidence(attestationServiceURL, csrPEM string) (CertificateResult, error) {
	return c.ObtainCertificateWithEvidenceContext(context.Background(), attestationServiceURL, csrPEM)
}

// ObtainCertificateWithEvidenceContext is ObtainCertificateWithEvidence with
// caller-controlled cancellation across authenticate, local attest, and CDS
// attest requests.
func (c Client) ObtainCertificateWithEvidenceContext(ctx context.Context, attestationServiceURL, csrPEM string) (CertificateResult, error) {
	ctx = contextOrBackground(ctx)

	// Step 1: get challenge from CDS
	challengeResp, err := c.AuthenticateContext(ctx)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("authenticate: %w", err)
	}

	// Step 2: generate TEE evidence bound to the CSR public key and challenge.
	challengeBytes, err := base64.StdEncoding.DecodeString(challengeResp.Challenge)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("invalid base64 in challenge: %w", err)
	}

	reportData, err := reportDataForCSR(csrPEM, challengeBytes)
	if err != nil {
		return CertificateResult{}, err
	}

	asResp, err := c.GenerateEvidenceContext(ctx, attestationServiceURL, reportData)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("attestation service: %w", err)
	}

	// Step 3: submit evidence + CSR to CDS for verification and cert issuance.
	// asResp.Evidence is the platform-specific evidence object as emitted by
	// /attest; CDS's /attest expects it wrapped in an AttestationEvidence
	// envelope keyed by Platform.
	attestReq := attestRequest{
		Challenge: challengeResp.Challenge,
		Evidence: attestEvidence{
			Platform: asResp.Platform,
			Evidence: asResp.Evidence,
		},
		CSR: csrPEM,
	}
	certPEM, err := c.AttestContext(ctx, attestReq)
	if err != nil {
		return CertificateResult{}, err
	}

	return CertificateResult{
		Certificate: certPEM,
		Challenge:   challengeResp.Challenge,
		Platform:    asResp.Platform,
		Evidence:    asResp.Evidence,
	}, nil
}

// AttestKey performs the attestation flow for an in-process ECDSA key:
//  1. Requests a challenge nonce from CDS (POST /authenticate)
//  2. Calls the local attestation service for evidence binding
//     SHA-384(pubkey || challenge) into REPORTDATA
//  3. Submits evidence + the PKIX-DER pubkey to CDS (POST /attest-key) and
//     returns the signed EAR JWT
//
// Used by in-cluster c8s components (CDS for its handoff signer key
// bootstrap) that need a CDS-issued EAR bound to a key they hold in
// memory, without going through the cert-issuance flow.
func (c Client) AttestKey(ctx context.Context, attestationServiceURL string, pubKeyDER []byte) (string, error) {
	ctx = contextOrBackground(ctx)

	challengeResp, err := c.AuthenticateContext(ctx)
	if err != nil {
		return "", fmt.Errorf("authenticate: %w", err)
	}
	challengeBytes, err := base64.StdEncoding.DecodeString(challengeResp.Challenge)
	if err != nil {
		return "", fmt.Errorf("invalid base64 in challenge: %w", err)
	}

	pubAny, err := x509.ParsePKIXPublicKey(pubKeyDER)
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	reportData, err := ratls.ReportDataForKey(pubAny, challengeBytes)
	if err != nil {
		return "", err
	}

	asResp, err := c.GenerateEvidenceContext(ctx, attestationServiceURL, reportData[:sha512.Size384])
	if err != nil {
		return "", fmt.Errorf("attestation service: %w", err)
	}

	body, err := json.Marshal(types.AttestKeyRequestBody{
		Challenge: challengeResp.Challenge,
		Evidence:  types.AttestationEvidence(asResp),
		PublicKey: base64.StdEncoding.EncodeToString(pubKeyDER),
	})
	if err != nil {
		return "", err
	}

	url := c.baseURL + "/attest-key"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(httpResp.Body)
		return "", &StatusError{Status: httpResp.StatusCode, Body: string(respBody)}
	}

	var out types.AttestKeyResponseBody
	if err := json.NewDecoder(httpResp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if out.EAR == "" {
		return "", fmt.Errorf("response missing ear")
	}
	return out.EAR, nil
}

// Authenticate requests an attestation challenge nonce.
func (c Client) Authenticate() (types.ChallengeResponse, error) {
	return c.AuthenticateContext(context.Background())
}

// AuthenticateContext requests an attestation challenge nonce with
// caller-controlled cancellation.
func (c Client) AuthenticateContext(ctx context.Context) (types.ChallengeResponse, error) {
	url := c.baseURL + "/authenticate"
	httpReq, err := http.NewRequestWithContext(contextOrBackground(ctx), http.MethodPost, url, nil)
	if err != nil {
		return types.ChallengeResponse{}, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return types.ChallengeResponse{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return types.ChallengeResponse{}, &StatusError{Status: resp.StatusCode, Body: string(body)}
	}

	var result types.ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return types.ChallengeResponse{}, err
	}
	return result, nil
}

type attestRequest struct {
	Challenge string         `json:"challenge"`
	Evidence  attestEvidence `json:"evidence"`
	CSR       string         `json:"csr"`
}

type attestEvidence struct {
	Platform string          `json:"platform"`
	Evidence json.RawMessage `json:"evidence"`
}

// Attest submits attestation evidence and receives a signed certificate chain
// PEM.
func (c Client) Attest(req attestRequest) (string, error) {
	return c.AttestContext(context.Background(), req)
}

// AttestContext submits attestation evidence with caller-controlled
// cancellation.
func (c Client) AttestContext(ctx context.Context, req attestRequest) (string, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	url := c.baseURL + "/attest"
	httpReq, err := http.NewRequestWithContext(contextOrBackground(ctx), http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", &StatusError{Status: resp.StatusCode, Body: string(body)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// Healthz checks liveness of the CDS service.
func (c Client) Healthz() (bool, error) {
	url := c.baseURL + "/healthz"
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// Readyz checks readiness of the CDS service.
func (c Client) Readyz() (bool, error) {
	url := c.baseURL + "/readyz"
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

func contextOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func reportDataForCSR(csrPEM string, challenge []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("CSR must be a PEM-encoded certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	reportData, err := ratls.ReportDataForKey(csr.PublicKey, challenge)
	if err != nil {
		return nil, err
	}
	out := make([]byte, sha512.Size384)
	copy(out, reportData[:sha512.Size384])
	return out, nil
}

// StatusError represents a non-success HTTP response.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Body)
}
