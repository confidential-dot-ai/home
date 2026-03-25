package attestclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/types"
)

// Client is a high-level client for the assam attestation flow.
// It handles the full challenge-attest-certify flow in a single call.
type Client struct {
	baseURL                  string
	httpClient               *http.Client
	attestationServiceAPIKey string
}

// NewClient creates a new attestation flow client.
func NewClient(baseURL string) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
	}
}

// NewClientWithAPIKey creates a new client that passes an API key to the attestation service.
func NewClientWithAPIKey(baseURL, attestationServiceAPIKey string) Client {
	return Client{
		baseURL:                  strings.TrimRight(baseURL, "/"),
		httpClient:               http.DefaultClient,
		attestationServiceAPIKey: attestationServiceAPIKey,
	}
}

// NewClientWithHTTP creates a new client with a custom HTTP client.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

// NewClientWithHTTPAndAPIKey creates a new client with a custom HTTP client and attestation service API key.
func NewClientWithHTTPAndAPIKey(baseURL string, httpClient *http.Client, attestationServiceAPIKey string) Client {
	return Client{
		baseURL:                  strings.TrimRight(baseURL, "/"),
		httpClient:               httpClient,
		attestationServiceAPIKey: attestationServiceAPIKey,
	}
}

// GenerateEvidence calls the local attestation service to generate TEE evidence
// for the given report data. This is the same attestation service call used
// internally by ObtainCertificate, exposed for callers that need evidence
// without the full assam challenge-attest-certify flow.
func (c Client) GenerateEvidence(attestationServiceURL string, reportData []byte) (types.AttestResponse, error) {
	asClient := attestationclient.NewClientWithHTTPAndAPIKey(attestationServiceURL, c.httpClient, c.attestationServiceAPIKey)
	return asClient.Attest(c.ctx(), types.AttestRequest{
		ReportData: types.NewBase64Bytes(reportData),
		Platform:   types.PlatformAuto,
	})
}

// ObtainCertificate performs the full attestation flow and returns a signed certificate.
//
// It:
//  1. Requests a challenge nonce from assam (POST /authenticate)
//  2. Passes the challenge as report_data to the local attestation service (POST /attest)
//  3. Submits the evidence and caller-provided CSR to assam (POST /attest)
//     which verifies the evidence and returns a signed certificate
func (c Client) ObtainCertificate(attestationServiceURL, csrPEM string) (string, error) {
	// Step 1: get challenge from assam
	challengeResp, err := c.Authenticate()
	if err != nil {
		return "", fmt.Errorf("authenticate: %w", err)
	}

	// Step 2: generate TEE evidence using the challenge as report_data
	challengeBytes, err := base64.StdEncoding.DecodeString(challengeResp.Challenge)
	if err != nil {
		return "", fmt.Errorf("invalid base64 in challenge: %w", err)
	}

	asResp, err := c.GenerateEvidence(attestationServiceURL, challengeBytes)
	if err != nil {
		return "", fmt.Errorf("attestation service: %w", err)
	}

	// Step 3: submit evidence + CSR to assam for verification and cert issuance
	attestReq := attestRequest{
		Challenge: challengeResp.Challenge,
		Evidence: attestEvidence{
			Platform: asResp.Evidence.Platform,
			Evidence: asResp.Evidence.Evidence,
		},
		CSR: csrPEM,
	}
	return c.Attest(attestReq)
}

// Authenticate requests an attestation challenge nonce.
func (c Client) Authenticate() (types.ChallengeResponse, error) {
	url := c.baseURL + "/authenticate"
	resp, err := c.httpClient.Post(url, "", nil)
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

// Attest submits attestation evidence and receives a signed certificate PEM.
func (c Client) Attest(req attestRequest) (string, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	url := c.baseURL + "/attest"
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
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

// Healthz checks liveness of the assam service.
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

// Readyz checks readiness of the assam service.
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

func (c Client) ctx() context.Context {
	return context.Background()
}

// StatusError represents a non-success HTTP response.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Body)
}
