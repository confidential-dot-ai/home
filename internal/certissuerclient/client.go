package certissuerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lunal-dev/c8s/pkg/types"
)

// Client is an HTTP client for the cert-issuer service.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new cert-issuer client.
func NewClient(baseURL string) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
	}
}

// NewClientWithHTTP creates a new cert-issuer client with a custom HTTP client.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

// SignCSR signs a CSR with the cert-issuer, returning the signed certificate
// chain PEM.
func (c Client) SignCSR(ctx context.Context, earToken, csrPEM, ttl string) (string, error) {
	reqBody := types.SignCsrRequest{
		Ear: earToken,
		Csr: csrPEM,
		Ttl: ttl,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal sign-csr request: %w", err)
	}

	url := c.baseURL + "/sign-csr"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", &APIError{Status: resp.StatusCode, Body: string(respBody)}
	}

	var signResp types.SignCsrResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return "", err
	}

	cert, err := signResp.SignedCert()
	if err != nil {
		return "", fmt.Errorf("decode sign-csr response: %w", err)
	}
	return cert, nil
}

// Ready checks if the cert-issuer is ready (GET /ready).
func (c Client) Ready(ctx context.Context) (bool, error) {
	url := c.baseURL + "/ready"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// APIError represents a non-success response from the cert-issuer.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("cert-issuer returned %d: %s", e.Status, e.Body)
}
