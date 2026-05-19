package attestationclient

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

// Client is an HTTP client for the external attestation service.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new attestation service client.
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

// Health calls GET /health on the attestation service.
func (c Client) Health(ctx context.Context) (types.HealthResponse, error) {
	var result types.HealthResponse
	if err := c.getJSON(ctx, "/health", &result); err != nil {
		return types.HealthResponse{}, err
	}
	return result, nil
}

// Attest calls POST /attest on the attestation service.
func (c Client) Attest(ctx context.Context, req types.AttestRequest) (types.AttestResponse, error) {
	var result types.AttestResponse
	if err := c.postJSON(ctx, "/attest", req, &result); err != nil {
		return types.AttestResponse{}, err
	}
	return result, nil
}

// Verify calls POST /verify on the attestation service.
func (c Client) Verify(ctx context.Context, req types.VerifyRequest) (types.VerifyResponse, error) {
	var result types.VerifyResponse
	if err := c.postJSON(ctx, "/verify", req, &result); err != nil {
		return types.VerifyResponse{}, err
	}
	return result, nil
}

func (c Client) getJSON(ctx context.Context, path string, out any) error {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	return c.doAndDecode(req, out)
}

func (c Client) postJSON(ctx context.Context, path string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	return c.doAndDecode(req, out)
}

func (c Client) doAndDecode(req *http.Request, out any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &RequestError{Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		var errResp types.ErrorResponse
		if json.Unmarshal(body, &errResp) == nil {
			return &APIError{Status: resp.StatusCode, Response: errResp}
		}
		return &UnexpectedError{Status: resp.StatusCode, Text: string(body)}
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

// RequestError wraps transport-level errors.
type RequestError struct {
	Err error
}

func (e *RequestError) Error() string {
	return fmt.Sprintf("HTTP request failed: %s", e.Err)
}

func (e *RequestError) Unwrap() error {
	return e.Err
}

// APIError represents a structured error response from the attestation service.
type APIError struct {
	Status   int
	Response types.ErrorResponse
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (%d): %s", e.Status, e.Response.Message)
}

// UnexpectedError represents a non-JSON error response.
type UnexpectedError struct {
	Status int
	Text   string
}

func (e *UnexpectedError) Error() string {
	return fmt.Sprintf("unexpected response (%d): %s", e.Status, e.Text)
}
