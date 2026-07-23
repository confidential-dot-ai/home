package attestationclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// maxErrorBodyBytes caps how much of a non-2xx response body is read into
// APIError/UnexpectedError.
const maxErrorBodyBytes = 8 << 10

// Client is an HTTP client for the external attestation-api.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new attestation-api client.
//
// A "unix:///path/to/attest.sock" baseURL routes every request over that local
// Unix-domain socket instead of a routable HTTP address. Because the verifier
// trusts whatever the attestation-api returns (the /verify verdict is not
// signed), a routable URL lets a hostile control plane redirect it under the
// documented threat model (C-05); a private in-TCB socket removes that spoofable
// hop. The socket's owner and mode are checked on every dial (see
// validateVerifierSocket) so a swapped or world-writable socket fails closed.
func NewClient(baseURL string) Client {
	if socket, ok := strings.CutPrefix(baseURL, "unix://"); ok {
		return Client{
			baseURL:    "http://unix",
			httpClient: &http.Client{Transport: unixSocketTransport(socket)},
		}
	}
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
	}
}

// unixSocketTransport dials socketPath for every request, validating its
// ownership and mode first so the verifier never talks to a socket an untrusted
// actor could have replaced or made world-writable.
func unixSocketTransport(socketPath string) *http.Transport {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if err := validateVerifierSocket(socketPath); err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
}

// validateVerifierSocket asserts socketPath is a real Unix socket (not a
// symlink), owned by root or the calling process, and not world-writable.
func validateVerifierSocket(socketPath string) error {
	if !filepath.IsAbs(socketPath) {
		return fmt.Errorf("attestationclient: verifier socket %q must be an absolute path", socketPath)
	}
	fi, err := os.Lstat(socketPath)
	if err != nil {
		return fmt.Errorf("attestationclient: stat verifier socket %q: %w", socketPath, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("attestationclient: %q is not a socket (mode %s)", socketPath, fi.Mode())
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("attestationclient: verifier socket %q is world-writable (mode %#o)", socketPath, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if st.Uid != 0 && int(st.Uid) != os.Getuid() {
			return fmt.Errorf("attestationclient: verifier socket %q is owned by uid %d (want root or the verifier's own uid)", socketPath, st.Uid)
		}
	}
	return nil
}

// NewClientWithHTTP creates a new client with a custom HTTP client.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

// Health calls GET /health on the attestation-api.
func (c Client) Health(ctx context.Context) (types.HealthResponse, error) {
	var result types.HealthResponse
	if err := c.getJSON(ctx, "/health", &result); err != nil {
		return types.HealthResponse{}, err
	}
	return result, nil
}

// Attest calls POST /attest on the attestation-api.
func (c Client) Attest(ctx context.Context, req types.AttestRequest) (types.AttestResponse, error) {
	var result types.AttestResponse
	if err := c.postJSON(ctx, "/attest", req, &result); err != nil {
		return types.AttestResponse{}, err
	}
	return result, nil
}

// Verify calls POST /verify on the attestation-api.
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
		// Cap the error body: it can come from an unhealthy or untrusted
		// endpoint and flows into error strings and logs.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
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

// APIError represents a structured error response from the attestation-api.
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
