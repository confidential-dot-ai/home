package allowlistclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// Client is an HTTP client for the CDS allowlist API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new allowlist client.
func NewClient(baseURL string) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
	}
}

// NewClientWithHTTP creates a new allowlist client with a custom HTTP client.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

// List returns all allowlisted image digests.
func (c Client) List(ctx context.Context) (types.AllowlistListResponse, error) {
	url := c.baseURL + "/allowlist"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return types.AllowlistListResponse{}, fmt.Errorf("create request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return types.AllowlistListResponse{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return types.AllowlistListResponse{}, &StatusError{Status: resp.StatusCode, Body: string(body)}
	}

	var result types.AllowlistListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return types.AllowlistListResponse{}, err
	}
	return result, nil
}

// Add adds an image digest to the allowlist. Requires an EAR bearer token
// authorized for cds/allowlist-write.
func (c Client) Add(digest types.Digest, image string, earToken []byte) error {
	reqBody := types.AllowlistAddRequest{
		Digest: digest,
		Image:  image,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	url := c.baseURL + "/allowlist"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(earToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &StatusError{Status: resp.StatusCode}
	}
	return nil
}

// Delete removes image digests from the allowlist. Requires an EAR bearer token
// authorized for cds/allowlist-write.
// Returns an error with 404 status if any digest does not exist.
func (c Client) Delete(digests []types.Digest, earToken []byte) error {
	reqBody := types.AllowlistDeleteRequest{
		Digests: digests,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	url := c.baseURL + "/allowlist"
	req, err := http.NewRequest(http.MethodDelete, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(earToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &StatusError{Status: resp.StatusCode}
	}
	return nil
}

// maxAllowlistResponseBytes caps CDS response bodies. Generous for a
// realistic fleet (a sha256 entry + image ref is ~150 bytes; 4 MiB ≈ 27k
// entries) but bounded so a compromised or buggy CDS can't OOM the
// plugin process on every worker node.
const maxAllowlistResponseBytes = 4 * 1024 * 1024

// errAllowlistResponseTooLarge is returned when CDS exceeds the body cap.
var errAllowlistResponseTooLarge = fmt.Errorf("allowlist response exceeds %d bytes", maxAllowlistResponseBytes)

// FetchAllowlistConditional issues GET /allowlist with If-None-Match.
// notModified is true on a 304 (allowlist nil, etag ""); on 200 the
// parsed allowlist is returned with the new ETag (which may be empty).
func (c Client) FetchAllowlistConditional(ctx context.Context, ifNoneMatch string) (*allowlist.Allowlist, string, bool, error) {
	url := c.baseURL + "/allowlist"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("create request: %w", err)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("fetch allowlist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		io.Copy(io.Discard, resp.Body)
		return nil, "", true, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := readCapped(resp.Body, maxAllowlistResponseBytes)
		return nil, "", false, &StatusError{Status: resp.StatusCode, Body: string(body)}
	}

	if ct := resp.Header.Get("Content-Type"); !isJSONContentType(ct) {
		return nil, "", false, fmt.Errorf("fetch allowlist: unexpected content type: %s", ct)
	}

	body, err := readCapped(resp.Body, maxAllowlistResponseBytes)
	if err != nil {
		return nil, "", false, err
	}

	wl, err := allowlist.ParseJSON(body)
	if err != nil {
		return nil, "", false, err
	}
	return wl, resp.Header.Get("ETag"), false, nil
}

func isJSONContentType(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

// readCapped reads up to maxBytes from r and returns errAllowlistResponseTooLarge
// if the source produced more.
func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, errAllowlistResponseTooLarge
	}
	return body, nil
}

// StatusError represents a non-success HTTP response.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("server returned %d: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("server returned %d", e.Status)
}
