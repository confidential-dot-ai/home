package whitelistclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/lunal-dev/c8s/pkg/types"
	"github.com/lunal-dev/c8s/pkg/whitelist"
)

// Client is an HTTP client for the CDS whitelist API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new whitelist client.
func NewClient(baseURL string) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: http.DefaultClient,
	}
}

// NewClientWithHTTP creates a new whitelist client with a custom HTTP client.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) Client {
	return Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

// List returns all whitelisted image digests.
func (c Client) List() (types.WhitelistListResponse, error) {
	url := c.baseURL + "/whitelist"
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return types.WhitelistListResponse{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return types.WhitelistListResponse{}, &StatusError{Status: resp.StatusCode, Body: string(body)}
	}

	var result types.WhitelistListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return types.WhitelistListResponse{}, err
	}
	return result, nil
}

// Add adds an image digest to the whitelist. Requires an EAR bearer token
// authorized for cds/whitelist-write.
func (c Client) Add(digest types.Digest, image string, earToken []byte) error {
	reqBody := types.WhitelistAddRequest{
		Digest: digest,
		Image:  image,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	url := c.baseURL + "/whitelist"
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

// Delete removes image digests from the whitelist. Requires an EAR bearer token
// authorized for cds/whitelist-write.
// Returns an error with 404 status if any digest does not exist.
func (c Client) Delete(digests []types.Digest, earToken []byte) error {
	reqBody := types.WhitelistDeleteRequest{
		Digests: digests,
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	url := c.baseURL + "/whitelist"
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

// maxWhitelistResponseBytes caps CDS response bodies. Generous for a
// realistic fleet (a sha256 entry + image ref is ~150 bytes; 4 MiB ≈ 27k
// entries) but bounded so a compromised or buggy CDS can't OOM the
// plugin process on every worker node.
const maxWhitelistResponseBytes = 4 * 1024 * 1024

// errWhitelistResponseTooLarge is returned when CDS exceeds the body cap.
var errWhitelistResponseTooLarge = fmt.Errorf("whitelist response exceeds %d bytes", maxWhitelistResponseBytes)

// FetchWhitelistConditional issues GET /whitelist with If-None-Match.
// notModified is true on a 304 (whitelist nil, etag ""); on 200 the
// parsed whitelist is returned with the new ETag (which may be empty).
func (c Client) FetchWhitelistConditional(ctx context.Context, ifNoneMatch string) (*whitelist.Whitelist, string, bool, error) {
	url := c.baseURL + "/whitelist"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("create request: %w", err)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("fetch whitelist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		io.Copy(io.Discard, resp.Body)
		return nil, "", true, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := readCapped(resp.Body, maxWhitelistResponseBytes)
		return nil, "", false, &StatusError{Status: resp.StatusCode, Body: string(body)}
	}

	if ct := resp.Header.Get("Content-Type"); !isJSONContentType(ct) {
		return nil, "", false, fmt.Errorf("fetch whitelist: unexpected content type: %s", ct)
	}

	body, err := readCapped(resp.Body, maxWhitelistResponseBytes)
	if err != nil {
		return nil, "", false, err
	}

	wl, err := whitelist.ParseJSON(body)
	if err != nil {
		return nil, "", false, err
	}
	return wl, resp.Header.Get("ETag"), false, nil
}

func isJSONContentType(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

// readCapped reads up to maxBytes from r and returns errWhitelistResponseTooLarge
// if the source produced more.
func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, errWhitelistResponseTooLarge
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
