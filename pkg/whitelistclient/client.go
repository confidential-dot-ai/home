package whitelistclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lunal-dev/c8s/pkg/types"
	"github.com/lunal-dev/c8s/pkg/whitelist"
)

// Client is an HTTP client for the assam whitelist API.
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
// authorized for assam/whitelist-write.
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
// authorized for assam/whitelist-write.
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

// FetchWhitelist calls GET /whitelist and returns the parsed whitelist.
// This is a context-aware alternative to List that returns the whitelist type
// used by the NRI image policy plugin.
func (c Client) FetchWhitelist(ctx context.Context) (*whitelist.Whitelist, error) {
	url := c.baseURL + "/whitelist"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch whitelist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &StatusError{Status: resp.StatusCode, Body: string(body)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		return nil, fmt.Errorf("fetch whitelist: unexpected content type: %s", ct)
	}

	return whitelist.ParseJSON(body)
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
