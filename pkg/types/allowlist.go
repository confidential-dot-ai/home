package types

// AllowlistListResponse is the response body for GET /allowlist.
type AllowlistListResponse struct {
	Version string            `json:"version"`
	Digests map[Digest]string `json:"digests"`
}

// AllowlistAddRequest is the request body for POST /allowlist.
type AllowlistAddRequest struct {
	Digest Digest `json:"digest"`
	Image  string `json:"image"`
}

// AllowlistDeleteRequest is the request body for DELETE /allowlist.
type AllowlistDeleteRequest struct {
	Digests []Digest `json:"digests"`
}
