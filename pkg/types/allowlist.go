package types

// DigestAddRequest is the body for POST /allowlist/digests: a single floor
// digest and its informational image label.
type DigestAddRequest struct {
	Digest Digest `json:"digest"`
	Image  string `json:"image"`
}

// DigestDeleteRequest is the body for DELETE /allowlist/digests.
type DigestDeleteRequest struct {
	Digests []Digest `json:"digests"`
}
