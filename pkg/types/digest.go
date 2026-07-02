package types

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Digest is a validated container image digest in the format "sha256:<64 hex chars>".
// Use ParseDigest to construct one; the zero value is not valid.
type Digest struct {
	value string
}

// ParseDigest validates and returns a Digest from the given string. Hex is
// canonicalized to lowercase: a digest is compared by exact string match, and
// containerd emits lowercase, so a valid uppercase entry (e.g. "sha256:ABCD…")
// must not miss the lowercase resolved digest at lookup time.
func ParseDigest(s string) (Digest, error) {
	hex, ok := strings.CutPrefix(s, "sha256:")
	if !ok {
		return Digest{}, fmt.Errorf("invalid digest: expected sha256:<64 hex chars>")
	}
	if len(hex) != 64 {
		return Digest{}, fmt.Errorf("invalid digest: expected sha256:<64 hex chars>")
	}
	for _, b := range []byte(hex) {
		if !isHexDigit(b) {
			return Digest{}, fmt.Errorf("invalid digest: expected sha256:<64 hex chars>")
		}
	}
	return Digest{value: "sha256:" + strings.ToLower(hex)}, nil
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// String returns the full digest string.
func (d Digest) String() string {
	return d.value
}

// MarshalText implements encoding.TextMarshaler, enabling Digest as a JSON map key.
func (d Digest) MarshalText() ([]byte, error) {
	return []byte(d.value), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, enabling Digest as a JSON map key.
func (d *Digest) UnmarshalText(data []byte) error {
	parsed, err := ParseDigest(string(data))
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Digest) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.value)
}

// UnmarshalJSON implements json.Unmarshaler with validation.
func (d *Digest) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseDigest(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}
