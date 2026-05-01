package ear

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lunal-dev/c8s/internal/version"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/jwks"
)

const earProfile = "tag:ietf.org,2026:rats/ear#03"

// statusAffirming is the EAR trustworthiness tier value meaning
// "recognised and not compromised" (draft-ietf-rats-ear).
const statusAffirming = 2

// keyMat holds the signing material for atomic swap during rotation.
type keyMat struct {
	key *ecdsa.PrivateKey
	kid string
}

// Issuer produces signed EAR (Entity Attestation Result) JWT tokens
// conforming to draft-ietf-rats-ear. The signing key can be swapped
// atomically via SwapKey; all value copies of an Issuer share the
// same key material through the embedded pointer.
type Issuer struct {
	mat      *atomic.Pointer[keyMat]
	issuer   string
	lifetime time.Duration
}

// PublicKey returns a copy of the active signing public key, or nil if unset.
func (iss Issuer) PublicKey() *ecdsa.PublicKey {
	if iss.mat == nil {
		return nil
	}
	m := iss.mat.Load()
	if m == nil {
		return nil
	}
	pub := m.key.PublicKey
	return &pub
}

// Kid returns the RFC 7638 JWK thumbprint of the active signing key.
func (iss Issuer) Kid() string {
	if iss.mat == nil {
		return ""
	}
	m := iss.mat.Load()
	if m == nil {
		return ""
	}
	return m.kid
}

// SwapKey atomically replaces the signing key. All value copies of this
// Issuer see the new key immediately.
func (iss Issuer) SwapKey(key *ecdsa.PrivateKey, kid string) {
	iss.mat.Store(&keyMat{key: key, kid: kid})
}

// NewIssuer creates an EAR issuer from a PEM-encoded EC private key (P-256/ES256).
func NewIssuer(keyPEM []byte, issuer string, lifetime time.Duration) (Issuer, error) {
	ecKey, err := certutil.ParseECPrivateKey(keyPEM)
	if err != nil {
		return Issuer{}, fmt.Errorf("invalid EAR signing key: %w", err)
	}

	kid, err := jwks.Thumbprint(&ecKey.PublicKey)
	if err != nil {
		return Issuer{}, fmt.Errorf("compute EAR key thumbprint: %w", err)
	}

	mat := &atomic.Pointer[keyMat]{}
	mat.Store(&keyMat{key: ecKey, kid: kid})

	return Issuer{
		mat:      mat,
		issuer:   issuer,
		lifetime: lifetime,
	}, nil
}

// Issue produces a signed EAR JWT for a successful attestation verification.
func (iss Issuer) Issue(submodsEvidence json.RawMessage) (string, error) {
	m := iss.mat.Load()
	if m == nil {
		return "", fmt.Errorf("no signing key configured")
	}

	now := time.Now().Unix()

	claims := jwt.MapClaims{
		"eat_profile": earProfile,
		"iss":         iss.issuer,
		"iat":         now,
		"exp":         now + int64(iss.lifetime.Seconds()),
		"ear_verifier_id": map[string]string{
			"developer": iss.issuer,
			"build":     version.Version,
		},
		"submods": map[string]any{
			"attester": map[string]any{
				"ear_status": statusAffirming,
				"ear_trustworthiness_vector": map[string]any{
					"instance-identity": statusAffirming,
				},
				"ear_raw_evidence": json.RawMessage(submodsEvidence),
			},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = m.kid
	signed, err := token.SignedString(m.key)
	if err != nil {
		return "", fmt.Errorf("failed to sign EAR token: %w", err)
	}

	return signed, nil
}
