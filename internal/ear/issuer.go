package ear

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/jwks"
)

// Version is set at build time via ldflags.
var Version = "dev"

const earProfile = "tag:ietf.org,2026:rats/ear#03"

// statusAffirming is the EAR trustworthiness tier value meaning
// "recognised and not compromised" (draft-ietf-rats-ear).
const statusAffirming = 2

// Issuer produces signed EAR (Entity Attestation Result) JWT tokens
// conforming to draft-ietf-rats-ear.
type Issuer struct {
	signingKey *ecdsa.PrivateKey
	kid        string
	issuer     string
	lifetime   time.Duration
}

// PublicKey returns a copy of the public half of the signing key, or nil if
// no key is set.
func (iss Issuer) PublicKey() *ecdsa.PublicKey {
	if iss.signingKey == nil {
		return nil
	}
	pub := iss.signingKey.PublicKey
	return &pub
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

	return Issuer{
		signingKey: ecKey,
		kid:        kid,
		issuer:     issuer,
		lifetime:   lifetime,
	}, nil
}

// Issue produces a signed EAR JWT for a successful attestation verification.
// submodsEvidence is the raw attestation evidence to embed for audit purposes.
func (iss Issuer) Issue(submodsEvidence json.RawMessage) (string, error) {
	now := time.Now().Unix()

	claims := jwt.MapClaims{
		"eat_profile": earProfile,
		"iss":         iss.issuer,
		"iat":         now,
		"exp":         now + int64(iss.lifetime.Seconds()),
		"ear_verifier_id": map[string]string{
			"developer": iss.issuer,
			"build":     Version,
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
	token.Header["kid"] = iss.kid
	signed, err := token.SignedString(iss.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign EAR token: %w", err)
	}

	return signed, nil
}
