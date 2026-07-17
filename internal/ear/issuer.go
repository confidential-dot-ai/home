package ear

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
	"github.com/confidential-dot-ai/c8s/internal/version"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/jwks"
)

const earProfile = earclaims.EARProfileTag

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
	return iss.IssueWithLaunchDigest(submodsEvidence, "")
}

// IssueWithLaunchDigest produces a signed EAR JWT and includes the normalized
// launch digest extracted by the attestation verifier when available.
func (iss Issuer) IssueWithLaunchDigest(submodsEvidence json.RawMessage, launchDigest string) (string, error) {
	return iss.IssueWithLaunchDigestAndPubKey(submodsEvidence, launchDigest, nil)
}

// IssueForRequestBody produces an EAR JWT bound to a specific request body
// hash. Verifiers reject the token if the body they receive doesn't match
// the SHA-256 in the `pbh` claim, which stops captured tokens from being
// replayed against different payloads within their TTL.
//
// requestBody is the raw bytes that will be hashed and embedded as the
// `pbh` claim — the caller must hash the same bytes the server will see
// (canonicalized JSON, etc.) for verification to succeed.
func (iss Issuer) IssueForRequestBody(submodsEvidence json.RawMessage, launchDigest string, requestBody []byte) (string, error) {
	bodyHash := sha256.Sum256(requestBody)
	pbh := base64.RawURLEncoding.EncodeToString(bodyHash[:])
	return iss.issueWithExtras(submodsEvidence, launchDigest, nil, map[string]any{
		earclaims.PayloadBodyHash: pbh,
	})
}

// IssueWithLaunchDigestAndPubKey produces a signed EAR JWT, includes the
// normalized launch digest when available, and optionally binds the EAR to the
// attested ECDSA TEE public key.
func (iss Issuer) IssueWithLaunchDigestAndPubKey(submodsEvidence json.RawMessage, launchDigest string, teePubKey *ecdsa.PublicKey) (string, error) {
	return iss.IssueAttestedKey(submodsEvidence, launchDigest, teePubKey, "")
}

// IssueAttestedKey produces an EAR for a TEE-bound public key and optionally
// commits the CDS operator-key policy that was included in REPORTDATA.
func (iss Issuer) IssueAttestedKey(submodsEvidence json.RawMessage, launchDigest string, teePubKey *ecdsa.PublicKey, operatorKeysHash string) (string, error) {
	var extras map[string]any
	if operatorKeysHash != "" {
		extras = map[string]any{earclaims.OperatorKeysHash: operatorKeysHash}
	}
	return iss.issueWithExtras(submodsEvidence, launchDigest, teePubKey, extras)
}

func (iss Issuer) issueWithExtras(submodsEvidence json.RawMessage, launchDigest string, teePubKey *ecdsa.PublicKey, extras map[string]any) (string, error) {
	m := iss.mat.Load()
	if m == nil {
		return "", fmt.Errorf("no signing key configured")
	}

	now := time.Now().Unix()
	attester := map[string]any{
		earclaims.EARStatus: statusAffirming,
		earclaims.EARTrustworthinessVector: map[string]any{
			earclaims.InstanceIdentity: statusAffirming,
		},
		earclaims.EARRawEvidence: json.RawMessage(submodsEvidence),
	}
	if launchDigest != "" {
		attester[earclaims.LaunchDigest] = launchDigest
	}

	var teePubKeyClaim string
	if teePubKey != nil {
		pubDER, err := x509.MarshalPKIXPublicKey(teePubKey)
		if err != nil {
			return "", fmt.Errorf("marshal TEE public key: %w", err)
		}
		teePubKeyClaim = base64.RawURLEncoding.EncodeToString(pubDER)
	}

	claims := jwt.MapClaims{
		earclaims.EATProfile: earProfile,
		earclaims.Issuer:     iss.issuer,
		earclaims.IssuedAt:   now,
		earclaims.ExpiresAt:  now + int64(iss.lifetime.Seconds()),
		earclaims.EARVerifierID: map[string]string{
			earclaims.Developer: iss.issuer,
			earclaims.Build:     version.Version,
		},
		earclaims.Submods: map[string]any{earclaims.SubmodAttester: attester},
	}
	if teePubKeyClaim != "" {
		claims[earclaims.TEEPublicKey] = teePubKeyClaim
	}
	for k, v := range extras {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = m.kid
	signed, err := token.SignedString(m.key)
	if err != nil {
		return "", fmt.Errorf("failed to sign EAR token: %w", err)
	}

	return signed, nil
}
