package issuer

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
)

// EARClaims is the subset of an Entity Attestation Result (EAR) JWT's claim
// set that the c8s control-plane consumes: the issuer, validity window, the
// TEE-attested public key, and the raw attestation evidence (under submods).
type EARClaims struct {
	// Profile identifies the EAR profile version this token claims to follow.
	Profile string
	// Issuer is matched against the caller-supplied expected issuer.
	Issuer string
	// IssuedAt is a Unix timestamp.
	IssuedAt int64
	// NotBefore is a Unix timestamp before which the EAR is not valid.
	NotBefore int64
	// Expiry is a Unix timestamp.
	Expiry int64
	// TEEPubKey is the base64url-encoded DER PKIX public key from the TEE,
	// bound to the attestation report via REPORTDATA.
	TEEPubKey string
	// OperatorKeysHash is the canonical hash of the operator public-key set
	// bound into REPORTDATA for a handoff signer EAR.
	OperatorKeysHash string
	// VerifierID identifies the verifier that appraised the evidence.
	VerifierID json.RawMessage
	// PayloadBodyHash is the optional pbh claim: base64url(SHA-256(body)) that
	// binds a body-scoped EAR (e.g. allowlist writes) to a specific request
	// body. Empty when the token is not body-bound.
	PayloadBodyHash string
	// Submods is the raw EAR submodule map.
	Submods json.RawMessage
	// RawEvidence is the raw attestation evidence for audit hashing.
	// EAR carries submods as a JSON object, so we use json.RawMessage.
	RawEvidence json.RawMessage

	audience jwt.ClaimStrings
}

func (c *EARClaims) UnmarshalJSON(raw []byte) error {
	*c = EARClaims{RawEvidence: append(json.RawMessage(nil), raw...)}
	var rawEvidence json.RawMessage
	if err := earclaims.UnmarshalObject(raw,
		earclaims.Bind(earclaims.EATProfile, &c.Profile),
		earclaims.Bind(earclaims.Issuer, &c.Issuer),
		earclaims.Bind(earclaims.IssuedAt, &c.IssuedAt),
		earclaims.Bind(earclaims.NotBefore, &c.NotBefore),
		earclaims.Bind(earclaims.ExpiresAt, &c.Expiry),
		earclaims.Bind(earclaims.EARVerifierID, &c.VerifierID),
		earclaims.Bind(earclaims.TEEPublicKey, &c.TEEPubKey),
		earclaims.Bind(earclaims.OperatorKeysHash, &c.OperatorKeysHash),
		earclaims.Bind(earclaims.PayloadBodyHash, &c.PayloadBodyHash),
		earclaims.Bind(earclaims.Submods, &rawEvidence),
		earclaims.Bind(earclaims.Audience, &c.audience),
	); err != nil {
		return err
	}
	if len(rawEvidence) > 0 {
		c.Submods = append(json.RawMessage(nil), rawEvidence...)
		c.RawEvidence = rawEvidence
	}
	return nil
}

func (c EARClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return numericDateFromUnix(c.Expiry), nil
}

func (c EARClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return numericDateFromUnix(c.IssuedAt), nil
}

func (c EARClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return numericDateFromUnix(c.NotBefore), nil
}

func (c EARClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c EARClaims) GetSubject() (string, error) {
	return "", nil
}

func (c EARClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.audience, nil
}

func (c EARClaims) Validate() error {
	if len(c.audience) > 0 {
		return fmt.Errorf("audience-scoped EAR tokens are not accepted: %w", jwt.ErrTokenInvalidAudience)
	}
	return nil
}

func numericDateFromUnix(sec int64) *jwt.NumericDate {
	if sec == 0 {
		return nil
	}
	return jwt.NewNumericDate(time.Unix(sec, 0))
}
