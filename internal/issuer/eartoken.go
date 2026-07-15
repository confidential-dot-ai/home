package issuer

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/internal/earclaims"
)

// JWTClockSkew is the package-level leeway for EAR JWT time validation.
// Set this during process startup before calling ValidateEARToken.
var JWTClockSkew = 30 * time.Second

// KeyProvider resolves the ECDSA public key for verifying an EAR JWT
// signature. Single-key implementations (e.g. cert-pinned mode) may ignore
// kid; multi-key implementations (JWKS, in-process rotator) must require it
// to prevent token-confusion across the active and retiring keys.
type KeyProvider interface {
	PublicKey(kid string) (*ecdsa.PublicKey, error)
}

// Reason classifies an EAR JWT verification failure so callers can update
// per-reason metrics without parsing error strings.
type Reason string

const (
	ReasonExpired           Reason = "expired"
	ReasonInvalidSignature  Reason = "invalid_signature"
	ReasonMalformed         Reason = "malformed"
	ReasonInvalidIssuer     Reason = "invalid_issuer"
	ReasonInvalidAudience   Reason = "invalid_audience"
	ReasonNotYetValid       Reason = "not_yet_valid"
	ReasonMeasurementDenied Reason = "measurement_denied"
	ReasonKeyBinding        Reason = "key_binding"
	ReasonOperatorPolicy    Reason = "operator_policy"
)

// TokenValidationError wraps the underlying validation error with a stable
// Reason that callers route to metric labels.
type TokenValidationError struct {
	Reason Reason
	Err    error
}

func (e *TokenValidationError) Error() string { return e.Err.Error() }
func (e *TokenValidationError) Unwrap() error { return e.Err }

// ValidateEARToken parses and verifies an EAR JWT against provider, then
// checks the standard claim invariants: exp is present and not past, nbf/iat
// are not in the future, aud is absent, and iss matches expectedIssuer when
// non-empty.
func ValidateEARToken(tokenStr string, provider KeyProvider, expectedIssuer string) (*EARClaims, error) {
	if provider == nil {
		return nil, &TokenValidationError{
			Reason: ReasonInvalidSignature,
			Err:    fmt.Errorf("key provider is required"),
		}
	}

	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg(), jwt.SigningMethodES384.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(JWTClockSkew),
	}
	if expectedIssuer != "" {
		opts = append(opts, jwt.WithIssuer(expectedIssuer))
	}

	claims := &EARClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
		return keyForEARToken(provider, token)
	}, opts...)
	if err != nil {
		return nil, tokenValidationErrorFromJWT(err)
	}
	if !token.Valid {
		return nil, &TokenValidationError{
			Reason: ReasonInvalidSignature,
			Err:    fmt.Errorf("JWT signature verification failed"),
		}
	}

	if err := validateEARClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// validateEARClaims rejects a signed JWT that is not a structurally valid EAR:
// the time/issuer/audience checks above only prove the token is a well-formed
// JWT from the expected signer, not that it carries the mandatory EAR shape.
func validateEARClaims(claims *EARClaims) error {
	if claims == nil {
		return malformedEAR("EAR claims are required")
	}
	if claims.Profile != earclaims.EARProfileTag {
		return malformedEAR("EAR %s claim must be %q", earclaims.EATProfile, earclaims.EARProfileTag)
	}
	if claims.IssuedAt == 0 {
		return malformedEAR("EAR %s claim is required", earclaims.IssuedAt)
	}
	if err := requireNonEmptyJSONObject(earclaims.EARVerifierID, claims.VerifierID); err != nil {
		return err
	}
	return requireNonEmptyJSONObject(earclaims.Submods, claims.Submods)
}

func requireNonEmptyJSONObject(name string, raw json.RawMessage) error {
	if len(raw) == 0 {
		return malformedEAR("EAR %s claim is required", name)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return malformedEAR("EAR %s claim must be a JSON object: %w", name, err)
	}
	if len(object) == 0 {
		return malformedEAR("EAR %s claim must be a non-empty JSON object", name)
	}
	return nil
}

func malformedEAR(format string, args ...any) error {
	return &TokenValidationError{
		Reason: ReasonMalformed,
		Err:    fmt.Errorf(format, args...),
	}
}

func keyForEARToken(provider KeyProvider, token *jwt.Token) (any, error) {
	alg, ok := token.Header["alg"].(string)
	if !ok || (alg != jwt.SigningMethodES256.Alg() && alg != jwt.SigningMethodES384.Alg()) {
		return nil, &TokenValidationError{
			Reason: ReasonMalformed,
			Err:    fmt.Errorf("unsupported JWT algorithm: %v (need ES256 or ES384)", token.Header["alg"]),
		}
	}

	var kid string
	if rawKid, ok := token.Header["kid"]; ok {
		kid, ok = rawKid.(string)
		if !ok {
			return nil, &TokenValidationError{
				Reason: ReasonMalformed,
				Err:    fmt.Errorf("JWT kid header must be a string"),
			}
		}
	}

	ecPub, err := provider.PublicKey(kid)
	if err != nil {
		return nil, fmt.Errorf("resolve signing key: %w", err)
	}
	return ecPub, nil
}

func tokenValidationErrorFromJWT(err error) error {
	var validationErr *TokenValidationError
	if errors.As(err, &validationErr) {
		return validationErr
	}

	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return &TokenValidationError{
			Reason: ReasonExpired,
			Err:    fmt.Errorf("token expired: %w", err),
		}
	case errors.Is(err, jwt.ErrTokenNotValidYet), errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return &TokenValidationError{
			Reason: ReasonNotYetValid,
			Err:    fmt.Errorf("token is not yet valid: %w", err),
		}
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return &TokenValidationError{
			Reason: ReasonInvalidIssuer,
			Err:    fmt.Errorf("token issuer does not match expected issuer: %w", err),
		}
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return &TokenValidationError{
			Reason: ReasonInvalidAudience,
			Err:    fmt.Errorf("token audience is not accepted: %w", err),
		}
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		return &TokenValidationError{
			Reason: ReasonMalformed,
			Err:    fmt.Errorf("token missing required claim: %w", err),
		}
	case errors.Is(err, jwt.ErrTokenSignatureInvalid), errors.Is(err, jwt.ErrTokenUnverifiable),
		errors.Is(err, jwt.ErrInvalidKey), errors.Is(err, jwt.ErrInvalidKeyType):
		return &TokenValidationError{
			Reason: ReasonInvalidSignature,
			Err:    fmt.Errorf("JWT signature verification failed: %w", err),
		}
	case errors.Is(err, jwt.ErrTokenMalformed):
		return &TokenValidationError{
			Reason: ReasonMalformed,
			Err:    fmt.Errorf("parse JWT: %w", err),
		}
	default:
		return &TokenValidationError{
			Reason: ReasonMalformed,
			Err:    fmt.Errorf("validate JWT: %w", err),
		}
	}
}
