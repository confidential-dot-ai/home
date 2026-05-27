package issuer

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTClockSkew is the package-level leeway for EAR JWT time validation.
// Set this during process startup before calling ValidateEARToken.
var JWTClockSkew = 30 * time.Second

// KeyProvider resolves the ECDSA public key for verifying an EAR JWT
// signature. kid may be empty for legacy tokens issued before the JWKS
// rollout — implementations may return the active key in that case.
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

	return claims, nil
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
