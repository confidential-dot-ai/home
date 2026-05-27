package issuer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lunal-dev/c8s/internal/earclaims"
	"github.com/lunal-dev/c8s/internal/issuer"
)

type testKeyProvider struct{ pub *ecdsa.PublicKey }

func (p testKeyProvider) PublicKey(string) (*ecdsa.PublicKey, error) {
	return p.pub, nil
}

func signEARJWT(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

func validEARClaims(now int64) map[string]any {
	return map[string]any{
		earclaims.EATProfile: earclaims.EARProfileTag,
		earclaims.Issuer:     "cds",
		earclaims.IssuedAt:   now,
		earclaims.ExpiresAt:  now + 600,
		earclaims.EARVerifierID: map[string]any{
			earclaims.Developer: "test",
			earclaims.Build:     "test",
		},
		earclaims.Submods: map[string]any{
			earclaims.SubmodAttester: map[string]any{
				earclaims.EARStatus: 2,
			},
		},
	}
}

func TestValidateEARTokenRejectsFutureIssuedAt(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().Unix()
	claims := validEARClaims(now)
	claims[earclaims.IssuedAt] = now + 120
	token := signEARJWT(t, key, claims)

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	if err == nil {
		t.Fatal("expected future iat to be rejected")
	}
	var validationErr *issuer.TokenValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %[1]v, want TokenValidationError", err)
	}
	if validationErr.Reason != issuer.ReasonNotYetValid {
		t.Fatalf("reason = %q, want not_yet_valid", validationErr.Reason)
	}
}

func TestValidateEARTokenRejectsFutureNotBefore(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().Unix()
	claims := validEARClaims(now)
	claims[earclaims.NotBefore] = now + 120
	token := signEARJWT(t, key, claims)

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	if err == nil {
		t.Fatal("expected future nbf to be rejected")
	}
	var validationErr *issuer.TokenValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %[1]v, want TokenValidationError", err)
	}
	if validationErr.Reason != issuer.ReasonNotYetValid {
		t.Fatalf("reason = %q, want not_yet_valid", validationErr.Reason)
	}
}

func TestValidateEARTokenRejectsAudienceClaim(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().Unix()
	claims := validEARClaims(now)
	claims["aud"] = "other-service"
	token := signEARJWT(t, key, claims)

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	if err == nil {
		t.Fatal("expected aud claim to be rejected")
	}
	var validationErr *issuer.TokenValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %[1]v, want TokenValidationError", err)
	}
	if validationErr.Reason != issuer.ReasonInvalidAudience {
		t.Fatalf("reason = %q, want invalid_audience", validationErr.Reason)
	}
}

func TestValidateEARTokenRejectsSignedNonEARJWT(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().Unix()
	token := signEARJWT(t, key, map[string]any{
		earclaims.Issuer:    "cds",
		earclaims.IssuedAt:  now,
		earclaims.ExpiresAt: now + 600,
	})

	_, err = issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
	if err == nil {
		t.Fatal("expected signed non-EAR JWT to be rejected")
	}
	var validationErr *issuer.TokenValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %[1]v, want TokenValidationError", err)
	}
	if validationErr.Reason != issuer.ReasonMalformed {
		t.Fatalf("reason = %q, want malformed", validationErr.Reason)
	}
}

func TestValidateEARTokenRejectsMissingMandatoryEARClaims(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().Unix()

	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{name: "missing profile", edit: func(claims map[string]any) { delete(claims, earclaims.EATProfile) }},
		{name: "wrong profile", edit: func(claims map[string]any) { claims[earclaims.EATProfile] = "tag:example.com:not-ear" }},
		{name: "missing iat", edit: func(claims map[string]any) { delete(claims, earclaims.IssuedAt) }},
		{name: "missing verifier id", edit: func(claims map[string]any) { delete(claims, earclaims.EARVerifierID) }},
		{name: "empty verifier id", edit: func(claims map[string]any) { claims[earclaims.EARVerifierID] = map[string]any{} }},
		{name: "missing submods", edit: func(claims map[string]any) { delete(claims, earclaims.Submods) }},
		{name: "empty submods", edit: func(claims map[string]any) { claims[earclaims.Submods] = map[string]any{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := validEARClaims(now)
			tc.edit(claims)
			token := signEARJWT(t, key, claims)

			_, err := issuer.ValidateEARToken(token, testKeyProvider{pub: &key.PublicKey}, "cds")
			if err == nil {
				t.Fatal("expected malformed EAR to be rejected")
			}
			var validationErr *issuer.TokenValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error = %T %[1]v, want TokenValidationError", err)
			}
			if validationErr.Reason != issuer.ReasonMalformed {
				t.Fatalf("reason = %q, want malformed", validationErr.Reason)
			}
		})
	}
}
