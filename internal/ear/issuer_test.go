package ear

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/internal/earclaims"
)

func testKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}

func decodeJWTPayload(t *testing.T, token string, v any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if err := json.Unmarshal(payload, v); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
}

func TestIssuesValid3PartJWT(t *testing.T) {
	keyPEM := testKeyPEM(t)
	issuer, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	token, err := issuer.Issue(json.RawMessage(`{"foo":"bar"}`))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	for i, part := range parts {
		if len(part) == 0 {
			t.Fatalf("part %d is empty", i)
		}
	}
}

func TestTokenContainsRequiredEARClaims(t *testing.T) {
	keyPEM := testKeyPEM(t)
	issuer, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	token, err := issuer.Issue(json.RawMessage(`{"evidence":"data"}`))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var claims map[string]json.RawMessage
	decodeJWTPayload(t, token, &claims)

	requiredKeys := []string{earclaims.EATProfile, earclaims.Issuer, earclaims.IssuedAt, earclaims.ExpiresAt, earclaims.Submods, earclaims.EARVerifierID}
	for _, key := range requiredKeys {
		if _, ok := claims[key]; !ok {
			t.Fatalf("missing required claim: %s", key)
		}
	}

	var eatProfile string
	if err := json.Unmarshal(claims[earclaims.EATProfile], &eatProfile); err != nil {
		t.Fatalf("unmarshal eat_profile: %v", err)
	}
	if eatProfile != earProfile {
		t.Fatalf("%s: got %q, want %q", earclaims.EATProfile, eatProfile, earProfile)
	}

	var iss string
	if err := json.Unmarshal(claims[earclaims.Issuer], &iss); err != nil {
		t.Fatalf("unmarshal iss: %v", err)
	}
	if iss != "test-issuer" {
		t.Fatalf("iss: got %q, want %q", iss, "test-issuer")
	}
}

func TestIssueWithLaunchDigestAddsNormalizedClaim(t *testing.T) {
	keyPEM := testKeyPEM(t)
	issuer, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	token, err := issuer.IssueWithLaunchDigest(json.RawMessage(`{"evidence":"data"}`), "abc123")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var claims map[string]json.RawMessage
	decodeJWTPayload(t, token, &claims)

	var submods map[string]json.RawMessage
	if err := json.Unmarshal(claims[earclaims.Submods], &submods); err != nil {
		t.Fatalf("unmarshal %s: %v", earclaims.Submods, err)
	}
	var attester map[string]json.RawMessage
	if err := json.Unmarshal(submods[earclaims.SubmodAttester], &attester); err != nil {
		t.Fatalf("unmarshal %s: %v", earclaims.SubmodAttester, err)
	}
	var launchDigest string
	if err := json.Unmarshal(attester[earclaims.LaunchDigest], &launchDigest); err != nil {
		t.Fatalf("unmarshal %s: %v", earclaims.LaunchDigest, err)
	}
	if launchDigest != "abc123" {
		t.Fatalf("%s = %q, want abc123", earclaims.LaunchDigest, launchDigest)
	}
}

func TestIssueWithLaunchDigestAndPubKeyAddsTEEPubKeyClaim(t *testing.T) {
	keyPEM := testKeyPEM(t)
	issuer, err := NewIssuer(keyPEM, "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}
	teeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate tee key: %v", err)
	}

	token, err := issuer.IssueWithLaunchDigestAndPubKey(json.RawMessage(`{"evidence":"data"}`), "abc123", &teeKey.PublicKey)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var claims map[string]json.RawMessage
	decodeJWTPayload(t, token, &claims)
	var teePubKeyClaim string
	if err := json.Unmarshal(claims[earclaims.TEEPublicKey], &teePubKeyClaim); err != nil {
		t.Fatalf("unmarshal %s: %v", earclaims.TEEPublicKey, err)
	}
	if teePubKeyClaim == "" {
		t.Fatalf("%s claim is empty", earclaims.TEEPublicKey)
	}
	pubDER, err := base64.RawURLEncoding.DecodeString(teePubKeyClaim)
	if err != nil {
		t.Fatalf("decode tee_public_key: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("parse tee_public_key: %v", err)
	}
	if !teeKey.PublicKey.Equal(pub) {
		t.Fatal("tee_public_key claim does not match input public key")
	}
}

func TestTokenExpiryMatchesLifetime(t *testing.T) {
	keyPEM := testKeyPEM(t)
	lifetime := 10 * time.Minute
	issuer, err := NewIssuer(keyPEM, "test-issuer", lifetime)
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	token, err := issuer.Issue(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var claims map[string]json.RawMessage
	decodeJWTPayload(t, token, &claims)

	var issuedAt float64
	if err := json.Unmarshal(claims[earclaims.IssuedAt], &issuedAt); err != nil {
		t.Fatalf("unmarshal %s: %v", earclaims.IssuedAt, err)
	}
	var expiresAt float64
	if err := json.Unmarshal(claims[earclaims.ExpiresAt], &expiresAt); err != nil {
		t.Fatalf("unmarshal %s: %v", earclaims.ExpiresAt, err)
	}

	diff := expiresAt - issuedAt
	expected := lifetime.Seconds()
	if diff != expected {
		t.Fatalf("exp - iat = %v, want %v", diff, expected)
	}
}

func TestRejectsInvalidKey(t *testing.T) {
	_, err := NewIssuer([]byte("not a pem key"), "test-issuer", 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}
