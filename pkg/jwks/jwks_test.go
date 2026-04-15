package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestFromPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk, err := FromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if jwk.KeyID == "" {
		t.Error("kid should be non-empty")
	}
	if jwk.Use != "sig" {
		t.Errorf("use = %q, want sig", jwk.Use)
	}
	if jwk.Algorithm != string(jose.ES256) {
		t.Errorf("alg = %q, want ES256", jwk.Algorithm)
	}
}

func TestThumbprintStability(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwk1, _ := FromPublicKey(&key.PublicKey)
	jwk2, _ := FromPublicKey(&key.PublicKey)

	if jwk1.KeyID != jwk2.KeyID {
		t.Errorf("kid changed across calls: %s vs %s", jwk1.KeyID, jwk2.KeyID)
	}
}

func TestThumbprintUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for range 1000 {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		jwk, err := FromPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if seen[jwk.KeyID] {
			t.Fatalf("duplicate kid after %d keys", len(seen))
		}
		seen[jwk.KeyID] = true
	}
}

func TestMarshalSet(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := FromPublicKey(&key.PublicKey)

	data, err := MarshalSet(jwk)
	if err != nil {
		t.Fatal(err)
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(set.Keys))
	}
	if set.Keys[0].KeyID != jwk.KeyID {
		t.Error("round-tripped kid mismatch")
	}
}
