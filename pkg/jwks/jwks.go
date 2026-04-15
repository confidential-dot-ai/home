// Package jwks wraps go-jose to produce JWK Sets from ECDSA public keys.
package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// FromPublicKey builds a go-jose JSONWebKey with kid set to the RFC 7638
// thumbprint and use/alg populated for ES256 signing.
func FromPublicKey(pub *ecdsa.PublicKey) (jose.JSONWebKey, error) {
	jwk := jose.JSONWebKey{
		Key:       pub,
		Use:       "sig",
		Algorithm: string(jose.ES256),
	}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("compute JWK thumbprint: %w", err)
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(thumb)
	return jwk, nil
}

// Thumbprint computes the RFC 7638 JWK thumbprint of an ECDSA public key,
// returned as a base64url-encoded SHA-256 hash.
func Thumbprint(pub *ecdsa.PublicKey) (string, error) {
	jwk, err := FromPublicKey(pub)
	if err != nil {
		return "", err
	}
	return jwk.KeyID, nil
}

// MarshalSet serializes one or more JWKs as a JWKS JSON document.
func MarshalSet(keys ...jose.JSONWebKey) ([]byte, error) {
	set := jose.JSONWebKeySet{Keys: keys}
	return json.Marshal(set)
}
