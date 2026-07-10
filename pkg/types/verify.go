package types

import "encoding/json"

// Browser-facing attestation + over-encryption wire types for the c8s-verify
// v1 and v2 protocols served by the Load Balancer. These mirror
// c8s-verify-js/PROTOCOL.md
// and are consumed by the JavaScript client (c8s-verify-js) and any other
// out-of-cluster verifier. All *_pubkey / handshake byte fields are base64url
// (unpadded); the SNP evidence sub-fields use standard base64 (attestation-rs
// SnpEvidence shape).

// SessionPublicKey is the LB's per-session hybrid (X25519 + ML-KEM-768) public
// key. The selected Binding defines the report_data transcript that commits it.
type SessionPublicKey struct {
	X25519   string `json:"x25519"`   // base64url, 32 bytes
	MLKEM768 string `json:"mlkem768"` // base64url, 1184 bytes
}

// Binding identifies what the hardware report_data commits to in an
// AttestationBundle. The default (over-encryption) binds the per-session hybrid
// key; the tls-cert binding commits to the LB's serving-leaf SPKI instead, for
// clients (e.g. TEErminator Flow B) that ride the validated upstream TLS rather
// than the post-quantum tunnel.
const (
	// BindingOverEncryption: report_data = SHA-384(x25519 || mlkem768 || nonce).
	// The session key is bound, enabling the over-encryption handshake/tunnel.
	BindingOverEncryption = "over-encryption"
	// BindingOverEncryptionMeshIdentityV2 commits report_data to the hybrid
	// session key, nonce, mesh leaf, and issuing mesh CA. IdentityProof then
	// proves possession of that exact leaf's private key.
	BindingOverEncryptionMeshIdentityV2 = "over-encryption+mesh-identity-v2"
	// BindingTLSCert: report_data = SHA-384(serving_leaf_spki || nonce). The
	// attestation is bound to the LB's TLS leaf, so a client verifies it against
	// the certificate it already sees on the (mesh-CA-validated) connection.
	BindingTLSCert = "tls-cert"

	// MeshIdentityProofECDSASHA384 is the v2 proof-of-possession algorithm.
	MeshIdentityProofECDSASHA384 = "ecdsa-sha384"
)

// MeshIdentityProof authenticates the PQ session transcript with the private
// key corresponding to the mesh leaf in AttestationBundle.CDSCertPEM. Hashes
// are base64url SHA-256; Signature is base64url ASN.1 DER ECDSA.
type MeshIdentityProof struct {
	Algorithm    string `json:"algorithm"`      // MeshIdentityProofECDSASHA384
	LeafSHA256   string `json:"leaf_sha256"`    // base64url; exact leaf DER committed by report_data
	MeshCASHA256 string `json:"mesh_ca_sha256"` // base64url; issuing CA DER committed by report_data
	Signature    string `json:"signature"`      // base64url ASN.1 DER ECDSA signature
}

// AttestationBundle is the response body of
// GET /.well-known/c8s/attestation?nonce=<b64url>[&binding=...|&pq=false].
type AttestationBundle struct {
	Version    string          `json:"version"`      // "c8s-verify/v1" or "c8s-verify/v2"
	Platform   string          `json:"platform"`     // "snp" today
	Generation string          `json:"generation"`   // AMD gen: milan|genoa|turin
	Nonce      string          `json:"nonce"`        // echoed client nonce (b64url)
	Evidence   json.RawMessage `json:"evidence"`     // attestation-rs SnpEvidence
	CDSCertPEM string          `json:"cds_cert_pem"` // LB leaf + mesh CA chain (PEM)
	// Binding names what report_data commits to. Empty is treated as
	// BindingOverEncryption for backward compatibility with existing clients.
	Binding string `json:"binding,omitempty"`
	// SessionPubKey is the per-session over-encryption key, present only for the
	// over-encryption binding; omitted (nil) for the tls-cert binding.
	SessionPubKey *SessionPublicKey `json:"session_pubkey,omitempty"`
	// IdentityProof is present only for BindingOverEncryptionMeshIdentityV2.
	IdentityProof *MeshIdentityProof `json:"identity_proof,omitempty"`
}

// HandshakeRequest is the body of POST /.well-known/c8s/handshake: the client
// commits to a nonce (selecting the LB's stored session key) and supplies its
// hybrid handshake material.
type HandshakeRequest struct {
	Nonce        string `json:"nonce"`         // b64url, selects the pending session
	ClientX25519 string `json:"client_x25519"` // b64url, 32 bytes
	MLKEMCt      string `json:"mlkem_ct"`      // b64url, 1088 bytes
}

// HandshakeResponse returns the established session identifier.
type HandshakeResponse struct {
	SessionID string `json:"session_id"`
}

// TunnelRequest is the plaintext application request carried inside an
// over-encrypted record sent to POST /.well-known/c8s/tunnel. The whole request
// — method, path, headers, and body — is sealed, so a TLS-terminating proxy in
// front of the LB sees only ciphertext. The sidecar decrypts it and forwards the
// reconstructed request as plaintext to the backend (the cluster raTLS mesh wraps
// that hop).
type TunnelRequest struct {
	Method  string            `cbor:"method" json:"method"`
	Path    string            `cbor:"path" json:"path"`
	Headers map[string]string `cbor:"headers,omitempty" json:"headers,omitempty"`
	Body    []byte            `cbor:"body,omitempty" json:"body,omitempty"` // raw body, CBOR byte string
}

// TunnelResponse is the backend response, sealed back to the client.
type TunnelResponse struct {
	Status  int               `cbor:"status" json:"status"`
	Headers map[string]string `cbor:"headers,omitempty" json:"headers,omitempty"`
	Body    []byte            `cbor:"body,omitempty" json:"body,omitempty"` // raw body, CBOR byte string
}
