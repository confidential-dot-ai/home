// Package issuerapi defines the wire types for the cert-issuer HTTP API.
// Both cert-issuer (server) and its clients import this package to
// ensure the JSON contract stays in sync.
package issuerapi

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// PEMData wraps PEM-encoded data with validation on JSON unmarshal.
// Internally it stores the decoded block(s) so consumers can access
// DER bytes without re-parsing.
type PEMData struct {
	blocks []*pem.Block
	raw    []byte // original PEM bytes for re-serialization
}

// NewPEMData creates a PEMData from raw PEM bytes. Returns an error
// if the data contains no valid PEM blocks.
func NewPEMData(data []byte) (PEMData, error) {
	blocks, err := decodePEMBlocks(data)
	if err != nil {
		return PEMData{}, err
	}
	raw := make([]byte, len(data))
	copy(raw, data)
	return PEMData{blocks: blocks, raw: raw}, nil
}

// MustPEMData creates a PEMData from raw PEM bytes, panicking on error.
// Intended for tests and known-good literals.
func MustPEMData(data []byte) PEMData {
	p, err := NewPEMData(data)
	if err != nil {
		panic(err)
	}
	return p
}

// NewPEMDataFromDER creates a PEMData from a DER block and PEM block type
// (e.g., "CERTIFICATE", "CERTIFICATE REQUEST").
func NewPEMDataFromDER(blockType string, der []byte) PEMData {
	block := &pem.Block{Type: blockType, Bytes: der}
	raw := pem.EncodeToMemory(block)
	return PEMData{blocks: []*pem.Block{block}, raw: raw}
}

// Blocks returns all decoded PEM blocks.
func (p PEMData) Blocks() []*pem.Block {
	return p.blocks
}

// DER returns the DER bytes of the first PEM block.
// Returns nil if empty. For multi-block PEM (e.g., certificate chains),
// use DERAll to get all blocks.
func (p PEMData) DER() []byte {
	if len(p.blocks) == 0 {
		return nil
	}
	return p.blocks[0].Bytes
}

// DERAll returns the DER bytes of every PEM block.
// Returns nil if empty.
func (p PEMData) DERAll() [][]byte {
	if len(p.blocks) == 0 {
		return nil
	}
	out := make([][]byte, len(p.blocks))
	for i, b := range p.blocks {
		out[i] = b.Bytes
	}
	return out
}

// BlockType returns the PEM block type of the first block (e.g., "CERTIFICATE").
// Returns "" if empty.
func (p PEMData) BlockType() string {
	if len(p.blocks) == 0 {
		return ""
	}
	return p.blocks[0].Type
}

// String returns the PEM-encoded string.
func (p PEMData) String() string {
	return string(p.raw)
}

// Bytes returns the raw PEM bytes.
func (p PEMData) Bytes() []byte {
	return p.raw
}

// MarshalJSON encodes PEMData as a JSON string.
func (p PEMData) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(p.raw))
}

// UnmarshalJSON decodes a JSON string and validates it as PEM.
func (p *PEMData) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*p = PEMData{}
		return nil
	}
	blocks, err := decodePEMBlocks([]byte(s))
	if err != nil {
		return err
	}
	p.blocks = blocks
	p.raw = []byte(s)
	return nil
}

func decodePEMBlocks(data []byte) ([]*pem.Block, error) {
	var blocks []*pem.Block
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
	}
	if len(blocks) == 0 {
		return nil, errors.New("issuerapi: no valid PEM blocks found")
	}
	return blocks, nil
}

// Duration wraps time.Duration with JSON marshal/unmarshal as a Go duration
// string (e.g., "24h", "1h30m").
type Duration struct {
	time.Duration
}

// MarshalJSON encodes Duration as a JSON string.
// Zero duration marshals as "" (meaning "use server default").
func (d Duration) MarshalJSON() ([]byte, error) {
	if d.Duration == 0 {
		return json.Marshal("")
	}
	return json.Marshal(d.String())
}

// UnmarshalJSON decodes a JSON string as a Go duration.
// Rejects non-positive values — callers that want "use default" semantics
// should send an empty string (which unmarshals to zero and is distinguished
// from an explicit non-positive duration).
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		d.Duration = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("issuerapi: invalid duration %q: %w", s, err)
	}
	if parsed <= 0 {
		return fmt.Errorf("issuerapi: duration must be positive, got %s", parsed)
	}
	d.Duration = parsed
	return nil
}

// SignCSRRequest is the JSON request body for POST /sign-csr.
type SignCSRRequest struct {
	// EAR is the Entity Attestation Result JWT token from the EAR issuer.
	EAR string `json:"ear"`
	// CSR is the PEM-encoded Certificate Signing Request.
	CSR PEMData `json:"csr"`
	// TTL is the requested certificate lifetime (e.g., "24h"). Capped by MaxTTL.
	TTL Duration `json:"ttl"`
}

// SignCSRResponse is the JSON response for POST /sign-csr.
type SignCSRResponse struct {
	// Certificate is the PEM-encoded signed certificate.
	Certificate PEMData `json:"certificate"`
	// CACertificate is the PEM-encoded CA bundle for chain building.
	CACertificate PEMData `json:"ca_certificate"`
}

// HandoffRequest asks an active cert-issuer replica to wrap its in-memory CA
// signing material to a recipient-bound X25519 public key.
type HandoffRequest struct {
	// EAR is the requester's Entity Attestation Result JWT token.
	EAR string `json:"ear"`
	// PublicKey is the recipient's base64url-encoded raw X25519 public key.
	PublicKey string `json:"public_key"`
	// Signature is a base64url-encoded ECDSA signature over this request's
	// handoff public key, made by the private key bound to EAR's tee_public_key
	// claim.
	Signature string `json:"signature"`
}

// HandoffResponse carries the CA payload encrypted to the requester's public
// key. The issuer EAR lets the requester verify the active replica before
// accepting the unwrapped signing material.
type HandoffResponse struct {
	// IssuerEAR is the active replica's Entity Attestation Result JWT token.
	IssuerEAR string `json:"issuer_ear"`
	// PublicKey is the active replica's base64url-encoded ephemeral X25519
	// public key used for this wrap.
	PublicKey string `json:"public_key"`
	// Signature is a base64url-encoded ECDSA signature over this response's
	// handoff public key, made by the private key bound to IssuerEAR's
	// tee_public_key claim.
	Signature string `json:"signature"`
	// Nonce is the base64url-encoded AES-GCM nonce.
	Nonce string `json:"nonce"`
	// Ciphertext is the base64url-encoded wrapped handoff payload.
	Ciphertext string `json:"ciphertext"`
}
