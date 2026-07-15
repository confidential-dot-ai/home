// Package overenc implements the c8s-verify post-quantum over-encryption channel
// that terminates inside the Load Balancer's TEE. It is the Go counterpart of the
// browser library's keyagreement.js + channel.js and is wire-compatible with it
// (see c8s-verify-js/PROTOCOL.md).
//
// Hybrid KEM = X25519 (crypto/ecdh) + ML-KEM-768 (crypto/mlkem), combined per the
// TLS X25519MLKEM768 convention, run through HKDF-SHA256 to an AES-256-GCM key.
// The classical and post-quantum shared secrets are concatenated so the channel
// stays secure as long as EITHER primitive holds.
package overenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

const (
	hkdfInfo = "c8s-verify/v1/over-encryption"
	ivBytes  = 12

	// X25519PubBytes is the raw X25519 public key length.
	X25519PubBytes = 32
	// MLKEM768EKBytes is the ML-KEM-768 encapsulation (public) key length.
	MLKEM768EKBytes = 1184
	// MLKEM768CTBytes is the ML-KEM-768 ciphertext length.
	MLKEM768CTBytes = 1088
)

// PublicKey is the LB's per-session hybrid public key, published in the
// attestation bundle and bound into the hardware report_data.
type PublicKey struct {
	X25519   []byte // 32 bytes
	MLKEM768 []byte // 1184 bytes
}

// Handshake is what the client sends to the LB to establish the channel.
type Handshake struct {
	ClientX25519    []byte // 32 bytes
	MLKEMCiphertext []byte // 1088 bytes
}

// ServerKey holds the LB-side private halves of a per-session hybrid keypair.
// The private material never leaves the process.
type ServerKey struct {
	x25519 *ecdh.PrivateKey
	mlkem  *mlkem.DecapsulationKey768
	pub    PublicKey
}

// GenerateServerKey creates a fresh hybrid keypair for one client session.
func GenerateServerKey() (*ServerKey, error) {
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("overenc: generate X25519 key: %w", err)
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("overenc: generate ML-KEM-768 key: %w", err)
	}
	return &ServerKey{
		x25519: xPriv,
		mlkem:  dk,
		pub: PublicKey{
			X25519:   xPriv.PublicKey().Bytes(),
			MLKEM768: dk.EncapsulationKey().Bytes(),
		},
	}, nil
}

// Public returns the raw public halves to publish.
func (s *ServerKey) Public() PublicKey { return s.pub }

// Agree completes the handshake on the LB side: decapsulate the client's
// ML-KEM ciphertext, ECDH against the client's X25519 key, and derive the
// AES-256-GCM channel keyed to the identity transcript. transcriptHash is the
// SHA-384 value committed to report_data and verified by the client.
func (s *ServerKey) Agree(hs Handshake, transcriptHash []byte) (*Channel, error) {
	if len(transcriptHash) != sha512.Size384 {
		return nil, fmt.Errorf("overenc: identity transcript hash must be %d bytes, got %d", sha512.Size384, len(transcriptHash))
	}
	return s.agree(hs, transcriptHash)
}

func (s *ServerKey) agree(hs Handshake, salt []byte) (*Channel, error) {
	if len(hs.MLKEMCiphertext) != MLKEM768CTBytes {
		return nil, fmt.Errorf("overenc: ML-KEM ciphertext must be %d bytes, got %d", MLKEM768CTBytes, len(hs.MLKEMCiphertext))
	}
	if len(hs.ClientX25519) != X25519PubBytes {
		return nil, fmt.Errorf("overenc: client X25519 key must be %d bytes, got %d", X25519PubBytes, len(hs.ClientX25519))
	}
	mlkemSS, err := s.mlkem.Decapsulate(hs.MLKEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("overenc: ML-KEM decapsulate: %w", err)
	}
	clientPub, err := ecdh.X25519().NewPublicKey(hs.ClientX25519)
	if err != nil {
		return nil, fmt.Errorf("overenc: parse client X25519 key: %w", err)
	}
	x25519SS, err := s.x25519.ECDH(clientPub)
	if err != nil {
		return nil, fmt.Errorf("overenc: X25519 ECDH: %w", err)
	}
	return deriveChannel(mlkemSS, x25519SS, salt)
}

// ClientAgree is the client side, provided for Go clients and interop tests:
// encapsulate against the LB's hybrid public key and derive the same channel
// from the verified identity transcript.
func ClientAgree(pub PublicKey, transcriptHash []byte) (*Channel, Handshake, error) {
	if len(transcriptHash) != sha512.Size384 {
		return nil, Handshake{}, fmt.Errorf("overenc: identity transcript hash must be %d bytes, got %d", sha512.Size384, len(transcriptHash))
	}
	return clientAgree(pub, transcriptHash)
}

func clientAgree(pub PublicKey, salt []byte) (*Channel, Handshake, error) {
	if len(pub.MLKEM768) != MLKEM768EKBytes {
		return nil, Handshake{}, fmt.Errorf("overenc: ML-KEM key must be %d bytes, got %d", MLKEM768EKBytes, len(pub.MLKEM768))
	}
	if len(pub.X25519) != X25519PubBytes {
		return nil, Handshake{}, fmt.Errorf("overenc: X25519 key must be %d bytes, got %d", X25519PubBytes, len(pub.X25519))
	}
	ek, err := mlkem.NewEncapsulationKey768(pub.MLKEM768)
	if err != nil {
		return nil, Handshake{}, fmt.Errorf("overenc: parse ML-KEM key: %w", err)
	}
	mlkemSS, ct := ek.Encapsulate()

	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, Handshake{}, fmt.Errorf("overenc: generate client X25519 key: %w", err)
	}
	serverPub, err := ecdh.X25519().NewPublicKey(pub.X25519)
	if err != nil {
		return nil, Handshake{}, fmt.Errorf("overenc: parse server X25519 key: %w", err)
	}
	x25519SS, err := clientPriv.ECDH(serverPub)
	if err != nil {
		return nil, Handshake{}, fmt.Errorf("overenc: X25519 ECDH: %w", err)
	}
	ch, err := deriveChannel(mlkemSS, x25519SS, salt)
	if err != nil {
		return nil, Handshake{}, err
	}
	return ch, Handshake{ClientX25519: clientPriv.PublicKey().Bytes(), MLKEMCiphertext: ct}, nil
}

func deriveChannel(mlkemSS, x25519SS, salt []byte) (*Channel, error) {
	ikm := make([]byte, 0, len(mlkemSS)+len(x25519SS))
	ikm = append(ikm, mlkemSS...)
	ikm = append(ikm, x25519SS...)
	key, err := hkdf.Key(sha256.New, ikm, salt, hkdfInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("overenc: HKDF: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("overenc: AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("overenc: GCM: %w", err)
	}
	return &Channel{aead: aead}, nil
}

// Record is one AES-256-GCM record on the wire. Both fields are raw bytes,
// carried as CBOR byte strings by the tunnel transport — no base64 inflation.
type Record struct {
	IV []byte `cbor:"iv" json:"iv"`
	CT []byte `cbor:"ct" json:"ct"`
}

// Channel is a symmetric over-encryption channel; both ends hold an identical key.
type Channel struct {
	aead cipher.AEAD
}

// RequestAAD is the additional-authenticated-data domain separator for request
// records. The method and path are sealed inside the request envelope, so the
// AAD is a fixed tag rather than per-route.
func RequestAAD() []byte { return []byte("c8s-verify/v1/tunnel-request") }

// ResponseAAD is the AAD domain separator for response records.
func ResponseAAD() []byte { return []byte("c8s-verify/v1/tunnel-response") }

// Seal encrypts plaintext with a fresh random IV.
func (c *Channel) Seal(plaintext, aad []byte) (Record, error) {
	iv := make([]byte, ivBytes)
	if _, err := rand.Read(iv); err != nil {
		return Record{}, fmt.Errorf("overenc: generate IV: %w", err)
	}
	ct := c.aead.Seal(nil, iv, plaintext, aad)
	return Record{IV: iv, CT: ct}, nil
}

// Open decrypts and authenticates a record.
func (c *Channel) Open(rec Record, aad []byte) ([]byte, error) {
	if len(rec.IV) != ivBytes {
		return nil, fmt.Errorf("overenc: IV must be %d bytes", ivBytes)
	}
	pt, err := c.aead.Open(nil, rec.IV, rec.CT, aad)
	if err != nil {
		return nil, fmt.Errorf("overenc: authentication failed: %w", err)
	}
	return pt, nil
}
