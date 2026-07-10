package overenc

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

func TestIdentityTranscriptHashBindsEveryField(t *testing.T) {
	pub := PublicKey{
		X25519:   bytes.Repeat([]byte{0x11}, X25519PubBytes),
		MLKEM768: bytes.Repeat([]byte{0x22}, MLKEM768EKBytes),
	}
	nonce := bytes.Repeat([]byte{0x33}, identityNonceBytes)
	leaf := []byte("leaf-der")
	ca := []byte("ca-der")

	base, err := IdentityTranscriptHash(pub, nonce, leaf, ca)
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != sha512.Size384 {
		t.Fatalf("transcript hash length = %d, want %d", len(base), sha512.Size384)
	}
	const vector = "f6f10a6a95249c535ae3210248fa2c2fbe214744edffe53809795a877840731728175a35dd8091a1e15263190032b3f2"
	if hex.EncodeToString(base) != vector {
		t.Fatalf("cross-language transcript vector = %x, want %s", base, vector)
	}

	tests := []struct {
		name  string
		pub   PublicKey
		nonce []byte
		leaf  []byte
		ca    []byte
	}{
		{name: "x25519", pub: PublicKey{X25519: bytes.Repeat([]byte{0x44}, X25519PubBytes), MLKEM768: pub.MLKEM768}, nonce: nonce, leaf: leaf, ca: ca},
		{name: "mlkem", pub: PublicKey{X25519: pub.X25519, MLKEM768: bytes.Repeat([]byte{0x55}, MLKEM768EKBytes)}, nonce: nonce, leaf: leaf, ca: ca},
		{name: "nonce", pub: pub, nonce: bytes.Repeat([]byte{0x66}, identityNonceBytes), leaf: leaf, ca: ca},
		{name: "leaf", pub: pub, nonce: nonce, leaf: []byte("other-leaf"), ca: ca},
		{name: "ca", pub: pub, nonce: nonce, leaf: leaf, ca: []byte("other-ca")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IdentityTranscriptHash(tt.pub, tt.nonce, tt.leaf, tt.ca)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, base) {
				t.Fatal("changed field did not change transcript hash")
			}
		})
	}
}

func TestIdentityTranscriptHashValidatesShape(t *testing.T) {
	valid := PublicKey{X25519: make([]byte, X25519PubBytes), MLKEM768: make([]byte, MLKEM768EKBytes)}
	for _, tc := range []struct {
		name  string
		pub   PublicKey
		nonce []byte
		leaf  []byte
		ca    []byte
	}{
		{name: "x25519", pub: PublicKey{X25519: make([]byte, 1), MLKEM768: valid.MLKEM768}, nonce: make([]byte, identityNonceBytes), leaf: []byte{1}, ca: []byte{2}},
		{name: "mlkem", pub: PublicKey{X25519: valid.X25519, MLKEM768: make([]byte, 1)}, nonce: make([]byte, identityNonceBytes), leaf: []byte{1}, ca: []byte{2}},
		{name: "nonce", pub: valid, nonce: make([]byte, 16), leaf: []byte{1}, ca: []byte{2}},
		{name: "leaf", pub: valid, nonce: make([]byte, identityNonceBytes), ca: []byte{2}},
		{name: "ca", pub: valid, nonce: make([]byte, identityNonceBytes), leaf: []byte{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := IdentityTranscriptHash(tc.pub, tc.nonce, tc.leaf, tc.ca); err == nil {
				t.Fatal("invalid transcript input accepted")
			}
		})
	}
}

func TestIdentityProofMessageIsDomainSeparated(t *testing.T) {
	h := bytes.Repeat([]byte{0x77}, sha512.Size384)
	message, err := IdentityProofMessage(h)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(message, []byte(identityProofDomain)) || !bytes.Contains(message, h) {
		t.Fatalf("proof message does not contain its domain and transcript hash: %x", message)
	}
	if _, err := IdentityProofMessage(h[:len(h)-1]); err == nil {
		t.Fatal("short transcript hash accepted")
	}
}
