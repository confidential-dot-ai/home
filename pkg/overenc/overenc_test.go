package overenc

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"testing"
)

func TestHybridChannelRoundTrip(t *testing.T) {
	nonce := make([]byte, 32)
	rand.Read(nonce)

	srv, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := srv.Public()
	if len(pub.X25519) != X25519PubBytes || len(pub.MLKEM768) != MLKEM768EKBytes {
		t.Fatalf("unexpected public key sizes: x25519=%d mlkem=%d", len(pub.X25519), len(pub.MLKEM768))
	}

	clientCh, hs, err := ClientAgree(pub, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs.MLKEMCiphertext) != MLKEM768CTBytes {
		t.Fatalf("unexpected ciphertext size %d", len(hs.MLKEMCiphertext))
	}
	serverCh, err := srv.Agree(hs, nonce)
	if err != nil {
		t.Fatal(err)
	}

	aad := RequestAAD()
	rec, err := clientCh.Seal([]byte("hello pq"), aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := serverCh.Open(rec, aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello pq" {
		t.Fatalf("got %q", got)
	}

	// Reverse direction (server -> client).
	rec2, _ := serverCh.Seal([]byte("pong"), ResponseAAD())
	got2, err := clientCh.Open(rec2, ResponseAAD())
	if err != nil || string(got2) != "pong" {
		t.Fatalf("reverse round-trip failed: %v %q", err, got2)
	}
}

func TestIdentityChannelRoundTrip(t *testing.T) {
	srv, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	transcriptHash := bytes.Repeat([]byte{0xA5}, sha512.Size384)
	clientCh, hs, err := ClientAgreeIdentity(srv.Public(), transcriptHash)
	if err != nil {
		t.Fatal(err)
	}
	serverCh, err := srv.AgreeIdentity(hs, transcriptHash)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := clientCh.Seal([]byte("identity-bound"), RequestAAD())
	if err != nil {
		t.Fatal(err)
	}
	got, err := serverCh.Open(rec, RequestAAD())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "identity-bound" {
		t.Fatalf("opened %q", got)
	}
}

func TestIdentityChannelRejectsMismatchedTranscript(t *testing.T) {
	srv, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	clientHash := bytes.Repeat([]byte{0xA5}, sha512.Size384)
	serverHash := bytes.Repeat([]byte{0x5A}, sha512.Size384)
	clientCh, hs, err := ClientAgreeIdentity(srv.Public(), clientHash)
	if err != nil {
		t.Fatal(err)
	}
	serverCh, err := srv.AgreeIdentity(hs, serverHash)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := clientCh.Seal([]byte("secret"), RequestAAD())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverCh.Open(rec, RequestAAD()); err == nil {
		t.Fatal("mismatched identity transcript derived the same channel")
	}
}

func TestWrongNonceDerivesDifferentKey(t *testing.T) {
	n1 := bytes.Repeat([]byte{1}, 32)
	n2 := bytes.Repeat([]byte{2}, 32)
	srv, _ := GenerateServerKey()
	clientCh, hs, _ := ClientAgree(srv.Public(), n1)
	serverCh, _ := srv.Agree(hs, n2) // mismatched nonce
	rec, _ := clientCh.Seal([]byte("secret"), ResponseAAD())
	if _, err := serverCh.Open(rec, ResponseAAD()); err == nil {
		t.Fatal("expected open to fail with mismatched nonce-derived key")
	}
}

func TestOpenRejectsTamperedAAD(t *testing.T) {
	nonce := make([]byte, 32)
	srv, _ := GenerateServerKey()
	clientCh, hs, _ := ClientAgree(srv.Public(), nonce)
	srv.Agree(hs, nonce)
	rec, _ := clientCh.Seal([]byte("x"), RequestAAD())
	if _, err := clientCh.Open(rec, ResponseAAD()); err == nil {
		t.Fatal("expected AAD mismatch to fail authentication")
	}
}

func TestAgreeRejectsWrongSizes(t *testing.T) {
	srv, _ := GenerateServerKey()
	if _, err := srv.Agree(Handshake{ClientX25519: make([]byte, 32), MLKEMCiphertext: make([]byte, 10)}, nil); err == nil {
		t.Fatal("expected error for short ciphertext")
	}
	if _, _, err := ClientAgree(PublicKey{X25519: make([]byte, 32), MLKEM768: make([]byte, 10)}, nil); err == nil {
		t.Fatal("expected error for short ML-KEM key")
	}
}
