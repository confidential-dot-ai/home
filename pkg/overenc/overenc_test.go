package overenc

import (
	"bytes"
	"crypto/rand"
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

// channelPair returns an agreed (server, client) channel pair for tests.
func channelPair(t *testing.T) (server, client *Channel) {
	t.Helper()
	nonce := make([]byte, 32)
	rand.Read(nonce)
	srv, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	clientCh, hs, err := ClientAgree(srv.Public(), nonce)
	if err != nil {
		t.Fatal(err)
	}
	serverCh, err := srv.Agree(hs, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return serverCh, clientCh
}

func TestOpenRejectsReplayedRecord(t *testing.T) {
	serverCh, clientCh := channelPair(t)

	rec, err := clientCh.Seal([]byte("transfer $100"), RequestAAD())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverCh.Open(rec, RequestAAD()); err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	// Resubmitting the exact same authenticated record must not decrypt to a
	// second backend action.
	if _, err := serverCh.Open(rec, RequestAAD()); err == nil {
		t.Fatal("replayed record accepted; want rejection")
	}
	// A fresh, distinct record from the same channel still opens.
	rec2, err := clientCh.Seal([]byte("transfer $200"), RequestAAD())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverCh.Open(rec2, RequestAAD()); err != nil {
		t.Fatalf("distinct record rejected: %v", err)
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
