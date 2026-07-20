package overenc

import (
	"bytes"
	"crypto/sha512"
	"testing"
)

func testTranscriptHash(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, sha512.Size384)
}

func TestHybridChannelRoundTrip(t *testing.T) {
	srv, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := srv.Public()
	if len(pub.X25519) != X25519PubBytes || len(pub.MLKEM768) != MLKEM768EKBytes {
		t.Fatalf("unexpected public key sizes: x25519=%d mlkem=%d", len(pub.X25519), len(pub.MLKEM768))
	}

	transcriptHash := testTranscriptHash(0xA5)
	clientCh, hs, err := ClientAgree(pub, transcriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs.MLKEMCiphertext) != MLKEM768CTBytes {
		t.Fatalf("unexpected ciphertext size %d", len(hs.MLKEMCiphertext))
	}
	serverCh, err := srv.Agree(hs, transcriptHash)
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

func TestChannelRejectsMismatchedTranscript(t *testing.T) {
	srv, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	clientCh, hs, err := ClientAgree(srv.Public(), testTranscriptHash(0xA5))
	if err != nil {
		t.Fatal(err)
	}
	serverCh, err := srv.Agree(hs, testTranscriptHash(0x5A))
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

func TestOpenRejectsTamperedAAD(t *testing.T) {
	srv, _ := GenerateServerKey()
	clientCh, _, err := ClientAgree(srv.Public(), testTranscriptHash(0xA5))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := clientCh.Seal([]byte("x"), RequestAAD())
	if _, err := clientCh.Open(rec, ResponseAAD()); err == nil {
		t.Fatal("expected AAD mismatch to fail authentication")
	}
}

func TestAgreeRejectsWrongSizes(t *testing.T) {
	srv, _ := GenerateServerKey()
	transcriptHash := testTranscriptHash(0xA5)
	if _, err := srv.Agree(Handshake{ClientX25519: make([]byte, 32), MLKEMCiphertext: make([]byte, 10)}, transcriptHash); err == nil {
		t.Fatal("expected error for short ciphertext")
	}
	if _, _, err := ClientAgree(PublicKey{X25519: make([]byte, 32), MLKEM768: make([]byte, 10)}, transcriptHash); err == nil {
		t.Fatal("expected error for short ML-KEM key")
	}
	if _, err := srv.Agree(Handshake{ClientX25519: make([]byte, 32), MLKEMCiphertext: make([]byte, MLKEM768CTBytes)}, nil); err == nil {
		t.Fatal("expected error for missing transcript hash")
	}
	if _, _, err := ClientAgree(srv.Public(), make([]byte, 32)); err == nil {
		t.Fatal("expected error for short transcript hash")
	}
}
