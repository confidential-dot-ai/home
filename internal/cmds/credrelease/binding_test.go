package credrelease

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

// TestExpectedRTMR3ForKey checks the two-step formula
// RTMR[3] = SHA384(0x00*48 || SHA384(pubkey)) against an independent compute.
func TestExpectedRTMR3ForKey(t *testing.T) {
	pub := []byte("some operator public key bytes")
	got := hex.EncodeToString(expectedRTMR3ForKey(pub))

	keyDigest := sha512.Sum384(pub)
	want := sha512.Sum384(append(make([]byte, 48), keyDigest[:]...))
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("expectedRTMR3ForKey = %s, want %s", got, hex.EncodeToString(want[:]))
	}
}

// TestExpectedRTMR3MatchesHardware pins to the exact value the B1+B2 hardware
// run produced, computed from the same key-digest the guest reported.
func TestExpectedRTMR3MatchesHardware(t *testing.T) {
	// keyDigest = SHA-384(operator pubkey) from the b200 run; wantRTMR3 is
	// what /sys/.../rtmr3:sha384 read back after that launch.
	const (
		keyDigest = "0c06aa4f364e480ece13c58b1585dab43d7222fa331ccc9ff05ea18fdd39a4d9d75e87d711ac6aeda2782c2e339de7c1"
		wantRTMR3 = "db479dfe6333f8d3a2761494b6004bc4332688c6d5b72577b48ecfc0409e4cb53988dcd26b89ec605a81b00e7f0e0863"
	)
	dig, err := hex.DecodeString(keyDigest)
	if err != nil {
		t.Fatal(err)
	}
	// expectedRTMR3ForKey hashes the pubkey; here we already have the digest,
	// so replicate the second step directly and compare to the pinned value.
	rtmr3 := sha512.Sum384(append(make([]byte, 48), dig...))
	if got := hex.EncodeToString(rtmr3[:]); got != wantRTMR3 {
		t.Errorf("RTMR[3] from key digest = %s, want %s (hardware-confirmed)", got, wantRTMR3)
	}
}
