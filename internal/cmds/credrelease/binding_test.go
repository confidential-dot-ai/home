package credrelease

import (
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// overrideBindingPaths points the package's sysfs/staging paths at files under
// a temp dir for the duration of the test. The files do not exist yet; each
// test writes what its scenario needs.
func overrideBindingPaths(t *testing.T) (pubPath, rtmrPath string) {
	t.Helper()
	dir := t.TempDir()
	pubPath = filepath.Join(dir, "operator-pubkey")
	rtmrPath = filepath.Join(dir, "rtmr3")
	origPub, origRTMR := operatorPubkeyPath, rtmr3SysfsPath
	operatorPubkeyPath, rtmr3SysfsPath = pubPath, rtmrPath
	t.Cleanup(func() { operatorPubkeyPath, rtmr3SysfsPath = origPub, origRTMR })
	return pubPath, rtmrPath
}

func writeFileT(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

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

// TestLoadMeasuredOperatorKey covers the happy path: the staged pubkey matches
// the (fake) RTMR[3] the initrd would have extended, so the key is released.
func TestLoadMeasuredOperatorKey(t *testing.T) {
	pubPath, rtmrPath := overrideBindingPaths(t)
	pub := []byte("operator public key bytes")
	writeFileT(t, pubPath, pub)
	writeFileT(t, rtmrPath, expectedRTMR3ForKey(pub))

	got, err := LoadMeasuredOperatorKey()
	if err != nil {
		t.Fatalf("LoadMeasuredOperatorKey: %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("returned key = %q, want %q", got, pub)
	}
}

// TestLoadMeasuredOperatorKeyFailsClosed enumerates the ways the anchor check
// must refuse: substituted key, malformed or missing RTMR, missing/empty key.
func TestLoadMeasuredOperatorKeyFailsClosed(t *testing.T) {
	pub := []byte("operator public key bytes")
	tests := []struct {
		name    string
		stage   func(t *testing.T, pubPath, rtmrPath string)
		wantErr string
	}{
		{
			name: "substituted pubkey",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, []byte("a different key the host swapped in"))
				writeFileT(t, rtmrPath, expectedRTMR3ForKey(pub))
			},
			wantErr: "does not match the measured RTMR[3]",
		},
		{
			name: "rtmr wrong length",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, pub)
				writeFileT(t, rtmrPath, make([]byte, 47))
			},
			wantErr: "want 48",
		},
		{
			name: "rtmr missing",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, pub)
			},
			wantErr: "is this a TDX guest",
		},
		{
			name:    "pubkey missing",
			stage:   func(t *testing.T, pubPath, rtmrPath string) {},
			wantErr: "was the VM launched with an operator key?",
		},
		{
			name: "pubkey empty",
			stage: func(t *testing.T, pubPath, rtmrPath string) {
				writeFileT(t, pubPath, nil)
			},
			wantErr: "is empty",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubPath, rtmrPath := overrideBindingPaths(t)
			tc.stage(t, pubPath, rtmrPath)
			_, err := LoadMeasuredOperatorKey()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}
