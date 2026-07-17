// Package credrelease implements the in-guest credential-release service (B4
// of the operator-key design). It issues an operator a short-lived kube client
// certificate, but only to a caller who proves possession of the operator
// private key whose public half was bound into the CVM's RTMR[3] at launch —
// giving an external operator console-free, non-TOFU admin access with no
// pre-shared cluster secret and no trust in the untrusted host.
package credrelease

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
)

// operatorPubkeyPath is where the measured initrd stages the operator public
// key it read off the opkeydata disk (and hashed into RTMR[3]). The service
// reads this file rather than mounting the ISO itself — mounting fails under
// the unit's systemd hardening, and the initrd is the single, measured reader
// of the disk anyway.
const operatorPubkeyPath = "/etc/confai/operator-pubkey"

// rtmr3SysfsPath is the TDX runtime-measurement register the initrd extended
// with the operator key digest before switch_root. Reading it back lets the
// service confirm the on-disk operator pubkey is the one that was measured.
const rtmr3SysfsPath = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"

// expectedRTMR3ForKey computes the RTMR[3] value a guest reports after the
// initrd extends the zeroed register once with SHA-384(pubkey):
//
//	RTMR[3] = SHA384( 0x00*48 || SHA384(pubkey) )
//
// This is the same value the operator computes offline from their own key, so
// matching it proves the guest was launched to trust exactly this key.
func expectedRTMR3ForKey(pubkey []byte) []byte {
	keyDigest := sha512.Sum384(pubkey)
	rtmr3 := sha512.Sum384(append(make([]byte, 48), keyDigest[:]...))
	return rtmr3[:]
}

// readOwnRTMR3 reads the guest's current RTMR[3] from the tdx_guest sysfs.
// Returns the raw 48 bytes.
func readOwnRTMR3() ([]byte, error) {
	b, err := os.ReadFile(rtmr3SysfsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w (is this a TDX guest with runtime measurement?)", rtmr3SysfsPath, err)
	}
	if len(b) != 48 {
		return nil, fmt.Errorf("%s: got %d bytes, want 48", rtmr3SysfsPath, len(b))
	}
	return b, nil
}

// verifyKeyMeasured is the load-bearing anchor check: the operator pubkey file
// is NOT itself measured (only its hash, via RTMR[3]), so before trusting the
// on-disk key the service confirms it is the key that was measured. A host
// that swapped the pubkey file post-boot produces a mismatch here — it cannot
// forge RTMR[3], which is set by the (measured) initrd and sealed by the TD.
//
// With this check, the on-disk pubkey is anchored to RTMR[3], and RTMR[3] is
// what the operator's own attestation pins to their key: both directions bind
// to the same measured key, so neither side trusts the host.
func verifyKeyMeasured(pubkey []byte) error {
	own, err := readOwnRTMR3()
	if err != nil {
		return err
	}
	want := expectedRTMR3ForKey(pubkey)
	// Not secret (a public-key hash) — plain compare is fine.
	if !bytes.Equal(own, want) {
		return fmt.Errorf(
			"operator pubkey does not match the measured RTMR[3]: got %s, key implies %s (was the pubkey file substituted after boot?)",
			hex.EncodeToString(own), hex.EncodeToString(want))
	}
	return nil
}

// readOperatorPubkey reads the operator public key the initrd staged from the
// opkeydata disk. The bytes are exactly what the initrd hashed into RTMR[3],
// so verifyKeyMeasured can re-derive the same digest. Absence means the VM was
// launched without an operator key (no opkeydata disk).
func readOperatorPubkey() ([]byte, error) {
	pub, err := os.ReadFile(operatorPubkeyPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w — was the VM launched with an operator key?", operatorPubkeyPath, err)
	}
	if len(pub) == 0 {
		return nil, fmt.Errorf("%s is empty", operatorPubkeyPath)
	}
	return pub, nil
}

// LoadMeasuredOperatorKey reads the operator pubkey off the opkeydata disk and
// verifies it against RTMR[3]. The returned bytes are safe to trust as the
// authorized operator key. This is called once at service start; the key is
// fixed for the life of the TD.
func LoadMeasuredOperatorKey() ([]byte, error) {
	pub, err := readOperatorPubkey()
	if err != nil {
		return nil, err
	}
	if err := verifyKeyMeasured(pub); err != nil {
		return nil, err
	}
	return pub, nil
}
