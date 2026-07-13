package rtmr3

import (
	"encoding/hex"
	"testing"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// Golden vectors pin the convention. If any of these change, the measurer
// and every verifier disagree on RTMR[3] — treat a failure here as a
// breaking change to the attestation contract, not a test to update.
func TestConventionGoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  [Size]byte
		want string
	}{
		{"Event(A)", Event(digestA),
			"a3f24413601f0cebf6316f0e499927cbf4adae24d5421f94abdc135fa464bbbb2afb7075b075976eff5379cd25c3f8f2"},
		{"FromDigests[A]", FromDigests([]string{digestA}),
			"c22e78b178c845f91bdc8f575cd3e3b058a7903892807f81129f878df35bdf6566bd18dbcc5dce9177963b1d0e2889f3"},
		{"FromDigests[A,B]", FromDigests([]string{digestA, digestB}),
			"6e06070a4178ba9617ce1598f0e749a05c2e0b9c59e74236265f04d505348e203204ff3a7f920009b87ab272b34c3146"},
	} {
		if got := hex.EncodeToString(tc.got[:]); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestFromDigestsEmptyIsZero(t *testing.T) {
	if FromDigests(nil) != Zero {
		t.Error("FromDigests(nil) must equal the boot value Zero")
	}
}

func TestExtendMatchesFold(t *testing.T) {
	step := Extend(Extend(Zero, Event(digestA)), Event(digestB))
	if step != FromDigests([]string{digestA, digestB}) {
		t.Error("Extend composition disagrees with FromDigests")
	}
}
