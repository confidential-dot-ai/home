package secretspolicy

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

func TestParseAndLookupByDigest(t *testing.T) {
	p, err := ParseJSON([]byte(`{"entries":[
		{"workloadDigest":"AABBCC","allow":["secret/data/api/*#password"]},
		{"workloadDigest":"aabbcc","allow":["secret/data/shared/*"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	// Case-insensitive digest match; union across matching entries.
	got := p.Lookup("aabbcc")
	if len(got) != 2 {
		t.Fatalf("Lookup = %v, want 2 globs", got)
	}
	if p.Lookup("ddeeff") != nil {
		t.Fatal("unknown digest must grant nothing")
	}
}

func TestWorkloadImagesHashesToDigest(t *testing.T) {
	main := []string{"sha256:" + strings.Repeat("ab", 32)}
	dg, err := workloadclaims.Digest(nil, main)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseJSON([]byte(`{"entries":[{"workloadImages":{"main":["sha256:` +
		strings.Repeat("ab", 32) + `"]},"allow":["secret/data/x"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	// The entry named images; Lookup by the computed digest must match.
	if got := p.Lookup(hex.EncodeToString(dg)); len(got) != 1 {
		t.Fatalf("Lookup by image-derived digest = %v, want the grant", got)
	}
}

func TestParseRejectsBadEntries(t *testing.T) {
	cases := []string{
		`{"entries":[{"allow":["x"]}]}`, // no workload
		`{"entries":[{"workloadDigest":"aa","workloadImages":{"main":["x"]},"allow":["x"]}]}`, // both
		`{"entries":[{"workloadDigest":"aa"}]}`,                                               // no allow
		`{"entries":[{"workloadDigest":"nothex","allow":["x"]}]}`,                             // bad hex
		`{"entries":[{"workloadDigest":"aa","allow":["secret/x#"]}]}`,                         // stray '#'
		`{"entries":[{"workloadDigest":"aa","allow":["x"]}],"extra":1}`,                       // unknown field
	}
	for i, c := range cases {
		if _, err := ParseJSON([]byte(c)); err == nil {
			t.Errorf("case %d: expected error for %s", i, c)
		}
	}
}

func TestCanonicalIsOrderIndependent(t *testing.T) {
	a, err := ParseJSON([]byte(`{"entries":[
		{"workloadDigest":"bb","allow":["z","a"]},
		{"workloadDigest":"aa","allow":["m"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseJSON([]byte(`{"entries":[
		{"workloadDigest":"aa","allow":["m"]},
		{"workloadDigest":"bb","allow":["a","z"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := a.Canonical()
	cb, _ := b.Canonical()
	if !bytes.Equal(ca, cb) {
		t.Fatalf("canonical forms differ despite same logical policy:\n%s\n%s", ca, cb)
	}
	da, _ := a.CanonicalDigest()
	db, _ := b.CanonicalDigest()
	if !bytes.Equal(da, db) {
		t.Fatal("canonical digests differ")
	}
}
