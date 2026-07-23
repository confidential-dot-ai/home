package allowlist

import (
	"bytes"
	"testing"
)

// Canonical (and so CanonicalDigest) must be a function of the allowlist's
// content, not the source file's formatting — the chart-rendered seed, the
// install-time probe render, and the file an operator pins at verify time
// only agree through this property (docs/ratls.md).
func TestCanonicalDigestIgnoresFormatting(t *testing.T) {
	const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const digestAUpper = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	variants := []string{
		`{"version":"1","digests":{"` + digestA + `":"ghcr.io/x/cds:v1","` + digestB + `":"ghcr.io/x/as:v1"}}`,
		"{\n  \"digests\": {\n    \"" + digestB + "\": \"ghcr.io/x/as:v1\",\n    \"" + digestA + "\": \"ghcr.io/x/cds:v1\"\n  },\n  \"version\": \"1\"\n}",
		// Digest hex case differs; ParseJSON canonicalizes to lowercase.
		`{"version":"1","digests":{"` + digestAUpper + `":"ghcr.io/x/cds:v1","` + digestB + `":"ghcr.io/x/as:v1"}}`,
	}

	var first []byte
	for i, v := range variants {
		wl, err := ParseJSON([]byte(v))
		if err != nil {
			t.Fatalf("variant %d: %v", i, err)
		}
		d, err := wl.CanonicalDigest()
		if err != nil {
			t.Fatalf("variant %d: %v", i, err)
		}
		if first == nil {
			first = d
			continue
		}
		if !bytes.Equal(first, d) {
			t.Fatalf("variant %d canonical digest differs: %x != %x", i, first, d)
		}
	}

	other, err := ParseJSON([]byte(`{"version":"1","digests":{"` + digestA + `":"ghcr.io/x/evil:v1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	d, err := other.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, d) {
		t.Fatal("different content produced the same canonical digest")
	}
}

// Two case-variant spellings of the same digest are distinct JSON keys that
// collapse to one canonical entry; which image value survived would depend on
// map iteration order, so CanonicalDigest of the very same bytes would differ
// between runs. ParseJSON must reject the input instead (fail closed).
func TestParseJSONRejectsCaseVariantDuplicateDigests(t *testing.T) {
	const lower = "sha256:abababababababababababababababababababababababababababababababab"
	const upper = "sha256:ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"

	_, err := ParseJSON([]byte(`{"version":"1","digests":{"` + lower + `":"ghcr.io/x/a:v1","` + upper + `":"ghcr.io/x/b:v1"}}`))
	if err == nil {
		t.Fatal("case-variant duplicate digest keys accepted")
	}
}
