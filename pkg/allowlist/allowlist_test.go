package allowlist

import (
	"strings"
	"testing"
)

func TestParseJSON_Valid(t *testing.T) {
	data := `{"version":"1","digests":{"sha256:` + strings.Repeat("a", 64) + `":"img1"}}`
	wl, err := ParseJSON([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(wl.Digests) != 1 {
		t.Fatalf("got %d digests, want 1", len(wl.Digests))
	}
}

func TestParseJSON_EmptyDigests(t *testing.T) {
	wl, err := ParseJSON([]byte(`{"version":"1","digests":{}}`))
	if err != nil {
		t.Fatalf("empty digests should be accepted: %v", err)
	}
	if len(wl.Digests) != 0 {
		t.Fatalf("got %d digests, want 0", len(wl.Digests))
	}
}

func TestParseJSON_InvalidDigest(t *testing.T) {
	_, err := ParseJSON([]byte(`{"version":"1","digests":{"baddigest":"img"}}`))
	if err == nil {
		t.Fatal("expected error for invalid digest format")
	}
}

func TestParseJSON_BadJSON(t *testing.T) {
	_, err := ParseJSON([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}

func TestContains(t *testing.T) {
	present := "sha256:" + strings.Repeat("a", 64)
	absent := "sha256:" + strings.Repeat("b", 64)
	wl := &Allowlist{Digests: map[string]string{present: "img"}}
	if !wl.Contains(present) {
		t.Error("expected Contains=true for present digest")
	}
	if wl.Contains(absent) {
		t.Error("expected Contains=false for absent digest")
	}
	if wl.Contains("not-a-digest") {
		t.Error("expected Contains=false for a malformed digest")
	}
}

// TestContainsIsCaseInsensitive guards the enforcement bug where an uppercase
// allowlist entry would miss the lowercase digest containerd resolves (and the
// reverse). Both the stored key and the lookup are canonicalized to lowercase.
func TestContainsIsCaseInsensitive(t *testing.T) {
	lower := "sha256:" + strings.Repeat("a", 64)
	upper := "sha256:" + strings.Repeat("A", 64)

	t.Run("uppercase entry, lowercase lookup", func(t *testing.T) {
		wl, err := ParseJSON([]byte(`{"version":"1","digests":{"` + upper + `":"img"}}`))
		if err != nil {
			t.Fatal(err)
		}
		if !wl.Contains(lower) {
			t.Error("lowercase lookup missed an uppercase allowlist entry")
		}
	})

	t.Run("lowercase entry, uppercase lookup", func(t *testing.T) {
		wl, err := ParseJSON([]byte(`{"version":"1","digests":{"` + lower + `":"img"}}`))
		if err != nil {
			t.Fatal(err)
		}
		if !wl.Contains(upper) {
			t.Error("uppercase lookup missed a lowercase allowlist entry")
		}
	})
}
