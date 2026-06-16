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
	wl := &Allowlist{Digests: map[string]string{"sha256:abc": "img"}}
	if !wl.Contains("sha256:abc") {
		t.Error("expected Contains=true")
	}
	if wl.Contains("sha256:missing") {
		t.Error("expected Contains=false")
	}
}
