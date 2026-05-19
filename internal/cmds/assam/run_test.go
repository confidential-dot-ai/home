package assam

import (
	"testing"

	"github.com/lunal-dev/c8s/pkg/resources"
)

func TestBuildWhitelistWriteAllowlist(t *testing.T) {
	allowed, err := buildWhitelistWriteAllowlist(resources.Map{
		"measurement-a": {resources.AssamWhitelistWrite},
		"measurement-b": {"assam/*"},
		"measurement-c": {"cert-issuer/*"},
	})
	if err != nil {
		t.Fatalf("build allowlist: %v", err)
	}

	for _, measurement := range []string{"measurement-a", "measurement-b"} {
		if !allowed[measurement] {
			t.Fatalf("expected %s to be allowed", measurement)
		}
	}
	if allowed["measurement-c"] {
		t.Fatal("measurement-c should not be allowed")
	}
}

func TestBuildWhitelistWriteAllowlistRejectsInvalidGlob(t *testing.T) {
	_, err := buildWhitelistWriteAllowlist(resources.Map{
		"measurement-a": {"["},
	})
	if err == nil {
		t.Fatal("expected invalid glob error")
	}
}
