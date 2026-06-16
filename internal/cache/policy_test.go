package cache

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestGetAllowlist_NilByDefault(t *testing.T) {
	c := NewPolicyCache()
	if c.GetAllowlist() != nil {
		t.Error("expected nil allowlist initially")
	}
}

func TestSetAllowlist(t *testing.T) {
	c := NewPolicyCache()
	wl := &allowlist.Allowlist{
		Version: "1.0",
		Digests: map[string]string{"sha256:" + strings.Repeat("a", 64): "test"},
	}
	c.SetAllowlist(wl)

	got := c.GetAllowlist()
	if got == nil {
		t.Fatal("expected allowlist after SetAllowlist")
	}
	if len(got.Digests) != 1 {
		t.Errorf("expected 1 digest, got %d", len(got.Digests))
	}
}

func TestClear(t *testing.T) {
	c := NewPolicyCache()
	wl := &allowlist.Allowlist{
		Version: "1.0",
		Digests: map[string]string{"sha256:" + strings.Repeat("a", 64): "test"},
	}
	c.SetAllowlist(wl)
	c.Clear()

	if c.GetAllowlist() != nil {
		t.Error("expected nil allowlist after Clear")
	}
}
