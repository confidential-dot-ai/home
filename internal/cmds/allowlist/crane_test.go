package allowlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// With crane off PATH, the crane-backed commands must fail with an actionable
// message rather than an opaque exec error from the first crane call.

func TestInspectImageRequiresCrane(t *testing.T) {
	t.Setenv("PATH", "")
	_, _, err := runCmd("inspect-image", "docker.io/library/busybox:latest")
	if err == nil || !strings.Contains(err.Error(), "crane") {
		t.Fatalf("expected a crane-not-found error, got %v", err)
	}
}

func TestLintOnlineRequiresCrane(t *testing.T) {
	f := filepath.Join(t.TempDir(), "al.json")
	if err := os.WriteFile(f, []byte(`{"schema":"c8s.allowlist/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	_, _, err := runCmd("lint", "--online", f)
	if err == nil || !strings.Contains(err.Error(), "crane") {
		t.Fatalf("expected a crane-not-found error, got %v", err)
	}
}

func TestLintOfflineDoesNotNeedCrane(t *testing.T) {
	f := filepath.Join(t.TempDir(), "al.json")
	if err := os.WriteFile(f, []byte(`{"schema":"c8s.allowlist/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	if _, _, err := runCmd("lint", f); err != nil {
		t.Fatalf("offline lint must not require crane, got %v", err)
	}
}
