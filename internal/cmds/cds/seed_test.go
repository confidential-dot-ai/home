package cds

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func writeSeed(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
	return path
}

func digest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("parse digest %q: %v", s, err)
	}
	return d
}

const (
	digestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func TestSeedStore_AddsAllEntries(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	path := writeSeed(t, `{"version":"1","digests":{"`+digestA+`":"ghcr.io/x/cds:v1","`+digestB+`":"ghcr.io/x/as:v1"}}`)
	if err := seedStore(&store, path); err != nil {
		t.Fatalf("seedStore: %v", err)
	}

	_, got, err := store.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("seeded %d digests, want 2: %v", len(got), got)
	}
	if got[digest(t, digestA)] != "ghcr.io/x/cds:v1" {
		t.Errorf("digestA image = %q, want ghcr.io/x/cds:v1", got[digest(t, digestA)])
	}
}

// Re-seeding the same set on every CDS restart must not bump the store version;
// the version is the worker pull ETag, so churn would force every worker to
// re-pull on every CDS restart.
func TestSeedStore_IdempotentDoesNotBumpVersion(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	path := writeSeed(t, `{"version":"1","digests":{"`+digestA+`":"ghcr.io/x/cds:v1"}}`)
	if err := seedStore(&store, path); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	v1, _, err := store.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}

	if err := seedStore(&store, path); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	v2, _, err := store.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if v1 != v2 {
		t.Fatalf("version bumped on re-seed: %q -> %q (would force worker re-pull)", v1, v2)
	}
}

// Seeding is additive: an entry an operator added at runtime (via POST
// /allowlist) must survive a restart's re-seed.
func TestSeedStore_PreservesExistingEntries(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.Add(digest(t, digestB), "ghcr.io/x/runtime:v1"); err != nil {
		t.Fatalf("pre-add: %v", err)
	}

	path := writeSeed(t, `{"version":"1","digests":{"`+digestA+`":"ghcr.io/x/cds:v1"}}`)
	if err := seedStore(&store, path); err != nil {
		t.Fatalf("seedStore: %v", err)
	}

	_, got, err := store.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if _, ok := got[digest(t, digestB)]; !ok {
		t.Errorf("runtime-added digest was dropped by seed: %v", got)
	}
	if _, ok := got[digest(t, digestA)]; !ok {
		t.Errorf("seed digest missing: %v", got)
	}
}

func TestSeedStore_FailsClosedOnBadDigest(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// "sha256:bad" fails ParseJSON's digest validation.
	path := writeSeed(t, `{"version":"1","digests":{"sha256:bad":"ghcr.io/x/cds:v1"}}`)
	if err := seedStore(&store, path); err == nil {
		t.Fatal("seedStore accepted a malformed digest; want fail-closed error")
	}
}

func TestSeedStore_FailsClosedOnMissingFile(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := seedStore(&store, filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("seedStore accepted a missing seed file; want fail-closed error")
	}
}
