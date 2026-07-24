package cds

import (
	"bytes"
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

	path := writeSeed(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"ghcr.io/x/cds:v1","`+digestB+`":"ghcr.io/x/as:v1"}}`)
	if _, err := seedStore(&store, path); err != nil {
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

// A seed document carrying workloads seeds both layers: the floor and the named
// workload entries (additive, before serving).
func TestSeedStore_SeedsWorkloads(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	seed := `{"schema":"c8s.allowlist/v1","digests":{"` + digestA + `":"ghcr.io/x/cds:v1"},` +
		`"workloads":{"web":{"containers":[{"digest":"` + digestB + `"}]}}}`
	if _, err := seedStore(&store, writeSeed(t, seed)); err != nil {
		t.Fatalf("seedStore: %v", err)
	}

	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if _, ok := doc.Workloads["web"]; !ok {
		t.Fatalf("seeded workload missing: %#v", doc.Workloads)
	}
	// The workload's container digest is admitted via the workload index.
	if ok, err := store.Contains(digest(t, digestB)); err != nil || !ok {
		t.Fatalf("Contains(workload digest) = %t, %v; want true, nil", ok, err)
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

	path := writeSeed(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"ghcr.io/x/cds:v1"}}`)
	if _, err := seedStore(&store, path); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	v1, _, err := store.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}

	if _, err := seedStore(&store, path); err != nil {
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

	path := writeSeed(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"ghcr.io/x/cds:v1"}}`)
	if _, err := seedStore(&store, path); err != nil {
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
	path := writeSeed(t, `{"schema":"c8s.allowlist/v1","digests":{"sha256:bad":"ghcr.io/x/cds:v1"}}`)
	if _, err := seedStore(&store, path); err == nil {
		t.Fatal("seedStore accepted a malformed digest; want fail-closed error")
	}
}

// The returned digest feeds the serving cert's config-claims; it must be a
// function of seed content only, so a verifier holding an equivalent copy of
// the seed (any formatting) reproduces it.
func TestSeedStore_ReturnsCanonicalDigest(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	compact := writeSeed(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestA+`":"ghcr.io/x/cds:v1"}}`)
	d1, err := seedStore(&store, compact)
	if err != nil {
		t.Fatalf("seedStore: %v", err)
	}

	pretty := writeSeed(t, "{\n  \"digests\": {\n    \""+digestA+"\": \"ghcr.io/x/cds:v1\"\n  },\n  \"schema\": \"c8s.allowlist/v1\"\n}")
	d2, err := seedStore(&store, pretty)
	if err != nil {
		t.Fatalf("seedStore: %v", err)
	}
	if !bytes.Equal(d1, d2) {
		t.Fatalf("seed digest depends on formatting: %x != %x", d1, d2)
	}

	other := writeSeed(t, `{"schema":"c8s.allowlist/v1","digests":{"`+digestB+`":"ghcr.io/x/as:v1"}}`)
	d3, err := seedStore(&store, other)
	if err != nil {
		t.Fatalf("seedStore: %v", err)
	}
	if bytes.Equal(d1, d3) {
		t.Fatal("different seed content produced the same digest")
	}
}

func TestSeedStore_FailsClosedOnMissingFile(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if _, err := seedStore(&store, filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("seedStore accepted a missing seed file; want fail-closed error")
	}
}
