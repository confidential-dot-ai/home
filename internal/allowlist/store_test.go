package allowlist

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const digestA = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
const digestB = "sha256:b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

func mustParseDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("parse digest %q: %v", s, err)
	}
	return d
}

func TestInitialVersionIsOne(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if version != "1" {
		t.Fatalf("version: got %q, want %q", version, "1")
	}
	if len(digests) != 0 {
		t.Fatalf("expected empty digests, got %d", len(digests))
	}
}

func TestAddAndListRoundtrip(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA := mustParseDigest(t, digestA)
	if err := store.Add(dA, "nginx:latest"); err != nil {
		t.Fatalf("add: %v", err)
	}

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if version != "2" {
		t.Fatalf("version: got %q, want %q", version, "2")
	}
	if len(digests) != 1 {
		t.Fatalf("expected 1 digest, got %d", len(digests))
	}
	if digests[dA] != "nginx:latest" {
		t.Fatalf("image: got %q, want %q", digests[dA], "nginx:latest")
	}
}

func TestAddSameDigestReplacesImage(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA := mustParseDigest(t, digestA)

	if err := store.Add(dA, "nginx:1.0"); err != nil {
		t.Fatalf("add first: %v", err)
	}
	if err := store.Add(dA, "nginx:2.0"); err != nil {
		t.Fatalf("add second: %v", err)
	}

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// Two adds = version 3
	if version != "3" {
		t.Fatalf("version: got %q, want %q", version, "3")
	}
	if len(digests) != 1 {
		t.Fatalf("expected 1 digest, got %d", len(digests))
	}
	if digests[dA] != "nginx:2.0" {
		t.Fatalf("image: got %q, want %q", digests[dA], "nginx:2.0")
	}
}

func TestDeleteExistingDigests(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA := mustParseDigest(t, digestA)
	dB := mustParseDigest(t, digestB)

	if err := store.Add(dA, "nginx:latest"); err != nil {
		t.Fatalf("add A: %v", err)
	}
	if err := store.Add(dB, "redis:latest"); err != nil {
		t.Fatalf("add B: %v", err)
	}

	ok, err := store.Delete([]types.Digest{dA, dB})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !ok {
		t.Fatal("expected delete to return true")
	}

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// 2 adds + 1 delete = version 4
	if version != "4" {
		t.Fatalf("version: got %q, want %q", version, "4")
	}
	if len(digests) != 0 {
		t.Fatalf("expected 0 digests, got %d", len(digests))
	}
}

func TestDeleteNonexistentReturnsFalse(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA := mustParseDigest(t, digestA)

	ok, err := store.Delete([]types.Digest{dA})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if ok {
		t.Fatal("expected delete to return false for nonexistent digest")
	}

	// Version should not change
	version, _, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if version != "1" {
		t.Fatalf("version: got %q, want %q", version, "1")
	}
}

func TestDeleteEmptyListIsOK(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	ok, err := store.Delete([]types.Digest{})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !ok {
		t.Fatal("expected delete of empty list to return true")
	}
}

func TestSeedDigestsAddsNewEntries(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA, dB := mustParseDigest(t, digestA), mustParseDigest(t, digestB)
	added, err := store.SeedDigests(map[types.Digest]string{dA: "cds:v1", dB: "as:v1"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if added != 2 {
		t.Fatalf("added: got %d, want 2", added)
	}

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(digests) != 2 {
		t.Fatalf("expected 2 digests, got %d", len(digests))
	}
	if digests[dA] != "cds:v1" {
		t.Errorf("digestA image: got %q, want %q", digests[dA], "cds:v1")
	}
	// Seeding two new entries bumps the version exactly once (2 -> 1+1), not per entry.
	if version != "2" {
		t.Fatalf("version: got %q, want %q (one bump for the whole seed)", version, "2")
	}
}

// Re-seeding the same set must not bump the version: it is the worker pull
// ETag, so a no-op re-seed on restart would otherwise force every worker to
// re-pull.
func TestSeedDigestsIdempotentDoesNotBumpVersion(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	seed := map[types.Digest]string{mustParseDigest(t, digestA): "cds:v1"}
	if _, err := store.SeedDigests(seed); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	v1, _, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	added, err := store.SeedDigests(seed)
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if added != 0 {
		t.Fatalf("re-seed added: got %d, want 0", added)
	}
	v2, _, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if v1 != v2 {
		t.Fatalf("version bumped on no-op re-seed: %q -> %q", v1, v2)
	}
}

// A seed mixing new and existing digests adds only the new ones and bumps the
// version once; entries added at runtime (here, pre-added) survive untouched.
func TestSeedDigestsPreservesExistingEntries(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dB := mustParseDigest(t, digestB)
	if err := store.Add(dB, "runtime:v1"); err != nil {
		t.Fatalf("pre-add: %v", err)
	}

	dA := mustParseDigest(t, digestA)
	added, err := store.SeedDigests(map[types.Digest]string{dA: "cds:v1", dB: "cds-overwrite:v1"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if added != 1 {
		t.Fatalf("added: got %d, want 1 (only digestA is new)", added)
	}

	_, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if digests[dB] != "runtime:v1" {
		t.Errorf("existing digestB image overwritten: got %q, want %q", digests[dB], "runtime:v1")
	}
	if _, ok := digests[dA]; !ok {
		t.Errorf("new digestA missing after seed: %v", digests)
	}
}

func TestSeedDigestsEmptyIsNoop(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	added, err := store.SeedDigests(nil)
	if err != nil {
		t.Fatalf("seed nil: %v", err)
	}
	if added != 0 {
		t.Fatalf("added: got %d, want 0", added)
	}
	version, _, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if version != "1" {
		t.Fatalf("version: got %q, want %q (empty seed must not bump)", version, "1")
	}
}
