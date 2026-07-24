package allowlist

import (
	"errors"
	"strconv"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const digestA = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
const digestB = "sha256:b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
const digestC = "sha256:c1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

// oneContainerWorkload builds a minimally-specified entry (policies default to
// deny) with one main container at digest.
func oneContainerWorkload(digest types.Digest) pkgallowlist.Workload {
	return pkgallowlist.Workload{
		Containers: []pkgallowlist.Container{{Digest: digest}},
	}
}

func mustParseDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("parse digest %q: %v", s, err)
	}
	return d
}

func TestReplaceSwapsSetAndBumpsVersion(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if err := store.Add(mustParseDigest(t, digestA), "image-a"); err != nil {
		t.Fatalf("add: %v", err)
	}
	beforeVersion, _, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if err := store.Replace(map[types.Digest]string{
		mustParseDigest(t, digestB): "image-b",
	}); err != nil {
		t.Fatalf("replace: %v", err)
	}

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(digests) != 1 {
		t.Fatalf("expected 1 digest after replace, got %d", len(digests))
	}
	if digests[mustParseDigest(t, digestB)] != "image-b" {
		t.Fatalf("replacement entry missing: %#v", digests)
	}
	if _, ok := digests[mustParseDigest(t, digestA)]; ok {
		t.Fatal("pre-replace entry survived a full replace")
	}
	// Replace must *increment* the version, not clear or reset it: the version
	// lives in its own table, so DELETE FROM allowlist leaves it untouched and
	// bumpVersionTx increments it. Assert monotonic +1 (a reset-to-default bug
	// would still satisfy version != beforeVersion, so check the value).
	before, err := strconv.Atoi(beforeVersion)
	if err != nil {
		t.Fatalf("beforeVersion %q not numeric: %v", beforeVersion, err)
	}
	after, err := strconv.Atoi(version)
	if err != nil {
		t.Fatalf("version %q not numeric: %v", version, err)
	}
	if after != before+1 {
		t.Fatalf("expected version %d after replace, got %d (before=%d)", before+1, after, before)
	}
}

func TestReplaceEmptyClears(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if err := store.Add(mustParseDigest(t, digestA), "image-a"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := store.Replace(map[types.Digest]string{}); err != nil {
		t.Fatalf("replace empty: %v", err)
	}
	_, digests, err := store.ListAll()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(digests) != 0 {
		t.Fatalf("expected empty allowlist after replace with empty set, got %d", len(digests))
	}
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

func TestRestoreSnapshotReplacesStateAndPreservesVersion(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	oldDigest := mustParseDigest(t, digestA)
	newDigest := mustParseDigest(t, digestB)
	if err := store.Add(oldDigest, "old/image"); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("42", &pkgallowlist.Allowlist{
		Schema:  pkgallowlist.Schema,
		Digests: map[string]string{newDigest.String(): "new/image"},
	}); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}

	version, digests, err := store.ListAll()
	if err != nil {
		t.Fatal(err)
	}
	if version != "42" {
		t.Fatalf("version = %q, want 42", version)
	}
	if len(digests) != 1 || digests[newDigest] != "new/image" {
		t.Fatalf("digests = %#v, want only transferred digest", digests)
	}
	if _, ok := digests[oldDigest]; ok {
		t.Fatal("pre-existing digest survived snapshot restore")
	}
}

func TestRestoreSnapshotRejectsInvalidState(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, version := range []string{"", "0", "-1", "not-a-version"} {
		if err := store.RestoreSnapshot(version, &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Digests: map[string]string{}}); err == nil {
			t.Fatalf("RestoreSnapshot accepted version %q", version)
		}
	}
	if err := store.RestoreSnapshot("1", nil); err == nil {
		t.Fatal("RestoreSnapshot accepted nil allowlist")
	}
}

func TestPutAndDeleteWorkloadRoundtrip(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA := mustParseDigest(t, digestA)
	if err := store.PutWorkload("web", oneContainerWorkload(dA)); err != nil {
		t.Fatalf("put: %v", err)
	}

	doc, version, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if version != "2" {
		t.Fatalf("version after put: got %q, want 2", version)
	}
	w, ok := doc.Workloads["web"]
	if !ok || len(w.Containers) != 1 || w.Containers[0].Digest != dA {
		t.Fatalf("stored workload = %#v", doc.Workloads)
	}
	// Absent policies must have normalized to deny on the way in.
	if w.Containers[0].Command.Policy != pkgallowlist.PolicyDeny {
		t.Fatalf("entrypoint policy = %q, want deny", w.Containers[0].Command.Policy)
	}

	// The container digest is now admitted via the workload index.
	if ok, err := store.Contains(dA); err != nil || !ok {
		t.Fatalf("Contains(workload digest) = %t, %v; want true, nil", ok, err)
	}

	found, err := store.DeleteWorkload("web")
	if err != nil || !found {
		t.Fatalf("delete: found=%t err=%v", found, err)
	}
	if ok, err := store.Contains(dA); err != nil || ok {
		t.Fatalf("Contains after delete = %t, %v; want false, nil", ok, err)
	}
	if found, err := store.DeleteWorkload("web"); err != nil || found {
		t.Fatalf("re-delete: found=%t err=%v; want false, nil", found, err)
	}
}

func TestPutWorkloadRejectsBadName(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	err = store.PutWorkload("bad/name", oneContainerWorkload(mustParseDigest(t, digestA)))
	if err == nil {
		t.Fatal("PutWorkload accepted a name with a slash")
	}
	if !errors.Is(err, ErrInvalidWorkload) {
		t.Fatalf("error should wrap ErrInvalidWorkload, got %v", err)
	}
}

func TestSeedWorkloadsIsAdditiveAndIdempotent(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	seed := map[string]pkgallowlist.Workload{
		"web": oneContainerWorkload(mustParseDigest(t, digestA)),
		"db":  oneContainerWorkload(mustParseDigest(t, digestB)),
	}
	added, err := store.SeedWorkloads(seed)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if added != 2 {
		t.Fatalf("added: got %d, want 2", added)
	}
	v1, _, _ := store.ListAll()
	if v1 != "2" {
		t.Fatalf("version after seed: got %q, want 2 (one bump)", v1)
	}

	// Re-seeding the same set adds nothing and does not bump.
	added, err = store.SeedWorkloads(seed)
	if err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	if added != 0 {
		t.Fatalf("re-seed added: got %d, want 0", added)
	}
	v2, _, _ := store.ListAll()
	if v1 != v2 {
		t.Fatalf("version bumped on no-op re-seed: %q -> %q", v1, v2)
	}
}

func TestReplaceAllSwapsFloorAndWorkloads(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if err := store.Add(mustParseDigest(t, digestA), "old"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := store.PutWorkload("old-wl", oneContainerWorkload(mustParseDigest(t, digestB))); err != nil {
		t.Fatalf("put: %v", err)
	}

	replacement := &pkgallowlist.Allowlist{
		Schema:  pkgallowlist.Schema,
		Digests: map[string]string{digestC: "floor-c"},
		Workloads: map[string]pkgallowlist.Workload{
			"new-wl": oneContainerWorkload(mustParseDigest(t, digestA)),
		},
	}
	if err := store.ReplaceAll(replacement); err != nil {
		t.Fatalf("replace all: %v", err)
	}

	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(doc.Digests) != 1 || doc.Digests[digestC] != "floor-c" {
		t.Fatalf("floor after replace = %#v", doc.Digests)
	}
	if _, ok := doc.Workloads["old-wl"]; ok {
		t.Fatal("pre-replace workload survived ReplaceAll")
	}
	if _, ok := doc.Workloads["new-wl"]; !ok {
		t.Fatalf("replacement workload missing = %#v", doc.Workloads)
	}
	// The old workload's container digest is no longer admitted.
	if ok, _ := store.Contains(mustParseDigest(t, digestB)); ok {
		t.Fatal("old workload digest still admitted after ReplaceAll")
	}
}

func TestContains(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	present := mustParseDigest(t, digestA)
	absent := mustParseDigest(t, digestB)
	if err := store.Add(present, "ghcr.io/x/a:v1"); err != nil {
		t.Fatal(err)
	}

	if ok, err := store.Contains(present); err != nil || !ok {
		t.Fatalf("Contains(present) = %t, %v; want true, nil", ok, err)
	}
	if ok, err := store.Contains(absent); err != nil || ok {
		t.Fatalf("Contains(absent) = %t, %v; want false, nil", ok, err)
	}
}
