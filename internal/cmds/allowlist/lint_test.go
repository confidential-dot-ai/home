package allowlist

import (
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A digest on the floor is admitted by digest alone, so any argv/paths policy an
// operator also wrote for it in a workload is silently not enforced. lint must
// surface that overlap — and only for the overlapping digest.
func TestLintFloorWorkloadOverlap(t *testing.T) {
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1",
		"digests":{"` + digA + `":"base"},
		"workloads":{"w":{"containers":[
			{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}},
			{"digest":"` + digC + `","command":{"policy":"exact","argv":["/x"]},"args":{"policy":"deny"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}

	var overlap []string
	for _, w := range lintOffline(al) {
		if strings.Contains(w, "floor-listed") {
			overlap = append(overlap, w)
		}
	}
	joined := strings.Join(overlap, "\n")
	if !strings.Contains(joined, digA) {
		t.Fatalf("expected a floor-overlap warning naming %s, got:\n%s", digA, joined)
	}
	if strings.Contains(joined, digC) {
		t.Fatalf("digC is workload-only and must not be flagged as floor-listed:\n%s", joined)
	}
}

func TestLintNoFloorOverlap(t *testing.T) {
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1",
		"digests":{"` + digB + `":"infra"},
		"workloads":{"w":{"containers":[
			{"digest":"` + digA + `","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range lintOffline(al) {
		if strings.Contains(w, "floor-listed") {
			t.Fatalf("disjoint floor and workloads must not warn, got: %s", w)
		}
	}
}
