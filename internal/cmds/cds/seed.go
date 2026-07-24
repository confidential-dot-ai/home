package cds

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// seedStore reads the JSON allowlist at path, seeds its digests into store,
// and returns the seed's canonical digest for the serving cert's config-claims
// (docs/ratls.md — the attested "preloaded with seed S" statement
// verifiers pin with `c8s cds verify --allowlist-seed`). It owns the
// file/wire-format concerns; the additive, version-stable merge is
// Store.SeedDigests.
//
// Seeding runs before the HTTP server serves, so the first GET /allowlist
// reflects the seed. Any error fails closed: CDS must not serve an empty or
// partial allowlist because its seed could not be applied.
func seedStore(store *allowlist.Store, path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist seed %q: %w", path, err)
	}

	seed, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse allowlist seed %q: %w", path, err)
	}
	seedDigest, err := seed.CanonicalDigest()
	if err != nil {
		return nil, fmt.Errorf("digest allowlist seed %q: %w", path, err)
	}

	digests := make(map[types.Digest]string, len(seed.Digests))
	for digestStr, image := range seed.Digests {
		digest, err := types.ParseDigest(digestStr)
		if err != nil {
			// ParseJSON already validated every key; treat a parse failure
			// here as a hard error rather than silently skipping a digest.
			return nil, fmt.Errorf("seed digest %q: %w", digestStr, err)
		}
		digests[digest] = image
	}

	added, err := store.SeedDigests(digests)
	if err != nil {
		return nil, fmt.Errorf("seed allowlist store: %w", err)
	}

	wlAdded, err := store.SeedWorkloads(seed.Workloads)
	if err != nil {
		return nil, fmt.Errorf("seed allowlist workloads: %w", err)
	}

	slog.Info("allowlist seeded",
		"digests_added", added, "digests_in_seed", len(seed.Digests),
		"workloads_added", wlAdded, "workloads_in_seed", len(seed.Workloads),
		"seed_digest", fmt.Sprintf("%x", seedDigest))
	return seedDigest, nil
}
