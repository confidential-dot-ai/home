package cds

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// seedStore reads the JSON allowlist at path and seeds its digests into store.
// It owns the file/wire-format concerns; the additive, version-stable merge is
// Store.SeedDigests.
//
// Seeding runs before the HTTP server serves, so the first GET /allowlist
// reflects the seed. Any error fails closed: CDS must not serve an empty or
// partial allowlist because its seed could not be applied.
func seedStore(store *allowlist.Store, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read allowlist seed %q: %w", path, err)
	}

	seed, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return fmt.Errorf("parse allowlist seed %q: %w", path, err)
	}

	digests := make(map[types.Digest]string, len(seed.Digests))
	for digestStr, image := range seed.Digests {
		digest, err := types.ParseDigest(digestStr)
		if err != nil {
			// ParseJSON already validated every key; treat a parse failure
			// here as a hard error rather than silently skipping a digest.
			return fmt.Errorf("seed digest %q: %w", digestStr, err)
		}
		digests[digest] = image
	}

	added, err := store.SeedDigests(digests)
	if err != nil {
		return fmt.Errorf("seed allowlist store: %w", err)
	}

	slog.Info("allowlist seeded", "added", added, "in_seed", len(seed.Digests), "already_present", len(seed.Digests)-added)
	return nil
}
