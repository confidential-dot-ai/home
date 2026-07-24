package allowlist

import "github.com/confidential-dot-ai/c8s/pkg/types"

// Index answers admission queries for enforcers in O(1). Build it once from a
// normalized Allowlist.
type Index struct {
	floor    map[string]bool
	byDigest map[string][]Container
}

// BuildIndex projects an Allowlist into an admission index.
func (a *Allowlist) BuildIndex() *Index {
	idx := &Index{
		floor:    make(map[string]bool, len(a.Digests)),
		byDigest: map[string][]Container{},
	}
	for d := range a.Digests {
		idx.floor[d] = true
	}
	for _, w := range a.Workloads {
		for _, c := range w.InitContainers {
			idx.byDigest[c.Digest.String()] = append(idx.byDigest[c.Digest.String()], c)
		}
		for _, c := range w.Containers {
			idx.byDigest[c.Digest.String()] = append(idx.byDigest[c.Digest.String()], c)
		}
	}
	return idx
}

// AdmitsDigest reports whether an image with this digest may run at all — as a
// floor digest, or as any workload container. It ignores argv, so it answers the
// coarse "are these bytes allowlisted" question the CDS issuance gate asks.
func (i *Index) AdmitsDigest(digest string) bool {
	d, err := types.ParseDigest(digest)
	if err != nil {
		return false
	}
	if i.floor[d.String()] {
		return true
	}
	_, ok := i.byDigest[d.String()]
	return ok
}

// AdmitsContainer reports whether a container with the given digest may run the
// given effective argv (its OCI process.args). Floor digests are admitted
// regardless of argv. For a workload digest, admission is the union across every
// entry that lists it: the argv must satisfy some container's entrypoint
// (argv[0]) and cmd (argv[1:]) policy.
func (i *Index) AdmitsContainer(digest string, argv []string) bool {
	d, err := types.ParseDigest(digest)
	if err != nil {
		return false
	}
	if i.floor[d.String()] {
		return true
	}
	for _, c := range i.byDigest[d.String()] {
		if c.Entrypoint.matches(entrypointSegment(argv)) && c.Cmd.matches(cmdSegment(argv)) {
			return true
		}
	}
	return false
}

// entrypointSegment is argv[0] (the executable), empty if argv is empty.
func entrypointSegment(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	return argv[:1]
}

// cmdSegment is argv[1:] (the arguments), empty if argv has fewer than two elements.
func cmdSegment(argv []string) []string {
	if len(argv) < 2 {
		return nil
	}
	return argv[1:]
}

func (p ArgvPolicy) matches(segment []string) bool {
	switch p.Policy {
	case PolicyAny:
		return true
	case PolicyDeny:
		return len(segment) == 0
	case PolicyExact:
		return equalStrings(segment, p.Argv)
	default:
		return false
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
