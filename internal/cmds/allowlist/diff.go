package allowlist

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// changedEntry is a before/after pair for a single value.
type changedEntry struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// floorDiff reports what applying a desired floor over the current floor changes.
type floorDiff struct {
	Added   map[string]string       `json:"added"`
	Removed map[string]string       `json:"removed"`
	Changed map[string]changedEntry `json:"changed"`
}

// computeDiff reports what applying desired over current would change (floor).
func computeDiff(current, desired map[string]string) floorDiff {
	d := floorDiff{
		Added:   map[string]string{},
		Removed: map[string]string{},
		Changed: map[string]changedEntry{},
	}
	for digest, image := range desired {
		cur, ok := current[digest]
		switch {
		case !ok:
			d.Added[digest] = image
		case cur != image:
			d.Changed[digest] = changedEntry{From: cur, To: image}
		}
	}
	for digest, image := range current {
		if _, ok := desired[digest]; !ok {
			d.Removed[digest] = image
		}
	}
	return d
}

func (d floorDiff) empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// containerDiff names one container-level change within a workload entry. Kind
// is "init" or "main"; From/To are container policy summaries.
type containerDiff struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
}

// entryDiff is the field-level change set for one changed workload entry.
type entryDiff struct {
	Label   *changedEntry   `json:"label,omitempty"`
	Added   []containerDiff `json:"containersAdded,omitempty"`
	Removed []containerDiff `json:"containersRemoved,omitempty"`
	Changed []containerDiff `json:"containersChanged,omitempty"`
}

func (e entryDiff) empty() bool {
	return e.Label == nil && len(e.Added) == 0 && len(e.Removed) == 0 && len(e.Changed) == 0
}

// allowlistDiff is the combined floor + workload diff.
type allowlistDiff struct {
	Floor            floorDiff            `json:"floor"`
	WorkloadsAdded   []string             `json:"workloadsAdded"`
	WorkloadsRemoved []string             `json:"workloadsRemoved"`
	WorkloadsChanged map[string]entryDiff `json:"workloadsChanged"`
}

func (d allowlistDiff) empty() bool {
	return d.Floor.empty() && len(d.WorkloadsAdded) == 0 && len(d.WorkloadsRemoved) == 0 && len(d.WorkloadsChanged) == 0
}

// diffAllowlists computes the entry- and field-level diff of desired over live.
func diffAllowlists(live, desired *pkgallowlist.Allowlist) allowlistDiff {
	d := allowlistDiff{
		Floor:            computeDiff(live.Digests, desired.Digests),
		WorkloadsChanged: map[string]entryDiff{},
	}
	for name, dw := range desired.Workloads {
		lw, ok := live.Workloads[name]
		if !ok {
			d.WorkloadsAdded = append(d.WorkloadsAdded, name)
			continue
		}
		if ed := diffEntry(lw, dw); !ed.empty() {
			d.WorkloadsChanged[name] = ed
		}
	}
	for name := range live.Workloads {
		if _, ok := desired.Workloads[name]; !ok {
			d.WorkloadsRemoved = append(d.WorkloadsRemoved, name)
		}
	}
	sort.Strings(d.WorkloadsAdded)
	sort.Strings(d.WorkloadsRemoved)
	return d
}

// diffEntry compares two workload entries field by field.
func diffEntry(live, desired pkgallowlist.Workload) entryDiff {
	var ed entryDiff
	if live.Label != desired.Label {
		ed.Label = &changedEntry{From: live.Label, To: desired.Label}
	}
	added, removed, changed := diffContainers("init", live.InitContainers, desired.InitContainers)
	ed.Added, ed.Removed, ed.Changed = added, removed, changed
	a2, r2, c2 := diffContainers("main", live.Containers, desired.Containers)
	ed.Added = append(ed.Added, a2...)
	ed.Removed = append(ed.Removed, r2...)
	ed.Changed = append(ed.Changed, c2...)
	return ed
}

// diffContainers diffs two container lists grouped by digest. When a digest has
// exactly one dropped and one introduced policy it is reported as a change;
// otherwise the policies are reported as separate additions/removals.
func diffContainers(kind string, live, desired []pkgallowlist.Container) (added, removed, changed []containerDiff) {
	liveByDigest := groupSummaries(live)
	desiredByDigest := groupSummaries(desired)

	digests := map[string]bool{}
	for d := range liveByDigest {
		digests[d] = true
	}
	for d := range desiredByDigest {
		digests[d] = true
	}
	ordered := make([]string, 0, len(digests))
	for d := range digests {
		ordered = append(ordered, d)
	}
	sort.Strings(ordered)

	for _, digest := range ordered {
		onlyDesired := multisetSub(desiredByDigest[digest], liveByDigest[digest])
		onlyLive := multisetSub(liveByDigest[digest], desiredByDigest[digest])
		if len(onlyDesired) == 1 && len(onlyLive) == 1 {
			changed = append(changed, containerDiff{Kind: kind, Digest: digest, From: onlyLive[0], To: onlyDesired[0]})
			continue
		}
		for _, s := range onlyDesired {
			added = append(added, containerDiff{Kind: kind, Digest: digest, To: s})
		}
		for _, s := range onlyLive {
			removed = append(removed, containerDiff{Kind: kind, Digest: digest, From: s})
		}
	}
	return added, removed, changed
}

func groupSummaries(cs []pkgallowlist.Container) map[string][]string {
	out := map[string][]string{}
	for _, c := range cs {
		d := c.Digest.String()
		out[d] = append(out[d], containerSummary(c))
	}
	return out
}

// multisetSub returns the elements of a not covered by an equal element of b,
// respecting multiplicity.
func multisetSub(a, b []string) []string {
	counts := map[string]int{}
	for _, s := range b {
		counts[s]++
	}
	var out []string
	for _, s := range a {
		if counts[s] > 0 {
			counts[s]--
			continue
		}
		out = append(out, s)
	}
	return out
}

func printDiff(w io.Writer, format string, d allowlistDiff) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(d)
	}
	if d.empty() {
		fmt.Fprintln(w, "no changes")
		return nil
	}

	fmt.Fprintln(w, "floor:")
	for _, digest := range sortedKeys(d.Floor.Added) {
		fmt.Fprintf(w, "+ %s  %s\n", digest, d.Floor.Added[digest])
	}
	for _, digest := range sortedKeys(d.Floor.Removed) {
		fmt.Fprintf(w, "- %s  %s\n", digest, d.Floor.Removed[digest])
	}
	for _, digest := range sortedChangedKeys(d.Floor.Changed) {
		fmt.Fprintf(w, "~ %s  %s -> %s\n", digest, d.Floor.Changed[digest].From, d.Floor.Changed[digest].To)
	}
	if d.Floor.empty() {
		fmt.Fprintln(w, "  (no changes)")
	}

	fmt.Fprintln(w, "workloads:")
	for _, name := range d.WorkloadsAdded {
		fmt.Fprintf(w, "+ %s\n", name)
	}
	for _, name := range d.WorkloadsRemoved {
		fmt.Fprintf(w, "- %s\n", name)
	}
	changedNames := make([]string, 0, len(d.WorkloadsChanged))
	for name := range d.WorkloadsChanged {
		changedNames = append(changedNames, name)
	}
	sort.Strings(changedNames)
	for _, name := range changedNames {
		fmt.Fprintf(w, "~ %s\n", name)
		printEntryDiff(w, d.WorkloadsChanged[name])
	}
	if len(d.WorkloadsAdded) == 0 && len(d.WorkloadsRemoved) == 0 && len(d.WorkloadsChanged) == 0 {
		fmt.Fprintln(w, "  (no changes)")
	}
	return nil
}

func printEntryDiff(w io.Writer, e entryDiff) {
	if e.Label != nil {
		fmt.Fprintf(w, "    label: %q -> %q\n", e.Label.From, e.Label.To)
	}
	for _, c := range e.Added {
		fmt.Fprintf(w, "    + %s %s %s\n", c.Kind, c.Digest, c.To)
	}
	for _, c := range e.Removed {
		fmt.Fprintf(w, "    - %s %s %s\n", c.Kind, c.Digest, c.From)
	}
	for _, c := range e.Changed {
		fmt.Fprintf(w, "    ~ %s %s  %s -> %s\n", c.Kind, c.Digest, c.From, c.To)
	}
}

func sortedChangedKeys(m map[string]changedEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
