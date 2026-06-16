// Package resources defines the c8s resource path constants used in the
// EAR-driven access-control model: a resourceMap maps each attested launch
// measurement to the list of resources that measurement is authorised for.
//
// Concrete resource literals are exported as typed constants so a typo in
// any Go call site fails to compile. Glob patterns ("cds/*", "*") remain valid
// by construction (Resource is a labelled string), but should only be used at
// the operator-supplied resource-map.json boundary.
package resources

// Resource names a single c8s resource path that an attested workload can
// be authorised for via the chart's resourceMap.
type Resource string

const (
	// AllowlistWrite authorises POST/DELETE on /allowlist.
	AllowlistWrite Resource = "cds/allowlist-write"

	// SignCSR authorises POST /sign-csr.
	SignCSR Resource = "cds/sign-csr"

	// Handoff authorises POST /handoff (active CA exporting its in-process
	// state to a joining cds replica).
	Handoff Resource = "cds/handoff"
)

// Map matches the on-disk resource-map.json shape:
// { "<sha-384 hex measurement>": ["<resource>", ...] }
// Values are typed as Resource so Go call sites get compile-time
// verification of the literal names; glob patterns are spelled
// resources.Resource("cds/*").
type Map map[string][]Resource
