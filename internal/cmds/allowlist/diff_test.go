package allowlist

import (
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestDiffAllowlistsWorkloads(t *testing.T) {
	mk := func(argv string) pkgallowlist.Container {
		return pkgallowlist.Container{
			Digest:     mustDigest(t, digB),
			Entrypoint: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{argv}},
			Cmd:        pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
			Paths:      pkgallowlist.PathPolicy{Policy: pkgallowlist.PolicyDeny},
		}
	}
	live := &pkgallowlist.Allowlist{
		Schema:  pkgallowlist.Schema,
		Digests: map[string]string{digA: "img"},
		Workloads: map[string]pkgallowlist.Workload{
			"web":  {Containers: []pkgallowlist.Container{mk("/old")}},
			"gone": {Containers: []pkgallowlist.Container{{Digest: mustDigest(t, digC)}}},
		},
	}
	desired := &pkgallowlist.Allowlist{
		Schema:  pkgallowlist.Schema,
		Digests: map[string]string{digA: "img", digD: "img2"},
		Workloads: map[string]pkgallowlist.Workload{
			"web": {Containers: []pkgallowlist.Container{mk("/new")}},
			"new": {Containers: []pkgallowlist.Container{{Digest: mustDigest(t, digD)}}},
		},
	}

	d := diffAllowlists(live, desired)
	if d.empty() {
		t.Fatal("expected differences")
	}
	if d.Floor.Added[digD] != "img2" {
		t.Fatalf("floor added = %#v", d.Floor.Added)
	}
	if len(d.WorkloadsAdded) != 1 || d.WorkloadsAdded[0] != "new" {
		t.Fatalf("workloadsAdded = %#v", d.WorkloadsAdded)
	}
	if len(d.WorkloadsRemoved) != 1 || d.WorkloadsRemoved[0] != "gone" {
		t.Fatalf("workloadsRemoved = %#v", d.WorkloadsRemoved)
	}
	web, ok := d.WorkloadsChanged["web"]
	if !ok || len(web.Changed) != 1 {
		t.Fatalf("web changed = %#v", web)
	}
	if web.Changed[0].Digest != digB || web.Changed[0].From == web.Changed[0].To {
		t.Fatalf("web container change = %#v", web.Changed[0])
	}
}
