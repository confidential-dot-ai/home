//go:build !c8s_node

package main

import (
	"context"
	"os"
	"reflect"
	"regexp"
	"slices"
	"testing"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func TestValueArgsToTreeNestsDottedKeys(t *testing.T) {
	got, err := valueArgsToTree([]string{
		"--set-string", "attestationApi.image.repository=ghcr.io/x/attestation-api",
		"--set-string", "attestationApi.image.digest=sha256:abc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]any{
		"attestationApi": map[string]any{
			"image": map[string]any{
				"repository": "ghcr.io/x/attestation-api",
				"digest":     "sha256:abc",
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestValueArgsToTreeCoercesSetTypes(t *testing.T) {
	// --set typing mirrors helm strvals: null/bool/int are coerced, the rest
	// stay strings. --set-string never coerces.
	got, err := valueArgsToTree([]string{
		"--set", "cds.node.selector=null",
		"--set", "attestationApi.teeDevices.sevGuest=true",
		"--set", "attestationApi.teeDevices.tpm=false",
		"--set", "webhook.getCert.runAsUser=65532",
		"--set-string", "attestationApi.cvmMode=aks",
		"--set-string", "image.tag=main",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cds := got["cds"].(map[string]any)["node"].(map[string]any)
	if cds["selector"] != nil {
		t.Errorf("selector: got %#v, want nil (real null)", cds["selector"])
	}
	tee := got["attestationApi"].(map[string]any)["teeDevices"].(map[string]any)
	if tee["sevGuest"] != true {
		t.Errorf("sevGuest: got %#v, want bool true", tee["sevGuest"])
	}
	if tee["tpm"] != false {
		t.Errorf("tpm: got %#v, want bool false", tee["tpm"])
	}
	if got["webhook"].(map[string]any)["getCert"].(map[string]any)["runAsUser"] != int64(65532) {
		t.Errorf("runAsUser: want int64 65532")
	}
	// --set-string keeps "aks"/"main" as strings (cvmMode and tag are never
	// coerced even though they look plain).
	if got["attestationApi"].(map[string]any)["cvmMode"] != "aks" {
		t.Errorf("cvmMode: want string \"aks\"")
	}
	if got["image"].(map[string]any)["tag"] != "main" {
		t.Errorf("tag: want string \"main\"")
	}
}

func TestValueArgsToTreeRejectsScalarMapConflict(t *testing.T) {
	// A scalar at a.b then a map at a.b.c is a builder bug, not a silent merge.
	_, err := valueArgsToTree([]string{
		"--set-string", "a.b=scalar",
		"--set-string", "a.b.c=nested",
	})
	if err == nil {
		t.Fatal("expected a conflict error, got nil")
	}
}

// Descending into a key previously cleared with `=null` must create the map,
// not mis-report the nil as a "scalar conflict". A real scalar still conflicts
// (covered above). Terminal writes keep helm's last-wins semantics — this only
// fixes the intermediate-nil descend. (Latent today: no builder emits such a
// pair, but the nil-as-scalar error would be a sharp edge if one ever did.)
func TestValueArgsToTreeDescendsThroughNull(t *testing.T) {
	got, err := valueArgsToTree([]string{
		"--set", "a=null",
		"--set-string", "a.b=v",
	})
	if err != nil {
		t.Fatalf("descend through null should not error, got: %v", err)
	}
	want := map[string]any{"a": map[string]any{"b": "v"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestValueArgsToTreeRejectsMalformedArg(t *testing.T) {
	if _, err := valueArgsToTree([]string{"--set", "noequalshere"}); err == nil {
		t.Fatal("expected error for value arg without '='")
	}
	if _, err := valueArgsToTree([]string{"--set"}); err == nil {
		t.Fatal("expected error for dangling flag with no key=value")
	}
}

// buildValueArgs must assume nothing the operator did not pass — like install,
// an unset --distro (distro == "") emits no distro keys, leaving the chart
// default to stand; a set --distro plumbs both component distro keys.
func TestBuildValueArgsOmitsDistroWhenUnset(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String(flagCvmMode, "baremetal", "") // registered, not Changed

	// Isolate the distro logic from the crane digest path (which needs the
	// binary on PATH); this test is about what the builder assumes, not digests.
	prev := installResolveDigests
	installResolveDigests = false
	defer func() { installResolveDigests = prev }()

	args, err := buildValueArgs(context.Background(), cmd, nil, "main", "", appendResolvedDigestArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if slices.ContainsFunc(args, func(a string) bool {
		return a == "kata.distro=" || a == "nriImagePolicy.distro=" ||
			a == "kata.distro=k8s" || a == "nriImagePolicy.distro=k8s"
	}) {
		t.Fatalf("unset distro should emit no distro keys, got %v", args)
	}

	args, err = buildValueArgs(context.Background(), cmd, nil, "main", "rke2", appendResolvedDigestArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Contains(args, "nriImagePolicy.distro=rke2") || !slices.Contains(args, "kata.distro=rke2") {
		t.Fatalf("set distro should plumb both component keys, got %v", args)
	}
}

// On the no-digest path a numeric or zero-padded image tag (a date or build-id
// tag) must survive as a string: buildValueArgs emits .tag via --set-string, so
// coerce never int-coerces it (0640 -> 640 would pin the wrong image).
func TestBuildValueArgsKeepsNumericImageTagAString(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String(flagCvmMode, "baremetal", "")
	prev := installResolveDigests
	installResolveDigests = false // tag is the sole image ref only when digests are off
	defer func() { installResolveDigests = prev }()

	args, err := buildValueArgs(context.Background(), cmd,
		[]c8sComponent{{valuePrefix: "cds.image", repository: "ghcr.io/x/cds"}},
		"0640", "", appendResolvedDigestArgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tree, err := valueArgsToTree(args)
	if err != nil {
		t.Fatalf("valueArgsToTree: %v", err)
	}
	if got := tree["cds"].(map[string]any)["image"].(map[string]any)["tag"]; got != "0640" {
		t.Errorf("tag: got %#v, want string \"0640\" (must not int-coerce to 640)", got)
	}
}

// When digests are resolved, the bundle must pin by digest only — emitting .tag
// too is redundant and contradicts the chart's digest-XOR-tag convention (kata
// helpers fail the render on both). The injected resolver mirrors the real
// appendResolvedDigestArgs (repository + digest + deriveComponents) so the test
// also confirms allowlist derivation survives to the tree, and keeps crane off
// PATH.
func TestBuildValueArgsOmitsTagWhenDigestsResolved(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String(flagCvmMode, "baremetal", "")

	prevFlag := installResolveDigests
	defer func() { installResolveDigests = prevFlag }()
	installResolveDigests = true
	stubResolver := func(_ context.Context, args []string, _ string, comps []c8sComponent) ([]string, error) {
		for _, c := range comps {
			args = append(args, "--set-string", c.valuePrefix+".repository="+c.repository,
				"--set-string", c.valuePrefix+".digest=sha256:abc")
		}
		return append(args, "--set", "nriImagePolicy.bootstrapAllowlist.deriveComponents=true"), nil
	}

	got, err := buildValueArgs(context.Background(), cmd,
		[]c8sComponent{{valuePrefix: "cds.image", repository: "ghcr.io/x/cds"}},
		"main", "", stubResolver)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tree, err := valueArgsToTree(got)
	if err != nil {
		t.Fatalf("valueArgsToTree: %v", err)
	}
	img := tree["cds"].(map[string]any)["image"].(map[string]any)
	if _, hasTag := img["tag"]; hasTag {
		t.Errorf("digest path must not emit a tag, got image=%#v", img)
	}
	if img["digest"] != "sha256:abc" {
		t.Errorf("digest: got %#v, want sha256:abc", img["digest"])
	}
	if got := tree["nriImagePolicy"].(map[string]any)["bootstrapAllowlist"].(map[string]any)["deriveComponents"]; got != true {
		t.Errorf("deriveComponents: got %#v, want bool true", got)
	}
}

// writeComputedValues turns the --set pairs into a real values.yaml file that
// helm can read back — install passes it as -f instead of inline --set flags.
func TestWriteComputedValuesProducesReadableFile(t *testing.T) {
	path, err := writeComputedValues([]string{
		"--set-string", "image.repository=ghcr.io/x/c8s-operator",
		"--set", "attestationApi.teeDevices.tpm=true",
		"--set", "cds.node.selector=null",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read computed values: %v", err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("computed values is not valid yaml: %v\n%s", err, data)
	}
	if got["image"].(map[string]any)["repository"] != "ghcr.io/x/c8s-operator" {
		t.Errorf("repository not in computed values: %#v", got["image"])
	}
	if got["attestationApi"].(map[string]any)["teeDevices"].(map[string]any)["tpm"] != true {
		t.Errorf("tpm should be bool true: %#v", got["attestationApi"])
	}
	// null clears the key (real YAML null, not the string "null").
	cds := got["cds"].(map[string]any)["node"].(map[string]any)
	if v, ok := cds["selector"]; !ok || v != nil {
		t.Errorf("selector should be present and null, got %#v (present=%v)", v, ok)
	}
}

// coerceSafeValueArg is the value-arg grammar valueArgsToTree / coerce actually
// handle: a single `dotted.path=value` token whose path segments are
// [A-Za-z0-9.] only — no list indexing (`foo[0]`), no escaped dots (`a\.b`), no
// comma-joined multi-values (`a=1,b=2`). valueArgsToTree's doc explicitly opts
// out of helm's full --set grammar on the promise that buildValueArgs never
// emits those shapes.
var coerceSafeValueArg = regexp.MustCompile(`^[A-Za-z0-9.]+=[^,]*$`)

// TestBuildValueArgsStaysWithinParserGrammar is the lockstep guard between the
// emitter (buildValueArgs / buildDigestArgs) and the parser (valueArgsToTree /
// coerce). The parser handles only a subset of helm's --set grammar; this
// drives the real builders with every value-producing toggle set and asserts
// each emitted token stays inside that subset and round-trips cleanly. Without
// it, a helper that emits e.g. `foo[0]=x`, an escaped dot, or a bare
// non-value flag would silently break BOTH install and render-values (the
// shared path hides the divergence) with every existing test still green.
func TestBuildValueArgsStaysWithinParserGrammar(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String(flagCvmMode, "baremetal", "")
	cmd.Flags().Int64("webhook-cert-fs-group", 0, "")
	cmd.Flags().String("webhook-cert-key-mode", "", "")
	cmd.Flags().Duration("webhook-get-cert-renew-interval", 0, "")
	cmd.Flags().Int64("webhook-get-cert-run-as-user", 0, "")
	cmd.Flags().Int64("webhook-get-cert-run-as-group", 0, "")
	cmd.Flags().Bool("webhook-get-cert-run-as-non-root", false, "")
	for _, name := range []string{
		flagCvmMode, "webhook-cert-fs-group", "webhook-cert-key-mode",
		"webhook-get-cert-renew-interval", "webhook-get-cert-run-as-user",
		"webhook-get-cert-run-as-group", "webhook-get-cert-run-as-non-root",
	} {
		if err := cmd.Flags().Set(name, cmd.Flags().Lookup(name).DefValue); err != nil {
			t.Fatalf("mark %q changed: %v", name, err)
		}
	}

	prev := struct {
		crds, singleNode, kata, resolveDigests bool
		secret, cvm                            string
	}{installCRDs, installSingleNode, installKata, installResolveDigests, installImagePullSecret, installCvmMode}
	defer func() {
		installCRDs, installSingleNode, installKata, installResolveDigests = prev.crds, prev.singleNode, prev.kata, prev.resolveDigests
		installImagePullSecret, installCvmMode = prev.secret, prev.cvm
	}()
	// Drive every value-producing toggle. --install-crds=false exercises the
	// non-default CRD path; --resolve-digests=false keeps crane off PATH (the
	// digest-arg shape is covered separately via buildDigestArgs below).
	installCRDs, installSingleNode, installKata, installResolveDigests = false, true, true, false
	installImagePullSecret, installCvmMode = "regcred", "aks"

	args, err := buildValueArgs(context.Background(), cmd, nil, "main", "rke2", appendResolvedDigestArgs)
	if err != nil {
		t.Fatalf("buildValueArgs: %v", err)
	}
	// Add the digest helper's repository/digest tokens (stubbed resolver, no crane).
	args, err = buildDigestArgs(args, "main",
		[]c8sComponent{{valuePrefix: "cds.image", repository: "ghcr.io/x/cds"}},
		func(string) (string, error) { return "sha256:abc", nil })
	if err != nil {
		t.Fatalf("buildDigestArgs: %v", err)
	}

	for i := 0; i < len(args); i += 2 {
		if flag := args[i]; flag != "--set" && flag != "--set-string" {
			t.Fatalf("arg %d: expected --set/--set-string, got %q (slice: %v)", i, flag, args)
		}
		if i+1 >= len(args) {
			t.Fatalf("dangling %s with no key=value", args[i])
		}
		if kv := args[i+1]; !coerceSafeValueArg.MatchString(kv) {
			t.Errorf("value arg %q is outside the grammar valueArgsToTree handles "+
				"(list index, escaped dot, comma multi-value, or a bare non-value flag); "+
				"update coerce/valueArgsToTree or keep the builders within the subset", kv)
		}
	}

	// The whole point of the grammar guard is that these args round-trip
	// through the parser cleanly, so prove it.
	if _, err := valueArgsToTree(args); err != nil {
		t.Fatalf("builder output failed to parse: %v", err)
	}
}

func TestCoerceTypedVsString(t *testing.T) {
	tests := []struct {
		raw   string
		typed bool
		want  any
	}{
		{"null", true, nil},
		{"true", true, true},
		{"false", true, false},
		{"42", true, int64(42)},
		{"main", true, "main"},  // non-numeric/non-bool stays string
		{"null", false, "null"}, // --set-string never coerces
		{"true", false, "true"}, // --set-string never coerces
		{"sha256:abc", false, "sha256:abc"},
	}
	for _, tt := range tests {
		if got := coerce(tt.raw, tt.typed); got != tt.want {
			t.Errorf("coerce(%q, typed=%v) = %#v, want %#v", tt.raw, tt.typed, got, tt.want)
		}
	}
}
