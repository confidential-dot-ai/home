package allowlist

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCrane installs a shell script named "crane" at the front of PATH so the
// exec-backed helpers run hermetically. The script body sees the crane
// subcommand as $1 and the reference as $2.
func fakeCrane(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "crane")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake crane: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// --- inspect-image ---

func TestInspectImageTextOutput(t *testing.T) {
	fakeCrane(t, `case "$1" in
digest) echo "`+digA+`" ;;
config) echo '{"config":{"Entrypoint":["/bin/app"],"Cmd":["serve","--port=8080"]}}' ;;
esac`)

	out, _, err := runCmd("inspect-image", "registry.example.com/app:v1")
	if err != nil {
		t.Fatalf("inspect-image: %v", err)
	}
	for _, want := range []string{"digest:     " + digA, "entrypoint: /bin/app", "cmd:        serve --port=8080"} {
		if !strings.Contains(out, want) {
			t.Errorf("inspect-image output missing %q:\n%s", want, out)
		}
	}
}

func TestInspectImageJSONOutput(t *testing.T) {
	fakeCrane(t, `case "$1" in
digest) echo "`+digA+`" ;;
config) echo '{"config":{"Entrypoint":["/bin/app"],"Cmd":null}}' ;;
esac`)

	out, _, err := runCmd("inspect-image", "registry.example.com/app:v1", "-o", "json")
	if err != nil {
		t.Fatalf("inspect-image -o json: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if got["digest"] != digA || got["ref"] != "registry.example.com/app:v1" {
		t.Fatalf("unexpected JSON: %#v", got)
	}
}

func TestInspectImageDigestFailure(t *testing.T) {
	fakeCrane(t, `echo "MANIFEST_UNKNOWN" >&2; exit 3`)

	_, _, err := runCmd("inspect-image", "registry.example.com/app:v1")
	if err == nil || !strings.Contains(err.Error(), "crane digest") || !strings.Contains(err.Error(), "MANIFEST_UNKNOWN") {
		t.Fatalf("expected a crane digest error carrying stderr, got %v", err)
	}
}

func TestInspectImageUnexpectedDigestValue(t *testing.T) {
	fakeCrane(t, `echo "not-a-digest"`)

	_, _, err := runCmd("inspect-image", "registry.example.com/app:v1")
	if err == nil || !strings.Contains(err.Error(), "unexpected value") {
		t.Fatalf("expected an unexpected-value error, got %v", err)
	}
}

func TestInspectImageConfigFailure(t *testing.T) {
	fakeCrane(t, `case "$1" in
digest) echo "`+digA+`" ;;
config) echo "boom" >&2; exit 1 ;;
esac`)

	_, _, err := runCmd("inspect-image", "registry.example.com/app:v1")
	if err == nil || !strings.Contains(err.Error(), "crane config") {
		t.Fatalf("expected a crane config error, got %v", err)
	}
}

func TestInspectImageConfigBadJSON(t *testing.T) {
	fakeCrane(t, `case "$1" in
digest) echo "`+digA+`" ;;
config) echo "not json" ;;
esac`)

	_, _, err := runCmd("inspect-image", "registry.example.com/app:v1")
	if err == nil || !strings.Contains(err.Error(), "parse crane config") {
		t.Fatalf("expected a config parse error, got %v", err)
	}
}

func TestCraneErrorNonExit(t *testing.T) {
	err := craneError("digest", "ref", errors.New("plain failure"))
	if err == nil || !strings.Contains(err.Error(), `crane digest "ref"`) || !strings.Contains(err.Error(), "plain failure") {
		t.Fatalf("unexpected wrap: %v", err)
	}
}

func TestCraneManifestExists(t *testing.T) {
	fakeCrane(t, `exit 0`)
	if err := craneManifestExists(context.Background(), "registry.example.com/app@"+digA); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	fakeCrane(t, `exit 1`)
	if err := craneManifestExists(context.Background(), "registry.example.com/app@"+digA); err == nil {
		t.Fatal("expected a manifest error")
	}
}

// --- lint --online ---

func TestLintOnlineWarnings(t *testing.T) {
	// digA has an image label and is missing from the registry; digB has no
	// image label; digC has an unparseable image label.
	file := writeFile(t, "al.json", `{"schema":"c8s.allowlist/v1","workloads":{
		"w":{"containers":[
			{"digest":"`+digA+`","image":"registry.example.com/app@`+digA+`","command":{"policy":"any"},"args":{"policy":"any"}},
			{"digest":"`+digB+`","command":{"policy":"any"},"args":{"policy":"any"}},
			{"digest":"`+digC+`","image":"not a valid ref!!","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`)
	fakeCrane(t, `exit 1`) // every manifest lookup fails

	out, _, err := runCmd("lint", "--online", file)
	if err != nil {
		t.Fatalf("lint --online: %v", err)
	}
	for _, want := range []string{
		"container digest not found in registry: registry.example.com/app@" + digA,
		"has no image label",
		`image "not a valid ref!!"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lint --online output missing %q:\n%s", want, out)
		}
	}
}

func TestLintOnlineCleanRegistry(t *testing.T) {
	file := writeFile(t, "al.json", `{"schema":"c8s.allowlist/v1","workloads":{
		"w":{"containers":[
			{"digest":"`+digA+`","image":"registry.example.com/app@`+digA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]}}}`)
	fakeCrane(t, `exit 0`)

	out, _, err := runCmd("lint", "--online", file)
	if err != nil {
		t.Fatalf("lint --online: %v", err)
	}
	if strings.Contains(out, "not found in registry") {
		t.Fatalf("resolvable digest must not warn:\n%s", out)
	}
	if !strings.Contains(out, "ok: no warnings") {
		t.Fatalf("expected a clean lint:\n%s", out)
	}
}

// --- lint offline warning surface and --strict ---

func TestLintOfflineWarningSurface(t *testing.T) {
	file := writeFile(t, "al.json", `{"schema":"c8s.allowlist/v1","workloads":{
		"empty":{},
		"tagged":{"label":"docker.io/library/busybox:latest","containers":[
			{"digest":"`+digA+`","image":"docker.io/library/busybox:latest",
			 "command":{"policy":"any"},"args":{"policy":"any"},"paths":{"policy":"any"}}]},
		"other":{"containers":[
			{"digest":"`+digA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},
			 "paths":{"policy":"allow","read":["/**"]}},
			{"digest":"`+digB+`","command":{"policy":"deny"},"args":{"policy":"deny"}}]}}}`)

	out, _, err := runCmd("lint", file)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	for _, want := range []string{
		`workload "empty" has no init or main containers`,
		`workload "tagged" label "docker.io/library/busybox:latest" is a tag`,
		`image "docker.io/library/busybox:latest" is a tag`,
		"the container can never start",
		`grants a root-subtree path "/**"`,
		"appears in 2 entries and one grants 'any'",
		"'any' (unconstrained) policy value(s) across all entries",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lint output missing %q:\n%s", want, out)
		}
	}

	// --strict turns those warnings into a non-zero exit.
	_, _, err = runCmd("lint", "--strict", file)
	if err == nil || !strings.Contains(err.Error(), "lint warning(s) with --strict") {
		t.Fatalf("expected --strict to fail, got %v", err)
	}
}

func TestLintRejectsMissingAndInvalidFile(t *testing.T) {
	if _, _, err := runCmd("lint", filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected a missing lint file to fail")
	}
	bad := writeFile(t, "bad.json", `{"schema":"wrong/schema"}`)
	if _, _, err := runCmd("lint", bad); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("expected a schema error, got %v", err)
	}
}
