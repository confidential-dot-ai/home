package allowlist

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// servingAllowlistCDS serves an arbitrary parsed allowlist document on GET and
// accepts writes with 204, recording the HTTP methods it saw.
func servingAllowlistCDS(t *testing.T, al *pkgallowlist.Allowlist) (url string, methods *[]string) {
	t.Helper()
	body, err := al.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	var mu sync.Mutex
	seen := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method)
		mu.Unlock()
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `W/"3"`)
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &seen
}

// runCmdIn is runCmd with a stdin payload, for '-' file arguments and prompts.
func runCmdIn(stdin string, args ...string) (string, string, error) {
	cmd := NewCmd()
	var out, errb bytes.Buffer
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

// ctrJSON renders one canonical exact-command container entry.
func ctrJSON(digest, argv string) string {
	return `{"digest":"` + digest + `","command":{"policy":"exact","argv":["` + argv + `"]},"args":{"policy":"deny"}}`
}

// mustParseAllowlist parses a JSON allowlist document or fails the test.
func mustParseAllowlist(t *testing.T, doc string) *pkgallowlist.Allowlist {
	t.Helper()
	al, err := pkgallowlist.ParseJSON([]byte(doc))
	if err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}
	return al
}

// writeFile writes data to a fresh temp file and returns its path.
func writeFile(t *testing.T, name, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// --- workload list / get ---

func TestWorkloadListText(t *testing.T) {
	al := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"web":{"initContainers":[`+ctrJSON(digA, "/init")+`],
		       "containers":[{"digest":"`+digB+`","command":{"policy":"any"},"args":{"policy":"any"},"paths":{"policy":"any"}},
		                     {"digest":"`+digC+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"},"paths":{"policy":"allow","read":["/data/**"],"write":["/tmp/**"]}}]}}}`)
	url, _ := servingAllowlistCDS(t, al)

	out, _, err := runCmd("workload", "list", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("workload list: %v", err)
	}
	for _, want := range []string{"workloads (1):", "NAME", "web", "any,exact", "R=1 W=1 any=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("workload list output missing %q:\n%s", want, out)
		}
	}
}

func TestWorkloadListJSON(t *testing.T) {
	al := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"web":{"containers":[`+ctrJSON(digA, "/app")+`]}}}`)
	url, _ := servingAllowlistCDS(t, al)

	out, _, err := runCmd("workload", "list", "--url", url, "--insecure", "-o", "json")
	if err != nil {
		t.Fatalf("workload list -o json: %v", err)
	}
	if !strings.Contains(out, `"web"`) || !strings.Contains(out, digA) {
		t.Fatalf("unexpected JSON output:\n%s", out)
	}
}

func TestWorkloadGet(t *testing.T) {
	al := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"web":{"label":"registry/app","containers":[`+ctrJSON(digA, "/app")+`]}}}`)
	url, _ := servingAllowlistCDS(t, al)

	out, _, err := runCmd("workload", "get", "web", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("workload get: %v", err)
	}
	if !strings.Contains(out, digA) || !strings.Contains(out, "registry/app") {
		t.Fatalf("unexpected get output:\n%s", out)
	}

	_, _, err = runCmd("workload", "get", "nope", "--url", url, "--insecure")
	if err == nil || !strings.Contains(err.Error(), `no workload entry named "nope"`) {
		t.Fatalf("expected a not-found error, got %v", err)
	}
}

// --- workload apply ---

func TestWorkloadApplyDryRunDiff(t *testing.T) {
	live := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"same":{"containers":[`+ctrJSON(digA, "/app")+`]},
		"web":{"containers":[`+ctrJSON(digB, "/old")+`]}}}`)
	url, methods := servingAllowlistCDS(t, live)

	file := writeFile(t, "wl.json", `{"schema":"c8s.allowlist/v1",
		"digests":{"`+digD+`":"floor-img"},
		"workloads":{
			"same":{"containers":[`+ctrJSON(digA, "/app")+`]},
			"web":{"containers":[`+ctrJSON(digB, "/new")+`]},
			"new":{"containers":[`+ctrJSON(digC, "/fresh")+`]}}}`)

	out, stderr, err := runCmd("workload", "apply", file, "--url", url, "--insecure", "--dry-run")
	if err != nil {
		t.Fatalf("workload apply --dry-run: %v", err)
	}
	for _, want := range []string{"= same (unchanged)", "~ web", "+ new (new)", "dry-run: would upsert 3 workload entr(ies)"} {
		if !strings.Contains(out, want) {
			t.Errorf("apply output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "/old") || !strings.Contains(out, "/new") {
		t.Errorf("apply output missing the container-level diff:\n%s", out)
	}
	if !strings.Contains(stderr, "1 floor digest(s) in the file are ignored") {
		t.Errorf("missing ignored-floor note, stderr=%q", stderr)
	}
	if contains(*methods, http.MethodPut) {
		t.Fatal("dry-run must not PUT")
	}
}

func TestWorkloadApplyWrites(t *testing.T) {
	live := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1"}`)
	url, methods := servingAllowlistCDS(t, live)
	keyPath := writeOperatorKey(t, t.TempDir())
	file := writeFile(t, "wl.json", `{"schema":"c8s.allowlist/v1","workloads":{
		"web":{"containers":[`+ctrJSON(digA, "/app")+`]}}}`)

	out, _, err := runCmd("workload", "apply", file, "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("workload apply: %v", err)
	}
	if !contains(*methods, http.MethodPut) {
		t.Fatalf("expected a PUT, saw %v", *methods)
	}
	if !strings.Contains(out, "applied web") {
		t.Fatalf("missing apply confirmation:\n%s", out)
	}
}

func TestWorkloadApplyFromStdinBareMap(t *testing.T) {
	live := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1"}`)
	url, _ := servingAllowlistCDS(t, live)

	// A bare name-keyed map (not an allowlist document) read from stdin.
	stdin := `{"w1":{"containers":[` + ctrJSON(digA, "/app") + `]}}`
	out, _, err := runCmdIn(stdin, "workload", "apply", "-", "--url", url, "--insecure", "--dry-run")
	if err != nil {
		t.Fatalf("workload apply -: %v", err)
	}
	if !strings.Contains(out, "+ w1 (new)") {
		t.Fatalf("missing new-entry line:\n%s", out)
	}
}

func TestWorkloadApplyRejectsEmptyAndBadInput(t *testing.T) {
	url, _ := servingCDS(t, nil)

	empty := writeFile(t, "empty.json", `{"schema":"c8s.allowlist/v1"}`)
	if _, _, err := runCmd("workload", "apply", empty, "--url", url, "--insecure"); err == nil ||
		!strings.Contains(err.Error(), "no workload entries") {
		t.Fatalf("expected a no-entries error, got %v", err)
	}

	missing := filepath.Join(t.TempDir(), "nope.json")
	if _, _, err := runCmd("workload", "apply", missing, "--url", url, "--insecure"); err == nil ||
		!strings.Contains(err.Error(), "read") {
		t.Fatalf("expected a read error, got %v", err)
	}

	garbage := writeFile(t, "bad.json", `not json at all`)
	if _, _, err := runCmd("workload", "apply", garbage, "--url", url, "--insecure"); err == nil ||
		!strings.Contains(err.Error(), "parse workload entries") {
		t.Fatalf("expected a parse error, got %v", err)
	}
}

func TestParseWorkloadEntriesBadEntry(t *testing.T) {
	// Valid JSON map, but the entry body fails workload validation (no digest).
	_, _, err := parseWorkloadEntries([]byte(`{"w1":{"containers":[{"command":{"policy":"any"},"args":{"policy":"any"}}]}}`))
	if err == nil || !strings.Contains(err.Error(), `workload "w1"`) {
		t.Fatalf("expected an entry validation error, got %v", err)
	}
}

// --- workload edit ---

// setEditor installs a fake $EDITOR that replaces the edited file with content.
func setEditor(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-editor")
	script := "#!/bin/sh\ncat > \"$1\" <<'EOF'\n" + content + "\nEOF\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write editor: %v", err)
	}
	t.Setenv("EDITOR", path)
}

func editFixtureCDS(t *testing.T) (url string, methods *[]string) {
	t.Helper()
	live := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"web":{"containers":[`+ctrJSON(digA, "/app")+`]}}}`)
	return servingAllowlistCDS(t, live)
}

func TestWorkloadEditApplies(t *testing.T) {
	url, methods := editFixtureCDS(t)
	keyPath := writeOperatorKey(t, t.TempDir())
	setEditor(t, `{"label":"v2","containers":[`+ctrJSON(digA, "/app")+`]}`)

	out, _, err := runCmdIn("y\n", "workload", "edit", "web", "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("workload edit: %v", err)
	}
	if !strings.Contains(out, "~ web") || !strings.Contains(out, `label: "" -> "v2"`) {
		t.Fatalf("missing edit diff:\n%s", out)
	}
	if !strings.Contains(out, "applied web") {
		t.Fatalf("missing apply confirmation:\n%s", out)
	}
	if !contains(*methods, http.MethodPut) {
		t.Fatalf("expected a PUT, saw %v", *methods)
	}
}

func TestWorkloadEditNoChanges(t *testing.T) {
	url, methods := editFixtureCDS(t)
	t.Setenv("EDITOR", "true") // leaves the file untouched

	_, stderr, err := runCmd("workload", "edit", "web", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("workload edit (no changes): %v", err)
	}
	if !strings.Contains(stderr, "no changes") {
		t.Fatalf("expected 'no changes', stderr=%q", stderr)
	}
	if contains(*methods, http.MethodPut) {
		t.Fatal("an unchanged edit must not PUT")
	}
}

func TestWorkloadEditAborted(t *testing.T) {
	url, methods := editFixtureCDS(t)
	setEditor(t, `{"label":"v2","containers":[`+ctrJSON(digA, "/app")+`]}`)

	_, stderr, err := runCmdIn("n\n", "workload", "edit", "web", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("workload edit (aborted): %v", err)
	}
	if !strings.Contains(stderr, "aborted") {
		t.Fatalf("expected 'aborted', stderr=%q", stderr)
	}
	if contains(*methods, http.MethodPut) {
		t.Fatal("an aborted edit must not PUT")
	}
}

func TestWorkloadEditEditorFails(t *testing.T) {
	url, _ := editFixtureCDS(t)
	t.Setenv("EDITOR", "false") // exits non-zero

	_, _, err := runCmd("workload", "edit", "web", "--url", url, "--insecure")
	if err == nil || !strings.Contains(err.Error(), "editor") {
		t.Fatalf("expected an editor error, got %v", err)
	}
}

func TestWorkloadEditMissingEntry(t *testing.T) {
	url, _ := editFixtureCDS(t)
	_, _, err := runCmd("workload", "edit", "nope", "--url", url, "--insecure")
	if err == nil || !strings.Contains(err.Error(), `no workload entry named "nope"`) {
		t.Fatalf("expected a not-found error, got %v", err)
	}
}

// --- workload delete ---

func TestWorkloadDelete(t *testing.T) {
	url, methods := servingCDS(t, nil)
	keyPath := writeOperatorKey(t, t.TempDir())

	out, _, err := runCmd("workload", "delete", "web", "old", "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("workload delete: %v", err)
	}
	if !strings.Contains(out, "deleted web") || !strings.Contains(out, "deleted old") {
		t.Fatalf("missing delete confirmations:\n%s", out)
	}
	if !contains(*methods, http.MethodDelete) {
		t.Fatalf("expected a DELETE, saw %v", *methods)
	}
}

func TestWorkloadDeleteNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such workload", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	keyPath := writeOperatorKey(t, t.TempDir())

	_, _, err := runCmd("workload", "delete", "ghost", "--url", srv.URL, "--insecure", "--operator-key", keyPath)
	if err == nil || !strings.Contains(err.Error(), `no workload entry named "ghost"`) {
		t.Fatalf("expected a mapped 404 error, got %v", err)
	}
}

// --- small helpers ---

func TestSanitizeFileName(t *testing.T) {
	if got := sanitizeFileName("web-1_A.b/..\\x y"); got != "web-1_A_b____x_y" {
		t.Fatalf("sanitizeFileName = %q", got)
	}
}

func TestValidateRequiresURL(t *testing.T) {
	_, _, err := runCmd("list")
	if err == nil || !strings.Contains(err.Error(), "--url is required") {
		t.Fatalf("expected a missing --url error, got %v", err)
	}
}

func TestArgvSummary(t *testing.T) {
	if got := argvSummary(pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/bin/sh", "-c"}}); got != "exact[/bin/sh -c]" {
		t.Fatalf("exact summary = %q", got)
	}
	if got := argvSummary(pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}); got != "any" {
		t.Fatalf("any summary = %q", got)
	}
	if got := argvSummary(pkgallowlist.ArgvPolicy{}); got != "deny" {
		t.Fatalf("deny summary = %q", got)
	}
}

func TestPathSummary(t *testing.T) {
	if got := pathSummary(pkgallowlist.PathPolicy{Policy: pkgallowlist.PolicyAny}); got != "any" {
		t.Fatalf("any summary = %q", got)
	}
	if got := pathSummary(pkgallowlist.PathPolicy{Policy: pkgallowlist.PolicyAllow, Read: []string{"/a"}, Write: []string{"/b", "/c"}}); got != "allow(r=1,w=2)" {
		t.Fatalf("allow summary = %q", got)
	}
	if got := pathSummary(pkgallowlist.PathPolicy{}); got != "deny" {
		t.Fatalf("deny summary = %q", got)
	}
}
