//go:build linux

package policymonitor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// writeConfigJSON synthesises an OCI spec config.json with the given
// annotations and writes it under <watchDir>/<cid>/config.json.
func writeConfigJSON(t *testing.T, watchDir, cid string, annotations map[string]string) {
	t.Helper()
	dir := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ociSpec{Annotations: annotations})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// newTestMonitor wires the monitor against tempdirs + fakes.
func newTestMonitor(t *testing.T, allowlistEntries []string) (*monitor, *fakeKiller, string) {
	t.Helper()
	watchDir := t.TempDir()

	allowlistDir := t.TempDir()
	allowlistPath := filepath.Join(allowlistDir, "allowlist.json")
	body, err := json.Marshal(bootstrapAllowlistFile{Sha256Digests: allowlistEntries})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowlistPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	a, _, err := loadAllowlist(allowlistPath)
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}

	killer := &fakeKiller{}
	killer.ok = true

	logger, err := certutil.NewJSONLogger("debug")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	m := &monitor{
		cfg: &Config{
			AllowlistPath: allowlistPath,
			WatchDir:      watchDir,
			CgroupRoot:    "/sys/fs/cgroup",
			LogLevel:      "debug",
		},
		logger:             logger,
		allowlist:          a,
		killer:             killer,
		configReadDeadline: 200 * time.Millisecond,
		configReadInterval: 10 * time.Millisecond,
	}
	return m, killer, watchDir
}

func TestHandleNewContainer_AllowedDigest(t *testing.T) {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})

	cid := "abcdef0123"
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "container",
		"io.kubernetes.cri.image-name":     "ghcr.io/confidential-dot-ai/assam@sha256:" + digest,
	})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("unexpected kill calls: %+v", calls)
	}
}

func TestHandleNewContainer_DeniedDigest(t *testing.T) {
	allowed := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	denied := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + allowed})

	cid := "deadbeef"
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "container",
		"io.kubernetes.cri.image-name":     "ghcr.io/evil/badimage@sha256:" + denied,
	})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	calls := killer.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 kill, got %d: %+v", len(calls), calls)
	}
	if calls[0] != cid {
		t.Errorf("container ID = %q, want %q", calls[0], cid)
	}
}

func TestHandleNewContainer_NoDigestAnnotation_Denies(t *testing.T) {
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	cid := "no-anno"
	writeConfigJSON(t, watchDir, cid, map[string]string{})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected deny+kill on missing annotation, got %d calls", len(calls))
	}
}

func TestHandleNewContainer_UnreadableConfigDenies(t *testing.T) {
	// config.json exists but cannot be read as a file (a directory in its
	// place): the bundle is clearly present but its digest is undeterminable,
	// so the monitor must fail closed (deny+kill) rather than let it run (H-01).
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	m.configReadDeadline = 50 * time.Millisecond
	cid := "unreadable-config"
	dir := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(filepath.Join(dir, "config.json"), 0o755); err != nil {
		t.Fatal(err)
	}

	m.handleNewContainer(context.Background(), dir)

	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected deny+kill on present-but-unreadable config.json, got %d calls: %+v", len(calls), calls)
	}
}

func TestHandleNewContainer_AbsentConfigSkips(t *testing.T) {
	// An absent config.json (a non-container watch entry, or a bundle not yet
	// written) must be skipped, not killed — killing infrastructure dirs would
	// be a false positive (H-01 scope boundary).
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	m.configReadDeadline = 50 * time.Millisecond
	cid := "shared"
	if err := os.MkdirAll(filepath.Join(watchDir, cid), 0o755); err != nil {
		t.Fatal(err)
	}

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("expected no kill for an absent config.json, got %d calls: %+v", len(calls), calls)
	}
}

func TestHandleNewContainer_MalformedConfigDenies(t *testing.T) {
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	m.configReadDeadline = 50 * time.Millisecond
	cid := "bad-config"
	dir := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{ not valid json"), 0o644); err != nil {
		t.Fatal(err)
	}

	m.handleNewContainer(context.Background(), dir)

	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected deny+kill on malformed config.json, got %d calls: %+v", len(calls), calls)
	}
}

func TestHandleNewContainer_SandboxSkipped(t *testing.T) {
	// The pod sandbox (pause) container carries container-type=sandbox and
	// no image digest. kata runs the measured baked pause for it, so
	// policy-monitor must skip it rather than deny — otherwise every pod's
	// sandbox gets killed and no pod can start.
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	cid := "sandbox0"
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "sandbox",
	})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("sandbox container should be skipped, got %d kill calls: %+v", len(calls), calls)
	}
}

func TestHandleNewContainer_SandboxSkippedEvenWithUnallowlistedDigest(t *testing.T) {
	// Safety property: a container marked as the sandbox is skipped even
	// when it also carries a non-allowlisted image digest. That's safe
	// because kata-agent runs the measured baked pause for any sandbox
	// regardless of the requested image, so a host that mislabels a
	// workload as a sandbox to dodge enforcement gains nothing — its image
	// never runs. policy-monitor identifies the sandbox the same way kata
	// does (isSandbox), keeping the two in lockstep.
	denied := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	cid := "sandbox-evil"
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.container-type": "sandbox",
		"io.kubernetes.cri.image-name":     "ghcr.io/evil/badimage@sha256:" + denied,
	})

	m.handleNewContainer(context.Background(), filepath.Join(watchDir, cid))

	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("sandbox should be skipped even with a non-allowlisted digest, got %d kill calls: %+v", len(calls), calls)
	}
}

func TestHandleNewContainer_ConfigJSONAppearsLate(t *testing.T) {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})

	cid := "late-config"
	// Create only the directory; spawn a goroutine to drop config.json
	// in after a short delay (mirrors the kata-agent race between mkdir
	// and write).
	dir := filepath.Join(watchDir, cid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		body, _ := json.Marshal(ociSpec{
			Annotations: map[string]string{
				"io.kubernetes.cri.container-type": "container",
				"io.kubernetes.cri.image-name":     "ghcr.io/confidential-dot-ai/assam@sha256:" + digest,
			},
		})
		_ = os.WriteFile(filepath.Join(dir, "config.json"), body, 0o644)
	}()
	m.handleNewContainer(context.Background(), dir)
	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("expected allow (no kills) after late config.json, got %+v", calls)
	}
}

// A valid annotation-less spec is a complete policy input and must not wait
// for an attacker-controlled annotation to appear.
func TestReadConfigJSON_ValidAnnotationlessSpecReturnsImmediately(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	cid := "annotationless"
	path := filepath.Join(watchDir, cid, "config.json")
	writeConfigJSON(t, watchDir, cid, map[string]string{"unrelated": "x"})
	m.configReadDeadline = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	spec, err := m.readConfigJSON(ctx, path)
	if err != nil {
		t.Fatalf("readConfigJSON: %v", err)
	}
	if spec == nil || spec.Annotations["unrelated"] != "x" {
		t.Fatalf("got spec %+v, want complete annotationless spec", spec)
	}
}

func TestPathLooksLikeContainer(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	for _, tc := range []struct {
		path string
		want bool
	}{
		{filepath.Join(watchDir, "abc123"), true},
		{filepath.Join(watchDir, "shared"), true},                    // not a digest, but valid id charset; filtered later by no annotation
		{filepath.Join(watchDir, "deep", "nested", "abc123"), false}, // not a direct child
		{filepath.Join(watchDir, "with spaces"), false},              // disallowed character
		{filepath.Join(watchDir, ""), false},                         // empty
		{watchDir, false},                                            // the watch dir itself
	} {
		got := m.pathLooksLikeContainer(tc.path)
		if got != tc.want {
			t.Errorf("pathLooksLikeContainer(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestRun_DetectsCreatedContainer(t *testing.T) {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	denied := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()

	// Give the watcher time to install.
	time.Sleep(50 * time.Millisecond)

	cid := "live-deny"
	writeConfigJSON(t, watchDir, cid, map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/evil/badimage@sha256:" + denied,
	})

	// Poll for the kill (the watcher dispatches to a goroutine, so
	// we don't have a synchronisation point; one second is generous).
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if killSeen(killer) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !killSeen(killer) {
		t.Fatal("denied container did not trigger SIGKILL via inotify event")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run returned err: %v", err)
	}
}

func killSeen(k *fakeKiller) bool {
	return len(k.snapshot()) > 0
}

// TestRun_SurvivesWatchDirReplacement reproduces what kata-agent's
// create_sandbox does to the watch dir at every first sandbox:
// remove_dir_all + create_dir_all (rpc.rs), which orphans an
// inode-bound inotify watch. The monitor must notice, re-establish the
// watch on the new inode, and still deny a non-allowlisted container
// created afterwards — this was the "silently inert enforcement" field
// failure.
func TestRun_SurvivesWatchDirReplacement(t *testing.T) {
	allowed := strings.Repeat("a", 64)
	denied := strings.Repeat("b", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + allowed})
	// Shrink the revalidation backstop so the test doesn't depend on
	// the Remove event being delivered (either recovery path must work).
	m.revalidateInterval = 25 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()

	// Give the first watch generation time to install.
	time.Sleep(50 * time.Millisecond)

	// kata-agent create_sandbox equivalent: replace the dir wholesale,
	// then immediately drop a bundle in — no pause, exactly like the
	// agent writing bundles right after create_dir_all.
	if err := os.RemoveAll(watchDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(watchDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfigJSON(t, watchDir, "post-replace-deny", map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/evil/badimage@sha256:" + denied,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if killSeen(killer) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !killSeen(killer) {
		t.Fatal("denied container created after watch-dir replacement was not killed — watch was not re-established")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run returned err: %v", err)
	}
}
