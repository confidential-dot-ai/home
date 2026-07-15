//go:build linux

package policymonitor

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// testLogger returns a debug-level JSON logger for tests that drive the
// CDS-refresh helpers directly (which take a *slog.Logger).
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	logger, err := certutil.NewJSONLogger("debug")
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return logger
}

// --- splitCSV -------------------------------------------------------------

func TestSplitCSV(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ,, c ", []string{"a", "b", "c"}},
		{",,,", nil},
	} {
		got := splitCSV(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("splitCSV(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

// --- refreshOnce ----------------------------------------------------------

// newSeededAllowlist builds an *allowlist with a single seed digest.
func newSeededAllowlist(t *testing.T, seed string) *allowlist {
	t.Helper()
	dir := t.TempDir()
	body, err := json.Marshal(bootstrapAllowlistFile{Sha256Digests: []string{seed}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "seed.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	a, _, err := loadAllowlist(path)
	if err != nil {
		t.Fatalf("loadAllowlist: %v", err)
	}
	return a
}

func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("ParseDigest(%q): %v", s, err)
	}
	return d
}

func TestRefreshOnce_MergesNewDigests(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	pulled := "sha256:" + strings.Repeat("b", 64)
	a := newSeededAllowlist(t, seed)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/allowlist" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(types.AllowlistListResponse{
			Version: "v2",
			Digests: map[types.Digest]string{
				mustDigest(t, seed):   "seed-image",
				mustDigest(t, pulled): "pulled-image",
			},
		})
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, srv.Client())
	refreshOnce(context.Background(), testLogger(t), client, a, time.Second)

	if a.Size() != 2 {
		t.Fatalf("size after refresh = %d, want 2", a.Size())
	}
	if !a.Contains(pulled) {
		t.Error("pulled digest not merged")
	}
	if !a.Contains(seed) {
		t.Error("seed digest dropped")
	}
}

func TestRefreshOnce_NoNewDigests(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	a := newSeededAllowlist(t, seed)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(types.AllowlistListResponse{
			Version: "v1",
			Digests: map[types.Digest]string{mustDigest(t, seed): "seed-image"},
		})
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, srv.Client())
	refreshOnce(context.Background(), testLogger(t), client, a, time.Second)

	if a.Size() != 1 {
		t.Fatalf("size = %d, want 1 (no growth)", a.Size())
	}
}

func TestRefreshOnce_CDSErrorKeepsAllowlist(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	a := newSeededAllowlist(t, seed)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, srv.Client())
	refreshOnce(context.Background(), testLogger(t), client, a, time.Second)

	// A CDS failure must never shrink the allowlist below the seed.
	if a.Size() != 1 {
		t.Fatalf("size after failed refresh = %d, want 1 (seed preserved)", a.Size())
	}
	if !a.Contains(seed) {
		t.Error("seed dropped after CDS failure")
	}
}

// --- runAllowlistRefresh disabled paths -----------------------------------

func TestRunAllowlistRefresh_InvalidMeasurements(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	a := newSeededAllowlist(t, seed)
	cfg := &Config{
		CDSURL:          "https://cds.example",
		CDSMeasurements: "not-valid-hex!!",
		RefreshInterval: time.Second,
	}
	// Returns promptly (refresh disabled) and never touches the network.
	runAllowlistRefresh(context.Background(), testLogger(t), cfg, a)
	if a.Size() != 1 {
		t.Fatalf("size = %d, want 1 (seed unchanged)", a.Size())
	}
}

func TestRunAllowlistRefresh_EmptyMeasurementsFailsClosed(t *testing.T) {
	seed := "sha256:" + strings.Repeat("a", 64)
	a := newSeededAllowlist(t, seed)
	cfg := &Config{
		CDSURL:          "https://cds.example",
		CDSMeasurements: "",
		RefreshInterval: time.Second,
	}
	runAllowlistRefresh(context.Background(), testLogger(t), cfg, a)
	if a.Size() != 1 {
		t.Fatalf("size = %d, want 1", a.Size())
	}
}

// --- monitor.kill paths ---------------------------------------------------

func TestMonitorKill_KillerError(t *testing.T) {
	m, killer, _ := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	killer.err = os.ErrPermission
	m.kill("somecid")
	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected one cgroup kill attempt, got %+v", calls)
	}
}

func TestMonitorKill_CgroupNotFound(t *testing.T) {
	m, killer, _ := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	killer.ok = false
	m.kill("somecid")
	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected one cgroup lookup, got %+v", calls)
	}
}

// --- seedExisting ---------------------------------------------------------

func TestSeedExisting_DeniesPreexistingContainer(t *testing.T) {
	denied := strings.Repeat("b", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})

	// A container directory already present when the monitor starts (e.g.
	// systemd restarted policy-monitor while a workload was live).
	writeConfigJSON(t, watchDir, "preexisting", map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/evil@sha256:" + denied,
	})
	// A sibling artifact that is not a container id should be skipped.
	if err := os.MkdirAll(filepath.Join(watchDir, "shared", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := m.seedExisting(); err != nil {
		t.Fatalf("seedExisting: %v", err)
	}
	if calls := killer.snapshot(); len(calls) != 1 {
		t.Fatalf("expected 1 kill for the preexisting denied container, got %+v", calls)
	}
}

func TestSeedExisting_MissingWatchDir(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.cfg.WatchDir = filepath.Join(watchDir, "does-not-exist")
	if err := m.seedExisting(); err == nil {
		t.Fatal("expected error reading a missing watch dir")
	}
}

// --- readConfigJSON / readOCISpec error paths -----------------------------

func TestReadConfigJSON_MissingForeverTimesOut(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 60 * time.Millisecond
	m.configReadInterval = 10 * time.Millisecond
	_, err := m.readConfigJSON(context.Background(), filepath.Join(watchDir, "nope", "config.json"))
	if err == nil {
		t.Fatal("expected error when config.json never appears")
	}
}

func TestReadConfigJSON_ContextCancelled(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 5 * time.Second
	m.configReadInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := m.readConfigJSON(ctx, filepath.Join(watchDir, "nope", "config.json"))
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestReadConfigJSON_UnrecoverableIsADir(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	// Point at a directory: os.ReadFile returns a non-ENOENT, non-partial
	// error, which readConfigJSON must surface immediately rather than
	// retrying to the deadline.
	dir := filepath.Join(watchDir, "isadir")
	if err := os.MkdirAll(filepath.Join(dir, "config.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	m.configReadDeadline = 5 * time.Second
	start := time.Now()
	if _, err := m.readConfigJSON(context.Background(), filepath.Join(dir, "config.json")); err == nil {
		t.Fatal("expected error for a directory in place of config.json")
	}
	if time.Since(start) > time.Second {
		t.Fatal("readConfigJSON retried an unrecoverable error instead of failing fast")
	}
}

func TestReadOCISpec_EmptyFileIsPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readOCISpec(path)
	if !isPartialJSON(err) {
		t.Fatalf("empty file: err = %v, want partial-json sentinel", err)
	}
}

func TestReadOCISpec_BadJSONIsPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readOCISpec(path)
	if !isPartialJSON(err) {
		t.Fatalf("bad json: err = %v, want partial-json sentinel", err)
	}
}

func TestHandleNewContainer_ConfigNeverAppears_NoKill(t *testing.T) {
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	m.configReadDeadline = 40 * time.Millisecond
	m.configReadInterval = 10 * time.Millisecond
	// Only the directory, no config.json ever. The read fails and the
	// container is logged-and-skipped (not killed: we couldn't make a
	// decision).
	dir := filepath.Join(watchDir, "ghost")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	m.handleNewContainer(context.Background(), dir)
	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("expected no kill when config.json never appears, got %+v", calls)
	}
}

// --- cgroup helpers -------------------------------------------------------

func TestNewCgroupKiller_Defaults(t *testing.T) {
	killer := newCgroupKiller("/sys/fs/cgroup")
	if killer.cgroupRoot != "/sys/fs/cgroup" {
		t.Errorf("cgroupRoot = %q", killer.cgroupRoot)
	}
	if killer.waitTimeout <= 0 || killer.pollInterval <= 0 {
		t.Errorf("expected positive wait/poll, got %v/%v", killer.waitTimeout, killer.pollInterval)
	}
}

func TestFindCgroupDir_EmptyID(t *testing.T) {
	_, err := findCgroupDir(t.TempDir(), "")
	if err == nil {
		t.Fatal("expected error for empty container id")
	}
}

// --- allowlist nil receivers ----------------------------------------------

func TestAllowlistNilReceivers(t *testing.T) {
	var a *allowlist
	if a.Contains("sha256:" + strings.Repeat("a", 64)) {
		t.Error("nil allowlist Contains should be false")
	}
	if a.Size() != 0 {
		t.Error("nil allowlist Size should be 0")
	}
	if a.MergePulled([]string{"sha256:" + strings.Repeat("a", 64)}) != 0 {
		t.Error("nil allowlist MergePulled should add 0")
	}
}

func TestAllowlistContains_Malformed(t *testing.T) {
	a := newSeededAllowlist(t, "sha256:"+strings.Repeat("a", 64))
	if a.Contains("garbage") {
		t.Error("Contains should be false for malformed input")
	}
	if a.Contains("") {
		t.Error("Contains should be false for empty input")
	}
}

// --- loadAllowlist malformed JSON -----------------------------------------

func TestLoadAllowlist_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAllowlist(path); err == nil {
		t.Fatal("expected parse error for malformed allowlist JSON")
	}
}

// --- runMonitor end-to-end ------------------------------------------------

func TestRunMonitor_BadLogLevel(t *testing.T) {
	cfg := &Config{LogLevel: "not-a-level"}
	if err := runMonitor(context.Background(), cfg); err == nil {
		t.Fatal("expected error for invalid log level")
	}
}

func TestRunMonitor_MissingAllowlist(t *testing.T) {
	cfg := &Config{
		LogLevel:      "info",
		AllowlistPath: filepath.Join(t.TempDir(), "absent.json"),
		WatchDir:      t.TempDir(),
		CgroupRoot:    t.TempDir(),
	}
	if err := runMonitor(context.Background(), cfg); err == nil {
		t.Fatal("expected error loading a missing allowlist")
	}
}

func TestRunMonitor_RunsAndStopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "allowlist.json")
	body, _ := json.Marshal(bootstrapAllowlistFile{Sha256Digests: []string{"sha256:" + strings.Repeat("a", 64)}})
	if err := os.WriteFile(allowlistPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		LogLevel:      "info",
		AllowlistPath: allowlistPath,
		WatchDir:      filepath.Join(dir, "watch"), // created by runMonitor
		CgroupRoot:    t.TempDir(),
		// CDSURL empty: stays baked-seed-only, never touches the network.
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runMonitor(ctx, cfg) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runMonitor returned err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runMonitor did not stop after context cancel")
	}
	// The watch dir should have been created.
	if _, err := os.Stat(cfg.WatchDir); err != nil {
		t.Errorf("watch dir not created: %v", err)
	}
}

// --- run() overflow rescan recovery (drives seedExisting via Errors) ------

func TestMonitorRun_AllowedContainerNotKilled(t *testing.T) {
	digest := strings.Repeat("a", 64)
	m, killer, watchDir := newTestMonitor(t, []string{"sha256:" + digest})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.run(ctx) }()
	time.Sleep(50 * time.Millisecond)

	writeConfigJSON(t, watchDir, "allowed-live", map[string]string{
		"io.kubernetes.cri.image-name": "ghcr.io/ok@sha256:" + digest,
	})
	time.Sleep(200 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run err: %v", err)
	}
	if calls := killer.snapshot(); len(calls) != 0 {
		t.Fatalf("allowed container should not be killed, got %+v", calls)
	}
}

// run() creates a missing watch dir itself — it has to, to re-establish the
// watch after kata-agent replaces the dir at sandbox creation — so "missing"
// is not an error. "Uncreatable" still must be: a regular file where the
// parent dir should be.
func TestMonitorRun_WatchDirUncreatable(t *testing.T) {
	m, _, watchDir := newTestMonitor(t, []string{"sha256:" + strings.Repeat("a", 64)})
	blocker := filepath.Join(watchDir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	m.cfg.WatchDir = filepath.Join(blocker, "absent")
	if err := m.run(context.Background()); err == nil {
		t.Fatal("expected error when the watch dir cannot be created")
	}
}

// --- newMonitorCommand flag parsing ---------------------------------------

func TestNewMonitorCommand_FlagParsing(t *testing.T) {
	cmd := newMonitorCommand()
	err := cmd.Flags().Parse([]string{
		"--allowlist", "/tmp/a.json",
		"--watch-dir", "/tmp/watch",
		"--cgroup-root", "/tmp/cg",
		"--log-level", "warn",
		"--cds-url", "https://cds",
		"--cds-measurements", "abc,def",
		"--attestation-service-url", "http://127.0.0.1:9000",
		"--allowlist-refresh-interval", "5s",
	})
	if err != nil {
		t.Fatalf("flag parse: %v", err)
	}
	get := func(name string) string {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Fatalf("flag %q missing", name)
		}
		return f.Value.String()
	}
	if got := get("allowlist"); got != "/tmp/a.json" {
		t.Errorf("allowlist = %q", got)
	}
	if got := get("allowlist-refresh-interval"); got != "5s" {
		t.Errorf("refresh-interval = %q", got)
	}
	if got := get("cds-url"); got != "https://cds" {
		t.Errorf("cds-url = %q", got)
	}
}

func TestNewMonitorCommand_RunEErrorsOnMissingAllowlist(t *testing.T) {
	cmd := newMonitorCommand()
	// Force a deterministic failure: a non-existent allowlist path. Use a
	// short-lived already-cancelled context so the run never blocks even if
	// it somehow got past the allowlist load.
	if err := cmd.Flags().Parse([]string{
		"--allowlist", filepath.Join(t.TempDir(), "absent.json"),
		"--watch-dir", t.TempDir(),
		"--cgroup-root", t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd.SetContext(ctx)
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("expected RunE to error on missing allowlist")
	}
}

func TestConfig_FillDefaults_FromEnv(t *testing.T) {
	t.Setenv("C8S_CDS_URL", "https://cds.from.env")
	t.Setenv("C8S_CDS_MEASUREMENTS", "aabb")
	t.Setenv("C8S_ATTESTATION_SERVICE_URL", "http://attester.env")
	var c Config
	c.fillDefaults()
	if c.CDSURL != "https://cds.from.env" {
		t.Errorf("CDSURL = %q", c.CDSURL)
	}
	if c.CDSMeasurements != "aabb" {
		t.Errorf("CDSMeasurements = %q", c.CDSMeasurements)
	}
	if c.AttestationServiceURL != "http://attester.env" {
		t.Errorf("AttestationServiceURL = %q", c.AttestationServiceURL)
	}
	if c.RefreshInterval != defaultRefreshInterval {
		t.Errorf("RefreshInterval = %v, want default", c.RefreshInterval)
	}
}

func TestConfig_FillDefaults_AttestationFallback(t *testing.T) {
	t.Setenv("C8S_CDS_URL", "")
	t.Setenv("C8S_CDS_MEASUREMENTS", "")
	t.Setenv("C8S_ATTESTATION_SERVICE_URL", "")
	var c Config
	c.fillDefaults()
	if c.AttestationServiceURL != defaultAttestationServiceURL {
		t.Errorf("AttestationServiceURL = %q, want %q", c.AttestationServiceURL, defaultAttestationServiceURL)
	}
}

// --- Run() top-level ------------------------------------------------------

func TestRun_UnknownSubcommandErrors(t *testing.T) {
	if err := Run([]string{"nonexistent-subcommand"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}
