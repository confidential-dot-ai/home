package nriimagepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cache"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	pushDigestA = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	pushDigestB = "sha256:0000000000000000000000000000000000000000000000000000000000000002"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestMergeAllowlistsOverlay(t *testing.T) {
	a := &allowlist.Allowlist{Version: "a", Digests: map[string]string{
		pushDigestA: "image-a",
	}}
	b := &allowlist.Allowlist{Version: "b", Digests: map[string]string{
		pushDigestB: "image-b",
	}}

	merged := mergeAllowlists(a, b)

	if got := merged.Version; got != "b" {
		t.Fatalf("version = %q, want b", got)
	}
	if got, ok := merged.Digests[pushDigestA]; !ok || got != "image-a" {
		t.Fatalf("bootstrap entry missing: %q ok=%v", got, ok)
	}
	if got, ok := merged.Digests[pushDigestB]; !ok || got != "image-b" {
		t.Fatalf("pushed entry missing: %q ok=%v", got, ok)
	}
}

func TestMergeAllowlistsOverlayOverrides(t *testing.T) {
	a := &allowlist.Allowlist{Digests: map[string]string{
		pushDigestA: "old-image",
	}}
	b := &allowlist.Allowlist{Digests: map[string]string{
		pushDigestA: "new-image",
	}}

	merged := mergeAllowlists(a, b)
	if got := merged.Digests[pushDigestA]; got != "new-image" {
		t.Fatalf("override entry = %q, want new-image", got)
	}
}

func TestMergeAllowlistsNilOverlay(t *testing.T) {
	a := &allowlist.Allowlist{Version: "a", Digests: map[string]string{
		pushDigestA: "image-a",
	}}
	merged := mergeAllowlists(a, nil)
	if merged.Digests[pushDigestA] != "image-a" || merged.Version != "a" {
		t.Fatalf("nil overlay should return a copy of a, got %+v", merged)
	}
	// Caller mutating the result must not bleed into a.
	merged.Digests[pushDigestA] = "mutated"
	if a.Digests[pushDigestA] != "image-a" {
		t.Fatalf("merged result aliases a; mutation leaked")
	}
}

func TestStartupSourceMode(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config
		want string
	}{
		{
			name: "pull",
			cfg: &config{Allowlist: allowlistConfig{
				Pull: pullConfig{URL: "https://cds.example"},
			}},
			want: "pull",
		},
		{
			name: "push",
			cfg: &config{Allowlist: allowlistConfig{
				Push: pushConfig{PersistPath: "/run/nri/pushed.json"},
			}},
			want: "push",
		},
		{
			name: "always allow only",
			cfg: &config{Allowlist: allowlistConfig{
				AlwaysAllow: map[string]string{pushDigestA: "image-a"},
			}},
			want: "always_allow",
		},
		{
			name: "label rules only",
			cfg: &config{Policy: policyConfig{
				LabelRules: []labelRule{{Name: "require-tenant"}},
			}},
			want: "label_rules",
		},
		{
			name: "static and label rules",
			cfg: &config{
				Allowlist: allowlistConfig{
					AlwaysAllow: map[string]string{pushDigestA: "image-a"},
				},
				Policy: policyConfig{
					LabelRules: []labelRule{{Name: "require-tenant"}},
				},
			},
			want: "always_allow+label_rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := startupSourceMode(tt.cfg); got != tt.want {
				t.Fatalf("startupSourceMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadAllowlistFileMissingReturnsNil(t *testing.T) {
	wl, err := loadAllowlistFile(filepath.Join(t.TempDir(), "absent.yaml"), "bootstrap", discardLogger())
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if wl != nil {
		t.Fatalf("missing file should return nil, got %+v", wl)
	}
}

func TestLoadAllowlistFileParseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("digests: not-a-map\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAllowlistFile(path, "bootstrap", discardLogger()); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadAllowlistFileYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap.yaml")
	yamlSrc := `version: "1"
digests:
  "` + pushDigestA + `": "image-a"
`
	if err := os.WriteFile(path, []byte(yamlSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	wl, err := loadAllowlistFile(path, "bootstrap", discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wl.Digests[pushDigestA] != "image-a" {
		t.Fatalf("digest not parsed: %+v", wl.Digests)
	}
}

// --- push handler ---

func makePushHandler(t *testing.T, bootstrap *allowlist.Allowlist) (*pushHandler, *cache.PolicyCache, string) {
	t.Helper()
	c := cache.NewPolicyCache()
	c.SetAllowlist(bootstrap)
	pushedPath := filepath.Join(t.TempDir(), "pushed.json")
	h, err := newPushHandler(c, bootstrap, pushedPath, discardLogger())
	if err != nil {
		t.Fatalf("newPushHandler: %v", err)
	}
	return h, c, pushedPath
}

func pushBody(t *testing.T, entries ...string) string {
	t.Helper()
	if len(entries)%2 != 0 {
		t.Fatalf("pushBody: entries must be pairs, got %d", len(entries))
	}
	payload := types.AllowlistListResponse{Version: "1", Digests: map[types.Digest]string{}}
	for i := 0; i < len(entries); i += 2 {
		d, err := types.ParseDigest(entries[i])
		if err != nil {
			t.Fatalf("pushBody: invalid digest %q: %v", entries[i], err)
		}
		payload.Digests[d] = entries[i+1]
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("pushBody: marshal: %v", err)
	}
	return string(b)
}

func TestNewPushHandlerRejectsEmptyPath(t *testing.T) {
	c := cache.NewPolicyCache()
	if _, err := newPushHandler(c, &allowlist.Allowlist{Digests: map[string]string{}}, "", discardLogger()); err == nil {
		t.Fatal("expected error for empty pushedPath")
	}
}

func TestPushHandlerValidSingleEntry(t *testing.T) {
	bootstrap := &allowlist.Allowlist{Digests: map[string]string{
		pushDigestA: "bootstrap-image",
	}}
	h, c, pushedPath := makePushHandler(t, bootstrap)

	req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(pushBody(t, pushDigestB, "pushed-image")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	wl := c.GetAllowlist()
	if wl.Digests[pushDigestA] != "bootstrap-image" {
		t.Fatal("bootstrap entry lost after push")
	}
	if wl.Digests[pushDigestB] != "pushed-image" {
		t.Fatal("pushed entry missing")
	}
	if _, err := os.Stat(pushedPath); err != nil {
		t.Fatalf("pushed.json not written: %v", err)
	}
}

func TestPushHandlerTwoEntriesRejected(t *testing.T) {
	h, c, pushedPath := makePushHandler(t, &allowlist.Allowlist{Digests: map[string]string{
		pushDigestA: "bootstrap-image",
	}})
	body := pushBody(t, pushDigestA, "a", pushDigestB, "b")

	req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if _, err := os.Stat(pushedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pushed.json should not exist on 422, err=%v", err)
	}
	if got := c.GetAllowlist().Digests[pushDigestA]; got != "bootstrap-image" {
		t.Fatalf("cache mutated on 422; bootstrap entry = %q", got)
	}
}

func TestPushHandlerMalformedJSON(t *testing.T) {
	h, c, _ := makePushHandler(t, &allowlist.Allowlist{Digests: map[string]string{}})
	req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if c.GetAllowlist() == nil || len(c.GetAllowlist().Digests) != 0 {
		t.Fatal("cache should be untouched on 400")
	}
}

func TestPushHandlerWrongMethod(t *testing.T) {
	h, _, _ := makePushHandler(t, &allowlist.Allowlist{Digests: map[string]string{}})
	req := httptest.NewRequest(http.MethodPost, "/allowlist", strings.NewReader(pushBody(t, pushDigestA, "img")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestStartHealthServerRejectsPushHandlerOnTCP(t *testing.T) {
	h, _, _ := makePushHandler(t, &allowlist.Allowlist{Digests: map[string]string{}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := startHealthServer(ctx, healthServerConfig{
		logger:       discardLogger(),
		plugin:       &plugin{},
		addr:         ":8080",
		readTimeout:  time.Second,
		writeTimeout: time.Second,
		pushHandler:  h,
	})

	if err == nil {
		t.Fatal("expected push handler on TCP health address to be rejected")
	}
	if !errors.Is(err, errPushHandlerRequiresUnixAddr) {
		t.Fatalf("expected errPushHandlerRequiresUnixAddr, got %v", err)
	}
}

func TestPushHandlerDiskWriteFailure(t *testing.T) {
	// Point pushedPath at a path whose parent is a regular file so the
	// atomic-write tempfile create fails with ENOTDIR.
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(blocker, []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}
	bootstrap := &allowlist.Allowlist{Digests: map[string]string{
		pushDigestA: "bootstrap-image",
	}}
	c := cache.NewPolicyCache()
	c.SetAllowlist(bootstrap)
	h, err := newPushHandler(c, bootstrap, filepath.Join(blocker, "pushed.json"), discardLogger())
	if err != nil {
		t.Fatalf("newPushHandler: %v", err)
	}

	preCache := c.GetAllowlist()

	req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(pushBody(t, pushDigestB, "img")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	// Contract: cache pointer unchanged from pre-PUT state on disk failure.
	if c.GetAllowlist() != preCache {
		t.Fatal("cache pointer should be unchanged on disk-write failure")
	}
}

// --- pull loop ---

// flippingHandler counts ETag-conditional hits and answers 200 or 304
// based on the configured cycle.
type flippingHandler struct {
	mu         sync.Mutex
	versions   []string // sequence of versions to serve; index advances after each 200
	idx        int
	hits       atomic.Int32
	digestByV  map[string]string
	imageByV   map[string]string
	statusCode int // overrides 200/304 logic when non-zero
}

func (f *flippingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.statusCode != 0 {
		w.WriteHeader(f.statusCode)
		return
	}

	version := f.versions[f.idx]
	etag := `W/"` + version + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	out := map[string]any{
		"version": version,
		"digests": map[string]string{f.digestByV[version]: f.imageByV[version]},
	}
	_ = json.NewEncoder(w).Encode(out)
	if f.idx < len(f.versions)-1 {
		f.idx++
	}
}

func TestPullLoopOnly200UpdatesCacheAndETag(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{
		versions:  []string{"1", "2"},
		digestByV: map[string]string{"1": pushDigestA, "2": pushDigestB},
		imageByV:  map[string]string{"1": "image-1", "2": "image-2"},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	c := cache.NewPolicyCache()
	bootstrap := &allowlist.Allowlist{Digests: map[string]string{}}
	c.SetAllowlist(bootstrap)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			client:    client,
			cache:     c,
			bootstrap: bootstrap,
			interval:  20 * time.Millisecond,
			timeout:   time.Second,
			etag:      "",
			logger:    discardLogger(),
		})
		close(done)
	}()

	// Wait until the cache has reflected both 200 responses.
	deadline := time.Now().Add(2 * time.Second)
	for {
		wl := c.GetAllowlist()
		if wl != nil && wl.Digests[pushDigestB] != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pull loop did not pick up the second update; cache=%+v", wl.Digests)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done
}

func TestPullLoop304LeavesCacheUntouched(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{
		versions:  []string{"1"},
		digestByV: map[string]string{"1": pushDigestA},
		imageByV:  map[string]string{"1": "image-1"},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	c := cache.NewPolicyCache()
	preload := &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-1"}}
	c.SetAllowlist(preload)
	bootstrap := &allowlist.Allowlist{Digests: map[string]string{}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Pre-seed the loop with the matching ETag so the first tick should 304.
	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			client:    client,
			cache:     c,
			bootstrap: bootstrap,
			interval:  10 * time.Millisecond,
			timeout:   time.Second,
			etag:      `W/"1"`,
			logger:    discardLogger(),
		})
		close(done)
	}()

	// Give the loop time to run a few ticks; verify cache is unchanged
	// (i.e. still references preload, not a merge with empty bootstrap).
	time.Sleep(100 * time.Millisecond)
	wl := c.GetAllowlist()
	if wl != preload {
		t.Fatalf("304 ticks should leave cache pointer unchanged; got=%p want=%p", wl, preload)
	}

	cancel()
	<-done
}

func TestPullLoop5xxLeavesCacheAndETagUntouched(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{statusCode: http.StatusInternalServerError})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	c := cache.NewPolicyCache()
	preload := &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "image-1"}}
	c.SetAllowlist(preload)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			client:    client,
			cache:     c,
			bootstrap: &allowlist.Allowlist{Digests: map[string]string{}},
			interval:  10 * time.Millisecond,
			timeout:   time.Second,
			etag:      `W/"5"`,
			logger:    discardLogger(),
		})
		close(done)
	}()

	time.Sleep(80 * time.Millisecond)
	if c.GetAllowlist() != preload {
		t.Fatal("5xx ticks should leave cache pointer unchanged")
	}

	cancel()
	<-done
}

func TestPushHandlerMergesBootstrapWithPushed(t *testing.T) {
	bootstrap := &allowlist.Allowlist{Digests: map[string]string{
		pushDigestA: "bootstrap-image",
	}}
	h, c, _ := makePushHandler(t, bootstrap)

	req := httptest.NewRequest(http.MethodPut, "/allowlist",
		strings.NewReader(pushBody(t, pushDigestB, "pushed-image")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	wl := c.GetAllowlist()
	if wl.Digests[pushDigestA] != "bootstrap-image" {
		t.Fatal("bootstrap entry must survive push (always_allow is the static floor)")
	}
	if wl.Digests[pushDigestB] != "pushed-image" {
		t.Fatal("pushed entry must be merged in")
	}
}

func TestPullLoopMergesBootstrapWithPulled(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{
		versions:  []string{"1"},
		digestByV: map[string]string{"1": pushDigestB},
		imageByV:  map[string]string{"1": "pulled-image"},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	bootstrap := &allowlist.Allowlist{Digests: map[string]string{
		pushDigestA: "bootstrap-image",
	}}
	c := cache.NewPolicyCache()
	c.SetAllowlist(bootstrap)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			client:    client,
			cache:     c,
			bootstrap: bootstrap,
			interval:  10 * time.Millisecond,
			timeout:   time.Second,
			etag:      "",
			logger:    discardLogger(),
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		wl := c.GetAllowlist()
		if wl != nil && wl.Digests[pushDigestB] != "" {
			if wl.Digests[pushDigestA] != "bootstrap-image" {
				t.Fatalf("bootstrap entry lost after pull; cache=%+v", wl.Digests)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pull loop never delivered the pulled entry; cache=%+v", wl)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-done
}

func TestPullInitialSucceedsAfterTransientFailures(t *testing.T) {
	orig := allowlistApiInitialDelay
	allowlistApiInitialDelay = time.Millisecond
	defer func() { allowlistApiInitialDelay = orig }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	// We can't easily inject a mock Client (concrete type), so spin up
	// an httptest server that fails the first two requests then returns
	// 200 with valid JSON. Reuse the existing allowlistclient.Client.
	var n atomic.Int32
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("ETag", `W/"1"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"1","digests":{"` + pushDigestB + `":"pulled-image"}}`))
	})

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	c := cache.NewPolicyCache()
	bootstrap := &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "bootstrap-image"}}
	c.SetAllowlist(bootstrap)

	pluginErrCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	etag, err := pullInitial(ctx, pullArgs{
		client:      client,
		cache:       c,
		bootstrap:   bootstrap,
		timeout:     time.Second,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if etag != `W/"1"` {
		t.Fatalf("etag = %q, want W/\"1\"", etag)
	}
	if got := c.GetAllowlist().Digests[pushDigestB]; got != "pulled-image" {
		t.Fatalf("cache missing pulled entry: %+v", c.GetAllowlist().Digests)
	}
}

func TestPullInitialFailsAfterMaxRetries(t *testing.T) {
	orig := allowlistApiInitialDelay
	allowlistApiInitialDelay = time.Millisecond
	defer func() { allowlistApiInitialDelay = orig }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 200 * time.Millisecond})
	c := cache.NewPolicyCache()
	pluginErrCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := pullInitial(ctx, pullArgs{
		client:      client,
		cache:       c,
		bootstrap:   &allowlist.Allowlist{Digests: map[string]string{}},
		timeout:     200 * time.Millisecond,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("expected error after max retries against a 5xx server")
	}
	// A fetch failure must NOT look like a dead plugin: run() degrades to the
	// bootstrap floor on a fetch failure but stays fatal on errPluginDied.
	if errors.Is(err, errPluginDied) {
		t.Fatalf("fetch failure misclassified as errPluginDied: %v", err)
	}
}

// A plugin-half death during init wraps errPluginDied so run() can treat it as
// fatal, unlike a recoverable fetch failure.
func TestPullInitialPluginDeathWrapsErrPluginDied(t *testing.T) {
	pluginErrCh := make(chan error, 1)
	pluginErrCh <- errors.New("nri socket closed")
	_, err := pullInitial(context.Background(), pullArgs{
		client:      allowlistclient.NewClientWithHTTP("https://unused", &http.Client{}),
		cache:       cache.NewPolicyCache(),
		bootstrap:   &allowlist.Allowlist{Digests: map[string]string{}},
		timeout:     time.Second,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if !errors.Is(err, errPluginDied) {
		t.Fatalf("plugin death not classified as errPluginDied: %v", err)
	}
}

func TestPullInitialNotModifiedDoesNotDereferenceNilAllowlist(t *testing.T) {
	origDelay := allowlistApiInitialDelay
	origRetries := allowlistApiMaxRetries
	allowlistApiInitialDelay = time.Millisecond
	allowlistApiMaxRetries = 1
	defer func() {
		allowlistApiInitialDelay = origDelay
		allowlistApiMaxRetries = origRetries
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 200 * time.Millisecond})
	c := cache.NewPolicyCache()
	bootstrap := &allowlist.Allowlist{Digests: map[string]string{pushDigestA: "bootstrap-image"}}
	c.SetAllowlist(bootstrap)
	pluginErrCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := pullInitial(ctx, pullArgs{
		client:      client,
		cache:       c,
		bootstrap:   bootstrap,
		timeout:     200 * time.Millisecond,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("expected error for initial 304 without cached CDS allowlist")
	}
	if !errors.Is(err, errInitialAllowlistNotModified) {
		t.Fatalf("expected errInitialAllowlistNotModified, got %v", err)
	}
	if c.GetAllowlist() != bootstrap {
		t.Fatal("initial 304 should leave cache pointer unchanged")
	}
}

func TestPullInitialCancelledMidRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 200 * time.Millisecond})
	c := cache.NewPolicyCache()
	pluginErrCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay so we land inside the backoff sleep.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	etag, err := pullInitial(ctx, pullArgs{
		client:      client,
		cache:       c,
		bootstrap:   &allowlist.Allowlist{Digests: map[string]string{}},
		timeout:     200 * time.Millisecond,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation should surface context.Canceled, got err=%v", err)
	}
	if etag != "" {
		t.Fatalf("cancellation should return empty etag, got %q", etag)
	}
}
