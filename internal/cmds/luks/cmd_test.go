package luks

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

// testBao builds a bao client with no custom CA and the default timeout.
func testBao(addr, token string) *bao {
	return newBao(addr, token, nil, 15*time.Second)
}

func TestGeneratePassphrase(t *testing.T) {
	for _, bytesN := range []int{16, 32, 64, 128} {
		p, err := generatePassphrase(bytesN)
		if err != nil {
			t.Fatalf("bytes=%d: %v", bytesN, err)
		}
		if len(p) != hex.EncodedLen(bytesN) {
			t.Errorf("bytes=%d: got %d hex chars, want %d", bytesN, len(p), hex.EncodedLen(bytesN))
		}
		// hex-only
		if _, err := hex.DecodeString(string(p)); err != nil {
			t.Errorf("bytes=%d: not valid hex: %v", bytesN, err)
		}
	}
}

func TestGeneratePassphraseEntropyBounds(t *testing.T) {
	for _, bytesN := range []int{0, 8, 15, 129, 256} {
		if _, err := generatePassphrase(bytesN); err == nil {
			t.Errorf("bytes=%d: want error", bytesN)
		}
	}
}

func TestZero(t *testing.T) {
	b := []byte("secret")
	zero(b)
	for i, c := range b {
		if c != 0 {
			t.Fatalf("b[%d] = %#x, want 0", i, c)
		}
	}
}

// putPassphrase hand-builds its JSON body; bytes that would need escaping
// must be rejected before any request is attempted.
func TestPutPassphraseRejectsJSONUnsafeBytes(t *testing.T) {
	c := testBao("https://unreachable.invalid", "root")
	for _, p := range [][]byte{[]byte(`pa"ss`), []byte("pa\\ss"), []byte("pa\nss"), {0xff}} {
		err := c.putPassphrase(context.Background(), "api", "data", p)
		if err == nil || !strings.Contains(err.Error(), "JSON-unsafe") {
			t.Errorf("passphrase %q: err = %v, want JSON-unsafe rejection", p, err)
		}
	}
}

func TestKVPathShape(t *testing.T) {
	if got := kvPath("api", "data"); got != "v1/secret/data/api/luks-data" {
		t.Errorf("kvPath = %q, want v1/secret/data/api/luks-data", got)
	}
	if got := kvListPath("api"); got != "v1/secret/metadata/api" {
		t.Errorf("kvListPath = %q", got)
	}
	if got := kvMetaPath("api", "data"); got != "v1/secret/metadata/api/luks-data" {
		t.Errorf("kvMetaPath = %q", got)
	}
}

func TestValidateCreate(t *testing.T) {
	base := createConfig{
		workload: "api", name: "data", mount: "/data", driver: "local",
		fstype: "ext4", output: "yaml", size: resource.MustParse("1Gi"),
		namespace: "default", allowHostFormat: true,
	}
	if err := validateCreate(base); err != nil {
		t.Errorf("baseline should be valid: %v", err)
	}
	xfs := base
	xfs.fstype = "xfs"
	if err := validateCreate(xfs); err != nil {
		t.Errorf("xfs should be allowed: %v", err)
	}
	tests := []struct {
		name string
		mut  func(*createConfig)
		want string
	}{
		{"missing workload", func(c *createConfig) { c.workload = "" }, "required"},
		{"missing name", func(c *createConfig) { c.name = "" }, "required"},
		{"bad workload label", func(c *createConfig) { c.workload = "Bad_Name" }, "DNS-1123"},
		{"bad name label", func(c *createConfig) { c.name = "Bad_Name" }, "DNS-1123"},
		{"zero size", func(c *createConfig) { c.size = resource.MustParse("0") }, "positive"},
		{"relative mount", func(c *createConfig) { c.mount = "data" }, "absolute path"},
		{"bad output", func(c *createConfig) { c.output = "xml" }, "yaml or json"},
		{"bad driver", func(c *createConfig) { c.driver = "nfs" }, "local | pvc"},
		{"csi not offered", func(c *createConfig) { c.driver = "csi" }, "local | pvc"},
		{"bad namespace", func(c *createConfig) { c.namespace = "Bad_NS" }, "DNS-1123"},
		{"traversal workload", func(c *createConfig) { c.workload = "../etc" }, "DNS-1123"},
		{"flag-shaped name", func(c *createConfig) { c.name = "--all" }, "DNS-1123"},
		{"name too long", func(c *createConfig) { c.name = strings.Repeat("a", 55) }, "max 54"},
		{"unknown fstype", func(c *createConfig) { c.fstype = "btrfs" }, "ext4 or xfs"},
		{"empty fstype", func(c *createConfig) { c.fstype = "" }, "ext4 or xfs"},
		{"fstype argv injection", func(c *createConfig) { c.fstype = "ext4 -E hack" }, "ext4 or xfs"},
		{"mount comma injection", func(c *createConfig) { c.mount = "/data,secret=evil#x" }, "absolute path"},
		{"mount equals", func(c *createConfig) { c.mount = "/data=x" }, "absolute path"},
		{"mount newline", func(c *createConfig) { c.mount = "/data\nmode=open" }, "absolute path"},
		{"mount space", func(c *createConfig) { c.mount = "/my data" }, "absolute path"},
		{"mount shell metachar", func(c *createConfig) { c.mount = "/data;rm" }, "absolute path"},
		{"local host-format gated", func(c *createConfig) {
			c.driver = "local"
			c.deferFormat = false
			c.allowHostFormat = false
		}, "allow-host-format"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mut(&c)
			err := validateCreate(c)
			if err == nil {
				t.Fatalf("want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// Every subcommand builds KV paths and kubectl argv from workload/name, so the
// shared validators must reject separators, dots, and flag-shaped values.
func TestValidateWorkloadName(t *testing.T) {
	if err := validateWorkloadName("api", "data"); err != nil {
		t.Errorf("valid labels rejected: %v", err)
	}
	for _, tc := range []struct{ workload, name string }{
		{"", "data"},
		{"api", ""},
		{"../etc", "data"},
		{"api", "a/b"},
		{"api", "data.v2"},
		{"-leading", "data"},
		{"api", "--all"},
		{"api", "data\npwned"},
	} {
		if err := validateWorkloadName(tc.workload, tc.name); err == nil {
			t.Errorf("workload=%q name=%q: want error", tc.workload, tc.name)
		}
	}
	if err := validateWorkload(""); err == nil {
		t.Error("empty workload: want error")
	}
	if err := validateNamespace("kube system"); err == nil {
		t.Error("namespace with space: want error")
	}
}

// localImgPath must confine the backing file to a direct child of --local-dir
// even for unvalidated inputs (defense in depth behind DNS-1123 validation).
func TestLocalImgPathConfinement(t *testing.T) {
	got, err := localImgPath("/var/lib/c8s/luks", "api", "data")
	if err != nil || got != "/var/lib/c8s/luks/api-data.img" {
		t.Fatalf("got (%q, %v), want /var/lib/c8s/luks/api-data.img", got, err)
	}
	for _, tc := range []struct{ dir, workload, name string }{
		{"relative/dir", "api", "data"},
		{"/var/lib/c8s/luks/../luks", "api", "data"},
		{"/var/lib/c8s/luks/", "api", "data"},
		{"/var/lib/c8s/luks", "../snap", "data"},
		{"/var/lib/c8s/luks", "api", "../../etc/shadow"},
		{"/var/lib/c8s/luks", "api", "x/y"},
	} {
		if p, err := localImgPath(tc.dir, tc.workload, tc.name); err == nil {
			t.Errorf("dir=%q workload=%q name=%q: want error, got %q", tc.dir, tc.workload, tc.name, p)
		}
	}
}

func TestLUKSModeAlias(t *testing.T) {
	if got := luksMode(true); got != "format-if-empty" {
		t.Errorf("deferFormat=true → %q, want format-if-empty", got)
	}
	if got := luksMode(false); got != "open" {
		t.Errorf("deferFormat=false → %q, want open", got)
	}
}

// The bao client uses an httptest server so we exercise the KV write / read /
// list / delete verbs without an openbao dependency.
func TestBaoKVLifecycle(t *testing.T) {
	// Track state per path so read/delete behave naturally.
	kv := map[string]any{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/data/api/luks-data", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "root" {
			http.Error(w, "no token", http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodPost:
			var body struct {
				Data map[string]any `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			kv["api/luks-data"] = body.Data
			// KV v2 answers a write with data.version; the client requires it.
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": 1}})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/v1/secret/metadata/api/luks-data", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if _, ok := kv["api/luks-data"]; !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"created_time": "2026-07-10T00:00:00Z", "versions": 1},
			})
		case http.MethodDelete:
			delete(kv, "api/luks-data")
			w.WriteHeader(http.StatusNoContent)
		}
	})
	mux.HandleFunc("/v1/secret/metadata/api", func(w http.ResponseWriter, r *http.Request) {
		// LIST arrives as a custom verb; openbao also accepts ?list=true.
		if r.Method != "LIST" && r.URL.Query().Get("list") != "true" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var keys []string
		for k := range kv {
			if strings.HasPrefix(k, "api/") {
				keys = append(keys, strings.TrimPrefix(k, "api/"))
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"keys": keys},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := testBao(srv.URL, "root")
	ctx := context.Background()

	// list is empty initially
	if got, err := c.listVolumes(ctx, "api"); err != nil || len(got) != 0 {
		t.Fatalf("list before create: got=%v err=%v", got, err)
	}
	// put
	if err := c.putPassphrase(ctx, "api", "data", []byte("s3cr3t")); err != nil {
		t.Fatalf("put: %v", err)
	}
	// list now has our entry
	names, err := c.listVolumes(ctx, "api")
	if err != nil {
		t.Fatalf("list after create: %v", err)
	}
	if len(names) != 1 || names[0] != "data" {
		t.Errorf("list = %v, want [data]", names)
	}
	// metadata read succeeds
	meta, err := c.readMetadata(ctx, "api", "data")
	if err != nil {
		t.Fatalf("readMetadata: %v", err)
	}
	if meta["created_time"] == nil {
		t.Errorf("metadata missing created_time: %+v", meta)
	}
	// delete
	if err := c.deleteVolume(ctx, "api", "data"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// metadata read now 404s
	if _, err := c.readMetadata(ctx, "api", "data"); err == nil || !isNotFound(err) {
		t.Errorf("after delete: want not-found error, got %v", err)
	}
}

// putPassphrase is a create-only (cas=0) write: a KV v2 cas conflict on an
// existing entry must surface as errVolumeExists so create refuses to overwrite
// (and never rolls back / destroys) a passphrase it did not create.
func TestPutPassphraseCASConflict(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/data/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["check-and-set parameter did not match the current version"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	err := testBao(srv.URL, "root").putPassphrase(context.Background(), "api", "data", []byte("s3cr3t"))
	if !errors.Is(err, errVolumeExists) {
		t.Fatalf("cas conflict: got %v, want errVolumeExists", err)
	}
}

// A redirecting openbao must not have the request (and X-Vault-Token)
// replayed to the redirect target.
func TestBaoRefusesRedirect(t *testing.T) {
	var targetHit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit = true
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	_, err := testBao(redirector.URL, "root").readMetadata(context.Background(), "api", "data")
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v, want redirect refusal", err)
	}
	if targetHit {
		t.Fatal("redirect target was contacted; token would have been replayed")
	}
}

// Error and success bodies come from an untrusted endpoint: reads must be
// capped, and error text must not carry control characters into logs.
func TestBaoResponseReadsCapped(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/metadata/api/luks-err", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("bad\r\nfake-log-line\x1b[31m "))
		_, _ = w.Write(bytes.Repeat([]byte("A"), 64<<10))
	})
	mux.HandleFunc("/v1/secret/metadata/api/luks-big", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"blob":"`))
		_, _ = w.Write(bytes.Repeat([]byte("A"), 2<<20))
		_, _ = w.Write([]byte(`"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := testBao(srv.URL, "root")

	_, err := c.readMetadata(context.Background(), "api", "err")
	var he *httpError
	if !errors.As(err, &he) {
		t.Fatalf("err = %v, want *httpError", err)
	}
	if len(he.body) > 8<<10 {
		t.Errorf("error body not capped: %d bytes", len(he.body))
	}
	if s := he.Error(); strings.ContainsAny(s, "\r\n\x1b") {
		t.Errorf("Error() leaks control characters: %q", s[:64])
	}

	// A >1MiB success body must fail decoding, not be read unboundedly.
	if _, err := c.readMetadata(context.Background(), "api", "big"); err == nil {
		t.Error("oversized response body: want decode error")
	}
}

// The openbao token and passphrases transit this connection, so client()
// must refuse anything but https unless --allow-insecure-store is explicit.
func TestBaoFlagsClientSchemeGate(t *testing.T) {
	for _, tc := range []struct {
		addr     string
		insecure bool
		wantErr  string
	}{
		{"https://bao.example:8200", false, ""},
		{"http://bao.example:8200", false, "refusing plaintext http"},
		{"http://bao.example:8200", true, ""},
		{"ftp://bao.example", false, "scheme must be https"},
		{"ftp://bao.example", true, "scheme must be https"},
		{"", false, "not a valid URL"},
		{"bao.example:8200", false, "not a valid URL"},
	} {
		f := baoFlags{Addr: tc.addr, Token: "root", AllowInsecure: tc.insecure}
		_, err := f.client()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("addr=%q insecure=%v: unexpected error %v", tc.addr, tc.insecure, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("addr=%q insecure=%v: err = %v, want substring %q", tc.addr, tc.insecure, err, tc.wantErr)
		}
	}
}

func TestReadTokenFile(t *testing.T) {
	// Empty path = empty token, no error.
	if got, err := readTokenFile(""); err != nil || got != "" {
		t.Errorf("empty path: got (%q, %v)", got, err)
	}
	// Non-existent path = error.
	if _, err := readTokenFile("/nonexistent/nowhere/token"); err == nil {
		t.Error("nonexistent path: want error")
	}
}

// The emitted annotation pair is the byte-level contract the webhook parser
// (webhook stage) consumes — pin it golden so drift fails in CI, not at pod
// admission.
func TestLuksAnnotationsGolden(t *testing.T) {
	cfg := createConfig{workload: "api", name: "data", mount: "/data", fstype: "ext4"}
	kvPath := "secret/data/api/luks-data"

	local := luksAnnotations(cfg, provisioned{devToken: "dev=/dev/loop7", mode: "open"}, kvPath)
	wantLocal := map[string]string{
		"confidential.ai/luks-data":   "dev=/dev/loop7,mount=/data,secret=secret/data/api/luks-data#passphrase,fstype=ext4,mode=open",
		"confidential.ai/secret-data": "secret/data/api/luks-data#passphrase",
	}
	for k, want := range wantLocal {
		if got := local[k]; got != want {
			t.Errorf("local annotation %q = %q, want %q", k, got, want)
		}
	}
	if len(local) != len(wantLocal) {
		t.Errorf("local annotations: got %d keys, want %d", len(local), len(wantLocal))
	}

	pvc := luksAnnotations(cfg, provisioned{devToken: "pvc=c8s-luks-api-data", mode: "format-if-empty"}, kvPath)
	want := "pvc=c8s-luks-api-data,mount=/data,secret=secret/data/api/luks-data#passphrase,fstype=ext4,mode=format-if-empty"
	if got := pvc["confidential.ai/luks-data"]; got != want {
		t.Errorf("pvc annotation = %q, want %q", got, want)
	}
}

// runCreate rolls back the KV entry it just created when provisioning fails,
// and surfaces a rollback failure joined with the original error.
func TestRunCreateRollback(t *testing.T) {
	newRollbackServer := func(deleteErr bool) (*httptest.Server, *bool) {
		deleted := false
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/secret/data/api/luks-data", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": 1}})
		})
		mux.HandleFunc("/v1/secret/metadata/api/luks-data", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				if deleteErr {
					http.Error(w, "sealed", http.StatusInternalServerError)
					return
				}
				deleted = true
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.NotFound(w, r)
		})
		return httptest.NewServer(mux), &deleted
	}
	cfg := createConfig{
		workload: "api", name: "data", driver: "pvc", fstype: "ext4",
		mount: "/data", namespace: "default", output: "yaml",
		size: resource.MustParse("1Gi"), entropyBytes: 32,
	}
	stubProvision := func(err error) {
		orig := provisionFn
		provisionFn = func(context.Context, createConfig, []byte) (provisioned, error) {
			return provisioned{}, err
		}
		t.Cleanup(func() { provisionFn = orig })
	}

	t.Run("provision failure deletes the KV entry", func(t *testing.T) {
		srv, deleted := newRollbackServer(false)
		defer srv.Close()
		stubProvision(errors.New("boom"))
		bf := &baoFlags{Addr: srv.URL, Token: "root", AllowInsecure: true}
		if err := runCreate(context.Background(), bf, cfg); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("err = %v, want the provision error", err)
		}
		if !*deleted {
			t.Error("KV entry not rolled back after provision failure")
		}
	})

	t.Run("rollback failure is surfaced", func(t *testing.T) {
		srv, _ := newRollbackServer(true)
		defer srv.Close()
		stubProvision(errors.New("boom"))
		bf := &baoFlags{Addr: srv.URL, Token: "root", AllowInsecure: true}
		err := runCreate(context.Background(), bf, cfg)
		if err == nil || !strings.Contains(err.Error(), "rollback") || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("err = %v, want provision + rollback errors joined", err)
		}
	})
}

// A KV v1 mount accepts the write with a bodiless 204 (ignoring cas) — the
// client must refuse rather than trust create-only semantics that don't exist.
func TestPutPassphraseRejectsNonV2Mount(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/data/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent) // KV v1 write response
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	err := testBao(srv.URL, "root").putPassphrase(context.Background(), "api", "data", []byte("s3cr3t"))
	if err == nil || !strings.Contains(err.Error(), "KV v2") {
		t.Fatalf("err = %v, want a KV v2 refusal", err)
	}
}

// An openbao serving under an internal CA is unreachable with system roots;
// --openbao-ca-cert must make the https path work.
func TestBaoCustomCA(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/metadata/api/luks-data", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"created_time": "2026-07-24T00:00:00Z"}})
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	if _, err := testBao(srv.URL, "root").readMetadata(context.Background(), "api", "data"); err == nil {
		t.Fatal("want TLS verification error without a custom CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	if _, err := newBao(srv.URL, "root", pool, 15*time.Second).readMetadata(context.Background(), "api", "data"); err != nil {
		t.Fatalf("with custom CA: %v", err)
	}
}

// fdHolders is the in-use signal for the local driver: it must see a plain
// userspace open, which sysfs holders never show.
func TestFdHoldersFindsOpenFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "held-*.img")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pids, err := fdHolders(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	mine := strconv.Itoa(os.Getpid())
	found := false
	for _, p := range pids {
		if p == mine {
			found = true
		}
	}
	if !found {
		t.Errorf("fdHolders(%s) = %v, want pid %s present", f.Name(), pids, mine)
	}
}

// destroy on a host where the volume was never provisioned (wrong node, or
// --driver local against a pvc volume) must refuse before touching the KV.
func TestRunDestroyLocalRefusesWhenNotProvisionedHere(t *testing.T) {
	kvDeleted := false
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/metadata/api/luks-data", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			kvDeleted = true
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := destroyCfg{workload: "api", name: "data", driver: "local", localBackingDir: t.TempDir(), namespace: "default"}
	err := runDestroy(context.Background(), testBao(srv.URL, "root"), cfg)
	if err == nil || !strings.Contains(err.Error(), "not provisioned here") {
		t.Fatalf("err = %v, want a not-provisioned-here refusal", err)
	}
	if kvDeleted {
		t.Fatal("KV entry deleted despite the refusal")
	}
}
