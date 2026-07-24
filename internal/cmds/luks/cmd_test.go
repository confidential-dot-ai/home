package luks

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

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
		namespace: "default",
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
		{"relative mount", func(c *createConfig) { c.mount = "data" }, "absolute"},
		{"bad output", func(c *createConfig) { c.output = "xml" }, "yaml or json"},
		{"bad driver", func(c *createConfig) { c.driver = "nfs" }, "local | pvc | csi"},
		{"bad namespace", func(c *createConfig) { c.namespace = "Bad_NS" }, "DNS-1123"},
		{"traversal workload", func(c *createConfig) { c.workload = "../etc" }, "DNS-1123"},
		{"flag-shaped name", func(c *createConfig) { c.name = "--all" }, "DNS-1123"},
		{"unknown fstype", func(c *createConfig) { c.fstype = "btrfs" }, "ext4 or xfs"},
		{"empty fstype", func(c *createConfig) { c.fstype = "" }, "ext4 or xfs"},
		{"fstype argv injection", func(c *createConfig) { c.fstype = "ext4 -E hack" }, "ext4 or xfs"},
		{"mount comma injection", func(c *createConfig) { c.mount = "/data,secret=evil#x" }, "must not contain"},
		{"mount equals", func(c *createConfig) { c.mount = "/data=x" }, "must not contain"},
		{"mount newline", func(c *createConfig) { c.mount = "/data\nmode=open" }, "must not contain"},
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
			w.WriteHeader(http.StatusNoContent)
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

	c := newBao(srv.URL, "root")
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

	err := newBao(srv.URL, "root").putPassphrase(context.Background(), "api", "data", []byte("s3cr3t"))
	if !errors.Is(err, errVolumeExists) {
		t.Fatalf("cas conflict: got %v, want errVolumeExists", err)
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
