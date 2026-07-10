package luks

import (
	"context"
	"encoding/hex"
	"encoding/json"
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
		workload: "api", name: "data", mount: "/data",
		output: "yaml", size: resource.MustParse("1Gi"),
	}
	if err := validateCreate(base); err != nil {
		t.Errorf("baseline should be valid: %v", err)
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
