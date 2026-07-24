package cds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeOperatorKeysPEM writes a PEM bundle with one EC public key and returns
// its path.
func writeOperatorKeysPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen operator key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal operator key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "operator-keys.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write operator keys: %v", err)
	}
	return path
}

// newHealthyAttestationApi returns an httptest server that answers every path
// with a healthy JSON response, enough for readiness checks during run().
func newHealthyAttestationApi(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// validRunConfig returns a config that passes run()'s validation with RA-TLS
// disabled, an in-tempdir allowlist DB, and hermetic endpoints.
func validRunConfig(t *testing.T, attestationURL string) config {
	t.Helper()
	return config{
		host:                     "127.0.0.1",
		port:                     0,
		logLevel:                 "error",
		attestationApiURL:        attestationURL,
		caCommonName:             "test ca",
		caCertValidity:           24 * time.Hour,
		earIssuerName:            "cds",
		jwtClockSkew:             30,
		maxTTL:                   time.Hour,
		certTTL:                  time.Hour,
		challengeTTL:             time.Minute,
		requestTimeout:           time.Second,
		maxRequestSize:           65536,
		readinessInterval:        50 * time.Millisecond,
		minCAValidity:            time.Hour,
		allowlistDB:              filepath.Join(t.TempDir(), "allowlist.db"),
		rateLimit:                1000,
		rateBurst:                1000,
		rateLimiterMax:           1000,
		rateLimiterEvictInterval: time.Minute,
		rateLimiterIdleTimeout:   5 * time.Minute,
		handoffPeerTimeout:       2 * time.Minute,
		ratlsPlatform:            "",
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func TestRun_ErrorPaths(t *testing.T) {
	api := newHealthyAttestationApi(t)
	opKeys := writeOperatorKeysPEM(t)

	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, cfg *config)
		wantSub string
	}{
		{
			name:    "bad log level",
			mutate:  func(_ *testing.T, cfg *config) { cfg.logLevel = "bogus" },
			wantSub: "--log-level",
		},
		{
			name:    "bad attestation api url",
			mutate:  func(_ *testing.T, cfg *config) { cfg.attestationApiURL = "not a url" },
			wantSub: "--attestation-api-url",
		},
		{
			name:    "invalid config",
			mutate:  func(_ *testing.T, cfg *config) { cfg.maxTTL = 0 },
			wantSub: "--max-ttl",
		},
		{
			name:    "rate limiter max entries",
			mutate:  func(_ *testing.T, cfg *config) { cfg.rateLimiterMax = 0 },
			wantSub: "rate limiter",
		},
		{
			name: "operator keys file missing",
			mutate: func(t *testing.T, cfg *config) {
				cfg.operatorKeys = filepath.Join(t.TempDir(), "missing.pem")
			},
			wantSub: "--operator-keys",
		},
		{
			name: "operator keys file has no EC key",
			mutate: func(t *testing.T, cfg *config) {
				path := filepath.Join(t.TempDir(), "bad.pem")
				if err := os.WriteFile(path, []byte("not pem at all"), 0o600); err != nil {
					t.Fatalf("write bad operator keys: %v", err)
				}
				cfg.operatorKeys = path
			},
			wantSub: "--operator-keys",
		},
		{
			name: "allowlist db unopenable",
			mutate: func(t *testing.T, cfg *config) {
				cfg.allowlistDB = filepath.Join(t.TempDir(), "no-such-dir", "allowlist.db")
			},
			wantSub: "allowlist database",
		},
		{
			name: "handoff peer unreachable fails closed",
			mutate: func(_ *testing.T, cfg *config) {
				cfg.operatorKeys = opKeys
				cfg.handoffMeasurements = []string{"deadbeef"}
				cfg.handoffPeerURL = "https://127.0.0.1:1"
				cfg.handoffPeerTimeout = 100 * time.Millisecond
			},
			wantSub: "provision mesh CA",
		},
		{
			name:    "invalid dns san pattern",
			mutate:  func(_ *testing.T, cfg *config) { cfg.dnsSANPatterns = []string{"("} },
			wantSub: "--dns-san-pattern",
		},
		{
			name:    "invalid cn pattern",
			mutate:  func(_ *testing.T, cfg *config) { cfg.allowedCNPattern = "(" },
			wantSub: "--allowed-cn-pattern",
		},
		{
			name: "seed file missing fails closed",
			mutate: func(t *testing.T, cfg *config) {
				cfg.allowlistSeed = filepath.Join(t.TempDir(), "missing-seed.json")
			},
			wantSub: "seed allowlist",
		},
		{
			name:    "unsupported ratls platform",
			mutate:  func(_ *testing.T, cfg *config) { cfg.ratlsPlatform = "bogus-platform" },
			wantSub: "ratls server config",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validRunConfig(t, api.URL)
			tc.mutate(t, &cfg)
			err := run(cfg)
			if err == nil {
				t.Fatalf("run() succeeded, want error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("run() error = %q, want it to contain %q", err, tc.wantSub)
			}
		})
	}
}

// Full plain-HTTP startup: operator keys, measurements, seed, handoff, and key
// rotation all enabled. run() must serve /healthz and exit cleanly on SIGTERM.
func TestRun_ServesAndShutsDownOnSIGTERM(t *testing.T) {
	api := newHealthyAttestationApi(t)

	seedPath := filepath.Join(t.TempDir(), "seed.json")
	seedJSON := `{"schema":"c8s.allowlist/v1","digests":{"` + digestA + `":"ghcr.io/x/cds:v1"}}`
	if err := os.WriteFile(seedPath, []byte(seedJSON), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	cfg := validRunConfig(t, api.URL)
	cfg.port = freePort(t)
	cfg.measurements = []string{"deadbeef"}
	cfg.dnsSANPatterns = []string{`^[a-z.-]+$`}
	cfg.allowedCNPattern = `^.*$`
	cfg.operatorKeys = writeOperatorKeysPEM(t)
	cfg.allowlistSeed = seedPath
	cfg.handoffMeasurements = []string{"deadbeef"}
	cfg.rotationInterval = time.Hour
	cfg.rotationOverlap = time.Minute
	cfg.sanValidation = true

	errCh := make(chan error, 1)
	go func() { errCh <- run(cfg) }()

	base := fmt.Sprintf("http://127.0.0.1:%d", cfg.port)
	deadline := time.Now().Add(15 * time.Second)
	up := false
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("run() exited early: %v", err)
		default:
		}
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				up = true
			}
		}
		if up {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !up {
		t.Fatal("cds never became healthy")
	}

	// The seeded allowlist must be served before shutdown.
	resp, err := http.Get(base + "/allowlist")
	if err != nil {
		t.Fatalf("GET /allowlist: %v", err)
	}
	body := resp.Body
	var listing struct {
		Digests map[string]string `json:"digests"`
	}
	decodeErr := json.NewDecoder(body).Decode(&listing)
	_ = body.Close()
	if decodeErr != nil {
		t.Fatalf("decode /allowlist: %v", decodeErr)
	}
	if _, ok := listing.Digests[digestA]; !ok {
		t.Errorf("seeded digest missing from /allowlist: %v", listing.Digests)
	}

	// Operator keys are pinned, so /operator-keys must serve the bundle.
	resp, err = http.Get(base + "/operator-keys")
	if err != nil {
		t.Fatalf("GET /operator-keys: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /operator-keys = %d, want 200", resp.StatusCode)
	}

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run() returned error on shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not shut down after SIGTERM")
	}
}

func TestLoadOperatorKeys(t *testing.T) {
	t.Run("valid bundle", func(t *testing.T) {
		path := writeOperatorKeysPEM(t)
		keys, pemBytes, err := loadOperatorKeys(path)
		if err != nil {
			t.Fatalf("loadOperatorKeys: %v", err)
		}
		if len(keys) != 1 {
			t.Errorf("keys = %d, want 1", len(keys))
		}
		if len(pemBytes) == 0 {
			t.Error("raw PEM bytes empty")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, _, err := loadOperatorKeys(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("no EC key fails closed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.pem")
		if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, _, err := loadOperatorKeys(path); err == nil {
			t.Fatal("expected error for bundle without EC public key")
		}
	})
}

// The cobra RunE closure must propagate run()'s error.
func TestNewCmd_RunEPropagatesRunError(t *testing.T) {
	cmd := NewCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{
		"--attestation-api-url", "http://127.0.0.1:9",
		"--allowlist-db", filepath.Join(t.TempDir(), "allowlist.db"),
		"--log-level", "bogus",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() succeeded, want --log-level error")
	}
	if !strings.Contains(err.Error(), "--log-level") {
		t.Fatalf("error = %q, want it to mention --log-level", err)
	}
}
