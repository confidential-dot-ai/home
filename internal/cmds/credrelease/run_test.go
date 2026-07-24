package credrelease

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// stageMeasuredOperatorKey writes pubPEM to the (test-overridden) staging path
// and a matching fake RTMR[3], as the measured initrd would have.
func stageMeasuredOperatorKey(t *testing.T, pubPEM []byte) {
	t.Helper()
	pubPath, rtmrPath := overrideBindingPaths(t)
	writeFileT(t, pubPath, pubPEM)
	writeFileT(t, rtmrPath, expectedRTMR3ForKey(pubPEM))
}

// freshOperatorPubPEM generates a fresh ECDSA keypair and returns the PKIX
// public-key PEM the initrd would stage.
func freshOperatorPubPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// fakeAttestationAPI is a stand-in for the local attestation-api: POST /attest
// returns a syntactically valid TDX evidence envelope (no real quote — the
// RA-TLS serving cert only embeds it, nothing verifies it in these tests).
func fakeAttestationAPI(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.AttestResponse{
			Platform: string(types.PlatformTdx),
			Evidence: json.RawMessage(`{"quote":"ZmFrZS1xdW90ZQ=="}`),
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runnableConfig stages a measured operator key, on-disk CAs, and a fake
// attestation-api, returning a Config Run can fully start from.
func runnableConfig(t *testing.T) Config {
	t.Helper()
	stageMeasuredOperatorKey(t, freshOperatorPubPEM(t))
	dir := t.TempDir()
	clientCert, clientKey, _ := namedCA(t, dir, "client-ca")
	serverCert, _, _ := namedCA(t, dir, "server-ca")
	return Config{
		ListenAddr:        "127.0.0.1:0",
		AttestationAPIURL: fakeAttestationAPI(t).URL,
		Platform:          "tdx",
		ClientCACert:      clientCert,
		ClientCAKey:       clientKey,
		ServerCACert:      serverCert,
		CertTTL:           time.Hour,
		CertOrg:           "system:masters",
		CertCN:            "operator",
	}
}

// TestRunStartupErrors walks Run's fail-closed startup ladder: missing
// platform, unmeasured key, unreadable CA, non-ECDSA key, and a dead
// attestation-api at warm-up.
func TestRunStartupErrors(t *testing.T) {
	tests := []struct {
		name    string
		cfg     func(t *testing.T) Config
		wantErr string
	}{
		{
			name: "platform required",
			cfg: func(t *testing.T) Config {
				return Config{Platform: ""}
			},
			wantErr: "--platform is required",
		},
		{
			name: "operator key not staged",
			cfg: func(t *testing.T) Config {
				overrideBindingPaths(t) // paths exist, files do not
				return Config{Platform: "tdx"}
			},
			wantErr: "load measured operator key",
		},
		{
			name: "cluster CA unreadable",
			cfg: func(t *testing.T) Config {
				stageMeasuredOperatorKey(t, freshOperatorPubPEM(t))
				missing := filepath.Join(t.TempDir(), "missing")
				return Config{Platform: "tdx", ClientCACert: missing, ClientCAKey: missing, ServerCACert: missing}
			},
			wantErr: "load cluster CA",
		},
		{
			name: "measured key is not an ECDSA PKIX PEM",
			cfg: func(t *testing.T) Config {
				cfg := runnableConfig(t)
				// Measured (RTMR matches) but unusable for operatorauth.
				stageMeasuredOperatorKey(t, []byte("measured but not a key"))
				return cfg
			},
			wantErr: "build handler",
		},
		{
			name: "attestation-api down at warm-up",
			cfg: func(t *testing.T) Config {
				cfg := runnableConfig(t)
				cfg.AttestationAPIURL = "http://127.0.0.1:1" // nothing listens
				return cfg
			},
			wantErr: "warm up RA-TLS serving cert",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Run(context.Background(), tc.cfg(t))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestRunServesAndShutsDown starts the full service (fake attestation-api,
// temp CAs, measured key), waits for it to accept connections, then cancels
// the context and expects a clean shutdown.
func TestRunServesAndShutsDown(t *testing.T) {
	cfg := runnableConfig(t)
	// Reserve a port so the test knows where to probe.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ListenAddr = ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", cfg.ListenAddr, time.Second)
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Run exited before serving: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("server never started accepting connections")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run after cancel = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// TestRunReturnsListenError: with the port already taken, the serve goroutine
// fails and Run surfaces the bind error (the errCh select arm).
func TestRunReturnsListenError(t *testing.T) {
	cfg := runnableConfig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg.ListenAddr = ln.Addr().String() // already bound

	err = Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("err = %v, want address already in use", err)
	}
}
