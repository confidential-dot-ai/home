package cdsattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// writeClientKeyPair writes a self-signed client cert + key PEM pair.
func writeClientKeyPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "c8s-tls-lb-client"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestNewHTTPBackendErrors(t *testing.T) {
	dir := t.TempDir()
	garbageCA := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbageCA, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		base    string
		opts    HTTPBackendOptions
		wantSub string
	}{
		{"bad scheme", "ftp://backend", HTTPBackendOptions{}, "must be an http:// or https:// URL"},
		{"missing CA file", "https://backend", HTTPBackendOptions{TrustedCAFile: filepath.Join(dir, "missing-ca.pem")}, "read upstream CA"},
		{"CA file with no certs", "https://backend", HTTPBackendOptions{TrustedCAFile: garbageCA}, "has no certificates"},
		{"missing client keypair", "https://backend", HTTPBackendOptions{
			ClientCertFile: filepath.Join(dir, "missing.pem"),
			ClientKeyFile:  filepath.Join(dir, "missing.key"),
		}, "load upstream client cert"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHTTPBackend(tc.base, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("NewHTTPBackend() error = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestHTTPBackendHTTPSWithMTLSMaterial(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secure hello "+r.Method+" "+r.URL.Path)
	}))
	defer backend.Close()

	// Trust the httptest server's own certificate as the "mesh CA".
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeClientKeyPair(t)

	hb, err := NewHTTPBackend(backend.URL+"/", HTTPBackendOptions{
		TrustedCAFile:  caPath,
		ClientCertFile: certPath,
		ClientKeyFile:  keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Empty method defaults to GET; a path without a leading slash gets one.
	resp, err := hb.Forward(context.Background(), types.TunnelRequest{Path: "v1/models"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusOK || string(resp.Body) != "secure hello GET /v1/models" {
		t.Fatalf("unexpected response: %d %q", resp.Status, resp.Body)
	}
}

func TestHTTPBackendStripsHopByHopHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-C8s-Session"); got != "" {
			t.Errorf("session header leaked upstream: %q", got)
		}
		if got := r.Header.Get("X-App"); got != "kept" {
			t.Errorf("app header not forwarded: %q", got)
		}
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-Resp", "kept")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	hb, err := NewHTTPBackend(backend.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hb.Forward(context.Background(), types.TunnelRequest{
		Method:  "GET",
		Path:    "/",
		Headers: map[string]string{"X-C8s-Session": "sess-id", "X-App": "kept"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := resp.Headers["Keep-Alive"]; ok {
		t.Error("hop-by-hop response header not stripped")
	}
	if resp.Headers["X-Resp"] != "kept" {
		t.Errorf("response header lost: %+v", resp.Headers)
	}
}

func TestHTTPBackendForwardErrors(t *testing.T) {
	// Point at a closed listener so client.Do fails.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	hb, err := NewHTTPBackend(deadURL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hb.Forward(context.Background(), types.TunnelRequest{Method: "GET", Path: "/"}); err == nil ||
		!strings.Contains(err.Error(), "forward to upstream") {
		t.Fatalf("expected forward error, got %v", err)
	}

	// An invalid method makes request construction itself fail.
	if _, err := hb.Forward(context.Background(), types.TunnelRequest{Method: "BAD METHOD", Path: "/"}); err == nil ||
		!strings.Contains(err.Error(), "build upstream request") {
		t.Fatalf("expected build error, got %v", err)
	}
}
