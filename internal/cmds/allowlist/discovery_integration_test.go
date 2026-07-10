package allowlist

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internalallowlist "github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/lbdiscovery"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// tlsLBServer stands in for the tls-lb front door: a TLS server whose serving
// cert carries NO RA-TLS extension, serving its discovery document plus the
// CDS allowlist read handler it proxies.
func tlsLBServer(t *testing.T, measurementChallenge []byte) *httptest.Server {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tls-lb"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	store, err := internalallowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	digest, err := types.ParseDigest(digA)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(digest, "registry/c8s/cds@"+digA); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	h := internalallowlist.Handler{Store: &store}

	doc, err := json.Marshal(types.DiscoveryDocument{
		Version: "1",
		CDSTLS: types.CDSTLSDiscovery{
			CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		},
		Attestation: types.AttestationDiscovery{
			Challenge: base64.StdEncoding.EncodeToString(measurementChallenge),
			Platform:  string(types.PlatformAzSnp),
			Evidence:  json.RawMessage(`{"hcl_report":"fake"}`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+lbdiscovery.DefaultPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(doc)
	})
	mux.HandleFunc("GET /allowlist", h.HandleList)

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(func() {
		srv.Close()
		store.Close()
	})
	return srv
}

// attestationAPIServer fakes the attestation-api /verify endpoint, approving
// with the given launch measurement.
func attestationAPIServer(t *testing.T, measurement []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{
				"platform":          string(types.PlatformAzSnp),
				"signature_valid":   true,
				"report_data_match": true,
				"claims":            map[string]any{"launch_digest": hex.EncodeToString(measurement)},
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestListThroughTLSLB is the regression test for `c8s allowlist list` against
// a tls-lb front door: the serving cert has no RA-TLS extension (OID
// 1.3.6.1.4.1.59888.1.1), so the CLI must verify the LB's discovery document
// instead of failing the handshake, then read the allowlist over the pinned
// cert.
func TestListThroughTLSLB(t *testing.T) {
	measurement := bytes.Repeat([]byte{0x42}, ratls.SNPMeasurementSize)
	lb := tlsLBServer(t, []byte("issuance-challenge"))
	api := attestationAPIServer(t, measurement)

	out, errOut, err := runCmd("list",
		"--url", lb.URL,
		"--measurements", hex.EncodeToString(measurement),
		"--attestation-api-url", api.URL,
	)
	if err != nil {
		t.Fatalf("list through tls-lb failed: %v (stderr: %s)", err, errOut)
	}
	if !strings.Contains(out, digA) {
		t.Fatalf("output missing seeded digest %s:\n%s", digA, out)
	}
}

// TestListThroughTLSLBFailsClosed proves a front door whose discovery evidence
// does not verify is rejected outright — no fallback, no allowlist read.
func TestListThroughTLSLBFailsClosed(t *testing.T) {
	pinned := bytes.Repeat([]byte{0x42}, ratls.SNPMeasurementSize)
	reported := bytes.Repeat([]byte{0x01}, ratls.SNPMeasurementSize)
	lb := tlsLBServer(t, []byte("issuance-challenge"))
	api := attestationAPIServer(t, reported)

	_, _, err := runCmd("list",
		"--url", lb.URL,
		"--measurements", hex.EncodeToString(pinned),
		"--attestation-api-url", api.URL,
	)
	if err == nil {
		t.Fatal("expected a measurement mismatch to fail the command")
	}
	if !strings.Contains(err.Error(), "discovery document verification failed") {
		t.Fatalf("want a discovery verification error, got: %v", err)
	}
}
