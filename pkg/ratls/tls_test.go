package ratls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAttestFunc returns an AttestFunc that parses hex-encoded REPORTDATA
// from customData and wraps it in a fake SNP report. Suitable for tests
// that exercise TLS plumbing without real AMD hardware.
func fakeAttestFunc(_ context.Context, customData string) (string, error) {
	var rd [64]byte
	fmt.Sscanf(customData, "%x", &rd)
	return string(fakeSNPReport(rd)), nil
}

// testServerConfig returns a minimal ServerConfig for tests.
func testServerConfig() *ServerConfig {
	return &ServerConfig{
		Platform:   "sev-snp",
		DNSNames:   []string{"localhost"},
		CertTTL:    1 * time.Hour,
		AttestFunc: fakeAttestFunc,
	}
}

func TestNewServerTLSConfig(t *testing.T) {
	tlsCfg, _, err := NewServerTLSConfig(testServerConfig())
	if err != nil {
		t.Fatal(err)
	}

	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Error("expected TLS 1.3 minimum")
	}
	if tlsCfg.GetCertificate == nil {
		t.Fatal("GetCertificate is nil")
	}

	// Simulate a handshake to trigger cert provisioning.
	cert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	if cert == nil {
		t.Fatal("cert is nil")
	}
	if cert.PrivateKey == nil {
		t.Error("private key is nil")
	}
	if len(cert.Certificate) == 0 {
		t.Error("no certificate chain")
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	requireRATLSExtension(t, parsed)
}

func TestNewServerTLSConfigCaching(t *testing.T) {
	callCount := 0
	cfg := testServerConfig()
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		callCount++
		return fakeAttestFunc(ctx, customData)
	}

	tlsCfg, _, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// First call provisions.
	_, err = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 attestation call, got %d", callCount)
	}

	// Second call should use cache.
	_, err = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 attestation call (cached), got %d", callCount)
	}
}

func TestNewServerTLSConfigWithClientPolicy(t *testing.T) {
	cfg := testServerConfig()
	cfg.ClientPolicy = &VerifyPolicy{}

	tlsCfg, _, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if tlsCfg.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAnyClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("VerifyPeerCertificate should be set when ClientPolicy is provided")
	}
}

func TestNewServerTLSConfigWithoutClientPolicy(t *testing.T) {
	tlsCfg, _, err := NewServerTLSConfig(testServerConfig())
	if err != nil {
		t.Fatal(err)
	}

	if tlsCfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.VerifyPeerCertificate != nil {
		t.Error("VerifyPeerCertificate should be nil without ClientPolicy")
	}
}

func TestNewClientTLSConfig(t *testing.T) {
	tlsCfg, _, err := NewClientTLSConfig(&ClientConfig{Policy: &VerifyPolicy{}})
	if err != nil {
		t.Fatal(err)
	}

	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Error("expected TLS 1.3 minimum")
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true (trust from hardware attestation)")
	}
	if tlsCfg.VerifyPeerCertificate == nil {
		t.Error("VerifyPeerCertificate is nil")
	}
	if tlsCfg.GetClientCertificate != nil {
		t.Error("GetClientCertificate should be nil without mTLS fields")
	}
}

func TestNewClientTLSConfigWithAttestation(t *testing.T) {
	tlsCfg, _, err := NewClientTLSConfig(&ClientConfig{
		Platform:   "sev-snp",
		AttestFunc: fakeAttestFunc,
		CertTTL:    1 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if tlsCfg.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate is nil")
	}

	// Trigger client cert provisioning.
	cert, err := tlsCfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}

	if cert.PrivateKey == nil {
		t.Error("private key is nil")
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	requireRATLSExtension(t, parsed)
}

func TestNewClientTLSConfigInvalidMTLS(t *testing.T) {
	// Platform without AttestFunc.
	_, _, err := NewClientTLSConfig(&ClientConfig{Platform: "sev-snp"})
	if err == nil {
		t.Error("expected error for Platform without AttestFunc")
	}

	// AttestFunc without Platform.
	_, _, err = NewClientTLSConfig(&ClientConfig{AttestFunc: fakeAttestFunc})
	if err == nil {
		t.Error("expected error for AttestFunc without Platform")
	}
}

func TestEndToEnd(t *testing.T) {
	serverTLS, _, err := NewServerTLSConfig(testServerConfig())
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "attested")
	})
	go http.Serve(ln, mux)

	// Client skips PKI verification — in production, VerifyPeerCertificate
	// checks the RA-TLS extension. Here we just validate TLS plumbing.
	clientTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
	}

	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := string(body); got != "attested\n" {
		t.Errorf("body = %q, want %q", got, "attested\n")
	}

	// Verify the server cert has RA-TLS extension.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	requireRATLSExtension(t, conn.ConnectionState().PeerCertificates[0])
}

func TestMutualTLS(t *testing.T) {
	// Server presents RA-TLS cert and requires client RA-TLS cert.
	// We can't use VerifyPeerCertificate callbacks here because fake reports
	// lack valid AMD signatures. Instead we manually wire ClientAuth and
	// verify that both sides exchange certs with RA-TLS extensions.
	serverTLS, _, err := NewServerTLSConfig(testServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	serverTLS.ClientAuth = tls.RequireAnyClientCert

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Capture the client cert as seen by the server.
	var clientCert *x509.Certificate
	var mu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if len(r.TLS.PeerCertificates) > 0 {
			clientCert = r.TLS.PeerCertificates[0]
		}
		mu.Unlock()
		fmt.Fprintln(w, "mutual")
	})
	go http.Serve(ln, mux)

	// Client presents its own RA-TLS cert.
	clientProvider := &SelfSignedProvider{
		Platform:   "sev-snp",
		AttestFunc: fakeAttestFunc,
		Opts:       &CertOptions{TTL: 1 * time.Hour},
	}
	clientState := &certState{provider: clientProvider}
	clientTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientState.getOrProvision(info.Context())
		},
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
	}

	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Verify server cert has RA-TLS extension.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	requireRATLSExtension(t, conn.ConnectionState().PeerCertificates[0])

	// Verify client cert (as seen by server) has RA-TLS extension.
	mu.Lock()
	defer mu.Unlock()
	if clientCert == nil {
		t.Fatal("server did not receive client certificate")
	}
	requireRATLSExtension(t, clientCert)
}

func TestNewServerTLSConfigMissingPlatform(t *testing.T) {
	_, _, err := NewServerTLSConfig(&ServerConfig{
		AttestFunc: func(context.Context, string) (string, error) { return "", nil },
	})
	if err == nil {
		t.Error("expected error for missing platform")
	}
}

func TestNewServerTLSConfigMissingAttestFunc(t *testing.T) {
	_, _, err := NewServerTLSConfig(&ServerConfig{
		Platform: "sev-snp",
	})
	if err == nil {
		t.Error("expected error for missing AttestFunc")
	}
}

func TestTDXPlatformAcceptedAtConfigTime(t *testing.T) {
	// TDX is a supported platform end-to-end. Server + client configs must
	// build. Verification of a real TDX quote (VerifyAttestation) is
	// handled at handshake time; config-time is only the platform
	// allowlist gate.
	if _, _, err := NewServerTLSConfig(&ServerConfig{
		Platform:   "tdx",
		AttestFunc: fakeAttestFunc,
	}); err != nil {
		t.Errorf("expected TDX server config to build, got: %v", err)
	}
	if _, _, err := NewClientTLSConfig(&ClientConfig{
		Platform:   "tdx",
		AttestFunc: fakeAttestFunc,
	}); err != nil {
		t.Errorf("expected TDX client config to build, got: %v", err)
	}
}

func TestParseTEEType(t *testing.T) {
	tests := []struct {
		input string
		want  TEEType
		err   bool
	}{
		{"sev-snp", TEETypeSEVSNP, false},
		{"tdx", TEETypeTDX, false},
		{"unknown", 0, true},
	}
	for _, tt := range tests {
		got, err := parseTEEType(tt.input)
		if (err != nil) != tt.err {
			t.Errorf("parseTEEType(%q) error = %v, wantErr %v", tt.input, err, tt.err)
		}
		if got != tt.want {
			t.Errorf("parseTEEType(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestConcurrentCertProvisioning(t *testing.T) {
	var callCount atomic.Int32
	cfg := testServerConfig()
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		callCount.Add(1)
		return fakeAttestFunc(ctx, customData)
	}

	tlsCfg, _, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 10
	certs := make([]*tls.Certificate, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			certs[idx], errs[idx] = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
		}(i)
	}
	wg.Wait()

	// All must succeed.
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}

	// All must get the same cert (pointer equality).
	for i := 1; i < goroutines; i++ {
		if certs[i] != certs[0] {
			t.Errorf("goroutine %d got different cert pointer", i)
		}
	}

	// AttestFunc should be called exactly once.
	if got := callCount.Load(); got != 1 {
		t.Errorf("AttestFunc called %d times, want 1", got)
	}
}

func TestCertRotationTiming(t *testing.T) {
	var callCount atomic.Int32
	cfg := testServerConfig()
	cfg.CertTTL = 100 * time.Millisecond
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		callCount.Add(1)
		return fakeAttestFunc(ctx, customData)
	}

	tlsCfg, _, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// First call provisions synchronously.
	cert1, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if callCount.Load() != 1 {
		t.Fatalf("expected 1 attestation call, got %d", callCount.Load())
	}

	// Wait past rotation window (50% of 100ms = 50ms).
	time.Sleep(60 * time.Millisecond)

	// This call triggers background rotation but returns the OLD cert.
	certOld, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if certOld != cert1 {
		t.Error("expected old cert returned during background rotation")
	}

	// Poll until the rotated cert is served. callCount bumps when the
	// background attestation *starts*, but the new cert is stored only after
	// Provision returns, so waiting on the counter races the store. Poll the
	// observable outcome instead — the cert actually changing.
	deadline := time.After(2 * time.Second)
	for {
		cert2, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		if cert2 != cert1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for background rotation to serve the new cert")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestBackgroundRotationNonBlocking(t *testing.T) {
	var callCount atomic.Int32
	cfg := testServerConfig()
	cfg.CertTTL = 100 * time.Millisecond
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		n := callCount.Add(1)
		if n > 1 {
			// Slow rotation to prove callers aren't blocked.
			time.Sleep(200 * time.Millisecond)
		}
		return fakeAttestFunc(ctx, customData)
	}

	tlsCfg, _, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// First call: fast, synchronous provisioning.
	_, err = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}

	// Wait past rotation window.
	time.Sleep(60 * time.Millisecond)

	// Trigger background rotation (slow: 200ms).
	_, _ = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})

	// Concurrent calls must all return immediately (not blocked by 200ms rotation).
	const goroutines = 10
	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	// All calls should complete well under 200ms (the rotation time).
	if elapsed > 100*time.Millisecond {
		t.Errorf("concurrent GetCertificate took %v, expected <100ms (non-blocking)", elapsed)
	}
}

func TestCertManagerWarmUp(t *testing.T) {
	var callCount atomic.Int32
	cfg := testServerConfig()
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		callCount.Add(1)
		return fakeAttestFunc(ctx, customData)
	}

	_, mgr, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Before warm-up: not ready.
	if mgr.CertReady() {
		t.Error("CertReady should be false before WarmUp")
	}

	// Warm up.
	if err := mgr.WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}

	// After warm-up: ready.
	if !mgr.CertReady() {
		t.Error("CertReady should be true after WarmUp")
	}

	// AttestFunc should have been called exactly once.
	if got := callCount.Load(); got != 1 {
		t.Errorf("AttestFunc called %d times, want 1", got)
	}
}

func TestCertManagerRotationFailCallback(t *testing.T) {
	var failCount atomic.Int32
	var callCount atomic.Int32
	cfg := testServerConfig()
	cfg.CertTTL = 100 * time.Millisecond
	cfg.AttestFunc = func(ctx context.Context, customData string) (string, error) {
		n := callCount.Add(1)
		if n > 1 {
			return "", fmt.Errorf("simulated failure")
		}
		return fakeAttestFunc(ctx, customData)
	}

	_, mgr, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetOnRotationFail(func() { failCount.Add(1) })

	// Warm up successfully.
	if err := mgr.WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Wait past rotation window (50% of 100ms = 50ms).
	time.Sleep(60 * time.Millisecond)

	// Trigger background rotation (which will fail).
	state := mgr.state
	if state.rotating.CompareAndSwap(false, true) {
		state.backgroundProvision(state.provider)
	}

	// The failure callback should have been called.
	if got := failCount.Load(); got != 1 {
		t.Errorf("rotation failure callback called %d times, want 1", got)
	}
}

// --- Helpers for dual-verify and swap-provider tests ---

type mockProvider struct {
	cert *tls.Certificate
	ttl  time.Duration
}

func (m *mockProvider) Provision(_ context.Context) (*tls.Certificate, time.Duration, error) {
	return m.cert, m.ttl, nil
}

func generateSimpleCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func generateCACert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}
	return caKey, caCert
}

func TestDualVerifyPeerCallback_CASigned(t *testing.T) {
	// Generate a CA keypair and self-signed CA cert.
	caKey, caCert := generateCACert(t)

	// Generate a leaf keypair and cert signed by the CA.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Get the dual-verify callback.
	verifyFunc := dualVerifyPeerCallback(&VerifyPolicy{}, newSharedCACerts([]*x509.Certificate{caCert}))

	// CA-signed cert should be accepted.
	if err := verifyFunc([][]byte{leafCertDER}, nil); err != nil {
		t.Fatalf("expected CA-signed cert to be accepted, got: %v", err)
	}
}

func TestDualVerifyPeerCallback_RATLSSelfSigned(t *testing.T) {
	// The RA-TLS fallback path: a self-signed attested cert fails CA-chain
	// verification, so the callback falls back to attestation verification,
	// which is delegated to a (mocked) attestation-api.
	_, _, ratlsCert := testAttestedCert(t, &CertOptions{TTL: 1 * time.Hour})

	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
	srv := newMockedVerifySrv(t, verifyResponse(measurement))
	defer srv.Close()

	_, caCert := generateCACert(t)
	verifyFunc := dualVerifyPeerCallback(
		&VerifyPolicy{AttestationApiURL: srv.URL, Measurements: [][]byte{measurement}},
		newSharedCACerts([]*x509.Certificate{caCert}),
	)

	if err := verifyFunc([][]byte{ratlsCert.Raw}, nil); err != nil {
		t.Fatalf("RA-TLS fallback failed: %v", err)
	}
}

func TestDualVerifyPeerCallback_BothFail(t *testing.T) {
	// Generate a random self-signed leaf cert (no CA chain, no RA-TLS extension).
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(300),
		Subject:      pkix.Name{CommonName: "random-leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &leafKey.PublicKey, leafKey)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a CA cert.
	_, caCert := generateCACert(t)

	// Get the dual-verify callback.
	verifyFunc := dualVerifyPeerCallback(&VerifyPolicy{}, newSharedCACerts([]*x509.Certificate{caCert}))

	// Random cert should fail both verification paths.
	err = verifyFunc([][]byte{leafCertDER}, nil)
	if err == nil {
		t.Fatal("expected error when both CA chain and RA-TLS verification fail")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "CA chain") {
		t.Errorf("error should mention 'CA chain', got: %v", errMsg)
	}
	if !strings.Contains(errMsg, "RA-TLS") {
		t.Errorf("error should mention 'RA-TLS', got: %v", errMsg)
	}
}

func TestDualVerifyPeerCallback_CASignedEnforcesClaimPins(t *testing.T) {
	caKey, caCert := generateCACert(t)
	shared := newSharedCACerts([]*x509.Certificate{caCert})

	// makeLeaf builds a CA-signed leaf, optionally carrying a config-claims
	// extension (nil = none).
	makeLeaf := func(t *testing.T, ext []byte) []byte {
		t.Helper()
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(400),
			Subject:      pkix.Name{CommonName: "workload"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		if ext != nil {
			tmpl.ExtraExtensions = []pkix.Extension{{Id: OIDRATLSConfigClaims, Value: ext}}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	claimsExt := func(t *testing.T, operatorKeys []byte) []byte {
		t.Helper()
		c := &ConfigClaims{
			OperatorKeysDigest: operatorKeys,
			SeedDigest:         UnsetDigest(),
			WorkloadDigest:     UnsetDigest(),
		}
		ext, err := c.MarshalExtension()
		if err != nil {
			t.Fatal(err)
		}
		return ext.Value
	}

	pinned := bytes.Repeat([]byte{0x11}, ClaimsDigestSize)
	verify := dualVerifyPeerCallback(&VerifyPolicy{OperatorKeysDigest: pinned}, shared)

	t.Run("missing claims rejected", func(t *testing.T) {
		if err := verify([][]byte{makeLeaf(t, nil)}, nil); err == nil {
			t.Fatal("CA-signed leaf without config-claims accepted despite a configured pin")
		}
	})
	t.Run("mismatched claims rejected", func(t *testing.T) {
		wrong := bytes.Repeat([]byte{0x22}, ClaimsDigestSize)
		if err := verify([][]byte{makeLeaf(t, claimsExt(t, wrong))}, nil); err == nil {
			t.Fatal("CA-signed leaf with mismatched operator-keys digest accepted")
		}
	})
	t.Run("matching claims accepted", func(t *testing.T) {
		if err := verify([][]byte{makeLeaf(t, claimsExt(t, pinned))}, nil); err != nil {
			t.Fatalf("CA-signed leaf with matching pin rejected: %v", err)
		}
	})
	t.Run("no pin accepts CA-signed", func(t *testing.T) {
		v := dualVerifyPeerCallback(&VerifyPolicy{}, shared)
		if err := v([][]byte{makeLeaf(t, nil)}, nil); err != nil {
			t.Fatalf("CA-signed leaf rejected when no pin configured: %v", err)
		}
	})
}

// TestDualVerifyPeerCallback_RequireCAEvidence covers the production trust mode:
// a valid CA chain is no longer sufficient — the leaf's embedded RA-TLS evidence
// (issuer copies the requester's nonce-free .1.1 extension onto the leaf) is
// re-verified per connection, catching a CA compromise or wrong issuance policy.
func TestDualVerifyPeerCallback_RequireCAEvidence(t *testing.T) {
	caKey, caCert := generateCACert(t)
	shared := newSharedCACerts([]*x509.Certificate{caCert})
	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
	srv := newMockedVerifySrv(t, verifyResponse(measurement))
	defer srv.Close()

	// caSignedLeaf builds a CA-signed leaf over key, optionally carrying the
	// RA-TLS .1.1 evidence extension.
	caSignedLeaf := func(t *testing.T, key *ecdsa.PrivateKey, ratlsExt *pkix.Extension) []byte {
		t.Helper()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(500),
			Subject:      pkix.Name{CommonName: "workload"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		if ratlsExt != nil {
			tmpl.ExtraExtensions = []pkix.Extension{*ratlsExt}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	freshKey := func(t *testing.T) *ecdsa.PrivateKey {
		t.Helper()
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}

	// A CA-signed leaf carrying evidence bound to its own key (the shape the
	// issuer produces by copying the requester's .1.1 extension).
	key, att := testKeyAndAttestation(t)
	ext, err := att.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	leafWithEvidence := caSignedLeaf(t, key, &ext)

	t.Run("accepts CA leaf with re-verifiable evidence", func(t *testing.T) {
		policy := &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: [][]byte{measurement}, RequireCAEvidence: true}
		if err := dualVerifyPeerCallback(policy, shared)([][]byte{leafWithEvidence}, nil); err != nil {
			t.Fatalf("valid CA leaf with embedded evidence rejected: %v", err)
		}
	})

	t.Run("rejects CA leaf without embedded evidence", func(t *testing.T) {
		policy := &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: [][]byte{measurement}, RequireCAEvidence: true}
		if err := dualVerifyPeerCallback(policy, shared)([][]byte{caSignedLeaf(t, freshKey(t), nil)}, nil); err == nil {
			t.Fatal("CA leaf without embedded evidence accepted in production mode")
		}
	})

	t.Run("rejects CA leaf whose measurement is not pinned", func(t *testing.T) {
		other := bytes.Repeat([]byte{0x99}, SNPMeasurementSize)
		policy := &VerifyPolicy{AttestationApiURL: srv.URL, Measurements: [][]byte{other}, RequireCAEvidence: true}
		if err := dualVerifyPeerCallback(policy, shared)([][]byte{leafWithEvidence}, nil); err == nil {
			t.Fatal("CA leaf with an unpinned launch measurement accepted in production mode")
		}
	})

	t.Run("legacy mode still accepts CA leaf without evidence", func(t *testing.T) {
		policy := &VerifyPolicy{AttestationApiURL: srv.URL} // RequireCAEvidence: false
		if err := dualVerifyPeerCallback(policy, shared)([][]byte{caSignedLeaf(t, freshKey(t), nil)}, nil); err != nil {
			t.Fatalf("legacy CA-only mode rejected a CA-signed leaf: %v", err)
		}
	})
}

func TestSwapProvider(t *testing.T) {
	// Create a server TLS config with fakeAttestFunc.
	cfg := testServerConfig()
	tlsCfg, certMgr, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Warm up to provision the first cert.
	if err := certMgr.WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Get the original cert.
	origCert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}

	// Create a mock provider with a different cert.
	newCert := generateSimpleCert(t)
	mock := &mockProvider{cert: newCert, ttl: 1 * time.Hour}

	// Swap the provider.
	if err := certMgr.SwapProvider(context.Background(), mock); err != nil {
		t.Fatal(err)
	}

	// Get cert from GetCertificate — should be the new one.
	gotCert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if gotCert == origCert {
		t.Error("expected different cert after SwapProvider")
	}
	if gotCert != newCert {
		t.Error("expected GetCertificate to return the mock provider's cert")
	}

	// CertReady should be true.
	if !certMgr.CertReady() {
		t.Error("CertReady should be true after SwapProvider")
	}
}

func TestSwapProvider_ConcurrentAccess(t *testing.T) {
	// Create a server TLS config with fakeAttestFunc.
	cfg := testServerConfig()
	tlsCfg, certMgr, err := NewServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Warm up to provision the first cert.
	if err := certMgr.WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Prepare the new cert for the swap.
	newCert := generateSimpleCert(t)
	mock := &mockProvider{cert: newCert, ttl: 1 * time.Hour}

	const goroutines = 10
	const iterations = 100
	errs := make([]error, goroutines)
	var wg sync.WaitGroup

	// Start goroutines that continuously call GetCertificate.
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
				if err != nil {
					errs[idx] = err
					return
				}
			}
		}(i)
	}

	// In the main goroutine, swap the provider while readers are active.
	if err := certMgr.SwapProvider(context.Background(), mock); err != nil {
		t.Fatalf("SwapProvider failed: %v", err)
	}

	wg.Wait()

	// No goroutine should have encountered an error.
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	// Eventually GetCertificate should return the new cert.
	gotCert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if gotCert != newCert {
		t.Error("expected GetCertificate to return the new cert after SwapProvider")
	}
}
