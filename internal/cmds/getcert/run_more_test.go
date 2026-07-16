package getcert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// plaintextCDSClient builds an attestclient over the default transport for
// tests that drive the cert flow against a plaintext httptest CDS. Production
// requires https (see cdsHTTPClient), so these tests inject the client
// directly rather than route through newCDSClient.
func plaintextCDSClient(cdsURL string) attestclient.Client {
	return attestclient.NewClientWithHTTP(cdsURL, http.DefaultClient)
}

func TestNewCmdFlagDefaultsAndRequired(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "get-cert" {
		t.Fatalf("Use = %q, want get-cert", cmd.Use)
	}

	flags := cmd.Flags()
	for _, name := range []string{"cds-url", "attestation-api-url", "san"} {
		flag := flags.Lookup(name)
		if flag == nil {
			t.Fatalf("flag %q not registered", name)
		}
		if _, ok := flag.Annotations[`cobra_annotation_bash_completion_one_required_flag`]; !ok {
			t.Errorf("flag %q not marked required", name)
		}
	}

	tests := []struct {
		name string
		want string
	}{
		{"key-mode", "0600"},
		{"discovery-public-tls-mode", "cds"},
		{"reload-watch-interval", "1m0s"},
		{"initial-retry-timeout", "2m0s"},
		{"initial-retry-interval", "2s"},
		{"reload-nginx", "true"},
	}
	for _, tt := range tests {
		flag := flags.Lookup(tt.name)
		if flag == nil {
			t.Fatalf("flag %q not registered", tt.name)
		}
		if flag.DefValue != tt.want {
			t.Errorf("flag %q default = %q, want %q", tt.name, flag.DefValue, tt.want)
		}
	}
}

func TestValidateConfigAccepts(t *testing.T) {
	tests := []struct {
		name string
		cfg  config
	}{
		{
			name: "minimal",
			cfg: config{
				CDSURL:            "http://cds:8443",
				AttestationApiURL: "http://attestation-api:8400",
				SAN:               "confidential-gke.confidential.ai",
			},
		},
		{
			name: "ip san",
			cfg: config{
				CDSURL:            "https://cds:8443",
				AttestationApiURL: "http://attestation-api:8400",
				SAN:               "10.0.0.1",
			},
		},
		{
			name: "reload watch with renew",
			cfg: config{
				CDSURL:              "http://cds:8443",
				AttestationApiURL:   "http://attestation-api:8400",
				SAN:                 "host.example.com",
				ReloadWatchPaths:    []string{"/tls.crt"},
				ReloadWatchInterval: time.Minute,
				RenewInterval:       time.Hour,
			},
		},
		{
			name: "continue on initial error with renew",
			cfg: config{
				CDSURL:                 "http://cds:8443",
				AttestationApiURL:      "http://attestation-api:8400",
				SAN:                    "host.example.com",
				ContinueOnInitialError: true,
				RenewInterval:          time.Hour,
			},
		},
		{
			name: "discovery webpki",
			cfg: config{
				CDSURL:                 "http://cds:8443",
				AttestationApiURL:      "http://attestation-api:8400",
				SAN:                    "host.example.com",
				DiscoveryOutPath:       "/tmp/d.json",
				DiscoveryPublicTLSMode: "webpki",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateConfig(tt.cfg); err != nil {
				t.Fatalf("validateConfig: %v", err)
			}
		})
	}
}

func TestValidateConfigRejects(t *testing.T) {
	base := config{
		CDSURL:            "http://cds:8443",
		AttestationApiURL: "http://attestation-api:8400",
		SAN:               "host.example.com",
	}
	tests := []struct {
		name   string
		mutate func(*config)
	}{
		{"empty cds url", func(c *config) { c.CDSURL = "" }},
		{"bad cds url", func(c *config) { c.CDSURL = "://nope" }},
		{"empty attestation url", func(c *config) { c.AttestationApiURL = "" }},
		{"empty san", func(c *config) { c.SAN = "" }},
		{"url san", func(c *config) { c.SAN = "https://host.example.com" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			if err := validateConfig(cfg); err == nil {
				t.Fatal("validateConfig succeeded, want error")
			}
		})
	}
}

func TestValidateSAN(t *testing.T) {
	tests := []struct {
		name    string
		san     string
		wantErr bool
	}{
		{"ipv4", "192.168.1.1", false},
		{"ipv6", "::1", false},
		{"hostname", "host.example.com", false},
		{"single label", "host", false},
		{"empty", "", true},
		{"http url", "http://host", true},
		{"https url", "https://host", true},
		{"wildcard", "*.example.com", true},
		{"trailing dot label", "host..com", true},
		{"too long", strings.Repeat("a", 254), true},
		{"label too long", strings.Repeat("a", 64) + ".com", true},
		{"underscore", "host_name.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSAN(tt.san)
			if tt.wantErr != (err != nil) {
				t.Fatalf("validateSAN(%q) err = %v, wantErr = %v", tt.san, err, tt.wantErr)
			}
		})
	}
}

func TestDiscoveryPublicTLSMode(t *testing.T) {
	if got := discoveryPublicTLSMode(""); got != "cds" {
		t.Fatalf("empty = %q, want cds", got)
	}
	if got := discoveryPublicTLSMode("webpki"); got != "webpki" {
		t.Fatalf("webpki = %q, want webpki", got)
	}
}

func TestValidateOutputPaths(t *testing.T) {
	dir := t.TempDir()

	t.Run("empty paths skipped", func(t *testing.T) {
		if err := validateOutputPaths("", "", ""); err != nil {
			t.Fatalf("validateOutputPaths: %v", err)
		}
	})

	t.Run("writable dir ok", func(t *testing.T) {
		if err := validateOutputPaths(filepath.Join(dir, "cert.pem")); err != nil {
			t.Fatalf("validateOutputPaths: %v", err)
		}
	})

	t.Run("missing dir", func(t *testing.T) {
		if err := validateOutputPaths(filepath.Join(dir, "missing", "cert.pem")); err == nil {
			t.Fatal("validateOutputPaths succeeded, want error for missing dir")
		}
	})

	t.Run("parent is a file", func(t *testing.T) {
		f := filepath.Join(dir, "afile")
		if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := validateOutputPaths(filepath.Join(f, "cert.pem")); err == nil {
			t.Fatal("validateOutputPaths succeeded, want error for file parent")
		}
	})
}

func TestLoadOrGenerateKey(t *testing.T) {
	t.Run("generate ephemeral", func(t *testing.T) {
		key, keyPEM, err := loadOrGenerateKey(config{})
		if err != nil {
			t.Fatalf("loadOrGenerateKey: %v", err)
		}
		if key == nil {
			t.Fatal("nil key")
		}
		if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
			t.Fatalf("keyPEM does not look like a PEM key: %q", keyPEM)
		}
		if key.Curve != elliptic.P256() {
			t.Fatalf("curve = %v, want P-256", key.Curve.Params().Name)
		}
	})

	t.Run("load from disk", func(t *testing.T) {
		dir := t.TempDir()
		genKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		genPEM, err := certutil.MarshalECKeyPEM(genKey)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(path, genPEM, 0600); err != nil {
			t.Fatal(err)
		}

		key, keyPEM, err := loadOrGenerateKey(config{KeyPath: path})
		if err != nil {
			t.Fatalf("loadOrGenerateKey: %v", err)
		}
		if !key.Equal(genKey) {
			t.Fatal("loaded key does not match written key")
		}
		if string(keyPEM) != string(genPEM) {
			t.Fatal("returned PEM does not match file contents")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, _, err := loadOrGenerateKey(config{KeyPath: filepath.Join(t.TempDir(), "nope.pem")}); err == nil {
			t.Fatal("loadOrGenerateKey succeeded, want error for missing file")
		}
	})

	t.Run("invalid key contents", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(path, []byte("not a key"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadOrGenerateKey(config{KeyPath: path}); err == nil {
			t.Fatal("loadOrGenerateKey succeeded, want error for invalid key")
		}
	})
}

func TestCreateCSR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ratlsExt := pkix.Extension{Id: ratls.OIDRATLSAttestation, Value: []byte{0x30, 0x03, 0x02, 0x01, 0x42}}

	parseCSR := func(t *testing.T, csrPEM []byte) *x509.CertificateRequest {
		t.Helper()
		block, _ := pem.Decode(csrPEM)
		if block == nil || block.Type != "CERTIFICATE REQUEST" {
			t.Fatalf("not a CSR PEM: %q", csrPEM)
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("parse CSR: %v", err)
		}
		return csr
	}

	t.Run("dns san", func(t *testing.T) {
		csrPEM, err := createCSR(key, "host.example.com", ratlsExt)
		if err != nil {
			t.Fatalf("createCSR: %v", err)
		}
		csr := parseCSR(t, csrPEM)
		// INVARIANT: the CSR carries the RA-TLS extension so CDS can copy it
		// into the issued leaf for downstream ratls-mode re-verification.
		found := false
		for _, ext := range csr.Extensions {
			if ext.Id.Equal(ratls.OIDRATLSAttestation) {
				found = true
				if string(ext.Value) != string(ratlsExt.Value) {
					t.Fatalf("RA-TLS ext value = %x, want %x", ext.Value, ratlsExt.Value)
				}
			}
		}
		if !found {
			t.Fatal("CSR missing the RA-TLS attestation extension")
		}
	})

	t.Run("ip san", func(t *testing.T) {
		csrPEM, err := createCSR(key, "10.0.0.5", ratlsExt)
		if err != nil {
			t.Fatalf("createCSR: %v", err)
		}
		if !strings.Contains(string(csrPEM), "CERTIFICATE REQUEST") {
			t.Fatalf("not a CSR PEM: %q", csrPEM)
		}
	})

	// The workload-claims flow embeds an RA-TLS attestation extension into the
	// CSR so CDS copies it onto the leaf (docs/ratls.md). Confirm an extra
	// extension survives into the request.
	t.Run("carries extra extension", func(t *testing.T) {
		want := []byte{0x30, 0x03, 0x02, 0x01, 0x2A}
		csrPEM, err := createCSR(key, "host.example.com", pkix.Extension{Id: ratls.OIDRATLSAttestation, Value: want})
		if err != nil {
			t.Fatalf("createCSR: %v", err)
		}
		block, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("parse csr: %v", err)
		}
		found := false
		for _, ext := range csr.Extensions {
			if ext.Id.Equal(ratls.OIDRATLSAttestation) {
				found = true
				if !bytes.Equal(ext.Value, want) {
					t.Fatalf("extension value = %x, want %x", ext.Value, want)
				}
			}
		}
		if !found {
			t.Fatal("RA-TLS extension not carried into the CSR")
		}
	})
}

// The extension embedded in the CSR must bind the bare public key — REPORTDATA
// = SHA-384(pubkey) with NO nonce — or downstream verifiers calling
// ratls.VerifyCert(cert, policy, nil) can never re-verify the issued leaf
// (the report_data mismatch bug this flow fixes).
func TestAttestationExtensionBindsBareKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var sawReportData []byte
	attestationApi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			t.Errorf("attestation-api path = %s, want /attest", r.URL.Path)
		}
		var req types.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode attest request: %v", err)
		}
		sawReportData = append([]byte(nil), req.ReportData.Bytes()...)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"platform":"az-snp","evidence":{"quote":"abc"}}`)
	}))
	defer attestationApi.Close()

	ext, err := attestclient.NewClient("").AttestationExtensionForClaims(context.Background(), attestationApi.URL, &key.PublicKey, nil)
	if err != nil {
		t.Fatalf("AttestationExtensionForClaims: %v", err)
	}

	want, err := ratls.ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(sawReportData) != string(want[:sha512.Size384]) {
		t.Fatalf("report_data sent to attestation-api = %x, want SHA-384(pubkey) = %x", sawReportData, want[:sha512.Size384])
	}

	att, err := ratls.UnmarshalExtension(ext.Value)
	if err != nil {
		t.Fatalf("unmarshal extension: %v", err)
	}
	if att.TEEType != ratls.TEETypeSEVSNP {
		t.Fatalf("TEEType = %v, want SEV-SNP", att.TEEType)
	}
}

func TestSnapshotReloadWatchPathsErrors(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		if _, err := snapshotReloadWatchPaths([]string{filepath.Join(dir, "nope")}); err == nil {
			t.Fatal("snapshotReloadWatchPaths succeeded, want error for missing file")
		}
	})

	t.Run("directory not allowed", func(t *testing.T) {
		if _, err := snapshotReloadWatchPaths([]string{dir}); err == nil {
			t.Fatal("snapshotReloadWatchPaths succeeded, want error for directory")
		}
	})
}

func TestReloadWatchChangedPropagatesError(t *testing.T) {
	if _, _, err := reloadWatchChanged(nil, []string{filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Fatal("reloadWatchChanged succeeded, want error for missing file")
	}
}

// The broker endpoint get-cert dials is a compiled Unix socket path, not a
// control-plane-supplied value, so the fetch can't be redirected.
func TestBrokerEndpointIsCompiledUnixPath(t *testing.T) {
	got := workloadclaims.BrokerEndpoint()
	if !strings.HasPrefix(got, "unix://") {
		t.Fatalf("broker endpoint %q is not a unix socket", got)
	}
	if !strings.HasSuffix(got, "/"+workloadclaims.SocketName) {
		t.Fatalf("broker endpoint %q does not end in the compiled socket name %q", got, workloadclaims.SocketName)
	}
}

// Without --workload-claims-broker, workloadClaims is a no-op: it returns the
// empty (claims-free) result without contacting any broker.
func TestWorkloadClaimsWithoutFlagIsClaimFree(t *testing.T) {
	res, err := workloadClaims(context.Background(), config{WorkloadClaimsBroker: false})
	if err != nil {
		t.Fatal(err)
	}
	if res.claimsDER != nil || res.initDigests != nil || res.mainDigests != nil {
		t.Fatalf("no --workload-claims-broker but a claim was produced: %+v", res)
	}
}

func TestWriteOutputsAllArtifacts(t *testing.T) {
	dir := t.TempDir()
	certPEM := testIssuedChainPEM(t)
	cfg := config{
		SAN:                    "host.example.com",
		OutPath:                filepath.Join(dir, "cert.pem"),
		CAOutPath:              filepath.Join(dir, "ca.pem"),
		KeyOutPath:             filepath.Join(dir, "key.pem"),
		KeyMode:                "0600",
		DiscoveryOutPath:       filepath.Join(dir, "discovery.json"),
		DiscoveryPublicTLSMode: "cds",
	}
	result := attestclient.CertificateResult{
		Certificate: certPEM,
		Challenge:   base64.StdEncoding.EncodeToString([]byte("challenge")),
		Platform:    "snp",
		Evidence:    json.RawMessage(`{"q":"e"}`),
	}

	if err := writeOutputs(cfg, []byte("KEYPEM"), result); err != nil {
		t.Fatalf("writeOutputs: %v", err)
	}

	cert, err := os.ReadFile(cfg.OutPath)
	if err != nil || string(cert) != certPEM {
		t.Fatalf("cert out mismatch: err=%v", err)
	}
	if data, err := os.ReadFile(cfg.KeyOutPath); err != nil || string(data) != "KEYPEM" {
		t.Fatalf("key out mismatch: err=%v", err)
	}
	info, err := os.Stat(cfg.KeyOutPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key mode = %#o, want 0600", info.Mode().Perm())
	}
	ca, err := os.ReadFile(cfg.CAOutPath)
	if err != nil || !strings.Contains(string(ca), "CERTIFICATE") {
		t.Fatalf("ca out mismatch: err=%v", err)
	}
	var doc types.DiscoveryDocument
	data, err := os.ReadFile(cfg.DiscoveryOutPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("discovery json: %v", err)
	}
	if doc.PublicTLS.Hostname != "host.example.com" {
		t.Fatalf("discovery hostname = %q", doc.PublicTLS.Hostname)
	}
}

func TestWriteOutputsBadKeyMode(t *testing.T) {
	err := writeOutputs(config{KeyOutPath: filepath.Join(t.TempDir(), "k"), KeyMode: "abc"}, []byte("k"), attestclient.CertificateResult{})
	if err == nil {
		t.Fatal("writeOutputs succeeded, want error for bad key mode")
	}
}

func TestWriteOutputsCAOutWithoutIssuerFails(t *testing.T) {
	// A chain with only a leaf has no CA bundle to extract.
	leafOnly := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("leaf")}))
	err := writeOutputs(config{CAOutPath: filepath.Join(t.TempDir(), "ca.pem")}, nil, attestclient.CertificateResult{Certificate: leafOnly})
	if err == nil {
		t.Fatal("writeOutputs succeeded, want error extracting CA bundle from leaf-only chain")
	}
}

func TestNewCDSClientInvalidURL(t *testing.T) {
	if _, err := newCDSClient(config{CDSURL: "://bad"}); err == nil {
		t.Fatal("newCDSClient succeeded, want error for invalid URL")
	}
}

func TestSetupLoggingDoesNotPanic(t *testing.T) {
	setupLogging(true)
	setupLogging(false)
}

// fakeCDSAndAttestation wires up an httptest server playing both the CDS role
// (/authenticate, /attest) and a separate attestation-api server (/attest).
// The challenge is valid base64 and the attestation-api echoes evidence so the
// full obtainCert flow can run without real TEE hardware.
func startFakeServers(t *testing.T, issuedChain string) (cdsURL, attURL string) {
	t.Helper()

	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			http.NotFound(w, r)
			return
		}
		// snp evidence must carry attestation_report — the CSR extension
		// build extracts the raw report bytes for the on-cert form.
		fakeReport := base64.StdEncoding.EncodeToString([]byte("fake-snp-report"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"platform": "snp",
			"evidence": json.RawMessage(`{"attestation_report":"` + fakeReport + `"}`),
		})
	}))
	t.Cleanup(att.Close)

	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authenticate":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"challenge": base64.StdEncoding.EncodeToString([]byte("the-challenge")),
			})
		case "/attest":
			_, _ = w.Write([]byte(issuedChain))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cds.Close)

	return cds.URL, att.URL
}

func TestObtainCertEndToEnd(t *testing.T) {
	dir := t.TempDir()
	chain := testIssuedChainPEM(t)
	cdsURL, attURL := startFakeServers(t, chain)

	cfg := config{
		CDSURL:            cdsURL,
		AttestationApiURL: attURL,
		SAN:               "host.example.com",
		OutPath:           filepath.Join(dir, "cert.pem"),
	}
	client := plaintextCDSClient(cfg.CDSURL)
	if err := obtainCert(context.Background(), cfg, client); err != nil {
		t.Fatalf("obtainCert: %v", err)
	}
	got, err := os.ReadFile(cfg.OutPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != chain {
		t.Fatalf("written cert does not match issued chain")
	}
}

func TestObtainCertCDSError(t *testing.T) {
	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "snp", "evidence": json.RawMessage(`{"attestation_report":"ZmFrZS1zbnAtcmVwb3J0"}`)})
	}))
	t.Cleanup(att.Close)
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(cds.Close)

	cfg := config{CDSURL: cds.URL, AttestationApiURL: att.URL, SAN: "host.example.com"}
	client := plaintextCDSClient(cfg.CDSURL)
	if err := obtainCert(context.Background(), cfg, client); err == nil {
		t.Fatal("obtainCert succeeded, want error when CDS fails")
	}
}

func TestObtainCertWithRetrySucceedsAfterTransientFailure(t *testing.T) {
	dir := t.TempDir()
	chain := testIssuedChainPEM(t)

	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "snp", "evidence": json.RawMessage(`{"attestation_report":"ZmFrZS1zbnAtcmVwb3J0"}`)})
	}))
	t.Cleanup(att.Close)

	var calls int
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authenticate":
			calls++
			if calls == 1 {
				http.Error(w, "warming up", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"challenge": base64.StdEncoding.EncodeToString([]byte("c")),
			})
		case "/attest":
			_, _ = w.Write([]byte(chain))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cds.Close)

	cfg := config{
		CDSURL:               cds.URL,
		AttestationApiURL:    att.URL,
		SAN:                  "host.example.com",
		OutPath:              filepath.Join(dir, "cert.pem"),
		InitialRetryTimeout:  5 * time.Second,
		InitialRetryInterval: time.Millisecond,
	}
	client := plaintextCDSClient(cfg.CDSURL)
	if err := obtainCertWithRetry(context.Background(), cfg, client); err != nil {
		t.Fatalf("obtainCertWithRetry: %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected a retry, got %d calls", calls)
	}
}

func TestObtainCertWithRetryNoTimeoutTriesOnce(t *testing.T) {
	att := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"platform": "snp", "evidence": json.RawMessage(`{"attestation_report":"ZmFrZS1zbnAtcmVwb3J0"}`)})
	}))
	t.Cleanup(att.Close)
	var calls int
	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(cds.Close)

	cfg := config{CDSURL: cds.URL, AttestationApiURL: att.URL, SAN: "host.example.com", InitialRetryTimeout: 0}
	client := plaintextCDSClient(cfg.CDSURL)
	if err := obtainCertWithRetry(context.Background(), cfg, client); err == nil {
		t.Fatal("obtainCertWithRetry succeeded, want error")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want exactly 1 with no retry timeout", calls)
	}
}

func TestRunOnceWritesCert(t *testing.T) {
	dir := t.TempDir()
	chain := testIssuedChainPEM(t)
	cdsURL, attURL := startFakeServers(t, chain)

	cfg := config{
		CDSURL:            cdsURL,
		AttestationApiURL: attURL,
		SAN:               "host.example.com",
		OutPath:           filepath.Join(dir, "cert.pem"),
		// run-once mode: RenewInterval == 0
	}
	// run() builds an https-only RA-TLS client via newCDSClient; drive the
	// run-once path (obtainCertWithRetry then return) against the plaintext
	// fake CDS with an injected client instead.
	if err := obtainCertWithRetry(context.Background(), cfg, plaintextCDSClient(cfg.CDSURL)); err != nil {
		t.Fatalf("obtainCertWithRetry: %v", err)
	}
	if _, err := os.Stat(cfg.OutPath); err != nil {
		t.Fatalf("cert not written: %v", err)
	}
}

func TestRunValidationError(t *testing.T) {
	if err := run(config{CDSURL: "", AttestationApiURL: "http://a", SAN: "h"}); err == nil {
		t.Fatal("run succeeded, want validation error")
	}
}

// testIssuedChainPEM builds a two-cert PEM chain (leaf + one issuer) that parses
// as real certificates, so buildDiscoveryDocument and caBundleFromChain succeed.
func testIssuedChainPEM(t *testing.T) string {
	t.Helper()
	leaf := testCertificatePEM(t)
	ca := testCertificatePEM(t)
	return leaf + ca
}
