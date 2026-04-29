package assamclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/pkg/types"
)

// mockServers creates test HTTP servers simulating assam, the attestation
// service, and the cert-issuer.
func mockServers(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate) (assam, attestSvc, issuer *httptest.Server) {
	t.Helper()

	// Attestation service: returns mock evidence for any request.
	attestSvc = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(types.AttestResponse{
			Platform: "snp",
			Evidence: json.RawMessage(`{"mock":"evidence"}`),
		})
	}))

	// Assam: authenticate returns challenge, attest verifies and returns cert.
	assam = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authenticate":
			challenge := make([]byte, 32)
			rand.Read(challenge)
			json.NewEncoder(w).Encode(types.ChallengeResponse{
				Challenge: base64.StdEncoding.EncodeToString(challenge),
			})

		case "/attest":
			var req types.AttestRequestBody
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", 400)
				return
			}
			if req.CSR == "" {
				http.Error(w, "missing CSR", 400)
				return
			}

			// Parse the CSR and sign it with the CA.
			block, _ := pem.Decode([]byte(req.CSR))
			if block == nil {
				http.Error(w, "bad PEM", 400)
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}

			serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			tmpl := &x509.Certificate{
				SerialNumber: serial,
				Subject:      csr.Subject,
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(1 * time.Hour),
				KeyUsage:     x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				IPAddresses:  csr.IPAddresses,
				DNSNames:     csr.DNSNames,
			}
			certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caKey)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}

			w.Header().Set("Content-Type", "application/x-pem-file")
			pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

		default:
			http.NotFound(w, r)
		}
	}))

	// Cert-issuer: serves the CA certificate bundle.
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ca" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	}))

	return assam, attestSvc, issuer
}

func testCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Mesh CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func TestProviderProvision(t *testing.T) {
	caKey, caCert := testCA(t)
	assam, attestSvc, issuer := mockServers(t, caKey, caCert)
	defer assam.Close()
	defer attestSvc.Close()
	defer issuer.Close()

	p, err := NewProvider(&Config{
		AssamURL:              assam.URL,
		AttestationServiceURL: attestSvc.URL,
		CertIssuerURL:         issuer.URL,
		NodeIP:                "10.0.0.1",
		NodeName:              "test-node",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	cert, ttl, err := p.Provision(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if cert == nil {
		t.Fatal("cert is nil")
	}
	if cert.PrivateKey == nil {
		t.Fatal("private key is nil")
	}
	if cert.Leaf == nil {
		t.Fatal("leaf cert is nil")
	}
	if len(cert.Certificate) < 2 {
		t.Fatalf("expected cert chain with leaf + CA, got %d certs", len(cert.Certificate))
	}
	if ttl <= 0 {
		t.Fatalf("TTL = %v, expected positive", ttl)
	}

	// Verify the cert chains to the CA.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("cert doesn't chain to CA: %v", err)
	}

	// Check subject.
	if cn := cert.Leaf.Subject.CommonName; cn != "ratls-mesh-10.0.0.1" {
		t.Errorf("CN = %q, want %q", cn, "ratls-mesh-10.0.0.1")
	}
}

func TestRefreshCABundle(t *testing.T) {
	_, caCert := testCA(t)

	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ca" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	}))
	defer issuer.Close()

	client := NewClient(&Config{
		AssamURL:              "http://unused",
		AttestationServiceURL: "http://unused",
		CertIssuerURL:         issuer.URL,
		NodeIP:                "10.0.0.1",
	})

	certs, err := client.RefreshCABundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 CA cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "Test Mesh CA" {
		t.Errorf("CA CN = %q, want %q", certs[0].Subject.CommonName, "Test Mesh CA")
	}
}

func TestNewProviderValidation(t *testing.T) {
	base := Config{
		AssamURL:              "http://assam",
		AttestationServiceURL: "http://attest",
		CertIssuerURL:         "http://issuer",
		NodeIP:                "10.0.0.1",
	}

	tests := []struct {
		name   string
		modify func(*Config)
	}{
		{"missing AssamURL", func(c *Config) { c.AssamURL = "" }},
		{"missing AttestationServiceURL", func(c *Config) { c.AttestationServiceURL = "" }},
		{"missing CertIssuerURL", func(c *Config) { c.CertIssuerURL = "" }},
		{"missing NodeIP", func(c *Config) { c.NodeIP = "" }},
		{"invalid NodeIP", func(c *Config) { c.NodeIP = "not-an-ip" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.modify(&cfg)
			_, err := NewProvider(&cfg, nil)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}
