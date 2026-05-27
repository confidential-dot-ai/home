package issuer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"net"
	"regexp"
	"strings"
	"testing"

	"github.com/lunal-dev/c8s/internal/issuer"
)

func TestValidateCSR(t *testing.T) {
	dnsAny := regexp.MustCompile(`[a-z]+\.mesh\.svc`)
	cnRatlsMesh := regexp.MustCompile(`ratls-mesh-[0-9.]+`)

	tests := []struct {
		name    string
		csr     *x509.CertificateRequest
		policy  issuer.CSRPolicy
		wantErr string // substring; empty = expect nil
	}{
		{
			name:   "empty CSR and empty policy pass",
			csr:    &x509.CertificateRequest{},
			policy: issuer.CSRPolicy{},
		},
		{
			name:    "DNS SAN with no pattern rejected",
			csr:     &x509.CertificateRequest{DNSNames: []string{"foo.mesh.svc"}},
			policy:  issuer.CSRPolicy{},
			wantErr: "no DNS SAN pattern configured",
		},
		{
			name:   "DNS SAN matching pattern accepted",
			csr:    &x509.CertificateRequest{DNSNames: []string{"foo.mesh.svc"}},
			policy: issuer.CSRPolicy{DNSSANPattern: dnsAny},
		},
		{
			name:    "DNS SAN not matching pattern rejected",
			csr:     &x509.CertificateRequest{DNSNames: []string{"evil.example.com"}},
			policy:  issuer.CSRPolicy{DNSSANPattern: dnsAny},
			wantErr: "does not match allowed pattern",
		},
		{
			name:    "DNS SAN substring match rejected",
			csr:     &x509.CertificateRequest{DNSNames: []string{"evil-foo.mesh.svc"}},
			policy:  issuer.CSRPolicy{DNSSANPattern: regexp.MustCompile(`foo\.mesh\.svc`)},
			wantErr: "does not match allowed pattern",
		},
		{
			name:    "CN not matching allowed pattern rejected",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil"}},
			policy:  issuer.CSRPolicy{AllowedCNPattern: cnRatlsMesh},
			wantErr: "CN \"evil\" does not match",
		},
		{
			name:   "CN matching allowed pattern accepted",
			csr:    &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ratls-mesh-10.0.0.1"}},
			policy: issuer.CSRPolicy{AllowedCNPattern: cnRatlsMesh},
		},
		{
			name:    "CN substring match rejected",
			csr:     &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil-ratls-mesh-10.0.0.1"}},
			policy:  issuer.CSRPolicy{AllowedCNPattern: cnRatlsMesh},
			wantErr: "does not match allowed pattern",
		},
		{
			name:    "IP SAN not matching source rejected",
			csr:     &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("10.0.0.2")}},
			policy:  issuer.CSRPolicy{SourceIP: "10.0.0.1"},
			wantErr: "does not match request source",
		},
		{
			name:   "IP SAN matching source accepted",
			csr:    &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}},
			policy: issuer.CSRPolicy{SourceIP: "10.0.0.1"},
		},
		{
			name:   "IPv4-in-IPv6 SAN matches IPv4 source",
			csr:    &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("::ffff:10.0.0.1")}},
			policy: issuer.CSRPolicy{SourceIP: "10.0.0.1"},
		},
		{
			name:   "IPv6 source with zone matches zoneless SAN",
			csr:    &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("fe80::1")}},
			policy: issuer.CSRPolicy{SourceIP: "fe80::1%eth0"},
		},
		{
			name:    "non-IP source rejected when CSR carries an IP SAN",
			csr:     &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}},
			policy:  issuer.CSRPolicy{SourceIP: "/run/cds.sock"},
			wantErr: "is not a valid IP",
		},
		{
			name:    "multiple IP SANs rejected even when matching source",
			csr:     &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.1")}},
			policy:  issuer.CSRPolicy{SourceIP: "10.0.0.1"},
			wantErr: "at most one is allowed",
		},
		{
			name:    "IP SAN rejected when SourceIP empty",
			csr:     &x509.CertificateRequest{IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}},
			policy:  issuer.CSRPolicy{},
			wantErr: "source-IP binding is disabled",
		},
		{
			name:   "no IP SAN with empty SourceIP accepted",
			csr:    &x509.CertificateRequest{},
			policy: issuer.CSRPolicy{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := issuer.ValidateCSR(tc.csr, tc.policy)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestSourceIPFromRemoteAddr(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"10.0.0.1:54321", "10.0.0.1"},
		{"[::1]:8080", "::1"},
		{"unix-socket", "unix-socket"},
	} {
		got := issuer.SourceIPFromRemoteAddr(tc.in)
		if got != tc.want {
			t.Errorf("SourceIPFromRemoteAddr(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestVerifyKeyBindingRejectsMalformedClaimKey(t *testing.T) {
	csr := csrForKeyBindingTest(t)

	err := issuer.VerifyKeyBinding(csr, &issuer.EARClaims{
		TEEPubKey: base64.RawURLEncoding.EncodeToString([]byte{0}),
	})
	if err == nil {
		t.Fatal("expected malformed attested key claim to be rejected")
	}
	if !strings.Contains(err.Error(), "claim length") {
		t.Fatalf("error = %q, want claim length rejection", err)
	}
}

func csrForKeyBindingTest(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}
