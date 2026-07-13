package verify

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
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// selfSignedCertPEM returns a throwaway ECDSA P-256 certificate (PEM) and its
// public key, for testing REPORTDATA-binding math without real SNP crypto.
func selfSignedCertPEM(t *testing.T) (string, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cds"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), &key.PublicKey
}

func TestEvidenceFromDiscovery(t *testing.T) {
	certPEM, pub := selfSignedCertPEM(t)
	report := bytes.Repeat([]byte{0x01}, 1184)
	vcek := []byte("vcek-der-bytes")
	challenge := bytes.Repeat([]byte{0x05}, 32)

	buildDoc := func(platform, cert string) []byte {
		doc := map[string]any{
			"cds_tls": map[string]any{"certificate_pem": cert},
			"attestation": map[string]any{
				"platform":  platform,
				"challenge": base64.StdEncoding.EncodeToString(challenge),
				"evidence": map[string]any{
					"attestation_report": base64.StdEncoding.EncodeToString(report),
					"cert_chain":         map[string]any{"vcek": base64.StdEncoding.EncodeToString(vcek)},
				},
			},
		}
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("forwards platform + evidence verbatim and binds cert key + challenge", func(t *testing.T) {
		ev, err := evidenceFromDiscovery(buildDoc("snp", certPEM), "test")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if ev.platform != "snp" {
			t.Errorf("platform = %q, want snp", ev.platform)
		}
		var inner map[string]any
		if err := json.Unmarshal(ev.rawEvidence, &inner); err != nil {
			t.Fatalf("rawEvidence not JSON: %v", err)
		}
		if inner["attestation_report"] != base64.StdEncoding.EncodeToString(report) {
			t.Error("evidence object not forwarded verbatim")
		}
		if ev.fresh {
			t.Error("discovery is bound to the issuance challenge, not a fresh nonce")
		}
		want, err := ratls.ReportDataForKey(pub, challenge)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ev.erd, keyAnchor(want)) {
			t.Error("erd must equal the unpadded ReportDataForKey(cert.pubkey, challenge) — the issuance binding")
		}
	})

	t.Run("forwards a non-snp platform (e.g. tdx) rather than rejecting it", func(t *testing.T) {
		ev, err := evidenceFromDiscovery(buildDoc("tdx", certPEM), "test")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if ev.platform != "tdx" {
			t.Errorf("platform = %q, want tdx forwarded", ev.platform)
		}
	})

	t.Run("rejects missing certificate", func(t *testing.T) {
		if _, err := evidenceFromDiscovery(buildDoc("snp", ""), "test"); err == nil {
			t.Fatal("expected error when certificate_pem is absent")
		}
	})
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct {
		raw      string
		port     int
		wantDial string
		wantBase string
	}{
		{"cds.example.com", 8443, "cds.example.com:8443", "https://cds.example.com:8443"},
		{"cds.example.com:9999", 8443, "cds.example.com:9999", "https://cds.example.com:9999"},
		{"https://lb.example.com", 443, "lb.example.com:443", "https://lb.example.com:443"},
		{"https://lb.example.com:8443/ignored", 443, "lb.example.com:8443", "https://lb.example.com:8443"},
		{"2001:db8::2", 8443, "[2001:db8::2]:8443", "https://[2001:db8::2]:8443"},
		{"[2001:db8::2]:9999", 8443, "[2001:db8::2]:9999", "https://[2001:db8::2]:9999"},
	}
	for _, c := range cases {
		dial, base, err := normalizeTarget(c.raw, c.port)
		if err != nil {
			t.Fatalf("normalizeTarget(%q): %v", c.raw, err)
		}
		if dial != c.wantDial || base != c.wantBase {
			t.Errorf("normalizeTarget(%q) = (%q,%q), want (%q,%q)", c.raw, dial, base, c.wantDial, c.wantBase)
		}
	}
}

func TestBuildPolicy_RejectsOutOfRangeMinTCB(t *testing.T) {
	if _, err := buildPolicy(config{minTCBSNP: 256}); err == nil {
		t.Fatal("expected --min-tcb-snp 256 to be rejected (would truncate to 0)")
	}
	if _, err := buildPolicy(config{minTCBBootloader: 255, minTCBTEE: 1}); err != nil {
		t.Errorf("in-range min-tcb values should be accepted: %v", err)
	}
}

func TestParseExpectedReportData(t *testing.T) {
	if _, err := parseExpectedReportData(strings.Repeat("ab", 64)); err != nil {
		t.Errorf("64-byte hex should parse: %v", err)
	}
	if _, err := parseExpectedReportData(strings.Repeat("cd", 48)); err != nil {
		t.Errorf("48-byte hex should parse: %v", err)
	}
	// Any 1–64 bytes is accepted, kept unpadded — the binding digest length
	// isn't fixed across platforms/schemes.
	if got, err := parseExpectedReportData(strings.Repeat("ab", 10)); err != nil || len(got) != 10 {
		t.Errorf("10-byte hex should parse unpadded: %v (len %d)", err, len(got))
	}
	if _, err := parseExpectedReportData("zzzz"); err == nil {
		t.Error("non-hex should fail")
	}
	if _, err := parseExpectedReportData(""); err == nil {
		t.Error("empty should fail")
	}
	if _, err := parseExpectedReportData(strings.Repeat("ab", 65)); err == nil {
		t.Error("more than 64 bytes should fail")
	}
}

func TestEndpointReportData_KnownVector(t *testing.T) {
	x := []byte("x25519-key")
	m := []byte("mlkem-key")
	n := []byte("nonce")
	h := sha512.New384()
	h.Write(x)
	h.Write(m)
	h.Write(n)
	want := h.Sum(nil)

	got := endpointReportData(x, m, n)
	if !bytes.Equal(got, want) {
		t.Errorf("endpointReportData mismatch")
	}
	// Azure vTPM verifiers compare the anchor raw against the quote's 48-byte
	// extraData — a zero-padded 64-byte anchor fails there (the az-snp CDS
	// verify regression).
	if len(got) != sha512.Size384 {
		t.Errorf("anchor is %d bytes, want unpadded SHA-384 (%d)", len(got), sha512.Size384)
	}
}

// buildEndpointJSON makes an attestation-response body with the given fields.
func buildEndpointJSON(t *testing.T, nonce, report, vcek, x25519, mlkem []byte) []byte {
	t.Helper()
	b64u := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	resp := map[string]any{
		"platform": "snp",
		"nonce":    b64u(nonce),
		"evidence": map[string]any{
			"attestation_report": base64.StdEncoding.EncodeToString(report),
			"cert_chain":         map[string]any{"vcek": base64.StdEncoding.EncodeToString(vcek)},
		},
		"session_pubkey": map[string]any{"x25519": b64u(x25519), "mlkem768": b64u(mlkem)},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEvidenceFromEndpointJSON(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x07}, nonceSize)
	report := bytes.Repeat([]byte{0x01}, 64)
	x := bytes.Repeat([]byte{0x02}, 32)
	m := bytes.Repeat([]byte{0x03}, 1184)
	data := buildEndpointJSON(t, nonce, report, []byte("vcek"), x, m)

	t.Run("fresh when nonce echoes", func(t *testing.T) {
		ev, err := evidenceFromEndpointJSON(data, nonce, "test")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if !ev.fresh {
			t.Error("expected fresh=true when challenge echoes")
		}
		if !bytes.Equal(ev.erd, endpointReportData(x, m, nonce)) {
			t.Error("erd does not match expected report_data binding")
		}
	})

	t.Run("nonce mismatch is a security error (not swallowed by auto fallback)", func(t *testing.T) {
		_, err := evidenceFromEndpointJSON(data, bytes.Repeat([]byte{0x09}, nonceSize), "test")
		if err == nil || !isSecurityError(err) {
			t.Fatalf("expected securityError on nonce mismatch, got %v", err)
		}
		if isConnectError(err) {
			t.Error("nonce mismatch must not be a connectError (would trigger silent cert fallback)")
		}
	})

	t.Run("missing session keys rejected", func(t *testing.T) {
		bare := buildEndpointJSON(t, nonce, report, []byte("vcek"), nil, nil)
		if _, err := evidenceFromEndpointJSON(bare, nonce, "test"); err == nil {
			t.Fatal("expected error when session_pubkey is absent")
		}
	})

	t.Run("non-canonical session-key length is accepted (lengths not policed)", func(t *testing.T) {
		// 16 bytes is not the PROTOCOL.md-canonical x25519 length, but the verifier
		// does not enforce lengths — the binding (REPORTDATA == SHA-384 over these
		// exact bytes) is what the hardware-signed report is checked against
		// downstream, so a wrong length just produces a binding that won't match.
		shortX16 := bytes.Repeat([]byte{0x02}, 16)
		data := buildEndpointJSON(t, nonce, report, []byte("vcek"), shortX16, m)
		ev, err := evidenceFromEndpointJSON(data, nonce, "test")
		if err != nil {
			t.Fatalf("non-canonical key length should be accepted: %v", err)
		}
		if !bytes.Equal(ev.erd, endpointReportData(shortX16, m, nonce)) {
			t.Error("erd must bind the session-key bytes as provided")
		}
	})

	t.Run("non-snp platform is forwarded, not rejected", func(t *testing.T) {
		var obj map[string]any
		_ = json.Unmarshal(data, &obj)
		obj["platform"] = "tdx"
		other, _ := json.Marshal(obj)
		ev, err := evidenceFromEndpointJSON(other, nonce, "test")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if ev.platform != "tdx" {
			t.Errorf("platform = %q, want tdx forwarded", ev.platform)
		}
	})
}

// TestEvidenceFromEndpointJSON_RealShape feeds a literal JSON document in the
// exact shape the attestation endpoint emits (per c8s-verify-js PROTOCOL.md),
// rather than one built from this package's own structs — so a renamed or
// re-nested wire field fails here even though the struct-built fixtures above
// wouldn't notice.
func TestEvidenceFromEndpointJSON_RealShape(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xA1}, nonceSize)
	x := bytes.Repeat([]byte{0xB2}, x25519PubLen)
	m := bytes.Repeat([]byte{0xC3}, mlkem768EncapLen)
	report := bytes.Repeat([]byte{0xD4}, 64)
	b64u := base64.RawURLEncoding.EncodeToString

	payload := fmt.Sprintf(`{
  "platform": "snp",
  "nonce": %q,
  "evidence": {
    "attestation_report": %q,
    "cert_chain": { "vcek": %q }
  },
  "session_pubkey": { "x25519": %q, "mlkem768": %q }
}`,
		b64u(nonce),
		base64.StdEncoding.EncodeToString(report),
		base64.StdEncoding.EncodeToString([]byte("vcek-der")),
		b64u(x), b64u(m),
	)

	ev, err := evidenceFromEndpointJSON([]byte(payload), nonce, "endpoint")
	if err != nil {
		t.Fatalf("real-shape endpoint payload should parse: %v", err)
	}
	if !ev.fresh {
		t.Error("expected fresh=true when the challenge echoes")
	}
	if ev.platform != "snp" {
		t.Errorf("platform = %q, want snp", ev.platform)
	}
	if !bytes.Equal(ev.erd, endpointReportData(x, m, nonce)) {
		t.Error("erd does not match SHA-384(x25519‖mlkem768‖nonce)")
	}
	// The platform-specific evidence object is forwarded verbatim.
	if !bytes.Contains(ev.rawEvidence, []byte("attestation_report")) {
		t.Error("evidence object should be forwarded verbatim")
	}
}

// TestParseRealSNPEvidence drives a *real* captured {platform, evidence} object
// — a Genoa SEV-SNP report + VCEK, vendored from the c8s-verify-js reference
// impl's fixture (demo/fixtures/snp-evidence-genoa.json) — through the parser,
// so field/encoding drift between the JS and Go implementations fails here.
func TestParseRealSNPEvidence(t *testing.T) {
	fixture, err := os.ReadFile("testdata/snp-evidence-genoa.json")
	if err != nil {
		t.Fatal(err)
	}

	// The bare {platform, evidence} path consumes it directly.
	bare, err := evidenceFromBareJSON(fixture, make([]byte, 48), "fixture")
	if err != nil {
		t.Fatalf("evidenceFromBareJSON on the real fixture: %v", err)
	}
	if bare.platform != "snp" {
		t.Errorf("platform = %q, want snp", bare.platform)
	}
	if !bytes.Contains(bare.rawEvidence, []byte("attestation_report")) || !bytes.Contains(bare.rawEvidence, []byte("vcek")) {
		t.Error("real evidence (report + vcek) should be forwarded verbatim")
	}

	// The attestation endpoint wraps that same platform-specific evidence; parse
	// a real endpoint response built around it.
	var env struct {
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(fixture, &env); err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x5A}, nonceSize)
	x := bytes.Repeat([]byte{0xB2}, x25519PubLen)
	m := bytes.Repeat([]byte{0xC3}, mlkem768EncapLen)
	b64u := base64.RawURLEncoding.EncodeToString
	resp := fmt.Sprintf(`{"platform":"snp","nonce":%q,"evidence":%s,"session_pubkey":{"x25519":%q,"mlkem768":%q}}`,
		b64u(nonce), string(env.Evidence), b64u(x), b64u(m))

	ev, err := evidenceFromEndpointJSON([]byte(resp), nonce, "endpoint")
	if err != nil {
		t.Fatalf("evidenceFromEndpointJSON on the real-evidence response: %v", err)
	}
	if !ev.fresh {
		t.Error("expected fresh=true when the challenge echoes")
	}
	if !bytes.Equal(ev.rawEvidence, env.Evidence) {
		t.Error("real evidence object should round-trip verbatim through the endpoint parser")
	}
	if !bytes.Equal(ev.erd, endpointReportData(x, m, nonce)) {
		t.Error("erd binding mismatch")
	}
}

// TestVerifyRealAzSnpEvidence_UnpaddedAnchor drives real az-snp evidence (vTPM
// quote extraData = ASCII "challenge", VCEK inline; vendored from
// attestation-go's azsnp testdata) through the --from-file override path. The
// anchor must reach the verifier unpadded: the Azure vTPM verifiers compare it
// raw against the quote's extraData, so the historical zero-padding to 64
// bytes failed every az-snp target with "TPM nonce length mismatch".
func TestVerifyRealAzSnpEvidence_UnpaddedAnchor(t *testing.T) {
	fixture, err := os.ReadFile("testdata/azsnp-evidence-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := gatherFromFile(fixture, []byte("challenge"), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if ev.platform != "az-snp" {
		t.Fatalf("platform = %q, want az-snp", ev.platform)
	}
	res, err := verifyInProcess(ev, &ratls.VerifyPolicy{}, nil)
	// The pinned attestation-go cannot yet verify this v2 HCL report's hardware
	// layer (VCEK product resolution + provisional firmware; fixed upstream), so
	// until the next bump only the nonce gate is asserted. See docs/roadmap.md.
	if err != nil && strings.Contains(err.Error(), "nonce") {
		t.Fatalf("the unpadded anchor must clear the vTPM nonce check: %v", err)
	}
	if err == nil && (res.ReportDataMatch == nil || !*res.ReportDataMatch) {
		t.Fatal("report_data_match must be affirmatively true")
	}

	// A different anchor still fails closed, at the nonce gate specifically.
	ev.erd = []byte("not-the-nonce")
	if _, err := verifyInProcess(ev, &ratls.VerifyPolicy{}, nil); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("wrong nonce must fail closed at the nonce check, got: %v", err)
	}
}

func TestGatherFromEndpoint_Integration(t *testing.T) {
	report := bytes.Repeat([]byte{0x01}, 64)
	x := bytes.Repeat([]byte{0x02}, 32)
	m := bytes.Repeat([]byte{0x03}, 1184)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != attestationPath {
			http.NotFound(w, r)
			return
		}
		nb := r.URL.Query().Get("nonce")
		nonce, _ := base64.RawURLEncoding.DecodeString(nb)
		w.Header().Set("Content-Type", "application/json")
		w.Write(buildEndpointJSON(t, nonce, report, []byte("vcek"), x, m))
	}))
	defer srv.Close()

	ev, err := gatherFromEndpoint(context.Background(), srv.URL, "", 5*time.Second)
	if err != nil {
		t.Fatalf("gatherFromEndpoint: %v", err)
	}
	if !ev.fresh {
		t.Error("expected fresh evidence from live endpoint")
	}
	var inner map[string]any
	if err := json.Unmarshal(ev.rawEvidence, &inner); err != nil {
		t.Fatalf("rawEvidence not JSON: %v", err)
	}
	if inner["attestation_report"] != base64.StdEncoding.EncodeToString(report) {
		t.Error("evidence object not forwarded verbatim from the endpoint")
	}
}

func TestGatherFromEndpoint_HTTPErrorIsConnectError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, err := gatherFromEndpoint(context.Background(), srv.URL, "", 5*time.Second)
	if err == nil || !isConnectError(err) {
		t.Fatalf("expected connectError on HTTP 503, got %v", err)
	}
}

func TestRenderOutcome(t *testing.T) {
	ev := &evidence{
		platform:    "snp",
		source:      "test",
		bindingNote: "test binding",
		fresh:       true,
	}
	measHex := "ab" + strings.Repeat("00", 47) // 48-byte launch digest
	result := &teetypes.VerificationResult{SignatureValid: true, Claims: teetypes.Claims{LaunchDigest: measHex}}

	pinnedPolicy := func(t *testing.T) *ratls.VerifyPolicy {
		t.Helper()
		m, err := ratls.ParseHexMeasurementsList([]string{measHex})
		if err != nil {
			t.Fatal(err)
		}
		return &ratls.VerifyPolicy{Measurements: m}
	}

	t.Run("verified + pinned -> no UNSAFE warning", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "text"}
		oc := newOutcome(cfg, ev, result, nil, pinnedPolicy(t))
		render(cfg, oc, &out)
		if !oc.Verified {
			t.Fatalf("expected verified; oc=%+v", oc)
		}
		if !strings.Contains(out.String(), "VERIFIED") || strings.Contains(out.String(), "UNSAFE") {
			t.Errorf("unexpected output: %s", out.String())
		}
	})

	t.Run("unpinned warns UNSAFE", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "text"}
		render(cfg, newOutcome(cfg, ev, result, nil, &ratls.VerifyPolicy{}), &out)
		if !strings.Contains(out.String(), "UNSAFE") {
			t.Errorf("expected UNSAFE warning when no measurements pinned: %s", out.String())
		}
	})

	t.Run("json output", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "json"}
		render(cfg, newOutcome(cfg, ev, result, nil, &ratls.VerifyPolicy{}), &out)
		var oc Outcome
		if err := json.Unmarshal(out.Bytes(), &oc); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if !oc.Verified || oc.Measurement != measHex {
			t.Errorf("unexpected outcome: %+v", oc)
		}
	})

	t.Run("verdict error -> NOT VERIFIED", func(t *testing.T) {
		var out bytes.Buffer
		cfg := config{output: "text"}
		oc := newOutcome(cfg, ev, nil, &securityError{err: errors.New("rejected")}, &ratls.VerifyPolicy{})
		render(cfg, oc, &out)
		if oc.Verified || !strings.Contains(out.String(), "NOT VERIFIED") {
			t.Errorf("unexpected output: %s", out.String())
		}
	})

	t.Run("measurement not in allowlist -> not verified", func(t *testing.T) {
		// A genuine TEE whose launch digest isn't pinned must fail closed: the
		// allowlist is enforced here (the verifier has no --measurements input).
		other, err := ratls.ParseHexMeasurementsList([]string{"00" + strings.Repeat("11", 47)})
		if err != nil {
			t.Fatal(err)
		}
		oc := newOutcome(config{}, ev, result, nil, &ratls.VerifyPolicy{Measurements: other})
		if oc.Verified || !strings.Contains(oc.Error, "not in --measurements allowlist") {
			t.Errorf("expected allowlist rejection, got %+v", oc)
		}
	})
}

func TestGatherFromFile_RejectsExpectedReportDataOnCert(t *testing.T) {
	// A certificate's binding is its key; an override would silently replace a
	// real binding while still reporting "binds the certificate public key".
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("does-not-matter")})
	if _, err := gatherFromFile(pemCert, make([]byte, 48), "file"); err == nil {
		t.Fatal("expected --expected-report-data to be rejected for a certificate file")
	}
}

func TestRun_NoTarget(t *testing.T) {
	// No URL and no --from-file is a usage error.
	var out, errOut bytes.Buffer
	code := run(context.Background(), config{}, &out, &errOut)
	if code != exitUsage {
		t.Errorf("code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "no target") {
		t.Errorf("missing 'no target' message: %s", errOut.String())
	}
}

// TestRunDiscoveryVerify_EndToEnd exercises run() through the discovery URL
// path: GET an unauthenticated discovery doc, then verify in-process. The stub
// evidence isn't a real SNP report, so verification fails closed — which proves
// the discovery → gather → verify → render → exit-code chain runs and the
// binding is extracted: a verification failure (exit 2), not a gather failure
// (exit 3).
func TestRunDiscoveryVerify_EndToEnd(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)
	challenge := []byte("issuance-challenge")
	doc := discoveryDocWith(t, certPEM, challenge, `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`)

	// The "tls-lb": serves the discovery doc unauthenticated at /v1/discovery.
	lb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != defaultDiscoveryPath {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Write(doc)
	}))
	defer lb.Close()

	var out, errOut bytes.Buffer
	code := run(context.Background(), config{
		url:    lb.URL,
		kind:   "lb",
		output: "text",
	}, &out, &errOut)
	output := out.String() + errOut.String()

	if code != exitFailed {
		t.Fatalf("code = %d, want %d (stub evidence must fail closed at verify, not gather); output:\n%s",
			code, exitFailed, output)
	}
	if !strings.Contains(out.String(), "NOT VERIFIED") {
		t.Errorf("expected NOT VERIFIED, got:\n%s", output)
	}
}

// TestResolveMode locks in kind→mode routing. The regression it guards: an
// explicit --kind must drive the evidence mode when --mode is left at its
// (auto) default, so `c8s cds verify --kind lb` resolves to discovery rather
// than dialing for the embedded RA-TLS extension the LB front door never
// serves. An explicit non-auto --mode always wins over kind.
func TestResolveMode(t *testing.T) {
	cases := []struct {
		name string
		kind string
		mode string
		want string
	}{
		{"lb kind, auto mode", "lb", "auto", "discovery"},
		{"lb kind, empty mode", "lb", "", "discovery"},
		{"cds kind, auto mode", "cds", "auto", "ratls-cert"},
		{"workload kind, auto mode", "workload", "auto", "ratls-cert"},
		{"auto kind, auto mode", "auto", "auto", "auto"},
		{"empty kind, empty mode", "", "", "auto"},
		{"explicit mode overrides lb kind", "lb", "ratls-cert", "ratls-cert"},
		{"explicit mode overrides cds kind", "cds", "attestation-endpoint", "attestation-endpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveMode(config{kind: tc.kind, mode: tc.mode})
			if got != tc.want {
				t.Errorf("resolveMode(kind=%q, mode=%q) = %q, want %q", tc.kind, tc.mode, got, tc.want)
			}
		})
	}
}

// TestGatherEvidence_AutoPrefersDiscovery proves auto mode (no --kind) detects
// an LB by fetching its discovery doc first — the bare `c8s verify <lb>` path.
func TestGatherEvidence_AutoPrefersDiscovery(t *testing.T) {
	certPEM, _ := selfSignedCertPEM(t)
	doc := discoveryDocWith(t, certPEM, []byte("challenge"), `{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`)
	lb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != defaultDiscoveryPath {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Write(doc)
	}))
	defer lb.Close()

	ev, err := gatherEvidence(context.Background(), config{url: lb.URL, kind: "auto"}, nil)
	if err != nil {
		t.Fatalf("auto mode should reach the discovery doc, got: %v", err)
	}
	if !strings.Contains(ev.source, "discovery document") {
		t.Errorf("source = %q, want the discovery-doc path", ev.source)
	}
}

// TestGatherEvidence_AutoFallsBackToServingCert proves auto mode falls through
// to the RA-TLS serving cert when discovery is absent (a non-LB TLS endpoint):
// the surfaced error is the cert-path verdict, not the discovery 404.
func TestGatherEvidence_AutoFallsBackToServingCert(t *testing.T) {
	// 404s every path (no /v1/discovery) and presents httptest's plain serving
	// cert, which carries no RA-TLS extension.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := gatherEvidence(context.Background(), config{url: srv.URL, kind: "auto"}, nil)
	if !errors.Is(err, ratls.ErrNotAttested) {
		t.Fatalf("want fall-through to the serving-cert path (ErrNotAttested), got: %v", err)
	}
}
