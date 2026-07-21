package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	wlDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	wlDigestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// fakeStore is a workloadDigestChecker over a fixed allowed set.
type fakeStore map[string]bool

func (s fakeStore) Contains(d types.Digest) (bool, error) { return s[d.String()], nil }

// asContainers wraps flat image-digest slices in the (image, argv) tuple
// shape the digest layer now takes. Test argv is a deterministic per-image
// placeholder so the same slice reused across a test hashes identically on
// both sides.
func asContainers(images ...string) []workloadclaims.Container {
	out := make([]workloadclaims.Container, 0, len(images))
	for _, img := range images {
		out = append(out, workloadclaims.Container{Digest: img, Args: []string{"/test", img}})
	}
	return out
}

func asAttestedContainers(images ...string) []types.AttestedContainer {
	out := make([]types.AttestedContainer, 0, len(images))
	for _, img := range images {
		out = append(out, types.AttestedContainer{Image: img, Args: []string{"/test", img}})
	}
	return out
}

func claimsDERFor(t *testing.T, initImages, mainImages []string) []byte {
	t.Helper()
	claims, err := workloadclaims.BuildConfigClaims(asContainers(initImages...), asContainers(mainImages...))
	if err != nil {
		t.Fatalf("build claims: %v", err)
	}
	ext, err := claims.MarshalExtension()
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return ext.Value
}

// csrWithBoundClaims builds a CSR carrying a real SEV-SNP RA-TLS attestation
// extension whose REPORTDATA binds boundClaims (what get-cert does). CDS's
// issuance-time binding check re-derives the same REPORTDATA and compares, so
// a CSR bound to different claims than the request carries is rejected.
func csrWithBoundClaims(t *testing.T, boundClaims []byte) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := ratls.ReportDataForKeyAndClaims(&key.PublicKey, boundClaims, nil)
	if err != nil {
		t.Fatal(err)
	}
	report := make([]byte, ratls.SNPReportSize)
	copy(report[0x50:], rd[:]) // REPORTDATA at the SNP offset
	att := &ratls.Attestation{TEEType: ratls.TEETypeSEVSNP, Report: report}
	ext, err := att.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test-node"}, ExtraExtensions: []pkix.Extension{ext}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// postAttestClaims posts a claims request whose CSR correctly binds claimsDER —
// so the binding check passes and the request exercises the downstream
// list/allowlist/role checks.
func postAttestClaims(t *testing.T, h AttestHandler, challenge string, claimsDER []byte, initImages, mainImages []string) *httptest.ResponseRecorder {
	t.Helper()
	return postAttestClaimsWithCSR(t, h, challenge, csrWithBoundClaims(t, claimsDER), claimsDER, initImages, mainImages)
}

func postAttestClaimsWithCSR(t *testing.T, h AttestHandler, challenge, csrPEM string, claimsDER []byte, initImages, mainImages []string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(types.AttestRequestBody{
		Challenge:      challenge,
		Evidence:       types.AttestationEvidence{Platform: "snp", Evidence: json.RawMessage(`{"test":true}`)},
		CSR:            csrPEM,
		WorkloadClaims: base64.StdEncoding.EncodeToString(claimsDER),
		InitContainers: asAttestedContainers(initImages...),
		Containers:     asAttestedContainers(mainImages...),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAttest(w, req)
	return w
}

func TestAttest_WorkloadClaims_EmbedsExtensionWhenAllowlisted(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.AllowlistStore = fakeStore{wlDigestA: true, wlDigestB: true}

	digests := []string{wlDigestA, wlDigestB}
	claimsDER := claimsDERFor(t, nil, digests)
	w := postAttestClaims(t, h, issueChallenge(t, h), claimsDER, nil, digests)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", w.Code, w.Body.String())
	}
	leaf := leafFromAttestResponse(t, w)
	if got := ratls.ExtractConfigClaimsBytes(leaf); !bytes.Equal(got, claimsDER) {
		t.Fatalf("leaf config-claims = %x, want %x", got, claimsDER)
	}
	// The RA-TLS attestation extension must be copied onto the leaf and parse,
	// so `c8s verify` can check the claims against evidence.
	if _, err := ratls.ExtractAttestation(leaf); err != nil {
		t.Fatalf("leaf missing/invalid RA-TLS attestation extension: %v", err)
	}
}

// A workload claim on a CSR that carries no RA-TLS attestation extension must
// be rejected: the leaf would stamp config-claims that no verifier could check
// against hardware evidence.
func TestAttest_WorkloadClaims_RejectsMissingRATLSExtension(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.AllowlistStore = fakeStore{wlDigestA: true}

	digests := []string{wlDigestA}
	w := postAttestClaimsWithCSR(t, h, issueChallenge(t, h), mustCSR(t), claimsDERFor(t, nil, digests), nil, digests)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d (want 400), body=%s", w.Code, w.Body.String())
	}
}

// The embedded evidence must bind the SAME claims the request carries. A CSR
// whose RA-TLS report binds a different claims set (so the leaf would never
// verify at a relying party) must be rejected at issuance, not later.
func TestAttest_WorkloadClaims_RejectsMismatchedEmbeddedBinding(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.AllowlistStore = fakeStore{wlDigestA: true, wlDigestB: true}

	sent := claimsDERFor(t, nil, []string{wlDigestA})
	otherBinding := claimsDERFor(t, nil, []string{wlDigestB}) // CSR binds a different claim
	w := postAttestClaimsWithCSR(t, h, issueChallenge(t, h), csrWithBoundClaims(t, otherBinding), sent, nil, []string{wlDigestA})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d (want 400), body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_WorkloadClaims_RejectsUnallowlistedImage(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.AllowlistStore = fakeStore{wlDigestA: true} // B not allowed

	digests := []string{wlDigestA, wlDigestB}
	w := postAttestClaims(t, h, issueChallenge(t, h), claimsDERFor(t, nil, digests), nil, digests)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d (want 403), body=%s", w.Code, w.Body.String())
	}
}

// The container-digest list is untrusted until CDS confirms it hashes to the
// evidence-bound workload digest. A list that doesn't match the claim must be
// rejected even if every listed image is allowlisted.
func TestAttest_WorkloadClaims_RejectsListNotMatchingClaim(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.AllowlistStore = fakeStore{wlDigestA: true, wlDigestB: true}

	claimsDER := claimsDERFor(t, nil, []string{wlDigestA}) // claim commits to main A only
	w := postAttestClaims(t, h, issueChallenge(t, h), claimsDER, nil, []string{wlDigestA, wlDigestB})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d (want 403), body=%s", w.Code, w.Body.String())
	}
}

func TestAttest_WorkloadClaims_RejectsWhenNoStoreWired(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h := newTestAttestHandler(t, mock.URL, nil) // AllowlistStore nil

	digests := []string{wlDigestA}
	w := postAttestClaims(t, h, issueChallenge(t, h), claimsDERFor(t, nil, digests), nil, digests)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d (want 403), body=%s", w.Code, w.Body.String())
	}
}

// A workload claim carrying non-sentinel operator-keys/seed digests must be
// rejected, so a CDS-issued leaf can never assert forged allowlist governance.
func TestAttest_WorkloadClaims_RejectsForgedGovernanceFields(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.AllowlistStore = fakeStore{wlDigestA: true}

	digests := []string{wlDigestA}
	mainCs := asContainers(digests...)
	wd, err := workloadclaims.Digest(nil, digests)
	if err != nil {
		t.Fatal(err)
	}
	ad, err := workloadclaims.ArgsDigest(nil, mainCs)
	if err != nil {
		t.Fatal(err)
	}
	// Valid workload digests, but attacker-chosen governance fields.
	forged := &ratls.ConfigClaims{
		OperatorKeysDigest: bytes.Repeat([]byte{0xEE}, ratls.ClaimsDigestSize),
		SeedDigest:         bytes.Repeat([]byte{0xDD}, ratls.ClaimsDigestSize),
		WorkloadDigest:     wd,
		WorkloadArgsDigest: ad,
	}
	ext, err := forged.MarshalExtension()
	if err != nil {
		t.Fatal(err)
	}
	w := postAttestClaims(t, h, issueChallenge(t, h), ext.Value, nil, digests)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d (want 403), body=%s", w.Code, w.Body.String())
	}
}

// CDS re-derives the role-partitioned digest, so a request that swaps the
// init/main split of the same images (claim built for init:A/main:B, but the
// lists sent as init:B/main:A) must fail even though both images are
// allowlisted.
func TestAttest_WorkloadClaims_RejectsSwappedRoleSplit(t *testing.T) {
	mock := newMockAttestationApi(t, "deadbeef")
	h := newTestAttestHandler(t, mock.URL, nil)
	h.AllowlistStore = fakeStore{wlDigestA: true, wlDigestB: true}

	claimsDER := claimsDERFor(t, []string{wlDigestA}, []string{wlDigestB}) // init:A, main:B
	// Lists sent with the roles swapped.
	w := postAttestClaims(t, h, issueChallenge(t, h), claimsDER, []string{wlDigestB}, []string{wlDigestA})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d (want 403), body=%s", w.Code, w.Body.String())
	}
}

func mustCSR(t *testing.T) string {
	t.Helper()
	csr, _ := generateCSR(t)
	return csr
}
