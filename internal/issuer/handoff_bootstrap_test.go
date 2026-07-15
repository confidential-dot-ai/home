package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// TestNextRefreshAfter exercises the refresh-cadence math without touching
// any network state. Each branch matters: a brand-new token (no exp yet)
// must not stall the loop; a token with very long TTL must be capped so we
// don't sleep through cluster events; an expired or malformed token must
// retry quickly.
func TestNextRefreshAfter(t *testing.T) {
	cases := []struct {
		name       string
		token      func(t *testing.T) string
		wantApprox time.Duration
		tolerance  time.Duration
	}{
		{
			name:       "empty token",
			token:      func(*testing.T) string { return "" },
			wantApprox: 30 * time.Second,
			tolerance:  time.Second,
		},
		{
			name:       "malformed token",
			token:      func(*testing.T) string { return "not.a.jwt" },
			wantApprox: 30 * time.Second,
			tolerance:  time.Second,
		},
		{
			name: "expired token",
			token: func(t *testing.T) string {
				return makeUnsignedJWTForTest(t, time.Now().Add(-time.Minute).Unix())
			},
			wantApprox: 30 * time.Second,
			tolerance:  time.Second,
		},
		{
			name: "long-TTL token capped at maxRefresh",
			token: func(t *testing.T) string {
				return makeUnsignedJWTForTest(t, time.Now().Add(48*time.Hour).Unix())
			},
			wantApprox: time.Hour,
			tolerance:  time.Second,
		},
		{
			name: "ordinary TTL halved",
			token: func(t *testing.T) string {
				return makeUnsignedJWTForTest(t, time.Now().Add(20*time.Minute).Unix())
			},
			wantApprox: 10 * time.Minute,
			tolerance:  2 * time.Second,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := nextRefreshAfter(c.token(t))
			if got < c.wantApprox-c.tolerance || got > c.wantApprox+c.tolerance {
				t.Fatalf("nextRefreshAfter = %v, want ≈ %v", got, c.wantApprox)
			}
		})
	}
}

// TestAtomicHandoffEARRoundTrip confirms the basic invariants the refresh
// loop and the request handler depend on: an unset source returns an
// error, a set source returns the token, set is observable atomically, and
// concurrent readers/writers don't tear.
func TestAtomicHandoffEARRoundTrip(t *testing.T) {
	a := &AtomicHandoffEAR{}
	if _, err := a.Current(); err == nil {
		t.Fatal("expected unset source to return error")
	}
	a.Set("token-1")
	got, err := a.Current()
	if err != nil {
		t.Fatalf("Current after set: %v", err)
	}
	if got != "token-1" {
		t.Fatalf("Current = %q, want token-1", got)
	}

	// Concurrent set + Current — race detector catches sliced reads.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = a.Current()
				}
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		a.Set(fmt.Sprintf("token-%d", i))
	}
	close(stop)
	wg.Wait()
}

// --- LocalHandoffBootstrap (cds in-process attest-key) ---

type stubAttestation struct {
	attestResp types.AttestResponse
	attestErr  error
	verifyResp types.VerifyResponse
	verifyErr  error
}

func (s stubAttestation) Attest(context.Context, types.AttestRequest) (types.AttestResponse, error) {
	return s.attestResp, s.attestErr
}

func (s stubAttestation) Verify(context.Context, types.VerifyRequest) (types.VerifyResponse, error) {
	return s.verifyResp, s.verifyErr
}

type stubMinter struct {
	called              atomic.Int32
	gotDigest           string
	gotPub              *ecdsa.PublicKey
	gotOperatorKeysHash string
	tokenToIssue        string
}

func (m *stubMinter) IssueAttestedKey(_ json.RawMessage, launchDigest string, pub *ecdsa.PublicKey, operatorKeysHash string) (string, error) {
	m.called.Add(1)
	m.gotDigest = launchDigest
	m.gotPub = pub
	m.gotOperatorKeysHash = operatorKeysHash
	return m.tokenToIssue, nil
}

const testOperatorKeysHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func verifyOK(match bool, digest string) types.VerifyResponse {
	return types.VerifyResponse{Result: types.VerificationResult{
		SignatureValid:  true,
		ReportDataMatch: &match,
		Claims:          types.Claims{LaunchDigest: digest},
	}}
}

// TestLocalHandoffBootstrapMintsOnlyAfterVerify is the load-bearing test for
// the cds-local handoff signer EAR: it must mint exactly when the verifier
// confirms both SignatureValid and ReportDataMatch, and must refuse otherwise.
// Skipping verification would let a host-supplied evidence blob dictate the
// EAR's launch digest — the value /handoff peers pin against.
func TestLocalHandoffBootstrapMintsOnlyAfterVerify(t *testing.T) {
	cases := []struct {
		name     string
		verify   types.VerifyResponse
		wantMint bool
	}{
		{"signature valid + report-data match", verifyOK(true, "deadbeef"), true},
		{"signature invalid", types.VerifyResponse{Result: types.VerificationResult{SignatureValid: false}}, false},
		{"report-data mismatch", verifyOK(false, "deadbeef"), false},
		{"report-data nil", types.VerifyResponse{Result: types.VerificationResult{SignatureValid: true}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			minter := &stubMinter{tokenToIssue: "minted-ear"}
			b, err := NewLocalHandoffBootstrap(
				stubAttestation{
					attestResp: types.AttestResponse{Platform: "snp"},
					verifyResp: tc.verify,
				},
				minter,
				testOperatorKeysHash,
			)
			if err != nil {
				t.Fatalf("NewLocalHandoffBootstrap: %v", err)
			}
			lb := b.(*localHandoffBootstrap)
			pubDER, err := x509.MarshalPKIXPublicKey(&lb.signer.PublicKey)
			if err != nil {
				t.Fatalf("marshal pubkey: %v", err)
			}

			token, err := lb.attestKey(context.Background(), pubDER)
			if tc.wantMint {
				if err != nil {
					t.Fatalf("attestKey: %v", err)
				}
				if token != "minted-ear" {
					t.Fatalf("token = %q, want minted-ear", token)
				}
				if minter.called.Load() != 1 {
					t.Fatalf("minter calls = %d, want 1", minter.called.Load())
				}
				if minter.gotDigest != "deadbeef" {
					t.Fatalf("launch digest = %q, want deadbeef", minter.gotDigest)
				}
				if minter.gotPub == nil || !minter.gotPub.Equal(&lb.signer.PublicKey) {
					t.Fatalf("minted EAR not bound to the signer pubkey")
				}
				if minter.gotOperatorKeysHash != testOperatorKeysHash {
					t.Fatalf("operator key-set hash = %q, want %q", minter.gotOperatorKeysHash, testOperatorKeysHash)
				}
			} else {
				if err == nil {
					t.Fatalf("expected attestKey to refuse, got token %q", token)
				}
				if minter.called.Load() != 0 {
					t.Fatalf("minter called %d times on a failed verify; must be 0", minter.called.Load())
				}
			}
		})
	}
}

// TestLocalHandoffBootstrapRequiresDeps guards the constructor's nil checks: a
// nil attestation-api or minter is a wiring bug that must fail loudly at
// startup, not silently disable handoff.
func TestLocalHandoffBootstrapRequiresDeps(t *testing.T) {
	as := stubAttestation{}
	mi := &stubMinter{}
	for _, tc := range []struct {
		name string
		as   AttestationApi
		mi   LocalEARMinter
	}{
		{"nil attestation", nil, mi},
		{"nil minter", as, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewLocalHandoffBootstrap(tc.as, tc.mi, testOperatorKeysHash); err == nil {
				t.Fatal("expected constructor to reject nil dependency")
			}
		})
	}
	if _, err := NewLocalHandoffBootstrap(as, mi, ""); err == nil {
		t.Fatal("expected constructor to reject an empty operator key-set hash")
	}
}

func makeUnsignedJWTForTest(t *testing.T, exp int64) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	claims := fmt.Sprintf(`{"exp":%d,"iat":0}`, exp)
	body := base64.RawURLEncoding.EncodeToString([]byte(claims))
	// Signature is irrelevant for handoffEARExpiry — it parses claims only.
	return header + "." + body + ".sig"
}
