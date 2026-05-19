package certissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lunal-dev/c8s/internal/earclaims"
	"github.com/lunal-dev/c8s/pkg/attestclient"
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
	a := &atomicHandoffEAR{}
	if _, err := a.Current(); err == nil {
		t.Fatal("expected unset source to return error")
	}
	a.set("token-1")
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
		a.set(fmt.Sprintf("token-%d", i))
	}
	close(stop)
	wg.Wait()
}

// TestHandoffBootstrapPopulatesEAROnSuccess walks the runRefresh loop once
// against a fake Assam and confirms the EAR source goes from
// not-yet-bootstrapped to populated. We construct the bootstrap struct by
// hand with a plain http.Client (the production path uses an RA-TLS
// transport; that's covered by the chart_test + ratls_test pair, not here).
func TestHandoffBootstrapPopulatesEAROnSuccess(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	calls := atomic.Int32{}
	srv := fakeAssamForBootstrap(t, signer, &calls, nil)
	defer srv.Close()

	boot := &handoffBootstrap{
		signer:                signer,
		earSource:             &atomicHandoffEAR{},
		assamClient:           attestclient.NewClientWithHTTP(srv.URL, srv.Client()),
		attestationServiceURL: srv.URL,
	}
	if _, err := boot.earSource.Current(); err == nil {
		t.Fatal("EAR source should not be ready before runRefresh runs")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go boot.runRefresh(ctx, slog.Default())

	waitFor(t, func() bool {
		_, err := boot.earSource.Current()
		return err == nil
	}, 2*time.Second, "EAR source bootstrapped")
	if got := calls.Load(); got < 1 {
		t.Fatalf("expected at least 1 attest-key call, got %d", got)
	}
}

// TestHandoffBootstrapRetriesAfterTransientFailure proves the loop survives
// a failing Assam: first request 500s, the next succeeds, the EAR source
// observes the eventually-good token. Without this behaviour cert-issuer
// would silently never recover from a single bad attest-key.
func TestHandoffBootstrapRetriesAfterTransientFailure(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	calls := atomic.Int32{}
	srv := fakeAssamForBootstrap(t, signer, &calls, func(call int32) bool {
		// Fail the first attest-key request, succeed afterwards.
		return call == 1
	})
	defer srv.Close()

	boot := &handoffBootstrap{
		signer:                signer,
		earSource:             &atomicHandoffEAR{},
		assamClient:           attestclient.NewClientWithHTTP(srv.URL, srv.Client()),
		attestationServiceURL: srv.URL,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	go boot.runRefresh(ctx, slog.Default())

	// nextRefreshAfter("") is 30s, so the second attempt happens ~30s after
	// the first failure. Allow up to 60s to cover slow CI.
	waitFor(t, func() bool {
		_, err := boot.earSource.Current()
		return err == nil
	}, 60*time.Second, "EAR source bootstrapped after transient failure")
	if got := calls.Load(); got < 2 {
		t.Fatalf("expected at least 2 attest-key calls, got %d", got)
	}
}

// fakeAssamForBootstrap stands up a minimal Assam stub that handles
// /authenticate, /attest, and /attest-key. shouldFail, when non-nil, is
// invoked with the per-call counter (1-indexed) and may force a 500 to
// exercise retry paths.
func fakeAssamForBootstrap(t *testing.T, _ *ecdsa.PrivateKey, calls *atomic.Int32, shouldFail func(int32) bool) *httptest.Server {
	t.Helper()

	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test signer: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		challenge := make([]byte, 32)
		_, _ = io.ReadFull(rand.Reader, challenge)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"challenge": base64.StdEncoding.EncodeToString(challenge),
		})
	})
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"platform": "snp",
			"evidence": json.RawMessage(`{"quote":"abc"}`),
		})
	})
	mux.HandleFunc("/attest-key", func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if shouldFail != nil && shouldFail(n) {
			http.Error(w, "transient", http.StatusInternalServerError)
			return
		}
		now := time.Now().Unix()
		token, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			earclaims.Issuer:    "assam",
			earclaims.IssuedAt:  now,
			earclaims.ExpiresAt: now + 60,
		}).SignedString(signKey)
		if err != nil {
			t.Fatalf("sign test EAR: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ear": token})
	})
	return httptest.NewServer(mux)
}

func makeUnsignedJWTForTest(t *testing.T, exp int64) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	claims := fmt.Sprintf(`{"exp":%d,"iat":0}`, exp)
	body := base64.RawURLEncoding.EncodeToString([]byte(claims))
	// Signature is irrelevant for handoffEARExpiry — it parses claims only.
	return header + "." + body + ".sig"
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
