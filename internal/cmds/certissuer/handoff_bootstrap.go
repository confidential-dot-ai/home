package certissuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/ratls"
)

// handoffBootstrap generates the cert-issuer's handoff signer key in process,
// gets a TEE attestation report binding it via the local attestation service,
// and exchanges that for an EAR with Assam's /attest-key endpoint over RA-TLS.
//
// The result is what the handoff handler needs: an in-memory signer key plus
// a refreshing EAR source. There are no operator-supplied key files; the
// alternative would be mounting a Secret-backed PEM into the cert-issuer pod,
// which contradicts the chart-managed CVM design ("CA private material never
// passes through Kubernetes Secrets" — see docs/THREAT_MODEL.md).
type handoffBootstrap struct {
	signer    *ecdsa.PrivateKey
	earSource *atomicHandoffEAR

	assamClient           attestclient.Client
	attestationServiceURL string
}

// atomicHandoffEAR is a handoffEARSource backed by an atomic.Value so the
// refresher goroutine can swap the token without locking the request path.
type atomicHandoffEAR struct {
	v atomic.Value // string
}

func (a *atomicHandoffEAR) Current() (string, error) {
	if v, _ := a.v.Load().(string); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("handoff EAR not yet bootstrapped")
}

func (a *atomicHandoffEAR) set(token string) {
	a.v.Store(token)
}

// newHandoffBootstrap generates the handoff signer key and prepares the
// RA-TLS client to Assam. It does NOT call /attest-key — that happens in the
// runRefresh loop, so cert-issuer can start independently of Assam's
// reachability. The /handoff endpoint stays registered but returns 503
// (via the EAR source's not-yet-ready error) until the first refresh
// succeeds.
func newHandoffBootstrap(assamURL, attestationServiceURL string, assamMeasurements [][]byte) (*handoffBootstrap, error) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate handoff signer key: %w", err)
	}
	httpClient, err := ratls.NewVerifyingHTTPClient(assamMeasurements, attestationServiceURL)
	if err != nil {
		return nil, err
	}
	return &handoffBootstrap{
		signer:                signer,
		earSource:             &atomicHandoffEAR{},
		assamClient:           attestclient.NewClientWithHTTP(assamURL, httpClient),
		attestationServiceURL: attestationServiceURL,
	}, nil
}

// runRefresh runs the initial /attest-key call and then re-attests the
// handoff signer key on a schedule keyed off the current EAR's expiry.
// Refreshes happen at half the remaining validity so a single failed attempt
// has another chance before workloads see expired tokens.
//
// The first iteration is the initial bootstrap. Until it succeeds the EAR
// source returns "not yet bootstrapped" and HandleHandoff returns 503.
// Failures during refresh keep the previous EAR (if any) serving — the
// handler keeps working until that EAR's exp passes.
func (h *handoffBootstrap) runRefresh(ctx context.Context, logger *slog.Logger) {
	pubDER, err := x509.MarshalPKIXPublicKey(&h.signer.PublicKey)
	if err != nil {
		logger.Error("handoff refresher: marshal pubkey", "error", err)
		return
	}

	for {
		refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		token, err := h.assamClient.AttestKey(refreshCtx, h.attestationServiceURL, pubDER)
		cancel()
		if err != nil {
			if _, haveCurrent := h.earSource.Current(); haveCurrent != nil {
				logger.Warn("handoff bootstrap: attest-key failed; will retry", "error", err)
			} else {
				logger.Warn("handoff refresh: attest-key failed; keeping previous EAR", "error", err)
			}
		} else {
			h.earSource.set(token)
			if _, haveCurrent := h.earSource.Current(); haveCurrent == nil {
				logger.Info("handoff EAR refreshed")
			}
		}

		current, _ := h.earSource.Current()
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextRefreshAfter(current)):
		}
	}
}

// nextRefreshAfter returns the duration until the next refresh attempt for
// the supplied token. Half the remaining validity, clamped to a sane band so
// we don't hammer Assam on every tick when the token is brand new and don't
// sleep forever on a malformed token.
func nextRefreshAfter(token string) time.Duration {
	const (
		minRefresh = 30 * time.Second
		maxRefresh = 1 * time.Hour
	)
	if token == "" {
		return minRefresh
	}
	exp, err := handoffEARExpiry(token)
	if err != nil {
		return minRefresh
	}
	remaining := time.Until(exp)
	if remaining <= 0 {
		return minRefresh
	}
	d := remaining / 2
	if d < minRefresh {
		return minRefresh
	}
	if d > maxRefresh {
		return maxRefresh
	}
	return d
}
