package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// DefaultPullRetryInterval is the fixed cadence between transient-failure
// retries when PullConfig.RetryInterval is zero.
const DefaultPullRetryInterval = 2 * time.Second

// AttestKeyClient obtains a TEE-bound EAR for a caller-generated key from a
// CDS peer's /attest-key. *attestclient.Client satisfies it.
type AttestKeyClient interface {
	AttestKeyWithOperatorKeysHash(ctx context.Context, attestationApiURL string, pubKeyDER []byte, operatorKeysHash string) (string, error)
}

// PullConfig carries everything PullHandoff needs. Peer identity lives in one
// place (PeerURL + Attest, both dialing the peer) so a multi-peer caller
// cannot mint an EAR at one peer and pull from another.
type PullConfig struct {
	// Deps verifies the peer's handoff EAR (JWKS key provider, expected
	// issuer, allowed measurements).
	Deps HandoffClientDeps
	// Attest mints the requester EAR from the peer's /attest-key.
	Attest AttestKeyClient
	// PeerURL is the CDS peer's https base URL (/handoff, /ca).
	PeerURL string
	// AttestationApiURL is the local attestation-api used for evidence.
	AttestationApiURL string
	// HTTPClient is the RA-TLS-verifying client for the peer.
	HTTPClient *http.Client
	// Logger is optional; nil uses slog.Default().
	Logger *slog.Logger
	// RetryInterval is the fixed cadence between transient-failure retries;
	// zero uses DefaultPullRetryInterval.
	RetryInterval time.Duration
}

// PullOutcome classifies a pull error so retry and exit-code decisions come
// from one place instead of two drifting ladders.
type PullOutcome int

const (
	// PullOK means no error.
	PullOK PullOutcome = iota
	// PullTransient is a retryable failure: transport errors, 5xx, and 429
	// rate limiting (the peer rolling, throttling, or still bootstrapping
	// its handoff EAR).
	PullTransient
	// PullDenied is a definitive attestation/verification failure: the
	// peer's RA-TLS measurement did not match, or its handoff EAR failed
	// validation. Retrying cannot help.
	PullDenied
	// PullDisabled means the peer does not serve /handoff (404): an
	// availability/config problem, not a verification verdict. Retrying the
	// same peer cannot help, but it is not a failed handshake.
	PullDisabled
	// PullFatal is any other definitive failure (4xx that is not 429/404, a
	// local/config error).
	PullFatal
)

// ClassifyPullError maps a pull error to a PullOutcome. It is the single
// source of truth for "should this retry" and "is this a verdict".
func ClassifyPullError(err error) PullOutcome {
	if err == nil {
		return PullOK
	}
	// An RA-TLS measurement/attestation denial surfaces from the TLS
	// handshake as a CertificateVerificationError inside a *url.Error;
	// check it before the generic transport case.
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return PullDenied
	}
	if s, ok := pullErrorStatus(err); ok {
		switch {
		case s == http.StatusTooManyRequests || s >= 500:
			return PullTransient
		case s == http.StatusNotFound:
			return PullDisabled
		default:
			return PullFatal
		}
	}
	// A bare transport error (connection refused during a peer restart, dial
	// timeout) is transient.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return PullTransient
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return PullTransient
	}
	return PullFatal
}

// pullErrorStatus extracts an HTTP status from the typed errors the pull
// stages return: the peer's /handoff and /attest-key responses
// (*HandoffStatusError, *attestclient.StatusError) and the local
// attestation-api (*attestationclient.APIError, *attestationclient.UnexpectedError).
func pullErrorStatus(err error) (int, bool) {
	var handoffErr *HandoffStatusError
	if errors.As(err, &handoffErr) {
		return handoffErr.Status, true
	}
	var statusErr *attestclient.StatusError
	if errors.As(err, &statusErr) {
		return statusErr.Status, true
	}
	var apiErr *attestationclient.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status, true
	}
	var unexpErr *attestationclient.UnexpectedError
	if errors.As(err, &unexpErr) {
		return unexpErr.Status, true
	}
	return 0, false
}

// PullHandoff drives the requester side of the handoff protocol end to end:
// a fresh in-memory requester signing key, a TEE-bound EAR for that key from
// the peer's /attest-key, then the CA material via /handoff. RequestHandoff
// separately creates a one-request X25519 recipient key for encryption;
// neither ephemeral key is the CA private key returned inside the encrypted
// material. Each stage retries transient failures (transport, 5xx, 429) until
// ctx is done — /handoff
// returns 503 while the peer's handoff EAR bootstraps — and the EAR is
// obtained once, not per attempt, so retries do not redo TEE report
// generation. A denial or other 4xx is a definitive verdict and fails fast.
func PullHandoff(ctx context.Context, cfg PullConfig) (*HandoffMaterial, error) {
	if cfg.Attest == nil {
		return nil, fmt.Errorf("handoff pull requires an attest-key client")
	}
	if err := operatorauth.ValidateKeySetHash(cfg.Deps.OperatorKeysHash); err != nil {
		return nil, fmt.Errorf("handoff pull requires an operator-key policy: %w", err)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	interval := cfg.RetryInterval
	if interval <= 0 {
		interval = DefaultPullRetryInterval
	}

	requesterSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate handoff requester signing key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&requesterSigningKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal handoff requester signing public key: %w", err)
	}

	ear, err := PullRetry(ctx, logger, interval, "attest-key", func() (string, error) {
		return cfg.Attest.AttestKeyWithOperatorKeysHash(ctx, cfg.AttestationApiURL, pubDER, cfg.Deps.OperatorKeysHash)
	})
	if err != nil {
		return nil, fmt.Errorf("attest-key: %w", err)
	}

	return PullRetry(ctx, logger, interval, "handoff", func() (*HandoffMaterial, error) {
		return RequestHandoff(ctx, cfg.Deps, cfg.PeerURL, ear, requesterSigningKey, cfg.HTTPClient)
	})
}

// PullRetry retries op while ClassifyPullError reports PullTransient, on a
// fixed cadence until ctx is done, returning the last error.
func PullRetry[T any](ctx context.Context, logger *slog.Logger, interval time.Duration, stage string, op func() (T, error)) (T, error) {
	for {
		v, err := op()
		if ClassifyPullError(err) != PullTransient {
			return v, err
		}
		logger.Warn("handoff pull attempt failed; retrying",
			"stage", stage, "retry_in", interval, "error", err)
		select {
		case <-ctx.Done():
			return v, err
		case <-time.After(interval):
		}
	}
}
