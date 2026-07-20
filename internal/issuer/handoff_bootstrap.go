package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// HandoffEARSource produces CDS's own EAR token that handoff responses sign
// over. Implementations must be safe for concurrent reads.
type HandoffEARSource interface {
	// Current returns the compact-serialized EAR. Callers retransmit it
	// verbatim — the JWS signature covers these exact bytes, so it must not be
	// decoded and re-encoded on the way out.
	Current() (string, error)
	// ExpiresAt returns the stored token's exp claim. Implementations derive it
	// when the token is stored so that refresh scheduling and the expiry gauge
	// do not each re-parse the same unchanging token on every read.
	ExpiresAt() (time.Time, error)
}

// handoffEAR pairs the wire-format token with the expiry read out of it at
// store time. Kept together in one atomic.Value so a reader can never observe
// a token with another token's expiry.
type handoffEAR struct {
	raw string
	exp time.Time
}

// AtomicHandoffEAR is a HandoffEARSource backed by an atomic.Value so the
// refresher goroutine can swap the token without locking the request path.
type AtomicHandoffEAR struct {
	v atomic.Value // handoffEAR
}

func (a *AtomicHandoffEAR) Current() (string, error) {
	if v, _ := a.v.Load().(handoffEAR); v.raw != "" {
		return v.raw, nil
	}
	return "", fmt.Errorf("handoff EAR not yet bootstrapped")
}

func (a *AtomicHandoffEAR) ExpiresAt() (time.Time, error) {
	if v, _ := a.v.Load().(handoffEAR); v.raw != "" {
		return v.exp, nil
	}
	return time.Time{}, fmt.Errorf("handoff EAR not yet bootstrapped")
}

// Set stores the token, reading its expiry once here rather than on every
// read. A token whose exp cannot be read is rejected instead of stored, so
// Current never hands out material the refresh loop cannot schedule against.
func (a *AtomicHandoffEAR) Set(token string) error {
	exp, err := unverifiedEARExpiry(token)
	if err != nil {
		return fmt.Errorf("store handoff EAR: %w", err)
	}
	a.v.Store(handoffEAR{raw: token, exp: exp})
	return nil
}

var _ HandoffEARSource = (*AtomicHandoffEAR)(nil)

// HandoffBootstrap provisions the handoff signer key + a refreshing EAR source
// that the handoff handler needs. CDS implements it in process via
// NewLocalHandoffBootstrap (it is its own EAR issuer); the signer key lives in
// process memory only, never an operator-supplied file or Kubernetes Secret.
type HandoffBootstrap interface {
	Signer() *ecdsa.PrivateKey
	EARSource() HandoffEARSource
	RunRefresh(ctx context.Context, logger *slog.Logger)
}

// LocalEARMinter mints an EAR over a TEE-attested ECDSA public key. It is the
// EAR-issuance half of the attestation /attest-key flow, used by CDS to
// self-provision its handoff signer EAR in process — CDS is its own EAR issuer,
// so there is no external service to dial for it.
type LocalEARMinter interface {
	IssueAttestedKey(submodsEvidence json.RawMessage, launchDigest string, teePubKey *ecdsa.PublicKey, operatorKeysHash string) (string, error)
}

// AttestationApi is the attestation-api client the bootstrap drives:
// Attest produces a TEE report binding reportData, Verify checks the report's
// signature and report-data and returns the launch digest. *attestationclient.Client
// satisfies it, so the same client used elsewhere in CDS is reused here.
type AttestationApi interface {
	Attest(ctx context.Context, req types.AttestRequest) (types.AttestResponse, error)
	Verify(ctx context.Context, req types.VerifyRequest) (types.VerifyResponse, error)
}

type localHandoffBootstrap struct {
	signer    *ecdsa.PrivateKey
	earSource *AtomicHandoffEAR

	attestation AttestationApi
	minter      LocalEARMinter

	operatorKeysHash string
}

var _ HandoffBootstrap = (*localHandoffBootstrap)(nil)

// NewLocalHandoffBootstrap generates the handoff signer key and prepares an
// in-process attest-key flow against the local attestation-api. It issues
// the EAR with the supplied minter (CDS's own EAR issuer) in process — there is
// no RA-TLS hop and no remote measurement to pin, because the evidence is
// verified and the EAR signed inside the CDS trust boundary.
func NewLocalHandoffBootstrap(attestation AttestationApi, minter LocalEARMinter, operatorKeysHash string) (HandoffBootstrap, error) {
	if attestation == nil || minter == nil {
		return nil, fmt.Errorf("local handoff bootstrap requires an attestation-api and EAR minter")
	}
	if err := operatorauth.ValidateKeySetHash(operatorKeysHash); err != nil {
		return nil, fmt.Errorf("local handoff bootstrap requires an operator-key policy: %w", err)
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate handoff signer key: %w", err)
	}
	return &localHandoffBootstrap{
		signer:           signer,
		earSource:        &AtomicHandoffEAR{},
		attestation:      attestation,
		minter:           minter,
		operatorKeysHash: operatorKeysHash,
	}, nil
}

func (h *localHandoffBootstrap) Signer() *ecdsa.PrivateKey { return h.signer }

func (h *localHandoffBootstrap) EARSource() HandoffEARSource { return h.earSource }

// RunRefresh runs an initial bootstrap attempt followed by re-attestation keyed
// off the current EAR's expiry. The /handoff endpoint returns 503 until the
// first attestKey succeeds.
func (h *localHandoffBootstrap) RunRefresh(ctx context.Context, logger *slog.Logger) {
	pubDER, err := x509.MarshalPKIXPublicKey(&h.signer.PublicKey)
	if err != nil {
		logger.Error("handoff refresher: marshal pubkey", "error", err)
		return
	}

	for {
		refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		token, err := h.attestKey(refreshCtx, pubDER)
		cancel()
		if err != nil {
			if _, curErr := h.earSource.Current(); curErr != nil {
				logger.Warn("handoff bootstrap: local attest-key failed; will retry", "error", err)
			} else {
				logger.Warn("handoff refresh: local attest-key failed; keeping previous EAR", "error", err)
			}
		} else if err := h.earSource.Set(token); err != nil {
			logger.Warn("handoff refresh: minted EAR is unreadable; keeping previous EAR", "error", err)
		} else {
			logger.Info("handoff EAR refreshed (local)")
		}

		// No readable token yet: retry on the short floor rather than sleeping
		// on an expiry we don't have.
		delay := minHandoffRefresh
		if exp, err := h.earSource.ExpiresAt(); err == nil {
			delay = nextRefreshAfter(exp)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// attestKey runs the /attest-key flow in process: generate evidence binding the
// signer pubkey to a report, verify the report's signature and report-data
// match, then mint the EAR over the verified launch digest.
//
// INVARIANT: the EAR is minted only after attestationclient.EnforceVerdict
// confirms SignatureValid and ReportDataMatch — the same gate the HTTP
// /attest-key handler enforces. We verify even though CDS produced the
// evidence: the verifier supplies the launch digest claim, and skipping
// verification would let a host-supplied evidence blob set the EAR's launch
// digest.
func (h *localHandoffBootstrap) attestKey(ctx context.Context, pubDER []byte) (string, error) {
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return "", fmt.Errorf("parse signer pubkey: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("signer pubkey is not ECDSA")
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return "", fmt.Errorf("generate challenge: %w", err)
	}
	reportData, err := ratls.ReportDataForKeyWithContext(ecPub, challenge, []byte(h.operatorKeysHash))
	if err != nil {
		return "", err
	}

	reportDataDigest := reportData[:sha512.Size384]
	asResp, err := h.attestation.Attest(ctx, types.AttestRequest{
		ReportData: types.NewBase64Bytes(reportDataDigest),
		Platform:   types.PlatformAuto,
	})
	if err != nil {
		return "", fmt.Errorf("generate evidence: %w", err)
	}

	verifyReq := types.VerifyReportData(
		types.AttestationEvidence(asResp),
		types.NewBase64Bytes(reportDataDigest),
	)
	verifyResp, err := h.attestation.Verify(ctx, verifyReq)
	if err != nil {
		return "", fmt.Errorf("verify evidence: %w", err)
	}
	if err := attestationclient.EnforceVerdict(verifyReq, verifyResp); err != nil {
		return "", fmt.Errorf("verify evidence: %w", err)
	}

	evidenceJSON, err := json.Marshal(asResp)
	if err != nil {
		return "", fmt.Errorf("marshal evidence for EAR: %w", err)
	}
	return h.minter.IssueAttestedKey(json.RawMessage(evidenceJSON), verifyResp.Result.Claims.LaunchDigest, ecPub, h.operatorKeysHash)
}

// unverifiedEARExpiry returns the EAR token's exp claim WITHOUT verifying the
// signature. It is deliberately unexported and deliberately named: the only
// safe input is a token this process minted itself, where the expiry drives
// local refresh scheduling and an operator-facing gauge. Never call it on a
// token received from a peer — those go through ValidateEARToken, which checks
// signature, issuer, and validity window before any claim is trusted.
func unverifiedEARExpiry(token string) (time.Time, error) {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return time.Time{}, fmt.Errorf("parse JWT claims: %w", err)
	}
	exp, err := claims.GetExpirationTime()
	if err != nil {
		return time.Time{}, fmt.Errorf("read JWT exp claim: %w", err)
	}
	if exp == nil || exp.IsZero() || exp.Unix() == 0 {
		return time.Time{}, fmt.Errorf("JWT missing exp claim")
	}
	return exp.Time, nil
}

const (
	minHandoffRefresh = 30 * time.Second
	maxHandoffRefresh = 1 * time.Hour
)

// nextRefreshAfter returns the duration until the next refresh attempt for a
// token expiring at exp. Half the remaining validity, clamped to a sane band
// so we don't re-attest on every tick when the token is brand new and don't
// sleep past the expiry of a long-lived one.
func nextRefreshAfter(exp time.Time) time.Duration {
	remaining := time.Until(exp)
	if remaining <= 0 {
		return minHandoffRefresh
	}
	d := remaining / 2
	if d < minHandoffRefresh {
		return minHandoffRefresh
	}
	if d > maxHandoffRefresh {
		return maxHandoffRefresh
	}
	return d
}
