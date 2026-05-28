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

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/types"
)

// HandoffEARSource produces CDS's own EAR token that handoff responses sign
// over. Implementations must be safe for concurrent reads.
type HandoffEARSource interface {
	Current() (string, error)
}

// AtomicHandoffEAR is a HandoffEARSource backed by an atomic.Value so the
// refresher goroutine can swap the token without locking the request path.
type AtomicHandoffEAR struct {
	v atomic.Value // string
}

func (a *AtomicHandoffEAR) Current() (string, error) {
	if v, _ := a.v.Load().(string); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("handoff EAR not yet bootstrapped")
}

func (a *AtomicHandoffEAR) Set(token string) {
	a.v.Store(token)
}

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
	IssueWithLaunchDigestAndPubKey(submodsEvidence json.RawMessage, launchDigest string, teePubKey *ecdsa.PublicKey) (string, error)
}

// AttestationService is the attestation-service client the bootstrap drives:
// Attest produces a TEE report binding reportData, Verify checks the report's
// signature and report-data and returns the launch digest. *attestationclient.Client
// satisfies it, so the same client used elsewhere in CDS is reused here.
type AttestationService interface {
	Attest(ctx context.Context, req types.AttestRequest) (types.AttestResponse, error)
	Verify(ctx context.Context, req types.VerifyRequest) (types.VerifyResponse, error)
}

type localHandoffBootstrap struct {
	signer    *ecdsa.PrivateKey
	earSource *AtomicHandoffEAR

	attestation AttestationService
	minter      LocalEARMinter
}

var _ HandoffBootstrap = (*localHandoffBootstrap)(nil)

// NewLocalHandoffBootstrap generates the handoff signer key and prepares an
// in-process attest-key flow against the local attestation service. It issues
// the EAR with the supplied minter (CDS's own EAR issuer) in process — there is
// no RA-TLS hop and no remote measurement to pin, because the evidence is
// verified and the EAR signed inside the CDS trust boundary.
func NewLocalHandoffBootstrap(attestation AttestationService, minter LocalEARMinter) (HandoffBootstrap, error) {
	if attestation == nil || minter == nil {
		return nil, fmt.Errorf("local handoff bootstrap requires an attestation service and EAR minter")
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate handoff signer key: %w", err)
	}
	return &localHandoffBootstrap{
		signer:      signer,
		earSource:   &AtomicHandoffEAR{},
		attestation: attestation,
		minter:      minter,
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
		} else {
			h.earSource.Set(token)
			logger.Info("handoff EAR refreshed (local)")
		}

		current, _ := h.earSource.Current()
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextRefreshAfter(current)):
		}
	}
}

// attestKey runs the /attest-key flow in process: generate evidence binding the
// signer pubkey to a report, verify the report's signature and report-data
// match, then mint the EAR over the verified launch digest.
//
// INVARIANT: the EAR is minted only after the verifier confirms SignatureValid
// and ReportDataMatch — the same gate the HTTP /attest-key handler enforces. We
// verify even though CDS produced the evidence: the verifier supplies the
// launch digest claim, and skipping verification would let a host-supplied
// evidence blob set the EAR's launch digest.
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
	reportData, err := ratls.ReportDataForKey(ecPub, challenge)
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

	verifyResp, err := h.attestation.Verify(ctx, types.VerifyReportData(
		types.AttestationEvidence(asResp),
		types.NewBase64Bytes(reportDataDigest),
	))
	if err != nil {
		return "", fmt.Errorf("verify evidence: %w", err)
	}
	if !verifyResp.Result.SignatureValid {
		return "", fmt.Errorf("attestation signature invalid")
	}
	if verifyResp.Result.ReportDataMatch == nil || !*verifyResp.Result.ReportDataMatch {
		return "", fmt.Errorf("report-data mismatch in attestation evidence")
	}

	evidenceJSON, err := json.Marshal(asResp)
	if err != nil {
		return "", fmt.Errorf("marshal evidence for EAR: %w", err)
	}
	return h.minter.IssueWithLaunchDigestAndPubKey(json.RawMessage(evidenceJSON), verifyResp.Result.Claims.LaunchDigest, ecPub)
}

// HandoffEARExpiry returns the EAR token's exp claim. The token is decoded
// without signature verification — this is for operator-facing observability
// of the locally provisioned EAR. Handoff peers re-validate signature, issuer,
// and expiry via ValidateEARToken before trusting any material.
func HandoffEARExpiry(token string) (time.Time, error) {
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse JWT: %w", err)
	}
	claims, err := jwt.Parse(msg.Payload(), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse JWT claims: %w", err)
	}
	exp := claims.Expiration()
	if exp.IsZero() || exp.Unix() == 0 {
		return time.Time{}, fmt.Errorf("JWT missing exp claim")
	}
	return exp, nil
}

// nextRefreshAfter returns the duration until the next refresh attempt for
// the supplied token. Half the remaining validity, clamped to a sane band so
// we don't re-attest on every tick when the token is brand new and don't
// sleep forever on a malformed token.
func nextRefreshAfter(token string) time.Duration {
	const (
		minRefresh = 30 * time.Second
		maxRefresh = 1 * time.Hour
	)
	if token == "" {
		return minRefresh
	}
	exp, err := HandoffEARExpiry(token)
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
