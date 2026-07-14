package issuer

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// CAProvisionConfig configures how CDS obtains its mesh CA at startup.
type CAProvisionConfig struct {
	// CommonName and Validity are used only when generating a fresh CA
	// (PeerURL empty).
	CommonName string
	Validity   time.Duration
	// Curve for a generated CA; nil defaults to P-384 (the mesh CA curve).
	Curve elliptic.Curve

	// PeerURL is a surviving CDS peer's https base URL. Empty means cold
	// start: generate a fresh self-signed CA. Non-empty means adopt the
	// peer's CA via /handoff, and fail closed if that does not succeed.
	PeerURL string
	// AttestationApiURL is the local attestation-api used to attest this
	// node's handoff signer key. Required when PeerURL is set.
	AttestationApiURL string
	// Measurements pins the peer's launch digest on both the RA-TLS serving
	// cert and the handoff issuer EAR. Required when PeerURL is set.
	Measurements []string
	// ExpectedIssuer is the EAR issuer claim required on the peer's handoff
	// EAR (the peer's --ear-issuer; "cds" by default).
	ExpectedIssuer string
	// Timeout bounds the adopt attempt. PullHandoff retries transient
	// failures until this elapses; a peer still unreachable at the deadline
	// is a fail-closed error, not a cue to self-generate.
	Timeout time.Duration
}

// caPuller adopts a CA from the configured peer. It is a seam so the
// generate/adopt/fail-closed policy can be tested without a live RA-TLS peer.
type caPuller func(ctx context.Context, cfg CAProvisionConfig, logger *slog.Logger) (*HandoffMaterial, error)

// ProvisionCA returns CDS's startup mesh CA and whether it was adopted from a
// peer, using the default RA-TLS puller. See provisionCA for the policy.
func ProvisionCA(ctx context.Context, cfg CAProvisionConfig, logger *slog.Logger) (ca *CA, adopted bool, err error) {
	return provisionCA(ctx, cfg, logger, adoptFromPeer)
}

// provisionCA implements the binary provisioning policy:
//
//   - PeerURL empty  -> generate a fresh self-signed CA (cold start / first
//     CDS). adopted=false.
//   - PeerURL set    -> adopt the peer's CA via pull. Any error (a denial, or
//     the peer unreachable within Timeout) is fatal: CDS must not mint a
//     divergent trust root when an operator has said a peer exists.
//
// It never silently falls back from a configured peer to a generated CA — that
// is the exact failure (a transient partition regenerating the trust root)
// this path exists to prevent.
func provisionCA(ctx context.Context, cfg CAProvisionConfig, logger *slog.Logger, pull caPuller) (*CA, bool, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.PeerURL == "" {
		curve := cfg.Curve
		if curve == nil {
			curve = elliptic.P384()
		}
		generated, err := NewCAWithCurve(cfg.CommonName, cfg.Validity, curve)
		if err != nil {
			return nil, false, err
		}
		return generated, false, nil
	}

	material, err := pull(ctx, cfg, logger)
	if err != nil {
		return nil, false, fmt.Errorf("adopt mesh CA from peer %s: %w", cfg.PeerURL, err)
	}
	return &CA{Cert: material.CACert, Key: material.CAKey}, true, nil
}

// adoptFromPeer builds the requester client stack and pulls the peer's CA. It
// is the in-process twin of the `c8s cds request-handoff` command.
func adoptFromPeer(ctx context.Context, cfg CAProvisionConfig, logger *slog.Logger) (*HandoffMaterial, error) {
	if cfg.AttestationApiURL == "" {
		return nil, fmt.Errorf("attestation-api URL is required to adopt a CA")
	}
	pinned, err := ratls.ParseHexMeasurementsList(cfg.Measurements)
	if err != nil {
		return nil, fmt.Errorf("parse handoff measurements: %w", err)
	}
	if len(pinned) == 0 {
		return nil, fmt.Errorf("adopting a CA requires pinned peer measurements")
	}
	// The same digest set pins both channels; the EAR-side map is derived
	// from the validated digests so the two representations stay in sync.
	allowed := make(map[string]bool, len(pinned))
	for _, m := range pinned {
		allowed[hex.EncodeToString(m)] = true
	}

	httpClient, err := ratls.NewVerifyingHTTPClient(pinned, cfg.AttestationApiURL)
	if err != nil {
		return nil, err
	}

	// The JWKS cache lives on the parent ctx so a kid-miss refresh still
	// resolves if EAR validation runs at the edge of the pull deadline.
	keyProvider, err := NewJWKSKeyProvider(ctx, cfg.PeerURL+"/.well-known/jwks.json", time.Minute, httpClient, logger)
	if err != nil {
		return nil, fmt.Errorf("build peer JWKS key provider: %w", err)
	}

	pullCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	return PullHandoff(pullCtx, PullConfig{
		Deps: HandoffClientDeps{
			KeyProvider:         keyProvider,
			ExpectedIssuer:      cfg.ExpectedIssuer,
			AllowedMeasurements: allowed,
		},
		Attest:            attestclient.NewClientWithHTTP(cfg.PeerURL, httpClient),
		PeerURL:           cfg.PeerURL,
		AttestationApiURL: cfg.AttestationApiURL,
		HTTPClient:        httpClient,
		Logger:            logger,
	})
}
