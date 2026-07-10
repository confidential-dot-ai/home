package cdsattest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// EvidenceProvider yields TEE attestation evidence whose report_data equals the
// selected protocol binding. The returned evidence is
// the attestation-rs SnpEvidence JSON the browser verifier consumes verbatim.
type EvidenceProvider interface {
	Evidence(ctx context.Context, reportData []byte) (evidence json.RawMessage, platform, generation string, err error)
}

var _ EvidenceProvider = LiveEvidenceProvider{}

// LiveEvidenceProvider asks the local attestation-api for a fresh report
// bound to reportData. This is the production path; it requires a reachable
// attestation-api and runs inside the LB's CVM.
type LiveEvidenceProvider struct {
	Client     attestationclient.Client
	Platform   types.Platform // e.g. types.PlatformSnp
	Generation string         // AMD processor generation for the browser verifier
}

// Evidence implements EvidenceProvider against the attestation-api.
func (p LiveEvidenceProvider) Evidence(ctx context.Context, reportData []byte) (json.RawMessage, string, string, error) {
	resp, err := p.Client.Attest(ctx, types.AttestRequest{
		ReportData: types.NewBase64Bytes(reportData),
		Platform:   p.Platform,
	})
	if err != nil {
		return nil, "", "", fmt.Errorf("attestation-api: %w", err)
	}
	platform := resp.Platform
	if platform == "" {
		platform = string(p.Platform)
	}
	return resp.Evidence, platform, p.Generation, nil
}

// FixtureEvidenceProvider serves a recorded evidence file. DEV/DEMO ONLY: the
// recorded report_data is fixed, so it cannot bind a live session key+nonce —
// clients must run with freshness enforcement downgraded. It exists so the LB
// can serve the full contract (and interoperate with the JS client) without a
// TEE, mirroring c8s's test/mock-cds.
type FixtureEvidenceProvider struct {
	Raw        json.RawMessage
	Platform   string
	Generation string
}

// LoadFixtureEvidence reads a recorded evidence JSON file. The file may be the
// bare SnpEvidence object or a {platform, evidence} envelope.
func LoadFixtureEvidence(path, platform, generation string) (FixtureEvidenceProvider, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return FixtureEvidenceProvider{}, fmt.Errorf("read evidence fixture: %w", err)
	}
	var env struct {
		Platform string          `json:"platform"`
		Evidence json.RawMessage `json:"evidence"`
	}
	evidence := json.RawMessage(raw)
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Evidence) > 0 {
		evidence = env.Evidence
		if platform == "" {
			platform = env.Platform
		}
	}
	if platform == "" {
		platform = "snp"
	}
	return FixtureEvidenceProvider{Raw: evidence, Platform: platform, Generation: generation}, nil
}

// Evidence implements EvidenceProvider; reportData is ignored (see type doc).
func (p FixtureEvidenceProvider) Evidence(_ context.Context, _ []byte) (json.RawMessage, string, string, error) {
	return p.Raw, p.Platform, p.Generation, nil
}
