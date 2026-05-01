package attestclient_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/types"
)

func TestExtractSNPReport_BareMetal(t *testing.T) {
	// Bare-metal SNP: attestation_report field, standard base64.
	fakeReport := make([]byte, 1184)
	fakeReport[0] = 0x02 // SNP version marker
	evidence := map[string]string{
		"attestation_report": base64.StdEncoding.EncodeToString(fakeReport),
	}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := types.AttestResponse{
		Platform: "snp",
		Evidence: evidenceJSON,
	}

	report, err := attestclient.ExtractSNPReport(resp)
	if err != nil {
		t.Fatalf("ExtractSNPReport failed: %v", err)
	}
	if len(report) != 1184 {
		t.Errorf("report length = %d, want 1184", len(report))
	}
	if report[0] != 0x02 {
		t.Errorf("report[0] = %02x, want 0x02", report[0])
	}
}

func TestExtractSNPReport_VTPM(t *testing.T) {
	// vTPM (az-snp): hcl_report field, URL-safe base64 (no padding).
	fakeHCLReport := make([]byte, 1184)
	fakeHCLReport[0] = 0x02
	evidence := map[string]any{
		"version":    1,
		"hcl_report": base64.RawURLEncoding.EncodeToString(fakeHCLReport),
		"tpm_quote": map[string]any{
			"signature": "deadbeef",
			"message":   "cafebabe",
			"pcrs":      []string{},
		},
		"vcek": "fake-vcek",
	}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := types.AttestResponse{
		Platform: "az-snp",
		Evidence: evidenceJSON,
	}

	report, err := attestclient.ExtractSNPReport(resp)
	if err != nil {
		t.Fatalf("ExtractSNPReport failed: %v", err)
	}
	if len(report) != 1184 {
		t.Errorf("report length = %d, want 1184", len(report))
	}
}

func TestExtractSNPReport_NoReport(t *testing.T) {
	evidence := map[string]string{"something_else": "value"}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := types.AttestResponse{
		Platform: "unknown",
		Evidence: evidenceJSON,
	}

	_, err := attestclient.ExtractSNPReport(resp)
	if err == nil {
		t.Fatal("expected error for missing report fields")
	}
}
