package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/types"
)

func TestMakeAttestFunc_ReportDataSize(t *testing.T) {
	// Simulate the data flow: ReportDataForKey returns a 64-byte array
	// (48-byte SHA-384 hash + 16 zero bytes). makeAttestFunc must send
	// only the 48-byte hash to the attestation service, NOT the full
	// 64-byte padded array. Sending 64 bytes causes TPM_RC_SIZE on vTPMs.
	var receivedSize int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		receivedSize = len(req.ReportData.Bytes())
		// Return minimal valid bare-metal SNP evidence.
		fakeReport := make([]byte, 1184)
		json.NewEncoder(w).Encode(map[string]any{
			"platform": "snp",
			"evidence": map[string]string{"attestation_report": base64.StdEncoding.EncodeToString(fakeReport)},
		})
	}))
	defer srv.Close()

	client := attestclient.NewClient("")
	attestFunc := makeAttestFunc(client, srv.URL)

	// Build a 64-byte hex string (like SelfSignedProvider.Provision does).
	var reportData [64]byte
	hash := sha512.Sum384([]byte("test-public-key"))
	copy(reportData[:], hash[:])
	customData := fmt.Sprintf("%x", reportData[:])

	_, err := attestFunc(context.Background(), customData)
	if err != nil {
		t.Fatalf("attestFunc failed: %v", err)
	}

	if receivedSize != sha512.Size384 {
		t.Errorf("attestation service received %d bytes, want %d (SHA-384 hash only, no zero padding)", receivedSize, sha512.Size384)
	}
}

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

	report, err := extractSNPReport(resp)
	if err != nil {
		t.Fatalf("extractSNPReport failed: %v", err)
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

	report, err := extractSNPReport(resp)
	if err != nil {
		t.Fatalf("extractSNPReport failed: %v", err)
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

	_, err := extractSNPReport(resp)
	if err == nil {
		t.Fatal("expected error for missing report fields")
	}
}

func TestMakeAttestFunc_ReportDataNotZeroPadded(t *testing.T) {
	// Regression test: even when the SHA-384 hash contains trailing bytes
	// that happen to be non-zero, the sent data must be exactly sha512.Size384
	// bytes — no more, no less.
	var receivedBytes []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.AttestRequest
		json.NewDecoder(r.Body).Decode(&req)
		receivedBytes = req.ReportData.Bytes()
		fakeReport := make([]byte, 1184)
		json.NewEncoder(w).Encode(map[string]any{
			"platform": "snp",
			"evidence": map[string]string{
				"attestation_report": base64.StdEncoding.EncodeToString(fakeReport),
			},
		})
	}))
	defer srv.Close()

	client := attestclient.NewClient("")
	attestFunc := makeAttestFunc(client, srv.URL)

	// Create report data where the hash fills all 48 bytes (no accidental zeros).
	var reportData [64]byte
	for i := range 48 {
		reportData[i] = byte(i + 1)
	}
	customData := hex.EncodeToString(reportData[:])

	_, err := attestFunc(context.Background(), customData)
	if err != nil {
		t.Fatalf("attestFunc failed: %v", err)
	}

	if len(receivedBytes) != sha512.Size384 {
		t.Fatalf("received %d bytes, want %d", len(receivedBytes), sha512.Size384)
	}
	// Verify the hash content is preserved (not trimmed or corrupted).
	for i := range 48 {
		if receivedBytes[i] != byte(i+1) {
			t.Errorf("byte %d: got %d, want %d", i, receivedBytes[i], i+1)
		}
	}
}
