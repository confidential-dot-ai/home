package ratlsmesh

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

func TestMakeAttestFunc_ReportDataNotZeroPadded(t *testing.T) {
	// Regression test: even when the SHA-384 hash contains trailing bytes
	// that happen to be non-zero, the sent data must be exactly sha512.Size384
	// bytes, no more and no less.
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

	// Create report data where the hash fills all 48 bytes.
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
	for i := range 48 {
		if receivedBytes[i] != byte(i+1) {
			t.Errorf("byte %d: got %d, want %d", i, receivedBytes[i], i+1)
		}
	}
}
