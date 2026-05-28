// mock-attestation is a fake attestation service for integration testing.
// It responds to /attest with synthetic evidence and to /health with OK.
// It does NOT perform real TEE attestation — use only in test environments.
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8400"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /attest", handleAttest)
	mux.HandleFunc("GET /health", handleHealth)

	slog.Info("mock attestation service starting", "port", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func handleAttest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReportData string `json:"report_data"`
		Platform   string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"bad_request","message":"%s"}`, err), http.StatusBadRequest)
		return
	}

	slog.Info("mock attest called", "platform", req.Platform)

	// Return synthetic evidence that the CDS mock/test mode can accept.
	resp := map[string]any{
		"platform": "mock",
		"evidence": map[string]any{
			"report_data":  req.ReportData,
			"mock_payload": "integration-test",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok","platform":"mock"}`)
}
