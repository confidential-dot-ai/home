package credrelease

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// maxBodyBytes caps the request body — a CSR is small; refuse anything large.
const maxBodyBytes = 1 << 16 // 64 KiB

// releaseRequest is the POST /release-credential body: a PEM CERTIFICATE
// REQUEST the operator generated locally. The operator authorizes the request
// with an operatorauth Bearer token whose pbh binds this exact body, so the
// CSR cannot be swapped in transit.
type releaseRequest struct {
	CSRPEM string `json:"csr"`
}

// releaseResponse returns the signed client cert and the cluster CA so the
// operator can assemble a kubeconfig. The apiserver address is known to the
// operator (it dialled this service on the same host).
type releaseResponse struct {
	CertPEM string `json:"cert"`
	CAPEM   string `json:"ca"`
}

// Handler serves POST /release-credential. It authorizes the caller against
// the measured operator key, validates the CSR, and issues a short-lived kube
// client cert signed by the cluster CA.
type Handler struct {
	verifier operatorauth.Verifier
	ca       *clusterCA
	certTTL  time.Duration
	certOrg  string // Kubernetes group (O) for the issued cert
	certCN   string // Kubernetes user (CN)
	now      func() time.Time
}

// NewHandler builds the release handler from the measured operator pubkey (PEM)
// and the loaded cluster CA. The pubkey MUST already have been verified against
// RTMR[3] by LoadMeasuredOperatorKey — NewHandler trusts it as authorized.
func NewHandler(operatorPubPEM []byte, ca *clusterCA, org, cn string, ttl time.Duration) (*Handler, error) {
	keys, err := operatorauth.ParsePublicKeysPEM(operatorPubPEM)
	if err != nil {
		return nil, fmt.Errorf("operator pubkey (must be ECDSA PKIX PEM): %w", err)
	}
	return &Handler{
		// ClockSkew tolerates a small offset between the operator's clock and
		// the guest's — without it, a token issued a second ahead of the
		// guest clock is rejected "used before issued". Bounded (still within
		// operatorauth's 5-min max validity), so it doesn't widen the replay
		// window meaningfully.
		verifier: operatorauth.Verifier{Keys: keys, ClockSkew: 60 * time.Second},
		ca:       ca,
		certTTL:  ttl,
		certOrg:  org,
		certCN:   cn,
		now:      time.Now,
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/release-credential" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	// AUTHORIZE: the caller must hold the operator private key whose public
	// half is measured into RTMR[3]. operatorauth verifies the Bearer JWT
	// (ES256/384/512) under the pinned key, enforces <=5min validity, and
	// binds the token to this method/path/body (pbh) — so a captured token
	// can't be replayed against a different CSR.
	if err := h.verifier.Authorize(r, body); err != nil {
		http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var req releaseRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	csr, err := parseCSR([]byte(req.CSRPEM))
	if err != nil {
		http.Error(w, "bad CSR: "+err.Error(), http.StatusBadRequest)
		return
	}

	certPEM, err := h.ca.signOperatorCert(signParams{
		csr: csr,
		org: h.certOrg,
		cn:  h.certCN,
		ttl: h.certTTL,
	}, h.now())
	if err != nil {
		http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := releaseResponse{CertPEM: string(certPEM), CAPEM: string(h.ca.pem)}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// parseCSR decodes a PEM CERTIFICATE REQUEST. The CSR's public key is what the
// issued cert binds to; the operator holds the matching private key. The CSR
// self-signature is verified here so a tampered CSR is a client fault (400),
// not a signing failure.
func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	// Reject a CSR whose key we can't reason about; kube client certs here
	// use ECDSA (matching the CA), but the apiserver accepts others too —
	// keep it permissive on the CSR key type, strict on the signature.
	if _, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok {
		// Not fatal for correctness, but v1 keeps it ECDSA for symmetry.
		return nil, fmt.Errorf("CSR public key is %T, want ECDSA", csr.PublicKey)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR self-signature invalid: %w", err)
	}
	return csr, nil
}
