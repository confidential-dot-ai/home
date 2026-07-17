package getkubeconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// releaseRequest / releaseResponse mirror the cred-release handler's shapes.
type releaseRequest struct {
	CSRPEM string `json:"csr"`
}
type releaseResponse struct {
	CertPEM string `json:"cert"`
	CAPEM   string `json:"ca"`
}

const releasePath = "/release-credential"

// clientIdentity is the kube-client keypair the operator generates locally.
// The private key never leaves the operator; the cert binds to its public key.
type clientIdentity struct {
	key    *ecdsa.PrivateKey
	keyPEM []byte
}

func newClientIdentity() (*clientIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &clientIdentity{
		key:    key,
		keyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
	}, nil
}

// csrPEM builds a CSR for this identity. The Subject is ignored by the server
// (it sets O/CN from its own config), so it's left empty.
func (id *clientIdentity) csrPEM() ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{},
	}, id.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// requestCredential mints an operator-signed JWT bound to the exact request
// body, POSTs the CSR to the cred-release endpoint, and returns the issued
// cert + cluster CA. httpClient is the (RA-TLS or plain) transport to :8443;
// operatorKeyPEM is the operator PRIVATE key that authorizes the release.
func requestCredential(ctx context.Context, httpClient *http.Client, baseURL string, operatorKeyPEM, csrPEM []byte) (*releaseResponse, error) {
	signer, err := operatorauth.NewSignerFromKeyPEM(operatorKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("operator key: %w", err)
	}

	body, err := json.Marshal(releaseRequest{CSRPEM: string(csrPEM)})
	if err != nil {
		return nil, err
	}

	// The JWT binds method/path/body (pbh) — must match exactly what we send.
	authz, err := signer.Authorization(http.MethodPost, releasePath, body)
	if err != nil {
		return nil, fmt.Errorf("sign operator token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+releasePath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authz)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("release request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release HTTP %d: %s", resp.StatusCode, respBody)
	}

	var out releaseResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse release response: %w", err)
	}
	if out.CertPEM == "" || out.CAPEM == "" {
		return nil, fmt.Errorf("release response missing cert or ca")
	}
	return &out, nil
}
