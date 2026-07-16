package getkubeconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Config is the get-kubeconfig client configuration.
type Config struct {
	// AttestURL is the guest attestation-api /attest endpoint (e.g.
	// http://<node>:8400/attest) used for the RTMR[3] trust gate.
	AttestURL string
	// ReleaseBaseURL is the cred-release endpoint base (e.g. https://<node>:8443).
	ReleaseBaseURL string
	// APIServerURL is the guest apiserver the kubeconfig points at
	// (e.g. https://<node>:6443).
	APIServerURL string
	// OperatorKeyPath is the operator ECDSA PRIVATE key (PEM). Its public half
	// was bound into the node's RTMR[3] at launch.
	OperatorKeyPath string
	// ContextName names the kubeconfig cluster/context/user.
	ContextName string
	// TLSServerName is emitted as the kubeconfig's tls-server-name, so cert
	// verification is pinned to a stable SAN the image bakes (c8s-cvm) rather
	// than the per-launch IP the operator dials (which the apiserver cert has
	// no SAN for). Empty omits it (verification then needs the dialed IP to be
	// a cert SAN, which it usually isn't).
	TLSServerName string
	// OutPath is where the kubeconfig is written.
	OutPath string
	// InsecureSkipTLSVerify skips server-cert verification on the :8443 dial.
	// v1 default true: the release is secured by the RTMR[3] attestation gate
	// (below) + the RKE2-CA signature on the returned cert + the JWT PoP, none
	// of which the host can forge. RA-TLS pinning of :8443 is a follow-up.
	InsecureSkipTLSVerify bool
	// Timeout bounds each network step.
	Timeout time.Duration
}

// Run executes the client flow: attest + RTMR[3] gate, then CSR -> cred-release
// -> kubeconfig.
func Run(ctx context.Context, cfg Config) error {
	keyPEM, err := os.ReadFile(cfg.OperatorKeyPath)
	if err != nil {
		return fmt.Errorf("read operator key: %w", err)
	}
	pubPEM, err := publicKeyPEMFromPrivate(keyPEM)
	if err != nil {
		return fmt.Errorf("derive operator public key: %w", err)
	}

	// 1. Trust gate: attest the node and confirm rtmr_3 == H(op_pub). This
	//    proves genuine TDX + the node was launched to trust THIS key, with no
	//    host trust and not TOFU. Everything downstream depends on it.
	attestCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	if err := attestAndCheckRTMR3(attestCtx, cfg.AttestURL, pubPEM); err != nil {
		cancel()
		return fmt.Errorf("attestation gate: %w", err)
	}
	cancel()

	// 2. Generate the kube-client identity + CSR.
	id, err := newClientIdentity()
	if err != nil {
		return fmt.Errorf("generate client key: %w", err)
	}
	csrPEM, err := id.csrPEM()
	if err != nil {
		return fmt.Errorf("build CSR: %w", err)
	}

	// 3. Exchange the CSR for a signed cert over cred-release.
	httpClient := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipTLSVerify}, //nolint:gosec // see Config.InsecureSkipTLSVerify
		},
	}
	relCtx, cancel2 := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel2()
	resp, err := requestCredential(relCtx, httpClient, cfg.ReleaseBaseURL, keyPEM, csrPEM)
	if err != nil {
		return fmt.Errorf("credential release: %w", err)
	}

	// 4. Assemble + write the kubeconfig.
	kc := buildKubeconfig(cfg.APIServerURL, cfg.ContextName, cfg.TLSServerName, []byte(resp.CertPEM), id.keyPEM, []byte(resp.CAPEM))
	if err := os.WriteFile(cfg.OutPath, kc, 0o600); err != nil {
		return fmt.Errorf("write kubeconfig: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (context %q) — attested, operator-key-bound\n", cfg.OutPath, cfg.ContextName)
	return nil
}

// publicKeyPEMFromPrivate derives the PKIX PEM public key from an ECDSA
// private key PEM. This MUST byte-match the pubkey the launcher put on the
// opkeydata disk (confai wrote `openssl ec -pubout`, which is PKIX PEM), or
// the RTMR[3] expected value won't match. Both use x509.MarshalPKIXPublicKey.
func publicKeyPEMFromPrivate(keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("operator key is not PEM")
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("operator key is %T, want ECDSA", k)
		}
		key = ec
	default:
		return nil, fmt.Errorf("unsupported key PEM type %q", block.Type)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
