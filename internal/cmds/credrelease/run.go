package credrelease

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// Config is the release service configuration.
type Config struct {
	// ListenAddr is the HTTPS bind address (e.g. ":8443").
	ListenAddr string
	// AttestationAPIURL is the local attestation-api base URL the RA-TLS
	// serving cert's TDX quote is fetched from (the same :8400 service the
	// rest of the stack uses).
	AttestationAPIURL string
	// Platform is the TEE platform ("tdx").
	Platform string
	// ClientCACert / ClientCAKey locate the cluster's client-signing CA
	// (defaults: the RKE2 paths; kubeadm works via /etc/kubernetes/pki/ca.{crt,key}).
	ClientCACert string
	ClientCAKey  string
	// ServerCACert locates the CA that signs the apiserver serving cert — the
	// trust anchor embedded in the released kubeconfig.
	ServerCACert string
	// CertTTL is the lifetime of issued operator certs.
	CertTTL time.Duration
	// CertOrg / CertCN are the Kubernetes group / user the issued cert
	// carries. v1: O=system:masters, CN=operator (cluster-admin).
	CertOrg string
	CertCN  string
}

// Run loads the measured operator key and cluster CA, then serves the
// RA-TLS-protected /release-credential endpoint. It blocks until ctx is done.
//
// Startup order matters for the trust story:
//  1. LoadMeasuredOperatorKey — read the opkeydata pubkey and CONFIRM it
//     matches RTMR[3]. Fails closed if the key was substituted after boot.
//  2. loadClusterCA — the cluster client-CA that signs the operator's cert.
//  3. serve over an RA-TLS config so the caller can attest this is the real
//     guest before trusting the returned cert.
func Run(ctx context.Context, cfg Config) error {
	// RA-TLS is mandatory here: this endpoint hands out cluster-admin creds,
	// so serving without an attested cert (empty platform => plain HTTP in the
	// ratls package) would let a host MITM impersonate the guest. Reject it.
	cfg.Platform = ratls.NormalizePlatform(cfg.Platform)
	if cfg.Platform == "" {
		return fmt.Errorf("--platform is required (RA-TLS is mandatory for credential release)")
	}

	operatorPub, err := LoadMeasuredOperatorKey()
	if err != nil {
		return fmt.Errorf("load measured operator key: %w", err)
	}

	ca, err := loadClusterCA(cfg.ClientCACert, cfg.ClientCAKey, cfg.ServerCACert)
	if err != nil {
		return fmt.Errorf("load cluster CA: %w", err)
	}

	handler, err := NewHandler(operatorPub, ca, cfg.CertOrg, cfg.CertCN, cfg.CertTTL)
	if err != nil {
		return fmt.Errorf("build handler: %w", err)
	}

	// RA-TLS serving config: the presented cert embeds a fresh TDX quote
	// bound to its own public key, so the operator's RA-TLS client verifies
	// it's talking to a genuine, correctly-measured guest before sending the
	// CSR or trusting the returned cert. AttestFunc fetches the quote from the
	// local attestation-api (platform-generic despite the SNP name — it reads
	// resp.Platform, so it yields a TDX quote here); same pattern as cds.
	attestFunc := attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), cfg.AttestationAPIURL)
	tlsCfg, certMgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:   cfg.Platform,
		AttestFunc: attestFunc,
		Logger:     slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("build RA-TLS config: %w", err)
	}
	// Provision the serving cert (and its quote) before accepting traffic, so
	// the first request doesn't race a cold cert manager.
	warmCtx, cancelWarm := context.WithTimeout(ctx, 30*time.Second)
	err = certMgr.WarmUp(warmCtx)
	cancelWarm()
	if err != nil {
		return fmt.Errorf("warm up RA-TLS serving cert: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		// certs come from tlsCfg (RA-TLS), so no cert/key files.
		errCh <- srv.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}
