package cdsattest

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type config struct {
	host                 string
	port                 int
	logLevel             string
	cdsCertFile          string
	servingCertFile      string
	meshIdentityCertFile string
	meshIdentityKeyFile  string
	meshIdentityCAFile   string
	evidenceFixture      string
	attestationAPIURL    string
	platform             string
	generation           string
	sessionTTL           time.Duration
	readHeaderTimeout    time.Duration

	// over-encryption backend
	upstream           string
	upstreamCAFile     string
	upstreamCertFile   string
	upstreamKeyFile    string
	upstreamServerName string
}

// NewCmd returns the `cds-attest` subcommand: a sidecar that runs inside the
// tls-lb pod and serves the *dynamic* browser-facing attestation +
// over-encryption endpoints (the c8s-verify/v1 protocol). The tls-lb nginx
// front-end terminates public TLS, serves the static CDS/mesh-CA certs, and
// reverse-proxies /.well-known/c8s/attestation, /handshake, and the
// over-encrypted application paths to this sidecar on loopback.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:   "cds-attest",
		Short: "Run the tls-lb attestation + over-encryption sidecar (c8s-verify/v1)",
		RunE:  func(_ *cobra.Command, _ []string) error { return run(cfg) },
	}
	f := cmd.Flags()
	f.StringVar(&cfg.host, "host", "127.0.0.1", "listen host (loopback: nginx proxies to it)")
	f.IntVarP(&cfg.port, "port", "p", 8800, "listen port")
	f.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	f.StringVar(&cfg.cdsCertFile, "cds-cert-file", "", "optional PEM (LB leaf + mesh CA): also serve /.well-known/c8s/cds-cert.pem from the sidecar. Normally nginx serves this statically; leave empty.")
	f.StringVar(&cfg.servingCertFile, "serving-cert-file", "", "path to the LB serving-leaf PEM (the cert nginx presents). Enables the tls-cert attestation binding (GET /.well-known/c8s/attestation?pq=false): report_data binds this leaf's SPKI. Re-read per request to follow get-cert rotation.")
	f.StringVar(&cfg.meshIdentityCertFile, "mesh-identity-cert-file", "", "TEE-held mesh leaf PEM for identity-bound PQ v2 (re-read per request)")
	f.StringVar(&cfg.meshIdentityKeyFile, "mesh-identity-key-file", "", "TEE-held mesh leaf private key for identity-bound PQ v2 (re-read per request)")
	f.StringVar(&cfg.meshIdentityCAFile, "mesh-identity-ca-file", "", "mesh CA bundle that issued the v2 identity leaf (re-read per request)")
	f.StringVar(&cfg.evidenceFixture, "evidence-fixture", "", "DEV ONLY: serve recorded SNP evidence from this file instead of the attestation-api")
	f.StringVar(&cfg.attestationAPIURL, "attestation-api-url", "", "attestation-api URL (production evidence source)")
	f.StringVar(&cfg.platform, "platform", "snp", "TEE platform")
	f.StringVar(&cfg.generation, "generation", "genoa", "AMD processor generation for the browser verifier: milan|genoa|turin")
	f.DurationVar(&cfg.sessionTTL, "session-ttl", 5*time.Minute, "pending-handshake TTL and established-session idle TTL")
	f.DurationVar(&cfg.readHeaderTimeout, "read-header-timeout", 5*time.Second, "HTTP read-header timeout")
	f.StringVar(&cfg.upstream, "upstream", "", "backend base URL to forward decrypted traffic to (http:// rides the raTLS mesh; https:// does mTLS). Empty uses an echo backend (demo).")
	f.StringVar(&cfg.upstreamCAFile, "upstream-ca", "", "PEM CA bundle to verify an https upstream (the mesh CA)")
	f.StringVar(&cfg.upstreamCertFile, "upstream-cert", "", "client cert presented to an https upstream (the CDS-issued LB cert)")
	f.StringVar(&cfg.upstreamKeyFile, "upstream-key", "", "client key for --upstream-cert")
	f.StringVar(&cfg.upstreamServerName, "upstream-server-name", "", "SNI/verification name for an https upstream")
	return cmd
}

func run(cfg config) error {
	logger := newLogger(cfg.logLevel)

	var cdsCertPEM []byte
	if cfg.cdsCertFile != "" {
		b, err := os.ReadFile(cfg.cdsCertFile)
		if err != nil {
			return fmt.Errorf("read --cds-cert-file: %w", err)
		}
		cdsCertPEM = b
	}

	var provider EvidenceProvider
	switch {
	case cfg.evidenceFixture != "":
		fp, err := LoadFixtureEvidence(cfg.evidenceFixture, cfg.platform, cfg.generation)
		if err != nil {
			return err
		}
		provider = fp
		logger.Warn("serving recorded evidence fixture (DEV ONLY): report_data is not bound to live session keys",
			"file", cfg.evidenceFixture)
	case cfg.attestationAPIURL != "":
		provider = LiveEvidenceProvider{
			Client:     attestationclient.NewClient(cfg.attestationAPIURL),
			Platform:   types.Platform(cfg.platform),
			Generation: cfg.generation,
		}
	default:
		return fmt.Errorf("one of --attestation-api-url or --evidence-fixture is required")
	}

	var backend Backend
	if cfg.upstream != "" {
		hb, err := NewHTTPBackend(cfg.upstream, HTTPBackendOptions{
			TrustedCAFile:  cfg.upstreamCAFile,
			ClientCertFile: cfg.upstreamCertFile,
			ClientKeyFile:  cfg.upstreamKeyFile,
			ServerName:     cfg.upstreamServerName,
		})
		if err != nil {
			return err
		}
		backend = hb
		logger.Info("forwarding decrypted traffic to upstream", "upstream", cfg.upstream)
	} else {
		backend = EchoBackend{}
		logger.Warn("no --upstream set: using echo backend (demo only)")
	}

	srv := NewServer(Config{
		Logger:               logger,
		Evidence:             provider,
		CDSCertPEM:           cdsCertPEM,
		ServingCertFile:      cfg.servingCertFile,
		MeshIdentityCertFile: cfg.meshIdentityCertFile,
		MeshIdentityKeyFile:  cfg.meshIdentityKeyFile,
		MeshIdentityCAFile:   cfg.meshIdentityCAFile,
		Backend:              backend,
		SessionTTL:           cfg.sessionTTL,
	})

	addr := cfg.host + ":" + strconv.Itoa(cfg.port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: cfg.readHeaderTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go cmdsutil.ShutdownOnDone(ctx, httpSrv, 5*time.Second)

	logger.Info("LB browser-facing endpoints listening", "addr", addr)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		slog.Error("unrecognized log level, defaulting to Info", "requested_level", level, "error", err)
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
