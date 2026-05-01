// Package assam implements the assam key-broker subcommand.
package assam

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/lunal-dev/c8s/internal/attestation"
	"github.com/lunal-dev/c8s/internal/certissuerclient"
	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	"github.com/lunal-dev/c8s/internal/ear"
	"github.com/lunal-dev/c8s/internal/readiness"
	"github.com/lunal-dev/c8s/internal/server"
	"github.com/lunal-dev/c8s/internal/whitelist"
	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/earsigner"
)

// NewCmd returns the cobra subcommand. It is registered as a child of
// `c8s` and as the root command of the standalone binary.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:   "assam",
		Short: "A key broker service for confidential computing",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.attestationSvcAPIKey == "" {
				cfg.attestationSvcAPIKey = os.Getenv("C8S_ATTESTATION_SERVICE_API_KEY")
			}
			if cfg.whitelistAdminPass == "" {
				cfg.whitelistAdminPass = os.Getenv("C8S_ASSAM_WHITELIST_ADMIN_PASSWORD")
			}
			return run(cfg)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&cfg.host, "host", "0.0.0.0", "Host address to bind to")
	flags.IntVarP(&cfg.port, "port", "p", 8080, "Port to listen on")
	flags.StringVar(&cfg.attestationSvcURL, "attestation-service-url", "", "URL of the attestation service")
	flags.StringVar(&cfg.attestationSvcAPIKey, "attestation-service-api-key", "", "API key for the attestation service (required when running in remote mode)")
	flags.StringVar(&cfg.certIssuerURL, "cert-issuer-url", "", "URL of the cert-issuer service")
	flags.StringVar(&cfg.earIssuerName, "ear-issuer", "assam", "Issuer name for EAR tokens")
	flags.DurationVar(&cfg.certTTL, "cert-ttl", 24*time.Hour, "TTL for issued certificates")
	flags.DurationVar(&cfg.challengeTTL, "challenge-ttl", 60*time.Second, "Challenge validity period")
	flags.DurationVar(&cfg.readinessInterval, "readiness-interval", 10*time.Second, "Interval between readiness health checks")
	flags.StringVar(&cfg.whitelistDB, "whitelist-db", "", "Path to the whitelist SQLite database file")
	flags.StringVar(&cfg.whitelistAdminPass, "whitelist-admin-password", "", "Admin password for whitelist mutation endpoints")
	flags.DurationVar(&cfg.rotationInterval, "token-signer-rotation-interval", 720*time.Hour, "How often to rotate the EAR signing key (0 = disable rotation)")
	flags.DurationVar(&cfg.rotationOverlap, "token-signer-overlap", 25*time.Hour, "How long a retired key stays in JWKS after rotation")
	flags.Float64Var(&cfg.rotationJitter, "token-signer-rotation-jitter", 0.1, "Fraction of rotation interval to jitter the first tick")

	_ = cmd.MarkFlagRequired("attestation-service-url")
	_ = cmd.MarkFlagRequired("cert-issuer-url")
	_ = cmd.MarkFlagRequired("whitelist-db")

	return cmd
}

type config struct {
	host                 string
	port                 int
	attestationSvcURL    string
	attestationSvcAPIKey string
	certIssuerURL        string
	earIssuerName        string
	certTTL              time.Duration
	challengeTTL         time.Duration
	readinessInterval    time.Duration
	whitelistDB          string
	whitelistAdminPass   string
	rotationInterval     time.Duration
	rotationOverlap      time.Duration
	rotationJitter       float64
}

func run(cfg config) error {
	slog.SetDefault(certutil.NewJSONLogger(""))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := cmdsutil.ValidateHTTPURL("--attestation-service-url", cfg.attestationSvcURL); err != nil {
		return err
	}
	if err := cmdsutil.ValidateHTTPURL("--cert-issuer-url", cfg.certIssuerURL); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.whitelistAdminPass) == "" {
		return fmt.Errorf("--whitelist-admin-password or $C8S_ASSAM_WHITELIST_ADMIN_PASSWORD is required")
	}

	// Generate an ephemeral token-signing key in memory.
	earKeyPEM, err := earsigner.Generate()
	if err != nil {
		return fmt.Errorf("generate token-signing key: %w", err)
	}
	slog.Debug("generated ephemeral token-signing key")

	earIssuer, err := ear.NewIssuer(earKeyPEM, cfg.earIssuerName, cfg.certTTL)
	if err != nil {
		return err
	}

	// Set up in-memory key rotation.
	var rotator *earsigner.Rotator
	if cfg.rotationInterval > 0 {
		rotator, err = earsigner.NewRotator(earsigner.RotatorConfig{
			Interval: cfg.rotationInterval,
			Overlap:  cfg.rotationOverlap,
			Jitter:   cfg.rotationJitter,
			Logger:   slog.Default(),
		}, earKeyPEM, earIssuer.SwapKey)
		if err != nil {
			return fmt.Errorf("create key rotator: %w", err)
		}
	}

	asClient := attestationclient.NewClientWithAPIKey(cfg.attestationSvcURL, cfg.attestationSvcAPIKey)
	ciClient := certissuerclient.NewClient(cfg.certIssuerURL)

	challengeStore := attestation.NewChallengeStore(cfg.challengeTTL)

	// Readiness checker (only checks attestation service health)
	checker := readiness.NewChecker(
		attestationclient.NewClientWithAPIKey(cfg.attestationSvcURL, cfg.attestationSvcAPIKey),
		cfg.readinessInterval,
	)

	// Open whitelist store
	whitelistStore, err := whitelist.OpenStore(cfg.whitelistDB)
	if err != nil {
		return fmt.Errorf("failed to open whitelist database: %w", err)
	}
	defer whitelistStore.Close()

	deps := server.Dependencies{
		AttestationHandler: attestation.Handler{
			Challenges:        &challengeStore,
			AttestationClient: asClient,
			CertIssuer:        ciClient,
			CertTTL:           cfg.certTTL.String(),
			EarIssuer:         earIssuer,
		},
		WhitelistHandler: whitelist.Handler{
			Store:            &whitelistStore,
			AdminPasswordB64: base64.StdEncoding.EncodeToString([]byte(cfg.whitelistAdminPass)),
		},
		ReadyFn:   checker.Ready,
		EarIssuer: earIssuer,
	}
	if rotator != nil {
		deps.JWKSFunc = rotator.JWKSetJSON
		go rotator.Run(ctx)
	}

	router := server.NewRouter(deps)

	// Start readiness checker in background
	go checker.Run(ctx)

	addr := fmt.Sprintf("%s:%d", cfg.host, cfg.port)
	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	go func() {
		<-ctx.Done()
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	slog.Info("listening", "addr", addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}

	return nil
}
