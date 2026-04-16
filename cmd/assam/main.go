package main

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
	"github.com/lunal-dev/c8s/internal/certissuer"
	"github.com/lunal-dev/c8s/internal/ear"
	"github.com/lunal-dev/c8s/internal/readiness"
	"github.com/lunal-dev/c8s/internal/server"
	"github.com/lunal-dev/c8s/internal/whitelist"
	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/ktoken"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	var (
		host                 string
		port                 int
		attestationSvcURL    string
		attestationSvcAPIKey string
		certIssuerURL        string
		earKeyPath           string
		earIssuerName        string
		certTTL              time.Duration
		challengeTTL         time.Duration
		readinessInterval    time.Duration
		whitelistDB          string
		whitelistAdminPass   string
		tokenSignerSecret    string
		tokenSignerNamespace string
		rotationInterval     time.Duration
		rotationOverlap      time.Duration
		rotationJitter       float64
	)

	rootCmd := &cobra.Command{
		Use:   "assam",
		Short: "A key broker service for confidential computing",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(config{
				host:                 host,
				port:                 port,
				attestationSvcURL:    attestationSvcURL,
				attestationSvcAPIKey: attestationSvcAPIKey,
				certIssuerURL:        certIssuerURL,
				earKeyPath:           earKeyPath,
				earIssuerName:        earIssuerName,
				certTTL:              certTTL,
				challengeTTL:         challengeTTL,
				readinessInterval:    readinessInterval,
				whitelistDB:          whitelistDB,
				whitelistAdminPass:   whitelistAdminPass,
				tokenSignerSecret:    tokenSignerSecret,
				tokenSignerNamespace: tokenSignerNamespace,
				rotationInterval:     rotationInterval,
				rotationOverlap:      rotationOverlap,
				rotationJitter:       rotationJitter,
			})
		},
	}

	flags := rootCmd.Flags()
	flags.StringVar(&host, "host", "0.0.0.0", "Host address to bind to")
	flags.IntVarP(&port, "port", "p", 8080, "Port to listen on")
	flags.StringVar(&attestationSvcURL, "attestation-service-url", "", "URL of the attestation service")
	flags.StringVar(&attestationSvcAPIKey, "attestation-service-api-key", "", "API key for the attestation service (required when running in remote mode)")
	flags.StringVar(&certIssuerURL, "cert-issuer-url", "", "URL of the cert-issuer service")
	flags.StringVar(&earKeyPath, "ear-key", "", "Path to the EC private key PEM for EAR tokens")
	flags.StringVar(&earIssuerName, "ear-issuer", "assam", "Issuer name for EAR tokens")
	flags.DurationVar(&certTTL, "cert-ttl", 24*time.Hour, "TTL for issued certificates")
	flags.DurationVar(&challengeTTL, "challenge-ttl", 60*time.Second, "Challenge validity period")
	flags.DurationVar(&readinessInterval, "readiness-interval", 10*time.Second, "Interval between readiness health checks")
	flags.StringVar(&whitelistDB, "whitelist-db", "", "Path to the whitelist SQLite database file")
	flags.StringVar(&whitelistAdminPass, "whitelist-admin-password", "", "Admin password for whitelist mutation endpoints")
	flags.StringVar(&tokenSignerSecret, "token-signer-secret", "kbs-token-signing-keys", "Kubernetes Secret holding the EAR signing key (set empty to use --ear-key file instead)")
	flags.StringVar(&tokenSignerNamespace, "token-signer-namespace", envOrDefault("POD_NAMESPACE", "tee-attestation"), "Namespace of the token-signer Secret")
	flags.DurationVar(&rotationInterval, "token-signer-rotation-interval", 720*time.Hour, "How often to rotate the EAR signing key (0 = disable rotation)")
	flags.DurationVar(&rotationOverlap, "token-signer-overlap", 25*time.Hour, "How long a retired key stays in JWKS after rotation")
	flags.Float64Var(&rotationJitter, "token-signer-rotation-jitter", 0.1, "Fraction of rotation interval to jitter the first tick")

	rootCmd.MarkFlagRequired("attestation-service-url")
	rootCmd.MarkFlagRequired("cert-issuer-url")
	rootCmd.MarkFlagRequired("whitelist-db")
	rootCmd.MarkFlagRequired("whitelist-admin-password")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type config struct {
	host                 string
	port                 int
	attestationSvcURL    string
	attestationSvcAPIKey string
	certIssuerURL        string
	earKeyPath           string
	earIssuerName        string
	certTTL              time.Duration
	challengeTTL         time.Duration
	readinessInterval    time.Duration
	whitelistDB          string
	whitelistAdminPass   string
	tokenSignerSecret    string
	tokenSignerNamespace string
	rotationInterval     time.Duration
	rotationOverlap      time.Duration
	rotationJitter       float64
}

func run(cfg config) error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := validateURL(cfg.attestationSvcURL); err != nil {
		return fmt.Errorf("--attestation-service-url: %w", err)
	}
	if err := validateURL(cfg.certIssuerURL); err != nil {
		return fmt.Errorf("--cert-issuer-url: %w", err)
	}

	earKeyPEM, err := loadEARKey(ctx, cfg)
	if err != nil {
		return err
	}

	earIssuer, err := ear.NewIssuer(earKeyPEM, cfg.earIssuerName, cfg.certTTL)
	if err != nil {
		return err
	}

	// Set up key rotation if running in Secret mode with rotation enabled.
	var rotator *ktoken.Rotator
	if cfg.tokenSignerSecret != "" && cfg.rotationInterval > 0 {
		k8sClient, err := buildK8sClient()
		if err != nil {
			return fmt.Errorf("k8s client for rotation: %w", err)
		}
		rotator, err = ktoken.NewRotator(ktoken.RotatorConfig{
			Client:    k8sClient,
			Namespace: cfg.tokenSignerNamespace,
			Secret:    cfg.tokenSignerSecret,
			Interval:  cfg.rotationInterval,
			Overlap:   cfg.rotationOverlap,
			Jitter:    cfg.rotationJitter,
			Logger:    slog.Default(),
		}, earKeyPEM, earIssuer.SwapKey)
		if err != nil {
			return fmt.Errorf("create key rotator: %w", err)
		}
	}

	asClient := attestationclient.NewClientWithAPIKey(cfg.attestationSvcURL, cfg.attestationSvcAPIKey)
	ciClient := certissuer.NewClient(cfg.certIssuerURL)

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

	certTTLStr := formatDuration(cfg.certTTL)

	deps := server.Dependencies{
		AttestationHandler: attestation.Handler{
			Challenges:        &challengeStore,
			AttestationClient: asClient,
			CertIssuer:        ciClient,
			CertTTL:           certTTLStr,
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
	}

	router := server.NewRouter(deps)

	// Start readiness checker in background
	go checker.Run(ctx)

	if rotator != nil {
		go rotator.Run(ctx)
	}

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

func validateURL(u string) error {
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("'%s' is not a valid URL - must start with http:// or https://", u)
	}
	return nil
}

// formatDuration converts a time.Duration to a Go-style string (e.g. "24h", "1h30m").
func formatDuration(d time.Duration) string {
	totalSecs := int64(d.Seconds())
	if totalSecs == 0 {
		return "0s"
	}

	hours := totalSecs / 3600
	totalSecs %= 3600
	minutes := totalSecs / 60
	totalSecs %= 60

	var s string
	if hours > 0 {
		s += fmt.Sprintf("%dh", hours)
	}
	if minutes > 0 {
		s += fmt.Sprintf("%dm", minutes)
	}
	if totalSecs > 0 {
		s += fmt.Sprintf("%ds", totalSecs)
	}
	return s
}

// loadEARKey loads the EAR signing key either from a Kubernetes Secret
// (default) or from a file (--ear-key, legacy mode). The two modes are
// mutually exclusive: if --token-signer-secret is non-empty, --ear-key
// is ignored.
func loadEARKey(ctx context.Context, cfg config) ([]byte, error) {
	if cfg.tokenSignerSecret != "" {
		if cfg.earKeyPath != "" {
			slog.Warn("--ear-key is ignored when --token-signer-secret is set")
		}
		client, err := buildK8sClient()
		if err != nil {
			return nil, fmt.Errorf("k8s client: %w", err)
		}
		return ktoken.Load(
			ctx, client,
			cfg.tokenSignerNamespace, cfg.tokenSignerSecret,
			slog.Default(),
		)
	}

	if cfg.earKeyPath == "" {
		return nil, fmt.Errorf("either --token-signer-secret or --ear-key must be set")
	}
	keyPEM, err := os.ReadFile(cfg.earKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read EAR key at %s: %w", cfg.earKeyPath, err)
	}
	return keyPEM, nil
}

func buildK8sClient() (kubernetes.Interface, error) {
	rc, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	return kubernetes.NewForConfig(rc)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
