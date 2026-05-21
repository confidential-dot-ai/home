// Package assam implements the assam key-broker subcommand.
package assam

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path"
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
	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/earsigner"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/resources"
)

// NewCmd returns the cobra subcommand. It is registered as a child of
// `c8s` and as the root command of the standalone binary.
func NewCmd() *cobra.Command {
	var cfg config
	cmd := &cobra.Command{
		Use:   "assam",
		Short: "A key broker service for confidential computing",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cfg)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&cfg.host, "host", "0.0.0.0", "Host address to bind to")
	flags.IntVarP(&cfg.port, "port", "p", 8080, "Port to listen on")
	flags.StringVar(&cfg.attestationSvcURL, "attestation-service-url", "", "URL of the attestation service")
	flags.StringVar(&cfg.certIssuerURL, "cert-issuer-url", "", "URL of the cert-issuer service")
	flags.StringVar(&cfg.earIssuerName, "ear-issuer", "assam", "Issuer name for EAR tokens")
	flags.DurationVar(&cfg.certTTL, "cert-ttl", 24*time.Hour, "TTL for issued certificates")
	flags.DurationVar(&cfg.challengeTTL, "challenge-ttl", 60*time.Second, "Challenge validity period")
	flags.DurationVar(&cfg.readinessInterval, "readiness-interval", 10*time.Second, "Interval between readiness health checks")
	flags.StringVar(&cfg.whitelistDB, "whitelist-db", "", "Path to the whitelist SQLite database file")
	flags.StringVar(&cfg.resourceMapPath, "resource-map", "", "Path to JSON resource map file for EAR-authorized whitelist mutations")
	flags.DurationVar(&cfg.jwtClockSkew, "jwt-clock-skew", 30*time.Second, "Maximum acceptable clock skew for whitelist EAR validation")
	flags.DurationVar(&cfg.rotationInterval, "token-signer-rotation-interval", 720*time.Hour, "How often to rotate the EAR signing key (0 = disable rotation)")
	flags.DurationVar(&cfg.rotationOverlap, "token-signer-overlap", 25*time.Hour, "How long a retired key stays in JWKS after rotation")
	flags.Float64Var(&cfg.rotationJitter, "token-signer-rotation-jitter", 0.1, "Fraction of rotation interval to jitter the first tick")
	flags.StringVar(&cfg.ratlsPlatform, "ratls-platform", "snp", "TEE platform for the Assam RA-TLS serving cert (snp, tdx, az-snp, az-tdx, gcp-snp, gcp-tdx). Empty disables TLS — UNSAFE outside tests.")
	flags.DurationVar(&cfg.ratlsCertTTL, "ratls-cert-ttl", 24*time.Hour, "TTL for the Assam RA-TLS serving certificate (rotated at 50%)")
	flags.Int64Var(&cfg.whitelistMaxBodyBytes, "whitelist-max-body-bytes", whitelist.DefaultMaxWriteBodyBytes, "Max bytes the whitelist mutation handler will read before authorising. Whitelist payloads are tiny; the cap stops a malicious client from forcing the handler to buffer megabytes during the auth check.")
	flags.StringVar(&cfg.certIssuerMeasurementsRaw, "cert-issuer-measurements", "", "comma-separated SHA-384 hex launch measurements that cert-issuer's RA-TLS peer cert must match when --cert-issuer-url is https. Empty = accept any (UNSAFE outside development; pin to the operator-supplied cert-issuer launch digest).")

	_ = cmd.MarkFlagRequired("attestation-service-url")
	_ = cmd.MarkFlagRequired("cert-issuer-url")
	_ = cmd.MarkFlagRequired("whitelist-db")

	return cmd
}

type config struct {
	host                      string
	port                      int
	attestationSvcURL         string
	certIssuerURL             string
	earIssuerName             string
	certTTL                   time.Duration
	challengeTTL              time.Duration
	readinessInterval         time.Duration
	whitelistDB               string
	resourceMapPath           string
	jwtClockSkew              time.Duration
	rotationInterval          time.Duration
	rotationOverlap           time.Duration
	rotationJitter            float64
	ratlsPlatform             string
	ratlsCertTTL              time.Duration
	whitelistMaxBodyBytes     int64
	certIssuerMeasurementsRaw string
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
	certIssuerMeasurements, err := ratls.ParseHexMeasurements(cfg.certIssuerMeasurementsRaw)
	if err != nil {
		return fmt.Errorf("--cert-issuer-measurements: %w", err)
	}

	// Generate an ephemeral token-signing key in memory.
	earKeyPEM, err := earsigner.Generate()
	if err != nil {
		return fmt.Errorf("generate token-signing key: %w", err)
	}
	slog.Debug("generated ephemeral token-signing key")

	earIssuer, err := ear.NewIssuer(earKeyPEM, cfg.earIssuerName, cfg.certTTL)
	if err != nil {
		return fmt.Errorf("create EAR issuer: %w", err)
	}

	rm, err := loadResourceMap(cfg.resourceMapPath)
	if err != nil {
		return fmt.Errorf("load resource map: %w", err)
	}
	whitelistWriteMeasurements, err := buildWhitelistWriteAllowlist(rm)
	if err != nil {
		return fmt.Errorf("build whitelist write allowlist: %w", err)
	}
	if len(whitelistWriteMeasurements) == 0 {
		slog.Warn("no whitelist write authorizer configured; mutation endpoints will reject all requests")
	} else {
		slog.Info("whitelist write resource map loaded", "resource", resources.AssamWhitelistWrite, "measurements", len(whitelistWriteMeasurements))
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

	asClient := attestationclient.NewClient(cfg.attestationSvcURL)

	ciHTTPClient, err := buildCertIssuerHTTPClient(cfg.certIssuerURL, certIssuerMeasurements, cfg.attestationSvcURL)
	if err != nil {
		return fmt.Errorf("build cert-issuer client: %w", err)
	}
	if !strings.HasPrefix(cfg.certIssuerURL, "https://") {
		slog.Warn("cert-issuer URL is plaintext HTTP; an on-path attacker between Assam and cert-issuer can forge sign-csr responses. Use https:// in production (the chart-managed CVM-only path does this).")
	} else if len(certIssuerMeasurements) == 0 {
		slog.Warn("--cert-issuer-measurements not set; the cert-issuer RA-TLS handshake accepts any measurement. Pin the operator-supplied launch digest to close bootstrap MITM.")
	}
	ciClient := certissuerclient.NewClientWithHTTP(cfg.certIssuerURL, ciHTTPClient)

	challengeStore := attestation.NewChallengeStore(cfg.challengeTTL)

	// Readiness checker (only checks attestation service health)
	checker := readiness.NewChecker(
		attestationclient.NewClient(cfg.attestationSvcURL),
		cfg.readinessInterval,
	)

	// Open whitelist store
	whitelistStore, err := whitelist.OpenStore(cfg.whitelistDB)
	if err != nil {
		return fmt.Errorf("failed to open whitelist database: %w", err)
	}
	defer whitelistStore.Close()

	writeAuthorizer := func(*http.Request, []byte) error {
		return fmt.Errorf("no measurements allowed for %s", resources.AssamWhitelistWrite)
	}
	if len(whitelistWriteMeasurements) > 0 {
		writeAuthorizer = whitelist.EARWriteAuthorizer{
			PublicKey:           earIssuer.PublicKey,
			ExpectedIssuer:      cfg.earIssuerName,
			AllowedMeasurements: whitelistWriteMeasurements,
			ClockSkew:           cfg.jwtClockSkew,
		}.Authorize
	}

	deps := server.Dependencies{
		AttestationHandler: attestation.Handler{
			Challenges:        &challengeStore,
			AttestationClient: asClient,
			CertIssuer:        ciClient,
			CertTTL:           cfg.certTTL.String(),
			EarIssuer:         earIssuer,
		},
		WhitelistHandler: whitelist.Handler{
			Store:             &whitelistStore,
			WriteAuthorizer:   writeAuthorizer,
			MaxWriteBodyBytes: cfg.whitelistMaxBodyBytes,
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

	if cfg.ratlsPlatform != "" {
		attestFunc := attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), cfg.attestationSvcURL)
		tlsCfg, certMgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
			Platform:   cfg.ratlsPlatform,
			AttestFunc: attestFunc,
			CertTTL:    cfg.ratlsCertTTL,
			Logger:     slog.Default(),
		})
		if err != nil {
			return fmt.Errorf("ratls server config: %w", err)
		}
		srv.TLSConfig = tlsCfg

		// Eagerly provision the serving cert so the first handshake doesn't
		// block on attestation.
		warmupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = certMgr.WarmUp(warmupCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("warm up ratls serving cert: %w", err)
		}

		go func() {
			<-ctx.Done()
			slog.Info("shutting down")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			srv.Shutdown(shutdownCtx)
		}()

		slog.Info("listening (RA-TLS)", "addr", addr, "platform", cfg.ratlsPlatform)
		// Empty cert/key paths: the cert is supplied by srv.TLSConfig.GetCertificate.
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			return err
		}
		return nil
	}

	slog.Warn("RA-TLS disabled (--ratls-platform empty); serving plain HTTP. UNSAFE outside tests.")

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

func loadResourceMap(path string) (resources.Map, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read resource map %s: %w", path, err)
	}
	var rm resources.Map
	if err := json.Unmarshal(data, &rm); err != nil {
		return nil, fmt.Errorf("parse resource map %s: %w", path, err)
	}
	return rm, nil
}

// buildCertIssuerHTTPClient picks an RA-TLS-aware http.Client when the
// cert-issuer URL is https; otherwise returns a plain-HTTP client. Empty
// measurements with https accepts ANY peer measurement — caller warns.
func buildCertIssuerHTTPClient(rawURL string, measurements [][]byte, attestationServiceURL string) (*http.Client, error) {
	if !strings.HasPrefix(rawURL, "https://") {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	return ratls.NewVerifyingHTTPClient(measurements, attestationServiceURL)
}

func buildWhitelistWriteAllowlist(rm resources.Map) (map[string]bool, error) {
	if len(rm) == 0 {
		return nil, nil
	}

	allowed := make(map[string]bool)
	for measurement, globs := range rm {
		for _, pattern := range globs {
			matched, err := path.Match(string(pattern), string(resources.AssamWhitelistWrite))
			if err != nil {
				return nil, fmt.Errorf("invalid resource map glob %q for measurement %q: %w", pattern, measurement, err)
			}
			if matched {
				allowed[measurement] = true
			}
		}
	}
	if len(allowed) == 0 {
		return nil, nil
	}
	return allowed, nil
}
