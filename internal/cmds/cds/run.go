package cds

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/lunal-dev/c8s/internal/attestation"
	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	"github.com/lunal-dev/c8s/internal/ear"
	"github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/internal/readiness"
	"github.com/lunal-dev/c8s/internal/whitelist"
	"github.com/lunal-dev/c8s/pkg/attestationclient"
	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/earsigner"
	"github.com/lunal-dev/c8s/pkg/ratls"
)

func run(cfg config) error {
	logger, err := certutil.NewJSONLogger(cfg.logLevel)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := cmdsutil.ValidateHTTPURL("--attestation-service-url", cfg.attestationSvcURL); err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	cfg.ratlsPlatform = normalizeRATLSPlatform(cfg.ratlsPlatform)

	// CDS generates its mesh CA in process; the private key never touches a
	// Kubernetes Secret. Rotation and public-bundle write-back land with the
	// in-memory CA machinery in a later stack PR.
	mesh, err := issuer.NewCAWithCurve(cfg.caCommonName, cfg.caCertValidity, elliptic.P384())
	if err != nil {
		return fmt.Errorf("generate mesh CA: %w", err)
	}
	slog.Info("generated in-memory mesh CA",
		"fingerprint", certutil.CertFingerprint(mesh.Cert.Raw),
		"not_after", mesh.Cert.NotAfter.Format(time.RFC3339),
	)
	caChainPEM := certutil.EncodeCertPEM(mesh.Cert.Raw)

	measurements := parseMeasurementAllowlist(cfg.measurements)
	if len(measurements) == 0 {
		slog.Warn("--measurements empty: /attest accepts any TEE measurement. UNSAFE outside development.")
	} else {
		slog.Info("measurement pinning enabled for /attest", "count", len(measurements))
	}

	dnsPattern, err := compilePattern("--dns-san-pattern", cfg.dnsSANPattern)
	if err != nil {
		return err
	}
	cnPattern, err := compilePattern("--allowed-cn-pattern", cfg.allowedCNPattern)
	if err != nil {
		return err
	}

	earKeyPEM, err := earsigner.Generate()
	if err != nil {
		return fmt.Errorf("generate token-signing key: %w", err)
	}
	earIssuer, err := ear.NewIssuer(earKeyPEM, cfg.earIssuerName, cfg.certTTL)
	if err != nil {
		return fmt.Errorf("create EAR issuer: %w", err)
	}

	rotator, err := earsigner.NewRotator(earsigner.RotatorConfig{
		Interval: cfg.rotationInterval,
		Overlap:  cfg.rotationOverlap,
		Jitter:   cfg.rotationJitter,
		Logger:   slog.Default(),
	}, earKeyPEM, earIssuer.SwapKey)
	if err != nil {
		return fmt.Errorf("create EAR key rotator: %w", err)
	}

	asClient := attestationclient.NewClient(cfg.attestationSvcURL)
	challengeStore := attestation.NewChallengeStore(cfg.challengeTTL)
	checker := readiness.NewChecker(asClient, cfg.readinessInterval)

	whitelistStore, err := whitelist.OpenStore(cfg.whitelistDB)
	if err != nil {
		return fmt.Errorf("open whitelist database: %w", err)
	}
	defer whitelistStore.Close()

	// /whitelist mutations are out of scope for PR #2a (resource-map-driven
	// EAR authorizer lands with the measurement pinning in PR #2c). For now,
	// reject all writes so the endpoint stays present but useless.
	rejectAllWrites := func(*http.Request, []byte) error {
		return fmt.Errorf("whitelist mutations require an EAR authorizer (see cds #2c)")
	}

	policy := issuer.CSRPolicy{
		DNSSANPattern:    dnsPattern,
		AllowedCNPattern: cnPattern,
	}
	deps := dependencies{
		AttestHandler: AttestHandler{
			Challenges:        &challengeStore,
			AttestationClient: asClient,
			CA:                mesh,
			CAChainPEM:        caChainPEM,
			CertTTL:           cfg.certTTL,
			RequestTimeout:    cfg.requestTimeout,
			Measurements:      measurements,
			SANValidation:     cfg.sanValidation,
			Policy:            policy,
		},
		SignCSRHandler: SignCSRHandler{
			CA:             mesh,
			CAChainPEM:     caChainPEM,
			MaxTTL:         cfg.maxTTL,
			KeyProvider:    rotator,
			ExpectedIssuer: cfg.expectedIssuer,
			RequestTimeout: cfg.requestTimeout,
			Measurements:   measurements,
			Policy:         policy,
			SANValidation:  cfg.sanValidation,
		},
		WhitelistHandler: whitelist.Handler{
			Store:           &whitelistStore,
			WriteAuthorizer: rejectAllWrites,
		},
		ReadyFn:        readinessFn(checker.Ready, mesh.Cert, cfg.minCAValidity),
		EarIssuer:      earIssuer,
		JWKSFunc:       rotator.JWKSetJSON,
		CACertPEM:      caChainPEM,
		MaxRequestSize: cfg.maxRequestSize,
	}
	if cfg.rotationInterval > 0 {
		go rotator.Run(ctx)
	}

	router := newRouter(deps)

	go checker.Run(ctx)

	addr := fmt.Sprintf("%s:%d", cfg.host, cfg.port)
	srv := newHTTPServer(addr, router, cfg)

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

		warmupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = certMgr.WarmUp(warmupCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("warm up ratls serving cert: %w", err)
		}

		go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)

		slog.Info("cds listening (RA-TLS)", "addr", addr, "platform", cfg.ratlsPlatform)
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			return err
		}
		return nil
	}

	slog.Warn("RA-TLS disabled (--ratls-platform empty); serving plain HTTP. UNSAFE outside tests.")
	go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)

	slog.Info("cds listening", "addr", addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func newHTTPServer(addr string, handler http.Handler, cfg config) *http.Server {
	cfg = normalizeHTTPServerConfig(cfg)
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       cfg.readTimeout,
		ReadHeaderTimeout: cfg.readHeaderTimeout,
		WriteTimeout:      cfg.writeTimeout,
		IdleTimeout:       cfg.idleTimeout,
		MaxHeaderBytes:    cfg.maxHeaderBytes,
	}
}

func normalizeHTTPServerConfig(cfg config) config {
	if cfg.readTimeout == 0 {
		cfg.readTimeout = defaultHTTPReadTimeout
	}
	if cfg.readHeaderTimeout == 0 {
		cfg.readHeaderTimeout = defaultHTTPReadHeaderTimeout
	}
	if cfg.writeTimeout == 0 {
		cfg.writeTimeout = defaultHTTPWriteTimeout
	}
	if cfg.idleTimeout == 0 {
		cfg.idleTimeout = defaultHTTPIdleTimeout
	}
	if cfg.maxHeaderBytes == 0 {
		cfg.maxHeaderBytes = defaultHTTPMaxHeaderBytes
	}
	return cfg
}

func validateConfig(cfg config) error {
	for _, timeout := range []struct {
		name  string
		value time.Duration
	}{
		{"--read-timeout", cfg.readTimeout},
		{"--read-header-timeout", cfg.readHeaderTimeout},
		{"--write-timeout", cfg.writeTimeout},
		{"--idle-timeout", cfg.idleTimeout},
	} {
		if timeout.value < 0 {
			return fmt.Errorf("%s must be non-negative", timeout.name)
		}
	}
	if cfg.maxHeaderBytes < 0 {
		return fmt.Errorf("--max-header-bytes must be non-negative")
	}
	if cfg.maxTTL <= 0 {
		return fmt.Errorf("--max-ttl must be positive")
	}
	if cfg.maxRequestSize <= 0 {
		return fmt.Errorf("--max-request-size must be positive")
	}
	if cfg.readinessInterval <= 0 {
		return fmt.Errorf("--readiness-interval must be positive")
	}
	return nil
}

func compilePattern(name, raw string) (*regexp.Regexp, error) {
	if raw == "" {
		return nil, nil
	}
	re, err := regexp.Compile(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s %q: %w", name, raw, err)
	}
	return re, nil
}

func parseMeasurementAllowlist(raw []string) map[string]bool {
	if len(raw) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(raw))
	for _, m := range raw {
		m = issuer.NormalizeMeasurement(m)
		if m != "" {
			allowed[m] = true
		}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

// readinessFn returns a closure that flips /readyz to 503 when either the
// attestation service is unhealthy or the loaded mesh CA is within
// minCAValidity of expiry. The CA expiry signal gives operators a window to
// rotate before signing requests start producing leaves that outlive the CA.
func readinessFn(svcReady func() bool, caCert *x509.Certificate, minCAValidity time.Duration) func() bool {
	return func() bool {
		if !svcReady() {
			return false
		}
		if caCert == nil {
			return false
		}
		if minCAValidity > 0 && time.Until(caCert.NotAfter) < minCAValidity {
			return false
		}
		return true
	}
}

func normalizeRATLSPlatform(platform string) string {
	switch p := strings.ToLower(strings.TrimSpace(platform)); p {
	case "snp", "sev-snp", "az-snp", "gcp-snp":
		return "sev-snp"
	case "tdx", "az-tdx", "gcp-tdx":
		return "tdx"
	default:
		return p
	}
}
