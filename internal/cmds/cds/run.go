package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/readiness"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/earsigner"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"golang.org/x/time/rate"
)

func run(cfg config) error {
	logger, err := certutil.NewJSONLogger(cfg.logLevel)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := cmdsutil.ValidateHTTPURL("--attestation-api-url", cfg.attestationApiURL); err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	cfg.ratlsPlatform = normalizeRATLSPlatform(cfg.ratlsPlatform)

	// EAR JWT validation reads the clock-skew leeway from this package-level
	// var; set it before any /sign-csr request can be served.
	issuer.JWTClockSkew = time.Duration(cfg.jwtClockSkew) * time.Second

	rateLimiter, err := issuer.NewIPRateLimiter(rate.Limit(cfg.rateLimit), cfg.rateBurst, cfg.rateLimiterMax)
	if err != nil {
		return fmt.Errorf("init rate limiter: %w", err)
	}

	// Load the operator policy before either side of handoff is attested. Its
	// canonical hash is committed to REPORTDATA by both replicas and compared
	// before any CA or allowlist state is released.
	var writeAuthorizer allowlist.WriteAuthorizer = func(*http.Request, []byte) error {
		return fmt.Errorf("allowlist writes are disabled: set --operator-keys")
	}
	var operatorKeysPEM []byte
	var operatorKeysHash string
	if cfg.operatorKeys != "" {
		keys, pemBytes, err := loadOperatorKeys(cfg.operatorKeys)
		if err != nil {
			return err
		}
		operatorKeysHash, err = operatorauth.KeySetHash(keys)
		if err != nil {
			return fmt.Errorf("hash --operator-keys %q: %w", cfg.operatorKeys, err)
		}
		operatorKeysPEM = pemBytes
		writeAuthorizer = operatorauth.Verifier{
			Keys:      keys,
			ClockSkew: time.Duration(cfg.jwtClockSkew) * time.Second,
		}.Authorize
		slog.Info("allowlist write authorization enabled (pinned operator keys)", "operator_keys", cfg.operatorKeys, "count", len(keys), "key_set_hash", operatorKeysHash)
	} else {
		slog.Warn("--operator-keys empty: allowlist writes are disabled (reads still served)")
	}

	allowlistStore, err := allowlist.OpenStore(cfg.allowlistDB)
	if err != nil {
		return fmt.Errorf("open allowlist database: %w", err)
	}
	defer allowlistStore.Close()

	// CDS obtains its mesh CA in process; the private key never touches a
	// Kubernetes Secret. With no --handoff-peer-url it generates a fresh
	// self-signed CA (cold start); with a peer set it adopts that peer's CA
	// via attested /handoff, failing closed if the peer cannot be reached or
	// denies the handoff so a partition never mints a divergent trust root.
	mesh, adopted, err := issuer.ProvisionCA(ctx, issuer.CAProvisionConfig{
		CommonName:        cfg.caCommonName,
		Validity:          cfg.caCertValidity,
		Curve:             elliptic.P384(),
		PeerURL:           strings.TrimRight(cfg.handoffPeerURL, "/"),
		AttestationApiURL: cfg.attestationApiURL,
		Measurements:      cfg.handoffMeasurements,
		ExpectedIssuer:    cfg.earIssuerName,
		Timeout:           cfg.handoffPeerTimeout,
		OperatorKeysHash:  operatorKeysHash,
		RestoreAllowlist:  allowlistStore.RestoreSnapshot,
	}, slog.Default())
	if err != nil {
		return fmt.Errorf("provision mesh CA: %w", err)
	}
	slog.Info("loaded in-memory mesh CA",
		"source", map[bool]string{true: "adopted-from-peer", false: "self-generated"}[adopted],
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

	dnsPatterns, err := compilePatterns("--dns-san-pattern", cfg.dnsSANPatterns)
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

	asClient := attestationclient.NewClient(cfg.attestationApiURL)
	challengeStore := attestation.NewChallengeStore(cfg.challengeTTL)
	checker := readiness.NewChecker(asClient, cfg.readinessInterval)

	// Seed before serving so the first GET /allowlist returns the bootstrap
	// allowlist (CDS, attestation-api, system images) rather than an empty
	// set; an unseeded store would deny every worker pull until an operator
	// populated it. Fail closed on any seed error.
	if cfg.allowlistSeed != "" {
		if err := seedStore(&allowlistStore, cfg.allowlistSeed); err != nil {
			return fmt.Errorf("seed allowlist: %w", err)
		}
	}

	if !cfg.allowlistPersistent {
		if adopted {
			slog.Warn("allowlist store is not durable (cds.persistence.enabled=false): this planned adoption restored the peer's dynamic entries, but a total CDS outage and deliberate re-bootstrap still resets them to the install seed")
		} else {
			slog.Warn("allowlist store is not persistent (cds.persistence.enabled=false): a restart without a surviving handoff peer resets the served allowlist to the install seed and regenerates the mesh CA. Operator-added digests do not survive")
		}
	}

	policy := issuer.CSRPolicy{
		DNSSANPatterns:   dnsPatterns,
		AllowedCNPattern: cnPattern,
	}

	// /attest-key issues a TEE-attested EAR for a caller-generated key (no CSR,
	// no certificate). Shares the challenge store, attestation-api, and EAR
	// issuer with /attest.
	attestKeyOperatorPolicy := ""
	if len(cfg.handoffMeasurements) > 0 {
		attestKeyOperatorPolicy = operatorKeysHash
	}
	attestKeyHandler := attestation.Handler{
		Challenges:        &challengeStore,
		AttestationClient: asClient,
		EarIssuer:         earIssuer,
		OperatorKeysHash:  attestKeyOperatorPolicy,
	}

	handoffHandler, err := buildHandoffHandler(ctx, cfg, mesh, &allowlistStore, operatorKeysHash, rotator, earIssuer, asClient)
	if err != nil {
		return err
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
		AllowlistHandler: allowlist.Handler{
			Store:           &allowlistStore,
			WriteAuthorizer: writeAuthorizer,
		},
		AttestKeyHandler: attestKeyHandler,
		HandoffHandler:   handoffHandler,
		ReadyFn:          readinessFn(checker.Ready, mesh.Cert, cfg.minCAValidity),
		EarIssuer:        earIssuer,
		JWKSFunc:         rotator.JWKSetJSON,
		CACertPEM:        caChainPEM,
		OperatorKeysPEM:  operatorKeysPEM,
		RateLimiter:      rateLimiter,
		MaxRequestSize:   cfg.maxRequestSize,
	}
	if cfg.rotationInterval > 0 {
		go rotator.Run(ctx)
	}
	go rateLimiter.EvictionLoop(ctx, cfg.rateLimiterEvictInterval, cfg.rateLimiterIdleTimeout)

	router := newRouter(deps)

	go checker.Run(ctx)

	addr := fmt.Sprintf("%s:%d", cfg.host, cfg.port)
	srv := newHTTPServer(addr, router, cfg)

	if cfg.ratlsPlatform != "" {
		attestFunc := attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), cfg.attestationApiURL)
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

// buildHandoffHandler wires the /handoff endpoint that hands the in-memory mesh
// CA to an attested peer replica. It is disabled (returns nil) unless
// --handoff-measurements pins which peer launch digests may pull the CA.
//
// cds self-provisions its handoff signer EAR in process via
// LocalHandoffBootstrap: cds is its own EAR issuer, so the requester EAR is
// validated against cds's own rotator/issuer name, and the signer EAR is minted
// by cds's earIssuer — no external service to dial for it.
func buildHandoffHandler(ctx context.Context, cfg config, mesh *issuer.CA, allowlistStore *allowlist.Store, operatorKeysHash string, keyProvider issuer.KeyProvider, earIssuer ear.Issuer, asClient attestationclient.Client) (*issuer.HandoffHandler, error) {
	handoffMeasurements := parseMeasurementAllowlist(cfg.handoffMeasurements)
	if len(handoffMeasurements) == 0 {
		slog.Info("/handoff disabled: set --handoff-measurements to enable mesh CA handoff to peer replicas")
		return nil, nil
	}

	boot, err := issuer.NewLocalHandoffBootstrap(asClient, earIssuer, operatorKeysHash)
	if err != nil {
		return nil, fmt.Errorf("prepare handoff bootstrap: %w", err)
	}

	hh, err := issuer.NewHandoffHandler(issuer.HandoffDeps{
		Logger:              slog.Default(),
		KeyProvider:         keyProvider,
		ExpectedIssuer:      cfg.earIssuerName,
		AllowedMeasurements: handoffMeasurements,
		OperatorKeysHash:    operatorKeysHash,
		Signer:              boot.Signer(),
		EARSource:           boot.EARSource(),
		Snapshot: func() (issuer.CASnapshot, bool) {
			version, digests, err := allowlistStore.ListAll()
			if err != nil {
				slog.Error("snapshot allowlist for handoff", "error", err)
				return issuer.CASnapshot{}, false
			}
			return issuer.CASnapshot{
				Cert:             mesh.Cert,
				Key:              mesh.Key,
				AllowlistVersion: version,
				Allowlist:        digests,
			}, true
		},
	})
	if err != nil {
		return nil, err
	}

	go boot.RunRefresh(ctx, slog.Default())
	go issuer.RunHandoffEARExpiryUpdater(ctx, hh.IssuerEARSource(), time.Minute, slog.Default())
	slog.Info("attested CA handoff enabled (bootstrap runs in background)", "measurements", len(handoffMeasurements))
	return hh, nil
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
	if len(cfg.handoffMeasurements) > 0 && cfg.operatorKeys == "" {
		return fmt.Errorf("--handoff-measurements requires --operator-keys so the operator policy is bound into handoff attestation")
	}
	if cfg.handoffPeerURL != "" {
		if !strings.HasPrefix(cfg.handoffPeerURL, "https://") {
			return fmt.Errorf("--handoff-peer-url must use https (RA-TLS)")
		}
		if len(cfg.handoffMeasurements) == 0 {
			return fmt.Errorf("--handoff-peer-url requires --handoff-measurements to pin the peer")
		}
		if cfg.handoffPeerTimeout <= 0 {
			return fmt.Errorf("--handoff-peer-timeout must be positive")
		}
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

// compilePatterns compiles each raw pattern, skipping empties so a stray "" in
// the list does not become a match-nothing rule. Returns nil for no patterns,
// which ValidateCSR treats as "reject any DNS SAN".
func compilePatterns(name string, raws []string) ([]*regexp.Regexp, error) {
	var patterns []*regexp.Regexp
	for _, raw := range raws {
		re, err := compilePattern(name, raw)
		if err != nil {
			return nil, err
		}
		if re != nil {
			patterns = append(patterns, re)
		}
	}
	return patterns, nil
}

// loadOperatorKeys reads the PEM operator public-key bundle used to verify
// operator write tokens, returning both the parsed keys and the raw PEM (served
// back on GET /operator-keys). It fails closed when the file has no EC public
// key so a typo cannot silently disable write authorization.
func loadOperatorKeys(path string) ([]*ecdsa.PublicKey, []byte, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read --operator-keys: %w", err)
	}
	keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("--operator-keys %q: %w", path, err)
	}
	return keys, pemBytes, nil
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
// attestation-api is unhealthy or the loaded mesh CA is within
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
