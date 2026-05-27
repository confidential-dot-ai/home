package certissuer

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	"github.com/lunal-dev/c8s/internal/issuer"
	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

// Run executes the cert-issuer binary. args is the slice of CLI args after
// the program name.
func Run(args []string) error {
	fs := flag.NewFlagSet("cert-issuer", flag.ContinueOnError)
	listen := fs.String("listen", ":8090", "listen address")
	caCommonName := fs.String("ca-common-name", issuer.DefaultCACommonName, "common name for an in-memory generated mesh CA")
	tokenCert := fs.String("token-cert", "", "path to EAR token-signer certificate (PEM, for JWT verification when --jwks-url is unset)")
	maxTTLF := fs.Duration("max-ttl", 24*time.Hour, "maximum certificate TTL")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	rateLimit := fs.Float64("rate-limit", 10, "maximum requests per second per source IP")
	rateBurst := fs.Int("rate-burst", 20, "maximum burst size per source IP")
	sanValidation := fs.Bool("san-validation", true, "validate CSR IP SANs match request source IP (false rejects CSRs carrying IP SANs)")
	dnsSANPattern := fs.String("dns-san-pattern", "", "regex pattern that must match allowed DNS SANs in full (empty = reject all DNS SANs)")
	allowedCNPattern := fs.String("allowed-cn-pattern", "", "regex pattern that must match allowed CNs in full (empty = no restriction)")
	expectedIssuer := fs.String("expected-issuer", "", "expected JWT issuer claim (empty = skip validation, with warning)")
	rateLimiterMax := fs.Int("rate-limiter-max-entries", 10000, "maximum entries in per-IP rate limiter")
	requestTimeout := fs.Duration("request-timeout", 5*time.Second, "per-request timeout for sign-csr handler")

	readTimeout := fs.Duration("read-timeout", 10*time.Second, "HTTP server read timeout")
	writeTimeout := fs.Duration("write-timeout", 10*time.Second, "HTTP server write timeout")
	idleTimeout := fs.Duration("idle-timeout", 20*time.Second, "HTTP server idle timeout")
	shutdownTimeout := fs.Duration("shutdown-timeout", 10*time.Second, "graceful server shutdown timeout")

	metricsUpdateInterval := fs.Duration("metrics-update-interval", 60*time.Second, "interval for cert expiry and node tracker metric updates")
	rateLimiterEvictInterval := fs.Duration("rate-limiter-evict-interval", 60*time.Second, "interval for per-IP rate limiter eviction sweep")
	rateLimiterIdleTimeout := fs.Duration("rate-limiter-idle-timeout", 5*time.Minute, "idle duration before a per-IP rate limiter entry is evicted")

	caRotationInterval := fs.Duration("ca-rotation-interval", 720*time.Hour, "positive interval for scheduled in-process mesh CA rotation")
	caRepoDir := fs.String("ca-repo-dir", "", "optional local path for public CA bundle write-back on startup and rotation; private keys are never persisted")
	caBundlePath := fs.String("ca-bundle-path", "ca-bundle.pem", "relative path under --ca-repo-dir for the public CA bundle")

	resourceMapF := fs.String("resource-map", "", "path to JSON resource map file for measurement-based endpoint access control")

	caCertValidity := fs.Duration("ca-cert-validity", 8760*time.Hour, "validity period for rotated CA certificates")
	jwtClockSkew := fs.Int64("jwt-clock-skew", 30, "clock skew tolerance in seconds for JWT validation")
	minCAValidity := fs.Duration("min-ca-validity", 1*time.Hour, "minimum remaining CA cert validity for readiness")
	maxRequestSize := fs.Int64("max-request-size", 65536, "maximum request body size in bytes")

	jwksURL := fs.String("jwks-url", "", "JWKS endpoint URL for EAR token verification (empty = use --token-cert). When the URL scheme is https, the fetch is RA-TLS-verified against --assam-measurements.")
	jwksCacheTTL := fs.Duration("jwks-cache-ttl", 5*time.Minute, "how long to cache the JWKS before re-fetching")
	assamMeasurementsRaw := fs.String("assam-measurements", "", "comma-separated SHA-384 hex launch measurements that Assam's RA-TLS peer cert must match. Used by JWKS fetch and handoff bootstrap. Empty = accept any (UNSAFE outside development; pin to the operator-supplied Assam launch digest).")

	handoffAssamURL := fs.String("handoff-assam-url", "", "Assam base URL used to bootstrap the in-process handoff signer key + EAR via /attest-key. Empty = /handoff disabled.")
	handoffAttestationServiceURL := fs.String("handoff-attestation-service-url", "", "local attestation service URL used by handoff bootstrap to mint TEE evidence binding the handoff signer key. Required when --handoff-assam-url is set.")

	ratlsPlatform := fs.String("ratls-platform", "", "TEE platform for the cert-issuer RA-TLS serving cert (snp, tdx, az-snp, az-tdx, gcp-snp, gcp-tdx). Empty disables TLS on the listener — UNSAFE outside tests; an on-path attacker between Assam and cert-issuer could otherwise forge sign-csr responses.")
	ratlsCertTTL := fs.Duration("ratls-cert-ttl", 24*time.Hour, "TTL for the cert-issuer RA-TLS serving certificate (rotated at 50%).")
	ratlsAttestationServiceURL := fs.String("ratls-attestation-service-url", "", "local attestation service URL used to mint evidence for the RA-TLS serving cert. Required when --ratls-platform is set.")

	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}

	logger, err := certutil.NewJSONLogger(*logLevel)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	slog.SetDefault(logger)

	if *jwtClockSkew < 0 {
		return fmt.Errorf("--jwt-clock-skew must be non-negative")
	}
	issuer.JWTClockSkew = time.Duration(*jwtClockSkew) * time.Second

	if *jwtClockSkew < 0 {
		return fmt.Errorf("--jwt-clock-skew must be non-negative")
	}
	issuer.JWTClockSkew = time.Duration(*jwtClockSkew) * time.Second

	if *caRotationInterval <= 0 {
		return fmt.Errorf("--ca-rotation-interval must be positive")
	}
	logger.Info("CA bundle management active")
	if *tokenCert == "" && *jwksURL == "" {
		return fmt.Errorf("either --token-cert or --jwks-url is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var tokenSignerCert *x509.Certificate
	var kp issuer.KeyProvider
	if *jwksURL != "" {
		jwksClient, err := buildJWKSHTTPClient(*jwksURL, *assamMeasurementsRaw, *ratlsAttestationServiceURL, logger)
		if err != nil {
			return err
		}
		provider, err := issuer.NewJWKSKeyProvider(ctx, *jwksURL, *jwksCacheTTL, jwksClient, logger)
		if err != nil {
			return fmt.Errorf("init JWKS key provider: %w", err)
		}
		kp = provider
		logger.Info("JWKS verification mode", "url", *jwksURL, "cache_ttl", *jwksCacheTTL)
	} else {
		cert, err := certutil.LoadCertificateFile(*tokenCert)
		if err != nil {
			return fmt.Errorf("load token-signer certificate: %w", err)
		}
		provider, err := issuer.NewCertKeyProvider(cert)
		if err != nil {
			return fmt.Errorf("invalid token-signer certificate: %w", err)
		}
		tokenSignerCert = cert
		kp = provider
	}

	var compiledDNSSANPattern *regexp.Regexp
	if *dnsSANPattern != "" {
		compiled, err := regexp.Compile(*dnsSANPattern)
		if err != nil {
			return fmt.Errorf("invalid --dns-san-pattern %q: %w", *dnsSANPattern, err)
		}
		compiledDNSSANPattern = compiled
		logger.Info("DNS SAN validation enabled", "pattern", *dnsSANPattern)
	}

	var compiledCNPattern *regexp.Regexp
	if *allowedCNPattern != "" {
		compiled, err := regexp.Compile(*allowedCNPattern)
		if err != nil {
			return fmt.Errorf("invalid --allowed-cn-pattern %q: %w", *allowedCNPattern, err)
		}
		compiledCNPattern = compiled
		logger.Info("CN validation enabled", "pattern", *allowedCNPattern)
	}

	if *expectedIssuer == "" {
		logger.Warn("--expected-issuer not set: JWT issuer claim will not be validated")
	}

	var signCSRMeasurements, handoffMeasurements map[string]bool
	if *resourceMapF != "" {
		rm, err := loadResourceMap(*resourceMapF)
		if err != nil {
			return fmt.Errorf("load resource map: %w", err)
		}
		signCSRMeasurements, handoffMeasurements, err = buildEndpointAllowlists(rm)
		if err != nil {
			return fmt.Errorf("build resource map allowlists: %w", err)
		}
		logger.Info("resource map loaded", "path", *resourceMapF)
	}

	ca, err := issuer.NewCAWithCurve(*caCommonName, *caCertValidity, elliptic.P384())
	if err != nil {
		return fmt.Errorf("generate in-memory CA: %w", err)
	}
	caKey := ca.Key
	caCert := ca.Cert
	if err := validateCAKeyPair(caCert, caKey); err != nil {
		return err
	}
	logger.Info("generated in-memory mesh CA",
		"ca_fingerprint", certutil.CertFingerprint(caCert.Raw),
		"not_after", caCert.NotAfter.Format(time.RFC3339),
	)

	iss := &Issuer{
		keyProvider:         kp,
		MaxTTL:              *maxTTLF,
		SANValidation:       *sanValidation,
		DNSSANPattern:       compiledDNSSANPattern,
		AllowedCNPattern:    compiledCNPattern,
		ExpectedIssuer:      *expectedIssuer,
		RequestTimeout:      *requestTimeout,
		MinCAValidity:       *minCAValidity,
		Logger:              logger,
		tracker:             newNodeTracker(*maxTTLF),
		SignCSRMeasurements: signCSRMeasurements,
		HandoffMeasurements: handoffMeasurements,
	}

	if len(iss.SignCSRMeasurements) > 0 {
		logger.Info("measurement pinning enabled for /sign-csr", "count", len(iss.SignCSRMeasurements))
	}
	if len(iss.HandoffMeasurements) > 0 {
		logger.Info("measurement pinning enabled for /handoff", "count", len(iss.HandoffMeasurements))
	}
	iss.bundle.Store(&certBundle{
		caCert:          caCert,
		caKey:           caKey,
		tokenSignerCert: tokenSignerCert,
	})

	// Set initial CA fingerprint metric.
	initialFingerprint := certutil.CertFingerprint(caCert.Raw)
	caCertFingerprintInfo.WithLabelValues(initialFingerprint).Set(1)

	rl := newIPRateLimiter(rate.Limit(*rateLimit), *rateBurst, *rateLimiterMax)

	// Initialize public bundle manager.
	bm := issuer.NewBundleManager(*maxTTLF, *caRepoDir, *caBundlePath, logger)

	// Try to load existing public bundle from the repo (restart recovery).
	existingBundle, err := bm.LoadFromRepo()
	if err != nil {
		logger.Warn("failed to load existing public CA bundle", "error", err)
	}
	if existingBundle != nil {
		bm.SetWithCurrent(caCert, existingBundle)
		logger.Info("loaded existing public CA bundle", "count", len(existingBundle))
	} else {
		bm.SetInitial(caCert)
	}
	if err := bm.PersistCurrent(); err != nil {
		return fmt.Errorf("persist initial public CA bundle: %w", err)
	}
	iss.caBundle = bm

	rotator, err := issuer.NewCARotator(newCARotatorDeps(iss, bm, *caCertValidity, *caCommonName))
	if err != nil {
		return fmt.Errorf("init CA rotator: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /sign-csr", http.MaxBytesHandler(rateLimitMiddleware(rl, http.HandlerFunc(iss.HandleSignCSR)), *maxRequestSize))
	mux.HandleFunc("GET /live", handleLive)
	mux.HandleFunc("GET /ready", iss.handleReady)
	mux.Handle("GET /metrics", promhttp.Handler())

	// /ca serves the public bundle unauthenticated; clients chain the
	// continuity check (see pkg/ratls/assamclient) to reject untrusted updates.
	mux.Handle("GET /ca", rateLimitMiddleware(rl, http.HandlerFunc(handlePublicCA(bm))))

	if *handoffAssamURL != "" && *handoffAttestationServiceURL == "" {
		return fmt.Errorf("--handoff-attestation-service-url is required when --handoff-assam-url is set")
	}
	var handoffSrc handoffEARSource
	var handoffBoot *handoffBootstrap
	if *handoffAssamURL != "" {
		measurements, err := ratls.ParseHexMeasurements(*assamMeasurementsRaw)
		if err != nil {
			return fmt.Errorf("--assam-measurements: %w", err)
		}
		if len(measurements) == 0 {
			logger.Warn("--assam-measurements not set; handoff bootstrap accepts any Assam measurement. Pin the operator-supplied launch digest to close bootstrap MITM.")
		}

		boot, err := newHandoffBootstrap(*handoffAssamURL, *handoffAttestationServiceURL, measurements)
		if err != nil {
			return fmt.Errorf("prepare handoff bootstrap: %w", err)
		}

		hh, err := newHandoffHandler(iss, bm, boot.signer, boot.earSource)
		if err != nil {
			return err
		}
		mux.Handle("POST /handoff", http.MaxBytesHandler(rateLimitMiddleware(rl, http.HandlerFunc(hh.HandleHandoff)), *maxRequestSize))
		logger.Info("attested CA handoff enabled (bootstrap will run in background)",
			"assam_url", *handoffAssamURL,
			"measurements", len(iss.HandoffMeasurements),
			"pinned_assam_measurements", len(measurements),
		)
		handoffSrc = hh.issuerEARSource
		handoffBoot = boot
	}

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		IdleTimeout:  *idleTimeout,
	}

	if *ratlsPlatform != "" {
		if *ratlsAttestationServiceURL == "" {
			return fmt.Errorf("--ratls-attestation-service-url is required when --ratls-platform is set")
		}
		attestFunc := attestclient.MakeSNPRATLSAttestFunc(attestclient.NewClient(""), *ratlsAttestationServiceURL)
		tlsCfg, certMgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
			Platform:   *ratlsPlatform,
			AttestFunc: attestFunc,
			CertTTL:    *ratlsCertTTL,
			Logger:     logger,
		})
		if err != nil {
			return fmt.Errorf("ratls server config: %w", err)
		}
		srv.TLSConfig = tlsCfg

		warmupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = certMgr.WarmUp(warmupCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("warm up ratls serving cert: %w", err)
		}
	} else {
		logger.Warn("RA-TLS disabled (--ratls-platform empty); serving plain HTTP. UNSAFE outside tests.")
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}

	go rotator.Run(ctx, *caRotationInterval)
	logger.Info("scheduled CA rotation enabled", "interval", caRotationInterval.String())

	// Update cert expiry gauges periodically.
	go certExpiryUpdater(ctx, iss, *metricsUpdateInterval)

	// Start rate limiter eviction goroutine.
	go rl.evictionLoop(ctx, *rateLimiterEvictInterval, *rateLimiterIdleTimeout)

	// Start node tracker metric updater.
	go nodeTrackerUpdater(ctx, iss.tracker, *metricsUpdateInterval)

	if handoffSrc != nil {
		go handoffEARExpiryUpdater(ctx, handoffSrc, *metricsUpdateInterval, logger)
	}
	if handoffBoot != nil {
		go handoffBoot.runRefresh(ctx, logger)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	if srv.TLSConfig != nil {
		logger.Info("cert-issuer starting (RA-TLS)", "address", ln.Addr().String(), "platform", *ratlsPlatform)
		if err := srv.ServeTLS(ln, "", ""); err != http.ErrServerClosed {
			return fmt.Errorf("server: %w", err)
		}
		return nil
	}
	logger.Info("cert-issuer starting", "address", ln.Addr().String())
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}

func handleLive(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

// certExpiryUpdater updates the CA and token cert expiry gauges on the given interval.
func certExpiryUpdater(ctx context.Context, iss *Issuer, interval time.Duration) {
	update := func() {
		b := iss.bundle.Load()
		if b == nil {
			return
		}
		now := time.Now()
		caCertExpirySeconds.Set(b.caCert.NotAfter.Sub(now).Seconds())
		if b.tokenSignerCert != nil {
			tokenCertExpirySeconds.Set(b.tokenSignerCert.NotAfter.Sub(now).Seconds())
		}
	}
	update()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			update()
		}
	}
}

// nodeTrackerUpdater periodically updates aggregate node metrics.
func nodeTrackerUpdater(ctx context.Context, tracker *nodeTracker, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tracker.updateMetrics()
		}
	}
}

// ipLimiterEntry wraps a rate.Limiter with a last-seen timestamp for eviction.
type ipLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// ipRateLimiter implements per-source-IP rate limiting with bounded memory.
type ipRateLimiter struct {
	mu         sync.Mutex
	limiters   map[string]*ipLimiterEntry
	rate       rate.Limit
	burst      int
	maxEntries int
}

func newIPRateLimiter(r rate.Limit, b, maxEntries int) *ipRateLimiter {
	return &ipRateLimiter{
		limiters:   make(map[string]*ipLimiterEntry),
		rate:       r,
		burst:      b,
		maxEntries: maxEntries,
	}
}

func (rl *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if entry, ok := rl.limiters[ip]; ok {
		entry.lastSeen = time.Now()
		return entry.limiter
	}
	// Enforce max entries cap.
	if len(rl.limiters) >= rl.maxEntries {
		// Evict oldest entry.
		var oldestIP string
		var oldestTime time.Time
		for ip, entry := range rl.limiters {
			if oldestTime.IsZero() || entry.lastSeen.Before(oldestTime) {
				oldestIP = ip
				oldestTime = entry.lastSeen
			}
		}
		if oldestIP != "" {
			delete(rl.limiters, oldestIP)
		}
	}
	lim := rate.NewLimiter(rl.rate, rl.burst)
	rl.limiters[ip] = &ipLimiterEntry{
		limiter:  lim,
		lastSeen: time.Now(),
	}
	return lim
}

// evictionLoop removes rate limiter entries idle longer than idleTimeout.
func (rl *ipRateLimiter) evictionLoop(ctx context.Context, interval, idleTimeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.evict(idleTimeout)
		}
	}
}

func (rl *ipRateLimiter) evict(idleTimeout time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-idleTimeout)
	for ip, entry := range rl.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(rl.limiters, ip)
		}
	}
	rateLimiterEntries.Set(float64(len(rl.limiters)))
}

func rateLimitMiddleware(rl *ipRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		if !rl.getLimiter(ip).Allow() {
			rateLimitRejectionsTotal.Inc()
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
