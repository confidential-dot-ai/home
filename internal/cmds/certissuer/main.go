package certissuer

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

// Run executes the cert-issuer binary. args is the slice of CLI args after
// the program name.
func Run(args []string) error {
	fs := flag.NewFlagSet("cert-issuer", flag.ContinueOnError)
	listen := fs.String("listen", ":8090", "listen address")
	caKeyF := fs.String("ca-key", "", "path to CA private key (PEM)")
	caCertF := fs.String("ca-cert", "", "path to CA certificate (PEM)")
	tokenCert := fs.String("token-cert", "", "path to EAR token-signer certificate (PEM, for JWT verification when --jwks-url is unset)")
	maxTTLF := fs.Duration("max-ttl", 24*time.Hour, "maximum certificate TTL")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	rateLimit := fs.Float64("rate-limit", 10, "maximum requests per second per source IP")
	rateBurst := fs.Int("rate-burst", 20, "maximum burst size per source IP")
	sanValidation := fs.Bool("san-validation", true, "validate CSR IP SANs match request source IP")
	parentCertF := fs.String("parent-cert", "", "path to parent (root) CA certificate for intermediate CA mode")
	dnsSANPattern := fs.String("dns-san-pattern", "", "regex pattern for allowed DNS SANs in CSRs (empty = reject all DNS SANs)")
	allowedCNPattern := fs.String("allowed-cn-pattern", "", "regex pattern for allowed CN in CSRs (empty = no restriction)")
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

	kbsModeF := fs.Bool("kbs-mode", false, "enable CDS mode: JWT-gated /v1/ca, /v1/rotate-ca endpoint, CA bundle management")
	caRepoDir := fs.String("ca-repo-dir", "/opt/confidential-containers/kbs/crypto-keys", "local path for CDS CA key write-back on rotation")

	resourceMapF := fs.String("resource-map", "", "path to JSON resource map file for measurement-based endpoint access control")

	caCertValidity := fs.Duration("ca-cert-validity", 8760*time.Hour, "validity period for rotated CA certificates")
	jwtClockSkew := fs.Int64("jwt-clock-skew", 30, "clock skew tolerance in seconds for JWT validation")
	minCAValidity := fs.Duration("min-ca-validity", 1*time.Hour, "minimum remaining CA cert validity for readiness")
	maxRequestSize := fs.Int64("max-request-size", 65536, "maximum request body size in bytes")
	certWatchDebounce := fs.Duration("cert-watch-debounce", 2*time.Second, "debounce delay for certificate file watcher")

	jwksURL := fs.String("jwks-url", "", "JWKS endpoint URL for EAR token verification (empty = use --token-cert)")
	jwksCacheTTL := fs.Duration("jwks-cache-ttl", 5*time.Minute, "how long to cache the JWKS before re-fetching")
	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}

	logger := certutil.NewJSONLogger(*logLevel)

	kbsMode := *kbsModeF
	if kbsMode {
		logger.Info("CDS mode enabled: /v1/rotate-ca and JWT-gated /v1/ca active")
	}

	if *caKeyF == "" || *caCertF == "" {
		return fmt.Errorf("--ca-key and --ca-cert are required")
	}
	if *tokenCert == "" && *jwksURL == "" {
		return fmt.Errorf("either --token-cert or --jwks-url is required")
	}

	caKey, err := certutil.LoadECPrivateKeyFile(*caKeyF)
	if err != nil {
		return fmt.Errorf("load CA key: %w", err)
	}

	caCert, err := certutil.LoadCertificateFile(*caCertF)
	if err != nil {
		return fmt.Errorf("load CA certificate: %w", err)
	}

	var kp KeyProvider
	if *jwksURL != "" {
		kp = newJWKSKeyProvider(*jwksURL, *jwksCacheTTL, logger)
		logger.Info("JWKS verification mode", "url", *jwksURL, "cache_ttl", *jwksCacheTTL)
	} else {
		tokenSignerCert, err := certutil.LoadCertificateFile(*tokenCert)
		if err != nil {
			return fmt.Errorf("load token-signer certificate: %w", err)
		}
		kp, err = newCertKeyProvider(tokenSignerCert)
		if err != nil {
			return fmt.Errorf("invalid token-signer certificate: %w", err)
		}
	}

	var parentCert *x509.Certificate
	if *parentCertF != "" {
		parentCert, err = certutil.LoadCertificateFile(*parentCertF)
		if err != nil {
			return fmt.Errorf("load parent CA certificate: %w", err)
		}
		if err := validateChain(caCert, parentCert); err != nil {
			return fmt.Errorf("intermediate CA chain validation: %w", err)
		}
		logger.Info("intermediate CA mode enabled", "parent_subject", parentCert.Subject.CommonName)
	}

	var compiledDNSSANPattern *regexp.Regexp
	if *dnsSANPattern != "" {
		compiledDNSSANPattern, err = regexp.Compile(*dnsSANPattern)
		if err != nil {
			return fmt.Errorf("invalid --dns-san-pattern %q: %w", *dnsSANPattern, err)
		}
		logger.Info("DNS SAN validation enabled", "pattern", *dnsSANPattern)
	}

	var compiledCNPattern *regexp.Regexp
	if *allowedCNPattern != "" {
		compiledCNPattern, err = regexp.Compile(*allowedCNPattern)
		if err != nil {
			return fmt.Errorf("invalid --allowed-cn-pattern %q: %w", *allowedCNPattern, err)
		}
		logger.Info("CN validation enabled", "pattern", *allowedCNPattern)
	}

	if *expectedIssuer == "" {
		logger.Warn("--expected-issuer not set: JWT issuer claim will not be validated")
	}

	var signCSRMeasurements, rotateCAMeasurements, caMeasurements map[string]bool
	if *resourceMapF != "" {
		rm, err := loadResourceMap(*resourceMapF)
		if err != nil {
			return fmt.Errorf("load resource map: %w", err)
		}
		signCSRMeasurements, rotateCAMeasurements, caMeasurements = buildEndpointAllowlists(rm)
		logger.Info("resource map loaded", "path", *resourceMapF)
	}

	iss := &Issuer{
		keyProvider:          kp,
		MaxTTL:               *maxTTLF,
		SANValidation:        *sanValidation,
		DNSSANPattern:        compiledDNSSANPattern,
		AllowedCNPattern:     compiledCNPattern,
		ExpectedIssuer:       *expectedIssuer,
		RequestTimeout:       *requestTimeout,
		JWTClockSkew:         *jwtClockSkew,
		MinCAValidity:        *minCAValidity,
		Logger:               logger,
		tracker:              newNodeTracker(*maxTTLF),
		SignCSRMeasurements:  signCSRMeasurements,
		RotateCAMeasurements: rotateCAMeasurements,
		CAMeasurements:       caMeasurements,
	}

	if len(iss.SignCSRMeasurements) > 0 {
		logger.Info("measurement pinning enabled for /v1/sign-csr", "count", len(iss.SignCSRMeasurements))
	}
	if len(iss.RotateCAMeasurements) > 0 {
		logger.Info("measurement pinning enabled for /v1/rotate-ca", "count", len(iss.RotateCAMeasurements))
	}
	if len(iss.CAMeasurements) > 0 {
		logger.Info("measurement pinning enabled for /v1/ca", "count", len(iss.CAMeasurements))
	}
	iss.bundle.Store(&certBundle{
		caCert:     caCert,
		caKey:      caKey,
		parentCert: parentCert,
	})

	// Set initial CA fingerprint metric.
	initialFingerprint := certutil.CertFingerprint(caCert.Raw)
	caCertFingerprintInfo.WithLabelValues(initialFingerprint).Set(1)

	rl := newIPRateLimiter(rate.Limit(*rateLimit), *rateBurst, *rateLimiterMax)

	// Initialize bundle manager for CDS mode.
	var bm *bundleManager
	if kbsMode {
		bundlePath := "default/mesh/ca-bundle"
		bm = newBundleManager(*maxTTLF, *caRepoDir, bundlePath, logger)

		// Try to load existing bundle from the CDS repo (restart recovery).
		existingBundle, err := bm.loadFromRepo()
		if err != nil {
			logger.Warn("failed to load existing CA bundle from CDS repo", "error", err)
		}
		if existingBundle != nil {
			bm.mu.Lock()
			bm.certs = existingBundle
			bm.mu.Unlock()
			logger.Info("loaded existing CA bundle from CDS repo", "count", len(existingBundle))
		} else {
			bm.setInitial(caCert)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("POST /v1/sign-csr", http.MaxBytesHandler(rateLimitMiddleware(rl, http.HandlerFunc(iss.HandleSignCSR)), *maxRequestSize))
	mux.HandleFunc("GET /live", handleLive)
	mux.HandleFunc("GET /ready", iss.handleReady)
	mux.Handle("GET /metrics", promhttp.Handler())

	// /v1/ca: in CDS mode, serve the full bundle from bundleManager and require JWT auth.
	// In file mode, serve CA cert chain directly (no auth, backward compatible).
	if kbsMode {
		mux.Handle("GET /v1/ca", rateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := iss.getBundle()
			if b == nil {
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}

			// Require JWT auth in CDS mode.
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "unauthorized: missing or invalid Authorization header", http.StatusUnauthorized)
				return
			}
			token := authHeader[7:]
			claims, err := validateEARToken(token, iss.keyProvider, iss.ExpectedIssuer, iss.JWTClockSkew)
			if err != nil {
				var tve *tokenValidationError
				if errors.As(err, &tve) {
					tokenValidationFailuresTotal.WithLabelValues(tve.Reason).Inc()
				}
				http.Error(w, "unauthorized: invalid attestation token", http.StatusUnauthorized)
				return
			}
			if err := checkMeasurement(claims, iss.CAMeasurements, "ca"); err != nil {
				measurementDeniedTotal.WithLabelValues("ca").Inc()
				http.Error(w, "forbidden: measurement not allowed", http.StatusForbidden)
				return
			}

			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Write(bm.bundlePEM())
		})))
	} else {
		mux.HandleFunc("GET /v1/ca", iss.HandleCA)
	}

	// /v1/rotate-ca: only available in CDS mode.
	if kbsMode {
		rh := &rotateHandler{
			issuer:         iss,
			bundle:         bm,
			caRepoDir:      *caRepoDir,
			keyPath:        "default/mesh/ca-key",
			maxTTL:         *maxTTLF,
			caCertValidity: *caCertValidity,
		}
		mux.Handle("POST /v1/rotate-ca", http.MaxBytesHandler(rateLimitMiddleware(rl, http.HandlerFunc(rh.HandleRotateCA)), *maxRequestSize))
		logger.Info("CDS mode: /v1/rotate-ca endpoint enabled")
	}

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		IdleTimeout:  *idleTimeout,
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Update cert expiry gauges periodically.
	go certExpiryUpdater(ctx, iss, *metricsUpdateInterval)

	// Start certificate hot-reload watcher.
	// In CDS mode, CA key is managed via /v1/rotate-ca, so skip watching the key file.
	caKeyPath := *caKeyF
	if kbsMode {
		caKeyPath = "" // Don't watch CA key file; /v1/rotate-ca handles rotation.
	}
	reloader := newCertReloader(iss, caKeyPath, *caCertF, *tokenCert, *parentCertF, *certWatchDebounce, logger)
	go func() {
		if err := reloader.run(ctx); err != nil {
			logger.Error("cert reloader failed", "error", err)
		}
	}()

	// Start rate limiter eviction goroutine.
	go rl.evictionLoop(ctx, *rateLimiterEvictInterval, *rateLimiterIdleTimeout)

	// Start node tracker metric updater.
	go nodeTrackerUpdater(ctx, iss.tracker, *metricsUpdateInterval)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

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
