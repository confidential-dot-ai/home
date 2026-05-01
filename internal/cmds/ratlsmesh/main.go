package ratlsmesh

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/ratls/assamclient"
)

// Run executes the ratls-mesh binary. args is the slice of CLI args after
// the program name. The first arg may be `iptables-setup` or
// `iptables-cleanup` to run a side-effect-only iptables operation; all
// other args go through the flag set.
func Run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "iptables-setup":
			return iptablesSetup(args[1:])
		case "iptables-cleanup":
			return iptablesCleanup(args[1:])
		}
	}

	fs := flag.NewFlagSet("ratls-mesh", flag.ContinueOnError)
	platform := fs.String("platform", "sev-snp", "TEE platform: sev-snp, tdx")
	attestationServiceURL := fs.String("attestation-service-url", "", "URL of the local attestation service (e.g. http://localhost:8400)")
	attestationServiceAPIKey := fs.String("attestation-service-api-key", "", "API key for the attestation service (required when running in remote mode)")
	outboundPort := fs.Int("outbound-port", 15001, "outbound listener port (intercepted app traffic)")
	inboundPort := fs.Int("inbound-port", 15006, "inbound listener port (RA-TLS from remote nodes)")
	nodeIP := fs.String("node-ip", "", "this node's IP (auto-detected from NODE_IP env if unset)")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	dialTimeout := fs.Duration("dial-timeout", 5*time.Second, "plain TCP dial timeout")
	tlsDialTimeout := fs.Duration("tls-dial-timeout", 10*time.Second, "RA-TLS dial timeout")
	destHeaderTimeout := fs.Duration("dest-header-timeout", 5*time.Second, "inbound destination header read timeout")
	drainTimeout := fs.Duration("drain-timeout", 30*time.Second, "graceful shutdown drain timeout")
	keepAlive := fs.Duration("keepalive", 30*time.Second, "TCP keepalive interval (0 to disable)")
	idleTimeout := fs.Duration("idle-timeout", 0, "close connections idle longer than this (0=disabled)")
	maxConns := fs.Int("max-conns", 0, "max concurrent connections (0=unlimited)")
	maxConnsPerSource := fs.Int("max-conns-per-source", 0, "max concurrent connections per source IP (0=unlimited)")
	healthPort := fs.Int("health-port", 15021, "health/metrics HTTP port")
	measurements := fs.String("measurements", "", "comma-separated hex SHA-384 launch measurements (empty = accept any TEE)")
	certTTL := fs.Duration("cert-ttl", 24*time.Hour, "RA-TLS certificate lifetime (rotates at 50%)")
	rotationTimeout := fs.Duration("rotation-timeout", 30*time.Second, "max time for background certificate rotation")

	certMode := fs.String("cert-mode", "self-signed", "certificate mode: self-signed (default), assam (boots self-signed, upgrades to assam-issued in background)")
	assamURL := fs.String("assam-url", "", "assam service URL for attestation (required for assam mode)")
	certIssuerURL := fs.String("cert-issuer-url", "", "cert-issuer URL for CA bundle retrieval (required for assam mode)")
	caCertPath := fs.String("ca-cert", "", "path to CA certificate file for peer verification")
	caURL := fs.String("ca-url", "", "cert-issuer /v1/ca URL for periodic CA bundle refresh (assam mode)")
	caPollInterval := fs.Duration("ca-poll-interval", 5*time.Minute, "interval to poll cert-issuer /v1/ca for CA bundle updates")

	sessionCacheSize := fs.Int("session-cache-size", 64, "TLS session cache size per node (0 disables session resumption)")
	accessLog := fs.Bool("access-log", true, "emit per-connection structured access log")
	certPipelineProbeURL := fs.String("cert-pipeline-probe-url", "", "cert-issuer /ready URL for pipeline health probing (empty = disabled)")

	assamRetryBackoff := fs.Duration("assam-retry-backoff", 2*time.Second, "initial backoff duration for assam certificate upgrade retries")
	assamRetryMaxBackoff := fs.Duration("assam-retry-max-backoff", 60*time.Second, "maximum backoff duration for assam certificate upgrade retries")

	maxDestHeaderSize := fs.Int("max-dest-header-size", 256, "maximum destination header size in bytes")
	pipeBufferSize := fs.Int("pipe-buffer-size", 32768, "buffer size for TCP pipe forwarding")
	acceptErrThreshold := fs.Int64("accept-error-threshold", 10, "consecutive accept errors before marking unhealthy")
	healthReadTimeout := fs.Duration("health-read-timeout", 5*time.Second, "health server read timeout")
	healthWriteTimeout := fs.Duration("health-write-timeout", 10*time.Second, "health server write timeout")

	metricsUpdateInterval := fs.Duration("metrics-update-interval", 10*time.Second, "interval for resolver cache and cert expiry metric updates")
	assamOpTimeout := fs.Duration("assam-op-timeout", 30*time.Second, "per-operation timeout for assam certificate upgrade and CA bundle refresh")
	certPipelineProbeTimeout := fs.Duration("cert-pipeline-probe-timeout", 5*time.Second, "HTTP client timeout for cert pipeline health probe requests")
	certPipelineProbeInterval := fs.Duration("cert-pipeline-probe-interval", 60*time.Second, "interval between cert pipeline health probe requests")
	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}

	logger := certutil.NewJSONLogger(*logLevel)

	if *nodeIP == "" {
		*nodeIP = os.Getenv("NODE_IP")
	}
	if *nodeIP == "" {
		return fmt.Errorf("node IP required: set --node-ip or NODE_IP env var")
	}

	if err := validateConfig(*attestationServiceURL, *outboundPort, *inboundPort, *certTTL); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("k8s in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("k8s clientset: %w", err)
	}
	resolver, err := newK8sResolver(ctx, clientset, *nodeIP, logger)
	if err != nil {
		return fmt.Errorf("k8s resolver: %w", err)
	}

	asClient := attestclient.NewClientWithHTTPAndAPIKey("", &http.Client{
		Timeout: durOrDefault(*rotationTimeout, 30*time.Second),
	}, *attestationServiceAPIKey)
	attestFunc := makeAttestFunc(asClient, *attestationServiceURL)

	meshPolicy := &ratls.VerifyPolicy{}
	if *measurements != "" {
		for _, h := range strings.Split(*measurements, ",") {
			h = strings.TrimSpace(h)
			b, err := hex.DecodeString(h)
			if err != nil {
				return fmt.Errorf("invalid measurement hex %q: %w", h, err)
			}
			if len(b) != ratls.SNPMeasurementSize {
				return fmt.Errorf("invalid measurement length: %q is %d bytes, want %d (SHA-384 measurement must be %d hex characters)",
					h, len(b), ratls.SNPMeasurementSize, ratls.SNPMeasurementSize*2)
			}
			meshPolicy.Measurements = append(meshPolicy.Measurements, b)
		}
		logger.Info("measurement pinning enabled", "count", len(meshPolicy.Measurements))
	} else {
		logger.Warn("no --measurements set: accepting any TEE attestation (unsafe for production)")
	}

	var caCerts []*x509.Certificate
	if *caCertPath != "" {
		var caErr error
		caCerts, caErr = certutil.LoadPEMCertificatesFile(*caCertPath)
		if caErr != nil {
			return fmt.Errorf("load CA certificate(s) from %q: %w", *caCertPath, caErr)
		}
		names := make([]string, len(caCerts))
		for i, c := range caCerts {
			names[i] = c.Subject.CommonName
		}
		logger.Info("CA certificate(s) loaded for dual-mode verification", "count", len(caCerts), "subjects", names)
	}

	if *certMode != "self-signed" && *certMode != "assam" {
		return fmt.Errorf("invalid --cert-mode %q (valid: self-signed, assam)", *certMode)
	}
	if *certMode == "assam" && (*assamURL == "" || *attestationServiceURL == "" || *certIssuerURL == "") {
		return fmt.Errorf("--assam-url, --attestation-service-url, and --cert-issuer-url are required for --cert-mode assam")
	}

	serverTLS, serverCertMgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:        *platform,
		AttestFunc:      attestFunc,
		DNSNames:        []string{*nodeIP},
		CertTTL:         *certTTL,
		ClientPolicy:    meshPolicy,
		CACert:          caCerts,
		DynamicCACert:   *caURL != "",
		RotationTimeout: *rotationTimeout,
		Logger:          logger,
	})
	if err != nil {
		return fmt.Errorf("create server TLS config: %w", err)
	}

	clientTLS, clientCertMgr, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy:          meshPolicy,
		Platform:        *platform,
		AttestFunc:      attestFunc,
		CACert:          caCerts,
		DynamicCACert:   *caURL != "",
		CertTTL:         *certTTL,
		RotationTimeout: *rotationTimeout,
		Logger:          logger,
	})
	if err != nil {
		return fmt.Errorf("create client TLS config: %w", err)
	}

	if *sessionCacheSize > 0 {
		clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(*sessionCacheSize)
	}

	m := newMetrics()
	if *certMode == "assam" {
		m.certModeExpected.Store(1)
	}
	if len(meshPolicy.Measurements) > 0 {
		m.measurementPinning.Store(1)
	}

	// Wire attestation failure counter into TLS peer verification callbacks.
	wrapVerify := func(orig func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
		if orig == nil {
			return nil
		}
		return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			err := orig(rawCerts, chains)
			if err != nil {
				m.attestationFailures.Add(1)
			}
			return err
		}
	}
	serverTLS.VerifyPeerCertificate = wrapVerify(serverTLS.VerifyPeerCertificate)
	clientTLS.VerifyPeerCertificate = wrapVerify(clientTLS.VerifyPeerCertificate)

	// Wire rotation failure metrics.
	serverCertMgr.SetOnRotationFail(func() { m.certRotationFailures.Add(1) })
	if clientCertMgr != nil {
		clientCertMgr.SetOnRotationFail(func() { m.certRotationFailures.Add(1) })
	}

	health := newHealthServer(m, serverCertMgr, clientCertMgr, *acceptErrThreshold, *healthReadTimeout, *healthWriteTimeout)

	var connSem chan struct{}
	if *maxConns > 0 {
		connSem = make(chan struct{}, *maxConns)
	}

	proxy := &Proxy{
		outboundAddr:      fmt.Sprintf(":%d", *outboundPort),
		inboundAddr:       fmt.Sprintf(":%d", *inboundPort),
		serverTLS:         serverTLS,
		clientTLS:         clientTLS,
		nodeIP:            *nodeIP,
		inboundPort:       *inboundPort,
		resolver:          resolver,
		origDstFunc:       defaultOrigDstFunc,
		logger:            logger,
		metrics:           m,
		accessLog:         *accessLog,
		dialTimeout:       *dialTimeout,
		tlsDialTimeout:    *tlsDialTimeout,
		destHeaderTimeout: *destHeaderTimeout,
		drainTimeout:      *drainTimeout,
		keepAlive:         *keepAlive,
		idleTimeout:       *idleTimeout,
		maxDestHeaderSize: *maxDestHeaderSize,
		pipeBufferSize:    *pipeBufferSize,
		bufPool:           newBufPool(*pipeBufferSize),
		connSem:           connSem,
		maxConnsPerSrc:    *maxConnsPerSource,
		onReady: func() {
			// Eagerly provision certificates before marking ready.
			// Bound the warm-up so a hanging attestation binary (missing
			// /dev/sev, TPM not loaded) doesn't block readiness forever.
			warmupTimeout := 2 * durOrDefault(*rotationTimeout, 30*time.Second)
			warmupCtx, warmupCancel := context.WithTimeout(ctx, warmupTimeout)
			defer warmupCancel()

			if err := serverCertMgr.WarmUp(warmupCtx); err != nil {
				logger.Error("server certificate warm-up failed", "error", err)
			}
			if clientCertMgr != nil {
				if err := clientCertMgr.WarmUp(warmupCtx); err != nil {
					logger.Error("client certificate warm-up failed", "error", err)
				}
			}
			health.ready.Store(true)
		},
		onShutdown: func() { health.ready.Store(false) },
	}

	// Start health/metrics server.
	go func() {
		if err := health.serve(ctx, fmt.Sprintf(":%d", *healthPort)); err != nil {
			logger.Error("health server error", "error", err)
		}
	}()

	// Periodically update resolver cache and cert expiry metrics.
	go func() {
		t := time.NewTicker(*metricsUpdateInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.resolverCacheSize.Store(int64(resolver.CacheSize()))
				m.resolverLastEventTime.Store(resolver.LastEventTime())

				if exp := serverCertMgr.CertExpiry(); !exp.IsZero() {
					m.certExpiryServer.Store(exp.Unix())
				}
				if clientCertMgr != nil {
					if exp := clientCertMgr.CertExpiry(); !exp.IsZero() {
						m.certExpiryClient.Store(exp.Unix())
					}
				}
			}
		}
	}()

	// Assam certificate upgrade: after self-signed RA-TLS boot, a background
	// goroutine contacts assam, gets CA-signed certs, and hot-swaps them via
	// CertManager.SwapProvider. The assamCfg is shared with the CA bundle
	// refresh goroutine below.
	var assamCfg *assamclient.Config
	if *certMode == "assam" {
		assamCfg = &assamclient.Config{
			AssamURL:                 *assamURL,
			AttestationServiceURL:    *attestationServiceURL,
			AttestationServiceAPIKey: *attestationServiceAPIKey,
			CertIssuerURL:            *certIssuerURL,
			NodeIP:                   *nodeIP,
		}
		go func() {
			assamProvider, err := assamclient.NewProvider(assamCfg, logger)
			if err != nil {
				logger.Error("assam provider creation failed", "error", err)
				return
			}

			// Wait for assam to become reachable. Retry with backoff.
			backoff := *assamRetryBackoff
			maxBackoff := *assamRetryMaxBackoff
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}

				upgradeCtx, cancel := context.WithTimeout(ctx, *assamOpTimeout)
				err := serverCertMgr.SwapProvider(upgradeCtx, assamProvider)
				cancel()
				if err == nil {
					logger.Info("certificate upgraded from self-signed to assam-issued (server)")
					break
				}
				logger.Warn("assam certificate upgrade attempt failed (will retry)", "error", err, "backoff", backoff)
				backoff = min(backoff*2, maxBackoff)
			}

			// Upgrade client cert too.
			if clientCertMgr != nil {
				upgradeCtx, cancel := context.WithTimeout(ctx, *assamOpTimeout)
				if err := clientCertMgr.SwapProvider(upgradeCtx, assamProvider); err != nil {
					logger.Warn("assam client certificate upgrade failed", "error", err)
				} else {
					logger.Info("certificate upgraded from self-signed to assam-issued (client)")
				}
				cancel()
			}

			m.certMode.Store(1) // 1 = assam mode active
		}()
	}

	// CA bundle refresh: periodically poll cert-issuer /v1/ca for updated CA bundle.
	if *caURL != "" && *certMode == "assam" {
		go func() {
			assamClient := assamclient.NewClient(assamCfg)

			ticker := time.NewTicker(*caPollInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					refreshCtx, cancel := context.WithTimeout(ctx, *assamOpTimeout)
					newCerts, err := assamClient.RefreshCABundle(refreshCtx)
					cancel()
					if err != nil {
						logger.Warn("CA bundle refresh failed", "url", *caURL, "error", err)
						continue
					}
					serverCertMgr.UpdateCACerts(newCerts)
					if clientCertMgr != nil {
						clientCertMgr.UpdateCACerts(newCerts)
					}
					logger.Debug("CA bundle refreshed from cert-issuer", "count", len(newCerts))
				}
			}
		}()
		logger.Info("CA bundle refresh enabled", "url", *caURL, "interval", *caPollInterval)
	}

	// Cert pipeline health probe: periodically check cert-issuer /ready.
	if *certPipelineProbeURL != "" {
		m.certPipelineHealthy.Store(0) // Start as unhealthy until first probe succeeds.
		go func() {
			client := &http.Client{Timeout: *certPipelineProbeTimeout}
			ticker := time.NewTicker(*certPipelineProbeInterval)
			defer ticker.Stop()

			probe := func() {
				resp, err := client.Get(*certPipelineProbeURL)
				if err != nil || resp.StatusCode != http.StatusOK {
					if m.certPipelineHealthy.Swap(0) != 0 {
						logger.Warn("cert pipeline probe failed", "url", *certPipelineProbeURL, "error", err)
					}
					if resp != nil {
						resp.Body.Close()
					}
					return
				}
				resp.Body.Close()
				if m.certPipelineHealthy.Swap(1) != 1 {
					logger.Info("cert pipeline probe healthy", "url", *certPipelineProbeURL)
				}
			}

			probe() // Initial probe immediately.
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					probe()
				}
			}
		}()
		logger.Info("cert pipeline health probe enabled", "url", *certPipelineProbeURL)
	} else {
		m.certPipelineHealthy.Store(-1) // Not configured.
	}

	logger.Info("starting ratls-mesh",
		"outbound", proxy.outboundAddr,
		"inbound", proxy.inboundAddr,
		"node", *nodeIP,
		"platform", *platform,
		"cert_mode", *certMode,
		"resolver", "k8s",
		"health_port", *healthPort,
		"max_conns", *maxConns,
		"max_conns_per_source", *maxConnsPerSource,
		"idle_timeout", *idleTimeout,
		"keepalive", *keepAlive,
		"session_cache_size", *sessionCacheSize,
	)

	if err := proxy.Run(ctx); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	return nil
}

// validateConfig checks for misconfigurations that would cause cryptic runtime
// failures. Called once at startup before any goroutine.
func validateConfig(attestationServiceURL string, outboundPort, inboundPort int, certTTL time.Duration) error {
	if attestationServiceURL == "" {
		return fmt.Errorf("--attestation-service-url is required")
	}
	if err := cmdsutil.ValidateHTTPURL("--attestation-service-url", attestationServiceURL); err != nil {
		return err
	}
	if outboundPort == inboundPort {
		return fmt.Errorf("--outbound-port and --inbound-port must differ (both are %d)", outboundPort)
	}
	if certTTL < time.Minute {
		return fmt.Errorf("--cert-ttl %s is too short (minimum 1m to avoid rotation thrashing)", certTTL)
	}
	return nil
}

// makeAttestFunc returns an AttestFunc that calls the attestation service
// via attestclient. Used for RA-TLS self-signed certificates.
func makeAttestFunc(client attestclient.Client, attestationServiceURL string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, customData string) (string, error) {
		// customData is hex-encoded REPORTDATA (e.g. SHA-384 of pubkey,
		// zero-padded to 64 bytes for the SNP REPORTDATA field).
		reportDataBytes, err := hex.DecodeString(customData)
		if err != nil {
			return "", fmt.Errorf("decode report data hex: %w", err)
		}

		// Strip SNP REPORTDATA zero-padding before sending to the attestation
		// service. Bare-metal SNP pads server-side; vTPM passes the data as
		// the TPM2_Quote nonce (TPM2B_DATA) which has a smaller max size than
		// 64 bytes, so sending the full padded array causes TPM_RC_SIZE.
		reportDataBytes = reportDataBytes[:sha512.Size384]

		resp, err := client.GenerateEvidence(attestationServiceURL, reportDataBytes)
		if err != nil {
			return "", fmt.Errorf("attestation service: %w", err)
		}

		return attestclient.ExtractSNPReport(resp)
	}
}
