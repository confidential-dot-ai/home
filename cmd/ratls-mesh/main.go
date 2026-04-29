package main

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/ratls/assamclient"
	"github.com/lunal-dev/c8s/pkg/types"
)

func main() {
	// Subcommand dispatch (before flag.Parse so flags don't conflict).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "iptables-setup":
			iptablesSetup()
			return
		case "iptables-cleanup":
			iptablesCleanup()
			return
		}
	}

	var (
		platform                 = flag.String("platform", "sev-snp", "TEE platform: sev-snp, tdx")
		attestationServiceURL    = flag.String("attestation-service-url", "", "URL of the local attestation service (e.g. http://localhost:8400)")
		attestationServiceAPIKey = flag.String("attestation-service-api-key", "", "API key for the attestation service (required when running in remote mode)")
		outboundPort             = flag.Int("outbound-port", 15001, "outbound listener port (intercepted app traffic)")
		inboundPort              = flag.Int("inbound-port", 15006, "inbound listener port (RA-TLS from remote nodes)")
		nodeIP                   = flag.String("node-ip", "", "this node's IP (auto-detected from NODE_IP env if unset)")
		logLevel                 = flag.String("log-level", "info", "log level: debug, info, warn, error")
		dialTimeout              = flag.Duration("dial-timeout", 5*time.Second, "plain TCP dial timeout")
		tlsDialTimeout           = flag.Duration("tls-dial-timeout", 10*time.Second, "RA-TLS dial timeout")
		destHeaderTimeout        = flag.Duration("dest-header-timeout", 5*time.Second, "inbound destination header read timeout")
		drainTimeout             = flag.Duration("drain-timeout", 30*time.Second, "graceful shutdown drain timeout")
		keepAlive                = flag.Duration("keepalive", 30*time.Second, "TCP keepalive interval (0 to disable)")
		idleTimeout              = flag.Duration("idle-timeout", 0, "close connections idle longer than this (0=disabled)")
		maxConns                 = flag.Int("max-conns", 0, "max concurrent connections (0=unlimited)")
		maxConnsPerSource        = flag.Int("max-conns-per-source", 0, "max concurrent connections per source IP (0=unlimited)")
		healthPort               = flag.Int("health-port", 15021, "health/metrics HTTP port")
		measurements             = flag.String("measurements", "", "comma-separated hex SHA-384 launch measurements (empty = accept any TEE)")
		certTTL                  = flag.Duration("cert-ttl", 24*time.Hour, "RA-TLS certificate lifetime (rotates at 50%)")
		rotationTimeout          = flag.Duration("rotation-timeout", 30*time.Second, "max time for background certificate rotation")

		// Assam certificate issuance flags.
		certMode       = flag.String("cert-mode", "self-signed", "certificate mode: self-signed (default), assam (boots self-signed, upgrades to assam-issued in background)")
		assamURL       = flag.String("assam-url", "", "assam service URL for attestation (required for assam mode)")
		certIssuerURL  = flag.String("cert-issuer-url", "", "cert-issuer URL for CA bundle retrieval (required for assam mode)")
		caCertPath     = flag.String("ca-cert", "", "path to CA certificate file for peer verification")
		caURL          = flag.String("ca-url", "", "cert-issuer /v1/ca URL for periodic CA bundle refresh (assam mode)")
		caPollInterval = flag.Duration("ca-poll-interval", 5*time.Minute, "interval to poll cert-issuer /v1/ca for CA bundle updates")

		sessionCacheSize     = flag.Int("session-cache-size", 64, "TLS session cache size per node (0 disables session resumption)")
		accessLog            = flag.Bool("access-log", true, "emit per-connection structured access log")
		certPipelineProbeURL = flag.String("cert-pipeline-probe-url", "", "cert-issuer /ready URL for pipeline health probing (empty = disabled)")

		assamRetryBackoff    = flag.Duration("assam-retry-backoff", 2*time.Second, "initial backoff duration for assam certificate upgrade retries")
		assamRetryMaxBackoff = flag.Duration("assam-retry-max-backoff", 60*time.Second, "maximum backoff duration for assam certificate upgrade retries")

		maxDestHeaderSize  = flag.Int("max-dest-header-size", 256, "maximum destination header size in bytes")
		pipeBufferSize     = flag.Int("pipe-buffer-size", 32768, "buffer size for TCP pipe forwarding")
		acceptErrThreshold = flag.Int64("accept-error-threshold", 10, "consecutive accept errors before marking unhealthy")
		healthReadTimeout  = flag.Duration("health-read-timeout", 5*time.Second, "health server read timeout")
		healthWriteTimeout = flag.Duration("health-write-timeout", 10*time.Second, "health server write timeout")

		// Background task intervals and timeouts.
		metricsUpdateInterval     = flag.Duration("metrics-update-interval", 10*time.Second, "interval for resolver cache and cert expiry metric updates")
		assamOpTimeout            = flag.Duration("assam-op-timeout", 30*time.Second, "per-operation timeout for assam certificate upgrade and CA bundle refresh")
		certPipelineProbeTimeout  = flag.Duration("cert-pipeline-probe-timeout", 5*time.Second, "HTTP client timeout for cert pipeline health probe requests")
		certPipelineProbeInterval = flag.Duration("cert-pipeline-probe-interval", 60*time.Second, "interval between cert pipeline health probe requests")
	)
	flag.Parse()

	logger := certutil.NewJSONLogger(*logLevel)

	// Auto-detect node IP from Kubernetes downward API.
	if *nodeIP == "" {
		*nodeIP = os.Getenv("NODE_IP")
	}
	if *nodeIP == "" {
		logger.Error("node IP required: set --node-ip or NODE_IP env var")
		os.Exit(1)
	}

	if err := validateConfig(*attestationServiceURL, *outboundPort, *inboundPort, *certTTL); err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Build resolver (k8s is the only production resolver).
	config, err := rest.InClusterConfig()
	if err != nil {
		logger.Error("k8s in-cluster config failed", "error", err)
		os.Exit(1)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Error("k8s clientset creation failed", "error", err)
		os.Exit(1)
	}
	resolver, err := newK8sResolver(ctx, clientset, *nodeIP, logger)
	if err != nil {
		logger.Error("k8s resolver failed", "error", err)
		os.Exit(1)
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
				logger.Error("invalid measurement hex", "value", h, "error", err)
				os.Exit(1)
			}
			if len(b) != ratls.SNPMeasurementSize {
				logger.Error("invalid measurement length",
					"value", h,
					"got_bytes", len(b),
					"want_bytes", ratls.SNPMeasurementSize,
					"hint", fmt.Sprintf("SHA-384 measurement must be exactly %d hex characters", ratls.SNPMeasurementSize*2))
				os.Exit(1)
			}
			meshPolicy.Measurements = append(meshPolicy.Measurements, b)
		}
		logger.Info("measurement pinning enabled", "count", len(meshPolicy.Measurements))
	} else {
		logger.Warn("no --measurements set: accepting any TEE attestation (unsafe for production)")
	}

	// Load CA certificate(s) for dual-mode verification (assam mode).
	// Supports multi-PEM bundles for safe CA rotation.
	var caCerts []*x509.Certificate
	if *caCertPath != "" {
		var caErr error
		caCerts, caErr = certutil.LoadPEMCertificatesFile(*caCertPath)
		if caErr != nil {
			logger.Error("failed to load CA certificate(s)", "path", *caCertPath, "error", caErr)
			os.Exit(1)
		}
		names := make([]string, len(caCerts))
		for i, c := range caCerts {
			names[i] = c.Subject.CommonName
		}
		logger.Info("CA certificate(s) loaded for dual-mode verification", "count", len(caCerts), "subjects", names)
	}

	// Validate cert-mode specific flags.
	if *certMode != "self-signed" && *certMode != "assam" {
		logger.Error("invalid --cert-mode", "mode", *certMode, "valid", "self-signed, assam")
		os.Exit(1)
	}
	if *certMode == "assam" && (*assamURL == "" || *attestationServiceURL == "" || *certIssuerURL == "") {
		logger.Error("--assam-url, --attestation-service-url, and --cert-issuer-url are required for --cert-mode assam")
		os.Exit(1)
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
		logger.Error("failed to create server TLS config", "error", err)
		os.Exit(1)
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
		logger.Error("failed to create client TLS config", "error", err)
		os.Exit(1)
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
		logger.Error("proxy error", "error", err)
		os.Exit(1)
	}
}

// validateConfig checks for misconfigurations that would cause cryptic runtime
// failures. Called once at startup before any goroutine.
func validateConfig(attestationServiceURL string, outboundPort, inboundPort int, certTTL time.Duration) error {
	if attestationServiceURL == "" {
		return fmt.Errorf("--attestation-service-url is required")
	}
	if !strings.HasPrefix(attestationServiceURL, "http://") && !strings.HasPrefix(attestationServiceURL, "https://") {
		return fmt.Errorf("--attestation-service-url %q must start with http:// or https://", attestationServiceURL)
	}
	if outboundPort == inboundPort {
		return fmt.Errorf("--outbound-port and --inbound-port must differ (both are %d)", outboundPort)
	}
	if certTTL < time.Minute {
		return fmt.Errorf("--cert-ttl %s is too short (minimum 1m to avoid rotation thrashing)", certTTL)
	}
	return nil
}

// attestEvidence holds the fields we need from attestation evidence.
// Bare-metal SNP uses attestation_report (standard base64).
// vTPM (az-snp, az-tdx) uses hcl_report (URL-safe base64, no padding).
type attestEvidence struct {
	AttestationReport string `json:"attestation_report"`
	HCLReport         string `json:"hcl_report"`
}

// makeAttestFunc returns an AttestFunc that calls the attestation service
// via attestclient. Used for RA-TLS self-signed certificates.
//
// The attestation service POST /attest returns structured JSON evidence
// whose format varies by platform. This function extracts the raw SNP
// report bytes from the platform-specific envelope.
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

		return extractSNPReport(resp)
	}
}

// extractSNPReport extracts the raw 1184-byte SNP report from attestation
// evidence. Handles both bare-metal SNP (attestation_report field, standard
// base64) and vTPM/Azure (hcl_report field, URL-safe base64 no padding).
func extractSNPReport(resp types.AttestResponse) (string, error) {
	var evidence attestEvidence
	if err := json.Unmarshal(resp.Evidence, &evidence); err != nil {
		return "", fmt.Errorf("parse attestation evidence: %w", err)
	}

	switch {
	case evidence.AttestationReport != "":
		rawReport, err := base64.StdEncoding.DecodeString(evidence.AttestationReport)
		if err != nil {
			return "", fmt.Errorf("decode attestation_report: %w", err)
		}
		return string(rawReport), nil

	case evidence.HCLReport != "":
		rawReport, err := base64.RawURLEncoding.DecodeString(evidence.HCLReport)
		if err != nil {
			return "", fmt.Errorf("decode hcl_report: %w", err)
		}
		return string(rawReport), nil

	default:
		return "", fmt.Errorf("attestation evidence contains neither attestation_report nor hcl_report (platform: %s)", resp.Platform)
	}
}
