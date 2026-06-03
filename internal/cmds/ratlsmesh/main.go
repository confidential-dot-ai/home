//go:build linux

package ratlsmesh

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/ratls"
	"github.com/lunal-dev/c8s/pkg/ratls/cdsclient"
)

// Run dispatches ratls-mesh CLI args via cobra. Signal handling is wired
// at the root so subcommand RunE bodies read cmd.Context() instead of
// reinstalling their own NotifyContext.
func Run(args []string) error {
	cmd := newRatlsMeshCommand()
	cmd.SetArgs(args)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return cmd.ExecuteContext(ctx)
}

func newRatlsMeshCommand() *cobra.Command {
	var cfg proxyConfig
	cmd := &cobra.Command{
		Use:           "ratls-mesh",
		Short:         "RA-TLS L4 mesh proxy",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProxy(cmd.Context(), &cfg)
		},
	}
	bindProxyFlags(cmd.Flags(), &cfg)
	cmd.AddCommand(newIptablesSyncCommand())
	cmd.AddCommand(newIptablesCleanupCommand())
	return cmd
}

type proxyConfig struct {
	platform                  string
	attestationApiURL         string
	outboundPort              int
	inboundPort               int
	nodeIP                    string
	certDNSSAN                string
	logLevel                  string
	dialTimeout               time.Duration
	tlsDialTimeout            time.Duration
	destHeaderTimeout         time.Duration
	drainTimeout              time.Duration
	keepAlive                 time.Duration
	idleTimeout               time.Duration
	maxConns                  int
	maxConnsPerSource         int
	healthPort                int
	measurements              string
	certTTL                   time.Duration
	rotationTimeout           time.Duration
	certMode                  string
	cdsURL                    string
	caCertPath                string
	caPollInterval            time.Duration
	cdsMeasurements           string
	sessionCacheSize          int
	accessLog                 bool
	certPipelineProbeURL      string
	cdsRetryBackoff           time.Duration
	cdsRetryMaxBackoff        time.Duration
	maxDestHeaderSize         int
	pipeBufferSize            int
	acceptErrThreshold        int64
	healthReadTimeout         time.Duration
	healthWriteTimeout        time.Duration
	metricsUpdateInterval     time.Duration
	localCIDRBootTimeout      time.Duration
	iptablesMetricsFile       string
	cdsOpTimeout              time.Duration
	certPipelineProbeTimeout  time.Duration
	certPipelineProbeInterval time.Duration
}

func bindProxyFlags(fs *pflag.FlagSet, c *proxyConfig) {
	fs.StringVar(&c.platform, "platform", "sev-snp", "TEE platform: sev-snp, tdx")
	fs.StringVar(&c.attestationApiURL, "attestation-api-url", "", "URL of the local attestation-api (e.g. http://localhost:8400)")
	fs.IntVar(&c.outboundPort, "outbound-port", 15001, "outbound listener port (intercepted app traffic)")
	fs.IntVar(&c.inboundPort, "inbound-port", 15006, "inbound listener port (RA-TLS from peer nodes)")
	fs.StringVar(&c.nodeIP, "node-ip", "", "this node's IP (auto-detected from NODE_IP env if unset)")
	fs.StringVar(&c.certDNSSAN, "cert-dns-san", "", "DNS SAN placed on the CDS-issued mesh cert (must match CDS --dns-san-pattern; empty omits SANs). Not used for peer verification, which is attestation-based.")
	fs.StringVar(&c.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	fs.DurationVar(&c.dialTimeout, "dial-timeout", 5*time.Second, "plain TCP dial timeout")
	fs.DurationVar(&c.tlsDialTimeout, "tls-dial-timeout", 10*time.Second, "RA-TLS dial timeout")
	fs.DurationVar(&c.destHeaderTimeout, "dest-header-timeout", 5*time.Second, "inbound destination header read timeout")
	fs.DurationVar(&c.drainTimeout, "drain-timeout", 30*time.Second, "graceful shutdown drain timeout")
	fs.DurationVar(&c.keepAlive, "keepalive", 30*time.Second, "TCP keepalive interval (0 to disable)")
	fs.DurationVar(&c.idleTimeout, "idle-timeout", 0, "close connections idle longer than this (0=disabled)")
	fs.IntVar(&c.maxConns, "max-conns", 0, "max concurrent connections (0=unlimited)")
	fs.IntVar(&c.maxConnsPerSource, "max-conns-per-source", 0, "max concurrent connections per source IP (0=unlimited)")
	fs.IntVar(&c.healthPort, "health-port", 15021, "health/metrics HTTP port")
	fs.StringVar(&c.measurements, "measurements", "", "comma-separated hex SHA-384 launch measurements (empty = accept any TEE)")
	fs.DurationVar(&c.certTTL, "cert-ttl", 24*time.Hour, "RA-TLS certificate lifetime (rotates at 50%)")
	fs.DurationVar(&c.rotationTimeout, "rotation-timeout", 30*time.Second, "max time for background certificate rotation")
	fs.StringVar(&c.certMode, "cert-mode", "self-signed", "certificate mode: self-signed (default), cds (boots self-signed, upgrades to CDS-issued in background)")
	fs.StringVar(&c.cdsURL, "cds-url", "", "CDS service URL for attestation and CA bundle retrieval (required for cds mode)")
	fs.StringVar(&c.caCertPath, "ca-cert", "", "path to CA certificate file for peer verification")
	fs.DurationVar(&c.caPollInterval, "ca-poll-interval", 5*time.Minute, "interval to poll CDS /ca for CA bundle updates")
	fs.StringVar(&c.cdsMeasurements, "cds-measurements", "", "comma-separated SHA-384 hex launch measurements that CDS's RA-TLS peer cert must match. Empty = accept any (UNSAFE outside development).")
	fs.IntVar(&c.sessionCacheSize, "session-cache-size", 64, "TLS session cache size per node (0 disables session resumption)")
	fs.BoolVar(&c.accessLog, "access-log", true, "emit per-connection structured access log")
	fs.StringVar(&c.certPipelineProbeURL, "cert-pipeline-probe-url", "", "CDS /ready URL for pipeline health probing (empty = disabled)")
	fs.DurationVar(&c.cdsRetryBackoff, "cds-retry-backoff", 2*time.Second, "initial backoff duration for CDS certificate upgrade retries")
	fs.DurationVar(&c.cdsRetryMaxBackoff, "cds-retry-max-backoff", 60*time.Second, "maximum backoff duration for CDS certificate upgrade retries")
	fs.IntVar(&c.maxDestHeaderSize, "max-dest-header-size", 256, "maximum destination header size in bytes")
	fs.IntVar(&c.pipeBufferSize, "pipe-buffer-size", 32768, "buffer size for TCP pipe forwarding")
	fs.Int64Var(&c.acceptErrThreshold, "accept-error-threshold", 10, "consecutive accept errors before marking unhealthy")
	fs.DurationVar(&c.healthReadTimeout, "health-read-timeout", 5*time.Second, "health server read timeout")
	fs.DurationVar(&c.healthWriteTimeout, "health-write-timeout", 10*time.Second, "health server write timeout")
	fs.DurationVar(&c.metricsUpdateInterval, "metrics-update-interval", 10*time.Second, "interval for resolver cache and cert expiry metric updates")
	fs.DurationVar(&c.localCIDRBootTimeout, "local-cidr-boot-timeout", time.Second, "synchronous retry budget at startup for host pod-network CIDR discovery; past this we fall through to the async refresh loop and ValidateLocalDest uses Kubernetes pod HostIP ownership until discovery recovers")
	fs.StringVar(&c.iptablesMetricsFile, "iptables-metrics-file", defaultIptablesMetricsFile, "shared file where iptables-sync publishes counters (empty disables)")
	fs.DurationVar(&c.cdsOpTimeout, "cds-op-timeout", 30*time.Second, "per-operation timeout for CDS certificate upgrade and CA bundle refresh")
	fs.DurationVar(&c.certPipelineProbeTimeout, "cert-pipeline-probe-timeout", 5*time.Second, "HTTP client timeout for cert pipeline health probe requests")
	fs.DurationVar(&c.certPipelineProbeInterval, "cert-pipeline-probe-interval", 60*time.Second, "interval between cert pipeline health probe requests")
}

func runProxy(ctx context.Context, c *proxyConfig) error {
	logger, err := certutil.NewJSONLogger(c.logLevel)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	slog.SetDefault(logger)

	if c.nodeIP == "" {
		c.nodeIP = os.Getenv("NODE_IP")
	}
	if c.nodeIP == "" {
		return fmt.Errorf("node IP required: set --node-ip or NODE_IP env var")
	}
	canonicalNodeIP := normalizeIP(c.nodeIP)
	if canonicalNodeIP == "" {
		return fmt.Errorf("--node-ip %q must be a valid IP address", c.nodeIP)
	}
	c.nodeIP = canonicalNodeIP

	if err := validateConfig(c.attestationApiURL, c.outboundPort, c.inboundPort, c.healthPort, c.certTTL); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	restCfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("k8s in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("k8s clientset: %w", err)
	}
	resolver, err := newK8sResolver(ctx, clientset, c.nodeIP, c.localCIDRBootTimeout, logger)
	if err != nil {
		return fmt.Errorf("k8s resolver: %w", err)
	}

	asClient := attestclient.NewClientWithHTTP("", &http.Client{
		Timeout: c.rotationTimeout,
	})
	attestFunc := makeAttestFunc(asClient, c.attestationApiURL)

	meshPolicy := &ratls.VerifyPolicy{AttestationApiURL: c.attestationApiURL}
	if c.measurements != "" {
		for _, h := range strings.Split(c.measurements, ",") {
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
	if c.caCertPath != "" {
		var caErr error
		caCerts, caErr = certutil.LoadPEMCertificatesFile(c.caCertPath)
		if caErr != nil {
			return fmt.Errorf("load CA certificate(s) from %q: %w", c.caCertPath, caErr)
		}
		names := make([]string, len(caCerts))
		for i, cert := range caCerts {
			names[i] = cert.Subject.CommonName
		}
		logger.Info("CA certificate(s) loaded for dual-mode verification", "count", len(caCerts), "subjects", names)
	}

	if c.certMode != "self-signed" && c.certMode != "cds" {
		return fmt.Errorf("invalid --cert-mode %q (valid: self-signed, cds)", c.certMode)
	}
	if c.certMode == "cds" && (c.cdsURL == "" || c.attestationApiURL == "") {
		return fmt.Errorf("--cds-url and --attestation-api-url are required for --cert-mode cds")
	}
	teeType, err := ratlsTEEType(c.platform)
	if err != nil {
		return err
	}
	effectiveCAURL := effectiveCDSCAURL(c.certMode, c.cdsURL)
	cdsMeasurements, err := parseHexMeasurements(c.cdsMeasurements)
	if err != nil {
		return fmt.Errorf("--cds-measurements: %w", err)
	}
	if c.certMode == "cds" && len(cdsMeasurements) == 0 {
		logger.Warn("--cds-measurements not set; the RA-TLS handshake will accept any CDS measurement. Set this to the chart-distributed launch digest of CDS to close bootstrap MITM.")
	}

	// The self-signed boot cert carries no SAN: mesh peers authenticate it by
	// hardware attestation, not by SAN/hostname (NewServerTLSConfig sets
	// InsecureSkipVerify and verifies the RA-TLS extension). The CDS-issued
	// upgrade cert does carry a DNS SAN (see cdsclient.Config.DNSSAN).
	serverTLS, serverCertMgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:        c.platform,
		AttestFunc:      attestFunc,
		CertTTL:         c.certTTL,
		ClientPolicy:    meshPolicy,
		CACert:          caCerts,
		DynamicCACert:   effectiveCAURL != "",
		RotationTimeout: c.rotationTimeout,
		Logger:          logger,
	})
	if err != nil {
		return fmt.Errorf("create server TLS config: %w", err)
	}

	clientTLS, clientCertMgr, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy:          meshPolicy,
		Platform:        c.platform,
		AttestFunc:      attestFunc,
		CACert:          caCerts,
		DynamicCACert:   effectiveCAURL != "",
		CertTTL:         c.certTTL,
		RotationTimeout: c.rotationTimeout,
		Logger:          logger,
	})
	if err != nil {
		return fmt.Errorf("create client TLS config: %w", err)
	}

	if c.sessionCacheSize > 0 {
		clientTLS.ClientSessionCache = tls.NewLRUClientSessionCache(c.sessionCacheSize)
	}

	m := newMetrics()
	if c.certMode == "cds" {
		m.certModeConfigured.Store(1)
	}
	if len(meshPolicy.Measurements) > 0 {
		m.measurementPinning.Set(1)
	}

	// Wire attestation failure counter into TLS peer verification callbacks.
	wrapVerify := func(orig func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
		if orig == nil {
			return nil
		}
		return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			err := orig(rawCerts, chains)
			if err != nil {
				m.attestationFailures.Inc()
			}
			return err
		}
	}
	serverTLS.VerifyPeerCertificate = wrapVerify(serverTLS.VerifyPeerCertificate)
	clientTLS.VerifyPeerCertificate = wrapVerify(clientTLS.VerifyPeerCertificate)

	// Wire rotation failure metrics.
	serverCertMgr.SetOnRotationFail(func() { m.certRotationFailures.Inc() })
	if clientCertMgr != nil {
		clientCertMgr.SetOnRotationFail(func() { m.certRotationFailures.Inc() })
	}

	health := newHealthServer(m, serverCertMgr, clientCertMgr, c.acceptErrThreshold, c.healthReadTimeout, c.healthWriteTimeout)

	var connSem chan struct{}
	if c.maxConns > 0 {
		connSem = make(chan struct{}, c.maxConns)
	}

	proxy := &Proxy{
		outboundAddr:      fmt.Sprintf(":%d", c.outboundPort),
		inboundAddr:       fmt.Sprintf(":%d", c.inboundPort),
		serverTLS:         serverTLS,
		clientTLS:         clientTLS,
		nodeIP:            c.nodeIP,
		inboundPort:       c.inboundPort,
		resolver:          resolver,
		origDstFunc:       defaultOrigDstFunc,
		logger:            logger,
		metrics:           m,
		accessLog:         c.accessLog,
		dialTimeout:       c.dialTimeout,
		tlsDialTimeout:    c.tlsDialTimeout,
		destHeaderTimeout: c.destHeaderTimeout,
		drainTimeout:      c.drainTimeout,
		keepAlive:         c.keepAlive,
		idleTimeout:       c.idleTimeout,
		maxDestHeaderSize: c.maxDestHeaderSize,
		pipeBufferSize:    c.pipeBufferSize,
		bufPool:           newBufPool(c.pipeBufferSize),
		connSem:           connSem,
		maxConnsPerSrc:    c.maxConnsPerSource,
		onReady: func() {
			// Eagerly provision certificates before marking ready.
			// Bound the warm-up so a hanging attestation binary (missing
			// /dev/sev, TPM not loaded) doesn't block readiness forever.
			warmupTimeout := 2 * c.rotationTimeout
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
		if err := health.serve(ctx, fmt.Sprintf(":%d", c.healthPort)); err != nil {
			logger.Error("health server error", "error", err)
		}
	}()

	// Periodically update resolver cache and cert expiry metrics.
	go func() {
		t := time.NewTicker(c.metricsUpdateInterval)
		defer t.Stop()
		// iptablesMetricsSeen flips true on the first successful read of the
		// sidecar metrics file. Before that, ENOENT is the cold-start path
		// and stays at Debug; after, every read failure (including ENOENT)
		// is escalated to Warn because something stopped writing.
		var iptablesMetricsSeen bool
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.resolverCacheSize.Set(float64(resolver.CacheSize()))
				m.resolverLocalCIDRs.Set(float64(resolver.LocalCIDRCount()))
				m.resolverLastEvent.Set(float64(resolver.LastEventTime()))
				switch err := m.refreshIptablesMetrics(c.iptablesMetricsFile); {
				case err == nil:
					iptablesMetricsSeen = true
				case iptablesMetricsSeen:
					logger.Warn("read iptables metrics file failed after prior success; sidecar may be wedged", "path", c.iptablesMetricsFile, "error", err)
				case !errors.Is(err, fs.ErrNotExist):
					logger.Debug("read iptables metrics file failed", "path", c.iptablesMetricsFile, "error", err)
				}

				if exp := serverCertMgr.CertExpiry(); !exp.IsZero() {
					m.certExpiry.WithLabelValues("server").Set(float64(exp.Unix()))
				}
				if clientCertMgr != nil {
					if exp := clientCertMgr.CertExpiry(); !exp.IsZero() {
						m.certExpiry.WithLabelValues("client").Set(float64(exp.Unix()))
					}
				}
			}
		}
	}()

	// CDS certificate upgrade: after self-signed RA-TLS boot, a background
	// goroutine contacts CDS, gets CA-signed certs, and hot-swaps them via
	// CertManager.SwapProvider. The cdsCfg is shared with the CA bundle
	// refresh goroutine below. cds serves both attestation and CA bundle on
	// one URL, so CDSURL and CDSCAURL both take --cds-url.
	var cdsCfg *cdsclient.Config
	if c.certMode == "cds" {
		cdsCfg = &cdsclient.Config{
			CDSURL:            c.cdsURL,
			AttestationApiURL: c.attestationApiURL,
			CDSCAURL:          c.cdsURL,
			CACertURL:         effectiveCAURL,
			NodeIP:            c.nodeIP,
			DNSSAN:            c.certDNSSAN,
			TEEType:           teeType,
			CDSMeasurements:   cdsMeasurements,
		}
		go func() {
			cdsProvider, err := cdsclient.NewProvider(cdsCfg, logger)
			if err != nil {
				logger.Error("cds provider creation failed", "error", err)
				return
			}

			bo := backoff.NewExponentialBackOff()
			bo.InitialInterval = c.cdsRetryBackoff
			bo.MaxInterval = c.cdsRetryMaxBackoff
			// MaxElapsedTime defaults to 0 (unlimited); ctx cancellation is
			// the only exit.

			_, err = backoff.Retry(ctx, func() (struct{}, error) {
				upgradeCtx, cancel := context.WithTimeout(ctx, c.cdsOpTimeout)
				defer cancel()
				if err := serverCertMgr.SwapProvider(upgradeCtx, cdsProvider); err != nil {
					return struct{}{}, err
				}
				return struct{}{}, nil
			},
				backoff.WithBackOff(bo),
				backoff.WithNotify(func(err error, d time.Duration) {
					logger.Warn("cds certificate upgrade attempt failed (will retry)", "error", err, "backoff", d)
				}),
			)
			if err != nil {
				// ctx cancelled or unrecoverable error from the operation.
				return
			}
			logger.Info("certificate upgraded from self-signed to cds-issued (server)")

			// Upgrade client cert too.
			if clientCertMgr != nil {
				upgradeCtx, cancel := context.WithTimeout(ctx, c.cdsOpTimeout)
				if err := clientCertMgr.SwapProvider(upgradeCtx, cdsProvider); err != nil {
					logger.Warn("cds client certificate upgrade failed", "error", err)
				} else {
					logger.Info("certificate upgraded from self-signed to cds-issued (client)")
				}
				cancel()
			}

			m.certMode.Store(1)
		}()
	}

	// CA bundle refresh: periodically poll CDS /ca for updated CA bundle.
	if effectiveCAURL != "" && c.certMode == "cds" {
		go func() {
			cdsClient := cdsclient.NewClient(cdsCfg)

			ticker := time.NewTicker(c.caPollInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					refreshCtx, cancel := context.WithTimeout(ctx, c.cdsOpTimeout)
					newCerts, err := cdsClient.RefreshCABundle(refreshCtx)
					cancel()
					if err != nil {
						logger.Warn("CA bundle refresh failed", "url", effectiveCAURL, "error", err)
						continue
					}
					serverCertMgr.UpdateCACerts(newCerts)
					if clientCertMgr != nil {
						clientCertMgr.UpdateCACerts(newCerts)
					}
					logger.Debug("CA bundle refreshed from CDS", "count", len(newCerts))
				}
			}
		}()
		logger.Info("CA bundle refresh enabled", "url", effectiveCAURL, "interval", c.caPollInterval)
	}

	// Cert pipeline health probe: periodically check CDS /ready.
	if c.certPipelineProbeURL != "" {
		m.certPipelineHealthy.Set(0) // Start as unhealthy until first probe succeeds.
		go func() {
			client := &http.Client{Timeout: c.certPipelineProbeTimeout}
			ticker := time.NewTicker(c.certPipelineProbeInterval)
			defer ticker.Stop()

			// lastHealth is kept goroutine-local for the transition-log gate;
			// the metric value is whatever Set was last called with.
			lastHealth := -1
			probe := func() {
				health := 0
				resp, err := client.Get(c.certPipelineProbeURL)
				if err != nil || resp.StatusCode != http.StatusOK {
					if lastHealth != 0 {
						logger.Warn("cert pipeline probe failed", "url", c.certPipelineProbeURL, "error", err)
					}
					if resp != nil {
						resp.Body.Close()
					}
				} else {
					resp.Body.Close()
					health = 1
					if lastHealth != 1 {
						logger.Info("cert pipeline probe healthy", "url", c.certPipelineProbeURL)
					}
				}
				lastHealth = health
				m.certPipelineHealthy.Set(float64(health))
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
		logger.Info("cert pipeline health probe enabled", "url", c.certPipelineProbeURL)
	}
	// When the probe is not configured, the gauge stays at its initial -1
	// (set in newMetrics) — operators can branch on -1 to know it isn't a
	// real "unhealthy" signal.

	logger.Info("starting ratls-mesh",
		"outbound", proxy.outboundAddr,
		"inbound", proxy.inboundAddr,
		"node", c.nodeIP,
		"platform", c.platform,
		"cert_mode", c.certMode,
		"resolver", "k8s",
		"health_port", c.healthPort,
		"max_conns", c.maxConns,
		"max_conns_per_source", c.maxConnsPerSource,
		"idle_timeout", c.idleTimeout,
		"keepalive", c.keepAlive,
		"session_cache_size", c.sessionCacheSize,
	)

	if err := proxy.Run(ctx); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	return nil
}

type iptablesSyncConfig struct {
	outboundPort            int
	uid                     int
	excludeUIDs             string
	excludeSourceNamespaces string
	nodeIPs                 []string
	resyncPeriod            time.Duration
	watchdogPeriod          time.Duration
	ipsetMaxElem            int
	readyFile               string
	metricsFile             string
	logLevel                string
}

func newIptablesSyncCommand() *cobra.Command {
	var cfg iptablesSyncConfig
	cmd := &cobra.Command{
		Use:           "iptables-sync",
		Short:         "Watch K8s pods and keep iptables/ipset routing current",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runIptablesSync(cmd.Context(), &cfg)
		},
	}
	fs := cmd.Flags()
	fs.IntVar(&cfg.outboundPort, "outbound-port", 15001, "outbound listener port")
	fs.IntVar(&cfg.uid, "uid", defaultProxyUID, "UID to exclude from redirect")
	fs.StringVar(&cfg.excludeUIDs, "exclude-uids", "0", "comma-separated UIDs to skip (e.g. root=0 so kubelet/containerd can reach registries)")
	fs.StringVar(&cfg.excludeSourceNamespaces, "exclude-source-namespaces", defaultMeshExcludedSourceNamespacesCSV(), "comma-separated local source namespaces excluded from transparent mesh interception")
	fs.StringSliceVar(&cfg.nodeIPs, "node-ip", nil, "local node IP(s); repeat or comma-separate for dual-stack (one per family). Defaults to NODE_IP env. Each address must be a non-loopback, non-unspecified IP bound to a local interface.")
	fs.DurationVar(&cfg.resyncPeriod, "resync-period", 30*time.Second, "periodic full ipset reconciliation interval")
	fs.DurationVar(&cfg.watchdogPeriod, "watchdog-period", 2*time.Second, "interval at which the base-chain jump rules are re-asserted at position 1 (bounds the race window against kube-proxy reinserting KUBE-SERVICES)")
	fs.IntVar(&cfg.ipsetMaxElem, "ipset-maxelem", defaultIPSetMaxElem, "maximum members per managed ipset")
	fs.StringVar(&cfg.readyFile, "ready-file", "", "path to write after initial ipset and iptables sync succeeds")
	fs.StringVar(&cfg.metricsFile, "iptables-metrics-file", defaultIptablesMetricsFile, "shared file where iptables-sync publishes counters (empty disables)")
	fs.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	return cmd
}

func newIptablesCleanupCommand() *cobra.Command {
	return &cobra.Command{
		Use:           "iptables-cleanup",
		Short:         "Remove iptables NAT rules and ipsets created by the mesh",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runIptablesCleanup()
		},
	}
}

// validateConfig checks for misconfigurations that would cause cryptic runtime
// failures. Called once at startup before any goroutine.
func validateConfig(attestationApiURL string, outboundPort, inboundPort, healthPort int, certTTL time.Duration) error {
	if attestationApiURL == "" {
		return fmt.Errorf("--attestation-api-url is required")
	}
	if !strings.HasPrefix(attestationApiURL, "http://") && !strings.HasPrefix(attestationApiURL, "https://") {
		return fmt.Errorf("--attestation-api-url %q must start with http:// or https://", attestationApiURL)
	}
	if err := validatePort("--outbound-port", outboundPort); err != nil {
		return err
	}
	if err := validatePort("--inbound-port", inboundPort); err != nil {
		return err
	}
	if err := validatePort("--health-port", healthPort); err != nil {
		return err
	}
	for _, pair := range []struct {
		aFlag, bFlag string
		aPort, bPort int
	}{
		{"--outbound-port", "--inbound-port", outboundPort, inboundPort},
		{"--outbound-port", "--health-port", outboundPort, healthPort},
		{"--inbound-port", "--health-port", inboundPort, healthPort},
	} {
		if pair.aPort == pair.bPort {
			return fmt.Errorf("%s and %s must differ (both are %d)", pair.aFlag, pair.bFlag, pair.aPort)
		}
	}
	if certTTL < time.Minute {
		return fmt.Errorf("--cert-ttl %s is too short (minimum 1m to avoid rotation thrashing)", certTTL)
	}
	return nil
}

func validatePort(flag string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s %d out of range (1-65535)", flag, port)
	}
	return nil
}

// makeAttestFunc returns an AttestFunc that calls the attestation-api
// via attestclient. Used for RA-TLS self-signed certificates.
func makeAttestFunc(client attestclient.Client, attestationApiURL string) func(context.Context, string) (string, error) {
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

		resp, err := client.GenerateEvidence(attestationApiURL, reportDataBytes)
		if err != nil {
			return "", fmt.Errorf("attestation-api: %w", err)
		}

		return attestclient.RATLSEvidence(resp)
	}
}

func effectiveCDSCAURL(certMode, cdsURL string) string {
	if certMode != "cds" {
		return ""
	}
	return strings.TrimRight(cdsURL, "/") + "/ca"
}

func ratlsTEEType(platform string) (ratls.TEEType, error) {
	switch strings.TrimSpace(platform) {
	case "sev-snp":
		return ratls.TEETypeSEVSNP, nil
	case "":
		return 0, fmt.Errorf("--platform is required")
	case "tdx":
		return 0, fmt.Errorf("ratls-mesh: TDX platform is not yet implemented (use sev-snp)")
	default:
		return 0, fmt.Errorf("ratls-mesh: unsupported --platform %q", platform)
	}
}

func parseHexMeasurements(raw string) ([][]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		decoded, err := hex.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("invalid hex measurement %q: %w", p, err)
		}
		if len(decoded) != ratls.SNPMeasurementSize {
			return nil, fmt.Errorf("measurement %q is %d bytes, want %d", p, len(decoded), ratls.SNPMeasurementSize)
		}
		out = append(out, decoded)
	}
	return out, nil
}
