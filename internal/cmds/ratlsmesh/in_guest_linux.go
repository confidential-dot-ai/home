//go:build linux

package ratlsmesh

// In-guest mode lives in its own file so the host DaemonSet flow stays
// untouched. The shared surface with host-mode is intentionally narrow:
// the iptables jump-chain layout, the TLS/proxy machinery, and the health
// server. Anything K8s-API-dependent (resolver_k8s.go, pod_ipsets,
// iptables-sync sidecar) is deliberately not used here.
//
// The env var names, ports, and unit-side expectations here are a
// contract shared with the kata-guest-base recipe — its systemd units,
// the cloud-init EnvironmentFile renderer, and the "What's baked in"
// table in kata-guest-base/README.md. Do not rename either side
// without updating the other.

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/ratls/cdsclient"
)

// Environment variable names. These are the contract surface against
// the kata-guest-base cloud-init / EnvironmentFile renderer; renaming
// any of them is a breaking change that must land on both sides together.
const (
	envWorkloadID            = "C8S_WORKLOAD_ID"
	envCDSURL                = "C8S_CDS_URL"
	envAttestationServiceURL = "C8S_ATTESTATION_SERVICE_URL"
	envLogLevel              = "C8S_LOG_LEVEL"
	envCDSMeasurements       = "C8S_CDS_MEASUREMENTS"
	envMeshMeasurements      = "C8S_MESH_MEASUREMENTS"
	envPlatform              = "C8S_PLATFORM"
	envPodIP                 = "C8S_POD_IP"
)

// defaultInGuestAttestationServiceURL is the loopback URL the in-guest
// attestation-service binds in localhost-only mode — matches the port
// the kata-guest-base attestation-service.service uses (`127.0.0.1:8400`).
const defaultInGuestAttestationServiceURL = "http://127.0.0.1:8400"

// Fixed in-guest ports. Per the contract these are not operator-tunable.
const (
	inGuestOutboundPort = 15001
	inGuestInboundPort  = 15006
	inGuestHealthPort   = 15021
)

// inGuestConfig is the env-driven configuration for `ratls-mesh in-guest`.
type inGuestConfig struct {
	workloadID            string
	cdsURL                string
	attestationServiceURL string
	logLevel              string
	platform              string
	cdsMeasurements       string
	meshMeasurements      string
	podIP                 string

	certTTL            time.Duration
	rotationTimeout    time.Duration
	dialTimeout        time.Duration
	tlsDialTimeout     time.Duration
	destHeaderTimeout  time.Duration
	drainTimeout       time.Duration
	keepAlive          time.Duration
	cdsRetryBackoff    time.Duration
	cdsRetryMaxBackoff time.Duration
	cdsOpTimeout       time.Duration
	caPollInterval     time.Duration
}

func defaultInGuestConfig() inGuestConfig {
	return inGuestConfig{
		platform:           "sev-snp",
		logLevel:           "info",
		certTTL:            24 * time.Hour,
		rotationTimeout:    30 * time.Second,
		dialTimeout:        5 * time.Second,
		tlsDialTimeout:     10 * time.Second,
		destHeaderTimeout:  5 * time.Second,
		drainTimeout:       30 * time.Second,
		keepAlive:          30 * time.Second,
		cdsRetryBackoff:    2 * time.Second,
		cdsRetryMaxBackoff: 60 * time.Second,
		cdsOpTimeout:       30 * time.Second,
		caPollInterval:     5 * time.Minute,
	}
}

// loadInGuestConfig pulls every contract-defined env var. The function is
// pure (env-lookup function → struct) so tests can drive it from a map
// without touching the process environment.
func loadInGuestConfig(env func(string) string) inGuestConfig {
	c := defaultInGuestConfig()
	c.workloadID = env(envWorkloadID)
	c.cdsURL = env(envCDSURL)
	if v := env(envAttestationServiceURL); v != "" {
		c.attestationServiceURL = v
	} else {
		c.attestationServiceURL = defaultInGuestAttestationServiceURL
	}
	if v := env(envLogLevel); v != "" {
		c.logLevel = v
	}
	if v := env(envPlatform); v != "" {
		c.platform = v
	}
	c.cdsMeasurements = env(envCDSMeasurements)
	c.meshMeasurements = env(envMeshMeasurements)
	c.podIP = env(envPodIP)
	return c
}

// validate enforces the required-field invariants for in-guest mode. Run
// before any side effects (iptables, listeners) so a misconfigured pod
// fails before consuming guest resources.
func (c *inGuestConfig) validate() error {
	if c.workloadID == "" {
		return fmt.Errorf("%s is required (set via cloud-init)", envWorkloadID)
	}
	if c.cdsURL == "" {
		return fmt.Errorf("%s is required (set via cloud-init)", envCDSURL)
	}
	if !hasURLScheme(c.cdsURL) {
		return fmt.Errorf("%s %q must start with http:// or https://", envCDSURL, c.cdsURL)
	}
	if !hasURLScheme(c.attestationServiceURL) {
		return fmt.Errorf("%s %q must start with http:// or https://", envAttestationServiceURL, c.attestationServiceURL)
	}
	return validateConfig(c.attestationServiceURL, inGuestOutboundPort, inGuestInboundPort, inGuestHealthPort, c.certTTL)
}

func hasURLScheme(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func newInGuestCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "in-guest",
		Short: "Run ratls-mesh as a systemd service inside a kata guest VM",
		Long: `Run ratls-mesh inside a kata guest VM, where it is invoked by systemd
(not by Kubernetes containers). Configuration is read from environment
variables (typically via systemd EnvironmentFile=/run/c8s/ratls-mesh.env,
which c8s-cloudinit-env.service populates from cloud-init user-data).

Required environment variables:
  C8S_WORKLOAD_ID         workload identity (logged and reported to CDS)
  C8S_CDS_URL             https URL of CDS (attestation + leaf signing + CA)

Optional environment variables:
  C8S_ATTESTATION_SERVICE_URL   defaults to http://127.0.0.1:8400
  C8S_LOG_LEVEL                 debug | info (default) | warn | error
  C8S_PLATFORM                  TEE platform (default sev-snp)
  C8S_CDS_MEASUREMENTS          comma-separated hex SHA-384 measurements
  C8S_MESH_MEASUREMENTS         comma-separated hex SHA-384 measurements
  C8S_POD_IP                    in-guest pod IP (auto-detected if empty)

Requires CAP_NET_ADMIN to install iptables redirects on the guest
interface; the systemd unit owns granting that capability.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := loadInGuestConfig(os.Getenv)
			return runInGuest(cmd.Context(), &cfg)
		},
	}
}

// runInGuest is the entry point for the `in-guest` subcommand. It has to
// compose what host-mode normally splits across an init container
// (iptables-sync) and a sidecar (ratls-mesh): inside the kata guest the
// same process does both.
//
// Error path: any failure here returns a non-nil error, which cobra
// turns into a non-zero exit code, which fails the systemd unit, which
// fails every dependent guest unit (kata-agent reports
// CreateContainerError).
func runInGuest(ctx context.Context, c *inGuestConfig) error {
	logger, err := certutil.NewJSONLogger(c.logLevel)
	if err != nil {
		return fmt.Errorf("in-guest config: %s: %w", envLogLevel, err)
	}

	if err := c.validate(); err != nil {
		return fmt.Errorf("in-guest config: %w", err)
	}

	podIP, err := resolvePodIP(c.podIP)
	if err != nil {
		return fmt.Errorf("in-guest: resolve pod IP: %w", err)
	}
	logger.Info("in-guest mode starting",
		"workload_id", c.workloadID,
		"pod_ip", podIP,
		"cds_url", c.cdsURL,
		"attestation_service_url", c.attestationServiceURL,
		"platform", c.platform,
	)

	// Disable the sidecar metrics file: in-guest there is no separate
	// iptables-sync process. The host-mode reader treats ENOENT as a
	// cold-start signal, so disabling the file path keeps that loop
	// quiet rather than warning every tick.
	configureIptablesMetricsFile("")

	// Install iptables redirects first. A failure here is non-recoverable:
	// the proxy would otherwise come up but the workload's traffic would
	// silently bypass the mesh — a worse failure mode than crashing.
	if err := setupInGuestIptables(logger, podIP); err != nil {
		return fmt.Errorf("in-guest iptables setup: %w", err)
	}

	teeType, err := ratlsTEEType(c.platform)
	if err != nil {
		return err
	}
	cdsMeasurements, err := parseHexMeasurements(c.cdsMeasurements)
	if err != nil {
		return fmt.Errorf("%s: %w", envCDSMeasurements, err)
	}
	meshPolicyMeasurements, err := parseHexMeasurements(c.meshMeasurements)
	if err != nil {
		return fmt.Errorf("%s: %w", envMeshMeasurements, err)
	}

	meshPolicy := &ratls.VerifyPolicy{
		Measurements:      meshPolicyMeasurements,
		AttestationApiURL: c.attestationServiceURL,
	}
	if len(meshPolicyMeasurements) == 0 {
		logger.Warn("no mesh measurements pinned (C8S_MESH_MEASUREMENTS empty); accepting any TEE attestation (unsafe for production)")
	}
	if len(cdsMeasurements) == 0 {
		logger.Warn("no CDS measurements pinned (C8S_CDS_MEASUREMENTS empty); the RA-TLS handshake with CDS will accept any measurement (unsafe for production)")
	}

	asClient := attestclient.NewClientWithHTTP("", &http.Client{Timeout: c.rotationTimeout})
	attestFunc := makeAttestFunc(asClient, c.attestationServiceURL)

	effectiveCAURL := strings.TrimRight(c.cdsURL, "/") + "/ca"

	// The self-signed boot cert carries no SAN, same as host-mode: mesh peers
	// authenticate it by hardware attestation, not by SAN/hostname. The
	// CDS-issued upgrade cert carries no SAN either; its CN binds the pod IP
	// (see cdsclient.Client.createCSR).
	serverTLS, serverCertMgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:        c.platform,
		AttestFunc:      attestFunc,
		CertTTL:         c.certTTL,
		ClientPolicy:    meshPolicy,
		DynamicCACert:   true,
		RotationTimeout: c.rotationTimeout,
		Logger:          logger,
	})
	if err != nil {
		return fmt.Errorf("in-guest: create server TLS config: %w", err)
	}
	clientTLS, clientCertMgr, err := ratls.NewClientTLSConfig(&ratls.ClientConfig{
		Policy:          meshPolicy,
		Platform:        c.platform,
		AttestFunc:      attestFunc,
		DynamicCACert:   true,
		CertTTL:         c.certTTL,
		RotationTimeout: c.rotationTimeout,
		Logger:          logger,
	})
	if err != nil {
		return fmt.Errorf("in-guest: create client TLS config: %w", err)
	}

	m := newMetrics()
	m.certModeConfigured.Store(1)
	if len(meshPolicy.Measurements) > 0 {
		m.measurementPinning.Set(1)
	}

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
	serverCertMgr.SetOnRotationFail(func() { m.certRotationFailures.Inc() })
	if clientCertMgr != nil {
		clientCertMgr.SetOnRotationFail(func() { m.certRotationFailures.Inc() })
	}

	resolver := &inGuestResolver{podIP: normalizeIP(podIP)}
	health := newHealthServer(m, serverCertMgr, clientCertMgr, 10, 5*time.Second, 10*time.Second)

	proxy := &Proxy{
		outboundAddr:      fmt.Sprintf(":%d", inGuestOutboundPort),
		inboundAddr:       fmt.Sprintf(":%d", inGuestInboundPort),
		serverTLS:         serverTLS,
		clientTLS:         clientTLS,
		nodeIP:            podIP,
		inboundPort:       inGuestInboundPort,
		resolver:          resolver,
		origDstFunc:       defaultOrigDstFunc,
		logger:            logger,
		metrics:           m,
		accessLog:         true,
		dialTimeout:       c.dialTimeout,
		tlsDialTimeout:    c.tlsDialTimeout,
		destHeaderTimeout: c.destHeaderTimeout,
		drainTimeout:      c.drainTimeout,
		keepAlive:         c.keepAlive,
		maxDestHeaderSize: 256,
		pipeBufferSize:    32768,
		bufPool:           newBufPool(32768),
		onReady: func() {
			warmupCtx, cancel := context.WithTimeout(ctx, 2*c.rotationTimeout)
			defer cancel()
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

	go func() {
		if err := health.serve(ctx, fmt.Sprintf(":%d", inGuestHealthPort)); err != nil {
			logger.Error("health server error", "error", err)
		}
	}()

	cdsCfg := &cdsclient.Config{
		CDSURL:            c.cdsURL,
		AttestationApiURL: c.attestationServiceURL,
		CDSCAURL:          c.cdsURL,
		CACertURL:         effectiveCAURL,
		NodeIP:            podIP,
		NodeName:          c.workloadID,
		TEEType:           teeType,
		CDSMeasurements:   cdsMeasurements,
	}
	go runInGuestCDSUpgrade(ctx, logger, c, cdsCfg, serverCertMgr, clientCertMgr, m)
	go runInGuestCABundleRefresh(ctx, logger, c, cdsCfg, serverCertMgr, clientCertMgr)

	logger.Info("ratls-mesh in-guest listening",
		"outbound", proxy.outboundAddr,
		"inbound", proxy.inboundAddr,
		"health", inGuestHealthPort,
	)
	if err := proxy.Run(ctx); err != nil {
		return fmt.Errorf("in-guest proxy: %w", err)
	}
	return nil
}

func runInGuestCDSUpgrade(
	ctx context.Context,
	logger *slog.Logger,
	c *inGuestConfig,
	cdsCfg *cdsclient.Config,
	serverCertMgr, clientCertMgr *ratls.CertManager,
	m *metrics,
) {
	provider, err := cdsclient.NewProvider(cdsCfg, logger)
	if err != nil {
		logger.Error("in-guest cds provider creation failed", "error", err)
		return
	}
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = c.cdsRetryBackoff
	bo.MaxInterval = c.cdsRetryMaxBackoff

	_, err = backoff.Retry(ctx, func() (struct{}, error) {
		upgradeCtx, cancel := context.WithTimeout(ctx, c.cdsOpTimeout)
		defer cancel()
		if err := serverCertMgr.SwapProvider(upgradeCtx, provider); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, nil
	},
		backoff.WithBackOff(bo),
		backoff.WithNotify(func(err error, d time.Duration) {
			logger.Warn("in-guest cds cert upgrade attempt failed (will retry)", "error", err, "backoff", d)
		}),
	)
	if err != nil {
		return
	}
	logger.Info("in-guest certificate upgraded from self-signed to cds-issued (server)")
	if clientCertMgr != nil {
		upgradeCtx, cancel := context.WithTimeout(ctx, c.cdsOpTimeout)
		if err := clientCertMgr.SwapProvider(upgradeCtx, provider); err != nil {
			logger.Warn("in-guest cds client cert upgrade failed", "error", err)
		} else {
			logger.Info("in-guest certificate upgraded from self-signed to cds-issued (client)")
		}
		cancel()
	}
	m.certMode.Store(1)
}

func runInGuestCABundleRefresh(
	ctx context.Context,
	logger *slog.Logger,
	c *inGuestConfig,
	cdsCfg *cdsclient.Config,
	serverCertMgr, clientCertMgr *ratls.CertManager,
) {
	client := cdsclient.NewClient(cdsCfg)
	ticker := time.NewTicker(c.caPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		refreshCtx, cancel := context.WithTimeout(ctx, c.cdsOpTimeout)
		newCerts, err := client.RefreshCABundle(refreshCtx)
		cancel()
		if err != nil {
			logger.Warn("in-guest CA bundle refresh failed", "error", err)
			continue
		}
		serverCertMgr.UpdateCACerts(newCerts)
		if clientCertMgr != nil {
			clientCertMgr.UpdateCACerts(newCerts)
		}
		logger.Debug("in-guest CA bundle refreshed", "count", len(newCerts))
	}
}

// inGuestResolver is the stub Resolver used by `ratls-mesh in-guest`.
//
// In a kata guest the workload's pod IP is the only "local" address and
// every other IP is, by construction, a remote mesh peer reachable over
// the cluster network. There is no K8s API access from inside the VM,
// so we cannot translate podIP→nodeIP. Resolve therefore returns the
// IP passed in (the proxy dials that IP on the inbound port 15006 of
// whichever node actually hosts it — the cluster overlay handles the
// routing).
//
// TODO: if per-pod cloud-init later carries a peer list or a CDS
// endpoint, replace this with a peer-cache-backed resolver.
type inGuestResolver struct {
	podIP string // canonical (normalizeIP) form
}

var _ Resolver = (*inGuestResolver)(nil)

func (r *inGuestResolver) Resolve(podIP string) (string, bool) {
	canonical := normalizeIP(podIP)
	if canonical == "" {
		return podIP, false
	}
	return canonical, canonical == r.podIP
}

func (r *inGuestResolver) ValidateOutboundDest(ip string) (bool, string) {
	canonical := normalizeIP(ip)
	if canonical == "" {
		return false, "invalid_ip"
	}
	if isLoopbackIP(canonical) {
		// Loopback inside the guest is intra-VM (attestation-service,
		// health probes). It must not be wrapped in RA-TLS or it will
		// loop on itself.
		return false, "loopback"
	}
	return true, ""
}

func (r *inGuestResolver) ValidateLocalDest(ip string) bool {
	canonical := normalizeIP(ip)
	if canonical == "" {
		return false
	}
	return canonical == r.podIP
}

func isLoopbackIP(canonical string) bool {
	parsed := net.ParseIP(canonical)
	return parsed != nil && parsed.IsLoopback()
}

// resolvePodIP picks the local pod IP either from the cloud-init-supplied
// env var (preferred — deterministic) or by inspecting the guest's
// interfaces and picking the first non-loopback unicast address. Auto
// detection exists for first-cluster bring-up where cloud-init might
// not have wired the env var yet; the systemd unit should set
// C8S_POD_IP whenever possible for reproducibility.
func resolvePodIP(fromEnv string) (string, error) {
	if fromEnv != "" {
		canonical := normalizeIP(fromEnv)
		if canonical == "" {
			return "", fmt.Errorf("%s %q is not a valid IP address", envPodIP, fromEnv)
		}
		return canonical, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("enumerate interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := addrIP(addr)
			if ip == nil || !ip.IsGlobalUnicast() {
				continue
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("no usable non-loopback IPv4/IPv6 unicast address; set " + envPodIP + " via cloud-init")
}

func addrIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

// readinessCheckResult captures the outcome of one HTTP /ready probe.
type readinessCheckResult struct {
	OK     bool
	Status int
	Err    error
}

// probeReadiness GETs the local /ready endpoint exposed by the in-guest
// proxy and returns the structured result. Used as `ExecStartPost=` by
// systemd: a non-zero exit fails the service unit, which in turn fails
// every dependent unit (the kata-guest-base unit ordering), so the
// workload never starts.
//
// READINESS SEMANTICS: /ready returns 200 once (a) the proxy's accept
// loops are bound and healthy, and (b) the cert manager has provisioned
// *any* leaf — the initial self-signed one from SelfSignedProvider is
// sufficient. The background goroutine that upgrades the leaf to a
// CDS-issued one (runInGuestCDSUpgrade) does NOT gate /ready.
//
// This is deliberate. Inside the CDS pod's VM, CDS is the workload
// container itself: it hasn't been started by kata-agent yet when
// ratls-mesh boots. If /ready required a CDS-signed leaf, the CDS
// pod would deadlock (ratls-mesh waits for CDS, kata-agent waits
// for ratls-mesh.service to be active, CDS waits for kata-agent
// to start it). The weak gate lets the CDS VM boot: ratls-mesh comes
// up self-signed, kata-agent starts CDS, the upgrade goroutine
// (which CDS can satisfy by issuing a cert to itself — it is its own
// CA) eventually swaps the provider. Workload pods, where CDS already
// exists in a peer VM, go through the same boot path and converge on a
// CDS-signed leaf within seconds of WarmUp.
func probeReadiness(ctx context.Context, healthURL string, timeout time.Duration) readinessCheckResult {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return readinessCheckResult{Err: fmt.Errorf("build request: %w", err)}
	}
	resp, err := client.Do(req)
	if err != nil {
		return readinessCheckResult{Err: fmt.Errorf("connect: %w", err)}
	}
	defer resp.Body.Close()
	return readinessCheckResult{
		OK:     resp.StatusCode == http.StatusOK,
		Status: resp.StatusCode,
	}
}

func newReadinessCheckCommand() *cobra.Command {
	var (
		healthPort int
		retries    int
		retryWait  time.Duration
		timeout    time.Duration
	)
	cmd := &cobra.Command{
		Use:   "readiness-check",
		Short: "Probe the in-guest ratls-mesh /ready endpoint (used as systemd ExecStartPost)",
		Long: `readiness-check exits 0 once the in-guest ratls-mesh has reached its
ready state: proxy listeners bound and accept loops healthy, and the
cert manager has provisioned *any* leaf (the bootstrap self-signed one
is sufficient). The background upgrade from self-signed to CDS-issued
does NOT gate readiness — see probeReadiness for the rationale (CDS
bootstrap would otherwise deadlock).

This is the readiness oracle that gates dependent guest units: the
systemd unit declares ExecStartPost=/usr/local/bin/ratls-mesh
readiness-check, so a failed probe fails the unit and dependent units
(Requires=ratls-mesh.service) never start. That in turn keeps
kata-agent's CreateContainer from completing, so kubelet surfaces
CreateContainerError rather than a "started but broken" pod.

A workload pod whose CDS is unreachable still fails closed: its
injected c8s-cert sidecar dials CDS to mint its leaf and that call
returns an error, so the sidecar's startupProbe never passes and
kubelet reports the workload pod stuck at Init. The fail-closed
property moves from ratls-mesh's startup gate to the c8s-cert
sidecar, one container later in the boot, with the same end state.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := "http://127.0.0.1:" + strconv.Itoa(healthPort) + "/ready"
			ctx := cmd.Context()
			var last readinessCheckResult
			for attempt := 0; attempt <= retries; attempt++ {
				last = probeReadiness(ctx, url, timeout)
				if last.OK {
					return nil
				}
				if attempt < retries {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(retryWait):
					}
				}
			}
			if last.Err != nil {
				return fmt.Errorf("readiness probe %s failed: %w", url, last.Err)
			}
			return fmt.Errorf("readiness probe %s returned status %d", url, last.Status)
		},
	}
	cmd.Flags().IntVar(&healthPort, "health-port", inGuestHealthPort, "ratls-mesh health server port")
	cmd.Flags().IntVar(&retries, "retries", 3, "extra probe attempts after the initial one")
	cmd.Flags().DurationVar(&retryWait, "retry-wait", 2*time.Second, "delay between probe attempts")
	cmd.Flags().DurationVar(&timeout, "timeout", 3*time.Second, "per-probe HTTP timeout")
	return cmd
}

// setupInGuestIptables installs the OUTPUT and PREROUTING NAT redirects
// that send the guest workload's TCP traffic through the mesh. The rules
// are intentionally narrower than the host-mode pod-IP-set redirects
// (no K8s API, no ipsets, no informers).
//
//   - OUTPUT: any TCP from a non-proxy UID (not 1337), except loopback
//     and traffic to attestation-service (127.0.0.1:8400 already
//     filtered by the loopback exclusion) and to the mesh's own
//     listener ports, is redirected to 15001. The owner exclusion
//     stops the proxy from looping on itself.
//   - PREROUTING: any TCP arriving on a non-loopback interface, except
//     traffic to the mesh's own listener ports (15001/15006/15021), is
//     redirected to 15006. PREROUTING has no socket-owner match so we
//     exclude by destination port instead.
//
// Returns an error on the first failure; the caller exits non-zero.
// Idempotent: installIptablesRules flushes the managed chains first so
// a crash-restart does not double-install rules.
func setupInGuestIptables(logger *slog.Logger, podIP string) error {
	if err := initIptablesClients(); err != nil {
		return err
	}
	rules := buildInGuestIptablesRules(inGuestOutboundPort, inGuestInboundPort, inGuestHealthPort)
	jumps := jumpRules()
	logger.Info("installing in-guest iptables redirects",
		"outbound_port", inGuestOutboundPort,
		"inbound_port", inGuestInboundPort,
		"health_port", inGuestHealthPort,
		"pod_ip", podIP,
	)
	return installIptablesRules(logger, rules, jumps)
}

// buildInGuestIptablesRules returns the NAT rules the in-guest mode
// installs into the RATLS-MESH and RATLS-MESH-PREROUTING chains. Kept
// pure (no system calls) so it can be unit-tested.
//
// Rule ordering matters: the early RETURN rules let the proxy's own
// traffic and the in-VM IPC (attestation-service on loopback) through
// without redirect; the trailing REDIRECT rules catch everything else.
func buildInGuestIptablesRules(outboundPort, inboundPort, healthPort int) []iptablesRule {
	uidStr := strconv.Itoa(defaultProxyUID)
	outPortStr := strconv.Itoa(outboundPort)
	inPortStr := strconv.Itoa(inboundPort)

	rules := make([]iptablesRule, 0, 8)

	// OUTPUT chain. Step 1: pass through proxy-owned traffic so we don't
	// loop. Step 1b: pass through in-guest infrastructure (root, UID 0).
	// Step 2: pass through loopback (intra-VM IPC). Step 3: pass
	// through traffic destined for the mesh's own ports (defence in
	// depth — owner match should already catch this). Step 4: REDIRECT
	// everything else TCP to the outbound proxy.
	rules = append(rules, iptablesRule{
		table: "nat", chain: chainName,
		label: "in-guest-output-skip-proxy-uid",
		args: []string{
			"-p", "tcp",
			"-m", "owner", "--uid-owner", uidStr,
			"-j", "RETURN",
		},
	})
	// Pass through in-guest INFRASTRUCTURE egress (root, UID 0). The mesh
	// proxy only terminates RA-TLS to mesh PEERS; it cannot proxy a plain
	// outbound TLS call to an external endpoint. attestation-service runs
	// as root and must reach AMD KDS over the internet to fetch the
	// per-chip VCEK while assembling SNP evidence for /attest — redirecting
	// that egress into the proxy makes /attest hang, which in turn makes
	// ratls-mesh's own leaf minting (and therefore c8s-ready.target) flap.
	// In-guest root is trusted TCB infrastructure (the c8s threat model
	// trusts the guest's own kernel); the workload that the mesh exists to
	// wrap runs unprivileged (the c8s image is UID 65532) and is still
	// redirected by the catch-all below.
	//
	// REQUIREMENT / LIMITATION: this exemption assumes the wrapped workload
	// runs unprivileged (the c8s image is UID 65532). A workload running as
	// UID 0 (an explicit runAsUser: 0, or simply an image whose default USER
	// is root) matches this rule and egresses in PLAINTEXT, bypassing the
	// mesh. Matching on UID cannot distinguish attestation-service from a
	// root workload, and admission control can pin runAsUser but cannot see
	// an image's default USER, so neither layer fully closes this.
	// Deployments relying on the mesh's confidentiality MUST run workloads
	// non-root. A follow-up should scope this exemption to
	// attestation-service (cgroup or binary match) instead of all of UID 0.
	rules = append(rules, iptablesRule{
		table: "nat", chain: chainName,
		label: "in-guest-output-skip-infra-uid",
		args: []string{
			"-p", "tcp",
			"-m", "owner", "--uid-owner", "0",
			"-j", "RETURN",
		},
	})
	for _, family := range []iptablesFamily{iptablesFamilyIPv4, iptablesFamilyIPv6} {
		rules = append(rules, iptablesRule{
			table: "nat", chain: chainName, family: family,
			label: "in-guest-output-skip-loopback-" + string(family),
			args:  []string{"-p", "tcp", "-o", "lo", "-j", "RETURN"},
		})
	}
	rules = append(rules, iptablesRule{
		table: "nat", chain: chainName,
		label: "in-guest-output-skip-mesh-ports",
		args: []string{
			"-p", "tcp",
			"-m", "multiport", "--dports",
			strings.Join([]string{outPortStr, inPortStr, strconv.Itoa(healthPort)}, ","),
			"-j", "RETURN",
		},
	})
	rules = append(rules, iptablesRule{
		table: "nat", chain: chainName,
		label: "in-guest-output-redirect",
		args: []string{
			"-p", "tcp",
			"-j", "REDIRECT", "--to-port", outPortStr,
		},
	})

	// PREROUTING chain. PREROUTING fires for traffic arriving from a
	// non-host interface (i.e. from the kata-agent virtio NIC, peer
	// pods). Loopback never hits PREROUTING. We skip the mesh's own
	// listener ports and redirect everything else to the inbound proxy.
	rules = append(rules, iptablesRule{
		table: "nat", chain: preroutingChainName,
		label: "in-guest-prerouting-skip-mesh-ports",
		args: []string{
			"-p", "tcp",
			"-m", "multiport", "--dports",
			strings.Join([]string{outPortStr, inPortStr, strconv.Itoa(healthPort)}, ","),
			"-j", "RETURN",
		},
	})
	rules = append(rules, iptablesRule{
		table: "nat", chain: preroutingChainName,
		label: "in-guest-prerouting-redirect",
		args: []string{
			"-p", "tcp",
			"-j", "REDIRECT", "--to-port", inPortStr,
		},
	})

	return rules
}
