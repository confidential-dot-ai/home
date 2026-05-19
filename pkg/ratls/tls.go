package ratls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Logger is an optional structured logger for RA-TLS operations.
// If nil, no logging occurs. Compatible with [log/slog.Logger].
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// ServerConfig configures an RA-TLS server.
type ServerConfig struct {
	// Platform is the TEE platform: "sev-snp" or "tdx".
	Platform string

	// AttestFunc generates attestation evidence given custom data
	// (hex-encoded REPORTDATA). This is the sole integration point
	// with the TEE attestation infrastructure. The context comes from
	// the TLS handshake and should be used for cancellation/timeouts.
	AttestFunc func(ctx context.Context, customData string) (string, error)

	// CertProvider, when set, is used instead of Platform/AttestFunc for
	// certificate provisioning. This enables pluggable certificate sources
	// (e.g., KBS-issued certificates). When nil, a SelfSignedProvider is
	// constructed from Platform and AttestFunc.
	CertProvider CertProvider

	// CACert, when set, enables standard X.509 chain verification for peer
	// certificates instead of RA-TLS attestation verification. Peers whose
	// certificates chain to any of these CAs are accepted. When nil, peers
	// are verified using RA-TLS attestation (the default behavior).
	// A multi-cert slice supports CA rotation: include both old and new CA
	// certs during the transition window.
	CACert []*x509.Certificate

	// DynamicCACert, when true, enables dual-mode verification with an
	// initially empty CA pool. CA certs are populated later via
	// CertManager.UpdateCACerts. Until then, falls through to RA-TLS.
	// Use this when CA certs are fetched at runtime (e.g., from cert-issuer /ca).
	DynamicCACert bool

	// DNSNames for the server certificate.
	DNSNames []string

	// Subject for the certificate. Defaults to "RA-TLS Workload".
	Subject pkix.Name

	// CertTTL is the certificate lifetime. Default: 24h.
	// The certificate is rotated automatically at 50% of TTL.
	CertTTL time.Duration

	// ClientPolicy, when set, enables mTLS: the server requires client
	// certificates and verifies their RA-TLS attestation against this policy.
	// When nil, the server does not request client certificates.
	ClientPolicy *VerifyPolicy

	// RotationTimeout is the maximum time allowed for background certificate
	// rotation. If the attestation binary doesn't respond within this duration,
	// rotation is aborted and retried on the next handshake past rotateAt.
	// Default: 30s.
	RotationTimeout time.Duration

	// Logger, when set, receives structured log messages for certificate
	// provisioning, rotation, and errors. If nil, no logging occurs.
	Logger Logger
}

// ClientConfig configures an RA-TLS client that verifies peer TEE claims.
// Trust comes from the hardware attestation chain (AMD ARK → ASK → VCEK),
// not from any certificate authority.
type ClientConfig struct {
	// Policy defines acceptable attestation claims for the server.
	Policy *VerifyPolicy

	// Platform and AttestFunc, when both set, enable mTLS: the client
	// presents its own RA-TLS certificate to the server. Both must be
	// set together or both left unset.
	Platform   string
	AttestFunc func(ctx context.Context, customData string) (string, error)

	// CertProvider, when set, is used instead of Platform/AttestFunc for
	// certificate provisioning. When nil, a SelfSignedProvider is constructed
	// from Platform and AttestFunc (if both are set).
	CertProvider CertProvider

	// CACert, when set, enables standard X.509 chain verification for peer
	// certificates instead of RA-TLS attestation verification. Peers whose
	// certificates chain to any of these CAs are accepted. When nil, peers
	// are verified using RA-TLS attestation (the default behavior).
	// A multi-cert slice supports CA rotation: include both old and new CA
	// certs during the transition window.
	CACert []*x509.Certificate

	// DynamicCACert, when true, enables dual-mode verification with an
	// initially empty CA pool. CA certs are populated later via
	// CertManager.UpdateCACerts.
	DynamicCACert bool

	// CertTTL is the client certificate lifetime. Default: 24h.
	// Only used when Platform and AttestFunc are set.
	CertTTL time.Duration

	// RotationTimeout is the maximum time allowed for background certificate
	// rotation. Default: 30s.
	RotationTimeout time.Duration

	// Logger, when set, receives structured log messages for certificate
	// provisioning, rotation, and errors. If nil, no logging occurs.
	Logger Logger
}

// certState holds a cached certificate and its rotation deadline.
// Rotation is non-blocking: when a cert is due for rotation, the old cert
// is returned immediately while a background goroutine provisions the new one.
type certState struct {
	mu              sync.RWMutex
	cert            *tls.Certificate
	rotateAt        time.Time
	provider        CertProvider // certificate provisioning strategy
	logger          Logger
	rotating        atomic.Bool   // prevents concurrent background rotations
	rotationTimeout time.Duration // 0 = default (30s)
	provisioned     atomic.Bool   // true after first successful provision
	onRotationFail  func()        // optional callback on rotation failure (for metrics)
	defaultTTL      time.Duration // fallback TTL if provider returns 0
}

// CertReady returns true if a certificate has been successfully provisioned
// at least once. Use this to gate readiness probes.
func (s *certState) CertReady() bool {
	return s.provisioned.Load()
}

// CertExpiry returns the NotAfter time of the current certificate, or the zero
// time if no certificate has been provisioned yet.
func (s *certState) CertExpiry() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cert == nil || s.cert.Leaf == nil {
		return time.Time{}
	}
	return s.cert.Leaf.NotAfter
}

// WarmUp eagerly provisions a certificate so the first TLS handshake doesn't
// block on attestation. Returns the cert or an error. Thread-safe.
func (s *certState) WarmUp(ctx context.Context) error {
	_, err := s.getOrProvision(ctx)
	return err
}

// getOrProvision returns a cached certificate or provisions a new one.
// If the cached cert is past its rotation deadline but still valid, the old
// cert is returned immediately and rotation happens in the background.
// Only the very first call (no cert at all) blocks synchronously.
func (s *certState) getOrProvision(ctx context.Context) (*tls.Certificate, error) {
	s.mu.RLock()
	if s.cert != nil {
		cert := s.cert
		needsRotation := time.Now().After(s.rotateAt)
		currentProvider := s.provider // capture under RLock before releasing
		s.mu.RUnlock()

		if !needsRotation {
			return cert, nil
		}

		// Cert still valid but due for rotation — return old cert,
		// provision new one in the background.
		if s.rotating.CompareAndSwap(false, true) {
			go s.backgroundProvision(currentProvider)
		}
		return cert, nil
	}
	s.mu.RUnlock()

	// No cert at all — first call, must provision synchronously.
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check: another goroutine may have provisioned while we waited.
	if s.cert != nil {
		return s.cert, nil
	}

	cert, ttl, err := s.provider.Provision(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("ratls: certificate provisioning failed", "err", err)
		}
		return nil, fmt.Errorf("ratls: provision certificate: %w", err)
	}

	if ttl == 0 {
		ttl = s.effectiveTTL()
	}
	rotateAt := time.Now().Add(ttl / 2)
	s.cert = cert
	s.rotateAt = rotateAt
	s.provisioned.Store(true)

	if s.logger != nil {
		s.logger.Info("ratls: certificate provisioned", "ttl", ttl, "rotateAt", rotateAt)
	}

	return cert, nil
}

// backgroundProvision provisions a new certificate without blocking callers.
// On failure, the old cert continues being served and the next handshake
// past rotateAt will retry. The spawnProvider parameter is the provider that
// was active when rotation was triggered — if SwapProvider replaced it since,
// the result is discarded to avoid overwriting the new provider's cert.
func (s *certState) backgroundProvision(spawnProvider CertProvider) {
	defer s.rotating.Store(false)

	timeout := s.rotationTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cert, ttl, err := spawnProvider.Provision(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("ratls: background certificate rotation failed", "err", err)
		}
		if s.onRotationFail != nil {
			s.onRotationFail()
		}
		return
	}

	if ttl == 0 {
		ttl = s.effectiveTTL()
	}
	rotateAt := time.Now().Add(ttl / 2)
	s.mu.Lock()
	if s.provider != spawnProvider {
		// Provider was swapped while we were provisioning — discard stale cert.
		s.mu.Unlock()
		if s.logger != nil {
			s.logger.Info("ratls: discarding background rotation (provider changed)")
		}
		return
	}
	s.cert = cert
	s.rotateAt = rotateAt
	s.mu.Unlock()

	if s.logger != nil {
		s.logger.Info("ratls: certificate rotated (background)", "ttl", ttl, "rotateAt", rotateAt)
	}
}

// effectiveTTL returns the default TTL, falling back to DefaultCertTTL.
func (s *certState) effectiveTTL() time.Duration {
	if s.defaultTTL > 0 {
		return s.defaultTTL
	}
	return DefaultCertTTL
}

// SwapProvider atomically replaces the certificate provider and triggers
// an immediate re-provisioning. Used for runtime upgrades (e.g., self-signed
// to KBS-issued). The old certificate continues serving until the new one
// is ready — if provisioning fails, the old cert and provider remain active.
func (s *certState) SwapProvider(ctx context.Context, provider CertProvider) error {
	// Provision with the new provider BEFORE swapping. This prevents a
	// readiness gap: if provisioning fails, the old cert and provider
	// remain active (the mesh stays ready and serves traffic).
	cert, ttl, err := provider.Provision(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("ratls: certificate provisioning failed", "err", err)
		}
		return fmt.Errorf("ratls: provision certificate: %w", err)
	}

	if ttl == 0 {
		ttl = s.effectiveTTL()
	}
	rotateAt := time.Now().Add(ttl / 2)

	// Swap atomically: old cert served until this lock is released.
	s.mu.Lock()
	s.provider = provider
	s.cert = cert
	s.rotateAt = rotateAt
	s.provisioned.Store(true)
	s.mu.Unlock()

	if s.logger != nil {
		s.logger.Info("ratls: certificate provisioned", "ttl", ttl, "rotateAt", rotateAt)
	}

	return nil
}

// sharedCACerts holds a dynamically-updatable list of CA certificates
// for dual-mode (CA chain + RA-TLS) peer verification.
type sharedCACerts struct {
	pool  atomic.Pointer[x509.CertPool]
	certs atomic.Pointer[[]*x509.Certificate]
}

func newSharedCACerts(certs []*x509.Certificate) *sharedCACerts {
	s := &sharedCACerts{}
	s.update(certs)
	return s
}

func (s *sharedCACerts) update(certs []*x509.Certificate) {
	pool := x509.NewCertPool()
	for _, ca := range certs {
		pool.AddCert(ca)
	}
	s.pool.Store(pool)
	s.certs.Store(&certs)
}

func (s *sharedCACerts) getPool() *x509.CertPool {
	return s.pool.Load()
}

// CertManager provides access to the RA-TLS certificate lifecycle.
// Use WarmUp to eagerly provision the certificate at startup and CertReady
// to gate readiness probes.
type CertManager struct {
	state    *certState
	sharedCA *sharedCACerts // non-nil when dual-mode verification is active
}

// WarmUp eagerly provisions the certificate. Call this at startup (after
// listener bind, before marking ready) to avoid blocking the first handshake.
func (m *CertManager) WarmUp(ctx context.Context) error {
	return m.state.WarmUp(ctx)
}

// CertReady returns true if a certificate has been provisioned at least once.
func (m *CertManager) CertReady() bool {
	return m.state.CertReady()
}

// CertExpiry returns the NotAfter time of the current certificate, or the zero
// time if no certificate has been provisioned yet.
func (m *CertManager) CertExpiry() time.Time {
	return m.state.CertExpiry()
}

// SetOnRotationFail registers a callback invoked when background rotation fails.
// Useful for incrementing Prometheus counters.
func (m *CertManager) SetOnRotationFail(fn func()) {
	m.state.onRotationFail = fn
}

// SwapProvider replaces the underlying certificate provider at runtime and
// immediately provisions a certificate from the new provider. Use this for
// runtime upgrades (e.g., self-signed to KBS-issued).
func (m *CertManager) SwapProvider(ctx context.Context, provider CertProvider) error {
	return m.state.SwapProvider(ctx, provider)
}

// UpdateCACerts dynamically updates the CA certificates used for dual-mode
// peer verification. This is used by the CA bundle refresh goroutine when
// polling the cert-issuer /ca endpoint in cert-issuer-backed modes.
func (m *CertManager) UpdateCACerts(certs []*x509.Certificate) {
	if m.sharedCA != nil {
		m.sharedCA.update(certs)
	}
}

// NewServerTLSConfig creates a tls.Config for an RA-TLS server. The private
// key is generated in memory and never written to disk. The attestation report
// is obtained lazily on the first TLS handshake and cached until rotation.
//
// If ClientPolicy is set, the server requires client certificates and verifies
// their RA-TLS attestation (mTLS). If CACert is also set, the server accepts
// peers with either valid RA-TLS attestation OR a certificate chain to the CA.
//
// If CertProvider is set, it is used for certificate provisioning instead of
// Platform/AttestFunc. When CertProvider is nil, Platform and AttestFunc are
// required and a SelfSignedProvider is created internally.
//
// The returned CertManager can be used to eagerly provision the certificate
// (WarmUp) and check readiness (CertReady).
func NewServerTLSConfig(cfg *ServerConfig) (*tls.Config, *CertManager, error) {
	provider := cfg.CertProvider
	if provider == nil {
		// Fall back to self-signed: require Platform + AttestFunc.
		if cfg.Platform == "" {
			return nil, nil, fmt.Errorf("ratls: Platform is required")
		}
		if err := validatePlatform(cfg.Platform); err != nil {
			return nil, nil, err
		}
		if cfg.AttestFunc == nil {
			return nil, nil, fmt.Errorf("ratls: AttestFunc is required")
		}
		provider = &SelfSignedProvider{
			Platform:   cfg.Platform,
			AttestFunc: cfg.AttestFunc,
			Opts: &CertOptions{
				Subject:  cfg.Subject,
				TTL:      cfg.CertTTL,
				DNSNames: cfg.DNSNames,
			},
		}
	}

	state := &certState{
		provider:        provider,
		logger:          cfg.Logger,
		rotationTimeout: cfg.RotationTimeout,
		defaultTTL:      cfg.CertTTL,
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return state.getOrProvision(hello.Context())
		},
	}

	// mTLS: require and verify client certificates.
	var sharedCA *sharedCACerts
	if cfg.ClientPolicy != nil {
		tlsCfg.ClientAuth = tls.RequireAnyClientCert
		if len(cfg.CACert) > 0 || cfg.DynamicCACert {
			sharedCA = newSharedCACerts(cfg.CACert) // empty slice is fine — falls through to RA-TLS
			tlsCfg.VerifyPeerCertificate = dualVerifyPeerCallback(cfg.ClientPolicy, sharedCA)
		} else {
			tlsCfg.VerifyPeerCertificate = verifyPeerCallback(cfg.ClientPolicy)
		}
	}

	mgr := &CertManager{state: state, sharedCA: sharedCA}
	return tlsCfg, mgr, nil
}

// NewClientTLSConfig creates a tls.Config for an RA-TLS client. It verifies
// the server's certificate contains a valid TEE attestation extension with
// REPORTDATA bound to the server's public key. Trust is established through
// the hardware attestation chain, not PKI — InsecureSkipVerify is true because
// the certificate's own signature is irrelevant.
//
// If CACert is set, the client also accepts servers with certificates chaining
// to that CA (dual-mode verification: RA-TLS or X.509 chain).
//
// If Platform and AttestFunc are set (or CertProvider is set), the client
// presents its own certificate for mutual attestation (mTLS).
//
// The returned CertManager is non-nil only when mTLS is configured. Use it
// for eager provisioning and readiness checks.
func NewClientTLSConfig(cfg *ClientConfig) (*tls.Config, *CertManager, error) {
	if cfg == nil {
		cfg = &ClientConfig{}
	}

	// Determine if mTLS is configured.
	hasProvider := cfg.CertProvider != nil
	hasLegacy := cfg.Platform != "" || cfg.AttestFunc != nil

	// Validate mTLS fields: both Platform and AttestFunc, or neither.
	if !hasProvider {
		if (cfg.Platform == "") != (cfg.AttestFunc == nil) {
			return nil, nil, fmt.Errorf("ratls: Platform and AttestFunc must both be set or both unset")
		}
		if cfg.Platform != "" {
			if err := validatePlatform(cfg.Platform); err != nil {
				return nil, nil, err
			}
		}
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Trust comes from hardware attestation, not PKI.
	}

	// Peer verification: dual-mode if CACert is set (or DynamicCACert for runtime population).
	var clientSharedCA *sharedCACerts
	if len(cfg.CACert) > 0 || cfg.DynamicCACert {
		clientSharedCA = newSharedCACerts(cfg.CACert) // empty slice is fine — falls through to RA-TLS
		tlsCfg.VerifyPeerCertificate = dualVerifyPeerCallback(cfg.Policy, clientSharedCA)
	} else {
		tlsCfg.VerifyPeerCertificate = verifyPeerCallback(cfg.Policy)
	}

	var mgr *CertManager

	// mTLS: present client certificate.
	if hasProvider || (hasLegacy && cfg.AttestFunc != nil) {
		var provider CertProvider
		if cfg.CertProvider != nil {
			provider = cfg.CertProvider
		} else {
			provider = &SelfSignedProvider{
				Platform:   cfg.Platform,
				AttestFunc: cfg.AttestFunc,
				Opts:       &CertOptions{TTL: cfg.CertTTL},
			}
		}

		state := &certState{
			provider:        provider,
			logger:          cfg.Logger,
			rotationTimeout: cfg.RotationTimeout,
			defaultTTL:      cfg.CertTTL,
		}

		tlsCfg.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return state.getOrProvision(info.Context())
		}

		mgr = &CertManager{state: state, sharedCA: clientSharedCA}
	}

	return tlsCfg, mgr, nil
}

// verifyPeerCallback returns a VerifyPeerCertificate function that checks
// the peer's RA-TLS attestation against the given policy.
func verifyPeerCallback(policy *VerifyPolicy) func([][]byte, [][]*x509.Certificate) error {
	// Extract nonce from policy for use in verification.
	var nonce []byte
	if policy != nil {
		nonce = policy.Nonce
	}

	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("ratls: no peer certificate")
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("ratls: parse peer cert: %w", err)
		}

		_, err = VerifyCert(cert, policy, nonce)
		if err != nil {
			return fmt.Errorf("ratls: peer attestation failed: %w", err)
		}
		return nil
	}
}

// dualVerifyPeerCallback returns a VerifyPeerCertificate function that accepts
// peers with EITHER a valid RA-TLS attestation OR a certificate chain to any
// of the given CAs. This enables rolling upgrades where some nodes have
// CA-signed certificates and others still use self-signed RA-TLS. The
// multi-cert pool also supports CA rotation: include both old and new CA
// during the transition window.
func dualVerifyPeerCallback(policy *VerifyPolicy, shared *sharedCACerts) func([][]byte, [][]*x509.Certificate) error {
	var nonce []byte
	if policy != nil {
		nonce = policy.Nonce
	}

	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("ratls: no peer certificate")
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("ratls: parse peer cert: %w", err)
		}

		// Try X.509 chain verification first (fast path — no AMD KDS).
		// Read the CA pool atomically so UpdateCACerts is safe.
		caPool := shared.getPool()
		intermediates := x509.NewCertPool()
		for _, rawCert := range rawCerts[1:] {
			if ic, err := x509.ParseCertificate(rawCert); err == nil {
				intermediates.AddCert(ic)
			}
		}
		_, chainErr := cert.Verify(x509.VerifyOptions{
			Roots:         caPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if chainErr == nil {
			return nil // CA-signed cert — valid.
		}

		// Fall back to RA-TLS attestation verification.
		_, err = VerifyCert(cert, policy, nonce)
		if err != nil {
			return fmt.Errorf("ratls: peer verification failed (CA chain: %v; RA-TLS: %w)", chainErr, err)
		}
		return nil
	}
}

// validatePlatform checks that the platform string refers to an implemented
// TEE type. Call at config creation time to fail fast instead of at first
// handshake. Currently only SEV-SNP is implemented; TDX is recognized by
// parseTEEType but not yet supported end-to-end.
func validatePlatform(platform string) error {
	switch platform {
	case "sev-snp":
		return nil
	case "tdx":
		return fmt.Errorf("ratls: TDX platform is not yet implemented (use sev-snp)")
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedTEE, platform)
	}
}

func parseTEEType(platform string) (TEEType, error) {
	switch platform {
	case "sev-snp":
		return TEETypeSEVSNP, nil
	case "tdx":
		return TEETypeTDX, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedTEE, platform)
	}
}
