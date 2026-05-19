// Package getcert implements the get-cert subcommand: it requests a TLS
// certificate from assam by proving the caller runs inside a TEE.
package getcert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	"github.com/lunal-dev/c8s/internal/fileutil"
	"github.com/lunal-dev/c8s/pkg/attestclient"
	"github.com/lunal-dev/c8s/pkg/certutil"
)

// config holds all CLI configuration for get-cert.
type config struct {
	AssamURL               string
	AttestationServiceURL  string
	OutPath                string
	KeyPath                string
	KeyOutPath             string
	KeyMode                string
	SAN                    string
	Verbose                bool
	RenewInterval          time.Duration
	ReloadNginx            bool
	ContinueOnInitialError bool
	ReloadWatchPaths       []string
	ReloadWatchInterval    time.Duration
	DiscoveryOutPath       string
	DiscoveryCDSCertURL    string
	DiscoveryMeshCAURL     string
	DiscoveryPublicTLSMode string
}

var (
	errInvalidDiscoveryPublicTLSMode             = errors.New("invalid discovery public TLS mode")
	errInvalidReloadWatchInterval                = errors.New("invalid reload watch interval")
	errReloadWatchRequiresRenewInterval          = errors.New("reload watch requires renew interval")
	errContinueOnInitialErrorRequiresRenewalLoop = errors.New("continue on initial error requires renewal loop")
)

type discoveryDocument struct {
	Version     string               `json:"version"`
	GeneratedAt string               `json:"generated_at"`
	PublicTLS   publicTLSDiscovery   `json:"public_tls"`
	CDSTLS      cdsTLSDiscovery      `json:"cds_tls"`
	Attestation attestationDiscovery `json:"attestation"`
}

type publicTLSDiscovery struct {
	Hostname string `json:"hostname"`
	Mode     string `json:"mode"`
}

type cdsTLSDiscovery struct {
	CertificatePEM    string `json:"certificate_pem"`
	CertificateSHA256 string `json:"certificate_sha256"`
	CertificateURL    string `json:"certificate_url,omitempty"`
	MeshCAURL         string `json:"mesh_ca_url,omitempty"`
}

type attestationDiscovery struct {
	Challenge string          `json:"challenge"`
	Platform  string          `json:"platform"`
	Evidence  json.RawMessage `json:"evidence"`
}

// NewCmd returns the cobra subcommand. It is registered as a child of
// `c8s` and as the root command of the standalone binary.
func NewCmd() *cobra.Command {
	var cfg config

	cmd := &cobra.Command{
		Use:   "get-cert",
		Short: "Obtain a signed certificate via the assam attestation flow",
		Long: `get-cert requests a TLS certificate from a key broker service (assam)
by proving it is running in a Trusted Execution Environment (TEE).

It generates an ECDSA P-256 key pair (or loads the key passed with --key),
creates a CSR with the specified SAN (Subject Alternative Name), and uses
the assam attestation flow to obtain a signed certificate. The P-384 keypair
used elsewhere in c8s is limited to mesh CA rotation; get-cert leaf keys stay
P-256 by default.

This tool is designed to run as a Kubernetes init container or renewal sidecar
alongside a workload that uses the obtained certificate.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			setupLogging(cfg.Verbose)
			return run(cfg)
		},
		SilenceUsage: true,
	}

	flags := cmd.Flags()
	flags.StringVar(&cfg.AssamURL, "assam-url", "", "URL of the assam service (e.g. http://assam:8080)")
	flags.StringVar(&cfg.AttestationServiceURL, "attestation-service-url", "", "URL of the local attestation service (e.g. http://localhost:8400)")
	flags.StringVarP(&cfg.OutPath, "out", "o", "", "Path to write the signed certificate chain PEM (prints to stdout if omitted)")
	flags.StringVar(&cfg.KeyPath, "key", "", "Path to a PEM private key to use for the CSR (generates an ephemeral key if omitted)")
	flags.StringVar(&cfg.KeyOutPath, "key-out", "", "Path to write the generated private key PEM (only used with ephemeral keys)")
	flags.StringVar(&cfg.KeyMode, "key-mode", "0600", "octal mode for generated private key")
	flags.StringVar(&cfg.SAN, "san", "", "Subject Alternative Name for the certificate (IP address or hostname)")
	flags.BoolVarP(&cfg.Verbose, "verbose", "v", false, "Enable debug logging")
	flags.DurationVar(&cfg.RenewInterval, "renew-interval", 0, "Re-obtain the certificate at this interval (0 = run once and exit)")
	flags.BoolVar(&cfg.ReloadNginx, "reload-nginx", true, "SIGHUP nginx after certificate renewal or watched file changes")
	flags.BoolVar(&cfg.ContinueOnInitialError, "continue-on-initial-error", false, "In renewal mode, keep running when the first certificate request fails")
	flags.StringArrayVar(&cfg.ReloadWatchPaths, "reload-watch", nil, "File path to poll for changes and reload nginx when it changes (repeatable)")
	flags.DurationVar(&cfg.ReloadWatchInterval, "reload-watch-interval", time.Minute, "Poll interval for --reload-watch paths")
	flags.StringVar(&cfg.DiscoveryOutPath, "discovery-out", "", "Path to write JSON discovery metadata for the issued certificate and attestation evidence")
	flags.StringVar(&cfg.DiscoveryCDSCertURL, "discovery-cds-cert-url", "", "Public URL path where the CDS certificate PEM is served")
	flags.StringVar(&cfg.DiscoveryMeshCAURL, "discovery-mesh-ca-url", "", "Public URL path where the mesh CA PEM is served")
	flags.StringVar(&cfg.DiscoveryPublicTLSMode, "discovery-public-tls-mode", "cds", "Public TLS mode to report in discovery metadata (cds or webpki)")

	_ = cmd.MarkFlagRequired("assam-url")
	_ = cmd.MarkFlagRequired("attestation-service-url")
	_ = cmd.MarkFlagRequired("san")

	return cmd
}

func setupLogging(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

func run(cfg config) error {
	slog.Info("starting get-cert", "san", cfg.SAN)

	if err := validateConfig(cfg); err != nil {
		return err
	}

	if err := validateOutputPaths(cfg.OutPath, cfg.KeyOutPath, cfg.DiscoveryOutPath); err != nil {
		return err
	}
	slog.Debug("output paths validated")

	client := attestclient.NewClient(cfg.AssamURL)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := obtainCert(ctx, cfg, client); err != nil {
		if cfg.RenewInterval <= 0 || !cfg.ContinueOnInitialError {
			return err
		}
		slog.Error("initial certificate request failed, will retry next interval", "error", err)
	} else if cfg.RenewInterval <= 0 {
		return nil
	}

	// Daemon mode: renew certificate periodically with graceful shutdown.
	slog.Info("entering renewal loop", "interval", cfg.RenewInterval)
	ticker := time.NewTicker(cfg.RenewInterval)
	defer ticker.Stop()

	var watchC <-chan time.Time
	var watchTicker *time.Ticker
	var watchState map[string]fileSnapshot
	if cfg.ReloadNginx && len(cfg.ReloadWatchPaths) > 0 {
		var err error
		watchState, err = snapshotReloadWatchPaths(cfg.ReloadWatchPaths)
		if err != nil {
			return err
		}
		watchTicker = time.NewTicker(cfg.ReloadWatchInterval)
		defer watchTicker.Stop()
		watchC = watchTicker.C
		slog.Info("watching files for nginx reload", "paths", cfg.ReloadWatchPaths, "interval", cfg.ReloadWatchInterval)
	}

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down cert renewer")
			return nil
		case <-ticker.C:
			if err := obtainCert(ctx, cfg, client); err != nil {
				slog.Error("certificate renewal failed, will retry next interval", "error", err)
				continue
			}
			if cfg.ReloadNginx {
				if err := reloadNginx(); err != nil {
					slog.Warn("certificate renewed but nginx reload failed", "error", err)
				}
			}
		case <-watchC:
			changed, nextState, err := reloadWatchChanged(watchState, cfg.ReloadWatchPaths)
			if err != nil {
				slog.Warn("reload watch check failed", "error", err)
				continue
			}
			watchState = nextState
			if !changed {
				continue
			}
			slog.Info("watched file changed, reloading nginx")
			if err := reloadNginx(); err != nil {
				slog.Warn("watched file changed but nginx reload failed", "error", err)
			}
		}
	}
}

func obtainCert(ctx context.Context, cfg config, client attestclient.Client) error {
	privateKey, keyPEM, err := loadOrGenerateKey(cfg.KeyPath)
	if err != nil {
		return err
	}

	csrPEM, err := createCSR(privateKey, cfg.SAN)
	if err != nil {
		return err
	}

	slog.Info("requesting certificate from assam", "assam_url", cfg.AssamURL, "san", cfg.SAN)
	result, err := client.ObtainCertificateWithEvidenceContext(ctx, cfg.AttestationServiceURL, string(csrPEM))
	if err != nil {
		return fmt.Errorf("attestation failed: %w", err)
	}
	slog.Info("certificate obtained")

	return writeOutputs(cfg, keyPEM, result)
}

// reloadNginx sends SIGHUP to the nginx master process to reload certs.
// Requires shareProcessNamespace: true in the pod spec. Walks /proc directly
// instead of shelling out to pgrep so this works in distroless images.
func reloadNginx() error {
	pid, err := findNginxMasterPID()
	if err != nil {
		return err
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("SIGHUP nginx (pid %d): %w", pid, err)
	}
	slog.Info("sent SIGHUP to nginx", "pid", pid)
	return nil
}

// findNginxMasterPID scans /proc for the nginx master process.
// Match: /proc/<pid>/comm == "nginx" AND cmdline contains "master".
func findNginxMasterPID() (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil || strings.TrimSpace(string(comm)) != "nginx" {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		// /proc/<pid>/cmdline is NUL-separated; nginx master argv[0] is
		// "nginx: master process ...".
		if !strings.Contains(string(cmdline), "master") {
			continue
		}
		return pid, nil
	}
	return 0, fmt.Errorf("no nginx master process found")
}

// validateConfig checks that all required configuration is valid.
func validateConfig(cfg config) error {
	if err := cmdsutil.ValidateHTTPURL("--assam-url", cfg.AssamURL); err != nil {
		return err
	}
	if err := cmdsutil.ValidateHTTPURL("--attestation-service-url", cfg.AttestationServiceURL); err != nil {
		return err
	}
	if err := validateSAN(cfg.SAN); err != nil {
		return fmt.Errorf("--san: %w", err)
	}
	if cfg.DiscoveryOutPath != "" {
		switch discoveryPublicTLSMode(cfg.DiscoveryPublicTLSMode) {
		case "cds", "webpki":
		default:
			return fmt.Errorf("%w: --discovery-public-tls-mode must be 'cds' or 'webpki', got %q", errInvalidDiscoveryPublicTLSMode, cfg.DiscoveryPublicTLSMode)
		}
	}
	if len(cfg.ReloadWatchPaths) > 0 {
		if cfg.ReloadWatchInterval <= 0 {
			return fmt.Errorf("%w: --reload-watch-interval must be greater than 0 when --reload-watch is set", errInvalidReloadWatchInterval)
		}
		if cfg.RenewInterval <= 0 {
			return fmt.Errorf("%w: --renew-interval must be greater than 0 when --reload-watch is set", errReloadWatchRequiresRenewInterval)
		}
	}
	if cfg.ContinueOnInitialError && cfg.RenewInterval <= 0 {
		return fmt.Errorf("%w: --continue-on-initial-error requires --renew-interval", errContinueOnInitialErrorRequiresRenewalLoop)
	}
	return nil
}

// hostnameLabelRe matches a valid RFC 1123 hostname label: alphanumeric, hyphens
// allowed in the middle, 1-63 characters.
var hostnameLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// validateSAN checks that a SAN is a valid IP address or RFC 1123 hostname.
func validateSAN(san string) error {
	if san == "" {
		return fmt.Errorf("SAN must not be empty")
	}
	// If it parses as an IP, it's valid.
	if isIPSAN(san) {
		return nil
	}
	if strings.HasPrefix(san, "http://") || strings.HasPrefix(san, "https://") {
		return fmt.Errorf("'%s' looks like a URL, not a hostname - provide just the hostname", san)
	}
	if strings.Contains(san, "*") {
		return fmt.Errorf("'%s' contains a wildcard - wildcards are not supported", san)
	}
	return validateHostname(san)
}

// validateHostname checks that s is a valid RFC 1123 hostname.
func validateHostname(s string) error {
	if len(s) > 253 {
		return fmt.Errorf("'%s' exceeds maximum hostname length of 253 characters", s)
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if !hostnameLabelRe.MatchString(label) {
			return fmt.Errorf("'%s' is not a valid RFC 1123 hostname", s)
		}
	}
	return nil
}

// isIPSAN returns true if the SAN is an IP address.
func isIPSAN(san string) bool {
	return net.ParseIP(san) != nil
}

// validateOutputPaths checks that output file locations are writable before
// doing any expensive work (key generation, attestation). This prevents
// requesting certificates that can't be saved.
func validateOutputPaths(paths ...string) error {
	for _, p := range paths {
		if p == "" {
			continue
		}
		dir := filepath.Dir(p)
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("output directory %q does not exist: %w", dir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("output path parent %q is not a directory", dir)
		}
		// Try creating a temp file to verify write access.
		f, err := os.CreateTemp(dir, ".get-cert-probe-*")
		if err != nil {
			return fmt.Errorf("output directory %q is not writable: %w", dir, err)
		}
		name := f.Name()
		f.Close()
		os.Remove(name)
	}
	return nil
}

// loadOrGenerateKey either reads a key from disk or generates a fresh P-256 key.
func loadOrGenerateKey(keyPath string) (*ecdsa.PrivateKey, []byte, error) {
	if keyPath != "" {
		slog.Debug("loading existing private key", "path", keyPath)
		return loadKey(keyPath)
	}
	slog.Debug("generating ephemeral P-256 key pair")
	return generateKey()
}

func loadKey(path string) (*ecdsa.PrivateKey, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key at %s: %w", path, err)
	}
	key, err := certutil.ParseECPrivateKey(data)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid key at %s: %w", path, err)
	}
	slog.Debug("private key loaded", "curve", key.Curve.Params().Name)
	return key, data, nil
}

func generateKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	slog.Debug("ephemeral P-256 key generated")
	return key, keyPEM, nil
}

// createCSR builds a PEM-encoded certificate signing request with the given SAN.
func createCSR(key *ecdsa.PrivateKey, san string) ([]byte, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{},
	}

	if isIPSAN(san) {
		template.IPAddresses = []net.IP{net.ParseIP(san)}
		slog.Debug("CSR will include IP SAN", "ip", san)
	} else {
		template.DNSNames = []string{san}
		slog.Debug("CSR will include DNS SAN", "hostname", san)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	slog.Debug("CSR created", "san", san, "pem_bytes", len(csrPEM))
	return csrPEM, nil
}

// writeOutputs writes the certificate, key, and optional discovery metadata.
func writeOutputs(cfg config, keyPEM []byte, result attestclient.CertificateResult) error {
	if cfg.KeyOutPath != "" {
		keyMode, err := parseFileMode(cfg.KeyMode)
		if err != nil {
			return fmt.Errorf("--key-mode: %w", err)
		}
		if err := fileutil.WriteAtomic(cfg.KeyOutPath, keyPEM, keyMode); err != nil {
			return fmt.Errorf("failed to write key to %s: %w", cfg.KeyOutPath, err)
		}
		slog.Info("private key written", "path", cfg.KeyOutPath)
	} else if cfg.KeyPath == "" {
		slog.Warn("ephemeral key used but --key-out not set, private key will be lost")
	}

	if cfg.OutPath != "" {
		if err := fileutil.WriteAtomic(cfg.OutPath, []byte(result.Certificate), 0644); err != nil {
			return fmt.Errorf("failed to write cert to %s: %w", cfg.OutPath, err)
		}
		slog.Info("certificate written", "path", cfg.OutPath)
	} else {
		fmt.Print(result.Certificate)
	}

	if cfg.DiscoveryOutPath != "" {
		doc, err := buildDiscoveryDocument(cfg, result)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal discovery metadata: %w", err)
		}
		data = append(data, '\n')
		if err := fileutil.WriteAtomic(cfg.DiscoveryOutPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write discovery metadata to %s: %w", cfg.DiscoveryOutPath, err)
		}
		slog.Info("discovery metadata written", "path", cfg.DiscoveryOutPath)
	}

	return nil
}

func buildDiscoveryDocument(cfg config, result attestclient.CertificateResult) (discoveryDocument, error) {
	cert, err := certutil.ParseCertificatePEM([]byte(result.Certificate))
	if err != nil {
		return discoveryDocument{}, fmt.Errorf("parse issued certificate for discovery: %w", err)
	}
	fingerprint := sha256.Sum256(cert.Raw)

	return discoveryDocument{
		Version:     "v1",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		PublicTLS: publicTLSDiscovery{
			Hostname: cfg.SAN,
			Mode:     discoveryPublicTLSMode(cfg.DiscoveryPublicTLSMode),
		},
		CDSTLS: cdsTLSDiscovery{
			CertificatePEM:    result.Certificate,
			CertificateSHA256: hex.EncodeToString(fingerprint[:]),
			CertificateURL:    cfg.DiscoveryCDSCertURL,
			MeshCAURL:         cfg.DiscoveryMeshCAURL,
		},
		Attestation: attestationDiscovery{
			Challenge: result.Challenge,
			Platform:  result.Platform,
			Evidence:  result.Evidence,
		},
	}, nil
}

func discoveryPublicTLSMode(mode string) string {
	if mode == "" {
		return "cds"
	}
	return mode
}

type fileSnapshot struct {
	size    int64
	modTime time.Time
	sha256  [sha256.Size]byte
}

func snapshotReloadWatchPaths(paths []string) (map[string]fileSnapshot, error) {
	snapshots := make(map[string]fileSnapshot, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat reload watch path %s: %w", path, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("reload watch path %s is a directory", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read reload watch path %s: %w", path, err)
		}
		snapshots[path] = fileSnapshot{
			size:    info.Size(),
			modTime: info.ModTime(),
			sha256:  sha256.Sum256(data),
		}
	}
	return snapshots, nil
}

func reloadWatchChanged(previous map[string]fileSnapshot, paths []string) (bool, map[string]fileSnapshot, error) {
	next, err := snapshotReloadWatchPaths(paths)
	if err != nil {
		return false, nil, err
	}
	for _, path := range paths {
		if previous[path] != next[path] {
			return true, next, nil
		}
	}
	return false, next, nil
}

func parseFileMode(mode string) (os.FileMode, error) {
	if mode == "" {
		return 0, fmt.Errorf("must not be empty")
	}
	parsed, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not an octal mode: %w", mode, err)
	}
	if parsed&^uint64(0777) != 0 {
		return 0, fmt.Errorf("%q sets bits outside file permissions", mode)
	}
	return os.FileMode(parsed), nil
}
