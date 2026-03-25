package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lunal-dev/c8s/pkg/attestclient"
)

// Config holds all CLI configuration for get-cert.
type Config struct {
	AssamURL                 string
	AttestationServiceURL    string
	AttestationServiceAPIKey string
	OutPath                  string
	KeyPath                  string
	KeyOutPath               string
	SAN                      string
	Verbose                  bool
}

func main() {
	var cfg Config

	rootCmd := &cobra.Command{
		Use:   "get-cert",
		Short: "Obtain a signed certificate via the assam attestation flow",
		Long: `get-cert requests a TLS certificate from a key broker service (assam)
by proving it is running in a Trusted Execution Environment (TEE).

It generates (or loads) an ECDSA P-256 key pair, creates a CSR with the
specified SAN (Subject Alternative Name), and uses the assam attestation
flow to obtain a signed certificate.

This tool is designed to run as a Kubernetes init-container alongside a
load balancer (e.g. nginx) that terminates TLS with the obtained certificate.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			setupLogging(cfg.Verbose)
			return run(cfg)
		},
		SilenceUsage: true,
	}

	flags := rootCmd.Flags()
	flags.StringVar(&cfg.AssamURL, "assam-url", "", "URL of the assam service (e.g. http://assam:8080)")
	flags.StringVar(&cfg.AttestationServiceURL, "attestation-service-url", "", "URL of the local attestation service (e.g. http://localhost:8400)")
	flags.StringVar(&cfg.AttestationServiceAPIKey, "attestation-service-api-key", "", "API key for the attestation service (required when running in remote mode)")
	flags.StringVarP(&cfg.OutPath, "out", "o", "", "Path to write the signed certificate PEM (prints to stdout if omitted)")
	flags.StringVar(&cfg.KeyPath, "key", "", "Path to a PEM private key to use for the CSR (generates an ephemeral key if omitted)")
	flags.StringVar(&cfg.KeyOutPath, "key-out", "", "Path to write the generated private key PEM (only used with ephemeral keys)")
	flags.StringVar(&cfg.SAN, "san", "", "Subject Alternative Name for the certificate (IP address or hostname)")
	flags.BoolVarP(&cfg.Verbose, "verbose", "v", false, "Enable debug logging")

	rootCmd.MarkFlagRequired("assam-url")
	rootCmd.MarkFlagRequired("attestation-service-url")
	rootCmd.MarkFlagRequired("san")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func setupLogging(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}

func run(cfg Config) error {
	slog.Info("starting get-cert", "san", cfg.SAN)

	if err := validateConfig(cfg); err != nil {
		return err
	}

	// Validate output paths are writable before doing any real work.
	if err := validateOutputPaths(cfg.OutPath, cfg.KeyOutPath); err != nil {
		return err
	}
	slog.Debug("output paths validated")

	privateKey, keyPEM, err := loadOrGenerateKey(cfg.KeyPath)
	if err != nil {
		return err
	}

	csrPEM, err := createCSR(privateKey, cfg.SAN)
	if err != nil {
		return err
	}

	slog.Info("requesting certificate from assam", "assam_url", cfg.AssamURL, "san", cfg.SAN)
	client := attestclient.NewClientWithAPIKey(cfg.AssamURL, cfg.AttestationServiceAPIKey)
	certPEM, err := client.ObtainCertificate(cfg.AttestationServiceURL, string(csrPEM))
	if err != nil {
		return fmt.Errorf("attestation failed: %w", err)
	}
	slog.Info("certificate obtained successfully")

	return writeOutputs(cfg, keyPEM, certPEM)
}

// validateConfig checks that all required configuration is valid.
func validateConfig(cfg Config) error {
	if err := validateURL(cfg.AssamURL); err != nil {
		return fmt.Errorf("--assam-url: %w", err)
	}
	if err := validateURL(cfg.AttestationServiceURL); err != nil {
		return fmt.Errorf("--attestation-service-url: %w", err)
	}
	if err := validateSAN(cfg.SAN); err != nil {
		return fmt.Errorf("--san: %w", err)
	}
	return nil
}

// validateURL checks that a string looks like an HTTP(S) URL.
func validateURL(u string) error {
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("'%s' is not a valid URL - must start with http:// or https://", u)
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
func validateOutputPaths(certPath, keyPath string) error {
	for _, p := range []string{certPath, keyPath} {
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
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("invalid key: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("invalid key: not an EC key")
	}
	slog.Debug("private key loaded", "curve", ecKey.Curve.Params().Name)
	return ecKey, data, nil
}

func generateKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})
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

// writeOutputs writes the certificate and key to their respective paths.
func writeOutputs(cfg Config, keyPEM []byte, certPEM string) error {
	if cfg.KeyOutPath != "" {
		if err := os.WriteFile(cfg.KeyOutPath, keyPEM, 0600); err != nil {
			return fmt.Errorf("failed to write key to %s: %w", cfg.KeyOutPath, err)
		}
		slog.Info("private key written", "path", cfg.KeyOutPath)
	} else if cfg.KeyPath == "" {
		slog.Warn("ephemeral key used but --key-out not set, private key will be lost")
	}

	if cfg.OutPath != "" {
		if err := os.WriteFile(cfg.OutPath, []byte(certPEM), 0644); err != nil {
			return fmt.Errorf("failed to write cert to %s: %w", cfg.OutPath, err)
		}
		slog.Info("certificate written", "path", cfg.OutPath)
	} else {
		fmt.Print(certPEM)
	}

	return nil
}
