package secretbroker

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

func run(cfg config) error {
	logger, err := certutil.NewJSONLogger(cfg.logLevel)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := resolveCredentialFiles(&cfg); err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	policy, err := LoadPolicy(cfg.policyFile)
	if err != nil {
		return err
	}

	store, err := newVaultClient(cfg)
	if err != nil {
		return fmt.Errorf("init openbao client: %w", err)
	}

	tlsCfg, verifier, err := buildServerTLS(cfg)
	if err != nil {
		return err
	}

	tokens := newTokenStore(cfg.tokenTTL)
	go tokens.reap(ctx)

	b := &broker{
		verifier: verifier,
		policy:   policy,
		tokens:   tokens,
		store:    store,
		tokenTTL: cfg.tokenTTL,
	}

	addr := fmt.Sprintf("%s:%d", cfg.host, cfg.port)
	srv := newHTTPServer(addr, newRouter(b, cfg.maxRequestSize), cfg)
	srv.TLSConfig = tlsCfg

	go cmdsutil.ShutdownOnDone(ctx, srv, 5*time.Second)

	logStartup(cfg, addr, len(policy.Rules))
	// Cert/key come from srv.TLSConfig; the empty filename args are intentional.
	if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// resolveCredentialFiles loads file-backed OpenBao credentials into the config
// so secrets can be delivered via a mounted Secret rather than argv.
func resolveCredentialFiles(cfg *config) error {
	if cfg.openbaoTokenFile != "" {
		b, err := os.ReadFile(cfg.openbaoTokenFile)
		if err != nil {
			return fmt.Errorf("--openbao-token-file: %w", err)
		}
		cfg.openbaoToken = strings.TrimSpace(string(b))
	}
	if cfg.openbaoSecretIDFile != "" {
		b, err := os.ReadFile(cfg.openbaoSecretIDFile)
		if err != nil {
			return fmt.Errorf("--openbao-approle-secret-id-file: %w", err)
		}
		cfg.openbaoSecretID = strings.TrimSpace(string(b))
	}
	return nil
}

func validateConfig(cfg config) error {
	// Exactly one store-auth method.
	methods := 0
	if cfg.openbaoToken != "" {
		methods++
	}
	if cfg.openbaoRoleID != "" {
		methods++
	}
	if cfg.openbaoCertAuth {
		methods++
	}
	if methods == 0 {
		return fmt.Errorf("set one of --openbao-token, --openbao-approle-role-id, or --openbao-cert-auth")
	}
	if methods > 1 {
		return fmt.Errorf("--openbao-token, --openbao-approle-role-id, and --openbao-cert-auth are mutually exclusive")
	}
	if cfg.openbaoRoleID != "" && cfg.openbaoSecretID == "" {
		return fmt.Errorf("--openbao-approle-role-id requires --openbao-approle-secret-id")
	}
	if cfg.openbaoCertRole != "" && !cfg.openbaoCertAuth {
		return fmt.Errorf("--openbao-cert-role requires --openbao-cert-auth")
	}
	if cfg.tokenTTL <= 0 {
		return fmt.Errorf("--token-ttl must be positive")
	}
	if cfg.maxRequestSize <= 0 {
		return fmt.Errorf("--max-request-size must be positive")
	}
	if cfg.attestationApiURL != "" {
		if err := cmdsutil.ValidateHTTPURL("--attestation-api-url", cfg.attestationApiURL); err != nil {
			return err
		}
	}
	return nil
}

// logStartup records the effective posture and emits loud warnings for the
// UNSAFE-outside-development configurations (empty store measurement allowlist).
func logStartup(cfg config, addr string, ruleCount int) {
	slog.Info("secret-broker listening (TLS)",
		"addr", addr,
		"openbao_addr", cfg.openbaoAddr,
		"openbao_attested", cfg.openbaoAttested,
		"policy_rules", ruleCount,
	)
	if cfg.openbaoAttested && len(cfg.openbaoMeasurements) == 0 {
		slog.Warn("--openbao-measurements empty: accepting any TEE measurement from the store. UNSAFE outside development.")
	}
	if !cfg.openbaoAttested {
		slog.Warn("--openbao-attested=false: the backing store is outside the trust boundary; the broker is the trust edge.")
	}
}

func newHTTPServer(addr string, handler http.Handler, cfg config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       orDefault(cfg.readTimeout, defaultHTTPReadTimeout),
		ReadHeaderTimeout: orDefault(cfg.readHeaderTimeout, defaultHTTPReadHeaderTimeout),
		WriteTimeout:      orDefault(cfg.writeTimeout, defaultHTTPWriteTimeout),
		IdleTimeout:       orDefault(cfg.idleTimeout, defaultHTTPIdleTimeout),
		MaxHeaderBytes:    orDefaultInt(cfg.maxHeaderBytes, defaultHTTPMaxHeaderBytes),
	}
}

func orDefault(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func orDefaultInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
