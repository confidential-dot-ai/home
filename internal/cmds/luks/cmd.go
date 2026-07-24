// Package luks implements the `c8s luks` CLI subtree — provision and manage
// openbao-gated LUKS volumes for confidential workloads.
//
// Volumes are backed by:
//
//   - openbao KV v2 at secret/data/<workload>/luks-<name>, {passphrase: <hex>}
//   - one of the drivers: `local` (hostPath-loop-file, dev clusters only) or
//     `pvc` (raw-block PersistentVolumeClaim via kubectl)
//
// The command emits pod annotations (confidential.ai/luks-<name> +
// confidential.ai/secret-<name>) consumed by the c8s webhook. It does NOT
// modify any workload — printing annotations to stdout is the intended UX,
// letting the caller pipe them into kubectl / Helm / their GitOps repo.
package luks

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// NewCmd returns the `c8s luks` parent command.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "luks",
		Short: "Manage openbao-gated LUKS volumes for confidential workloads",
		Long: "luks provisions encrypted volumes and stores their passphrase " +
			"in openbao behind an attestation-gated release policy. Emits the " +
			"pod annotations the c8s webhook expects; does not deploy the " +
			"workload itself.",
	}
	cmd.AddCommand(newCreateCmd())
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newShowCmd())
	cmd.AddCommand(newDestroyCmd())
	return cmd
}

// baoFlags holds the openbao endpoint + auth flags every subcommand shares.
type baoFlags struct {
	Addr          string
	Token         string
	TokenFile     string
	CACert        string
	Timeout       time.Duration
	AllowInsecure bool
}

func (f *baoFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.Addr, "openbao-addr", "",
		"openbao/Vault base URL, e.g. https://c8s-openbao.c8s-system.svc:8200 (required)")
	cmd.Flags().StringVar(&f.Token, "openbao-token", "",
		"openbao token; SUPPLY VIA --openbao-token-file WHENEVER POSSIBLE (this flag lands in shell history and /proc/<pid>/cmdline, readable by any local user)")
	cmd.Flags().StringVar(&f.TokenFile, "openbao-token-file", "",
		"file containing the openbao token")
	cmd.Flags().StringVar(&f.CACert, "openbao-ca-cert", "",
		"PEM file with the CA that signs openbao's TLS cert (e.g. an internal cluster CA)")
	cmd.Flags().DurationVar(&f.Timeout, "openbao-timeout", 15*time.Second,
		"timeout for each openbao API call")
	cmd.Flags().BoolVar(&f.AllowInsecure, "allow-insecure-store", false,
		"permit a plaintext http:// --openbao-addr (dev/test only; token and passphrases transit cleartext)")
}

// client refuses plaintext http unless --allow-insecure-store: the token and
// passphrase transit this connection (cf. internal/cmds/allowlist).
func (f *baoFlags) client() (*bao, error) {
	u, err := url.Parse(f.Addr)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("--openbao-addr %q is not a valid URL (need https://host:port)", f.Addr)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !f.AllowInsecure {
			return nil, errors.New("refusing plaintext http:// for --openbao-addr (token and passphrases would transit cleartext): use https://, or pass --allow-insecure-store for a dev/test endpoint")
		}
		fmt.Fprintln(os.Stderr, "warning: --openbao-addr is http:// with --allow-insecure-store; the openbao token and passphrases transit CLEARTEXT (dev/test only)")
	default:
		return nil, fmt.Errorf("--openbao-addr %q: scheme must be https (or http with --allow-insecure-store)", f.Addr)
	}
	tok := f.Token
	if tok == "" {
		fromFile, err := readTokenFile(f.TokenFile)
		if err != nil {
			return nil, err
		}
		tok = fromFile
	}
	if tok == "" {
		return nil, errors.New("an openbao token is required (--openbao-token-file or --openbao-token)")
	}
	var pool *x509.CertPool
	if f.CACert != "" {
		pem, err := os.ReadFile(f.CACert)
		if err != nil {
			return nil, fmt.Errorf("read --openbao-ca-cert %q: %w", f.CACert, err)
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--openbao-ca-cert %q contains no PEM certificates", f.CACert)
		}
	}
	return newBao(f.Addr, tok, pool, f.Timeout), nil
}
