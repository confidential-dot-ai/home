// Package luks implements the `c8s luks` CLI subtree — provision and manage
// openbao-gated LUKS volumes for confidential workloads.
//
// Volumes are backed by:
//
//   - openbao KV v2 at secret/data/<workload>/luks-<name>, {passphrase: <hex>}
//   - one of the pluggable "drivers" (Stage 6 ships `local` for a
//     hostPath-loop-file dev-cluster path; `pvc` and `csi` come later).
//
// The command emits pod annotations (confidential.ai/luks-<name> +
// confidential.ai/secret-<name>) matching Stage 5's parser. It does NOT
// modify any workload — printing annotations to stdout is the intended UX,
// letting the caller pipe them into kubectl / Helm / their GitOps repo.
package luks

import (
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

// NewCmd returns the `c8s luks` parent command.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "luks",
		Short: "Manage openbao-gated LUKS volumes for confidential workloads",
		Long: "luks provisions encrypted volumes and stores their passphrase " +
			"in openbao behind an attestation-gated release policy. Emits the " +
			"pod annotations the c8s webhook (Stage 5) expects; does not " +
			"deploy the workload itself.",
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
	AllowInsecure bool
}

func (f *baoFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.Addr, "openbao-addr", "",
		"openbao/Vault base URL, e.g. https://c8s-openbao.c8s-system.svc:8200 (required)")
	cmd.Flags().StringVar(&f.Token, "openbao-token", "",
		"openbao token; SUPPLY VIA --openbao-token-file WHENEVER POSSIBLE (this flag lands in shell history)")
	cmd.Flags().StringVar(&f.TokenFile, "openbao-token-file", "",
		"file containing the openbao token")
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
	return newBao(f.Addr, tok), nil
}
