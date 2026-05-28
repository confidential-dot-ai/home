// Command c8s is the operator-side binary for the confidential Kubernetes
// stack. Subcommands:
//
//   - c8s operator    — controller-manager + admission webhook
//   - c8s install     — client-side: helm install c8s + CRDs
//   - c8s get-cert    — certificate bootstrap and renewal
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lunal-dev/c8s/internal/version"
)

var rootCmd = &cobra.Command{
	Use:   "c8s",
	Short: "Confidential Kubernetes operator and companion CLI",
	Long: `c8s is a single binary that runs the confidential Kubernetes operator,
the per-pod get-cert helpers, and the client-side CLI for installation,
attestation, and day-2 operations.

Typical bootstrap flow on a fresh cluster:

    c8s install             # deploy operator + CRDs + component charts
    kubectl apply -f cwl.yaml

See 'c8s <subcommand> --help' for details.`,
	Version:       version.Version,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func main() {
	normalizeArgvAlias()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func normalizeArgvAlias() {
	base := filepath.Base(os.Args[0])
	for _, alias := range []string{
		"get-cert",
		"nri-image-policy",
		"ratls-mesh",
	} {
		if base == alias || strings.HasSuffix(base, "-"+alias) {
			if len(os.Args) < 2 || os.Args[1] != alias {
				os.Args = append([]string{os.Args[0], alias}, os.Args[1:]...)
			}
			return
		}
	}
}
