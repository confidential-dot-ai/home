// Command c8s is the operator-side binary for the confidential Kubernetes
// stack. Subcommands:
//
//   - c8s operator    — controller-manager + admission webhook
//   - c8s install     — client-side: helm install c8s + CRDs
//   - c8s get-cert    — init-container certificate bootstrap
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/lunal-dev/c8s/internal/version"
)

var rootCmd = &cobra.Command{
	Use:   "c8s",
	Short: "Confidential Kubernetes operator and companion CLI",
	Long: `c8s is a single binary that runs the confidential Kubernetes operator,
the per-pod init-container helpers, and the client-side CLI for installation,
attestation, and day-2 operations.

Typical bootstrap flow on a fresh cluster:

    c8s install             # deploy operator + CRDs + node-labeler
    kubectl apply -f cwl.yaml

See 'c8s <subcommand> --help' for details.`,
	Version:       version.Version,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
