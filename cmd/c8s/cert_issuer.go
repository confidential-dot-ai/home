package main

import "github.com/lunal-dev/c8s/internal/cmds/certissuer"

func init() {
	rootCmd.AddCommand(wrapFlagBinary(
		"cert-issuer [flags]",
		"Run the cert-issuer HTTP signing service",
		certissuer.Run,
	))
}
