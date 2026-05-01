// Command get-cert is a thin wrapper around the `c8s get-cert` cobra
// subcommand for `go build ./cmd/get-cert` users and the historical image
// entrypoint.
package main

import (
	"os"

	"github.com/lunal-dev/c8s/internal/cmds/getcert"
)

func main() {
	if err := getcert.NewCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
