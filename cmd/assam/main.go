// Command assam is a thin wrapper around the `c8s assam` cobra subcommand.
package main

import (
	"os"

	"github.com/lunal-dev/c8s/internal/cmds/assam"
)

func main() {
	if err := assam.NewCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
