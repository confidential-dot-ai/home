// Command cert-rotator is a thin wrapper around the `c8s cert-rotator`
// cobra subcommand.
package main

import (
	"github.com/lunal-dev/c8s/internal/cmds/certrotator"
	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
)

func main() { cmdsutil.RunMain(certrotator.Run) }
