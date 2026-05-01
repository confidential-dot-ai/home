// Command nri-image-policy is a thin wrapper around the
// `c8s nri-image-policy` cobra subcommand.
package main

import (
	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	"github.com/lunal-dev/c8s/internal/cmds/nriimagepolicy"
)

func main() { cmdsutil.RunMain(nriimagepolicy.Run) }
