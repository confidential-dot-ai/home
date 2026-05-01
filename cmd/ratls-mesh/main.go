// Command ratls-mesh is a thin wrapper around the `c8s ratls-mesh` cobra
// subcommand.
package main

import (
	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	"github.com/lunal-dev/c8s/internal/cmds/ratlsmesh"
)

func main() { cmdsutil.RunMain(ratlsmesh.Run) }
