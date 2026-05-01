// Command cert-issuer is a thin wrapper around the `c8s cert-issuer` cobra
// subcommand.
package main

import (
	"github.com/lunal-dev/c8s/internal/cmds/certissuer"
	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
)

func main() { cmdsutil.RunMain(certissuer.Run) }
