// Command node-container-whitelist is a thin wrapper around the
// `c8s node-container-whitelist` cobra subcommand. The canonical binary
// is `c8s`; this entrypoint exists for `go build ./cmd/node-container-whitelist`
// dev convenience and as the historical image entrypoint.
package main

import (
	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	cmd "github.com/lunal-dev/c8s/internal/cmds/nodecontainerwhitelist"
)

func main() { cmdsutil.RunMain(cmd.Run) }
