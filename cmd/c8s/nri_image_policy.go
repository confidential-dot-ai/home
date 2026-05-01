package main

import "github.com/lunal-dev/c8s/internal/cmds/nriimagepolicy"

func init() {
	rootCmd.AddCommand(wrapFlagBinary(
		"nri-image-policy [flags]",
		"Run the NRI image-policy plugin",
		nriimagepolicy.Run,
	))
}
