package main

import "github.com/lunal-dev/c8s/internal/cmds/nodecontainerwhitelist"

func init() {
	rootCmd.AddCommand(wrapFlagBinary(
		"node-container-whitelist [flags]",
		"Serve the NRI image whitelist as JSON over HTTP",
		nodecontainerwhitelist.Run,
	))
}
