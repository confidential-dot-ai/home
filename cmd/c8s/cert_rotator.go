package main

import "github.com/lunal-dev/c8s/internal/cmds/certrotator"

func init() {
	rootCmd.AddCommand(wrapFlagBinary(
		"cert-rotator [flags]",
		"Rotate mesh CA certificates in Kubernetes (CronJob entrypoint)",
		certrotator.Run,
	))
}
