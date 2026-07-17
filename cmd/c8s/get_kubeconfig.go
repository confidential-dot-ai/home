package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/getkubeconfig"

func init() {
	rootCmd.AddCommand(getkubeconfig.NewCmd())
}
