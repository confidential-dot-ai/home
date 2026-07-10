package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/luks"

func init() {
	rootCmd.AddCommand(luks.NewCmd())
}
