package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/luksopen"

func init() {
	rootCmd.AddCommand(luksopen.NewCmd())
}
