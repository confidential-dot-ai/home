package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/luksclose"

func init() {
	rootCmd.AddCommand(luksclose.NewCmd())
}
