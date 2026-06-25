package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/cdsattest"

func init() {
	rootCmd.AddCommand(cdsattest.NewCmd())
}
