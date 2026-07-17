package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"

func init() {
	rootCmd.AddCommand(credrelease.NewCmd())
}
