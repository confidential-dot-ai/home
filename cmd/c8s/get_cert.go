package main

import "github.com/lunal-dev/c8s/internal/cmds/getcert"

func init() {
	rootCmd.AddCommand(getcert.NewCmd())
}
