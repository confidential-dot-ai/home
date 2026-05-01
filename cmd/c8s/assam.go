package main

import "github.com/lunal-dev/c8s/internal/cmds/assam"

func init() {
	rootCmd.AddCommand(assam.NewCmd())
}
