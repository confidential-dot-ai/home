//go:build linux

package main

import "github.com/lunal-dev/c8s/internal/cmds/ratlsmesh"

func init() {
	rootCmd.AddCommand(wrapFlagBinary(
		"ratls-mesh [flags] | ratls-mesh iptables-sync | ratls-mesh iptables-cleanup",
		"Run the RA-TLS L4 mesh proxy or its iptables side commands",
		ratlsmesh.Run,
	))
}
