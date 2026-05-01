//go:build !linux

package ratlsmesh

import "fmt"

func iptablesSetup(_ []string) error {
	return fmt.Errorf("iptables-setup requires Linux")
}

func iptablesCleanup(_ []string) error {
	return fmt.Errorf("iptables-cleanup requires Linux")
}
