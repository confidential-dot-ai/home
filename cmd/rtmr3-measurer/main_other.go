//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "rtmr3-measurer requires Linux (inotify, TDX RTMR sysfs)")
	os.Exit(1)
}
