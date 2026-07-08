//go:build linux

// Command rtmr3-measurer is the thin wrapper around the c8s rtmr3-measurer
// entry point (mirrors cmd/policy-monitor/main.go). Baked into the
// kata-guest-tdx rootfs; extends TDX RTMR[3] with each deployed workload's
// image digest. Coexists with policy-monitor (allowlist enforcement).
package main

import (
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/rtmr3measurer"
)

func main() { cmdsutil.RunMain(rtmr3measurer.Run) }
