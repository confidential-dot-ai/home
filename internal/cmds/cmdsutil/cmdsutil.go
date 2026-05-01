// Package cmdsutil holds tiny helpers shared across the c8s subcommand
// packages under internal/cmds/. Anything bigger belongs in pkg/.
package cmdsutil

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// RunMain is the body of the per-binary thin shim under cmd/<name>/main.go.
// It calls run with os.Args[1:], prints any error to stderr, and exits with
// status 1 on failure. Each shim collapses to: cmdsutil.RunMain(pkg.Run).
func RunMain(run func([]string) error) {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ValidateHTTPURL returns an error if u is not an http:// or https:// URL.
// The flagName is interpolated into the error so callers needn't wrap.
func ValidateHTTPURL(flagName, u string) error {
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("%s %q must start with http:// or https://", flagName, u)
	}
	return nil
}

// ParseFlags is the standard fs.Parse(args) call used by every Run-style
// subcommand. Help output is redirected to stdout so `c8s <name> --help`
// matches the cobra convention. The returned flag.ErrHelp must still bubble
// up so callers stop before running post-parse validation/startup.
func ParseFlags(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(os.Stdout)
	return fs.Parse(args)
}
