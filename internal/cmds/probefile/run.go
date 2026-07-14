// Package probefile implements the probe-file subcommand: a tiny file-existence
// helper for distroless containers. gcr.io/distroless/static has no shell or
// coreutils, so waiting for a file to appear has no `test -s` available.
//
// It runs in two shapes:
//   - one-shot (default): exit 0 if the path exists and is non-empty, for a
//     kubelet exec probe.
//   - --wait: block until the path passes (or --timeout elapses), for use as
//     the entrypoint of a plain init container that gates a workload on the
//     initial cert. The locked kata-qemu-snp guest denies ExecProcessRequest,
//     so an exec probe can never pass there; a container waiting on its own is
//     CreateContainerRequest, which the guest allows. See
//     internal/webhook/pod_mutator.go (certWaitContainer).
package probefile

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// NewCmd returns the cobra subcommand. Registered as a child of `c8s`.
func NewCmd() *cobra.Command {
	var (
		wait     bool
		timeout  time.Duration
		interval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "probe-file <path>",
		Short: "Exit 0 if <path> exists and is non-empty",
		Long: `probe-file is a file-existence helper for distroless containers,
where /bin/test is not available. It exits 0 when <path> exists and is
non-empty, and non-zero otherwise.

With --wait it blocks until <path> passes the check (or --timeout elapses),
so it can be the entrypoint of an init container that gates a workload on a
file another container writes — the exec-free equivalent of a startup probe,
needed on locked kata guests where exec probes are denied by policy.

The non-empty check rules out passing on a half-written file. Writers of files
probed this way should still use atomic rename (write to a temp file and
rename into place) so the probe never sees a torn write.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if !wait {
				return probe(args[0])
			}
			return waitFor(args[0], interval, timeout)
		},
	}
	cmd.Flags().BoolVar(&wait, "wait", false, "block until <path> passes the check instead of probing once")
	cmd.Flags().DurationVar(&interval, "poll-interval", time.Second, "how often to re-check <path> in --wait mode")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "give up (non-zero exit) after this long in --wait mode; 0 waits forever")
	return cmd
}

func probe(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s: does not exist", path)
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s: is a directory", path)
	}
	if info.Size() == 0 {
		return fmt.Errorf("%s: empty", path)
	}
	return nil
}

// waitFor blocks until path passes probe, or returns an error once timeout
// elapses (timeout <= 0 waits forever). It fails closed: the caller container
// only exits 0 — releasing the workload it gates — once the file is present.
func waitFor(path string, interval, timeout time.Duration) error {
	if interval <= 0 {
		interval = time.Second
	}
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		if err := probe(path); err == nil {
			return nil
		} else if timeout > 0 && time.Now().After(deadline) {
			return fmt.Errorf("%s: not ready after %s: %w", path, timeout, err)
		}
		time.Sleep(interval)
	}
}
