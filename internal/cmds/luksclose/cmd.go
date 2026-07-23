// Package luksclose implements `c8s luks-close`: unmount each named LUKS
// volume and close its dm-crypt mapper. Runs from the injected c8s-luks-open
// container's preStop hook so the mapper + loop device are freed on graceful
// pod termination — the counterpart to `c8s luks-open`. See docs/pitfalls.md
// — LUKS leak.
//
// Best-effort by design: a failure on one volume must not stop the rest, and
// a mapper that is already gone (a prior close, kata guest disposal) is not an
// error. The preStop hook has grace-period seconds to complete; loud failure
// would delay pod deletion without cleaning up anything.
package luksclose

import (
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/devmapper"
)

// NewCmd returns the cobra subcommand.
func NewCmd() *cobra.Command {
	var cfg Config
	cmd := &cobra.Command{
		Use:   "luks-close",
		Short: "Unmount and close LUKS volumes opened by `c8s luks-open`",
		Long: "luks-close is the counterpart to luks-open. For each --volume it " +
			"unmounts <mount-root>/<name> and closes the /dev/mapper/c8s-<name> " +
			"mapper. Best-effort: a missing mount or mapper is not an error.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Run(cfg)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&cfg.MountRoot, "mount-root", "/c8s-luks",
		"parent directory volumes were mounted under (mirrors luks-open)")
	flags.StringSliceVar(&cfg.Names, "volume", nil,
		"volume name, repeatable (mirrors the --volume=<name>=… form's name)")
	return cmd
}

// Config is the parsed CLI shape. Exposed for tests.
type Config struct {
	MountRoot string
	Names     []string
}

// Run is the entry point tests exercise directly.
func Run(cfg Config) error {
	if len(cfg.Names) == 0 {
		return errors.New("no --volume names supplied")
	}
	var firstErr error
	for _, name := range cfg.Names {
		if err := closeOne(cfg, name); err != nil {
			slog.Error("luks-close: volume close failed", "name", name, "error", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		slog.Info("luks-close: volume closed", "name", name)
	}
	return firstErr
}

// closeOne unmounts then removes one volume's mapper. Missing mount/mapper are
// treated as no-ops (idempotent) so retries and races (concurrent NRI reap)
// don't turn into errors.
func closeOne(cfg Config, name string) error {
	mountPoint := filepath.Join(cfg.MountRoot, name)
	if err := unmountIfMounted(mountPoint); err != nil {
		return fmt.Errorf("unmount %s: %w", mountPoint, err)
	}
	mapperName := "c8s-" + name
	if err := devmapper.Remove(mapperName); err != nil {
		if errors.Is(err, devmapper.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("dm remove %s: %w", mapperName, err)
	}
	return nil
}

// unmountIfMounted returns nil when the path is already unmounted. Delegates to
// umount(8) rather than the umount2 syscall so the container's existing
// util-linux is enough — no need to add a syscall dependency for this one path.
func unmountIfMounted(path string) error {
	if mounted, err := isMounted(path); err != nil {
		return err
	} else if !mounted {
		return nil
	}
	out, err := exec.Command("umount", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("umount %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isMounted reuses the same /proc/self/mountinfo parse luksopen does — kept
// local to keep luksclose an isolated leaf (no import cycle risk).
func isMounted(path string) (bool, error) {
	return procMountinfoContains(path)
}
