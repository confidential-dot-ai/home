package luks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newDestroyCmd() *cobra.Command {
	var (
		bf              baoFlags
		workload, name  string
		driver          string
		force           bool
		localBackingDir string
	)
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Delete a LUKS volume's openbao entry and backing device",
		Long: "destroy removes the KV entry and, for --driver local, the " +
			"loop device + backing file. Refuses without --force if the " +
			"local backing file is currently attached to a loop device — " +
			"that's usually a sign a workload is running against it.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if workload == "" || name == "" {
				return errors.New("--workload and --name are required")
			}
			c, err := bf.client()
			if err != nil {
				return err
			}
			return runDestroy(cmd.Context(), c, destroyCfg{
				workload: workload, name: name, driver: driver,
				force: force, localBackingDir: localBackingDir,
			})
		},
	}
	bf.bind(cmd)
	cmd.Flags().StringVar(&workload, "workload", "", "confidential.ai/cw workload id (required)")
	cmd.Flags().StringVar(&name, "name", "", "volume name (required)")
	cmd.Flags().StringVar(&driver, "driver", "local", "backing driver that provisioned it (local | pvc | csi)")
	cmd.Flags().BoolVar(&force, "force", false, "proceed even if the loop device is still attached")
	cmd.Flags().StringVar(&localBackingDir, "local-dir", "/var/lib/c8s/luks",
		"host directory where the local driver stores backing .img files")
	return cmd
}

type destroyCfg struct {
	workload, name  string
	driver          string
	force           bool
	localBackingDir string
}

func runDestroy(ctx context.Context, c *bao, cfg destroyCfg) error {
	// Order: check-then-delete openbao before touching the disk, so a KV
	// failure doesn't leave the operator with an orphaned block device.
	if err := c.deleteVolume(ctx, cfg.workload, cfg.name); err != nil {
		if isNotFound(err) {
			// Openbao entry gone — still try to clean up local state.
			fmt.Fprintf(os.Stderr, "openbao entry already absent for %s/luks-%s; continuing\n", cfg.workload, cfg.name)
		} else {
			return fmt.Errorf("openbao KV delete: %w", err)
		}
	}
	switch cfg.driver {
	case "local":
		return destroyLocal(cfg)
	case "pvc":
		return errors.New("--driver pvc: not yet implemented")
	case "csi":
		return errors.New("--driver csi: not yet implemented")
	}
	return fmt.Errorf("--driver %q: want local | pvc | csi", cfg.driver)
}

func destroyLocal(cfg destroyCfg) error {
	imgPath := filepath.Join(cfg.localBackingDir, cfg.workload+"-"+cfg.name+".img")
	// Best-effort loop detach — if the file isn't attached, losetup -j returns
	// empty and we skip.
	loop, err := losetupLookup(imgPath)
	if err != nil {
		return err
	}
	if loop != "" {
		if !cfg.force {
			return fmt.Errorf("backing file %s is still attached at %s — pass --force to detach and delete anyway", imgPath, loop)
		}
		if err := losetupDetach(loop); err != nil {
			return err
		}
	}
	if err := os.Remove(imgPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove backing file %s: %w", imgPath, err)
	}
	return nil
}

// losetupLookup returns the loop device backing imgPath, or "" if none.
func losetupLookup(imgPath string) (string, error) {
	out, err := runOutput("losetup", "-j", imgPath)
	if err != nil {
		return "", err
	}
	// Output is empty when no attachment; when attached, first field is the
	// loop device path followed by ":".
	line := trimNewline(out)
	if line == "" {
		return "", nil
	}
	dev, _, ok := cutColon(line)
	if !ok {
		return "", fmt.Errorf("unexpected losetup -j output: %q", line)
	}
	return dev, nil
}
