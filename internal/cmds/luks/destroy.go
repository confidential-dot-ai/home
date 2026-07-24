package luks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func newDestroyCmd() *cobra.Command {
	var (
		bf              baoFlags
		workload, name  string
		driver          string
		force           bool
		localBackingDir string
		namespace       string
	)
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Delete a LUKS volume's openbao entry and backing device",
		Long: "destroy removes the KV entry and the backing device: the loop " +
			"device + backing file for --driver local, the PersistentVolumeClaim " +
			"for --driver pvc. Refuses without --force while the volume looks " +
			"in use (local: backing file attached to a loop device; pvc: a pod " +
			"mounts the claim) — the KV entry is left intact on refusal.",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := bf.client()
			if err != nil {
				return err
			}
			return runDestroy(cmd.Context(), c, destroyCfg{
				workload: workload, name: name, driver: driver,
				force: force, localBackingDir: localBackingDir,
				namespace: namespace,
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
	cmd.Flags().StringVar(&namespace, "namespace", "default",
		"claim namespace for --driver pvc")
	return cmd
}

type destroyCfg struct {
	workload, name  string
	driver          string
	force           bool
	localBackingDir string
	namespace       string
}

func runDestroy(ctx context.Context, c *bao, cfg destroyCfg) error {
	// Validate before anything else — workload/name/namespace feed KV paths
	// and kubectl argv below.
	if err := validateWorkloadName(cfg.workload, cfg.name); err != nil {
		return err
	}
	if err := validateNamespace(cfg.namespace); err != nil {
		return err
	}
	// Order: driver in-use pre-check FIRST (a refused destroy must leave the
	// KV entry intact — deleting the passphrase under a live volume orphans
	// its data at the next open), then the KV delete, then device teardown
	// (so a KV failure doesn't leave an orphaned block device).
	loop := ""
	switch cfg.driver {
	case "local":
		var err error
		if loop, err = losetupLookup(localImgPath(cfg)); err != nil {
			return err
		}
		if loop != "" && !cfg.force {
			return fmt.Errorf("backing file %s is still attached at %s — pass --force to detach and delete anyway", localImgPath(cfg), loop)
		}
	case "pvc":
		users, err := pvcConsumers(ctx, claimName(cfg.workload, cfg.name), cfg.namespace)
		if err != nil {
			return err
		}
		if len(users) > 0 && !cfg.force {
			return fmt.Errorf("PVC %s/%s is mounted by pod(s) %s — pass --force to delete anyway (the claim stays Terminating until they exit)",
				cfg.namespace, claimName(cfg.workload, cfg.name), strings.Join(users, ", "))
		}
	case "csi":
		return errors.New("--driver csi: not yet implemented")
	default:
		return fmt.Errorf("--driver %q: want local | pvc | csi", cfg.driver)
	}

	if err := c.deleteVolume(ctx, cfg.workload, cfg.name); err != nil {
		if isNotFound(err) {
			// Openbao entry gone — still try to clean up the device.
			fmt.Fprintf(os.Stderr, "openbao entry already absent for %s/luks-%s; continuing\n", cfg.workload, cfg.name)
		} else {
			return fmt.Errorf("openbao KV delete: %w", err)
		}
	}

	if cfg.driver == "pvc" {
		return destroyPVC(ctx, cfg)
	}
	return destroyLocal(cfg, loop)
}

func localImgPath(cfg destroyCfg) string {
	return filepath.Join(cfg.localBackingDir, cfg.workload+"-"+cfg.name+".img")
}

func destroyLocal(cfg destroyCfg, loop string) error {
	if loop != "" {
		if err := losetupDetach(loop); err != nil {
			return err
		}
	}
	if err := os.Remove(localImgPath(cfg)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove backing file %s: %w", localImgPath(cfg), err)
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
