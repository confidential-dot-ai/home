package luks

import (
	"context"
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
			"in use (local: a process holds the loop device, or it must be on " +
			"this host at all; pvc: a pod mounts the claim) — the KV entry is " +
			"left intact on refusal. Deleting the KV passphrase is the " +
			"crypto-shred: without it the LUKS data is unrecoverable. Removing " +
			"the backing device is cleanup, not a wipe.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := destroyCfg{
				workload: workload, name: name, driver: driver,
				force: force, localBackingDir: localBackingDir,
				namespace: namespace,
			}
			// Validate before building the client so flag errors are not
			// masked by endpoint errors.
			if err := cfg.validate(); err != nil {
				return err
			}
			c, err := bf.client()
			if err != nil {
				return err
			}
			return runDestroy(cmd.Context(), c, cfg)
		},
	}
	bf.bind(cmd)
	cmd.Flags().StringVar(&workload, "workload", "", "confidential.ai/cw workload id (required)")
	cmd.Flags().StringVar(&name, "name", "", "volume name (required)")
	cmd.Flags().StringVar(&driver, "driver", "local", "backing driver that provisioned it (local | pvc)")
	cmd.Flags().BoolVar(&force, "force", false, "proceed even if the volume looks in use (held loop device / mounted claim)")
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

func (cfg destroyCfg) validate() error {
	if err := validateWorkloadName(cfg.workload, cfg.name); err != nil {
		return err
	}
	return validateNamespace(cfg.namespace)
}

func runDestroy(ctx context.Context, c *bao, cfg destroyCfg) error {
	// Validate before anything else — workload/name/namespace feed KV paths
	// and kubectl argv below.
	if err := cfg.validate(); err != nil {
		return err
	}
	// Order: driver in-use pre-check FIRST (a refused destroy must leave the
	// KV entry intact — deleting the passphrase under a live volume orphans
	// its data at the next open), then the KV delete, then device teardown
	// (so a KV failure doesn't leave an orphaned block device).
	loop, img := "", ""
	switch cfg.driver {
	case "local":
		var err error
		if img, err = localImgPath(cfg.localBackingDir, cfg.workload, cfg.name); err != nil {
			return err
		}
		if loop, err = losetupLookup(img); err != nil {
			return err
		}
		if loop == "" && !cfg.force {
			// No attachment here; if the backing file is gone too, this host
			// simply isn't where the volume was provisioned — refuse rather
			// than silently shred a live volume on another node (or, with
			// --driver local against a pvc volume, in the cluster). --force
			// overrides: a decommissioned node's KV entry must stay deletable.
			if _, statErr := os.Stat(img); os.IsNotExist(statErr) {
				return fmt.Errorf("no loop attachment or backing file %s on this host — the volume was not provisioned here (wrong node? wrong --driver?); refusing to delete the KV passphrase", img)
			}
		} else if loop != "" && !cfg.force {
			users, err := loopUsers(loop)
			if err != nil {
				return err
			}
			if len(users) > 0 {
				return fmt.Errorf("loop device %s for %s is in use (%s) — stop the consumer, or pass --force to destroy anyway", loop, img, strings.Join(users, ", "))
			}
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
	default:
		return fmt.Errorf("--driver %q: want local | pvc", cfg.driver)
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
		if err := destroyPVC(ctx, cfg); err != nil {
			return err
		}
	} else if err := destroyLocal(loop, img); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "destroyed %s/luks-%s: KV passphrase deleted (crypto-shred), backing storage released\n", cfg.workload, cfg.name)
	return nil
}

// localImgPath builds the backing-file path, refusing a --local-dir that is
// not absolute+clean or a result outside it (cf. cmd/c8s/uninstall.go
// validateSweepPath).
func localImgPath(dir, workload, name string) (string, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return "", fmt.Errorf("--local-dir %q must be an absolute, clean path", dir)
	}
	p := filepath.Join(dir, workload+"-"+name+".img")
	if filepath.Dir(p) != dir {
		return "", fmt.Errorf("backing file path %q escapes --local-dir %q", p, dir)
	}
	return p, nil
}

func destroyLocal(loop, imgPath string) error {
	if loop != "" {
		if err := losetupDetach(loop); err != nil {
			return err
		}
	}
	if err := os.Remove(imgPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove backing file %s: %w", imgPath, err)
	}
	return nil
}

// loopUsers reports what holds dev: kernel holders (host-side dm-crypt
// mappings) plus any process with the device open. The designed consumer is
// a kata VMM holding a plain userspace fd — that creates no sysfs holder
// entry, and since kernel 3.7 a busy losetup -d succeeds via autoclear, so
// neither holders nor detach-EBUSY can see it. Scanning /proc is the only
// honest signal. See docs/pitfalls.md — loop in-use detection.
func loopUsers(dev string) ([]string, error) {
	var users []string
	holders, err := os.ReadDir(filepath.Join("/sys/block", filepath.Base(dev), "holders"))
	if err != nil {
		return nil, fmt.Errorf("check holders of %s: %w", dev, err)
	}
	for _, h := range holders {
		users = append(users, "kernel mapping "+h.Name())
	}
	pids, err := fdHolders(dev)
	if err != nil {
		return nil, err
	}
	for _, pid := range pids {
		users = append(users, "pid "+pid)
	}
	return users, nil
}

// fdHolders returns the pids of processes with dev open, via /proc/*/fd.
// Requires root (the CLI already needs it for losetup/cryptsetup); pids
// whose fd dir is unreadable are skipped.
func fdHolders(dev string) ([]string, error) {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("scan /proc for holders of %s: %w", dev, err)
	}
	var out []string
	for _, p := range procs {
		if p.Name()[0] < '0' || p.Name()[0] > '9' {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", p.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join("/proc", p.Name(), "fd", fd.Name()))
			if err == nil && target == dev {
				out = append(out, p.Name())
				break
			}
		}
	}
	return out, nil
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
