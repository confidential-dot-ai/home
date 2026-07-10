// Package luksopen implements the `c8s luks-open` subcommand: read an
// openbao-issued passphrase, luksOpen the corresponding block device, mount
// the decrypted filesystem into a per-pod emptyDir the app container
// consumes. Runs once per pod as an init container, then exits.
//
// It does not manage lifecycle — the mapper and mount are torn down by
// containerd when the pod is destroyed (the mount is on an emptyDir, and
// the mapper node is on /dev which is a hostPath but scoped to the pod's
// mount namespace only when kata is off; under kata everything is inside
// the guest, which is disposed with the pod).
package luksopen

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// NewCmd returns the cobra subcommand.
func NewCmd() *cobra.Command {
	var cfg Config
	cmd := &cobra.Command{
		Use:   "luks-open",
		Short: "Open openbao-gated LUKS volumes and mount them for the workload",
		Long: "luks-open reads passphrases templated by the injected Vault Agent " +
			"and calls cryptsetup luksOpen for each requested volume, then mounts " +
			"the decrypted filesystem under --mount-root/<name>. Runs once as an " +
			"init container and exits when every volume is open and mounted.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return Run(cfg)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&cfg.SecretsDir, "secrets-dir", "/vault/secrets",
		"directory the injected Vault Agent templates passphrases into (one file per volume)")
	flags.StringVar(&cfg.MountRoot, "mount-root", "/c8s-luks",
		"parent directory for per-volume mountpoints; each volume mounts at <mount-root>/<name>")
	flags.StringSliceVar(&cfg.VolumeSpecs, "volume", nil,
		"volume spec, repeatable: <name>=<dev>:<secretName>:<fstype>:<mode> (mode = open | format-if-empty)")
	return cmd
}

// Config is the parsed CLI shape. Exposed for tests.
type Config struct {
	SecretsDir  string
	MountRoot   string
	VolumeSpecs []string
}

// Volume is a parsed --volume=… flag.
type Volume struct {
	Name       string
	Dev        string // /dev/vdb
	SecretName string // filename under SecretsDir
	FSType     string
	Mode       string // "open" | "format-if-empty"
}

// Run is the entry point tests exercise directly.
func Run(cfg Config) error {
	vols, err := ParseVolumeSpecs(cfg.VolumeSpecs)
	if err != nil {
		return err
	}
	if len(vols) == 0 {
		return errors.New("no --volume specs supplied")
	}
	for _, v := range vols {
		if err := openOne(cfg, v); err != nil {
			return fmt.Errorf("volume %q: %w", v.Name, err)
		}
	}
	slog.Info("luks-open: all volumes opened and mounted", "count", len(vols))
	return nil
}

// ParseVolumeSpecs parses each spec of form
// <name>=<dev>:<secretName>:<fstype>:<mode>.
func ParseVolumeSpecs(specs []string) ([]Volume, error) {
	out := make([]Volume, 0, len(specs))
	for _, s := range specs {
		name, rest, ok := strings.Cut(s, "=")
		if !ok || name == "" || rest == "" {
			return nil, fmt.Errorf("--volume=%q: want <name>=<dev>:<secretName>:<fstype>:<mode>", s)
		}
		parts := strings.Split(rest, ":")
		if len(parts) != 4 {
			return nil, fmt.Errorf("--volume=%q: want 4 colon-separated fields, got %d", s, len(parts))
		}
		v := Volume{Name: name, Dev: parts[0], SecretName: parts[1], FSType: parts[2], Mode: parts[3]}
		if v.Dev == "" || v.SecretName == "" || v.FSType == "" {
			return nil, fmt.Errorf("--volume=%q: dev/secretName/fstype must be non-empty", s)
		}
		if v.Mode != "open" && v.Mode != "format-if-empty" {
			return nil, fmt.Errorf("--volume=%q: mode must be open or format-if-empty", s)
		}
		out = append(out, v)
	}
	return out, nil
}

func openOne(cfg Config, v Volume) error {
	passphrasePath := filepath.Join(cfg.SecretsDir, v.SecretName)
	passphrase, err := os.ReadFile(passphrasePath)
	if err != nil {
		return fmt.Errorf("read passphrase %s: %w", passphrasePath, err)
	}
	if len(passphrase) == 0 {
		return fmt.Errorf("passphrase file %s is empty", passphrasePath)
	}
	// cryptsetup accepts a trailing newline but reads the whole file as the
	// passphrase — templated files often end with a newline, so strip it.
	passphrase = trimTrailingNewline(passphrase)

	mapperName := "c8s-" + v.Name
	mapperPath := "/dev/mapper/" + mapperName
	mountPoint := filepath.Join(cfg.MountRoot, v.Name)

	// Idempotency: if the mount already exists (a previous init pass on a
	// pod restart), do nothing. cryptsetup + mkfs + mount are all destructive
	// operations we don't want to re-run.
	if mounted, err := isMounted(mountPoint); err != nil {
		return fmt.Errorf("check mount %s: %w", mountPoint, err)
	} else if mounted {
		slog.Info("luks-open: already mounted, skipping", "name", v.Name, "mount", mountPoint)
		return nil
	}

	isLUKS, err := runCryptsetupCheck("isLuks", v.Dev)
	if err != nil {
		return err
	}
	if !isLUKS {
		if v.Mode != "format-if-empty" {
			return fmt.Errorf("device %s is not LUKS-formatted and mode=%s (use mode=format-if-empty to init on first use)", v.Dev, v.Mode)
		}
		slog.Info("luks-open: formatting device", "dev", v.Dev)
		if err := runCryptsetup(passphrase, "luksFormat", "--batch-mode", v.Dev); err != nil {
			return fmt.Errorf("luksFormat %s: %w", v.Dev, err)
		}
	}

	if _, err := os.Stat(mapperPath); os.IsNotExist(err) {
		if err := runCryptsetup(passphrase, "luksOpen", v.Dev, mapperName); err != nil {
			return fmt.Errorf("luksOpen %s: %w", v.Dev, err)
		}
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", mapperPath, err)
	}

	// If we just formatted the device, mkfs the mapper. Detect a fresh mapper
	// by asking blkid for a filesystem signature; empty = needs mkfs.
	needsMkfs, err := mapperNeedsMkfs(mapperPath)
	if err != nil {
		return err
	}
	if needsMkfs {
		if v.Mode != "format-if-empty" {
			return fmt.Errorf("LUKS mapper %s has no filesystem and mode=%s", mapperPath, v.Mode)
		}
		slog.Info("luks-open: mkfs on empty mapper", "mapper", mapperPath, "fstype", v.FSType)
		if err := mkfs(v.FSType, mapperPath); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", mountPoint, err)
	}
	if err := mount(v.FSType, mapperPath, mountPoint); err != nil {
		return err
	}
	slog.Info("luks-open: opened and mounted", "name", v.Name, "dev", v.Dev, "mount", mountPoint)
	return nil
}

// --- process helpers (exec.LookPath fallbacks) ---

func runCryptsetup(passphrase []byte, args ...string) error {
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = bytesReader(passphrase)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cryptsetup %s: %w: %s", strings.Join(args, " "), err, string(out))
	}
	return nil
}

// runCryptsetupCheck runs `cryptsetup <cmd> <dev>` and treats exit 0 as true,
// non-zero as false (used for isLuks). Only non-zero exit codes are treated
// as "false" — an exec error (binary missing) is a real error.
func runCryptsetupCheck(sub, dev string) (bool, error) {
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		return false, fmt.Errorf("cryptsetup not on PATH: %w", err)
	}
	cmd := exec.Command("cryptsetup", sub, dev)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return false, nil
		}
		return false, fmt.Errorf("cryptsetup %s %s: %w", sub, dev, err)
	}
	return true, nil
}

func mapperNeedsMkfs(mapperPath string) (bool, error) {
	if _, err := exec.LookPath("blkid"); err != nil {
		// Fall back to conservative "no": if we can't check, don't destroy.
		return false, nil
	}
	cmd := exec.Command("blkid", "-o", "value", "-s", "TYPE", mapperPath)
	out, err := cmd.Output()
	if err != nil {
		// blkid exit 2 == no signature. Anything else is unusual; log and
		// treat as "has fs" to be safe.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			return true, nil
		}
		return false, nil
	}
	return strings.TrimSpace(string(out)) == "", nil
}

func mkfs(fstype, dev string) error {
	binary := "mkfs." + fstype
	if _, err := exec.LookPath(binary); err != nil {
		return fmt.Errorf("mkfs binary %s not on PATH: %w", binary, err)
	}
	cmd := exec.Command(binary, "-q", dev)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", binary, dev, err, string(out))
	}
	return nil
}

func mount(fstype, src, dst string) error {
	cmd := exec.Command("mount", "-t", fstype, src, dst)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount -t %s %s %s: %w: %s", fstype, src, dst, err, string(out))
	}
	return nil
}

func isMounted(path string) (bool, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	// Each line's 5th field (0-indexed: 4) is the mountpoint.
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[4] == path {
			return true, nil
		}
	}
	return false, nil
}

func trimTrailingNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// small helper so we don't pull bytes/reader tricks inline
func bytesReader(b []byte) *strings.Reader { return strings.NewReader(string(b)) }
