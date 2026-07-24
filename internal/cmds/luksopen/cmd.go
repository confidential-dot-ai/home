// Package luksopen implements the `c8s luks-open` subcommand: read an
// openbao-issued passphrase, luksOpen the corresponding block device, mount
// the decrypted filesystem into a per-pod emptyDir the app container
// consumes. Runs once per pod as an init container, then exits.
//
// Mapper names are per-pod — c8s-<podUID>-<name>, with the pod UID taken from
// the downward-API C8S_POD_UID env the webhook injects — so two pods can never
// collide on, or adopt, each other's mappers. Nothing here tears a mapper down
// when its pod goes away; that closure is the LUKS teardown work
// (feat/luks-teardown: NRI reaper + luks-close).
package luksopen

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/luksfs"
)

// podUIDEnv carries the pod UID (downward API, injected by the webhook) the
// per-pod mapper names are derived from.
const podUIDEnv = "C8S_POD_UID"

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
	podUID := os.Getenv(podUIDEnv)
	if podUID == "" {
		return fmt.Errorf("%s is not set (the webhook injects it via the downward API); cannot derive per-pod mapper names", podUIDEnv)
	}
	for _, v := range vols {
		if err := openOne(cfg, podUID, v); err != nil {
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
		// Defense in depth — the webhook already rejects these at admission.
		if !luksfs.Allowed(v.FSType) {
			return nil, fmt.Errorf("--volume=%q: unsupported fstype %q", s, v.FSType)
		}
		out = append(out, v)
	}
	return out, nil
}

func openOne(cfg Config, podUID string, v Volume) error {
	passphrasePath := filepath.Join(cfg.SecretsDir, v.SecretName)
	passphrase, err := os.ReadFile(passphrasePath)
	if err != nil {
		return fmt.Errorf("read passphrase %s: %w", passphrasePath, err)
	}
	// cryptsetup accepts a trailing newline but reads the whole file as the
	// passphrase — templated files often end with a newline, so strip it.
	passphrase = trimTrailingNewline(passphrase)
	if len(passphrase) == 0 {
		return fmt.Errorf("passphrase file %s is empty", passphrasePath)
	}

	mapperName := "c8s-" + podUID + "-" + v.Name
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
		// Even in format-if-empty, only format a device that carries no
		// signature at all: an existing filesystem or partition table means
		// the annotation points at the wrong device.
		blank, err := devBlank(v.Dev)
		if err != nil {
			return err
		}
		if !blank {
			return fmt.Errorf("device %s is not LUKS but carries an existing filesystem/partition-table signature; refusing to luksFormat it", v.Dev)
		}
		slog.Info("luks-open: formatting device", "dev", v.Dev)
		if err := runCryptsetup(passphrase, "luksFormat", "--batch-mode", v.Dev); err != nil {
			return fmt.Errorf("luksFormat %s: %w", v.Dev, err)
		}
	}

	if _, err := statMapper(mapperPath); err == nil {
		// The mapper already exists — legitimate only when our own restarted
		// init container left it behind (names are per-pod). Adopt it only
		// when it is provably backed by the requested device.
		if err := verifyAdoptedMapper(mapperName, v.Dev); err != nil {
			return err
		}
	} else if os.IsNotExist(err) {
		if err := runCryptsetup(passphrase, "luksOpen", v.Dev, mapperName); err != nil {
			return fmt.Errorf("luksOpen %s: %w", v.Dev, err)
		}
	} else {
		return fmt.Errorf("stat %s: %w", mapperPath, err)
	}

	// mkfs only ever runs on a mapper that is known to be ours: either just
	// luksOpened above, or adopted after verifyAdoptedMapper matched its
	// backing device.
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

// verifyAdoptedMapper confirms an existing mapper is backed by exactly dev,
// comparing device numbers (st_rdev) so path aliases cannot fool the check.
// A missing path, parse failure, or mismatch is an error — never adopt (and
// never mkfs) a mapping we cannot prove is over the requested device.
func verifyAdoptedMapper(mapperName, dev string) error {
	out, err := runCryptsetupStatus(mapperName)
	if err != nil {
		return err
	}
	backing, err := parseStatusDevice(out)
	if err != nil {
		return fmt.Errorf("mapper %s: %w", mapperName, err)
	}
	backingRdev, err := statRdev(backing)
	if err != nil {
		return fmt.Errorf("mapper %s backing device: %w", mapperName, err)
	}
	wantRdev, err := statRdev(dev)
	if err != nil {
		return fmt.Errorf("requested device: %w", err)
	}
	if backingRdev != wantRdev {
		return fmt.Errorf("mapper %s is backed by %s, not the requested %s; refusing to adopt it", mapperName, backing, dev)
	}
	return nil
}

// parseStatusDevice extracts the "device:" line from `cryptsetup status`
// output.
func parseStatusDevice(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && key == "device" {
			if dev := strings.TrimSpace(val); dev != "" {
				return dev, nil
			}
		}
	}
	return "", errors.New("cryptsetup status output has no device: line")
}

// --- process/syscall seams (package vars so tests can stub them) ---

var (
	runCryptsetup       = execCryptsetup
	runCryptsetupCheck  = execCryptsetupCheck
	runCryptsetupStatus = execCryptsetupStatus
	devBlank            = execDevBlank
	mapperNeedsMkfs     = execMapperNeedsMkfs
	mkfs                = execMkfs
	mount               = execMount
	statMapper          = os.Stat
	statRdev            = execStatRdev
)

func execCryptsetup(passphrase []byte, args ...string) error {
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = bytesReader(passphrase)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cryptsetup %s: %w: %s", strings.Join(args, " "), err, string(out))
	}
	return nil
}

// execCryptsetupCheck runs `cryptsetup <cmd> <dev>` and treats exit 0 as true,
// non-zero as false (used for isLuks). Only non-zero exit codes are treated
// as "false" — an exec error (binary missing) is a real error.
func execCryptsetupCheck(sub, dev string) (bool, error) {
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

func execCryptsetupStatus(mapperName string) (string, error) {
	cmd := exec.Command("cryptsetup", "status", mapperName)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("cryptsetup status %s: %w", mapperName, err)
	}
	return string(out), nil
}

// execDevBlank probes dev with blkid -p (superblocks and partition tables).
// Exit 2 = no signature found (blank); exit 0 = something found. Anything
// else — including blkid missing — is an error: when we cannot prove the
// device is blank, we refuse to format it.
func execDevBlank(dev string) (bool, error) {
	if _, err := exec.LookPath("blkid"); err != nil {
		return false, fmt.Errorf("blkid not on PATH: %w", err)
	}
	cmd := exec.Command("blkid", "-p", "-o", "export", dev)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			return true, nil
		}
		return false, fmt.Errorf("blkid -p %s: %w", dev, err)
	}
	return false, nil
}

func execMapperNeedsMkfs(mapperPath string) (bool, error) {
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

func execMkfs(fstype, dev string) error {
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

func execMount(fstype, src, dst string) error {
	cmd := exec.Command("mount", "-t", fstype, src, dst)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount -t %s %s %s: %w: %s", fstype, src, dst, err, string(out))
	}
	return nil
}

// execStatRdev returns the device number of the block-device node at path.
func execStatRdev(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return 0, fmt.Errorf("%s is not a block device", path)
	}
	return uint64(st.Rdev), nil
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
