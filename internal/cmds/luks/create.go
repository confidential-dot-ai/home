package luks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
)

func newCreateCmd() *cobra.Command {
	var (
		bf                baoFlags
		workload, name    string
		sizeStr           string
		driver            string
		fstype            string
		mount             string
		deferFormat       bool
		passphraseEntropy int
		output            string
		localBackingDir   string
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Provision an openbao-gated LUKS volume and emit its pod annotations",
		Long: "create generates a strong passphrase, writes it to openbao, " +
			"provisions the backing block device via the selected driver, " +
			"luksFormat + mkfs + luksClose (unless --defer-format), and " +
			"prints the workload pod annotations plus the volume snippet the " +
			"operator needs to merge into their PodSpec.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := createConfig{
				workload:        workload,
				name:            name,
				driver:          driver,
				fstype:          fstype,
				mount:           mount,
				deferFormat:     deferFormat,
				entropyBytes:    passphraseEntropy,
				output:          output,
				localBackingDir: localBackingDir,
			}
			size, err := resource.ParseQuantity(sizeStr)
			if err != nil {
				return fmt.Errorf("--size %q: %w", sizeStr, err)
			}
			cfg.size = size
			return runCreate(cmd.Context(), &bf, cfg)
		},
	}
	bf.bind(cmd)
	cmd.Flags().StringVar(&workload, "workload", "", "confidential.ai/cw workload id the volume belongs to (required)")
	cmd.Flags().StringVar(&name, "name", "", "volume name; forms the KV suffix (luks-<name>) and pod annotation (required)")
	cmd.Flags().StringVar(&sizeStr, "size", "", "volume size as a k8s quantity, e.g. 10Gi (required)")
	cmd.Flags().StringVar(&driver, "driver", "local", "backing driver: local (loop-file on this host, dev clusters only) | pvc (not yet implemented) | csi (not yet implemented)")
	cmd.Flags().StringVar(&fstype, "fstype", "ext4", "filesystem to create inside the LUKS container")
	cmd.Flags().StringVar(&mount, "mount", "/data", "in-container mountpoint for the app")
	cmd.Flags().BoolVar(&deferFormat, "defer-format", false, "skip luksFormat + mkfs; emit annotation with mode=format-if-empty so the pod formats on first boot")
	cmd.Flags().IntVar(&passphraseEntropy, "passphrase-entropy", 32, "raw random bytes before hex encoding (16-128)")
	cmd.Flags().StringVar(&output, "output", "yaml", "output format: yaml | json")
	cmd.Flags().StringVar(&localBackingDir, "local-dir", "/var/lib/c8s/luks",
		"host directory where the local driver stores backing .img files")
	return cmd
}

type createConfig struct {
	workload        string
	name            string
	size            resource.Quantity
	driver          string
	fstype          string
	mount           string
	deferFormat     bool
	entropyBytes    int
	output          string
	localBackingDir string
}

// createResult is what --output serialises.
type createResult struct {
	Workload    string            `json:"workload"                 yaml:"workload"`
	Name        string            `json:"name"                     yaml:"name"`
	Size        string            `json:"size"                     yaml:"size"`
	Driver      string            `json:"driver"                   yaml:"driver"`
	Device      string            `json:"device"                   yaml:"device"`
	KVPath      string            `json:"kv_path"                  yaml:"kv_path"`
	Annotations map[string]string `json:"annotations"              yaml:"annotations"`
	Volume      any               `json:"volume,omitempty"         yaml:"volume,omitempty"`
	VolumeMount any               `json:"volume_mount,omitempty"   yaml:"volume_mount,omitempty"`
	Notes       []string          `json:"notes,omitempty"          yaml:"notes,omitempty"`
}

func runCreate(ctx context.Context, bf *baoFlags, cfg createConfig) error {
	if err := validateCreate(cfg); err != nil {
		return err
	}

	// 1. Passphrase — before touching anything, so we fail early on bad entropy.
	passphrase, err := generatePassphrase(cfg.entropyBytes)
	if err != nil {
		return err
	}

	// 2. openbao write — before any host mutation, so a KV failure doesn't
	//    leave a formatted-but-unrecoverable disk lying around.
	client, err := bf.client()
	if err != nil {
		return err
	}
	if err := client.putPassphrase(ctx, cfg.workload, cfg.name, passphrase); err != nil {
		return fmt.Errorf("openbao KV write: %w", err)
	}

	// 3. Provision the backing device.
	device, notes, extraVolume, extraMount, err := provision(cfg, passphrase)
	if err != nil {
		// Roll back the KV entry so a retry gets a fresh passphrase and doesn't
		// see stale versions. Best-effort; log on failure.
		_ = client.deleteVolume(ctx, cfg.workload, cfg.name)
		return err
	}

	// 4. Emit the annotations + snippet.
	kvSubpath := fmt.Sprintf("%s/luks-%s", cfg.workload, cfg.name)
	kvFullPath := "secret/data/" + kvSubpath
	annoValue := fmt.Sprintf("dev=%s,mount=%s,secret=%s#passphrase,fstype=%s,mode=%s",
		device, cfg.mount, kvFullPath, cfg.fstype, luksMode(cfg.deferFormat))
	result := createResult{
		Workload: cfg.workload,
		Name:     cfg.name,
		Size:     cfg.size.String(),
		Driver:   cfg.driver,
		Device:   device,
		KVPath:   kvFullPath,
		Annotations: map[string]string{
			"confidential.ai/luks-" + cfg.name:   annoValue,
			"confidential.ai/secret-" + cfg.name: kvFullPath + "#passphrase",
		},
		Volume:      extraVolume,
		VolumeMount: extraMount,
		Notes:       notes,
	}
	// Always remind the operator secrets-inject is required — it isn't part of
	// the CLI's mint but the Stage 5 admission guard demands it.
	result.Notes = append(result.Notes,
		`Also set confidential.ai/secrets-inject: "true" on the workload pod`,
		"(Stage 5 admission rejects luks-<name> without this).")

	return writeResult(cfg.output, result)
}

func validateCreate(cfg createConfig) error {
	if cfg.workload == "" || cfg.name == "" {
		return errors.New("--workload and --name are required")
	}
	if errs := validation.IsDNS1123Label(cfg.workload); len(errs) > 0 {
		return fmt.Errorf("--workload %q must be a DNS-1123 label: %v", cfg.workload, errs)
	}
	if errs := validation.IsDNS1123Label(cfg.name); len(errs) > 0 {
		return fmt.Errorf("--name %q must be a DNS-1123 label: %v", cfg.name, errs)
	}
	if cfg.size.Sign() <= 0 {
		return errors.New("--size must be a positive quantity, e.g. 10Gi")
	}
	if cfg.mount == "" || cfg.mount[0] != '/' {
		return errors.New("--mount must be an absolute path")
	}
	if cfg.output != "yaml" && cfg.output != "json" {
		return fmt.Errorf("--output %q: must be yaml or json", cfg.output)
	}
	return nil
}

func luksMode(deferFormat bool) string {
	if deferFormat {
		return "format-if-empty"
	}
	return "open"
}

// provision routes to the selected driver and returns the device path plus
// any extra PodSpec-fragment volume/mount and human-readable notes.
func provision(cfg createConfig, passphrase []byte) (device string, notes []string, volume any, mount any, err error) {
	switch cfg.driver {
	case "local":
		return provisionLocal(cfg, passphrase)
	case "pvc":
		return "", nil, nil, nil, errors.New("--driver pvc: not yet implemented (design in docs/decisions/2026-07-10-luks-cli.md)")
	case "csi":
		return "", nil, nil, nil, errors.New("--driver csi: not yet implemented")
	default:
		return "", nil, nil, nil, fmt.Errorf("--driver %q: want local | pvc | csi", cfg.driver)
	}
}

// provisionLocal creates a loop-file backed device on the host, luksFormats
// (unless --defer-format), mkfs, and luksCloses so the emitted annotation
// can be consumed by the workload's kata guest reopening the device.
func provisionLocal(cfg createConfig, passphrase []byte) (device string, notes []string, volume any, mount any, err error) {
	if err := os.MkdirAll(cfg.localBackingDir, 0o700); err != nil {
		return "", nil, nil, nil, fmt.Errorf("mkdir %s: %w", cfg.localBackingDir, err)
	}
	imgPath := filepath.Join(cfg.localBackingDir, cfg.workload+"-"+cfg.name+".img")
	if _, err := os.Stat(imgPath); err == nil {
		return "", nil, nil, nil, fmt.Errorf("backing file %s already exists — delete it first or use `c8s luks destroy`", imgPath)
	}
	sizeBytes := cfg.size.Value()
	f, err := os.OpenFile(imgPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("create %s: %w", imgPath, err)
	}
	if err := f.Truncate(sizeBytes); err != nil {
		f.Close()
		_ = os.Remove(imgPath)
		return "", nil, nil, nil, fmt.Errorf("truncate %s to %d: %w", imgPath, sizeBytes, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(imgPath)
		return "", nil, nil, nil, err
	}

	loopDev, err := losetupFind(imgPath)
	if err != nil {
		_ = os.Remove(imgPath)
		return "", nil, nil, nil, err
	}

	if !cfg.deferFormat {
		if err := luksFormat(loopDev, passphrase); err != nil {
			_ = losetupDetach(loopDev)
			_ = os.Remove(imgPath)
			return "", nil, nil, nil, err
		}
		// luksOpen + mkfs + luksClose so the emitted volume is ready to mount.
		mapper := "c8s-luks-" + cfg.workload + "-" + cfg.name
		if err := luksOpen(loopDev, mapper, passphrase); err != nil {
			_ = losetupDetach(loopDev)
			_ = os.Remove(imgPath)
			return "", nil, nil, nil, err
		}
		mapperPath := "/dev/mapper/" + mapper
		if err := mkfs(cfg.fstype, mapperPath); err != nil {
			_ = luksClose(mapper)
			_ = losetupDetach(loopDev)
			_ = os.Remove(imgPath)
			return "", nil, nil, nil, err
		}
		if err := luksClose(mapper); err != nil {
			_ = losetupDetach(loopDev)
			_ = os.Remove(imgPath)
			return "", nil, nil, nil, err
		}
	}

	notes = []string{
		"local driver — the loop device only exists on the host that ran `c8s luks create`.",
		"For a multi-node cluster the workload pod must be nodeSelector-pinned to this host.",
	}
	// The workload PodSpec needs a hostPath volume for the backing file, and
	// the pod's runtime (kata) must attach the loop device inside the guest.
	// We emit the volume snippet so the operator can drop it in.
	volume = map[string]any{
		"name": "c8s-luks-" + cfg.name,
		"hostPath": map[string]string{
			"path": loopDev,
			"type": "BlockDevice",
		},
	}
	return loopDev, notes, volume, nil, nil
}

func writeResult(format string, r createResult) error {
	switch format {
	case "yaml":
		enc := yaml.NewEncoder(os.Stdout)
		enc.SetIndent(2)
		if err := enc.Encode(r); err != nil {
			return err
		}
		return enc.Close()
	case "json":
		enc := jsonEncoder()
		return enc.Encode(r)
	}
	return fmt.Errorf("--output %q: want yaml or json", format)
}

// --- cryptsetup / losetup thin wrappers ---

func luksFormat(dev string, passphrase []byte) error {
	cmd := exec.Command("cryptsetup", "luksFormat", "--batch-mode", dev)
	cmd.Stdin = bytesReader(passphrase)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cryptsetup luksFormat %s: %w: %s", dev, err, out)
	}
	return nil
}

func luksOpen(dev, mapper string, passphrase []byte) error {
	cmd := exec.Command("cryptsetup", "luksOpen", dev, mapper)
	cmd.Stdin = bytesReader(passphrase)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cryptsetup luksOpen %s: %w: %s", dev, err, out)
	}
	return nil
}

func luksClose(mapper string) error {
	out, err := exec.Command("cryptsetup", "luksClose", mapper).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cryptsetup luksClose %s: %w: %s", mapper, err, out)
	}
	return nil
}

func mkfs(fstype, dev string) error {
	binary := "mkfs." + fstype
	out, err := exec.Command(binary, "-q", dev).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", binary, dev, err, out)
	}
	return nil
}

func losetupFind(imgPath string) (string, error) {
	out, err := exec.Command("losetup", "--find", "--show", imgPath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("losetup --find --show %s: %w: %s", imgPath, err, out)
	}
	return trimNewline(string(out)), nil
}

func losetupDetach(dev string) error {
	out, err := exec.Command("losetup", "-d", dev).CombinedOutput()
	if err != nil {
		return fmt.Errorf("losetup -d %s: %w: %s", dev, err, out)
	}
	return nil
}
