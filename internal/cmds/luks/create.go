package luks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/confidential-dot-ai/c8s/internal/luksfs"
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
		allowHostFormat   bool
		passphraseEntropy int
		output            string
		localBackingDir   string
		namespace         string
		storageClass      string
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
				allowHostFormat: allowHostFormat,
				entropyBytes:    passphraseEntropy,
				output:          output,
				localBackingDir: localBackingDir,
				namespace:       namespace,
				storageClass:    storageClass,
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
	cmd.Flags().StringVar(&driver, "driver", "local", "backing driver: local (loop-file on this host, dev clusters only) | pvc (raw-block PersistentVolumeClaim via kubectl — no node access needed, implies mode=format-if-empty)")
	cmd.Flags().StringVar(&fstype, "fstype", "ext4", "filesystem to create inside the LUKS container")
	cmd.Flags().StringVar(&mount, "mount", "/data", "in-container mountpoint for the app")
	cmd.Flags().BoolVar(&deferFormat, "defer-format", false, "skip luksFormat + mkfs; emit annotation with mode=format-if-empty so the pod formats on first boot")
	cmd.Flags().BoolVar(&allowHostFormat, "allow-host-format", false, "permit host-side luksFormat with --driver local: the passphrase and dm-crypt volume key are exposed to THIS host, outside any TEE (dev only, never tenant data)")
	cmd.Flags().IntVar(&passphraseEntropy, "passphrase-entropy", 32, "raw random bytes before hex encoding (16-128)")
	cmd.Flags().StringVar(&output, "output", "yaml", "output format: yaml | json")
	cmd.Flags().StringVar(&localBackingDir, "local-dir", "/var/lib/c8s/luks",
		"host directory where the local driver stores backing .img files")
	cmd.Flags().StringVar(&namespace, "namespace", "default",
		"workload namespace the pvc driver creates the claim in")
	cmd.Flags().StringVar(&storageClass, "storage-class", "",
		"StorageClass for the pvc driver (empty = the cluster default; must support volumeMode: Block)")
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
	allowHostFormat bool
	entropyBytes    int
	output          string
	localBackingDir string
	namespace       string
	storageClass    string
}

// createResult is what --output serialises.
type createResult struct {
	Workload    string            `json:"workload"                 yaml:"workload"`
	Name        string            `json:"name"                     yaml:"name"`
	Size        string            `json:"size"                     yaml:"size"`
	Driver      string            `json:"driver"                   yaml:"driver"`
	Device      string            `json:"device,omitempty"         yaml:"device,omitempty"`
	Claim       string            `json:"claim,omitempty"          yaml:"claim,omitempty"`
	Namespace   string            `json:"namespace,omitempty"      yaml:"namespace,omitempty"`
	KVPath      string            `json:"kv_path"                  yaml:"kv_path"`
	Annotations map[string]string `json:"annotations"              yaml:"annotations"`
	Volume      any               `json:"volume,omitempty"         yaml:"volume,omitempty"`
	Notes       []string          `json:"notes,omitempty"          yaml:"notes,omitempty"`
}

// provisioned is a driver's provisioning outcome: what the annotation leads
// with (dev=<path> or pvc=<claim>), the effective open mode, and any PodSpec
// extras the operator must merge (local driver only — the pvc driver's claim
// is attached by the webhook).
type provisioned struct {
	device    string // node device path (local) or "" (pvc)
	claim     string // claim name (pvc) or "" (local)
	namespace string // claim namespace (pvc) or "" (local)
	devToken  string // "dev=/dev/loop7" | "pvc=c8s-luks-api-data"
	mode      string // "open" | "format-if-empty"
	notes     []string
	volume    any
}

func runCreate(ctx context.Context, bf *baoFlags, cfg createConfig) error {
	if err := validateCreate(cfg); err != nil {
		return err
	}
	if cfg.driver == "local" && !cfg.deferFormat {
		fmt.Fprintln(os.Stderr, "warning: --driver local formats the volume on this host — the passphrase and dm-crypt volume key are exposed here, outside any TEE (dev only, never tenant data)")
	}

	// 1. Passphrase — before touching anything, so we fail early on bad entropy.
	passphrase, err := generatePassphrase(cfg.entropyBytes)
	if err != nil {
		return err
	}
	defer zero(passphrase)

	// 2. openbao write — before any host mutation, so a KV failure doesn't
	//    leave a formatted-but-unrecoverable disk lying around.
	client, err := bf.client()
	if err != nil {
		return err
	}
	if err := client.putPassphrase(ctx, cfg.workload, cfg.name, passphrase); err != nil {
		if errors.Is(err, errVolumeExists) {
			return fmt.Errorf("openbao already holds a passphrase for %s/luks-%s — refusing to overwrite; `c8s luks destroy` it first", cfg.workload, cfg.name)
		}
		return fmt.Errorf("openbao KV write: %w", err)
	}

	// 3. Provision the backing device.
	prov, err := provisionFn(ctx, cfg, passphrase)
	if err != nil {
		// The KV write above was create-only (cas=0), so this entry is one this
		// call just created — roll it back so a retry gets a fresh passphrase.
		// A failed rollback leaves a stale entry that blocks retry, so surface it.
		if delErr := client.deleteVolume(ctx, cfg.workload, cfg.name); delErr != nil {
			return errors.Join(err, fmt.Errorf(
				"rollback of openbao entry %s/luks-%s failed (the stale entry blocks retry until `c8s luks destroy`): %w",
				cfg.workload, cfg.name, delErr))
		}
		return err
	}

	// 4. Emit the annotations + snippet.
	kvFullPath := "secret/data/" + cfg.workload + "/luks-" + cfg.name
	result := createResult{
		Workload:    cfg.workload,
		Name:        cfg.name,
		Size:        cfg.size.String(),
		Driver:      cfg.driver,
		Device:      prov.device,
		Claim:       prov.claim,
		Namespace:   prov.namespace,
		KVPath:      kvFullPath,
		Annotations: luksAnnotations(cfg, prov, kvFullPath),
		Volume:      prov.volume,
		Notes:       prov.notes,
	}
	// The webhook rejects luks-<name> without secrets-inject, and the broker
	// releases the passphrase only to a policy-granted attested identity.
	result.Notes = append(result.Notes,
		`Also set confidential.ai/secrets-inject: "true" on the workload pod.`,
		"Grant the workload's identity read access in secretBroker.releasePolicy.rules or the pod cannot boot:",
		fmt.Sprintf(`{"workloadId": "c8s-%s.%s.svc", "allow": ["%s#passphrase"]}`, cfg.workload, cfg.namespace, kvFullPath),
		"Passphrase confidentiality is bounded by your openbao's: the chart --kms store is dev-grade (see docs/luks.md).")

	return writeResult(cfg.output, result)
}

// luksAnnotations builds the pod annotation pair the webhook consumes. Pinned
// by a golden test: the sibling parser matches this byte-level contract.
func luksAnnotations(cfg createConfig, prov provisioned, kvFullPath string) map[string]string {
	annoValue := fmt.Sprintf("%s,mount=%s,secret=%s#passphrase,fstype=%s,mode=%s",
		prov.devToken, cfg.mount, kvFullPath, cfg.fstype, prov.mode)
	return map[string]string{
		"confidential.ai/luks-" + cfg.name:   annoValue,
		"confidential.ai/secret-" + cfg.name: kvFullPath + "#passphrase",
	}
}

// mountPathRe is the annotation-contract charset for --mount: no separators,
// no whitespace, nothing shell-active.
var mountPathRe = regexp.MustCompile(`^/[A-Za-z0-9/._-]+$`)

func validateCreate(cfg createConfig) error {
	if err := validateWorkloadName(cfg.workload, cfg.name); err != nil {
		return err
	}
	if cfg.size.Sign() <= 0 {
		return errors.New("--size must be a positive quantity, e.g. 10Gi")
	}
	if !mountPathRe.MatchString(cfg.mount) {
		return fmt.Errorf("--mount %q must be an absolute path using only [A-Za-z0-9/._-] (the annotation contract admits no separators or shell-active characters)", cfg.mount)
	}
	if !luksfs.Allowed(cfg.fstype) {
		return fmt.Errorf("--fstype %q: want ext4 or xfs", cfg.fstype)
	}
	switch cfg.driver {
	case "local":
		if !cfg.deferFormat && !cfg.allowHostFormat {
			return errors.New("--driver local without --defer-format luksFormats on this host, exposing the passphrase and volume key outside any TEE — pass --allow-host-format to confirm (dev only), or --defer-format to format inside the guest")
		}
	case "pvc":
	default:
		return fmt.Errorf("--driver %q: want local | pvc", cfg.driver)
	}
	if err := validateNamespace(cfg.namespace); err != nil {
		return err
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

// provisionFn routes to the selected driver. A package var so tests can stub
// provisioning (same pattern as kubectlRun).
var provisionFn = provision

func provision(ctx context.Context, cfg createConfig, passphrase []byte) (provisioned, error) {
	switch cfg.driver {
	case "local":
		device, notes, volume, err := provisionLocal(cfg, passphrase)
		if err != nil {
			return provisioned{}, err
		}
		return provisioned{
			device: device, devToken: "dev=" + device,
			mode: luksMode(cfg.deferFormat), notes: notes, volume: volume,
		}, nil
	case "pvc":
		claim, notes, err := provisionPVC(ctx, cfg)
		if err != nil {
			return provisioned{}, err
		}
		// Always format-if-empty: nothing can luksFormat an unbound claim,
		// so first-boot formatting in the pod is the only coherent mode.
		return provisioned{
			claim: claim, namespace: cfg.namespace, devToken: "pvc=" + claim,
			mode: "format-if-empty", notes: notes,
		}, nil
	default:
		return provisioned{}, fmt.Errorf("--driver %q: want local | pvc", cfg.driver)
	}
}

// provisionLocal creates a loop-file backed device on the host, luksFormats
// (unless --defer-format), mkfs, and luksCloses so the emitted annotation
// can be consumed by the workload's kata guest reopening the device.
func provisionLocal(cfg createConfig, passphrase []byte) (device string, notes []string, volume any, err error) {
	imgPath, err := localImgPath(cfg.localBackingDir, cfg.workload, cfg.name)
	if err != nil {
		return "", nil, nil, err
	}
	if err := os.MkdirAll(cfg.localBackingDir, 0o700); err != nil {
		return "", nil, nil, fmt.Errorf("mkdir %s: %w", cfg.localBackingDir, err)
	}
	if _, err := os.Stat(imgPath); err == nil {
		return "", nil, nil, fmt.Errorf("backing file %s already exists — delete it first or use `c8s luks destroy`", imgPath)
	}
	sizeBytes := cfg.size.Value()
	f, err := os.OpenFile(imgPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", nil, nil, fmt.Errorf("create %s: %w", imgPath, err)
	}
	if err := f.Truncate(sizeBytes); err != nil {
		f.Close()
		_ = os.Remove(imgPath)
		return "", nil, nil, fmt.Errorf("truncate %s to %d: %w", imgPath, sizeBytes, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(imgPath)
		return "", nil, nil, err
	}

	loopDev, err := losetupFind(imgPath)
	if err != nil {
		_ = os.Remove(imgPath)
		return "", nil, nil, err
	}

	if !cfg.deferFormat {
		if err := luksFormat(loopDev, passphrase); err != nil {
			_ = losetupDetach(loopDev)
			_ = os.Remove(imgPath)
			return "", nil, nil, err
		}
		// luksOpen + mkfs + luksClose so the emitted volume is ready to mount.
		mapper := "c8s-luks-" + cfg.workload + "-" + cfg.name
		if err := luksOpen(loopDev, mapper, passphrase); err != nil {
			_ = losetupDetach(loopDev)
			_ = os.Remove(imgPath)
			return "", nil, nil, err
		}
		mapperPath := "/dev/mapper/" + mapper
		if err := mkfs(cfg.fstype, mapperPath); err != nil {
			_ = luksClose(mapper)
			_ = losetupDetach(loopDev)
			_ = os.Remove(imgPath)
			return "", nil, nil, err
		}
		if err := luksClose(mapper); err != nil {
			_ = losetupDetach(loopDev)
			_ = os.Remove(imgPath)
			return "", nil, nil, err
		}
	}

	notes = []string{
		"local driver — the loop device only exists on the host that ran `c8s luks create`.",
		"For a multi-node cluster the workload pod must be nodeSelector-pinned to this host.",
		"dev=/dev/loopN is volatile: loop numbers do not survive a node reboot (reattach and update the annotation).",
	}
	// The workload PodSpec needs a hostPath volume for the loop device, and
	// the pod's runtime (kata) must attach it inside the guest. We emit the
	// volume snippet so the operator can drop it in.
	volume = map[string]any{
		"name": "c8s-luks-" + cfg.name,
		"hostPath": map[string]string{
			"path": loopDev,
			"type": "BlockDevice",
		},
	}
	return loopDev, notes, volume, nil
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
	out, err := exec.Command("losetup", "--find", "--show", "--nooverlap", imgPath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("losetup --find --show --nooverlap %s: %w: %s", imgPath, err, out)
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
