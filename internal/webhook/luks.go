package webhook

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// LUKS-injection annotations. A pod attaches one openbao-gated encrypted
// volume per confidential.ai/luks-<name> annotation. Requires
// confidential.ai/secrets-inject: "true" so the passphrase lands in
// /vault/secrets/<name> before the LUKS-open init container runs.
//
// Value grammar (comma-separated key=value):
//
//	dev=<block-device>          (XOR pvc=) node block device to luksOpen
//	pvc=<claim-name>            (XOR dev=) raw-block PVC attached by the webhook
//	mount=<path>                (required) mount point inside the app container
//	secret=<vault-path>[#field] (required) KV path holding the passphrase
//	fstype=<fs>                 (optional, default ext4) filesystem inside the volume
//	mode=open|format-if-empty   (optional, default open)
const (
	luksAnnotationPrefix = "confidential.ai/luks-"
)

// luksVolume is one parsed luks-<name> annotation.
type luksVolume struct {
	Name       string // sanitised from the annotation suffix (DNS-1123 label)
	Dev        string // e.g. /dev/vdb — passed verbatim to cryptsetup
	PVC        string // raw-block claim name; webhook wires it as a volumeDevice
	Mount      string // absolute in-container path where the decrypted fs is mounted
	SecretName string // matches secretsInjection.Entries[].Name — the passphrase file name
	SecretPath string // KV path (fed into the secrets agent so the file exists)
	SecretKey  string // KV field ("password" etc.); empty = whole KV data JSON
	FSType     string // "ext4" default
	Mode       string // "open" (default) or "format-if-empty"
}

// devicePath is what the luks-open init container luksOpens: the operator's
// dev= verbatim, or — for pvc= — the fixed in-container path the claim's block
// device is mapped to. NOT under /dev: that mount IS the host's /dev, and a
// volumeDevice path inside a hostPath mount would race the runtime's device
// node creation against the bind mount.
func (lv luksVolume) devicePath() string {
	if lv.PVC != "" {
		return "/c8s-dev/" + lv.Name
	}
	return lv.Dev
}

// pvcVolumeName is the pod-scope volume name the webhook declares for a
// pvc= LUKS volume.
func (lv luksVolume) pvcVolumeName() string { return "c8s-luks-pvc-" + lv.Name }

// parseLUKSVolumes returns nil when the pod does not request any LUKS volume.
// A luks-<name> annotation without secrets-inject: true is a hard error — the
// passphrase must land in /vault/secrets/<name> before the open step runs.
func parseLUKSVolumes(annotations map[string]string, secrets *secretsInjection) ([]luksVolume, error) {
	var vols []luksVolume
	for k, v := range annotations {
		if !strings.HasPrefix(k, luksAnnotationPrefix) {
			continue
		}
		name := strings.TrimPrefix(k, luksAnnotationPrefix)
		lv, err := parseLUKSValue(name, v)
		if err != nil {
			return nil, err
		}
		vols = append(vols, lv)
	}
	if len(vols) == 0 {
		return nil, nil
	}
	if secrets == nil {
		return nil, fmt.Errorf("%w: %s-<name> annotations require %s=\"true\" so the passphrase is templated to %s/<name> before the LUKS open step runs",
			errInvalidInjectionAnnotation, luksAnnotationPrefix, AnnotationSecretsInject, defaultSecretsDir)
	}
	// Every luks entry must correspond to a secrets entry the agent will
	// template, so the passphrase file is guaranteed to exist by the time the
	// open init container runs. Enforce here rather than at runtime.
	byName := make(map[string]struct{}, len(secrets.Entries))
	for _, e := range secrets.Entries {
		byName[e.Name] = struct{}{}
	}
	for _, lv := range vols {
		if _, ok := byName[lv.SecretName]; !ok {
			return nil, fmt.Errorf("%w: luks-%s references passphrase %q which is not declared by a matching %s%s annotation",
				errInvalidInjectionAnnotation, lv.Name, lv.SecretName, secretAnnotationPrefix, lv.SecretName)
		}
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].Name < vols[j].Name })
	return vols, nil
}

func parseLUKSValue(name, value string) (luksVolume, error) {
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		return luksVolume{}, fmt.Errorf("%w: luks-%s: name must be a DNS-1123 label: %s",
			errInvalidInjectionAnnotation, name, strings.Join(errs, "; "))
	}
	lv := luksVolume{
		Name:       name,
		FSType:     "ext4",
		Mode:       "open",
		SecretName: name, // default: passphrase templated to /vault/secrets/<name>
	}
	for _, kv := range strings.Split(value, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			return luksVolume{}, fmt.Errorf("%w: luks-%s: %q is not a key=value pair",
				errInvalidInjectionAnnotation, name, kv)
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "dev":
			lv.Dev = val
		case "pvc":
			if errs := validation.IsDNS1123Subdomain(val); len(errs) > 0 {
				return luksVolume{}, fmt.Errorf("%w: luks-%s: pvc= must be a valid claim name: %s",
					errInvalidInjectionAnnotation, name, strings.Join(errs, "; "))
			}
			lv.PVC = val
		case "mount":
			lv.Mount = val
		case "secret":
			path, field, _ := strings.Cut(val, "#")
			if path == "" {
				return luksVolume{}, fmt.Errorf("%w: luks-%s: secret= has an empty path",
					errInvalidInjectionAnnotation, name)
			}
			lv.SecretPath = path
			lv.SecretKey = field
		case "fstype":
			if val != "" {
				lv.FSType = val
			}
		case "mode":
			switch val {
			case "", "open":
				lv.Mode = "open"
			case "format-if-empty":
				lv.Mode = "format-if-empty"
			default:
				return luksVolume{}, fmt.Errorf("%w: luks-%s: unknown mode %q (want open or format-if-empty)",
					errInvalidInjectionAnnotation, name, val)
			}
		default:
			return luksVolume{}, fmt.Errorf("%w: luks-%s: unknown key %q",
				errInvalidInjectionAnnotation, name, key)
		}
	}
	if lv.Dev == "" && lv.PVC == "" {
		return luksVolume{}, fmt.Errorf("%w: luks-%s: one of dev= or pvc= is required",
			errInvalidInjectionAnnotation, name)
	}
	if lv.Dev != "" && lv.PVC != "" {
		return luksVolume{}, fmt.Errorf("%w: luks-%s: dev= and pvc= are mutually exclusive",
			errInvalidInjectionAnnotation, name)
	}
	if !strings.HasPrefix(lv.Mount, "/") {
		return luksVolume{}, fmt.Errorf("%w: luks-%s: mount= must be an absolute path",
			errInvalidInjectionAnnotation, name)
	}
	if lv.SecretPath == "" {
		return luksVolume{}, fmt.Errorf("%w: luks-%s: secret= is required",
			errInvalidInjectionAnnotation, name)
	}
	return lv, nil
}

func hasLUKSAnnotations(annotations map[string]string) bool {
	for k := range annotations {
		if strings.HasPrefix(k, luksAnnotationPrefix) {
			return true
		}
	}
	return false
}

// In-pod paths for the LUKS-open init container.
const (
	luksDataVolume = "c8s-luks-data" // holds mount-target dirs shared with the app
	luksDataDir    = "/c8s-luks"     // parent dir; per-volume dirs at /c8s-luks/<name>
)

// injectLUKS adds one init container that opens every requested LUKS volume
// and mounts each into a per-name subdir under a shared emptyDir. The app
// containers then mount that same subdir at the operator's requested Mount
// path. Runs after c8s-secrets-agent-init (so the passphrase file exists).
//
// SAFETY: the injected container is privileged and mounts /dev host-wide so
// cryptsetup can reach the block devices. This is only tolerable under kata
// (or another CVM shape where "the host" is the guest kernel, which the
// workload trusts). Without kata / node-as-cvm, an operator granting
// secrets-inject to a workload effectively grants it a privileged sidecar.
// The chart refuses that shape (kind=luks_plain_baremetal in validations.yaml).
func injectLUKS(pod *corev1.Pod, eff injection, cfg Config) {
	if len(eff.LUKS) == 0 {
		return
	}
	ensureVolume(pod, corev1.Volume{
		Name:         luksDataVolume,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	})

	// Mount each per-name subdir into the app containers at the operator's
	// requested mount path. pvc= volumes additionally get their claim declared
	// at pod scope; the luks-open container maps it as a raw volumeDevice.
	for _, v := range eff.LUKS {
		mountAll(pod, corev1.VolumeMount{
			Name:      luksDataVolume,
			MountPath: v.Mount,
			SubPath:   v.Name,
		})
		if v.PVC != "" {
			ensureVolume(pod, corev1.Volume{
				Name: v.pvcVolumeName(),
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: v.PVC},
				},
			})
		}
	}

	pod.Spec.InitContainers = insertAfterContainer(pod.Spec.InitContainers,
		"c8s-secrets-agent-init", []corev1.Container{luksOpenContainer(cfg, eff)})
}

// luksOpenContainer runs `c8s luks-open` — one process, all requested
// volumes at once. Runs privileged, with /dev bind-mounted so cryptsetup
// can create /dev/mapper/c8s-<name> nodes.
func luksOpenContainer(cfg Config, eff injection) corev1.Container {
	args := []string{"luks-open", "--secrets-dir=" + defaultSecretsDir, "--mount-root=" + luksDataDir}
	var devices []corev1.VolumeDevice
	for _, v := range eff.LUKS {
		spec := fmt.Sprintf("%s=%s:%s:%s:%s", v.Name, v.devicePath(), v.SecretName, v.FSType, v.Mode)
		args = append(args, "--volume="+spec)
		if v.PVC != "" {
			devices = append(devices, corev1.VolumeDevice{Name: v.pvcVolumeName(), DevicePath: v.devicePath()})
		}
	}
	priv := true
	f := false
	var uid, gid int64 = 0, 0
	return corev1.Container{
		Name:            "c8s-luks-open",
		Image:           cfg.LUKSOpenImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args:            args,
		VolumeDevices:   devices,
		VolumeMounts: []corev1.VolumeMount{
			{Name: secretsDataVolume, MountPath: defaultSecretsDir, ReadOnly: true},
			{Name: luksDataVolume, MountPath: luksDataDir, MountPropagation: mountPropagation(corev1.MountPropagationBidirectional)},
			{Name: "host-dev", MountPath: "/dev"},
		},
		SecurityContext: &corev1.SecurityContext{
			// Privileged is required for cryptsetup ioctls and to create
			// /dev/mapper nodes. Root is required to open the raw block
			// device (loop devices are root:disk mode 660, and the c8s
			// image's default USER is 65532 which cannot open them).
			// RunAsNonRoot: false is explicit so a Pod Security Standard
			// "restricted" ns doesn't reject the container at admission
			// for the root uid.
			Privileged:   &priv,
			RunAsUser:    &uid,
			RunAsGroup:   &gid,
			RunAsNonRoot: &f,
		},
	}
}

func mountPropagation(m corev1.MountPropagationMode) *corev1.MountPropagationMode { return &m }

// The luks-open init container also mounts /dev from the host; the pod
// spec must carry that volume already, so it's declared here rather than in
// the container helper (declarations are pod-scoped).
func ensureLUKSVolumes(pod *corev1.Pod) {
	ensureVolume(pod, corev1.Volume{
		Name: "host-dev",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: "/dev"},
		},
	})
	// The secrets emptyDir is already declared by injectSecrets — the LUKS
	// container just remounts it (see luksOpenContainer's VolumeMount above).
}
