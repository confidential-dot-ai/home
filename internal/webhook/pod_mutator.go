// Package webhook contains the mutating admission webhook that injects
// the c8s get-cert containers into pods opted in by annotation.
//
// The webhook reads one annotation on the pod (not its owning workload,
// not any CR — pod metadata only):
//
//	confidential.ai/cw=<workload-id>     required to opt in
//
// Pod-to-pod mTLS is handled by the node-level ratls-mesh DaemonSet
// (cmd/ratls-mesh/), so the webhook does not inject any mesh sidecar.
// Its only job is to add get-cert containers that fetch and renew the
// workload's own identity cert when the pod opts in.
//
// Pods without confidential.ai/cw pass through unchanged. The webhook does
// not GET any CR — sidecar injection runs whether or not a ConfidentialWorkload
// CR exists.
package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Pod annotations that drive sidecar injection.
const (
	// AnnotationWorkload opts a pod in to c8s injection. Required.
	AnnotationWorkload = "confidential.ai/cw"

	// AnnotationInjected is stamped on pods after a successful mutation
	// so re-invocations of the webhook are no-ops.
	AnnotationInjected = "confidential.ai/c8s-injected"

	// LabelWorkload mirrors AnnotationWorkload as a pod label so the
	// operator-managed headless Service (one per annotated workload) can
	// select the workload's pods — Service selectors match labels only.
	LabelWorkload = AnnotationWorkload

	// AnnotationSAN overrides the DNS SAN get-cert requests. For workloads
	// adopted into c8s whose clients already dial an existing Service name;
	// without it the SAN is derived from the cw id (see workloadSAN).
	AnnotationSAN = "confidential.ai/c8s-san"

	AnnotationCertVolume             = "confidential.ai/c8s-cert-volume"
	AnnotationCertDir                = "confidential.ai/c8s-cert-dir"
	AnnotationCertFile               = "confidential.ai/c8s-cert-file"
	AnnotationKeyFile                = "confidential.ai/c8s-key-file"
	AnnotationRenewInterval          = "confidential.ai/c8s-renew-interval"
	AnnotationReloadNginx            = "confidential.ai/c8s-reload-nginx"
	AnnotationReloadWatchPaths       = "confidential.ai/c8s-reload-watch-paths"
	AnnotationReloadWatchVolume      = "confidential.ai/c8s-reload-watch-volume"
	AnnotationReloadWatchMountPath   = "confidential.ai/c8s-reload-watch-mount-path"
	AnnotationDiscoveryVolume        = "confidential.ai/c8s-discovery-volume"
	AnnotationDiscoveryMountPath     = "confidential.ai/c8s-discovery-mount-path"
	AnnotationDiscoveryOut           = "confidential.ai/c8s-discovery-out"
	AnnotationDiscoveryCDSCertURL    = "confidential.ai/c8s-discovery-cds-cert-url"
	AnnotationDiscoveryMeshCAURL     = "confidential.ai/c8s-discovery-mesh-ca-url"
	AnnotationDiscoveryPublicTLSMode = "confidential.ai/c8s-discovery-public-tls-mode"
	AnnotationGetCertRunAsUser       = "confidential.ai/c8s-get-cert-run-as-user"
	AnnotationGetCertRunAsGroup      = "confidential.ai/c8s-get-cert-run-as-group"
	AnnotationGetCertRunAsNonRoot    = "confidential.ai/c8s-get-cert-run-as-non-root"
	AnnotationGetCertVerbose         = "confidential.ai/c8s-get-cert-verbose"
)

var errInvalidInjectionAnnotation = errors.New("invalid c8s injection annotation")

// defaultCertFSGroup is the shared group used for the injected EmptyDir
// when the pod does not already specify an fsGroup. The c8s image runs as
// the distroless nonroot UID/GID 65532, and get-cert writes tls.key 0640.
const defaultCertFSGroup int64 = 65532
const defaultCertKeyMode = "0640"
const defaultCertRenewInterval = 6 * time.Hour
const defaultGetCertRunAsUser int64 = 65532
const defaultGetCertRunAsGroup int64 = 65532
const defaultGetCertRunAsNonRoot = true
const discoveryPublicTLSModeCDS = "cds"
const discoveryPublicTLSModeWebPKI = "webpki"

// reservedCertContainerName is the injected mesh-cert sidecar's name. It is
// operator-reserved: a pod may not declare its own container under it. The
// webhook rebuilds the sidecar every call (injectInitContainers) and rejects
// the name in the regular/ephemeral lists (rejectReservedCertContainer); the
// cw-label-integrity VAP enforces its presence in the API server.
const reservedCertContainerName = "c8s-cert"

// reservedCertWaitContainerName is the injected gate init container that blocks
// the workload until c8s-cert has written the initial cert (see
// certWaitContainer). Operator-reserved like c8s-cert: a pod may not declare
// its own container under it.
const reservedCertWaitContainerName = "c8s-cert-wait"

// runtimeClassName values injected by kata enforcement. kata-qemu is a
// VM-isolated (non-confidential) pod; the confidential classes come in a
// (CPU, GPU) pair per hardware platform, selected by Config.HardwarePlatform.
// These are NOT configurable: the names are a fixed contract with the
// RuntimeClasses the c8s chart installs (internal/helmchart/c8s/templates/kata.yaml)
// AND with the kata-enforcement ValidatingAdmissionPolicy allowlist, so a custom
// class would be rejected by the policy and have no matching shim or measurement.
const kataRuntimeClass = "kata-qemu"

const (
	kataSnpRuntimeClass    = "kata-qemu-snp"
	kataSnpGpuRuntimeClass = "kata-qemu-snp-nvidia"
	kataTdxRuntimeClass    = "kata-qemu-tdx"
	kataTdxGpuRuntimeClass = "kata-qemu-tdx-nvidia"
)

// Hardware platforms the kata confidential classes target. Values match the
// install CLI's --hardware-platform flag; the chart forwards its platform
// choice to the operator so webhook injection and the rendered RuntimeClasses
// stay in lockstep.
const (
	HardwarePlatformSNP = "sev-snp"
	HardwarePlatformTDX = "tdx"
)

// nvidiaGpuResourcePrefix is the vendor prefix every NVIDIA GPU extended
// resource carries. The sandbox-device-plugin advertises per-model names
// (e.g. nvidia.com/GB202GL_RTX_PRO_6000_BLACKWELL_SERVER_EDITION), so the
// webhook matches the prefix rather than a fixed resource name.
const nvidiaGpuResourcePrefix = "nvidia.com/"

// Config tunes the injector.
type Config struct {
	// GetCertImage is the c8s multi-mode binary image used for the
	// injected get-cert containers.
	GetCertImage string

	// CDSURL points at the CDS Service in-cluster.
	CDSURL string

	// AttestationApiURL points at the node-local attestation-api.
	AttestationApiURL string

	// CertDir is the mount path for the shared cert volume.
	CertDir string

	// CertFSGroup is applied to the pod when it does not already specify
	// fsGroup. A negative value disables fsGroup mutation.
	CertFSGroup *int64

	// CertKeyMode is passed to get-cert for the generated tls.key.
	CertKeyMode string

	// CertRenewInterval is passed to the renewal sidecar. Non-positive
	// values use the default interval.
	CertRenewInterval time.Duration

	// GetCertRunAsUser/Group/NonRoot configure injected get-cert identity.
	GetCertRunAsUser    *int64
	GetCertRunAsGroup   *int64
	GetCertRunAsNonRoot *bool

	// SecretAgentImage is the OpenBao/Vault Agent image injected for pods that
	// opt in to secrets injection (confidential.ai/secrets-inject). Empty
	// disables secrets injection.
	SecretAgentImage string

	// SecretAgentCommand is the agent binary in SecretAgentImage ("bao" for
	// OpenBao, "vault" for HashiCorp Vault). Empty defaults to "bao".
	SecretAgentCommand string

	// SecretBrokerURL is the default secret-broker base URL the injected agent
	// dials (a pod can override with confidential.ai/secrets-broker).
	SecretBrokerURL string

	// LUKSOpenImage is the container image the webhook injects to open
	// openbao-gated LUKS volumes (confidential.ai/luks-<name> annotations).
	// Empty disables LUKS injection. The image must expose `c8s luks-open`
	// as its entrypoint; the standard c8s-operator image satisfies that.
	LUKSOpenImage string

	// KataEnforce turns on kata runtimeClass injection. When set, the webhook
	// injects a runtimeClassName into every in-scope workload pod that does
	// not already request one. Independent of get-cert injection — a pod with
	// no confidential.ai/cw annotation is still given a runtimeClassName. The
	// injected classes are fixed constants, not configurable;
	// kataRuntimeClassFor picks between them per HardwarePlatform.
	KataEnforce bool

	// HardwarePlatform selects which confidential (CPU, GPU) class pair kata
	// enforcement injects: HardwarePlatformSNP (kata-qemu-snp /
	// kata-qemu-snp-nvidia, the default) or HardwarePlatformTDX
	// (kata-qemu-tdx / kata-qemu-tdx-nvidia). Set from the operator's
	// --hardware-platform flag, which the chart derives from the same values
	// that pick the RuntimeClasses it renders.
	HardwarePlatform string
}

// Register wires the pod mutator onto the manager's webhook server.
func Register(mgr ctrl.Manager, cfg Config) error {
	cfg = cfg.withDefaults()
	mgr.GetWebhookServer().Register("/mutate-pods", &admission.Webhook{
		Handler: &podMutator{
			decoder: admission.NewDecoder(mgr.GetScheme()),
			cfg:     cfg,
		},
	})
	return nil
}

type podMutator struct {
	decoder admission.Decoder
	cfg     Config
}

// injection captures everything the mutator decides from pod annotations.
type injection struct {
	WorkloadID string
	// SAN is the DNS SAN get-cert requests from CDS. The c8s-san annotation
	// sets it directly; otherwise Handle derives it from the workload id and
	// pod namespace (see workloadSAN), falling back to the id verbatim.
	SAN       string
	Cert      certSpec
	Reload    reloadSpec
	Discovery discoverySpec
	Security  getCertSecuritySpec
	Verbose   bool
	// Secrets is non-nil when the pod opts in to secrets injection.
	Secrets *secretsInjection
	// LUKS is populated from confidential.ai/luks-<name> annotations. Empty
	// when the pod requests no encrypted volumes.
	LUKS []luksVolume
}

type certSpec struct {
	Volume        string
	Dir           string
	CertFile      string
	KeyFile       string
	RenewInterval time.Duration
}

type reloadSpec struct {
	Nginx          bool
	WatchPaths     []string
	WatchVolume    string
	WatchMountPath string
}

type discoverySpec struct {
	Volume        string
	MountPath     string
	Out           string
	CDSCertURL    string
	MeshCAURL     string
	PublicTLSMode string
}

type getCertSecuritySpec struct {
	RunAsUser    *int64
	RunAsGroup   *int64
	RunAsNonRoot *bool
}

// parseAnnotations returns nil if the pod isn't opted in.
func parseAnnotations(pod *corev1.Pod) (*injection, error) {
	annotations := pod.Annotations
	id := annotations[AnnotationWorkload]
	if id == "" {
		if hasInjectionDetailAnnotations(annotations) {
			return nil, fmt.Errorf("%w: %s is required when c8s injection detail annotations are set", errInvalidInjectionAnnotation, AnnotationWorkload)
		}
		return nil, nil
	}

	inj := &injection{
		WorkloadID: id,
		SAN:        strings.TrimSpace(annotations[AnnotationSAN]),
		Cert: certSpec{
			Volume:   annotations[AnnotationCertVolume],
			Dir:      annotations[AnnotationCertDir],
			CertFile: annotations[AnnotationCertFile],
			KeyFile:  annotations[AnnotationKeyFile],
		},
		Reload: reloadSpec{
			WatchVolume:    annotations[AnnotationReloadWatchVolume],
			WatchMountPath: annotations[AnnotationReloadWatchMountPath],
		},
		Discovery: discoverySpec{
			Volume:        annotations[AnnotationDiscoveryVolume],
			MountPath:     annotations[AnnotationDiscoveryMountPath],
			Out:           annotations[AnnotationDiscoveryOut],
			CDSCertURL:    annotations[AnnotationDiscoveryCDSCertURL],
			MeshCAURL:     annotations[AnnotationDiscoveryMeshCAURL],
			PublicTLSMode: annotations[AnnotationDiscoveryPublicTLSMode],
		},
	}
	var err error
	if inj.Cert.RenewInterval, err = durationAnnotation(annotations, AnnotationRenewInterval); err != nil {
		return nil, err
	}
	if inj.Reload.Nginx, err = boolAnnotation(annotations, AnnotationReloadNginx); err != nil {
		return nil, err
	}
	if inj.Reload.WatchPaths = listAnnotation(annotations, AnnotationReloadWatchPaths); len(inj.Reload.WatchPaths) > 0 {
		inj.Reload.Nginx = true
	}
	if inj.Security.RunAsUser, err = int64Annotation(annotations, AnnotationGetCertRunAsUser); err != nil {
		return nil, err
	}
	if inj.Security.RunAsGroup, err = int64Annotation(annotations, AnnotationGetCertRunAsGroup); err != nil {
		return nil, err
	}
	if inj.Security.RunAsNonRoot, err = boolPtrAnnotation(annotations, AnnotationGetCertRunAsNonRoot); err != nil {
		return nil, err
	}
	if inj.Verbose, err = boolAnnotation(annotations, AnnotationGetCertVerbose); err != nil {
		return nil, err
	}
	if inj.Secrets, err = parseSecretsInjection(annotations); err != nil {
		return nil, err
	}
	if inj.LUKS, err = parseLUKSVolumes(annotations, inj.Secrets); err != nil {
		return nil, err
	}
	if err := inj.validate(); err != nil {
		return nil, err
	}
	return inj, nil
}

func durationAnnotation(annotations map[string]string, name string) (time.Duration, error) {
	value := strings.TrimSpace(annotations[name])
	if value == "" {
		return 0, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%w %s: %v", errInvalidInjectionAnnotation, name, err)
	}
	return parsed, nil
}

func int64Annotation(annotations map[string]string, name string) (*int64, error) {
	value := strings.TrimSpace(annotations[name])
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %v", errInvalidInjectionAnnotation, name, err)
	}
	return &parsed, nil
}

func boolPtrAnnotation(annotations map[string]string, name string) (*bool, error) {
	value := strings.TrimSpace(annotations[name])
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return nil, fmt.Errorf("%w %s: %v", errInvalidInjectionAnnotation, name, err)
	}
	return &parsed, nil
}

func boolAnnotation(annotations map[string]string, name string) (bool, error) {
	parsed, err := boolPtrAnnotation(annotations, name)
	if err != nil || parsed == nil {
		return false, err
	}
	return *parsed, nil
}

func listAnnotation(annotations map[string]string, name string) []string {
	value := strings.TrimSpace(annotations[name])
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func hasInjectionDetailAnnotations(annotations map[string]string) bool {
	for _, name := range []string{
		AnnotationSAN,
		AnnotationCertVolume,
		AnnotationCertDir,
		AnnotationCertFile,
		AnnotationKeyFile,
		AnnotationRenewInterval,
		AnnotationReloadNginx,
		AnnotationReloadWatchPaths,
		AnnotationReloadWatchVolume,
		AnnotationReloadWatchMountPath,
		AnnotationDiscoveryVolume,
		AnnotationDiscoveryMountPath,
		AnnotationDiscoveryOut,
		AnnotationDiscoveryCDSCertURL,
		AnnotationDiscoveryMeshCAURL,
		AnnotationDiscoveryPublicTLSMode,
		AnnotationGetCertRunAsUser,
		AnnotationGetCertRunAsGroup,
		AnnotationGetCertRunAsNonRoot,
		AnnotationGetCertVerbose,
		AnnotationSecretsInject,
		AnnotationSecretsDir,
		AnnotationSecretsBroker,
		AnnotationSecretsRenew,
		// luks-<name> annotations are variadic so they're handled by
		// hasLUKSAnnotations() rather than the fixed-name list — see below.
	} {
		if annotations[name] != "" {
			return true
		}
	}
	return hasSecretEntryAnnotations(annotations) || hasLUKSAnnotations(annotations)
}

func (inj *injection) validate() error {
	if errs := validation.IsValidLabelValue(inj.WorkloadID); len(errs) > 0 {
		return fmt.Errorf("%w: %s must be a valid label value (mirrored as the %s pod label): %s",
			errInvalidInjectionAnnotation, AnnotationWorkload, LabelWorkload, strings.Join(errs, "; "))
	}
	if inj.SAN != "" {
		if errs := validation.IsDNS1123Subdomain(inj.SAN); len(errs) > 0 {
			return fmt.Errorf("%w: %s must be a valid DNS name: %s",
				errInvalidInjectionAnnotation, AnnotationSAN, strings.Join(errs, "; "))
		}
	}
	if inj.Cert.RenewInterval < 0 {
		return fmt.Errorf("%w: %s must not be negative", errInvalidInjectionAnnotation, AnnotationRenewInterval)
	}
	if err := inj.Reload.validate(); err != nil {
		return err
	}
	if err := inj.Discovery.validate(); err != nil {
		return err
	}
	return nil
}

func (r reloadSpec) validate() error {
	if len(r.WatchPaths) == 0 {
		if r.WatchVolume != "" || r.WatchMountPath != "" {
			return fmt.Errorf("%w: %s requires %s", errInvalidInjectionAnnotation, AnnotationReloadWatchVolume, AnnotationReloadWatchPaths)
		}
		return nil
	}
	if r.WatchVolume == "" {
		return fmt.Errorf("%w: %s requires %s", errInvalidInjectionAnnotation, AnnotationReloadWatchPaths, AnnotationReloadWatchVolume)
	}
	if r.WatchMountPath == "" {
		return fmt.Errorf("%w: %s requires %s", errInvalidInjectionAnnotation, AnnotationReloadWatchPaths, AnnotationReloadWatchMountPath)
	}
	return nil
}

func (d discoverySpec) validate() error {
	if !d.configured() {
		return nil
	}

	var missing []string
	if d.Volume == "" {
		missing = append(missing, AnnotationDiscoveryVolume)
	}
	if d.MountPath == "" {
		missing = append(missing, AnnotationDiscoveryMountPath)
	}
	if d.Out == "" {
		missing = append(missing, AnnotationDiscoveryOut)
	}
	if d.CDSCertURL == "" {
		missing = append(missing, AnnotationDiscoveryCDSCertURL)
	}
	if d.PublicTLSMode == "" {
		missing = append(missing, AnnotationDiscoveryPublicTLSMode)
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: incomplete discovery annotations, missing %s", errInvalidInjectionAnnotation, strings.Join(missing, ", "))
	}

	switch d.PublicTLSMode {
	case discoveryPublicTLSModeCDS, discoveryPublicTLSModeWebPKI:
		return nil
	default:
		return fmt.Errorf("%w: %s must be %q or %q, got %q", errInvalidInjectionAnnotation, AnnotationDiscoveryPublicTLSMode, discoveryPublicTLSModeCDS, discoveryPublicTLSModeWebPKI, d.PublicTLSMode)
	}
}

func (d discoverySpec) configured() bool {
	return d.Volume != "" ||
		d.MountPath != "" ||
		d.Out != "" ||
		d.CDSCertURL != "" ||
		d.MeshCAURL != "" ||
		d.PublicTLSMode != ""
}

func (m *podMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	l := log.FromContext(ctx).WithValues("pod", req.Name, "ns", req.Namespace)

	pod := &corev1.Pod{}
	if err := m.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if err := validateWorkloadLabel(pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	inj, err := parseAnnotations(pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	// A hostNetwork pod shares the node IP, so it cannot be a mesh endpoint
	// and the cw inbound guard (which keys on distinct pod IPs) cannot cover
	// it: the confidential workload would serve plaintext on the node IP with
	// no interception and no drop. Reject the contradictory combination at
	// admission rather than let it onboard silently unprotected.
	if inj != nil && pod.Spec.HostNetwork {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf(
			"%w: %s pods must not set hostNetwork — a hostNetwork pod shares the node IP and cannot be mesh-intercepted or protected by the cw inbound guard",
			errInvalidInjectionAnnotation, AnnotationWorkload))
	}
	if inj != nil && inj.SAN == "" {
		// req.Namespace, not pod.Namespace: template-created pods reach
		// admission with an empty metadata.namespace.
		inj.SAN = workloadSAN(inj.WorkloadID, req.Namespace)
	}
	// Fail closed: a pod that asks for secrets must not start without them. If
	// the operator has no agent image configured, reject rather than admit a
	// pod whose app would come up missing its secret files.
	if inj != nil && inj.Secrets != nil && m.cfg.SecretAgentImage == "" {
		return admission.Errored(http.StatusBadRequest,
			fmt.Errorf("pod requests secrets injection (%s) but the operator has no --secret-agent-image configured", AnnotationSecretsInject))
	}
	if inj != nil && len(inj.LUKS) > 0 && m.cfg.LUKSOpenImage == "" {
		return admission.Errored(http.StatusBadRequest,
			fmt.Errorf("pod requests LUKS injection (%s<name>) but the operator has no --luks-open-image configured", luksAnnotationPrefix))
	}

	// confidential.ai/cw drives both get-cert injection and confidential
	// class selection: a pod that opts in to a c8s workload identity also
	// gets a confidential VM (the platform's CPU class). Kata-only injection
	// (no annotation) under --kata-enforce gives kata-qemu. A pod that
	// requests an nvidia.com/* GPU gets the platform's confidential-GPU class
	// — GPU implies confidential, regardless of the annotation. An
	// operator-set runtimeClassName is always honored — an explicit
	// confidential class without the annotation runs as a confidential VM
	// without c8s identity (the bring-your-own-attestation path; see
	// docs/kata.md).
	// Injection is idempotent by reconstruction (mutatePod rebuilds the sidecar
	// every call), so it no longer keys off the confidential.ai/c8s-injected
	// marker: an author cannot skip injection by pre-setting it.
	getCertNeeded := inj != nil && m.cfg.GetCertImage != ""
	kataClass := kataRuntimeClassFor(pod, m.cfg)

	if inj == nil && kataClass == "" {
		return admission.Allowed("no c8s annotation — passthrough")
	}

	// Only the webhook may place a container under the reserved c8s-cert name.
	// The init sidecar is rebuilt below (injectInitContainers), but a
	// regular/ephemeral collision cannot be, so reject it. See docs/pitfalls.md —
	// "get-cert injection integrity is name-based".
	if inj != nil {
		if err := rejectReservedCertContainer(pod); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
	}

	if getCertNeeded {
		l.Info("injecting c8s get-cert containers", "workload", inj.WorkloadID)
		mutatePod(pod, inj, m.cfg)
	}
	if kataClass != "" {
		l.Info("injecting kata runtimeClassName", "runtimeClass", kataClass)
		pod.Spec.RuntimeClassName = &kataClass
		// Stamp AnnotationInjected here too — mutatePod only runs when
		// get-cert is needed, but a kata-only mutation is still a mutation
		// and the alreadyInjected short-circuit above must see it on
		// reinvocation (reinvocationPolicy: IfNeeded).
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		pod.Annotations[AnnotationInjected] = "true"
	}

	raw, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, raw)
}

// workloadServiceNamePrefix marks the operator-managed headless Service inside
// the workload namespace and keeps it from colliding with the workload's own
// Services.
const workloadServiceNamePrefix = "c8s-"

// WorkloadServiceName derives the managed headless Service name from the cw
// id, or "" when the id is absent or cannot name a Service. Shared with the
// WorkloadServiceReconciler so the Service it provisions and the SAN get-cert
// requests stay derived from one rule.
func WorkloadServiceName(cwID string) string {
	if cwID == "" {
		return ""
	}
	name := workloadServiceNamePrefix + cwID
	if len(validation.IsDNS1035Label(name)) > 0 {
		return ""
	}
	return name
}

// workloadServiceDNS is the managed headless Service's in-cluster DNS name,
// c8s-<id>.<namespace>.svc, or "" when the id cannot name a Service. Callers add
// the ".cluster.local" suffix (or not) per their DNS-name needs.
func workloadServiceDNS(cwID, namespace string) string {
	svc := WorkloadServiceName(cwID)
	if svc == "" || namespace == "" {
		return ""
	}
	return svc + "." + namespace + ".svc"
}

// WorkloadServiceFQDN is the managed headless Service's fully-qualified DNS name,
// c8s-<id>.<namespace>.svc.cluster.local, or "" when the id cannot name a
// Service. It is the name tls-lb dials for an adopted workload upstream.
func WorkloadServiceFQDN(cwID, namespace string) string {
	dns := workloadServiceDNS(cwID, namespace)
	if dns == "" {
		return ""
	}
	return dns + ".cluster.local"
}

// workloadSAN is the DNS SAN get-cert requests for a workload. An id that
// names a managed headless Service gets that Service's in-cluster DNS name,
// which CDS's default --dns-san-pattern signs; any other id passes through
// verbatim (e.g. the <name>.<ns>.svc ids the chart's own components use).
func workloadSAN(cwID, namespace string) string {
	if dns := workloadServiceDNS(cwID, namespace); dns != "" {
		return dns
	}
	return cwID
}

// validateWorkloadLabel rejects pods that set the confidential.ai/cw label
// out of band. The webhook stamps this label during injection and the
// operator-managed headless Services select on it, so a pod carrying it must
// also carry the matching opt-in annotation — otherwise an un-injected,
// un-attested pod could join a confidential workload's Service endpoints.
//
// CREATE-time check only. Post-create label mutation is denied by the
// cw-label-integrity ValidatingAdmissionPolicy (chart template
// cw-label-integrity-policy.yaml), which encodes this invariant in CEL plus
// UPDATE immutability. One deliberate difference: the CEL treats an empty
// label value as absent (it can never match a managed Service selector),
// while this check compares it against the annotation like any other value.
func validateWorkloadLabel(pod *corev1.Pod) error {
	label, ok := pod.Labels[LabelWorkload]
	if !ok {
		return nil
	}
	if pod.Annotations[AnnotationWorkload] != label {
		return fmt.Errorf("%w: pod label %s=%q must match the %s annotation (the webhook stamps this label during injection)",
			errInvalidInjectionAnnotation, LabelWorkload, label, AnnotationWorkload)
	}
	return nil
}

// kataRuntimeClassFor returns the runtimeClassName the webhook should inject
// into pod, or "" to leave the pod's runtime unchanged. It returns "" when
// kata enforcement is off, when the pod already requests a runtimeClassName
// (an explicit operator choice the ValidatingAdmissionPolicy still checks),
// or when the pod uses a host namespace (a VM cannot share the host's
// namespaces, so such a pod can only run as an ordinary container).
//
// A pod that requests an nvidia.com/* GPU gets the platform's confidential-GPU
// class: c8s has no non-confidential GPU runtime, so a GPU request alone means
// a confidential VM with the device passed through — independent of
// confidential.ai/cw. The GPU runtime ships with every kata install, so this
// needs no separate gate. A pod annotated confidential.ai/cw gets the
// platform's confidential CPU class: opting in to a c8s workload identity also
// means running as a confidential VM. Any other in-scope pod gets the
// non-confidential kata class.
func kataRuntimeClassFor(pod *corev1.Pod, cfg Config) string {
	if !cfg.KataEnforce {
		return ""
	}
	if pod.Spec.RuntimeClassName != nil && *pod.Spec.RuntimeClassName != "" {
		return ""
	}
	if kataIncompatible(pod) {
		return ""
	}
	tdx := cfg.HardwarePlatform == HardwarePlatformTDX
	if podRequestsNvidiaGpu(pod) {
		if tdx {
			return kataTdxGpuRuntimeClass
		}
		return kataSnpGpuRuntimeClass
	}
	if pod.Annotations[AnnotationWorkload] != "" {
		if tdx {
			return kataTdxRuntimeClass
		}
		return kataSnpRuntimeClass
	}
	return kataRuntimeClass
}

// podRequestsNvidiaGpu reports whether any container (regular or init) asks
// for an nvidia.com/* extended resource. Extended resources must appear in
// Limits (kubernetes copies the value into Requests), but a hand-written pod
// can set Requests directly, so both maps are scanned. Sidecar containers
// live in InitContainers, so they are scanned too.
func podRequestsNvidiaGpu(pod *corev1.Pod) bool {
	containers := make([]corev1.Container, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	containers = append(containers, pod.Spec.Containers...)
	containers = append(containers, pod.Spec.InitContainers...)
	for _, c := range containers {
		if resourceListHasNvidiaGpu(c.Resources.Limits) || resourceListHasNvidiaGpu(c.Resources.Requests) {
			return true
		}
	}
	return false
}

func resourceListHasNvidiaGpu(list corev1.ResourceList) bool {
	for name, qty := range list {
		if strings.HasPrefix(string(name), nvidiaGpuResourcePrefix) && !qty.IsZero() {
			return true
		}
	}
	return false
}

// kataIncompatible reports whether pod uses a host namespace. Kata launches
// each pod as its own VM, which cannot join the host's network, PID, or IPC
// namespace — such a pod can only run as an ordinary container, so kata
// enforcement leaves it alone instead of forcing a class it cannot honor.
func kataIncompatible(pod *corev1.Pod) bool {
	return pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC
}

// mutatePod is pure — easy to unit test.
func mutatePod(pod *corev1.Pod, inj *injection, cfg Config) {
	cfg = cfg.withDefaults()
	effective := inj.withDefaults(cfg)
	if *cfg.CertFSGroup >= 0 {
		ensureFSGroup(pod, *cfg.CertFSGroup)
	}
	ensureVolume(pod, certsVolume(effective.Cert.Volume))

	mountAll(pod, corev1.VolumeMount{
		Name:      effective.Cert.Volume,
		MountPath: effective.Cert.Dir,
		ReadOnly:  true,
	})

	if effective.Reload.Nginx {
		pod.Spec.ShareProcessNamespace = boolPtr(true)
	}

	pod.Spec.InitContainers = injectInitContainers(pod.Spec.InitContainers,
		certContainer(&effective, cfg), certWaitContainer(&effective, cfg))

	if effective.Secrets != nil && cfg.SecretAgentImage != "" {
		injectSecrets(pod, effective, cfg)
	}

	if len(effective.LUKS) > 0 && cfg.LUKSOpenImage != "" {
		ensureLUKSVolumes(pod)
		injectLUKS(pod, effective, cfg)
	}

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[AnnotationInjected] = "true"
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels[LabelWorkload] = inj.WorkloadID
}

// certContainer is the workload's mesh-cert sidecar. It bootstraps the leaf
// cert from CDS on startup and keeps it fresh on a --renew-interval, SIGHUP-ing
// nginx after each renewal when --reload-nginx is on.
//
// Native sidecar (restartPolicy: Always) so it stays resident — that's what
// makes nginx reload work under kata. Kata has no in-guest pause container,
// so the kata-agent anchors shareProcessNamespace on the first container's
// pidns (sandbox.rs:update_shared_pidns), and a PID namespace dies the
// moment its last process exits (kata's namespace.rs explicitly rejects
// persisting pidns via bind mount). A run-once init container would let the
// anchor die before the workload joined it, and the SIGHUP-by-PID path
// would never see nginx in /proc. As the sole, long-lived first init
// container the sidecar plays the same role runc's pause container does.
//
// --key-out is idempotent (load if a key already exists at the path, else
// generate-and-write); a fresh key on every restart would invalidate every
// cert CDS has previously issued for it.
func certContainer(inj *injection, cfg Config) corev1.Container {
	args := []string{
		"get-cert",
		"--cds-url=" + cfg.CDSURL,
		"--attestation-api-url=" + cfg.AttestationApiURL,
		"--san=" + inj.SAN,
		"--out=" + certPath(inj.Cert.Dir, inj.Cert.CertFile),
		"--key-out=" + certPath(inj.Cert.Dir, inj.Cert.KeyFile),
		"--key-mode=" + cfg.CertKeyMode,
		"--renew-interval=" + inj.Cert.RenewInterval.String(),
		"--reload-nginx=" + strconv.FormatBool(inj.Reload.Nginx),
		"--continue-on-initial-error",
	}
	// Secrets injection needs the mesh CA on disk so the injected agent can
	// trust the broker's CDS-issued serving cert.
	if inj.Secrets != nil {
		args = append(args, "--ca-out="+certPath(inj.Cert.Dir, "ca.crt"))
	}
	for _, path := range inj.Reload.WatchPaths {
		args = append(args, "--reload-watch="+path)
	}
	args = append(args, discoveryArgs(inj.Discovery)...)
	if inj.Verbose {
		args = append(args, "--verbose")
	}

	always := corev1.ContainerRestartPolicyAlways
	return corev1.Container{
		Name:            reservedCertContainerName,
		Image:           cfg.GetCertImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		RestartPolicy:   &always,
		Args:            args,
		Env:             getCertEnv(inj),
		VolumeMounts:    getCertVolumeMounts(inj, true),
		SecurityContext: getCertSecurityContext(inj),
		// The workload is gated on the initial cert by the c8s-cert-wait
		// init container (certWaitContainer), not a startupProbe here: a
		// native sidecar is "started" the moment its process launches, and
		// an exec startupProbe is denied by the locked kata-qemu-snp guest
		// (ExecProcessRequest := false), so it could never pass there and
		// the workload would hang in Init forever. See certWaitContainer.
	}
}

// certWaitTimeout bounds how long c8s-cert-wait blocks before failing (and
// being restarted by the kubelet, which re-waits). Comfortably exceeds
// get-cert's own initial-fetch retry so a slow CDS cold start is absorbed in
// one wait, while a genuinely stuck bootstrap surfaces as Init:Error/CrashLoop
// rather than a silent Init hang.
const certWaitTimeout = 3 * time.Minute

// certWaitContainer gates the workload on the initial cert being written by the
// c8s-cert sidecar. It is a plain (run-once) init container that blocks on the
// cert file and exits 0 once it appears, so normal init-completion ordering
// holds the workload until the attested cert exists — fail-closed. It replaces
// the exec startupProbe that used to sit on the sidecar: the locked
// kata-qemu-snp guest denies ExecProcessRequest, so an exec probe can never
// pass there, whereas a container running its own entrypoint is a
// CreateContainerRequest the guest allows. It must be ordered after c8s-cert
// (the pidns anchor) and before the workload; injectInitContainers does that.
func certWaitContainer(inj *injection, cfg Config) corev1.Container {
	return corev1.Container{
		Name:            reservedCertWaitContainerName,
		Image:           cfg.GetCertImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command: []string{
			"/c8s", "probe-file", "--wait",
			"--timeout=" + certWaitTimeout.String(),
			certPath(inj.Cert.Dir, inj.Cert.CertFile),
		},
		VolumeMounts:    getCertVolumeMounts(inj, false),
		SecurityContext: getCertSecurityContext(inj),
	}
}

func certPath(dir, name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(dir, name)
}

func discoveryArgs(discovery discoverySpec) []string {
	var args []string
	if discovery.Out != "" {
		args = append(args, "--discovery-out="+discovery.Out)
	}
	if discovery.CDSCertURL != "" {
		args = append(args, "--discovery-cds-cert-url="+discovery.CDSCertURL)
	}
	if discovery.PublicTLSMode != "" {
		args = append(args, "--discovery-public-tls-mode="+discovery.PublicTLSMode)
	}
	if discovery.MeshCAURL != "" {
		args = append(args, "--discovery-mesh-ca-url="+discovery.MeshCAURL)
	}
	return args
}

func getCertVolumeMounts(inj *injection, includeReloadWatch bool) []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{
		{Name: inj.Cert.Volume, MountPath: inj.Cert.Dir},
	}
	if inj.Discovery.Volume != "" && inj.Discovery.MountPath != "" {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      inj.Discovery.Volume,
			MountPath: inj.Discovery.MountPath,
		})
	}
	if includeReloadWatch && inj.Reload.WatchVolume != "" && inj.Reload.WatchMountPath != "" {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      inj.Reload.WatchVolume,
			MountPath: inj.Reload.WatchMountPath,
			ReadOnly:  true,
		})
	}
	return mounts
}

func getCertEnv(inj *injection) []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "C8S_WORKLOAD_ID", Value: inj.WorkloadID},
		{Name: "C8S_POD_NAME", ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
		}},
		{Name: "C8S_POD_UID", ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"},
		}},
	}
}

func (inj *injection) withDefaults(cfg Config) injection {
	effective := *inj
	if effective.SAN == "" {
		effective.SAN = effective.WorkloadID
	}
	if effective.Cert.Volume == "" {
		effective.Cert.Volume = "c8s-certs"
	}
	if effective.Cert.Dir == "" {
		effective.Cert.Dir = cfg.CertDir
	}
	if effective.Cert.CertFile == "" {
		effective.Cert.CertFile = "tls.crt"
	}
	if effective.Cert.KeyFile == "" {
		effective.Cert.KeyFile = "tls.key"
	}
	if effective.Cert.RenewInterval <= 0 {
		effective.Cert.RenewInterval = cfg.CertRenewInterval
	}
	if effective.Security.RunAsUser == nil {
		effective.Security.RunAsUser = cfg.GetCertRunAsUser
	}
	if effective.Security.RunAsGroup == nil {
		effective.Security.RunAsGroup = cfg.GetCertRunAsGroup
	}
	if effective.Security.RunAsNonRoot == nil {
		effective.Security.RunAsNonRoot = cfg.GetCertRunAsNonRoot
	}
	return effective
}

func (cfg Config) withDefaults() Config {
	if cfg.CertDir == "" {
		cfg.CertDir = "/etc/c8s/certs"
	}
	if cfg.CertFSGroup == nil {
		cfg.CertFSGroup = int64Ptr(defaultCertFSGroup)
	}
	if cfg.CertKeyMode == "" {
		cfg.CertKeyMode = defaultCertKeyMode
	}
	if cfg.CertRenewInterval <= 0 {
		cfg.CertRenewInterval = defaultCertRenewInterval
	}
	if cfg.GetCertRunAsUser == nil {
		cfg.GetCertRunAsUser = int64Ptr(defaultGetCertRunAsUser)
	}
	if cfg.GetCertRunAsGroup == nil {
		cfg.GetCertRunAsGroup = int64Ptr(defaultGetCertRunAsGroup)
	}
	if cfg.GetCertRunAsNonRoot == nil {
		cfg.GetCertRunAsNonRoot = boolPtr(defaultGetCertRunAsNonRoot)
	}
	if cfg.HardwarePlatform == "" {
		cfg.HardwarePlatform = HardwarePlatformSNP
	}
	return cfg
}

func getCertSecurityContext(inj *injection) *corev1.SecurityContext {
	falseValue := false
	trueValue := true
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &falseValue,
		ReadOnlyRootFilesystem:   &trueValue,
		RunAsNonRoot:             inj.Security.RunAsNonRoot,
		RunAsUser:                inj.Security.RunAsUser,
		RunAsGroup:               inj.Security.RunAsGroup,
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}

func certsVolume(name string) corev1.Volume {
	return corev1.Volume{
		Name: name,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory},
		},
	}
}

func ensureVolume(pod *corev1.Pod, v corev1.Volume) {
	for _, existing := range pod.Spec.Volumes {
		if existing.Name == v.Name {
			return
		}
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, v)
}

func ensureFSGroup(pod *corev1.Pod, fsGroup int64) {
	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	if pod.Spec.SecurityContext.FSGroup == nil {
		pod.Spec.SecurityContext.FSGroup = &fsGroup
	}
}

// injectInitContainers prepends the c8s-managed init containers, in the given
// order, and drops any existing init container that collides with an injected
// name. Injection is therefore idempotent (a reinvocation rebuilds the same
// list) and a pre-declared c8s-cert/c8s-cert-wait cannot shed or shadow the
// real ones — the operator-built containers always win. Order matters:
// c8s-cert leads (it anchors shareProcessNamespace under kata — see
// certContainer), then c8s-cert-wait gates the workload on the initial cert
// (see certWaitContainer), then the pod's own init containers.
func injectInitContainers(existing []corev1.Container, injected ...corev1.Container) []corev1.Container {
	reserved := make(map[string]struct{}, len(injected))
	for _, c := range injected {
		reserved[c.Name] = struct{}{}
	}
	out := make([]corev1.Container, 0, len(existing)+len(injected))
	out = append(out, injected...)
	for _, ec := range existing {
		if _, ok := reserved[ec.Name]; !ok {
			out = append(out, ec)
		}
	}
	return out
}

// rejectReservedCertContainer denies an opted-in pod that parks a container
// under the reserved c8s-cert name outside the init-container slot the webhook
// rebuilds. Such a container would survive injection and collide with the
// injected init sidecar (names are unique across all three lists), so it can
// only be an attempt to shed or impersonate it; init-container collisions are
// handled by injectInitContainers instead.
func rejectReservedCertContainer(pod *corev1.Pod) error {
	for _, c := range pod.Spec.Containers {
		if isReservedCertName(c.Name) {
			return fmt.Errorf("%w: container name %q is reserved for the injected c8s cert containers",
				errInvalidInjectionAnnotation, c.Name)
		}
	}
	for _, c := range pod.Spec.EphemeralContainers {
		if isReservedCertName(c.Name) {
			return fmt.Errorf("%w: ephemeral container name %q is reserved for the injected c8s cert containers",
				errInvalidInjectionAnnotation, c.Name)
		}
	}
	return nil
}

func isReservedCertName(name string) bool {
	return name == reservedCertContainerName || name == reservedCertWaitContainerName
}

func mountAll(pod *corev1.Pod, mount corev1.VolumeMount) {
	add := func(cs []corev1.Container) []corev1.Container {
		for i := range cs {
			if containerHasMount(cs[i], mount.Name, mount.MountPath) {
				continue
			}
			cs[i].VolumeMounts = append(cs[i].VolumeMounts, mount)
		}
		return cs
	}
	pod.Spec.Containers = add(pod.Spec.Containers)
	pod.Spec.InitContainers = add(pod.Spec.InitContainers)
}

// containerHasMount matches on (volume, mountPath): one volume may be mounted
// at several paths (per-LUKS-volume subPath mounts), while a reinvocation must
// not duplicate a mount at the same path.
func containerHasMount(c corev1.Container, name, mountPath string) bool {
	for _, m := range c.VolumeMounts {
		if m.Name == name && m.MountPath == mountPath {
			return true
		}
	}
	return false
}
