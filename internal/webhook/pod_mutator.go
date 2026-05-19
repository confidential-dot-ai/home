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

// Config tunes the injector.
type Config struct {
	// GetCertImage is the c8s multi-mode binary image used for the
	// injected get-cert containers.
	GetCertImage string

	// AssamURL points at the assam Service in-cluster.
	AssamURL string

	// AttestationServiceURL points at the node-local attestation-service.
	AttestationServiceURL string

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
	Cert       certSpec
	Reload     reloadSpec
	Discovery  discoverySpec
	Security   getCertSecuritySpec
	Verbose    bool
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
	} {
		if annotations[name] != "" {
			return true
		}
	}
	return false
}

func (inj *injection) validate() error {
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

	inj, err := parseAnnotations(pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	if inj == nil {
		return admission.Allowed("no c8s annotation — passthrough")
	}
	if _, already := pod.Annotations[AnnotationInjected]; already {
		return admission.Allowed("already injected")
	}

	l.Info("injecting c8s get-cert containers", "workload", inj.WorkloadID)
	mutatePod(pod, inj, m.cfg)

	raw, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, raw)
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

	pod.Spec.InitContainers = ensureInitContainer(pod.Spec.InitContainers,
		renewCertContainer(&effective, cfg))
	pod.Spec.InitContainers = ensureInitContainer(pod.Spec.InitContainers,
		initCertContainer(&effective, cfg))

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[AnnotationInjected] = "true"
}

// initCertContainer fetches the workload's leaf cert from assam over HTTP
// using the existing get-cert subcommand.
func initCertContainer(inj *injection, cfg Config) corev1.Container {
	args := []string{
		"get-cert",
		"--assam-url=" + cfg.AssamURL,
		"--attestation-service-url=" + cfg.AttestationServiceURL,
		"--san=" + inj.WorkloadID,
		"--out=" + certPath(inj.Cert.Dir, inj.Cert.CertFile),
		"--key-out=" + certPath(inj.Cert.Dir, inj.Cert.KeyFile),
		"--key-mode=" + cfg.CertKeyMode,
	}
	args = append(args, discoveryArgs(inj.Discovery)...)
	if inj.Verbose {
		args = append(args, "--verbose")
	}

	c := corev1.Container{
		Name:            "c8s-init-cert",
		Image:           cfg.GetCertImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args:            args,
		Env:             getCertEnv(inj),
		VolumeMounts:    getCertVolumeMounts(inj, false),
		SecurityContext: getCertSecurityContext(inj),
	}
	return c
}

// renewCertContainer keeps the workload leaf cert fresh after the pod starts.
// It reuses the private key written by c8s-init-cert and only rewrites tls.crt.
func renewCertContainer(inj *injection, cfg Config) corev1.Container {
	always := corev1.ContainerRestartPolicyAlways
	args := []string{
		"get-cert",
		"--assam-url=" + cfg.AssamURL,
		"--attestation-service-url=" + cfg.AttestationServiceURL,
		"--san=" + inj.WorkloadID,
		"--key=" + certPath(inj.Cert.Dir, inj.Cert.KeyFile),
		"--out=" + certPath(inj.Cert.Dir, inj.Cert.CertFile),
		"--renew-interval=" + inj.Cert.RenewInterval.String(),
		"--reload-nginx=" + strconv.FormatBool(inj.Reload.Nginx),
		"--continue-on-initial-error",
	}
	for _, path := range inj.Reload.WatchPaths {
		args = append(args, "--reload-watch="+path)
	}
	args = append(args, discoveryArgs(inj.Discovery)...)
	if inj.Verbose {
		args = append(args, "--verbose")
	}

	return corev1.Container{
		Name:            "c8s-renew-cert",
		Image:           cfg.GetCertImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		RestartPolicy:   &always,
		Args:            args,
		Env:             getCertEnv(inj),
		VolumeMounts:    getCertVolumeMounts(inj, true),
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

func ensureInitContainer(existing []corev1.Container, c corev1.Container) []corev1.Container {
	for _, ec := range existing {
		if ec.Name == c.Name {
			return existing
		}
	}
	return append([]corev1.Container{c}, existing...)
}

func mountAll(pod *corev1.Pod, mount corev1.VolumeMount) {
	add := func(cs []corev1.Container) []corev1.Container {
		for i := range cs {
			if containerHasMount(cs[i], mount.Name) {
				continue
			}
			cs[i].VolumeMounts = append(cs[i].VolumeMounts, mount)
		}
		return cs
	}
	pod.Spec.Containers = add(pod.Spec.Containers)
	pod.Spec.InitContainers = add(pod.Spec.InitContainers)
}

func containerHasMount(c corev1.Container, name string) bool {
	for _, m := range c.VolumeMounts {
		if m.Name == name {
			return true
		}
	}
	return false
}
