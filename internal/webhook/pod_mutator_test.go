package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestMutatePodInjectsCertSidecar(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
		CDSURL:            "http://cds.c8s-system.svc:8443",
		AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
		CertDir:           "/etc/c8s/certs",
	})

	if len(pod.Spec.InitContainers) != 2 {
		t.Fatalf("init containers = %d, want c8s-cert sidecar + c8s-cert-wait gate", len(pod.Spec.InitContainers))
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("containers = %d, want app container only", len(pod.Spec.Containers))
	}

	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.FSGroup == nil {
		t.Fatalf("expected injected fsGroup")
	}
	if got := *pod.Spec.SecurityContext.FSGroup; got != defaultCertFSGroup {
		t.Fatalf("fsGroup = %d, want %d", got, defaultCertFSGroup)
	}
	cert := pod.Spec.InitContainers[0]
	if cert.Name != "c8s-cert" {
		t.Fatalf("init container[0] name = %q, want c8s-cert (single sidecar that anchors shareProcessNamespace under kata)", cert.Name)
	}
	for _, want := range []string{
		"--cds-url=http://cds.c8s-system.svc:8443",
		"--san=api",
		"--out=/etc/c8s/certs/tls.crt",
		"--key-out=/etc/c8s/certs/tls.key",
		"--key-mode=0640",
		"--renew-interval=6h0m0s",
		"--reload-nginx=false",
		"--continue-on-initial-error",
	} {
		if !hasArg(cert.Args, want) {
			t.Fatalf("c8s-cert args %v missing %s", cert.Args, want)
		}
	}
	if cert.RestartPolicy == nil || *cert.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("c8s-cert restartPolicy = %#v, want Always (native sidecar so the pidns anchor stays alive under kata)", cert.RestartPolicy)
	}
	// The workload is gated by the c8s-cert-wait init container, not an exec
	// startupProbe on the sidecar — the locked kata guest denies exec, so a
	// probe could never pass there. The sidecar must carry no startupProbe.
	if cert.StartupProbe != nil {
		t.Fatalf("c8s-cert must NOT carry a startupProbe (exec is denied on locked kata guests); got %#v", cert.StartupProbe)
	}
	wait := pod.Spec.InitContainers[1]
	if wait.Name != reservedCertWaitContainerName {
		t.Fatalf("init container[1] name = %q, want %s (the exec-free cert gate)", wait.Name, reservedCertWaitContainerName)
	}
	if wait.RestartPolicy != nil {
		t.Fatalf("c8s-cert-wait must be a run-once init container (nil restartPolicy), got %#v", wait.RestartPolicy)
	}
	for _, want := range []string{"/c8s", "probe-file", "--wait", "/etc/c8s/certs/tls.crt"} {
		if !hasArg(wait.Command, want) {
			t.Fatalf("c8s-cert-wait command %v missing %s", wait.Command, want)
		}
	}
	if cert.SecurityContext == nil {
		t.Fatalf("missing c8s-cert security context")
	}
	if cert.SecurityContext.AllowPrivilegeEscalation == nil || *cert.SecurityContext.AllowPrivilegeEscalation {
		t.Fatalf("c8s-cert allows privilege escalation")
	}
	if cert.SecurityContext.RunAsNonRoot == nil || !*cert.SecurityContext.RunAsNonRoot {
		t.Fatalf("c8s-cert does not require non-root")
	}
	if cert.SecurityContext.RunAsUser == nil || *cert.SecurityContext.RunAsUser != defaultGetCertRunAsUser {
		t.Fatalf("c8s-cert runAsUser = %v", cert.SecurityContext.RunAsUser)
	}
	if cert.SecurityContext.RunAsGroup == nil || *cert.SecurityContext.RunAsGroup != defaultGetCertRunAsGroup {
		t.Fatalf("c8s-cert runAsGroup = %v", cert.SecurityContext.RunAsGroup)
	}
	if cert.SecurityContext.SeccompProfile == nil || cert.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("c8s-cert seccomp profile = %#v", cert.SecurityContext.SeccompProfile)
	}
	if len(cert.VolumeMounts) != 1 || cert.VolumeMounts[0].ReadOnly {
		t.Fatalf("c8s-cert mounts = %#v, want writable c8s cert mount", cert.VolumeMounts)
	}

	app := pod.Spec.Containers[0]
	if len(app.VolumeMounts) != 1 || !app.VolumeMounts[0].ReadOnly {
		t.Fatalf("app mounts = %#v, want read-only c8s cert mount", app.VolumeMounts)
	}
}

func TestMutatePodPreservesExistingFSGroup(t *testing.T) {
	existing := int64(1234)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{FSGroup: &existing},
			Containers:      []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:      "image",
		CDSURL:            "http://cds",
		AttestationApiURL: "http://attestation-api",
		CertDir:           "/etc/c8s/certs",
	})

	if got := *pod.Spec.SecurityContext.FSGroup; got != existing {
		t.Fatalf("fsGroup = %d, want existing %d", got, existing)
	}
}

func TestMutatePodUsesConfiguredCertAndInitSecurity(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:        "image",
		CDSURL:              "http://cds",
		AttestationApiURL:   "http://attestation-api",
		CertDir:             "/etc/c8s/certs",
		CertFSGroup:         int64Ptr(4242),
		CertKeyMode:         "0440",
		CertRenewInterval:   time.Hour,
		GetCertRunAsUser:    int64Ptr(0),
		GetCertRunAsGroup:   int64Ptr(0),
		GetCertRunAsNonRoot: boolPtr(false),
	})

	if got := *pod.Spec.SecurityContext.FSGroup; got != 4242 {
		t.Fatalf("fsGroup = %d, want 4242", got)
	}
	if len(pod.Spec.InitContainers) != 2 {
		t.Fatalf("init containers = %d, want c8s-cert sidecar + c8s-cert-wait gate", len(pod.Spec.InitContainers))
	}
	cert := pod.Spec.InitContainers[0]
	if !hasArg(cert.Args, "--key-mode=0440") {
		t.Fatalf("c8s-cert args %v missing --key-mode=0440", cert.Args)
	}
	if !hasArg(cert.Args, "--renew-interval=1h0m0s") {
		t.Fatalf("c8s-cert args %v missing configured renewal interval", cert.Args)
	}
	if got := *cert.SecurityContext.RunAsUser; got != 0 {
		t.Fatalf("runAsUser = %d, want 0", got)
	}
	if got := *cert.SecurityContext.RunAsGroup; got != 0 {
		t.Fatalf("runAsGroup = %d, want 0", got)
	}
	if got := *cert.SecurityContext.RunAsNonRoot; got {
		t.Fatalf("runAsNonRoot = %t, want false", got)
	}
}

func TestMutatePodSupportsTLSLBProfile(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationWorkload:               "c8s-tls-lb.c8s-system.svc",
			AnnotationCertVolume:             "tls-certs",
			AnnotationCertDir:                "/tls",
			AnnotationCertFile:               "cert.pem",
			AnnotationKeyFile:                "key.pem",
			AnnotationRenewInterval:          "1h",
			AnnotationReloadNginx:            "true",
			AnnotationReloadWatchVolume:      "public-tls",
			AnnotationReloadWatchMountPath:   "/edge-tls",
			AnnotationReloadWatchPaths:       "/edge-tls/public.crt,/edge-tls/public.key",
			AnnotationDiscoveryVolume:        "discovery",
			AnnotationDiscoveryMountPath:     "/discovery",
			AnnotationDiscoveryOut:           "/discovery/discovery.json",
			AnnotationDiscoveryCDSCertURL:    "/.well-known/cds-cert.pem",
			AnnotationDiscoveryMeshCAURL:     "/.well-known/mesh-ca.pem",
			AnnotationDiscoveryPublicTLSMode: "webpki",
			AnnotationGetCertRunAsUser:       "101",
			AnnotationGetCertRunAsGroup:      "101",
			AnnotationGetCertRunAsNonRoot:    "true",
			AnnotationGetCertVerbose:         "true",
		}},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "tls-certs"},
				{Name: "public-tls"},
				{Name: "discovery"},
			},
			Containers: []corev1.Container{{
				Name:         "nginx",
				VolumeMounts: []corev1.VolumeMount{{Name: "tls-certs", MountPath: "/tls", ReadOnly: true}},
			}},
		},
	}

	inj, err := parseAnnotations(pod)
	if err != nil {
		t.Fatalf("parseAnnotations: %v", err)
	}
	mutatePod(pod, inj, Config{
		GetCertImage:      "image",
		CDSURL:            "http://cds",
		AttestationApiURL: "http://attestation-api",
		CertDir:           "/etc/c8s/certs",
	})

	if pod.Spec.ShareProcessNamespace == nil || !*pod.Spec.ShareProcessNamespace {
		t.Fatalf("shareProcessNamespace = %v, want true", pod.Spec.ShareProcessNamespace)
	}
	if len(pod.Spec.Volumes) != 3 {
		t.Fatalf("volumes = %#v, want existing tls-lb volumes only", pod.Spec.Volumes)
	}
	if len(pod.Spec.InitContainers) != 2 {
		t.Fatalf("init containers = %d, want c8s-cert sidecar + c8s-cert-wait gate", len(pod.Spec.InitContainers))
	}
	cert := pod.Spec.InitContainers[0]
	for _, want := range []string{
		"--out=/tls/cert.pem",
		"--key-out=/tls/key.pem",
		"--renew-interval=1h0m0s",
		"--reload-nginx=true",
		"--reload-watch=/edge-tls/public.crt",
		"--reload-watch=/edge-tls/public.key",
		"--discovery-out=/discovery/discovery.json",
		"--discovery-cds-cert-url=/.well-known/cds-cert.pem",
		"--discovery-public-tls-mode=webpki",
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem",
		"--verbose",
	} {
		if !hasArg(cert.Args, want) {
			t.Fatalf("c8s-cert args %v missing %s", cert.Args, want)
		}
	}
	if got := *cert.SecurityContext.RunAsUser; got != 101 {
		t.Fatalf("c8s-cert runAsUser = %d, want 101", got)
	}
	if !hasMount(cert.VolumeMounts, "tls-certs", "/tls", false) {
		t.Fatalf("c8s-cert mounts %v missing writable tls-certs", cert.VolumeMounts)
	}
	if !hasMount(cert.VolumeMounts, "public-tls", "/edge-tls", true) {
		t.Fatalf("c8s-cert mounts %v missing read-only public-tls", cert.VolumeMounts)
	}
	if !hasMount(cert.VolumeMounts, "discovery", "/discovery", false) {
		t.Fatalf("c8s-cert mounts %v missing writable discovery", cert.VolumeMounts)
	}
}

func TestMutatePodStampsWorkloadLabel(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage: "ghcr.io/confidential-dot-ai/c8s-operator:test",
		CDSURL:       "http://cds.c8s-system.svc:8443",
	})

	if got := pod.Labels[LabelWorkload]; got != "api" {
		t.Fatalf("label %s = %q, want %q", LabelWorkload, got, "api")
	}
}

func TestParseAnnotationsRejectsWorkloadIDInvalidAsLabelValue(t *testing.T) {
	for _, id := range []string{
		"has spaces",
		"-leading-dash",
		"waaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay-too-long-for-a-label-value",
	} {
		_, err := parseAnnotations(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
				AnnotationWorkload: id,
			}},
		})
		if !errors.Is(err, errInvalidInjectionAnnotation) {
			t.Fatalf("parseAnnotations(%q) error = %v, want invalid annotation", id, err)
		}
	}
}

func TestValidateWorkloadLabelRequiresMatchingAnnotation(t *testing.T) {
	cases := []struct {
		name    string
		labels  map[string]string
		ann     map[string]string
		wantErr bool
	}{
		{"no label", nil, map[string]string{AnnotationWorkload: "api"}, false},
		{"label matches annotation", map[string]string{LabelWorkload: "api"}, map[string]string{AnnotationWorkload: "api"}, false},
		{"label without annotation", map[string]string{LabelWorkload: "api"}, nil, true},
		{"label differs from annotation", map[string]string{LabelWorkload: "other"}, map[string]string{AnnotationWorkload: "api"}, true},
	}
	for _, tc := range cases {
		err := validateWorkloadLabel(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Labels: tc.labels, Annotations: tc.ann},
		})
		if tc.wantErr && !errors.Is(err, errInvalidInjectionAnnotation) {
			t.Fatalf("%s: err = %v, want invalid annotation", tc.name, err)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("%s: err = %v, want nil", tc.name, err)
		}
	}
}

func TestParseAnnotationsRejectsInvalidRenewInterval(t *testing.T) {
	_, err := parseAnnotations(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationWorkload:      "api",
			AnnotationRenewInterval: "not-a-duration",
		}},
	})
	if !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("parseAnnotations error = %v, want invalid annotation", err)
	}
}

func TestParseAnnotationsRejectsInjectionDetailsWithoutWorkloadAnnotation(t *testing.T) {
	_, err := parseAnnotations(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationCertVolume: "tls-certs",
		}},
	})
	if !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("parseAnnotations error = %v, want invalid annotation", err)
	}
}

func TestParseAnnotationsRejectsReloadWatchWithoutMount(t *testing.T) {
	_, err := parseAnnotations(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationWorkload:         "api",
			AnnotationReloadWatchPaths: "/public-tls/tls.crt",
		}},
	})
	if !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("parseAnnotations error = %v, want invalid annotation", err)
	}
}

func TestParseAnnotationsRejectsIncompleteDiscovery(t *testing.T) {
	_, err := parseAnnotations(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationWorkload:            "api",
			AnnotationDiscoveryCDSCertURL: "/.well-known/cds-cert.pem",
		}},
	})
	if !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("parseAnnotations error = %v, want invalid annotation", err)
	}
}

func TestParseAnnotationsRejectsInvalidDiscoveryPublicTLSMode(t *testing.T) {
	_, err := parseAnnotations(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationWorkload:               "api",
			AnnotationDiscoveryVolume:        "discovery",
			AnnotationDiscoveryMountPath:     "/discovery",
			AnnotationDiscoveryOut:           "/discovery/discovery.json",
			AnnotationDiscoveryCDSCertURL:    "/.well-known/cds-cert.pem",
			AnnotationDiscoveryPublicTLSMode: "invalid",
		}},
	})
	if !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("parseAnnotations error = %v, want invalid annotation", err)
	}
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func hasMount(mounts []corev1.VolumeMount, name, path string, readOnly bool) bool {
	for _, mount := range mounts {
		if mount.Name == name && mount.MountPath == path && mount.ReadOnly == readOnly {
			return true
		}
	}
	return false
}

// kataEnforceConfig is a withDefaults-resolved Config with kata enforcement
// on, so the kata-qemu / kata-qemu-snp class defaults are exercised too.
func kataEnforceConfig() Config {
	return Config{KataEnforce: true}.withDefaults()
}

func TestKataRuntimeClassForInjectsDefaultClass(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	if got := kataRuntimeClassFor(pod, kataEnforceConfig()); got != "kata-qemu" {
		t.Fatalf("kataRuntimeClassFor = %q, want kata-qemu for a plain workload pod", got)
	}
}

func TestKataRuntimeClassForConfidentialPodGetsSNP(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationWorkload: "api"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	if got := kataRuntimeClassFor(pod, kataEnforceConfig()); got != "kata-qemu-snp" {
		t.Fatalf("kataRuntimeClassFor = %q, want kata-qemu-snp for a confidential.ai/cw pod", got)
	}
}

func TestKataRuntimeClassForRespectsExplicitRuntimeClass(t *testing.T) {
	existing := "kata-clh"
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		RuntimeClassName: &existing,
		Containers:       []corev1.Container{{Name: "app"}},
	}}
	if got := kataRuntimeClassFor(pod, kataEnforceConfig()); got != "" {
		t.Fatalf("kataRuntimeClassFor = %q, want \"\" — an operator's explicit runtimeClassName must not be overridden", got)
	}
}

func TestKataRuntimeClassForExemptsHostNamespacePods(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec corev1.PodSpec
	}{
		{"hostNetwork", corev1.PodSpec{HostNetwork: true}},
		{"hostPID", corev1.PodSpec{HostPID: true}},
		{"hostIPC", corev1.PodSpec{HostIPC: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Also annotate confidential.ai/cw to prove the host-namespace
			// exemption wins over the confidential-class path.
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationWorkload: "api"}},
				Spec:       tc.spec,
			}
			if got := kataRuntimeClassFor(pod, kataEnforceConfig()); got != "" {
				t.Fatalf("kataRuntimeClassFor = %q, want \"\" — a %s pod cannot run as a VM", got, tc.name)
			}
		})
	}
}

func TestKataRuntimeClassForDisabled(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationWorkload: "api"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	if got := kataRuntimeClassFor(pod, Config{KataEnforce: false}.withDefaults()); got != "" {
		t.Fatalf("kataRuntimeClassFor = %q, want \"\" when kata enforcement is off", got)
	}
}

// gpuPod builds a pod whose first container requests one unit of the given
// per-model GPU resource (the shape the sandbox-device-plugin advertises).
func gpuPod(resourceName string, annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: annotations},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app",
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceName(resourceName): resource.MustParse("1"),
				},
			},
		}}},
	}
}

func TestKataRuntimeClassForGpuRequestGetsConfidentialGpuClass(t *testing.T) {
	// Per-model resource name, no confidential.ai/cw annotation: a GPU request
	// alone selects the confidential-GPU class.
	pod := gpuPod("nvidia.com/GB202GL_RTX_PRO_6000_BLACKWELL_SERVER_EDITION", nil)
	if got := kataRuntimeClassFor(pod, kataEnforceConfig()); got != "kata-qemu-snp-nvidia" {
		t.Fatalf("kataRuntimeClassFor = %q, want kata-qemu-snp-nvidia for an nvidia.com/* GPU pod", got)
	}
}

func TestKataRuntimeClassForGpuWinsOverConfidentialAnnotation(t *testing.T) {
	// confidential.ai/cw would give kata-qemu-snp; the GPU request upgrades it
	// to the GPU variant (still confidential).
	pod := gpuPod("nvidia.com/GB202GL_RTX_PRO_6000_BLACKWELL_SERVER_EDITION",
		map[string]string{AnnotationWorkload: "api"})
	if got := kataRuntimeClassFor(pod, kataEnforceConfig()); got != "kata-qemu-snp-nvidia" {
		t.Fatalf("kataRuntimeClassFor = %q, want kata-qemu-snp-nvidia (GPU implies confidential)", got)
	}
}

func TestKataRuntimeClassForGpuRequestInInitContainer(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name: "warmup",
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						"nvidia.com/GB202GL_RTX_PRO_6000_BLACKWELL_SERVER_EDITION": resource.MustParse("1"),
					},
				},
			}},
			Containers: []corev1.Container{{Name: "app"}},
		},
	}
	if got := kataRuntimeClassFor(pod, kataEnforceConfig()); got != "kata-qemu-snp-nvidia" {
		t.Fatalf("kataRuntimeClassFor = %q, want kata-qemu-snp-nvidia for a GPU init container", got)
	}
}

func TestKataRuntimeClassForGpuExemptsHostNamespacePods(t *testing.T) {
	// A host-namespace GPU pod cannot be a VM; the exemption wins over the GPU
	// path just as it does over the confidential path.
	pod := gpuPod("nvidia.com/GB202GL_RTX_PRO_6000_BLACKWELL_SERVER_EDITION", nil)
	pod.Spec.HostNetwork = true
	if got := kataRuntimeClassFor(pod, kataEnforceConfig()); got != "" {
		t.Fatalf("kataRuntimeClassFor = %q, want \"\" — a host-namespace GPU pod cannot run as a VM", got)
	}
}

func TestKataRuntimeClassForGpuRespectsExplicitRuntimeClass(t *testing.T) {
	pod := gpuPod("nvidia.com/GB202GL_RTX_PRO_6000_BLACKWELL_SERVER_EDITION", nil)
	existing := "kata-qemu-snp"
	pod.Spec.RuntimeClassName = &existing
	if got := kataRuntimeClassFor(pod, kataEnforceConfig()); got != "" {
		t.Fatalf("kataRuntimeClassFor = %q, want \"\" — an explicit runtimeClassName must not be overridden", got)
	}
}

// tdxEnforceConfig mirrors kataEnforceConfig for a --hardware-platform=tdx
// operator: the confidential (CPU, GPU) pair resolves to the TDX classes.
func tdxEnforceConfig() Config {
	return Config{KataEnforce: true, HardwarePlatform: HardwarePlatformTDX}.withDefaults()
}

func TestKataRuntimeClassForTDXPlatform(t *testing.T) {
	t.Run("confidential.ai/cw pod gets kata-qemu-tdx", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationWorkload: "api"}},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
		}
		if got := kataRuntimeClassFor(pod, tdxEnforceConfig()); got != "kata-qemu-tdx" {
			t.Fatalf("kataRuntimeClassFor = %q, want kata-qemu-tdx on a TDX install", got)
		}
	})

	t.Run("GPU pod gets kata-qemu-tdx-nvidia", func(t *testing.T) {
		pod := gpuPod("nvidia.com/GB202GL_RTX_PRO_6000_BLACKWELL_SERVER_EDITION", nil)
		if got := kataRuntimeClassFor(pod, tdxEnforceConfig()); got != "kata-qemu-tdx-nvidia" {
			t.Fatalf("kataRuntimeClassFor = %q, want kata-qemu-tdx-nvidia on a TDX install", got)
		}
	})

	t.Run("plain workload pod still gets kata-qemu", func(t *testing.T) {
		pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
		if got := kataRuntimeClassFor(pod, tdxEnforceConfig()); got != "kata-qemu" {
			t.Fatalf("kataRuntimeClassFor = %q, want kata-qemu — the non-confidential default is platform-independent", got)
		}
	})
}

func TestConfigDefaultsHardwarePlatformToSNP(t *testing.T) {
	if got := (Config{KataEnforce: true}).withDefaults().HardwarePlatform; got != HardwarePlatformSNP {
		t.Fatalf("withDefaults().HardwarePlatform = %q, want %q", got, HardwarePlatformSNP)
	}
}

func TestPodRequestsNvidiaGpu(t *testing.T) {
	cases := []struct {
		name string
		pod  *corev1.Pod
		want bool
	}{
		{"no resources", &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}, false},
		{"per-model GPU", gpuPod("nvidia.com/GB202GL_RTX_PRO_6000_BLACKWELL_SERVER_EDITION", nil), true},
		{"generic GPU", gpuPod("nvidia.com/gpu", nil), true},
		{"zero quantity", gpuPod("nvidia.com/gpu", nil), true}, // overwritten below
		{"non-nvidia vendor", gpuPod("amd.com/gpu", nil), false},
		{"cpu only", gpuPod("cpu", nil), false},
	}
	// Patch the zero-quantity case to a real zero request — a 0 GPU request is
	// not a GPU pod.
	cases[3].pod = &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
		Name: "app",
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{"nvidia.com/gpu": resource.MustParse("0")},
		},
	}}}}
	cases[3].want = false
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := podRequestsNvidiaGpu(tc.pod); got != tc.want {
				t.Fatalf("podRequestsNvidiaGpu = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWorkloadSAN(t *testing.T) {
	cases := []struct {
		name      string
		cwID      string
		namespace string
		want      string
	}{
		{"bare id gets managed service dns name", "api", "default", "c8s-api.default.svc"},
		{"dotted id passes through", "c8s-tls-lb.c8s-system.svc", "c8s-system", "c8s-tls-lb.c8s-system.svc"},
		{"empty namespace falls back to id", "api", "", "api"},
		{"id too long for a service name passes through", strings.Repeat("a", 60), "default", strings.Repeat("a", 60)},
		{"empty id stays empty", "", "default", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := workloadSAN(tc.cwID, tc.namespace); got != tc.want {
				t.Fatalf("workloadSAN(%q, %q) = %q, want %q", tc.cwID, tc.namespace, got, tc.want)
			}
		})
	}
}

// TestHandleDerivesServiceSAN proves the request namespace, not the pod
// object's (empty for template-created pods), feeds the injected --san.
func TestHandleDerivesServiceSAN(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
			CDSURL:            "http://cds.c8s-system.svc:8443",
			AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
			CertDir:           "/etc/c8s/certs",
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationWorkload: "api"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: "default",
			Object:    runtime.RawExtension{Raw: raw},
		},
	})
	if !resp.Allowed {
		t.Fatalf("Handle denied: %v", resp.Result)
	}

	initContainers := initContainersPatch(t, resp)
	if len(initContainers) != 2 {
		t.Fatalf("initContainers patch = %d containers, want c8s-cert sidecar + c8s-cert-wait gate", len(initContainers))
	}
	if !hasArg(initContainers[0].Args, "--san=c8s-api.default.svc") {
		t.Fatalf("%s args %v missing --san=c8s-api.default.svc", initContainers[0].Name, initContainers[0].Args)
	}
}

// TestHandleRejectsCWHostNetwork proves a cw-annotated hostNetwork pod is
// denied: it shares the node IP so it cannot be mesh-intercepted or covered by
// the cw inbound guard, and must not onboard silently unprotected.
func TestHandleRejectsCWHostNetwork(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage: "ghcr.io/confidential-dot-ai/c8s-operator:test",
			CDSURL:       "http://cds.c8s-system.svc:8443",
			CertDir:      "/etc/c8s/certs",
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationWorkload: "api"}},
		Spec:       corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: "default",
			Object:    runtime.RawExtension{Raw: raw},
		},
	})
	if resp.Allowed {
		t.Fatal("Handle admitted a cw hostNetwork pod; want denial")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "hostNetwork") {
		t.Fatalf("denial message = %+v, want it to mention hostNetwork", resp.Result)
	}
}

// A hostNetwork pod WITHOUT the cw annotation is untouched: the guardrail is
// scoped to opted-in workloads, not every hostNetwork pod on the cluster.
func TestHandleAllowsPlainHostNetwork(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{decoder: admission.NewDecoder(scheme), cfg: Config{}.withDefaults()}
	pod := &corev1.Pod{Spec: corev1.PodSpec{HostNetwork: true, Containers: []corev1.Container{{Name: "app"}}}}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{Namespace: "default", Object: runtime.RawExtension{Raw: raw}},
	})
	if !resp.Allowed {
		t.Fatalf("Handle denied a plain hostNetwork pod: %v", resp.Result)
	}
}

// initContainersPatch decodes the /spec/initContainers patch op from an
// admission response into typed containers.
func initContainersPatch(t *testing.T, resp admission.Response) []corev1.Container {
	t.Helper()
	var initContainers []corev1.Container
	for _, op := range resp.Patches {
		if op.Path != "/spec/initContainers" {
			continue
		}
		value, err := json.Marshal(op.Value)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(value, &initContainers); err != nil {
			t.Fatal(err)
		}
	}
	return initContainers
}

func TestParseAnnotationsSANOverride(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		AnnotationWorkload: "api",
		AnnotationSAN:      "api.default.svc",
	}}}
	inj, err := parseAnnotations(pod)
	if err != nil {
		t.Fatalf("parseAnnotations: %v", err)
	}
	if inj.SAN != "api.default.svc" {
		t.Fatalf("SAN = %q, want api.default.svc", inj.SAN)
	}

	pod.Annotations[AnnotationSAN] = "https://api.default.svc"
	if _, err := parseAnnotations(pod); !errors.Is(err, errInvalidInjectionAnnotation) {
		t.Fatalf("parseAnnotations error = %v, want invalid annotation", err)
	}
}

func TestHandleSANOverrideWinsOverDerivation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
			CDSURL:            "http://cds.c8s-system.svc:8443",
			AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
			CertDir:           "/etc/c8s/certs",
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationWorkload: "api",
			AnnotationSAN:      "api.default.svc",
		}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: "default",
			Object:    runtime.RawExtension{Raw: raw},
		},
	})
	if !resp.Allowed {
		t.Fatalf("Handle denied: %v", resp.Result)
	}
	initContainers := initContainersPatch(t, resp)
	if len(initContainers) != 2 {
		t.Fatalf("initContainers patch = %d containers, want c8s-cert sidecar + c8s-cert-wait gate", len(initContainers))
	}
	if !hasArg(initContainers[0].Args, "--san=api.default.svc") {
		t.Fatalf("%s args %v missing --san=api.default.svc", initContainers[0].Name, initContainers[0].Args)
	}
}

// TestMutatePodReplacesPreexistingCertContainer proves injection is by
// reconstruction: a pod that pre-declares its own c8s-cert init container to
// shed the real one does not win — the operator-built sidecar replaces the
// decoy rather than being skipped.
func TestMutatePodReplacesPreexistingCertContainer(t *testing.T) {
	decoy := int64(0)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:            "c8s-cert",
				Image:           "attacker/pause:latest",
				Command:         []string{"sleep", "infinity"},
				SecurityContext: &corev1.SecurityContext{RunAsUser: &decoy},
			}},
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
		CDSURL:            "http://cds.c8s-system.svc:8443",
		AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
		CertDir:           "/etc/c8s/certs",
	})

	certs := 0
	for _, c := range pod.Spec.InitContainers {
		if c.Name == "c8s-cert" {
			certs++
		}
	}
	if certs != 1 {
		t.Fatalf("c8s-cert init containers = %d, want exactly 1 (real sidecar replaces the decoy)", certs)
	}
	got := pod.Spec.InitContainers[0]
	if got.Name != "c8s-cert" {
		t.Fatalf("init[0] = %q, want c8s-cert leading the list", got.Name)
	}
	if got.Image != "ghcr.io/confidential-dot-ai/c8s-operator:test" {
		t.Fatalf("c8s-cert image = %q, want the operator get-cert image (decoy survived)", got.Image)
	}
	if !hasArg(got.Args, "--cds-url=http://cds.c8s-system.svc:8443") {
		t.Fatalf("c8s-cert args %v are not operator-built (decoy survived)", got.Args)
	}
	if got.RestartPolicy == nil || *got.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("c8s-cert restartPolicy = %#v, want Always", got.RestartPolicy)
	}
}

// TestMutatePodInjectionIsIdempotent proves a reinvocation (mutatePod applied
// twice, as reinvocationPolicy: IfNeeded can trigger) converges: one sidecar,
// one cert volume, one mount per container.
func TestMutatePodInjectionIsIdempotent(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	cfg := Config{
		GetCertImage:      "img",
		CDSURL:            "http://cds",
		AttestationApiURL: "http://attestation-api",
		CertDir:           "/etc/c8s/certs",
	}
	mutatePod(pod, &injection{WorkloadID: "api"}, cfg)
	mutatePod(pod, &injection{WorkloadID: "api"}, cfg)

	if got := len(pod.Spec.InitContainers); got != 2 {
		t.Fatalf("init containers = %d after two injections, want 2 (c8s-cert + c8s-cert-wait, deduped)", got)
	}
	volumes := 0
	for _, v := range pod.Spec.Volumes {
		if v.Name == "c8s-certs" {
			volumes++
		}
	}
	if volumes != 1 {
		t.Fatalf("c8s-certs volumes = %d after two injections, want 1", volumes)
	}
	for _, c := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
		mounts := 0
		for _, mnt := range c.VolumeMounts {
			if mnt.Name == "c8s-certs" {
				mounts++
			}
		}
		if mounts != 1 {
			t.Fatalf("container %s c8s-certs mounts = %d, want 1", c.Name, mounts)
		}
	}
}

// TestHandleRejectsReservedCertContainerName proves an opted-in pod cannot park
// its own container under the reserved c8s-cert name (in the regular list) to
// shadow the injected sidecar — the collision is rejected at admission.
func TestHandleRejectsReservedCertContainerName(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage: "ghcr.io/confidential-dot-ai/c8s-operator:test",
			CDSURL:       "http://cds.c8s-system.svc:8443",
			CertDir:      "/etc/c8s/certs",
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationWorkload: "api"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "app"},
			{Name: "c8s-cert", Image: "attacker/pause"},
		}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{Namespace: "default", Object: runtime.RawExtension{Raw: raw}},
	})
	if resp.Allowed {
		t.Fatal("Handle admitted a cw pod with a reserved c8s-cert container; want denial")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "reserved") {
		t.Fatalf("denial message = %+v, want it to mention the reserved name", resp.Result)
	}
}

// TestHandleInjectsDespitePresetInjectedMarker proves the
// confidential.ai/c8s-injected marker no longer suppresses injection: a pod
// that presets it (with no real sidecar) is still given the c8s-cert sidecar,
// so the marker cannot be used to skip attestation-bound injection.
func TestHandleInjectsDespitePresetInjectedMarker(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
			CDSURL:            "http://cds.c8s-system.svc:8443",
			AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
			CertDir:           "/etc/c8s/certs",
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationWorkload: "api",
			AnnotationInjected: "true",
		}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	resp := m.Handle(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{Namespace: "default", Object: runtime.RawExtension{Raw: raw}},
	})
	if !resp.Allowed {
		t.Fatalf("Handle denied: %v", resp.Result)
	}
	inits := initContainersPatch(t, resp)
	if len(inits) != 2 || inits[0].Name != "c8s-cert" || inits[1].Name != "c8s-cert-wait" {
		t.Fatalf("initContainers patch = %+v, want injected c8s-cert + c8s-cert-wait despite the preset marker", inits)
	}
}
