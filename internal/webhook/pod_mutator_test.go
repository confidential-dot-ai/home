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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestMutatePodInjectsCertBootstrapAndRenewal(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:      "ghcr.io/lunal-dev/c8s-operator:test",
		CDSURL:            "http://cds.c8s-system.svc:8443",
		AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
		CertDir:           "/etc/c8s/certs",
	})

	if len(pod.Spec.InitContainers) != 2 {
		t.Fatalf("init containers = %d, want bootstrap + renew", len(pod.Spec.InitContainers))
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
	init := pod.Spec.InitContainers[0]
	if !hasArg(init.Args, "--cds-url=http://cds.c8s-system.svc:8443") {
		t.Fatalf("init args %v missing --cds-url", init.Args)
	}
	if !hasArg(init.Args, "--key-mode=0640") {
		t.Fatalf("init args %v missing --key-mode=0640", init.Args)
	}
	if !hasArg(init.Args, "--key-out=/etc/c8s/certs/tls.key") {
		t.Fatalf("init args %v missing key output", init.Args)
	}
	if init.SecurityContext == nil {
		t.Fatalf("missing init security context")
	}
	if init.SecurityContext.AllowPrivilegeEscalation == nil || *init.SecurityContext.AllowPrivilegeEscalation {
		t.Fatalf("init container allows privilege escalation")
	}
	if init.SecurityContext.RunAsNonRoot == nil || !*init.SecurityContext.RunAsNonRoot {
		t.Fatalf("init container does not require non-root")
	}
	if init.SecurityContext.RunAsUser == nil || *init.SecurityContext.RunAsUser != defaultGetCertRunAsUser {
		t.Fatalf("init runAsUser = %v", init.SecurityContext.RunAsUser)
	}
	if init.SecurityContext.RunAsGroup == nil || *init.SecurityContext.RunAsGroup != defaultGetCertRunAsGroup {
		t.Fatalf("init runAsGroup = %v", init.SecurityContext.RunAsGroup)
	}
	if init.SecurityContext.SeccompProfile == nil || init.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("init seccomp profile = %#v", init.SecurityContext.SeccompProfile)
	}

	app := pod.Spec.Containers[0]
	if len(app.VolumeMounts) != 1 || !app.VolumeMounts[0].ReadOnly {
		t.Fatalf("app mounts = %#v, want read-only c8s cert mount", app.VolumeMounts)
	}
	renew := pod.Spec.InitContainers[1]
	if renew.Name != "c8s-renew-cert" {
		t.Fatalf("renew sidecar name = %q", renew.Name)
	}
	if renew.RestartPolicy == nil || *renew.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("renew restartPolicy = %#v, want Always", renew.RestartPolicy)
	}
	for _, want := range []string{
		"--key=/etc/c8s/certs/tls.key",
		"--out=/etc/c8s/certs/tls.crt",
		"--renew-interval=6h0m0s",
		"--reload-nginx=false",
		"--continue-on-initial-error",
	} {
		if !hasArg(renew.Args, want) {
			t.Fatalf("renew args %v missing %s", renew.Args, want)
		}
	}
	if len(renew.VolumeMounts) != 1 || renew.VolumeMounts[0].ReadOnly {
		t.Fatalf("renew mounts = %#v, want writable c8s cert mount", renew.VolumeMounts)
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
	init := pod.Spec.InitContainers[0]
	if !hasArg(init.Args, "--key-mode=0440") {
		t.Fatalf("init args %v missing --key-mode=0440", init.Args)
	}
	renew := pod.Spec.InitContainers[1]
	if !hasArg(renew.Args, "--renew-interval=1h0m0s") {
		t.Fatalf("renew args %v missing configured renewal interval", renew.Args)
	}
	if got := *init.SecurityContext.RunAsUser; got != 0 {
		t.Fatalf("runAsUser = %d, want 0", got)
	}
	if got := *init.SecurityContext.RunAsGroup; got != 0 {
		t.Fatalf("runAsGroup = %d, want 0", got)
	}
	if got := *init.SecurityContext.RunAsNonRoot; got {
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
	init := pod.Spec.InitContainers[0]
	for _, want := range []string{
		"--out=/tls/cert.pem",
		"--key-out=/tls/key.pem",
		"--discovery-out=/discovery/discovery.json",
		"--discovery-cds-cert-url=/.well-known/cds-cert.pem",
		"--discovery-public-tls-mode=webpki",
		"--discovery-mesh-ca-url=/.well-known/mesh-ca.pem",
		"--verbose",
	} {
		if !hasArg(init.Args, want) {
			t.Fatalf("init args %v missing %s", init.Args, want)
		}
	}
	renew := pod.Spec.InitContainers[1]
	for _, want := range []string{
		"--key=/tls/key.pem",
		"--out=/tls/cert.pem",
		"--renew-interval=1h0m0s",
		"--reload-nginx=true",
		"--reload-watch=/edge-tls/public.crt",
		"--reload-watch=/edge-tls/public.key",
		"--discovery-out=/discovery/discovery.json",
		"--verbose",
	} {
		if !hasArg(renew.Args, want) {
			t.Fatalf("renew args %v missing %s", renew.Args, want)
		}
	}
	if got := *renew.SecurityContext.RunAsUser; got != 101 {
		t.Fatalf("renew runAsUser = %d, want 101", got)
	}
	if !hasMount(renew.VolumeMounts, "tls-certs", "/tls", false) {
		t.Fatalf("renew mounts %v missing writable tls-certs", renew.VolumeMounts)
	}
	if !hasMount(renew.VolumeMounts, "public-tls", "/edge-tls", true) {
		t.Fatalf("renew mounts %v missing read-only public-tls", renew.VolumeMounts)
	}
	if !hasMount(renew.VolumeMounts, "discovery", "/discovery", false) {
		t.Fatalf("renew mounts %v missing writable discovery", renew.VolumeMounts)
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
		GetCertImage: "ghcr.io/lunal-dev/c8s-operator:test",
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
			GetCertImage:      "ghcr.io/lunal-dev/c8s-operator:test",
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
		t.Fatalf("initContainers patch = %d containers, want bootstrap + renew", len(initContainers))
	}
	for _, c := range initContainers {
		if !hasArg(c.Args, "--san=c8s-api.default.svc") {
			t.Fatalf("%s args %v missing --san=c8s-api.default.svc", c.Name, c.Args)
		}
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
			GetCertImage:      "ghcr.io/lunal-dev/c8s-operator:test",
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
		t.Fatalf("initContainers patch = %d containers, want bootstrap + renew", len(initContainers))
	}
	for _, c := range initContainers {
		if !hasArg(c.Args, "--san=api.default.svc") {
			t.Fatalf("%s args %v missing --san=api.default.svc", c.Name, c.Args)
		}
	}
}
