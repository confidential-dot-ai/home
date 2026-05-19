package webhook

import (
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMutatePodInjectsCertBootstrapAndRenewal(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}

	mutatePod(pod, &injection{WorkloadID: "api"}, Config{
		GetCertImage:          "ghcr.io/lunal-dev/c8s-operator:test",
		AssamURL:              "http://assam.c8s-system.svc:8080",
		AttestationServiceURL: "http://attestation-service.c8s-system.svc:8400",
		CertDir:               "/etc/c8s/certs",
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
		GetCertImage:          "image",
		AssamURL:              "http://assam",
		AttestationServiceURL: "http://attestation-service",
		CertDir:               "/etc/c8s/certs",
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
		GetCertImage:          "image",
		AssamURL:              "http://assam",
		AttestationServiceURL: "http://attestation-service",
		CertDir:               "/etc/c8s/certs",
		CertFSGroup:           int64Ptr(4242),
		CertKeyMode:           "0440",
		CertRenewInterval:     time.Hour,
		GetCertRunAsUser:      int64Ptr(0),
		GetCertRunAsGroup:     int64Ptr(0),
		GetCertRunAsNonRoot:   boolPtr(false),
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
		GetCertImage:          "image",
		AssamURL:              "http://assam",
		AttestationServiceURL: "http://attestation-service",
		CertDir:               "/etc/c8s/certs",
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
