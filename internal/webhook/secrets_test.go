package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestParseSecretsInjection(t *testing.T) {
	si, err := parseSecretsInjection(map[string]string{
		AnnotationWorkload:           "api",
		AnnotationSecretsInject:      "true",
		secretAnnotationPrefix + "z": "secret/data/api/z",
		secretAnnotationPrefix + "a": "secret/data/api/a#field",
	})
	if err != nil {
		t.Fatal(err)
	}
	if si == nil || len(si.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %#v", si)
	}
	// Deterministic order (sorted by name): a before z.
	if si.Entries[0].Name != "a" || si.Entries[0].Field != "field" || si.Entries[1].Name != "z" {
		t.Fatalf("entries not parsed/sorted: %#v", si.Entries)
	}
}

func TestParseSecretsInjectionErrors(t *testing.T) {
	// inject=true but no secrets declared.
	if _, err := parseSecretsInjection(map[string]string{AnnotationSecretsInject: "true"}); err == nil {
		t.Error("inject without entries should error")
	}
	// secret-* without opt-in.
	if _, err := parseSecretsInjection(map[string]string{secretAnnotationPrefix + "db": "secret/data/x"}); err == nil {
		t.Error("secret entry without inject should error")
	}
	// not opted in: nil, no error.
	if si, err := parseSecretsInjection(map[string]string{}); err != nil || si != nil {
		t.Errorf("no opt-in should be (nil,nil), got (%v,%v)", si, err)
	}
	// invalid secret name.
	if _, err := parseSecretsInjection(map[string]string{
		AnnotationSecretsInject:             "true",
		secretAnnotationPrefix + "Bad_Name": "secret/data/x",
	}); err == nil {
		t.Error("invalid secret name should error")
	}
}

func secretsTestConfig() Config {
	return Config{
		GetCertImage:      "ghcr.io/confidential-dot-ai/c8s-operator:test",
		CDSURL:            "http://cds.c8s-system.svc:8443",
		AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
		CertDir:           "/etc/c8s/certs",
		SecretAgentImage:  "ghcr.io/openbao/openbao:test",
		SecretBrokerURL:   "https://c8s-secret-broker.c8s-system.svc:8443",
	}
}

func TestMutatePodInjectsSecretsAgent(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	inj := &injection{
		WorkloadID: "api",
		Secrets: &secretsInjection{
			Entries: []secretEntry{{Name: "db", Path: "secret/data/api/db", Field: "password"}},
		},
	}
	mutatePod(pod, inj, secretsTestConfig())

	// Order: c8s-cert (native sidecar) → cert-wait gate → config render →
	// one-shot agent init. The agent needs the mesh cert + CA on disk, which
	// only the c8s-cert-wait gate guarantees.
	wantOrder := []string{"c8s-cert", "c8s-cert-wait", "c8s-secrets-config", "c8s-secrets-agent-init"}
	if got := containerNames(pod.Spec.InitContainers); !equalStrings(got, wantOrder) {
		t.Fatalf("init container order = %v, want %v", got, wantOrder)
	}

	// get-cert must now also emit the mesh CA for the agent to trust the broker.
	cert := findContainer(t, pod.Spec.InitContainers, "c8s-cert")
	if !hasArg(cert.Args, "--ca-out=/etc/c8s/certs/ca.crt") {
		t.Fatalf("c8s-cert missing --ca-out: %v", cert.Args)
	}

	// Config-render container passes broker + secret to the c8s subcommand.
	cfgc := findContainer(t, pod.Spec.InitContainers, "c8s-secrets-config")
	for _, want := range []string{
		"secret-agent-config",
		"--out=/vault/config/agent.hcl",
		"--broker-addr=https://c8s-secret-broker.c8s-system.svc:8443",
		"--ca=/etc/c8s/certs/ca.crt",
		"--secret=db=secret/data/api/db#password",
	} {
		if !hasArg(cfgc.Args, want) {
			t.Fatalf("config-render args %v missing %s", cfgc.Args, want)
		}
	}

	// One-shot agent runs the real agent binary with exit-after-auth.
	ag := findContainer(t, pod.Spec.InitContainers, "c8s-secrets-agent-init")
	wantCmd := []string{"bao", "agent", "-config=/vault/config/agent.hcl", "-exit-after-auth=true"}
	if !equalStrings(ag.Command, wantCmd) {
		t.Fatalf("agent-init command = %v, want %v", ag.Command, wantCmd)
	}
	if ag.RestartPolicy != nil {
		t.Fatalf("agent-init must be an ordinary init container (gates the app), got restartPolicy %v", *ag.RestartPolicy)
	}

	// In-memory volumes; app sees secrets read-only.
	assertMemoryVolume(t, pod, secretsConfigVolume)
	assertMemoryVolume(t, pod, secretsDataVolume)
	app := pod.Spec.Containers[0]
	if !hasReadOnlyMount(app, secretsDataVolume, defaultSecretsDir) {
		t.Fatalf("app missing read-only secrets mount: %#v", app.VolumeMounts)
	}
}

func TestMutatePodSecretsRenewAddsSidecar(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	inj := &injection{
		WorkloadID: "api",
		Secrets: &secretsInjection{
			Renew:   true,
			Entries: []secretEntry{{Name: "db", Path: "secret/data/api/db", Field: "password"}},
		},
	}
	mutatePod(pod, inj, secretsTestConfig())

	sidecar := findContainer(t, pod.Spec.InitContainers, "c8s-secrets-agent")
	if sidecar.RestartPolicy == nil || *sidecar.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Fatalf("renewal agent must be a native sidecar (restartPolicy Always), got %v", sidecar.RestartPolicy)
	}
	if hasArg(sidecar.Command, "-exit-after-auth=true") {
		t.Fatalf("renewal agent must not exit after auth: %v", sidecar.Command)
	}
}

// TestMutatePodSecretsInjectionIsIdempotent proves a reinvocation (mutatePod
// applied twice, as reinvocationPolicy: IfNeeded can trigger) converges: the
// secrets containers are rebuilt in place, not duplicated, and no (volume,
// path) mount repeats.
func TestMutatePodSecretsInjectionIsIdempotent(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	inj := &injection{
		WorkloadID: "api",
		Secrets: &secretsInjection{
			Renew:   true,
			Entries: []secretEntry{{Name: "db", Path: "secret/data/api/db", Field: "password"}},
		},
	}
	mutatePod(pod, inj, secretsTestConfig())
	mutatePod(pod, inj, secretsTestConfig())

	wantOrder := []string{"c8s-cert", "c8s-cert-wait", "c8s-secrets-config", "c8s-secrets-agent-init", "c8s-secrets-agent"}
	if got := containerNames(pod.Spec.InitContainers); !equalStrings(got, wantOrder) {
		t.Fatalf("init containers after two injections = %v, want %v", got, wantOrder)
	}
	seenVol := map[string]int{}
	for _, v := range pod.Spec.Volumes {
		seenVol[v.Name]++
	}
	for name, n := range seenVol {
		if n > 1 {
			t.Fatalf("volume %q declared %d× after two injections, want 1", name, n)
		}
	}
	for _, c := range append(pod.Spec.InitContainers, pod.Spec.Containers...) {
		seen := map[string]int{}
		for _, mnt := range c.VolumeMounts {
			seen[mnt.Name+":"+mnt.MountPath]++
		}
		for key, n := range seen {
			if n > 1 {
				t.Fatalf("container %s mount %s duplicated %d× after two injections", c.Name, key, n)
			}
		}
	}
}

func TestMutatePodUsesVaultCommandForVaultImage(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	cfg := secretsTestConfig()
	cfg.SecretAgentImage = "hashicorp/vault:test"
	cfg.SecretAgentCommand = "vault"
	inj := &injection{
		WorkloadID: "api",
		Secrets:    &secretsInjection{Entries: []secretEntry{{Name: "db", Path: "secret/data/api/db"}}},
	}
	mutatePod(pod, inj, cfg)

	ag := findContainer(t, pod.Spec.InitContainers, "c8s-secrets-agent-init")
	if len(ag.Command) == 0 || ag.Command[0] != "vault" {
		t.Fatalf("agent command should start with 'vault' for the Vault image, got %v", ag.Command)
	}
}

func TestHandleFailsClosedWhenAgentImageMissing(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	// GetCertImage set (injection enabled) but no SecretAgentImage.
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
			AnnotationWorkload:            "api",
			AnnotationSecretsInject:       "true",
			secretAnnotationPrefix + "db": "secret/data/api/db#password",
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
	if resp.Allowed {
		t.Fatal("expected admission to be denied when secrets requested but no agent image configured")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "secret-agent-image") {
		t.Fatalf("expected a clear error mentioning secret-agent-image, got %#v", resp.Result)
	}
}

// A secrets request must fail closed when --get-cert-image is empty: injection
// is gated behind GetCertImage, so otherwise the pod is admitted unmutated and
// the app starts with no secrets.
func TestHandleFailsClosedWhenGetCertImageMissing(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	// SecretAgentImage set, but GetCertImage empty (injection never runs).
	m := &podMutator{
		decoder: admission.NewDecoder(scheme),
		cfg: Config{
			SecretAgentImage:  "ghcr.io/openbao/openbao:test",
			CDSURL:            "http://cds.c8s-system.svc:8443",
			AttestationApiURL: "http://attestation-api.c8s-system.svc:8400",
			CertDir:           "/etc/c8s/certs",
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationWorkload:            "api",
			AnnotationSecretsInject:       "true",
			secretAnnotationPrefix + "db": "secret/data/api/db#password",
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
	if resp.Allowed {
		t.Fatal("expected admission denied when secrets requested but no get-cert-image configured")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "get-cert-image") {
		t.Fatalf("expected a clear error mentioning get-cert-image, got %#v", resp.Result)
	}
}

// --- helpers ---

func containerNames(cs []corev1.Container) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Name
	}
	return out
}

func findContainer(t *testing.T, cs []corev1.Container, name string) corev1.Container {
	t.Helper()
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("container %q not found in %v", name, containerNames(cs))
	return corev1.Container{}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func assertMemoryVolume(t *testing.T, pod *corev1.Pod, name string) {
	t.Helper()
	for _, v := range pod.Spec.Volumes {
		if v.Name == name {
			if v.EmptyDir == nil || v.EmptyDir.Medium != corev1.StorageMediumMemory {
				t.Fatalf("volume %q must be an in-memory emptyDir, got %#v", name, v.VolumeSource)
			}
			return
		}
	}
	t.Fatalf("volume %q not found", name)
}

func hasReadOnlyMount(c corev1.Container, name, path string) bool {
	for _, m := range c.VolumeMounts {
		if m.Name == name && m.MountPath == path && m.ReadOnly {
			return true
		}
	}
	return false
}
