package webhook

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Secrets-injection annotations. A pod opts in with confidential.ai/secrets-inject
// (and must already carry confidential.ai/cw for its mesh identity). Each secret
// to template is one confidential.ai/secret-<name> annotation whose value is
// "<vault-path>[#<field>]".
const (
	AnnotationSecretsInject = "confidential.ai/secrets-inject"
	AnnotationSecretsDir    = "confidential.ai/secrets-dir"
	AnnotationSecretsBroker = "confidential.ai/secrets-broker"
	AnnotationSecretsRenew  = "confidential.ai/secrets-renew"
	secretAnnotationPrefix  = "confidential.ai/secret-"
)

// In-pod paths for the injected agent. Both volumes are in-memory: secrets and
// the broker token never touch disk.
const (
	secretsConfigVolume = "c8s-secrets-config"
	secretsDataVolume   = "c8s-secrets"
	secretsConfigDir    = "/vault/config"
	secretsConfigPath   = secretsConfigDir + "/agent.hcl"
	secretsTokenSink    = secretsConfigDir + "/.agent-token"
	defaultSecretsDir   = "/vault/secrets"
)

type secretEntry struct {
	Name  string
	Path  string
	Field string
}

// secretsInjection captures the secrets-injection request parsed from a pod.
type secretsInjection struct {
	Entries    []secretEntry
	BrokerURL  string // override; falls back to Config.SecretBrokerURL
	SecretsDir string
	Renew      bool
}

// parseSecretsInjection returns nil when the pod does not opt in. It collects
// confidential.ai/secret-<name> entries deterministically (sorted by name).
func parseSecretsInjection(annotations map[string]string) (*secretsInjection, error) {
	on, err := boolAnnotation(annotations, AnnotationSecretsInject)
	if err != nil {
		return nil, err
	}
	if !on {
		if hasSecretEntryAnnotations(annotations) {
			return nil, fmt.Errorf("%w: %s is required when %s-<name> annotations are set",
				errInvalidInjectionAnnotation, AnnotationSecretsInject, secretAnnotationPrefix)
		}
		return nil, nil
	}

	si := &secretsInjection{
		BrokerURL:  strings.TrimSpace(annotations[AnnotationSecretsBroker]),
		SecretsDir: strings.TrimSpace(annotations[AnnotationSecretsDir]),
	}
	if si.Renew, err = boolAnnotation(annotations, AnnotationSecretsRenew); err != nil {
		return nil, err
	}
	for k, v := range annotations {
		if !strings.HasPrefix(k, secretAnnotationPrefix) {
			continue
		}
		name := strings.TrimPrefix(k, secretAnnotationPrefix)
		entry, err := parseSecretEntry(name, v)
		if err != nil {
			return nil, err
		}
		si.Entries = append(si.Entries, entry)
	}
	if len(si.Entries) == 0 {
		return nil, fmt.Errorf("%w: %s is set but no %s-<name> secrets are declared",
			errInvalidInjectionAnnotation, AnnotationSecretsInject, secretAnnotationPrefix)
	}
	sort.Slice(si.Entries, func(i, j int) bool { return si.Entries[i].Name < si.Entries[j].Name })
	return si, nil
}

func parseSecretEntry(name, value string) (secretEntry, error) {
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		return secretEntry{}, fmt.Errorf("%w: secret name %q must be a valid filename label: %s",
			errInvalidInjectionAnnotation, name, strings.Join(errs, "; "))
	}
	path, field, _ := strings.Cut(strings.TrimSpace(value), "#")
	if path == "" {
		return secretEntry{}, fmt.Errorf("%w: secret %q has an empty path", errInvalidInjectionAnnotation, name)
	}
	return secretEntry{Name: name, Path: path, Field: field}, nil
}

func hasSecretEntryAnnotations(annotations map[string]string) bool {
	for k := range annotations {
		if strings.HasPrefix(k, secretAnnotationPrefix) {
			return true
		}
	}
	return false
}

// injectSecrets adds the OpenBao/Vault Agent that templates the pod's secrets.
// It runs after mutatePod, so the c8s-cert sidecar and shared cert volume
// already exist. The injected init containers are ordered after c8s-cert-wait —
// the agent dials the broker with the mesh client cert + CA, and only the wait
// gate guarantees those files are on disk (the c8s-cert sidecar is "started",
// not done, when the next init container runs):
//
//	c8s-cert (native sidecar)  → provides the mesh cert + CA
//	c8s-cert-wait              → gates on the initial cert being written
//	c8s-secrets-config         → renders the agent config (c8s image)
//	c8s-secrets-agent-init     → one-shot agent: auth + template, gates the app
//	c8s-secrets-agent          → optional renewal sidecar (Renew)
func injectSecrets(pod *corev1.Pod, eff injection, cfg Config) {
	si := eff.Secrets
	secretsDir := si.SecretsDir
	if secretsDir == "" {
		secretsDir = defaultSecretsDir
	}
	brokerURL := si.BrokerURL
	if brokerURL == "" {
		brokerURL = cfg.SecretBrokerURL
	}

	ensureVolume(pod, memoryVolume(secretsConfigVolume))
	ensureVolume(pod, memoryVolume(secretsDataVolume))

	// App containers see the templated secrets read-only.
	mountAll(pod, corev1.VolumeMount{Name: secretsDataVolume, MountPath: secretsDir, ReadOnly: true})

	inits := []corev1.Container{
		agentConfigContainer(cfg, eff, brokerURL, secretsDir),
		agentContainer("c8s-secrets-agent-init", cfg, eff, secretsDir, true),
	}
	if si.Renew {
		inits = append(inits, agentContainer("c8s-secrets-agent", cfg, eff, secretsDir, false))
	}
	pod.Spec.InitContainers = insertAfterContainer(pod.Spec.InitContainers, reservedCertWaitContainerName, inits)
}

// agentConfigContainer renders the agent config inside the measured c8s image,
// so no control-plane object carries it.
func agentConfigContainer(cfg Config, eff injection, brokerURL, secretsDir string) corev1.Container {
	certDir := eff.Cert.Dir
	args := []string{
		"secret-agent-config",
		"--out=" + secretsConfigPath,
		"--broker-addr=" + brokerURL,
		"--ca=" + certPath(certDir, "ca.crt"),
		"--client-cert=" + certPath(certDir, eff.Cert.CertFile),
		"--client-key=" + certPath(certDir, eff.Cert.KeyFile),
		"--token-sink=" + secretsTokenSink,
		"--secrets-dir=" + secretsDir,
	}
	for _, e := range eff.Secrets.Entries {
		spec := e.Name + "=" + e.Path
		if e.Field != "" {
			spec += "#" + e.Field
		}
		args = append(args, "--secret="+spec)
	}
	return corev1.Container{
		Name:            "c8s-secrets-config",
		Image:           cfg.GetCertImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Args:            args,
		VolumeMounts: []corev1.VolumeMount{
			{Name: secretsConfigVolume, MountPath: secretsConfigDir},
		},
		SecurityContext: agentSecurityContext(),
	}
}

// agentContainer runs the OpenBao/Vault Agent. The init variant exits after the
// first auth+template (gating the workload on its secrets); the renewal variant
// is a native sidecar. It mounts the same cert volume the get-cert sidecar
// populates, plus the in-memory config and secrets volumes.
func agentContainer(name string, cfg Config, eff injection, secretsDir string, exitAfterAuth bool) corev1.Container {
	command := []string{cfg.secretAgentCommand(), "agent", "-config=" + secretsConfigPath}
	if exitAfterAuth {
		command = append(command, "-exit-after-auth=true")
	}
	c := corev1.Container{
		Name:            name,
		Image:           cfg.SecretAgentImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         command,
		VolumeMounts: []corev1.VolumeMount{
			{Name: eff.Cert.Volume, MountPath: eff.Cert.Dir, ReadOnly: true},
			{Name: secretsConfigVolume, MountPath: secretsConfigDir},
			{Name: secretsDataVolume, MountPath: secretsDir},
		},
		SecurityContext: vaultAgentSecurityContext(),
	}
	if !exitAfterAuth {
		always := corev1.ContainerRestartPolicyAlways
		c.RestartPolicy = &always
	}
	return c
}

func (cfg Config) secretAgentCommand() string {
	if cfg.SecretAgentCommand != "" {
		return cfg.SecretAgentCommand
	}
	return "bao"
}

// agentSecurityContext is the strict context for the c8s-owned config-render
// init container, which runs the c8s image and needs no privileged bits.
func agentSecurityContext() *corev1.SecurityContext {
	f, tr := false, true
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &f,
		ReadOnlyRootFilesystem:   &tr,
		RunAsNonRoot:             &tr,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

// vaultAgentSecurityContext pins the OpenBao/Vault Agent container to the same
// non-root UID (65532) the c8s-secrets-config init container uses. That's the
// minimum needed for the agent to read the config file c8s-secrets-config
// wrote (drop-ALL caps means no CAP_DAC_OVERRIDE, so root cannot bypass file
// ownership), and it satisfies the RunAsNonRoot check kubelet applies to the
// openbao image (whose Dockerfile has no USER directive → defaults to root).
// The k8s container Command overrides the openbao Dockerfile's ENTRYPOINT, so
// docker-entrypoint.sh's chown-then-su-exec dance doesn't run — the `bao`
// binary runs directly, which happily starts as an arbitrary non-root UID.
func vaultAgentSecurityContext() *corev1.SecurityContext {
	f, tr := false, true
	var uid, gid int64 = 65532, 65532
	return &corev1.SecurityContext{
		AllowPrivilegeEscalation: &f,
		RunAsNonRoot:             &tr,
		RunAsUser:                &uid,
		RunAsGroup:               &gid,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

func memoryVolume(name string) corev1.Volume {
	return corev1.Volume{
		Name:         name,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}},
	}
}

// insertAfterContainer inserts items immediately after the container named
// target, dropping any existing container that collides with an injected name —
// same rule as injectInitContainers, so reinvocation (reinvocationPolicy:
// IfNeeded) converges and a pre-declared name cannot shadow the injected
// container. If target is absent, items are prepended (they still precede the
// workload's own init containers).
func insertAfterContainer(existing []corev1.Container, target string, items []corev1.Container) []corev1.Container {
	injected := make(map[string]struct{}, len(items))
	for _, c := range items {
		injected[c.Name] = struct{}{}
	}
	kept := make([]corev1.Container, 0, len(existing))
	for _, ec := range existing {
		if _, ok := injected[ec.Name]; !ok {
			kept = append(kept, ec)
		}
	}
	idx := -1
	for i, c := range kept {
		if c.Name == target {
			idx = i
			break
		}
	}
	if idx < 0 {
		return append(append([]corev1.Container{}, items...), kept...)
	}
	out := make([]corev1.Container, 0, len(kept)+len(items))
	out = append(out, kept[:idx+1]...)
	out = append(out, items...)
	out = append(out, kept[idx+1:]...)
	return out
}
