package nriimagepolicy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/internal/cache"
	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
)

const (
	pluginName = "image-policy"
	pluginIdx  = "00"

	// Kubernetes CRI annotations for image info
	annotationImageName = "io.kubernetes.cri.image-name"
)

// imageVerdict is the result of checking an image against the allowlist.
type imageVerdict int

const (
	verdictAllow imageVerdict = iota
	verdictDeny
	verdictSkip // exempt namespace, etc.
)

// plugin implements the NRI plugin interface for image policy enforcement.
type plugin struct {
	stub     stub.Stub
	cfg      *config
	resolver *ctrdresolver.Resolver
	cache    *cache.PolicyCache
	audit    *audit.Logger
	logger   *slog.Logger
	ready    atomic.Bool

	// broker serves the workload-claims flow (docs/ratls.md).
	broker *workloadBroker

	// Deferred sweep: pods/containers observed during Synchronize before
	// the plugin is ready, replayed once the cache has a allowlist.
	deferredMu   sync.Mutex
	deferredPods []*api.PodSandbox
	deferredCtrs []*api.Container
}

func newPlugin(
	cfg *config,
	resolver *ctrdresolver.Resolver,
	policyCache *cache.PolicyCache,
	auditLogger *audit.Logger,
	logger *slog.Logger,
) (*plugin, error) {
	p := &plugin{
		cfg:      cfg,
		resolver: resolver,
		cache:    policyCache,
		audit:    auditLogger,
		logger:   logger,
	}
	if cfg.WorkloadClaims.SocketDir != "" {
		procRoot := cfg.WorkloadClaims.ProcRoot
		if procRoot == "" {
			procRoot = "/proc"
		}
		p.broker = newWorkloadBroker(procRoot)
	}

	// Check if running as pre-installed plugin (containerd sets these env vars)
	isPreInstalled := os.Getenv("NRI_PLUGIN_NAME") != ""

	var opts []stub.Option
	if !isPreInstalled {
		// Only set name/idx for external plugins - pre-installed plugins
		// get these from environment variables set by containerd
		opts = append(opts,
			stub.WithPluginName(pluginName),
			stub.WithPluginIdx(pluginIdx),
		)
	} else {
		logger.Info("running as pre-installed plugin",
			"NRI_PLUGIN_NAME", os.Getenv("NRI_PLUGIN_NAME"),
			"NRI_PLUGIN_IDX", os.Getenv("NRI_PLUGIN_IDX"),
			"NRI_PLUGIN_SOCKET", os.Getenv(api.PluginSocketEnvVar),
		)
	}

	s, err := stub.New(p, opts...)
	if err != nil {
		return nil, fmt.Errorf("create NRI stub: %w", err)
	}
	p.stub = s

	return p, nil
}

// Ready returns true when the plugin has a allowlist loaded and is serving.
func (p *plugin) Ready() bool {
	return p.ready.Load()
}

// SetReady marks the plugin as ready to serve.
func (p *plugin) SetReady() {
	p.ready.Store(true)
}

// Run starts the plugin and blocks until context is cancelled.
func (p *plugin) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		p.stub.Stop()
	}()

	return p.stub.Run(ctx)
}

// Configure is called when the plugin is registered with the runtime.
func (p *plugin) Configure(ctx context.Context, config, runtime, version string) (api.EventMask, error) {
	p.logger.Info("plugin configured",
		"runtime", runtime,
		"version", version,
	)

	var mask api.EventMask
	mask.Set(api.Event_CREATE_CONTAINER)
	if p.broker != nil {
		// The broker needs eviction on stop to stay correct across pod churn.
		mask.Set(api.Event_REMOVE_CONTAINER)
	}
	return mask, nil
}

// RemoveContainer evicts a stopped container from the workload-claims broker.
// Only subscribed when the broker is enabled (see Configure).
func (p *plugin) RemoveContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	if p.broker != nil {
		p.broker.remove(ctr.GetId())
	}
	return nil
}

// recordForBroker resolves a container's admitted image digest and records it
// for the workload-claims broker. A resolve failure records an empty digest,
// which the broker omits from its answer — so the pod's workload claim commits
// a SUBSET of its images. That weakens `--workload-image` (a pin-holding
// verifier still catches the resulting mismatch, but the whole-set property is
// lost for that image), so it is logged at error, not swallowed. It never
// blocks the create path: admission already decided the container.
// See docs/getcert-workload-binding.md, Corner 3 (whole-set-per-role).
func (p *plugin) recordForBroker(ctx context.Context, ctr *api.Container, imageRef string) {
	if p.broker == nil {
		return
	}
	digest := extractDigest(imageRef)
	if digest == "" && imageRef != "" {
		if resolved, err := p.resolver.Resolve(ctx, imageRef); err == nil {
			digest = extractDigest(resolved)
		} else {
			p.logger.Error("workload-claims: cannot resolve admitted image digest; container will be absent from the workload claim", "image", imageRef, "error", err)
		}
	}
	p.broker.record(ctr.GetId(), ctr.GetPodSandboxId(), ctr.GetName(), digest)
}

// evaluateRule checks whether a pod satisfies a compiled Kubernetes selector.
// Returns true if the pod satisfies the rule (i.e. should be allowed).
func evaluateRule(rule labelRule, podLabels map[string]string) bool {
	if rule.selector == nil {
		return false
	}
	return rule.selector.Matches(labels.Set(podLabels))
}

// checkLabels evaluates all label rules against a pod's labels.
// Returns verdictSkip for exempt namespaces, verdictDeny if any rule is violated,
// or verdictAllow if all rules pass.
func (p *plugin) checkLabels(cfg *config, namespace, podName, containerName string, podLabels map[string]string) (imageVerdict, string) {
	if slices.Contains(cfg.Policy.ExemptNamespaces, namespace) {
		return verdictSkip, ""
	}

	for _, rule := range cfg.Policy.LabelRules {
		if !evaluateRule(rule, podLabels) {
			reason := fmt.Sprintf("label rule %q denied workload", rule.Name)
			p.logger.Warn("label rule violated",
				"rule", rule.Name,
				"namespace", namespace,
				"pod", podName,
				"container", containerName,
			)
			p.audit.Log(audit.Event{
				Action:    "deny",
				Reason:    "label_rule",
				Rule:      rule.Name,
				Namespace: namespace,
				Pod:       podName,
				Container: containerName,
			})
			return verdictDeny, reason
		}
	}
	return verdictAllow, ""
}

// checkImage validates a container's image against the allowlist.
// Returns the verdict and an error string (empty if none).
func (p *plugin) checkImage(ctx context.Context, cfg *config, namespace, podName, containerName, imageRef string) (imageVerdict, string) {
	log := p.logger.With(
		"namespace", namespace,
		"pod", podName,
		"container", containerName,
		"image", imageRef,
	)

	// Check if namespace is exempt
	if slices.Contains(cfg.Policy.ExemptNamespaces, namespace) {
		log.Info("namespace exempt from policy")
		p.audit.Log(audit.Event{
			Action:    "allow",
			Reason:    "namespace_exempt",
			Namespace: namespace,
			Pod:       podName,
			Container: containerName,
			Image:     imageRef,
		})
		return verdictSkip, ""
	}

	// If no image ref found, deny by default (missing annotation means kubelet was bypassed)
	if imageRef == "" {
		if cfg.Policy.DenyMissingAnnotation {
			log.Warn("no image reference found in annotations, denying")
			p.audit.Log(audit.Event{
				Action:    "deny",
				Reason:    "no_image_annotation",
				Namespace: namespace,
				Pod:       podName,
				Container: containerName,
			})
			return verdictDeny, "container has no image annotation"
		}
		log.Warn("no image reference found in annotations, allowing (deny_missing_annotation disabled)")
		p.audit.Log(audit.Event{
			Action:    "allow",
			Reason:    "no_image_annotation",
			Namespace: namespace,
			Pod:       podName,
			Container: containerName,
		})
		return verdictSkip, ""
	}

	// Extract digest from image reference (e.g. repo@sha256:abc)
	digest := extractDigest(imageRef)
	if digest == "" {
		// No digest in reference — resolve tag via containerd image store
		resolved, err := p.resolver.Resolve(ctx, imageRef)
		if err != nil {
			log.Warn("cannot resolve image digest via containerd", "error", err)
			p.audit.Log(audit.Event{
				Action:    "deny",
				Reason:    "resolve_failed",
				Namespace: namespace,
				Pod:       podName,
				Container: containerName,
				Image:     imageRef,
				Error:     err.Error(),
			})
			return verdictDeny, fmt.Sprintf("cannot resolve digest for %s: %v", imageRef, err)
		}
		digest = resolved
		log.Debug("resolved tag to digest via containerd", "digest", digest)
	}

	wl := p.cache.GetAllowlist()
	if wl == nil {
		log.Error("no cached allowlist; denying")
		p.audit.Log(audit.Event{
			Action:    "deny",
			Reason:    "no_allowlist_available",
			Namespace: namespace,
			Pod:       podName,
			Container: containerName,
			Image:     imageRef,
		})
		return verdictDeny, fmt.Sprintf("no allowlist available for %s", imageRef)
	}

	// Check digest against allowlist
	if !wl.Contains(digest) {
		log.Warn("image not in allowlist", "digest", digest)
		p.audit.Log(audit.Event{
			Action:    "deny",
			Reason:    "not_in_allowlist",
			Namespace: namespace,
			Pod:       podName,
			Container: containerName,
			Image:     imageRef,
		})
		return verdictDeny, fmt.Sprintf("image not in allowlist: %s", imageRef)
	}

	// All checks passed
	log.Info("image allowed")
	p.audit.Log(audit.Event{
		Action:    "allow",
		Reason:    "verified",
		Namespace: namespace,
		Pod:       podName,
		Container: containerName,
		Image:     imageRef,
	})
	return verdictAllow, ""
}

// Synchronize is called when the plugin connects to containerd.
// It checks all existing containers against the allowlist and kills violations.
func (p *plugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, ctrs []*api.Container) ([]*api.ContainerUpdate, error) {
	cfg := p.cfg

	if !cfg.Policy.EnforceExisting {
		p.logger.Info("startup sweep disabled", "pods", len(pods), "containers", len(ctrs))
		return nil, nil
	}

	// If not ready yet, defer the sweep until after CDS init completes.
	if !p.Ready() {
		p.logger.Info("plugin not ready, deferring startup sweep",
			"pods", len(pods), "containers", len(ctrs))
		p.deferredMu.Lock()
		p.deferredPods = pods
		p.deferredCtrs = ctrs
		p.deferredMu.Unlock()
		return nil, nil
	}

	p.runSweep(ctx, cfg, pods, ctrs)
	return nil, nil
}

// runSweep checks all existing containers against the allowlist and kills violations.
func (p *plugin) runSweep(ctx context.Context, cfg *config, pods []*api.PodSandbox, ctrs []*api.Container) {
	p.logger.Info("startup sweep: checking existing containers", "pods", len(pods), "containers", len(ctrs))

	// Build pod lookup by sandbox ID
	podByID := make(map[string]*api.PodSandbox, len(pods))
	for _, pod := range pods {
		podByID[pod.GetId()] = pod
	}

	var killed, failed int
	for _, ctr := range ctrs {
		pod := podByID[ctr.GetPodSandboxId()]
		if pod == nil {
			continue
		}

		denied := false

		labelVerdict, _ := p.checkLabels(cfg, pod.GetNamespace(), pod.GetName(), ctr.GetName(), pod.GetLabels())
		if labelVerdict == verdictSkip {
			continue
		}
		if labelVerdict == verdictDeny {
			denied = true
		}

		if !denied && cfg.AllowlistEnabled() {
			imageRef := ctr.GetAnnotations()[annotationImageName]
			imgVerdict, _ := p.checkImage(ctx, cfg, pod.GetNamespace(), pod.GetName(), ctr.GetName(), imageRef)
			if imgVerdict == verdictDeny {
				denied = true
			} else {
				p.recordForBroker(ctx, ctr, imageRef)
			}
		}

		if !denied {
			continue
		}

		if cfg.Policy.Mode == ModeAudit {
			continue
		}

		if err := p.resolver.StopContainer(ctx, ctr.GetId()); err != nil {
			p.logger.Error("sync: failed to kill container", "container", ctr.GetName(), "error", err)
			failed++
		} else {
			killed++
		}
	}

	p.logger.Info("startup sweep complete", "killed", killed, "failed", failed, "checked", len(ctrs))
}

// RunDeferredSweep runs the startup sweep on pods/containers that were seen
// during Synchronize before the plugin was ready. Should be called after
// SetReady and CDS init.
func (p *plugin) RunDeferredSweep(ctx context.Context) {
	cfg := p.cfg

	if !cfg.Policy.EnforceExisting {
		return
	}

	p.deferredMu.Lock()
	pods := p.deferredPods
	ctrs := p.deferredCtrs
	p.deferredPods = nil
	p.deferredCtrs = nil
	p.deferredMu.Unlock()

	if len(ctrs) == 0 {
		p.logger.Info("no deferred containers to sweep")
		return
	}

	p.logger.Info("running deferred startup sweep", "pods", len(pods), "containers", len(ctrs))
	p.runSweep(ctx, cfg, pods, ctrs)
}

// CreateContainer is called when a container is being created.
// Returning an error will reject the container creation.
func (p *plugin) CreateContainer(ctx context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	cfg := p.cfg

	// Not-ready guard: plugin is registered with NRI but allowlist hasn't
	// been fetched yet. Deny all non-exempt container creation to close
	// the startup window.
	if !p.Ready() {
		// Exempt namespaces always pass (prevents deadlock when CDS itself
		// runs in-cluster inside an exempt namespace).
		if slices.Contains(cfg.Policy.ExemptNamespaces, pod.GetNamespace()) {
			p.logger.Info("plugin initializing: allowing container in exempt namespace",
				"namespace", pod.GetNamespace(),
				"pod", pod.GetName(),
				"container", ctr.GetName(),
			)
			return nil, nil, nil
		}

		if cfg.Policy.Mode == ModeAudit {
			p.logger.Warn("plugin initializing: would deny container creation (audit mode)",
				"namespace", pod.GetNamespace(),
				"pod", pod.GetName(),
				"container", ctr.GetName(),
			)
			return nil, nil, nil
		}

		p.logger.Warn("plugin initializing: denying container creation",
			"namespace", pod.GetNamespace(),
			"pod", pod.GetName(),
			"container", ctr.GetName(),
		)
		return nil, nil, fmt.Errorf("image policy plugin initializing, container creation denied")
	}

	// Label-based policy check (fast, no I/O — runs before image check)
	labelVerdict, labelReason := p.checkLabels(cfg, pod.GetNamespace(), pod.GetName(), ctr.GetName(), pod.GetLabels())
	if labelVerdict == verdictDeny {
		if cfg.Policy.Mode == ModeAudit {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("%s", labelReason)
	}
	if labelVerdict == verdictSkip {
		return nil, nil, nil
	}

	// Image allowlist check (only when configured)
	if cfg.AllowlistEnabled() {
		annotations := ctr.GetAnnotations()
		imageRef := annotations[annotationImageName]
		if imageRef == "" {
			podAnnotations := pod.GetAnnotations()
			imageRef = podAnnotations[annotationImageName]
		}

		verdict, reason := p.checkImage(ctx, cfg, pod.GetNamespace(), pod.GetName(), ctr.GetName(), imageRef)
		if verdict == verdictDeny {
			if cfg.Policy.Mode == ModeAudit {
				return nil, nil, nil
			}
			return nil, nil, fmt.Errorf("%s", reason)
		}
		// Admitted: record for the workload-claims broker.
		p.recordForBroker(ctx, ctr, imageRef)
	}

	return nil, nil, nil
}

// extractDigest extracts the digest from an image reference.
// Returns empty string if no digest is present.
func extractDigest(imageRef string) string {
	// Format: registry/repo@sha256:abc123 or registry/repo:tag@sha256:abc123
	if idx := strings.LastIndex(imageRef, "@"); idx != -1 {
		return imageRef[idx+1:]
	}
	return ""
}
