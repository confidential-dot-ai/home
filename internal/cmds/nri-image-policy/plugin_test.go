package nriimagepolicy

import (
	"context"
	"log/slog"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/audit"
	"github.com/confidential-dot-ai/c8s/internal/cache"
	ctrdresolver "github.com/confidential-dot-ai/c8s/internal/containerd"
	"github.com/containerd/nri/pkg/api"
)

func newTestPlugin(cfg *config) *plugin {
	if err := validateLabelRules(cfg.Policy.LabelRules); err != nil {
		panic(err)
	}
	return &plugin{
		cfg:      cfg,
		resolver: &ctrdresolver.Resolver{},
		audit:    audit.NewLogger(),
		logger:   slog.Default(),
	}
}

func TestCheckImage_MissingAnnotation_DenyEnabled(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			DenyMissingAnnotation: true,
		},
	})

	verdict, reason := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", "")
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason != "container has no image annotation" {
		t.Fatalf("unexpected reason: %s", reason)
	}
}

func TestCheckImage_MissingAnnotation_DenyDisabled(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			DenyMissingAnnotation: false,
		},
	})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "default", "pod", "ctr", "")
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip, got %d", verdict)
	}
}

func TestCheckImage_MissingAnnotation_ExemptNamespace(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			DenyMissingAnnotation: true,
			ExemptNamespaces:      []string{"kube-system"},
		},
	})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "kube-system", "pod", "ctr", "")
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip for exempt namespace, got %d", verdict)
	}
}

func TestCheckImage_NonExemptSystemNamespace(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			DenyMissingAnnotation: true,
			ExemptNamespaces:      []string{"kube-system"},
		},
	})

	verdict, _ := p.checkImage(context.Background(), p.cfg, "kube-node-lease", "pod", "ctr", "")
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny for non-exempt namespace, got %d", verdict)
	}
}

// --- Startup security gap tests ---

func makePod(namespace, name string) *api.PodSandbox {
	return &api.PodSandbox{
		Id:        name + "-id",
		Name:      name,
		Namespace: namespace,
	}
}

func makeCtr(podSandboxID, name string) *api.Container {
	return &api.Container{
		Id:           name + "-id",
		PodSandboxId: podSandboxID,
		Name:         name,
	}
}

func TestCreateContainer_NotReady_DenyNonExempt(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:             "fail-closed",
			ExemptNamespaces: []string{"kube-system"},
		},
	})
	// plugin is NOT ready (default zero value of atomic.Bool is false)

	pod := makePod("default", "mypod")
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error when plugin not ready and namespace non-exempt")
	}
	if err.Error() != "image policy plugin initializing, container creation denied" {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestCreateContainer_NotReady_AllowExemptNamespace(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:             "fail-closed",
			ExemptNamespaces: []string{"kube-system"},
		},
	})

	pod := makePod("kube-system", "coredns")
	ctr := makeCtr(pod.Id, "coredns")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected exempt namespace to be allowed, got error: %v", err)
	}
}

func TestCreateContainer_NotReady_AuditModeAllows(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:             "audit",
			ExemptNamespaces: []string{"kube-system"},
		},
	})

	pod := makePod("default", "mypod")
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected audit mode to allow during init, got error: %v", err)
	}
}

func TestSynchronize_NotReady_Defers(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:            "fail-closed",
			EnforceExisting: true,
		},
	})

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	ctrs := []*api.Container{makeCtr(pods[0].Id, "ctr1")}

	updates, err := p.Synchronize(context.Background(), pods, ctrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates != nil {
		t.Fatal("expected nil updates")
	}

	p.deferredMu.Lock()
	defer p.deferredMu.Unlock()
	if len(p.deferredPods) != 1 {
		t.Fatalf("expected 1 deferred pod, got %d", len(p.deferredPods))
	}
	if len(p.deferredCtrs) != 1 {
		t.Fatalf("expected 1 deferred container, got %d", len(p.deferredCtrs))
	}
}

func TestSynchronize_NotReady_EnforceExistingDisabled_NoDeferral(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:            "fail-closed",
			EnforceExisting: false,
		},
	})

	pods := []*api.PodSandbox{makePod("default", "pod1")}
	ctrs := []*api.Container{makeCtr(pods[0].Id, "ctr1")}

	_, err := p.Synchronize(context.Background(), pods, ctrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p.deferredMu.Lock()
	defer p.deferredMu.Unlock()
	if len(p.deferredPods) != 0 {
		t.Fatalf("expected no deferred pods, got %d", len(p.deferredPods))
	}
}

func TestRunDeferredSweep_NothingDeferred(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:            "fail-closed",
			EnforceExisting: true,
		},
	})
	p.SetReady()

	// Should be a no-op without panic
	p.RunDeferredSweep(context.Background())
}

func TestCreateContainer_Ready_PassesThrough(t *testing.T) {
	policyCache := cache.NewPolicyCache()
	p := &plugin{
		cfg: &config{
			Allowlist: allowlistConfig{Pull: pullConfig{URL: "http://wl.local:8080", Timeout: 30}},
			Policy: policyConfig{
				Mode:                  "fail-closed",
				DenyMissingAnnotation: true,
				ExemptNamespaces:      []string{"kube-system"},
			},
		},
		resolver: &ctrdresolver.Resolver{},
		audit:    audit.NewLogger(),
		logger:   slog.Default(),
		cache:    policyCache,
	}
	p.SetReady()

	// Container with no image annotation and deny_missing_annotation=true
	// should go through the normal path and be denied (not the init guard).
	pod := makePod("default", "mypod")
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error from normal allowlist check path")
	}
	// Should be the "no image annotation" denial, not the "initializing" denial
	if err.Error() == "image policy plugin initializing, container creation denied" {
		t.Fatal("got init guard denial but plugin is ready — should use normal path")
	}
	expected := "container has no image annotation"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

// --- Label selector evaluation tests ---

func makePodWithLabels(namespace, name string, labels map[string]string) *api.PodSandbox {
	return &api.PodSandbox{
		Id:        name + "-id",
		Name:      name,
		Namespace: namespace,
		Labels:    labels,
	}
}

func mustCompileRule(t *testing.T, rule labelRule) labelRule {
	t.Helper()
	rules := []labelRule{rule}
	if err := validateLabelRules(rules); err != nil {
		t.Fatalf("compile label rule: %v", err)
	}
	return rules[0]
}

// --- evaluateRule tests ---

func TestEvaluateRule_AllExpressionsMustMatch(t *testing.T) {
	rule := mustCompileRule(t, labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "In", Values: []string{"acme"}},
			{Key: "team", Operator: "Exists"},
		},
	})
	// Both match
	if !evaluateRule(rule, map[string]string{"tenant": "acme", "team": "backend"}) {
		t.Fatal("expected rule to pass when all expressions match")
	}
	// Only first matches
	if evaluateRule(rule, map[string]string{"tenant": "acme"}) {
		t.Fatal("expected rule to fail when not all expressions match")
	}
}

func TestEvaluateRule_NilLabels(t *testing.T) {
	rule := mustCompileRule(t, labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "Exists"},
		},
	})
	if evaluateRule(rule, nil) {
		t.Fatal("expected rule to fail with nil labels")
	}
}

func TestEvaluateRule_DoesNotExist_NilLabels(t *testing.T) {
	rule := mustCompileRule(t, labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "privileged", Operator: "DoesNotExist"},
		},
	})
	if !evaluateRule(rule, nil) {
		t.Fatal("expected DoesNotExist to pass with nil labels")
	}
}

func TestEvaluateRule_UncompiledRuleFailsClosed(t *testing.T) {
	rule := labelRule{
		Name: "test",
		MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "Exists"},
		},
	}
	if evaluateRule(rule, map[string]string{"tenant": "acme"}) {
		t.Fatal("uncompiled label rule should fail closed")
	}
}

// --- checkLabels tests ---

func TestCheckLabels_ExemptNamespace(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			ExemptNamespaces: []string{"kube-system"},
			LabelRules: []labelRule{
				{Name: "require-tenant", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "Exists"},
				}},
			},
		},
	})

	verdict, _ := p.checkLabels(p.cfg, "kube-system", "pod", "ctr", nil)
	if verdict != verdictSkip {
		t.Fatalf("expected verdictSkip for exempt namespace, got %d", verdict)
	}
}

func TestCheckLabels_RuleViolation(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme", "beta"}},
				}},
			},
		},
	})

	// Pod with wrong tenant value
	verdict, reason := p.checkLabels(p.cfg, "default", "pod", "ctr",
		map[string]string{"tenant": "gamma"})
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason != `label rule "allowed-tenants" denied workload` {
		t.Fatalf("unexpected reason: %s", reason)
	}
}

func TestCheckLabels_AllRulesPass(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme", "beta"}},
				}},
				{Name: "no-privileged", MatchExpressions: []labelExpression{
					{Key: "privileged", Operator: "DoesNotExist"},
				}},
			},
		},
	})

	verdict, _ := p.checkLabels(p.cfg, "default", "pod", "ctr",
		map[string]string{"tenant": "acme"})
	if verdict != verdictAllow {
		t.Fatalf("expected verdictAllow, got %d", verdict)
	}
}

func TestCheckLabels_FirstViolationWins(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			LabelRules: []labelRule{
				{Name: "first-rule", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "Exists"},
				}},
				{Name: "second-rule", MatchExpressions: []labelExpression{
					{Key: "team", Operator: "Exists"},
				}},
			},
		},
	})

	// Both rules violated — first should be reported
	verdict, reason := p.checkLabels(p.cfg, "default", "pod", "ctr", map[string]string{})
	if verdict != verdictDeny {
		t.Fatalf("expected verdictDeny, got %d", verdict)
	}
	if reason != `label rule "first-rule" denied workload` {
		t.Fatalf("expected first rule to be reported, got: %s", reason)
	}
}

// --- CreateContainer with label rules ---

func TestCreateContainer_LabelRuleDeny_FailClosed(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode: "fail-closed",
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme"}},
				}},
			},
		},
	})
	p.SetReady()

	pod := makePodWithLabels("default", "mypod", map[string]string{"tenant": "evil"})
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error from label rule denial")
	}
	if err.Error() != `label rule "allowed-tenants" denied workload` {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestCreateContainer_LabelRuleDeny_AuditMode(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode: "audit",
			LabelRules: []labelRule{
				{Name: "allowed-tenants", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "In", Values: []string{"acme"}},
				}},
			},
		},
	})
	p.SetReady()

	pod := makePodWithLabels("default", "mypod", map[string]string{"tenant": "evil"})
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected audit mode to allow, got error: %v", err)
	}
}

func TestCreateContainer_AllowlistDisabled_SkipsImageCheck(t *testing.T) {
	p := newTestPlugin(&config{
		Policy: policyConfig{
			Mode:                  "fail-closed",
			DenyMissingAnnotation: true,
			LabelRules: []labelRule{
				{Name: "require-tenant", MatchExpressions: []labelExpression{
					{Key: "tenant", Operator: "Exists"},
				}},
			},
		},
	})
	p.SetReady()

	// Pod has tenant label, no image annotation — should pass because
	// allowlist is disabled (no URL), image check is skipped.
	pod := makePodWithLabels("default", "mypod", map[string]string{"tenant": "acme"})
	ctr := makeCtr(pod.Id, "myctr")

	_, _, err := p.CreateContainer(context.Background(), pod, ctr)
	if err != nil {
		t.Fatalf("expected no error with allowlist disabled, got: %v", err)
	}
}
