package nriimagepolicy

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// config represents the plugin configuration.
type config struct {
	Plugin     pluginConfig     `yaml:"plugin"`
	Allowlist  allowlistConfig  `yaml:"allowlist"`
	Containerd containerdConfig `yaml:"containerd"`
	Policy     policyConfig     `yaml:"policy"`
	Logging    loggingConfig    `yaml:"logging"`
}

// pluginConfig contains plugin runtime settings.
type pluginConfig struct {
	// HealthAddr is the listen address for the readiness/liveness HTTP
	// server. `host:port` selects TCP; `unix:///path/to.sock` selects a
	// Unix socket.
	HealthAddr string `yaml:"health_addr"`
}

// allowlistConfig groups the digest-source mechanisms.
//
// AlwaysAllow is a static baseline, always merged into the cache at
// startup (the chart's floor: self-allows the installer + the CDS digest,
// so a floor-rewrite roll admits the new images without a network round-trip).
// Pull is the runtime-update source: every plugin polls CDS.
type allowlistConfig struct {
	AlwaysAllow map[string]string `yaml:"always_allow"`
	Pull        pullConfig        `yaml:"pull"`
}

// pullConfig configures the CDS polling source.
type pullConfig struct {
	URL               string        `yaml:"url"`                 // empty disables pull
	Interval          time.Duration `yaml:"interval"`            // ticker cadence; > 0 required when URL is set
	Timeout           time.Duration `yaml:"timeout"`             // per-request timeout; > 0 required when URL is set
	AttestationApiURL string        `yaml:"attestation_api_url"` // required for https pull
	CDSMeasurements   []string      `yaml:"cds_measurements"`    // SHA-384 hex launch digests
}

// containerdConfig contains containerd connection settings for tag-to-digest resolution.
type containerdConfig struct {
	Socket    string `yaml:"socket"`
	Namespace string `yaml:"namespace"`
}

// policyConfig contains policy enforcement settings.
type policyConfig struct {
	Mode                  string      `yaml:"mode"`                    // fail-closed, audit
	EnforceExisting       bool        `yaml:"enforce_existing"`        // kill non-allowlisted containers on startup
	DenyMissingAnnotation bool        `yaml:"deny_missing_annotation"` // deny containers without image annotation
	ExemptNamespaces      []string    `yaml:"exempt_namespaces"`
	LabelRules            []labelRule `yaml:"label_rules"`
}

// labelRule defines a constraint on pod labels. Pods that do not satisfy
// all match expressions are denied.
type labelRule struct {
	Name             string            `yaml:"name"`
	MatchExpressions []labelExpression `yaml:"match_expressions"`
	selector         labels.Selector   `yaml:"-"`
}

// labelExpression is a single label selector requirement (Kubernetes-style).
type labelExpression struct {
	Key      string   `yaml:"key"`
	Operator string   `yaml:"operator"` // In, NotIn, Exists, DoesNotExist
	Values   []string `yaml:"values"`
}

// Label expression operators.
const (
	OpIn           = "In"
	OpNotIn        = "NotIn"
	OpExists       = "Exists"
	OpDoesNotExist = "DoesNotExist"
)

// Policy modes.
const (
	ModeFailClosed = "fail-closed"
	ModeAudit      = "audit"
)

// loggingConfig contains logging settings.
type loggingConfig struct {
	Level string `yaml:"level"`
}

const defaultPullInterval = 30 * time.Second
const defaultPullTimeout = 30 * time.Second

// loadConfig loads configuration from a YAML file.
func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &config{
		Allowlist: allowlistConfig{
			Pull: pullConfig{
				Interval: defaultPullInterval,
				Timeout:  defaultPullTimeout,
			},
		},
		Containerd: containerdConfig{
			Socket:    "/run/containerd/containerd.sock",
			Namespace: "k8s.io",
		},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			EnforceExisting:       true,
			DenyMissingAnnotation: true,
		},
		Logging: loggingConfig{
			Level: "info",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// PullEnabled reports whether the plugin should poll a remote CDS.
func (c *config) PullEnabled() bool { return c.Allowlist.Pull.URL != "" }

// AllowlistEnabled reports whether any digest-based enforcement is active.
func (c *config) AllowlistEnabled() bool {
	return c.PullEnabled() || len(c.Allowlist.AlwaysAllow) > 0
}

// Validate checks the configuration for errors.
func (c *config) Validate() error {
	if c.PullEnabled() && len(c.Allowlist.AlwaysAllow) == 0 {
		return fmt.Errorf("allowlist.always_allow must be non-empty when pull is configured (cold-boot baseline)")
	}
	for d := range c.Allowlist.AlwaysAllow {
		if _, err := types.ParseDigest(d); err != nil {
			return fmt.Errorf("allowlist.always_allow: invalid digest %q (expected sha256:<64 hex chars>)", d)
		}
	}
	if c.PullEnabled() {
		if c.Allowlist.Pull.Timeout <= 0 {
			return fmt.Errorf("allowlist.pull.timeout must be > 0 when pull.url is set")
		}
		if c.Allowlist.Pull.Interval <= 0 {
			return fmt.Errorf("allowlist.pull.interval must be > 0 when pull.url is set")
		}
		parsed, err := url.Parse(c.Allowlist.Pull.URL)
		if err != nil {
			return fmt.Errorf("allowlist.pull.url: %w", err)
		}
		// CDS serves RA-TLS only, so the pull URL must be https — a plaintext
		// pull would defeat the attestation handshake entirely.
		if parsed.Scheme != "https" {
			return fmt.Errorf("allowlist.pull.url scheme must be https, got %q", parsed.Scheme)
		}
		if c.Allowlist.Pull.AttestationApiURL == "" {
			return fmt.Errorf("allowlist.pull.attestation_api_url must be set")
		}
		if _, err := ratls.ParseHexMeasurementsList(c.Allowlist.Pull.CDSMeasurements); err != nil {
			return fmt.Errorf("allowlist.pull.cds_measurements: %w", err)
		}
	}
	if !c.AllowlistEnabled() && len(c.Policy.LabelRules) == 0 {
		return fmt.Errorf("set allowlist.always_allow (required when pull is enabled) or configure policy.label_rules")
	}
	if c.Policy.Mode != ModeFailClosed && c.Policy.Mode != ModeAudit {
		return fmt.Errorf("policy.mode must be '%s' or '%s'", ModeFailClosed, ModeAudit)
	}
	return validateLabelRules(c.Policy.LabelRules)
}

// validateLabelRules checks label rules for errors.
func validateLabelRules(rules []labelRule) error {
	seen := make(map[string]bool, len(rules))
	for i := range rules {
		r := rules[i]
		if r.Name == "" {
			return fmt.Errorf("label_rules[%d]: name must be set", i)
		}
		if seen[r.Name] {
			return fmt.Errorf("label_rules[%d]: duplicate name %q", i, r.Name)
		}
		seen[r.Name] = true
		if len(r.MatchExpressions) == 0 {
			return fmt.Errorf("label_rules[%d] %q: at least one match_expression required", i, r.Name)
		}
		selector, err := buildLabelSelector(r)
		if err != nil {
			return fmt.Errorf("label_rules[%d] %q: %w", i, r.Name, err)
		}
		rules[i].selector = selector
	}
	return nil
}

func buildLabelSelector(rule labelRule) (labels.Selector, error) {
	selector := labels.NewSelector()
	for j, expr := range rule.MatchExpressions {
		if expr.Key == "" {
			return nil, fmt.Errorf("expression[%d]: key must be set", j)
		}
		op, err := labelOperator(expr.Operator)
		if err != nil {
			return nil, fmt.Errorf("expression[%d]: %w", j, err)
		}
		req, err := labels.NewRequirement(expr.Key, op, expr.Values)
		if err != nil {
			return nil, fmt.Errorf("expression[%d]: %w", j, err)
		}
		selector = selector.Add(*req)
	}
	return selector, nil
}

func labelOperator(op string) (selection.Operator, error) {
	switch op {
	case OpIn:
		return selection.In, nil
	case OpNotIn:
		return selection.NotIn, nil
	case OpExists:
		return selection.Exists, nil
	case OpDoesNotExist:
		return selection.DoesNotExist, nil
	default:
		return "", fmt.Errorf("operator must be %s, %s, %s, or %s", OpIn, OpNotIn, OpExists, OpDoesNotExist)
	}
}
