package nriimagepolicy

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// config represents the plugin configuration.
type config struct {
	Whitelist  whitelistConfig  `yaml:"whitelist"`
	Containerd containerdConfig `yaml:"containerd"`
	Policy     policyConfig     `yaml:"policy"`
	Logging    loggingConfig    `yaml:"logging"`
}

// whitelistConfig contains KBS connection settings for whitelist retrieval.
type whitelistConfig struct {
	URL     string        `yaml:"url"`     // KBS service URL
	Timeout time.Duration `yaml:"timeout"` // Per-request timeout (default: 30s)
}

// containerdConfig contains containerd connection settings for tag-to-digest resolution.
type containerdConfig struct {
	Socket    string `yaml:"socket"`
	Namespace string `yaml:"namespace"`
}

// policyConfig contains policy enforcement settings.
type policyConfig struct {
	Mode                  string      `yaml:"mode"`                    // fail-closed, audit
	EnforceExisting       bool        `yaml:"enforce_existing"`        // kill non-whitelisted containers on startup
	DenyMissingAnnotation bool        `yaml:"deny_missing_annotation"` // deny containers without image annotation
	ExemptNamespaces      []string    `yaml:"exempt_namespaces"`
	LabelRules            []labelRule `yaml:"label_rules"`
}

// labelRule defines a constraint on pod labels. Pods that do not satisfy
// all match expressions are denied.
type labelRule struct {
	Name             string            `yaml:"name"`
	MatchExpressions []labelExpression `yaml:"match_expressions"`
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

// loadConfig loads configuration from a YAML file.
func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &config{
		// Defaults for optional fields only.
		// Required fields come from the config file templated by Ansible.
		Whitelist: whitelistConfig{
			Timeout: 30 * time.Second,
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

// WhitelistEnabled returns true if the image whitelist check is configured.
func (c *config) WhitelistEnabled() bool {
	return c.Whitelist.URL != ""
}

// Validate checks the configuration for errors.
func (c *config) Validate() error {
	if c.WhitelistEnabled() {
		if c.Whitelist.Timeout <= 0 {
			return fmt.Errorf("whitelist.timeout must be positive")
		}
	}
	if !c.WhitelistEnabled() && len(c.Policy.LabelRules) == 0 {
		return fmt.Errorf("at least one enforcement mechanism must be configured (whitelist or label_rules)")
	}
	if c.Policy.Mode != ModeFailClosed && c.Policy.Mode != ModeAudit {
		return fmt.Errorf("policy.mode must be '%s' or '%s'", ModeFailClosed, ModeAudit)
	}
	return validateLabelRules(c.Policy.LabelRules)
}

// validateLabelRules checks label rules for errors.
func validateLabelRules(rules []labelRule) error {
	seen := make(map[string]bool, len(rules))
	for i, r := range rules {
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
		for j, expr := range r.MatchExpressions {
			if expr.Key == "" {
				return fmt.Errorf("label_rules[%d] %q: expression[%d]: key must be set", i, r.Name, j)
			}
			switch expr.Operator {
			case OpIn, OpNotIn:
				if len(expr.Values) == 0 {
					return fmt.Errorf("label_rules[%d] %q: expression[%d]: %s requires at least one value", i, r.Name, j, expr.Operator)
				}
			case OpExists, OpDoesNotExist:
				if len(expr.Values) != 0 {
					return fmt.Errorf("label_rules[%d] %q: expression[%d]: %s must not have values", i, r.Name, j, expr.Operator)
				}
			default:
				return fmt.Errorf("label_rules[%d] %q: expression[%d]: operator must be %s, %s, %s, or %s", i, r.Name, j, OpIn, OpNotIn, OpExists, OpDoesNotExist)
			}
		}
	}
	return nil
}
