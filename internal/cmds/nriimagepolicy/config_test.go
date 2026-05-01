package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validConfig() config {
	return config{
		Whitelist: whitelistConfig{
			URL:     "http://localhost:8080",
			Timeout: 30 * time.Second,
		},
		Policy: policyConfig{
			Mode: "fail-closed",
		},
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_AuditMode(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Mode = "audit"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_NoEnforcementMechanism(t *testing.T) {
	cfg := config{
		Policy: policyConfig{Mode: "fail-closed"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when neither whitelist nor label_rules configured")
	}
}

func TestValidate_ZeroTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.Whitelist.Timeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for zero timeout")
	}
}

func TestValidate_NegativeTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.Whitelist.Timeout = -1 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative timeout")
	}
}

func TestValidate_InvalidMode(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Mode = "permissive"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid policy mode")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	yaml := `
whitelist:
  url: http://localhost:8080
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Whitelist.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %s", cfg.Whitelist.Timeout)
	}
	if cfg.Policy.Mode != "fail-closed" {
		t.Errorf("expected default mode fail-closed, got %s", cfg.Policy.Mode)
	}
	if cfg.Containerd.Socket != "/run/containerd/containerd.sock" {
		t.Errorf("expected default socket, got %s", cfg.Containerd.Socket)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(":::bad"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := loadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// --- WhitelistEnabled tests ---

func TestWhitelistEnabled_WithURL(t *testing.T) {
	cfg := validConfig()
	if !cfg.WhitelistEnabled() {
		t.Fatal("expected whitelist to be enabled")
	}
}

func TestWhitelistEnabled_WithoutURL(t *testing.T) {
	cfg := validConfig()
	cfg.Whitelist.URL = ""
	if cfg.WhitelistEnabled() {
		t.Fatal("expected whitelist to be disabled")
	}
}

// --- Label rules validation tests ---

func validLabelRule() labelRule {
	return labelRule{
		Name: "test-rule",
		MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "In", Values: []string{"acme"}},
		},
	}
}

func TestValidate_LabelRulesOnly(t *testing.T) {
	cfg := config{
		Policy: policyConfig{
			Mode:       "fail-closed",
			LabelRules: []labelRule{validLabelRule()},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_LabelRuleMissingName(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{MatchExpressions: []labelExpression{{Key: "x", Operator: "Exists"}}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing rule name")
	}
}

func TestValidate_LabelRuleDuplicateName(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "dup", MatchExpressions: []labelExpression{{Key: "x", Operator: "Exists"}}},
		{Name: "dup", MatchExpressions: []labelExpression{{Key: "y", Operator: "Exists"}}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for duplicate rule name")
	}
}

func TestValidate_LabelRuleNoExpressions(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "empty", MatchExpressions: []labelExpression{}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty match_expressions")
	}
}

func TestValidate_LabelRuleInvalidOperator(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "test", MatchExpressions: []labelExpression{
			{Key: "x", Operator: "Equals", Values: []string{"y"}},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid operator")
	}
}

func TestValidate_LabelRuleInRequiresValues(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "test", MatchExpressions: []labelExpression{
			{Key: "x", Operator: "In"},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for In without values")
	}
}

func TestValidate_LabelRuleExistsMustNotHaveValues(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "test", MatchExpressions: []labelExpression{
			{Key: "x", Operator: "Exists", Values: []string{"y"}},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for Exists with values")
	}
}

func TestValidate_LabelRuleExpressionMissingKey(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "test", MatchExpressions: []labelExpression{
			{Operator: "Exists"},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestLoadConfig_WithLabelRules(t *testing.T) {
	yaml := `
whitelist:
  url: http://localhost:8080
policy:
  label_rules:
    - name: allowed-tenants
      match_expressions:
        - key: tenant
          operator: In
          values: [acme, beta]
    - name: must-have-team
      match_expressions:
        - key: team
          operator: Exists
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Policy.LabelRules) != 2 {
		t.Fatalf("expected 2 label rules, got %d", len(cfg.Policy.LabelRules))
	}
	if cfg.Policy.LabelRules[0].Name != "allowed-tenants" {
		t.Errorf("expected first rule name 'allowed-tenants', got %s", cfg.Policy.LabelRules[0].Name)
	}
	if cfg.Policy.LabelRules[0].MatchExpressions[0].Operator != "In" {
		t.Errorf("expected operator 'In', got %s", cfg.Policy.LabelRules[0].MatchExpressions[0].Operator)
	}
	if len(cfg.Policy.LabelRules[0].MatchExpressions[0].Values) != 2 {
		t.Errorf("expected 2 values, got %d", len(cfg.Policy.LabelRules[0].MatchExpressions[0].Values))
	}
}

func TestLoadConfig_LabelRulesOnly(t *testing.T) {
	yaml := `
policy:
  label_rules:
    - name: require-tenant
      match_expressions:
        - key: tenant
          operator: Exists
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.WhitelistEnabled() {
		t.Fatal("expected whitelist to be disabled")
	}
	if len(cfg.Policy.LabelRules) != 1 {
		t.Fatalf("expected 1 label rule, got %d", len(cfg.Policy.LabelRules))
	}
}
