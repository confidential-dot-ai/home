package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validConfig() config {
	return config{
		Allowlist: allowlistConfig{
			AlwaysAllow: map[string]string{
				"sha256:0000000000000000000000000000000000000000000000000000000000000001": "test-installer",
			},
			Pull: pullConfig{
				URL:               "https://127.0.0.1:30808",
				Timeout:           30 * time.Second,
				Interval:          30 * time.Second,
				AttestationApiURL: "http://localhost:30840",
			},
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
		t.Fatal("expected error when neither allowlist nor label_rules configured")
	}
}

func TestValidate_ZeroTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.Timeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for zero timeout")
	}
}

func TestValidate_NegativeTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.Timeout = -1 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for negative timeout")
	}
}

func TestValidate_PullRequiresAttestationApi(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.AttestationApiURL = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when pull lacks attestation_api_url")
	}
}

func TestValidate_PullRejectsInvalidCDSMeasurement(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.CDSMeasurements = []string{"not-hex"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid CDS measurement")
	}
}

func TestValidate_PullRejectsPlaintextScheme(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.URL = "http://localhost:8080"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for plaintext http pull URL")
	}
}

func TestValidate_PullRejectsUnsupportedScheme(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.URL = "ftp://127.0.0.1/allowlist"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for unsupported pull URL scheme")
	}
}

func TestValidate_AlwaysAllowRequiredWithPull(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.AlwaysAllow = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when pull is configured but always_allow is empty")
	}
}

func TestValidate_AlwaysAllowRejectsMalformedDigest(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.AlwaysAllow = map[string]string{
		"sha256:not-hex": "installer",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for non-hex digest in always_allow")
	}

	cfg.Allowlist.AlwaysAllow = map[string]string{
		"sha512:0000000000000000000000000000000000000000000000000000000000000001": "installer",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for non-sha256 digest in always_allow")
	}

	cfg.Allowlist.AlwaysAllow = map[string]string{
		// 63 hex chars instead of 64.
		"sha256:000000000000000000000000000000000000000000000000000000000000001": "installer",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for short digest in always_allow")
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
allowlist:
  always_allow:
    "sha256:0000000000000000000000000000000000000000000000000000000000000001": "installer"
  pull:
    url: https://127.0.0.1:30808
    attestation_api_url: http://localhost:30840
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Allowlist.Pull.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %s", cfg.Allowlist.Pull.Timeout)
	}
	if cfg.Allowlist.Pull.Interval != 30*time.Second {
		t.Errorf("expected default interval 30s, got %s", cfg.Allowlist.Pull.Interval)
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

// --- AllowlistEnabled tests ---

func TestAllowlistEnabled_WithURL(t *testing.T) {
	cfg := validConfig()
	if !cfg.AllowlistEnabled() {
		t.Fatal("expected allowlist to be enabled")
	}
}

func TestAllowlistEnabled_WithoutURL(t *testing.T) {
	cfg := validConfig()
	cfg.Allowlist.Pull.URL = ""
	cfg.Allowlist.AlwaysAllow = nil
	if cfg.AllowlistEnabled() {
		t.Fatal("expected allowlist to be disabled")
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
	if cfg.Policy.LabelRules[0].selector == nil {
		t.Fatal("expected label rule selector to be compiled during validation")
	}
	if !evaluateRule(cfg.Policy.LabelRules[0], map[string]string{"tenant": "acme"}) {
		t.Fatal("compiled selector should match valid labels")
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

func TestValidate_LabelRuleRejectsInvalidKubernetesLabelValue(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.LabelRules = []labelRule{
		{Name: "test", MatchExpressions: []labelExpression{
			{Key: "tenant", Operator: "In", Values: []string{"not valid"}},
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected Kubernetes label selector validation to reject invalid value")
	}
}

func TestLoadConfig_WithLabelRules(t *testing.T) {
	yaml := `
allowlist:
  always_allow:
    "sha256:0000000000000000000000000000000000000000000000000000000000000001": "installer"
  pull:
    url: https://127.0.0.1:30808
    attestation_api_url: http://localhost:30840
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

	if cfg.AllowlistEnabled() {
		t.Fatal("expected allowlist to be disabled")
	}
	if len(cfg.Policy.LabelRules) != 1 {
		t.Fatalf("expected 1 label rule, got %d", len(cfg.Policy.LabelRules))
	}
}
