package secretbroker

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"
)

// Default in-pod paths for the injected agent. The cert/key/ca come from the
// shared c8s-certs volume the get-cert sidecar populates; secrets are templated
// into an in-memory volume the app containers mount read-only.
const (
	defaultAgentCertDir   = "/etc/c8s/certs"
	defaultAgentSecretDir = "/vault/secrets"
	defaultAgentTokenSink = "/vault/.c8s-agent-token"
)

// SecretSpec is one secret the agent should template into a file.
type SecretSpec struct {
	Name  string // output filename under SecretsDir
	Path  string // KV v2 read path, e.g. secret/data/api/db
	Field string // optional; empty templates the whole data object as JSON
}

// AgentConfig is the rendered-config input for the injected OpenBao/Vault Agent.
type AgentConfig struct {
	BrokerAddr string
	CACert     string
	ClientCert string
	ClientKey  string
	TokenSink  string
	SecretsDir string
	Secrets    []SecretSpec
}

// RenderAgentConfig produces an OpenBao/Vault Agent config (HCL) that auto-auths
// to the broker with the pod's mesh client cert and templates each secret to a
// file. HCL (not JSON) is emitted because the agent's block grammar maps cleanly
// to HCL; the form here is the one validated end-to-end against a real agent.
func RenderAgentConfig(c AgentConfig) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "auto_auth {\n  method \"cert\" {\n    config = {}\n  }\n  sink \"file\" {\n    config = { path = %q }\n  }\n}\n\n", c.TokenSink)
	fmt.Fprintf(&b, "vault {\n  address     = %q\n  ca_cert     = %q\n  client_cert = %q\n  client_key  = %q\n}\n\n",
		c.BrokerAddr, c.CACert, c.ClientCert, c.ClientKey)
	for _, s := range c.Secrets {
		fmt.Fprintf(&b, "template {\n  contents    = %q\n  destination = %q\n}\n\n",
			templateContents(s), path.Join(c.SecretsDir, s.Name))
	}
	return b.String(), nil
}

// templateContents builds the consul-template body for one secret. `index` is
// used for the field lookup so arbitrary field names (dashes, dots) are safe.
func templateContents(s SecretSpec) string {
	if s.Field != "" {
		return fmt.Sprintf(`{{ with secret "%s" }}{{ index .Data.data "%s" }}{{ end }}`, s.Path, s.Field)
	}
	return fmt.Sprintf(`{{ with secret "%s" }}{{ .Data.data | toJSON }}{{ end }}`, s.Path)
}

func (c AgentConfig) validate() error {
	for _, f := range []struct{ name, val string }{
		{"broker-addr", c.BrokerAddr},
		{"ca", c.CACert},
		{"client-cert", c.ClientCert},
		{"client-key", c.ClientKey},
		{"token-sink", c.TokenSink},
		{"secrets-dir", c.SecretsDir},
	} {
		if strings.TrimSpace(f.val) == "" {
			return fmt.Errorf("--%s is required", f.name)
		}
	}
	if len(c.Secrets) == 0 {
		return fmt.Errorf("at least one --secret is required")
	}
	seen := map[string]bool{}
	for _, s := range c.Secrets {
		if s.Name == "" || s.Path == "" {
			return fmt.Errorf("secret %q: name and path are required", s.Name)
		}
		if strings.ContainsAny(s.Name, "/\\") {
			return fmt.Errorf("secret name %q must not contain a path separator", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("duplicate secret name %q", s.Name)
		}
		seen[s.Name] = true
	}
	return nil
}

// parseSecretFlag parses "name=path[#field]".
func parseSecretFlag(raw string) (SecretSpec, error) {
	name, rest, ok := strings.Cut(raw, "=")
	if !ok || name == "" || rest == "" {
		return SecretSpec{}, fmt.Errorf("invalid --secret %q: want name=path[#field]", raw)
	}
	p, field, _ := strings.Cut(rest, "#")
	if p == "" {
		return SecretSpec{}, fmt.Errorf("invalid --secret %q: empty path", raw)
	}
	return SecretSpec{Name: name, Path: p, Field: field}, nil
}

// NewAgentConfigCmd renders the injected agent config at pod start. It runs in
// an init container (the c8s image) so the config is produced inside the
// measured guest, not handed in via a control-plane object.
func NewAgentConfigCmd() *cobra.Command {
	var (
		out     string
		secrets []string
		cfg     AgentConfig
	)
	cmd := &cobra.Command{
		Use:   "secret-agent-config",
		Short: "Render the injected OpenBao/Vault Agent config for a secrets-enabled pod",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, raw := range secrets {
				s, err := parseSecretFlag(raw)
				if err != nil {
					return err
				}
				cfg.Secrets = append(cfg.Secrets, s)
			}
			hcl, err := RenderAgentConfig(cfg)
			if err != nil {
				return err
			}
			if out == "" || out == "-" {
				fmt.Print(hcl)
				return nil
			}
			return os.WriteFile(out, []byte(hcl), 0o600)
		},
	}
	f := cmd.Flags()
	f.StringVar(&out, "out", "", "write the config here (default stdout)")
	f.StringVar(&cfg.BrokerAddr, "broker-addr", "", "secret-broker base URL, e.g. https://c8s-secret-broker.c8s-system.svc:8443 (required)")
	f.StringVar(&cfg.CACert, "ca", defaultAgentCertDir+"/ca.crt", "CA bundle the agent uses to trust the broker")
	f.StringVar(&cfg.ClientCert, "client-cert", defaultAgentCertDir+"/tls.crt", "mesh client cert the agent presents")
	f.StringVar(&cfg.ClientKey, "client-key", defaultAgentCertDir+"/tls.key", "mesh client key the agent presents")
	f.StringVar(&cfg.TokenSink, "token-sink", defaultAgentTokenSink, "file sink for the broker token")
	f.StringVar(&cfg.SecretsDir, "secrets-dir", defaultAgentSecretDir, "directory templated secret files are written to")
	f.StringArrayVar(&secrets, "secret", nil, "secret to template: name=path[#field] (repeatable)")
	_ = cmd.MarkFlagRequired("broker-addr")
	return cmd
}
