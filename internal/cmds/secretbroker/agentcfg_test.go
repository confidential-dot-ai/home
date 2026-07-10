package secretbroker

import (
	"strings"
	"testing"
)

func TestParseSecretFlag(t *testing.T) {
	cases := []struct {
		in              string
		name, path, fld string
		wantErr         bool
	}{
		{in: "db=secret/data/api/db#password", name: "db", path: "secret/data/api/db", fld: "password"},
		{in: "blob=secret/data/api/blob", name: "blob", path: "secret/data/api/blob"},
		{in: "noeq", wantErr: true},
		{in: "=path", wantErr: true},
		{in: "name=", wantErr: true},
	}
	for _, c := range cases {
		got, err := parseSecretFlag(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseSecretFlag(%q): want error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSecretFlag(%q): %v", c.in, err)
			continue
		}
		if got.Name != c.name || got.Path != c.path || got.Field != c.fld {
			t.Errorf("parseSecretFlag(%q) = %+v", c.in, got)
		}
	}
}

func baseAgentConfig() AgentConfig {
	return AgentConfig{
		BrokerAddr: "https://broker:8443",
		CACert:     "/etc/c8s/certs/ca.crt",
		ClientCert: "/etc/c8s/certs/tls.crt",
		ClientKey:  "/etc/c8s/certs/tls.key",
		TokenSink:  "/vault/.c8s-agent-token",
		SecretsDir: "/vault/secrets",
		Secrets:    []SecretSpec{{Name: "db", Path: "secret/data/api/db", Field: "password"}},
	}
}

func TestRenderAgentConfig(t *testing.T) {
	got, err := RenderAgentConfig(baseAgentConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`method "cert"`,
		`address     = "https://broker:8443"`,
		`client_cert = "/etc/c8s/certs/tls.crt"`,
		`{{ with secret \"secret/data/api/db\" }}{{ index .Data.data \"password\" }}{{ end }}`,
		`destination = "/vault/secrets/db"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered config missing %q\n---\n%s", want, got)
		}
	}
}

func TestRenderAgentConfigWholeSecret(t *testing.T) {
	cfg := baseAgentConfig()
	cfg.Secrets = []SecretSpec{{Name: "blob", Path: "secret/data/api/blob"}}
	got, err := RenderAgentConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `.Data.data | toJSON`) {
		t.Errorf("expected whole-data toJSON template, got:\n%s", got)
	}
}

func TestRenderAgentConfigValidation(t *testing.T) {
	noBroker := baseAgentConfig()
	noBroker.BrokerAddr = ""
	if _, err := RenderAgentConfig(noBroker); err == nil {
		t.Error("missing broker-addr should error")
	}

	noSecrets := baseAgentConfig()
	noSecrets.Secrets = nil
	if _, err := RenderAgentConfig(noSecrets); err == nil {
		t.Error("no secrets should error")
	}

	badName := baseAgentConfig()
	badName.Secrets = []SecretSpec{{Name: "a/b", Path: "secret/data/x"}}
	if _, err := RenderAgentConfig(badName); err == nil {
		t.Error("secret name with separator should error")
	}

	dup := baseAgentConfig()
	dup.Secrets = []SecretSpec{
		{Name: "db", Path: "secret/data/x"},
		{Name: "db", Path: "secret/data/y"},
	}
	if _, err := RenderAgentConfig(dup); err == nil {
		t.Error("duplicate secret name should error")
	}
}
