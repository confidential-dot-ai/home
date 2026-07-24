package credrelease

import (
	"context"
	"io"
	"strings"
	"testing"
)

// TestNewCmdDefaults pins the flag surface: names and defaults are part of the
// systemd-unit contract baked into the node image.
func TestNewCmdDefaults(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "cred-release" {
		t.Errorf("Use = %q, want cred-release", cmd.Use)
	}
	wantDefaults := map[string]string{
		"listen":              ":8443",
		"attestation-api-url": "http://127.0.0.1:8400",
		"platform":            "tdx",
		"client-ca-cert":      defaultClientCACert,
		"client-ca-key":       defaultClientCAKey,
		"server-ca-cert":      defaultServerCACert,
		"cert-ttl":            "24h0m0s",
		"cert-org":            "system:masters",
		"cert-cn":             "operator",
	}
	for name, want := range wantDefaults {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("flag --%s not registered", name)
			continue
		}
		if f.DefValue != want {
			t.Errorf("flag --%s default = %q, want %q", name, f.DefValue, want)
		}
	}
}

// TestNewCmdRunEFailsClosedWithoutPlatform executes the command with an empty
// platform: RunE must surface Run's fail-closed RA-TLS refusal.
func TestNewCmdRunEFailsClosedWithoutPlatform(t *testing.T) {
	cmd := NewCmd()
	cmd.SetArgs([]string{"--platform="})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	err := cmd.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--platform is required") {
		t.Errorf("err = %v, want --platform is required", err)
	}
}
