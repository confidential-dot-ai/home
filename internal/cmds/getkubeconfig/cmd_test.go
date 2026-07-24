package getkubeconfig

import (
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// execCmd runs the get-kubeconfig command with the given args and returns the
// error, keeping cobra's own output out of the test log.
func execCmd(t *testing.T, args ...string) error {
	t.Helper()
	cmd := NewCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestNewCmdValidation(t *testing.T) {
	t.Run("missing operator-key and out", func(t *testing.T) {
		err := execCmd(t, "--node", "127.0.0.1")
		if err == nil || !strings.Contains(err.Error(), "--operator-key and --out are required") {
			t.Fatalf("want required-flags error, got %v", err)
		}
	})

	t.Run("missing node and URLs", func(t *testing.T) {
		err := execCmd(t, "--operator-key", "k.pem", "--out", "kc")
		if err == nil || !strings.Contains(err.Error(), "set --node") {
			t.Fatalf("want set-node error, got %v", err)
		}
	})

	t.Run("node fills URLs", func(t *testing.T) {
		// A nonexistent operator key makes Run fail at its first step, which
		// proves --node satisfied the URL validation and Run was reached.
		err := execCmd(t,
			"--node", "127.0.0.1",
			"--operator-key", filepath.Join(t.TempDir(), "nope.key"),
			"--out", filepath.Join(t.TempDir(), "kc"))
		if err == nil || !strings.Contains(err.Error(), "read operator key") {
			t.Fatalf("want read-key error from Run, got %v", err)
		}
	})
}

// TestNewCmdEndToEnd runs the whole command against the fake node: flags,
// attest gate, RA-TLS release, kubeconfig on disk.
func TestNewCmdEndToEnd(t *testing.T) {
	env := newTestEnv(t, http.StatusOK, http.StatusOK, goodRelease)

	err := execCmd(t,
		"--attest-url", env.attestURL,
		"--release-url", env.releaseURL,
		"--apiserver-url", "https://node:6443",
		"--operator-key", env.keyPath,
		"--out", env.outPath,
		"--context", "testctx",
		"--tls-server-name", "c8s-cvm",
		"--timeout", "10s")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	kc, err := os.ReadFile(env.outPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"current-context: testctx",
		"server: https://node:6443",
		"client-certificate-data: " + base64.StdEncoding.EncodeToString([]byte("CERTPEM")),
	} {
		if !strings.Contains(string(kc), want) {
			t.Errorf("kubeconfig missing %q", want)
		}
	}
}
