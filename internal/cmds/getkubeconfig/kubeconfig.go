package getkubeconfig

import (
	"encoding/base64"
	"fmt"
)

// buildKubeconfig assembles a minimal kubeconfig from the issued client cert +
// key, the cluster CA, and the apiserver address. Written directly as YAML — no
// clientcmd dependency for a fixed single-context shape.
//
// tlsServerName, when non-empty, is emitted as tls-server-name: the operator
// dials the guest at a per-launch IP the apiserver cert has no SAN for, so
// verification is pinned to a stable SAN the image bakes into tls-san
// (c8s-cvm) instead. Without it the kubeconfig would need
// --insecure-skip-tls-verify.
func buildKubeconfig(apiserverURL, contextName, tlsServerName string, clientCertPEM, clientKeyPEM, caPEM []byte) []byte {
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	tlsLine := ""
	if tlsServerName != "" {
		tlsLine = fmt.Sprintf("\n    tls-server-name: %s", tlsServerName)
	}
	return []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: %[1]s
clusters:
- name: %[1]s
  cluster:
    server: %[2]s
    certificate-authority-data: %[3]s%[6]s
contexts:
- name: %[1]s
  context:
    cluster: %[1]s
    user: %[1]s
users:
- name: %[1]s
  user:
    client-certificate-data: %[4]s
    client-key-data: %[5]s
`, contextName, apiserverURL, b64(caPEM), b64(clientCertPEM), b64(clientKeyPEM), tlsLine))
}
