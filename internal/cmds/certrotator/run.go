// Package certrotator rotates mesh CA certificates in Kubernetes.
//
// Designed to run as a CronJob. Reads existing Secrets, generates new keypairs,
// updates Secrets and ConfigMaps with CA bundles (new + old), and verifies
// cert-issuer hot-reload via metrics polling.
//
// Token-signer rotation is handled by assam in-process (see pkg/earsigner).
package certrotator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/issuerapi"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

// Run executes the cert-rotator binary. args is the slice of CLI args
// after the program name.
func Run(args []string) error {
	fs := flag.NewFlagSet("cert-rotator", flag.ContinueOnError)
	namespace := fs.String("namespace", "tee-attestation", "namespace holding the kbs-mesh-ca Secret and mesh-ca-cert ConfigMap")
	components := fs.String("components", "mesh-ca", "comma-separated components to rotate")
	meshCAValidity := fs.Int("mesh-ca-validity-days", 365, "mesh CA certificate validity in days")
	certIssuerURL := fs.String("cert-issuer-url", "", "cert-issuer metrics URL for reload verification; cert_issuer_ca_cert_expiry_seconds is the alertable CA lifetime gauge")
	verifyTimeout := fs.Duration("verify-timeout", 120*time.Second, "timeout for reload verification")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	maxTTL := fs.Duration("max-ttl", 4*time.Hour, "max certificate TTL for CA bundle trimming")

	verifyPollInterval := fs.Duration("verify-poll-interval", 5*time.Second, "polling interval for cert-issuer reload verification")
	httpTimeout := fs.Duration("http-timeout", 30*time.Second, "HTTP client timeout for CDS and cert-issuer requests")

	kbsURL := fs.String("kbs-url", "", "CDS base URL (enables attested rotation via cert-issuer /v1/rotate-ca)")
	attestCmd := fs.String("attest-cmd", "/attest-sev-snp", "path to attestation binary")
	certIssuerRotateURL := fs.String("cert-issuer-rotate-url", "", "cert-issuer /v1/rotate-ca endpoint URL")
	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}

	logger := certutil.NewJSONLogger(*logLevel)

	ctx := context.Background()

	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("k8s in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("k8s clientset: %w", err)
	}

	componentList := strings.Split(*components, ",")
	logger.Info("starting cert-rotator", "namespace", *namespace, "components", componentList)

	var baselineReloads float64
	httpClient := &http.Client{Timeout: *httpTimeout}
	if *certIssuerURL != "" {
		baselineReloads, _, err = captureBaselineMetrics(ctx, httpClient, *certIssuerURL)
		if err != nil {
			logger.Warn("failed to capture baseline metrics (cert-issuer may not be running yet)", "error", err)
		}
	}

	kbsMode := *kbsURL != ""
	if kbsMode {
		logger.Info("CDS attestation mode enabled", "cds_url", *kbsURL)
	}

	var expectedFingerprint string
	for _, comp := range componentList {
		comp = strings.TrimSpace(comp)
		switch comp {
		case "mesh-ca":
			if kbsMode {
				fp, err := rotateMeshCAViaKBS(ctx, *kbsURL, *attestCmd, *certIssuerRotateURL, *httpTimeout, logger)
				if err != nil {
					return fmt.Errorf("mesh-ca rotation via CDS: %w", err)
				}
				expectedFingerprint = fp
			} else {
				fp, err := rotateMeshCA(ctx, clientset, *namespace, *meshCAValidity, *maxTTL, logger)
				if err != nil {
					return fmt.Errorf("mesh-ca rotation: %w", err)
				}
				expectedFingerprint = fp
			}
		default:
			return fmt.Errorf("unknown component %q", comp)
		}
	}

	if *certIssuerURL != "" {
		if err := verifyCertIssuerReload(ctx, httpClient, *certIssuerURL, *verifyTimeout, *verifyPollInterval, baselineReloads, expectedFingerprint, logger); err != nil {
			return fmt.Errorf("cert-issuer reload verification: %w", err)
		}
	}

	logger.Info("cert-rotator completed successfully")
	return nil
}

func rotateMeshCA(ctx context.Context, client kubernetes.Interface, namespace string, validityDays int, maxTTL time.Duration, logger *slog.Logger) (string, error) {
	logger.Info("rotating mesh CA keypair")

	// Read existing CA cert for bundle and rollback.
	secretsClient := client.CoreV1().Secrets(namespace)
	existingSecret, err := secretsClient.Get(ctx, "kbs-mesh-ca", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get existing mesh CA secret: %w", err)
	}

	// Parse old certificate for audit fingerprint.
	var oldFingerprint string
	if cert, err := certutil.ParseCertificatePEM(existingSecret.Data["mesh-ca.crt"]); err == nil {
		oldFingerprint = certutil.CertFingerprint(cert.Raw)
	}

	// Save original Secret data for rollback.
	originalSecretData := copySecretData(existingSecret.Data)

	// Generate new P-384 key for mesh CA.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}

	serial, err := certutil.GenerateSerial()
	if err != nil {
		return "", fmt.Errorf("generate serial: %w", err)
	}

	template := certutil.NewCATemplate(serial, "Mesh CA", time.Now().AddDate(0, 0, validityDays))

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", fmt.Errorf("create certificate: %w", err)
	}

	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		return "", err
	}

	newCertPEM := certutil.EncodeCertPEM(certDER)

	// Update mesh CA Secret.
	existingSecret.Data["mesh-ca.key"] = keyPEM
	existingSecret.Data["mesh-ca.crt"] = newCertPEM
	if _, err := secretsClient.Update(ctx, existingSecret, metav1.UpdateOptions{}); err != nil {
		return "", fmt.Errorf("update mesh CA secret: %w", err)
	}

	// Update CA bundle ConfigMap if it exists. When using dynamic CA URL
	// (ratls-mesh polls cert-issuer /v1/ca), the ConfigMap may not exist
	// and the Secret update alone is sufficient — cert-issuer hot-reloads
	// and serves the new cert.
	cmClient := client.CoreV1().ConfigMaps(namespace)
	cm, err := cmClient.Get(ctx, "mesh-ca-cert", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		newFingerprint := certutil.CertFingerprint(certDER)
		logger.Info("mesh CA rotated (no mesh-ca-cert ConfigMap, skipping bundle update)",
			"old_fingerprint", oldFingerprint,
			"new_fingerprint", newFingerprint,
			"not_after", template.NotAfter.Format(time.RFC3339),
		)
		return newFingerprint, nil
	}
	if err != nil {
		logger.Error("get mesh-ca-cert ConfigMap failed, rolling back Secret", "error", err)
		rollbackSecret(ctx, secretsClient, originalSecretData, logger)
		return "", fmt.Errorf("get mesh-ca-cert ConfigMap: %w", err)
	}

	// Build bundle: new cert + old certs, trimmed.
	existingBundle := cm.Data["ca.pem"]
	trimmedOld := trimExpiredCerts(existingBundle, maxTTL, logger)
	bundlePEM := string(newCertPEM) + trimmedOld

	cm.Data["ca.pem"] = bundlePEM
	if cm.Annotations == nil {
		cm.Annotations = make(map[string]string)
	}
	cm.Annotations["lunal.dev/ca-rotation-timestamp"] = time.Now().UTC().Format(time.RFC3339)
	if _, err := cmClient.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		// Rollback Secret.
		logger.Error("update mesh-ca-cert ConfigMap failed, rolling back Secret", "error", err)
		rollbackSecret(ctx, secretsClient, originalSecretData, logger)
		return "", fmt.Errorf("update mesh-ca-cert ConfigMap: %w", err)
	}

	newFingerprint := certutil.CertFingerprint(certDER)
	logger.Info("mesh CA rotated",
		"old_fingerprint", oldFingerprint,
		"new_fingerprint", newFingerprint,
		"not_after", template.NotAfter.Format(time.RFC3339),
	)

	return newFingerprint, nil
}

// trimExpiredCerts removes certificates from a PEM bundle that expired more than 2x maxTTL ago.
// Unparseable PEM blocks (e.g. comments or non-CERTIFICATE blocks) are passed through unchanged.
func trimExpiredCerts(bundlePEM string, maxTTL time.Duration, logger *slog.Logger) string {
	cutoff := time.Now().Add(-2 * maxTTL)
	var (
		certs       []*x509.Certificate
		certBlocks  []*pem.Block
		passthrough []byte
	)
	remaining := []byte(bundlePEM)
	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			passthrough = append(passthrough, pem.EncodeToMemory(block)...)
			continue
		}
		certs = append(certs, cert)
		certBlocks = append(certBlocks, block)
	}

	kept, dropped := certutil.TrimExpiredCABundle(certs, cutoff)
	for _, cert := range dropped {
		logger.Info("trimming expired CA from bundle",
			"fingerprint", certutil.CertFingerprint(cert.Raw),
			"not_after", cert.NotAfter.Format(time.RFC3339),
		)
	}

	keptSet := make(map[*x509.Certificate]bool, len(kept))
	for _, c := range kept {
		keptSet[c] = true
	}
	var result []byte
	for i, cert := range certs {
		if keptSet[cert] {
			result = append(result, certutil.EncodeCertPEM(certBlocks[i].Bytes)...)
		}
	}
	return string(result) + string(passthrough)
}

// captureBaselineMetrics fetches the current cert_reloads_total and fingerprint from cert-issuer metrics.
func captureBaselineMetrics(ctx context.Context, httpClient *http.Client, metricsURL string) (reloadsTotal float64, fingerprint string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", metricsURL, nil)
	if err != nil {
		return 0, "", fmt.Errorf("create request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("fetch metrics: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	reloadsTotal = parseMetricValue(bodyStr, `cert_issuer_cert_reloads_total`)
	fingerprint = parseMetricLabel(bodyStr, `cert_issuer_ca_cert_fingerprint_info`, "fingerprint")

	return reloadsTotal, fingerprint, nil
}

// verifyCertIssuerReload polls cert-issuer metrics until the reload counter increments
// AND the CA fingerprint matches the expected value.
func verifyCertIssuerReload(ctx context.Context, httpClient *http.Client, metricsURL string, timeout, pollInterval time.Duration, baselineReloads float64, expectedFingerprint string, logger *slog.Logger) error {
	logger.Info("verifying cert-issuer reload",
		"url", metricsURL,
		"baseline_reloads", baselineReloads,
		"expected_fingerprint", expectedFingerprint,
	)

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, "GET", metricsURL, nil)
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			logger.Debug("cert-issuer metrics not yet available", "error", err)
			time.Sleep(pollInterval)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		currentReloads := parseMetricValue(bodyStr, `cert_issuer_cert_reloads_total`)
		currentFingerprint := parseMetricLabel(bodyStr, `cert_issuer_ca_cert_fingerprint_info`, "fingerprint")

		// When we know the expected fingerprint, it is authoritative: a matching
		// fingerprint proves the right cert is loaded even if the cert-issuer pod
		// restarted during rotation (which resets the reload counter to 0). Only
		// fall back to the counter when no expected fingerprint is known.
		var verified bool
		if expectedFingerprint != "" {
			verified = currentFingerprint == expectedFingerprint
		} else {
			verified = currentReloads > baselineReloads
		}

		if verified {
			logger.Info("cert-issuer reload verified",
				"reloads_total", currentReloads,
				"fingerprint", currentFingerprint,
			)
			return nil
		}

		logger.Debug("waiting for cert-issuer reload",
			"current_reloads", currentReloads,
			"current_fingerprint", currentFingerprint,
		)
		time.Sleep(pollInterval)
	}

	return fmt.Errorf("cert-issuer reload verification timed out after %s", timeout)
}

// parseMetricValue extracts a metric value using regex.
func parseMetricValue(metricsBody, metricName string) float64 {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(metricName) + `\s+([\d.eE+-]+)`)
	match := re.FindStringSubmatch(metricsBody)
	if len(match) < 2 {
		return 0
	}
	var v float64
	fmt.Sscanf(match[1], "%g", &v)
	return v
}

// parseMetricLabel extracts a label value from an info-style metric.
func parseMetricLabel(metricsBody, metricName, labelName string) string {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(metricName) + `\{[^}]*` + regexp.QuoteMeta(labelName) + `="([^"]*)"`)
	match := re.FindStringSubmatch(metricsBody)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

// copySecretData creates a deep copy of Secret data for rollback.
func copySecretData(data map[string][]byte) map[string][]byte {
	cp := make(map[string][]byte, len(data))
	for k, v := range data {
		cp[k] = bytes.Clone(v)
	}
	return cp
}

// rollbackSecret restores Secret data from a snapshot. Re-fetches the
// current Secret first so the rollback uses a fresh resourceVersion and
// doesn't fail with optimistic-concurrency errors.
func rollbackSecret(ctx context.Context, client typedcorev1.SecretInterface, original map[string][]byte, logger *slog.Logger) {
	current, err := client.Get(ctx, "kbs-mesh-ca", metav1.GetOptions{})
	if err != nil {
		logger.Error("CRITICAL: Secret rollback re-get failed", "error", err)
		return
	}
	current.Data = original
	if _, err := client.Update(ctx, current, metav1.UpdateOptions{}); err != nil {
		logger.Error("CRITICAL: Secret rollback also failed", "error", err)
	}
}

// rotateMeshCAViaKBS performs mesh CA rotation via CDS attestation:
// 1. Attest to CDS → get EAR JWT
// 2. POST /v1/rotate-ca on cert-issuer with EAR JWT
// 3. Cert-issuer generates new CA keypair, returns new cert PEM
// No K8s Secret or ConfigMap updates needed in this mode.
func rotateMeshCAViaKBS(ctx context.Context, kbsURL, attestCmd, rotateURL string, httpTimeout time.Duration, logger *slog.Logger) (string, error) {
	logger.Info("rotating mesh CA via CDS attestation", "cds_url", kbsURL, "rotate_url", rotateURL)

	if rotateURL == "" {
		return "", fmt.Errorf("--cert-issuer-rotate-url is required for CDS mode mesh-ca rotation")
	}

	// Step 1: Attest to CDS.
	token, err := kbsAttest(ctx, kbsURL, attestCmd, httpTimeout)
	if err != nil {
		return "", fmt.Errorf("CDS attestation: %w", err)
	}
	logger.Info("CDS attestation succeeded")

	// Step 2: POST /v1/rotate-ca with EAR JWT.
	reqBody, err := json.Marshal(issuerapi.RotateCARequest{EAR: token})
	if err != nil {
		return "", fmt.Errorf("marshal rotate request: %w", err)
	}

	httpClient := &http.Client{Timeout: httpTimeout}
	req, err := http.NewRequestWithContext(ctx, "POST", rotateURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("create rotate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("rotate request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("rotate-ca returned %d: %s", resp.StatusCode, body)
	}

	var rotResp issuerapi.RotateCAResponse
	if err := json.NewDecoder(resp.Body).Decode(&rotResp); err != nil {
		return "", fmt.Errorf("decode rotate response: %w", err)
	}

	// Parse the new CA cert to get fingerprint.
	rotCert, err := certutil.ParseCertificatePEM(rotResp.CACertificate.Bytes())
	if err != nil {
		return "", fmt.Errorf("parse rotate response cert: %w", err)
	}
	fingerprint := certutil.CertFingerprint(rotCert.Raw)

	logger.Info("mesh CA rotated via CDS attestation",
		"new_fingerprint", fingerprint,
	)
	return fingerprint, nil
}

// kbsAttest performs the KBS auth → attest flow and returns an EAR JWT.
func kbsAttest(ctx context.Context, kbsURL, attestCmd string, httpTimeout time.Duration) (string, error) {
	httpClient := &http.Client{Timeout: httpTimeout}

	// POST /kbs/v0/auth → get challenge.
	type authResp struct {
		Challenge string `json:"challenge"`
	}
	authReq, err := http.NewRequestWithContext(ctx, "POST", kbsURL+"/kbs/v0/auth", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return "", err
	}
	authReq.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(authReq)
	if err != nil {
		return "", fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("auth returned %d: %s", resp.StatusCode, body)
	}

	var ar authResp
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return "", fmt.Errorf("decode auth response: %w", err)
	}

	// Exec attestation binary.
	c := exec.CommandContext(ctx, attestCmd, "--report-data", ar.Challenge)
	out, err := c.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("attestation command failed: %w\noutput: %s", err, out)
	}

	// POST /kbs/v0/attest with evidence.
	type attestReq struct {
		TEEEvidence string `json:"tee-evidence"`
	}
	type attestResp struct {
		Token string `json:"token"`
	}

	attestBody, err := json.Marshal(attestReq{TEEEvidence: string(out)})
	if err != nil {
		return "", err
	}

	attestHTTPReq, err := http.NewRequestWithContext(ctx, "POST", kbsURL+"/kbs/v0/attest", bytes.NewReader(attestBody))
	if err != nil {
		return "", err
	}
	attestHTTPReq.Header.Set("Content-Type", "application/json")

	attestHTTPResp, err := httpClient.Do(attestHTTPReq)
	if err != nil {
		return "", fmt.Errorf("attest request: %w", err)
	}
	defer attestHTTPResp.Body.Close()

	if attestHTTPResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(attestHTTPResp.Body, 1024))
		return "", fmt.Errorf("attest returned %d: %s", attestHTTPResp.StatusCode, body)
	}

	var attResp attestResp
	if err := json.NewDecoder(attestHTTPResp.Body).Decode(&attResp); err != nil {
		return "", fmt.Errorf("decode attest response: %w", err)
	}

	return attResp.Token, nil
}
