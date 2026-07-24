// Package allowlist implements the `c8s allowlist` operator CLI for reading and
// mutating the CDS-served image allowlist that nri-image-policy enforces on
// every node. The allowlist has two layers: a digest floor (admitted by digest
// alone) and named workload entries (each pins an init/main container set with
// per-container argv and path policy, looked up by container digest).
//
// Reads (list, export, diff, workload list/get, lint, inspect-image) are
// unauthenticated. Writes (add, remove, upload, workload apply/edit/delete) are
// authorized by an operator EC private key whose public key CDS pins
// (cds --operator-keys); the CLI mints a short-lived, body-bound token per write
// via pkg/operatorauth.
package allowlist

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/lbdiscovery"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// envOperatorKey supplies the operator private key when --operator-key is unset.
// The flag takes precedence.
const envOperatorKey = "C8S_OPERATOR_KEY"

// defaultRequiredComponents are the core c8s components an allowlist is expected
// to cover. `upload` warns (and requires --force) when an uploaded file names
// none of these, since a cluster missing them cannot pull its own control plane.
//
// Each entry is a case-insensitive substring matched against the image
// references in the uploaded allowlist (see missingComponents). They are chosen
// to match the chart image repositories: "cds", "ratls-mesh",
// "nri-image-policy", and "attestation-api" are the component repo basenames,
// and "nginx" deliberately stays loose because the tls-lb image is the
// third-party "nginxinc/nginx-unprivileged" — a tighter needle would miss it.
// TestMissingComponentsMatchesRealChartImages pins these against the real repos.
var defaultRequiredComponents = []string{
	"cds",
	"ratls-mesh",
	"nri-image-policy",
	"attestation-api",
	"nginx",
}

// options holds the flags shared by every subcommand.
type options struct {
	url              string
	measurements     []string
	measurementsFile string
	timeout          time.Duration

	operatorKey string

	output   string // "text" | "json"
	insecure bool

	// verify is the evidence verifier; a stub in tests.
	verify localverify.VerifyFunc
}

// NewCmd returns the `c8s allowlist` command tree.
func NewCmd() *cobra.Command {
	return newCmd(localverify.Verify)
}

// newCmd is the injectable constructor behind NewCmd.
func newCmd(verify localverify.VerifyFunc) *cobra.Command {
	o := &options{verify: verify}
	cmd := &cobra.Command{
		Use:   "allowlist",
		Short: "Manage the CDS image allowlist",
		Long: `Read and mutate the image allowlist that CDS serves and nri-image-policy
enforces on every node. The allowlist has two layers: a digest floor (images
admitted by digest alone) and named workload entries under 'allowlist workload'
(each pins an init/main container set with per-container argv and path policy).

Reads (list, export, diff, workload list/get, lint, inspect-image) are
unauthenticated. Writes (add, remove, upload, workload apply/edit/delete) are
signed with an operator EC private key you supply to THIS CLI via --operator-key
(or C8S_OPERATOR_KEY). The private key never leaves the CLI — it signs a
short-lived token that CDS verifies against the operator public keys it was
configured to pin separately (cds --operator-keys, set by 'c8s install
--operator-keys').

CDS has no public ingress; reach it over a port-forward or the tls-lb (see the
--url flag). To generate an operator key and pin its public half, see the c8s
README ("Operator allowlist credentials").`,
		SilenceUsage: true,
	}

	pf := cmd.PersistentFlags()
	pf.StringVar(&o.url, "url", "", "CDS base URL (required). CDS has no public ingress: reach it via 'kubectl port-forward svc/c8s-cds 8443:8443' then --url https://localhost:8443, or via the tls-lb")
	pf.StringSliceVar(&o.measurements, "measurements", nil, "allowed SHA-384 hex launch measurement(s) of the attested endpoint — CDS directly, or the tls-lb's discovery evidence when fronted (repeatable/comma-separated); empty = no pinning (UNSAFE)")
	pf.StringVar(&o.measurementsFile, "measurements-file", "", "file of allowed launch measurements, one hex digest per line")
	pf.DurationVar(&o.timeout, "timeout", 15*time.Second, "per-request timeout")
	pf.StringVar(&o.operatorKey, "operator-key", "", "operator EC private key PEM file, whose public key is pinned on CDS via --operator-keys (env "+envOperatorKey+"); required for writes")
	pf.StringVarP(&o.output, "output", "o", "text", "output format: text or json")
	pf.BoolVar(&o.insecure, "insecure", false, "dev/test only: allow a plaintext http:// CDS URL, skipping RA-TLS attestation of CDS")

	cmd.AddCommand(
		newListCmd(o),
		newExportCmd(o),
		newDiffCmd(o),
		newAddCmd(o),
		newRemoveCmd(o),
		newUploadCmd(o),
		newWorkloadCmd(o),
		newLintCmd(o),
		newInspectImageCmd(o),
	)
	return cmd
}

// validate checks the flags every subcommand needs.
func (o *options) validate() error {
	if strings.TrimSpace(o.url) == "" {
		return fmt.Errorf("--url is required")
	}
	if o.output != "text" && o.output != "json" {
		return fmt.Errorf("--output must be text or json, got %q", o.output)
	}
	return nil
}

// client builds an HTTP client for CDS. An https URL is verified via RA-TLS
// (CDS proves its TEE attestation). Plaintext http is refused unless --insecure
// is set, so a typo'd or downgraded URL never silently writes the allowlist to
// an unauthenticated endpoint.
func (o *options) client(ctx context.Context) (allowlistclient.Client, error) {
	u, err := url.Parse(o.url)
	if err != nil || u.Host == "" {
		return allowlistclient.Client{}, fmt.Errorf("invalid --url %q", o.url)
	}

	switch u.Scheme {
	case "http":
		if !o.insecure {
			return allowlistclient.Client{}, fmt.Errorf("refusing plaintext http:// for CDS (no attestation): use https:// (RA-TLS), or pass --insecure for a dev/test endpoint")
		}
		fmt.Fprintln(os.Stderr, "warning: --url is http:// with --insecure; CDS attestation is NOT verified (dev/test only)")
		return allowlistclient.NewClientWithHTTP(o.url, &http.Client{Timeout: o.timeout}), nil
	case "https":
		measurements, err := o.loadMeasurements()
		if err != nil {
			return allowlistclient.Client{}, err
		}
		if len(measurements) == 0 {
			fmt.Fprintln(os.Stderr, "warning: no --measurements set; accepting any RA-TLS-attested CDS (UNSAFE)")
		}
		hc, err := o.httpsClient(ctx, measurements)
		if err != nil {
			return allowlistclient.Client{}, err
		}
		hc.Timeout = o.timeout
		return allowlistclient.NewClientWithHTTP(o.url, hc), nil
	default:
		return allowlistclient.Client{}, fmt.Errorf("--url scheme must be http or https, got %q", u.Scheme)
	}
}

// httpsClient builds the attestation-verifying HTTP client. A tls-lb front
// door serves a CDS-issued cert with no RA-TLS extension; its trust path is
// the discovery document, so probe for that first and fall back to direct
// RA-TLS serving-cert verification (a port-forwarded CDS) when the target
// serves none — the same routing `c8s verify` uses in auto mode. A
// discovery document that fails verification is a hard error, never a
// fallback.
func (o *options) httpsClient(ctx context.Context, measurements [][]byte) (*http.Client, error) {
	probeCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	hc, err := lbdiscovery.NewVerifiedHTTPClient(probeCtx, o.url, measurements, o.verify)
	switch {
	case err == nil:
		fmt.Fprintln(os.Stderr, "note: target is a tls-lb front door; verified its discovery attestation and bound this session to the attested connection")
		return hc, nil
	case errors.Is(err, lbdiscovery.ErrNoDiscovery):
		return localverify.NewRATLSHTTPClient(measurements, o.verify, o.timeout), nil
	default:
		return nil, err
	}
}

// loadMeasurements combines --measurements and --measurements-file into the raw
// digest byte form RA-TLS verification expects.
func (o *options) loadMeasurements() ([][]byte, error) {
	hexes := append([]string{}, o.measurements...)
	if o.measurementsFile != "" {
		data, err := os.ReadFile(o.measurementsFile)
		if err != nil {
			return nil, fmt.Errorf("read --measurements-file: %w", err)
		}
		hexes = append(hexes, strings.Split(string(data), "\n")...)
	}
	return ratls.ParseHexMeasurementsList(hexes)
}

// signer builds the operator credential from the flags or environment. Required
// only for write subcommands.
func (o *options) signer() (*operatorauth.Signer, error) {
	keyPath := coalesce(o.operatorKey, os.Getenv(envOperatorKey))
	if keyPath == "" {
		return nil, fmt.Errorf("operator key required: set --operator-key or %s", envOperatorKey)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read operator key: %w", err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load operator key: %w", err)
	}
	return signer, nil
}

// matchedComponents returns the required component identifiers that appear as a
// (case-insensitive) substring of image — the same name-based signal the upload
// guard uses, applied to a single reference to recognise a component floor image.
func matchedComponents(image string, required []string) []string {
	low := strings.ToLower(image)
	var hits []string
	for _, comp := range required {
		if strings.Contains(low, strings.ToLower(comp)) {
			hits = append(hits, comp)
		}
	}
	return hits
}

// uploadImageLabels gathers every image label an allowlist carries — floor
// values, workload labels, and workload container images — the surface the
// upload component guard scans. Keys are synthetic; only the values matter.
func uploadImageLabels(al *pkgallowlist.Allowlist) map[string]string {
	labels := map[string]string{}
	n := 0
	add := func(s string) {
		if s != "" {
			labels[strconv.Itoa(n)] = s
			n++
		}
	}
	for _, img := range al.Digests {
		add(img)
	}
	for _, w := range al.Workloads {
		add(w.Label)
		for _, c := range w.InitContainers {
			add(c.Image)
		}
		for _, c := range w.Containers {
			add(c.Image)
		}
	}
	return labels
}

// missingComponents returns the required component identifiers not present as a
// (case-insensitive) substring of any image reference in images.
func missingComponents(images map[string]string, required []string) []string {
	var missing []string
	for _, comp := range required {
		needle := strings.ToLower(comp)
		found := false
		for _, image := range images {
			if strings.Contains(strings.ToLower(image), needle) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, comp)
		}
	}
	return missing
}

// coalesce returns a if non-empty, else b (which may itself be empty).
func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// sortedKeys returns the map keys sorted, for stable output.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ctx returns the command context or a background context as a fallback.
func ctx(cmd *cobra.Command) context.Context {
	if c := cmd.Context(); c != nil {
		return c
	}
	return context.Background()
}
