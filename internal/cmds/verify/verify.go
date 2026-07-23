package verify

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// Exit codes. These are a stable contract for CI: a wrong measurement (2) is
// distinguishable from an unreachable endpoint (3).
const (
	exitVerified   = 0
	exitUsage      = 1
	exitFailed     = 2 // evidence obtained, but verification/policy failed
	exitNoEvidence = 3 // could not obtain evidence (connect/parse/file)
)

// connectError marks a failure to obtain evidence or verification collateral
// (vs. a verification verdict), so the orchestration can map it to exit code 3.
type connectError struct{ err error }

func (e *connectError) Error() string { return e.err.Error() }
func (e *connectError) Unwrap() error { return e.err }

func isConnectError(err error) bool {
	var ce *connectError
	return errors.As(err, &ce)
}

// securityError marks a response that was reachable and well-formed but failed a
// security check (e.g. the attestation endpoint did not echo our nonce). Unlike
// a connectError it must NOT be swallowed by auto-mode's fall-through to the
// serving cert — a wrong nonce can signal replay or an active MITM.
type securityError struct{ err error }

func (e *securityError) Error() string { return e.err.Error() }
func (e *securityError) Unwrap() error { return e.err }

func isSecurityError(err error) bool {
	var se *securityError
	return errors.As(err, &se)
}

// Defaults preset a command's target shape so `c8s cds verify` is a thin
// shorthand for `c8s verify` with CDS conventions, sharing one implementation.
type Defaults struct {
	// Use is the command's name ("verify").
	Use string
	// Short is the one-line help.
	Short string
	// Kind preselects the component (cds|lb|workload|auto).
	Kind string
	// Mode preselects the evidence mode (auto|ratls-cert|attestation-endpoint).
	Mode string
	// DefaultPort is the port assumed when the target omits one (0 = by kind).
	DefaultPort int
}

type config struct {
	url           string
	kind          string
	mode          string
	server        string
	timeout       time.Duration
	fromFile      string
	discoveryPath string

	measurements        []string
	measurementsFile    string
	operatorKeys        string
	allowlistSeed       string
	allowlistSeedDigest string
	workloadImages      []string
	workloadInitImages  []string
	allowDebug          bool
	minTCBBootloader    uint
	minTCBTEE           uint
	minTCBSNP           uint
	minTCBMicrocode     uint
	expectedRDHex       string

	output       string
	showEvidence bool

	defaults Defaults
}

// NewCmd builds the verify command. The same constructor backs both the generic
// `c8s verify` and the `c8s cds verify` shorthand; d only changes defaults.
func NewCmd(d Defaults) *cobra.Command {
	cfg := config{defaults: d}
	use := d.Use
	if use == "" {
		use = "verify [target]"
	}
	short := d.Short
	if short == "" {
		short = "Verify a c8s component's TEE attestation"
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long: short + `.

Fetches a component's TEE attestation evidence (AMD SEV-SNP or Intel TDX) and
verifies it against the hardware signature chain plus a measurement / TCB /
policy, then reports the verdict.

Verification runs in-process using attestation-go — the Go port of the
attestation-rs engine the cluster runs. It auto-detects the platform and AMD
product — including Zen4c (Siena/Bergamo), which stock go-sev-guest cannot — so
the product line never has to be supplied by hand, and it fetches the VCEK for a
bare report from AMD KDS (bounded by --timeout), so the machine running it needs
outbound HTTPS to kdsintf.amd.com (no container runtime required).

Evidence sources:
  https://host:port      GET the discovery endpoint (/v1/discovery — cert +
                         evidence with the VCEK inline), or, in --mode ratls-cert,
                         dial the RA-TLS serving cert (bare report; the VCEK is
                         fetched from AMD KDS). Default mode: cds → ratls-cert,
                         lb → discovery, auto → discovery then serving cert.
  --from-file FILE       verify a saved PEM cert or attestation-response JSON.

  c8s cds verify https://cds.example.com:8443 --measurements <sha384-hex>
  c8s verify https://lb.example.com:443 --kind lb --measurements <sha384-hex>

Exit codes: 0 verified · 1 usage · 2 verification/policy failed · 3 evidence
unavailable (unreachable / unparseable).`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				cfg.url = args[0]
			}
			os.Exit(run(cmd.Context(), cfg, cmd.OutOrStdout(), cmd.ErrOrStderr()))
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&cfg.url, "url", "", "target URL or host:port (alternative to the positional argument)")
	f.StringVar(&cfg.kind, "kind", orDefault(d.Kind, "auto"), "component being verified: cds, lb, workload, or auto")
	f.StringVar(&cfg.mode, "mode", orDefault(d.Mode, "auto"), "evidence mode: auto, ratls-cert, discovery, or attestation-endpoint")
	f.StringVar(&cfg.discoveryPath, "discovery-path", defaultDiscoveryPath, "path of the LB discovery document (discovery mode)")
	f.StringVar(&cfg.server, "server-name", "", "TLS SNI server name (for port-forward / routed domains)")
	f.DurationVar(&cfg.timeout, "timeout", 15*time.Second, "per-attempt timeout (evidence fetch and AMD KDS collateral fetch)")
	f.StringVar(&cfg.fromFile, "from-file", "", "verify evidence from a saved PEM certificate or attestation-response JSON instead of dialing")

	f.StringSliceVar(&cfg.measurements, "measurements", nil, "allowed SHA-384 hex launch measurement(s) (repeatable / comma-separated); empty = no pinning (UNSAFE)")
	f.StringVar(&cfg.measurementsFile, "measurements-file", "", "file of allowed launch measurements, one hex digest per line")
	f.StringVar(&cfg.operatorKeys, "operator-keys", "", "PEM bundle of expected operator public keys; verification fails unless the target's attested config-claims digest matches this set (kind=cds targets)")
	f.StringVar(&cfg.allowlistSeed, "allowlist-seed", "", "expected allowlist seed JSON file; verification fails unless the target's attested seed digest matches its canonical digest (kind=cds targets)")
	f.StringVar(&cfg.allowlistSeedDigest, "allowlist-seed-digest", "", "expected hex SHA-256 canonical seed digest; alternative to --allowlist-seed")
	f.StringSliceVar(&cfg.workloadImages, "workload-image", nil, "expected main container image digest(s) (sha256:...; repeatable/comma-separated); with --workload-init-image, verification fails unless the target leaf's attested workload digest matches these role sets (docs/ratls.md)")
	f.StringSliceVar(&cfg.workloadInitImages, "workload-init-image", nil, "expected init container image digest(s) (sha256:...; repeatable/comma-separated); pairs with --workload-image")
	f.BoolVar(&cfg.allowDebug, "allow-debug", false, "accept debug-enabled guests")
	f.UintVar(&cfg.minTCBBootloader, "min-tcb-bootloader", 0, "minimum bootloader TCB component")
	f.UintVar(&cfg.minTCBTEE, "min-tcb-tee", 0, "minimum TEE TCB component")
	f.UintVar(&cfg.minTCBSNP, "min-tcb-snp", 0, "minimum SNP firmware TCB component")
	f.UintVar(&cfg.minTCBMicrocode, "min-tcb-microcode", 0, "minimum microcode TCB component")
	f.StringVar(&cfg.expectedRDHex, "expected-report-data", "", "hex REPORTDATA / TPM-nonce anchor override for bare evidence files (1–64 bytes, exactly as bound by the producer)")

	f.StringVarP(&cfg.output, "output", "o", "text", "output format: text or json")
	f.BoolVar(&cfg.showEvidence, "show-evidence", false, "print the raw report fields")

	return cmd
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// run performs the whole verification and renders the result, returning the
// process exit code. It is the unit-testable core (no os.Exit inside).
func run(ctx context.Context, cfg config, out, errOut io.Writer) int {
	policy, err := buildPolicy(cfg)
	if err != nil {
		fmt.Fprintf(errOut, "error: %v\n", err)
		return exitUsage
	}

	if cfg.url == "" && cfg.fromFile == "" {
		fmt.Fprintf(errOut, "error: no target: pass a component's discovery URL / host:port (or --from-file)\n")
		return exitUsage
	}

	// Verify in-process with attestation-go — the Go port of the engine the
	// cluster runs. It auto-detects the platform and AMD product (incl. Siena)
	// and fetches the VCEK from AMD KDS itself, so a bare RA-TLS report, a
	// discovery doc, and an endpoint response all verify through one path.
	var overrideERD []byte
	if cfg.expectedRDHex != "" {
		erd, perr := parseExpectedReportData(cfg.expectedRDHex)
		if perr != nil {
			fmt.Fprintf(errOut, "error: %v\n", perr)
			return exitUsage
		}
		overrideERD = erd
	}
	ev, err := gatherEvidence(ctx, cfg, overrideERD)
	if err != nil {
		fmt.Fprintf(errOut, "error: could not obtain evidence: %v\n", err)
		return exitNoEvidence
	}
	return verifyEvidence(ctx, cfg, policy, ev, gatherOperatorKeys(ctx, cfg, ev), out, errOut)
}

// operatorKeysReport is the pinned-operator-key section of the verdict. Keys
// authorize allowlist writes on CDS. The served list is informational on its
// own; when the target's evidence binds config-claims, applyClaimsPolicy
// requires digest to match the attested value.
type operatorKeysReport struct {
	fingerprints []string
	digest       []byte // KeySetDigest of the served list (nil when not fetched)
	note         string // non-empty when keys are absent/unavailable, explains why
	fetchErr     error  // non-nil when the fetch was attempted and failed
}

// gatherOperatorKeys fetches the CDS-pinned operator key fingerprints for
// kind=cds network targets. The fetch is bound to the attested serving cert
// (see fetchOperatorKeyFingerprints). A failed fetch degrades to a note for
// claims-free targets, but records fetchErr so applyClaimsPolicy can fail the
// verdict when the evidence binds config-claims: the served-vs-attested key
// cross-check is mandatory there, and an endpoint erroring on /operator-keys
// must not dodge it.
func gatherOperatorKeys(ctx context.Context, cfg config, ev *evidence) operatorKeysReport {
	if cfg.kind != "cds" || cfg.url == "" {
		return operatorKeysReport{}
	}
	if ev.certSHA256 == "" {
		return operatorKeysReport{note: "not fetched (no serving cert to bind to)"}
	}
	_, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return operatorKeysReport{note: "not fetched: " + err.Error()}
	}
	fps, digest, note, err := fetchOperatorKeyFingerprints(ctx, baseURL, cfg.server, ev.certSHA256, cfg.timeout)
	if err != nil {
		return operatorKeysReport{note: "not fetched: " + err.Error(), fetchErr: err}
	}
	return operatorKeysReport{fingerprints: fps, digest: digest, note: note}
}

// verifyEvidence verifies already-gathered evidence (from any source/mode)
// in-process with attestation-go (the Go port of the attestation-rs engine the
// cluster runs), which auto-detects the product and fetches the VCEK from KDS
// when it is not shipped inline — so a bare RA-TLS report and a discovery doc
// both work — then renders the verdict. The verification attempt (including the
// KDS fetch) is bounded by --timeout; an unobtainable-collateral failure is
// exit 3, not a verification verdict.
func verifyEvidence(ctx context.Context, cfg config, policy *ratls.VerifyPolicy, ev *evidence, opKeys operatorKeysReport, out, errOut io.Writer) int {
	if cfg.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}
	result, verr := verifyInProcess(ctx, ev, policy, minTCBFromCfg(cfg))
	if isConnectError(verr) {
		fmt.Fprintf(errOut, "error: could not fetch verification collateral: %v\n", verr)
		return exitNoEvidence
	}
	oc := newOutcome(cfg, ev, result, verr, policy)
	oc.OperatorKeys = opKeys.fingerprints
	oc.OperatorKeysNote = opKeys.note
	applyClaimsPolicy(&oc, ev, policy, opKeys)
	render(cfg, oc, out)
	if !oc.Verified {
		return exitFailed
	}
	return exitVerified
}

// buildPolicy parses the measurement allowlist and validates TCB bounds. The
// launch-measurement pin and min-TCB are enforced on the verifier verdict
// (newOutcome / verifyInProcess); only Measurements and AllowDebug are read
// downstream.
func buildPolicy(cfg config) (*ratls.VerifyPolicy, error) {
	// Each TCB component is a single byte; reject >255 rather than silently
	// truncating it (byte(256)==0 would weaken the policy without warning).
	for name, v := range map[string]uint{
		"--min-tcb-bootloader": cfg.minTCBBootloader,
		"--min-tcb-tee":        cfg.minTCBTEE,
		"--min-tcb-snp":        cfg.minTCBSNP,
		"--min-tcb-microcode":  cfg.minTCBMicrocode,
	} {
		if v > 255 {
			return nil, fmt.Errorf("%s is %d, must be 0-255", name, v)
		}
	}

	hexes := append([]string{}, cfg.measurements...)
	if cfg.measurementsFile != "" {
		data, err := os.ReadFile(cfg.measurementsFile)
		if err != nil {
			return nil, fmt.Errorf("read --measurements-file: %w", err)
		}
		hexes = append(hexes, strings.Split(string(data), "\n")...)
	}
	measurements, err := ratls.ParseHexMeasurementsList(hexes)
	if err != nil {
		return nil, err
	}

	var opKeysDigest []byte
	if cfg.operatorKeys != "" {
		pemBytes, err := os.ReadFile(cfg.operatorKeys)
		if err != nil {
			return nil, fmt.Errorf("read --operator-keys: %w", err)
		}
		keys, err := operatorauth.ParsePublicKeysPEM(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("--operator-keys: %w", err)
		}
		if opKeysDigest, err = operatorauth.KeySetDigest(keys); err != nil {
			return nil, err
		}
	}

	seedDigest, err := expectedSeedDigest(cfg)
	if err != nil {
		return nil, err
	}

	var workloadDigest []byte
	if len(cfg.workloadInitImages) > 0 || len(cfg.workloadImages) > 0 {
		if workloadDigest, err = workloadclaims.Digest(cfg.workloadInitImages, cfg.workloadImages); err != nil {
			return nil, fmt.Errorf("--workload-image/--workload-init-image: %w", err)
		}
	}

	return &ratls.VerifyPolicy{
		Measurements:       measurements,
		AllowDebug:         cfg.allowDebug,
		OperatorKeysDigest: opKeysDigest,
		SeedDigest:         seedDigest,
		WorkloadDigest:     workloadDigest,
	}, nil
}

// expectedSeedDigest resolves the seed pin from --allowlist-seed (a seed JSON
// file, digested canonically) or --allowlist-seed-digest (the hex digest
// directly). Nil means no seed pin.
func expectedSeedDigest(cfg config) ([]byte, error) {
	switch {
	case cfg.allowlistSeed != "" && cfg.allowlistSeedDigest != "":
		return nil, fmt.Errorf("--allowlist-seed and --allowlist-seed-digest are mutually exclusive")
	case cfg.allowlistSeed != "":
		data, err := os.ReadFile(cfg.allowlistSeed)
		if err != nil {
			return nil, fmt.Errorf("read --allowlist-seed: %w", err)
		}
		seed, err := pkgallowlist.ParseJSON(data)
		if err != nil {
			return nil, fmt.Errorf("--allowlist-seed: %w", err)
		}
		return seed.CanonicalDigest()
	case cfg.allowlistSeedDigest != "":
		digest, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(cfg.allowlistSeedDigest), "sha256:"))
		if err != nil {
			return nil, fmt.Errorf("--allowlist-seed-digest is not valid hex: %w", err)
		}
		if len(digest) != ratls.ClaimsDigestSize {
			return nil, fmt.Errorf("--allowlist-seed-digest decodes to %d bytes, want a SHA-256 digest (%d hex chars, optionally sha256:-prefixed)", len(digest), 2*ratls.ClaimsDigestSize)
		}
		return digest, nil
	default:
		return nil, nil
	}
}

func gatherEvidence(ctx context.Context, cfg config, overrideERD []byte) (*evidence, error) {
	if cfg.fromFile != "" {
		data, err := os.ReadFile(cfg.fromFile)
		if err != nil {
			return nil, err
		}
		return gatherFromFile(data, overrideERD, "file "+cfg.fromFile)
	}
	if cfg.url == "" {
		return nil, fmt.Errorf("no target: pass a host:port / URL argument or --from-file")
	}

	dialAddr, baseURL, err := normalizeTarget(cfg.url, defaultPort(cfg))
	if err != nil {
		return nil, err
	}

	switch resolveMode(cfg) {
	case "ratls-cert":
		return gatherFromRATLSCert(ctx, dialAddr, cfg.server, cfg.timeout)
	case "discovery":
		return gatherFromDiscovery(ctx, baseURL, cfg.discoveryPath, cfg.server, cfg.timeout)
	case "attestation-endpoint":
		return gatherFromEndpoint(ctx, baseURL, cfg.server, cfg.timeout)
	default: // auto: try the LB discovery doc (what the chart serves), then the
		// serving cert. Don't fall back on a security error — surface it.
		ev, err := gatherFromDiscovery(ctx, baseURL, cfg.discoveryPath, cfg.server, cfg.timeout)
		if err != nil && !isSecurityError(err) {
			return gatherFromRATLSCert(ctx, dialAddr, cfg.server, cfg.timeout)
		}
		return ev, err
	}
}

// resolveMode maps mode+kind to a concrete evidence mode.
func resolveMode(cfg config) string {
	if cfg.mode != "" && cfg.mode != "auto" {
		return cfg.mode
	}
	switch cfg.kind {
	case "lb":
		return "discovery"
	case "cds", "workload":
		return "ratls-cert"
	default: // auto (or unknown kind): let gatherEvidence try the LB discovery
		// doc, then the RA-TLS serving cert, so a bare target with no --kind is
		// detected either way. Returning a concrete mode here would defeat that.
		return "auto"
	}
}

func defaultPort(cfg config) int {
	if cfg.defaults.DefaultPort != 0 {
		return cfg.defaults.DefaultPort
	}
	switch cfg.kind {
	case "cds":
		return 8443
	default:
		return 443
	}
}

// normalizeTarget turns a URL or host[:port] into (dialAddr, baseURL).
// IPv6 literals are handled via net.JoinHostPort so they are bracketed correctly.
func normalizeTarget(raw string, port int) (dialAddr, baseURL string, err error) {
	defPort := strconv.Itoa(port)
	if strings.Contains(raw, "://") {
		u, perr := url.Parse(raw)
		if perr != nil {
			return "", "", fmt.Errorf("parse url %q: %w", raw, perr)
		}
		host := u.Hostname()
		if host == "" {
			return "", "", fmt.Errorf("url %q has no host", raw)
		}
		p := u.Port()
		if p == "" {
			p = defPort
		}
		dialAddr = net.JoinHostPort(host, p)
		return dialAddr, u.Scheme + "://" + dialAddr, nil
	}
	// SplitHostPort distinguishes "host:port" from a bare IPv6 literal (which has
	// colons but no port); on failure we treat raw as a host needing defPort.
	if host, p, splitErr := net.SplitHostPort(raw); splitErr == nil {
		dialAddr = net.JoinHostPort(host, p)
	} else {
		dialAddr = net.JoinHostPort(raw, defPort)
	}
	return dialAddr, "https://" + dialAddr, nil
}

// Outcome is the JSON-serializable verdict.
type Outcome struct {
	Verified    bool      `json:"verified"`
	VerifiedAt  time.Time `json:"verified_at"`
	Backend     string    `json:"backend"`
	Source      string    `json:"source"`
	Fresh       bool      `json:"fresh"`
	Binding     string    `json:"binding"`
	Platform    string    `json:"platform,omitempty"`
	Measurement string    `json:"measurement,omitempty"`
	ReportData  string    `json:"report_data,omitempty"`
	Debug       bool      `json:"debug,omitempty"`
	SMT         bool      `json:"smt,omitempty"`
	CurrentTCB  string    `json:"current_tcb,omitempty"`
	CertSHA256  string    `json:"cert_sha256,omitempty"`
	Pinned      bool      `json:"measurement_pinned"`
	Error       string    `json:"error,omitempty"`

	// OperatorKeys are hex SHA-256 fingerprints (of the PKIX/SPKI DER) of the
	// operator public keys the target pins for allowlist writes (served list,
	// kind=cds only). The *AttestedDigest fields carry the digests bound in
	// the evidence's config-claims (docs/ratls.md); when set, the
	// served key list was required to match, and --operator-keys /
	// --allowlist-seed pin against them.
	OperatorKeys               []string `json:"operator_keys,omitempty"`
	OperatorKeysNote           string   `json:"operator_keys_note,omitempty"`
	OperatorKeysAttestedDigest string   `json:"operator_keys_attested_digest,omitempty"`
	SeedAttestedDigest         string   `json:"allowlist_seed_attested_digest,omitempty"`
	WorkloadAttestedDigest     string   `json:"workload_attested_digest,omitempty"`
}

// applyClaimsPolicy surfaces the attested config-claims digests and fails the
// verdict when a --operator-keys / --allowlist-seed pin or the
// served-vs-attested key check does not hold. It only ever demotes Verified —
// the claims are proven by the evidence newOutcome already judged, so nothing
// here can rescue a failed verification (docs/ratls.md).
func applyClaimsPolicy(oc *Outcome, ev *evidence, policy *ratls.VerifyPolicy, opKeys operatorKeysReport) {
	// Surface digests only when the hardware evidence verified: "attested" must
	// never label extension bytes whose binding was not proven.
	if oc.Verified && ev.configClaims != nil {
		oc.OperatorKeysAttestedDigest = hex.EncodeToString(ev.configClaims.OperatorKeysDigest)
		if ev.configClaims.HasSeed() {
			oc.SeedAttestedDigest = hex.EncodeToString(ev.configClaims.SeedDigest)
		} else {
			oc.SeedAttestedDigest = "none (no seed configured)"
		}
		if ev.configClaims.HasWorkload() {
			oc.WorkloadAttestedDigest = hex.EncodeToString(ev.configClaims.WorkloadDigest)
		}
	}
	fail := func(format string, args ...any) {
		oc.Verified = false
		if oc.Error == "" {
			oc.Error = fmt.Sprintf(format, args...)
		}
	}
	if ev.claimsErr != nil {
		fail("config-claims extension unparseable (newer target than this CLI?): %v", ev.claimsErr)
		return
	}
	pinned := len(policy.OperatorKeysDigest) > 0 || len(policy.SeedDigest) > 0 || len(policy.WorkloadDigest) > 0
	if pinned && ev.configClaims == nil {
		fail("config-claims pin set but the evidence binds no config-claims (target predates config attestation, or is not a CDS serving cert)")
		return
	}
	if len(policy.OperatorKeysDigest) > 0 && !bytes.Equal(ev.configClaims.OperatorKeysDigest, policy.OperatorKeysDigest) {
		fail("attested operator-keys digest %x does not match the --operator-keys set (%x)", ev.configClaims.OperatorKeysDigest, policy.OperatorKeysDigest)
	}
	if len(policy.SeedDigest) > 0 && !bytes.Equal(ev.configClaims.SeedDigest, policy.SeedDigest) {
		fail("attested allowlist-seed digest %x does not match the expected seed (%x)", ev.configClaims.SeedDigest, policy.SeedDigest)
	}
	if len(policy.WorkloadDigest) > 0 && !bytes.Equal(ev.configClaims.WorkloadDigest, policy.WorkloadDigest) {
		fail("attested workload digest %x does not match the --workload-image set (%x)", ev.configClaims.WorkloadDigest, policy.WorkloadDigest)
	}
	// The served key list must be the set the measured code attested to
	// loading; a mismatch means MITM on the fetch or a CDS bug. A failed fetch
	// fails closed too: an endpoint erroring on /operator-keys must not dodge
	// a mandatory cross-check (a 404 is not an error — it maps to the
	// empty-set digest in fetchOperatorKeyFingerprints).
	if ev.configClaims != nil && opKeys.fetchErr != nil {
		fail("could not fetch /operator-keys to cross-check the attested operator-key set: %v", opKeys.fetchErr)
	}
	if ev.configClaims != nil && len(opKeys.digest) > 0 && !bytes.Equal(opKeys.digest, ev.configClaims.OperatorKeysDigest) {
		fail("served /operator-keys digest %x does not match the attested config-claims digest %x", opKeys.digest, ev.configClaims.OperatorKeysDigest)
	}
}

// newOutcome maps a verifier verdict to the shared Outcome. The verifier proves
// the AMD chain, REPORTDATA binding, debug, and min-TCB; the launch-measurement
// allowlist (--measurements) has no verifier-side input, so it is enforced here
// and fails closed.
func newOutcome(cfg config, ev *evidence, result *teetypes.VerificationResult, verr error, policy *ratls.VerifyPolicy) Outcome {
	pinned := len(policy.Measurements) > 0
	oc := Outcome{
		Backend:    "attestation-go",
		VerifiedAt: time.Now().UTC(),
		Source:     ev.source,
		Fresh:      ev.fresh,
		Binding:    ev.bindingNote,
		CertSHA256: ev.certSHA256,
		Pinned:     pinned,
	}
	if verr != nil {
		oc.Error = verr.Error()
		return oc
	}
	// Prefer the platform the verifier reported; fall back to what we sent.
	oc.Platform = string(result.Platform)
	if oc.Platform == "" {
		oc.Platform = ev.platform
	}
	oc.Measurement = result.Claims.LaunchDigest
	oc.CurrentTCB = formatTCB(result.Claims.TCB)

	if pinned {
		mb, err := hex.DecodeString(result.Claims.LaunchDigest)
		if err != nil || len(mb) == 0 {
			oc.Error = fmt.Sprintf("cannot enforce --measurements: launch_digest is missing or malformed (%q)", result.Claims.LaunchDigest)
			return oc
		}
		if !ratls.MeasurementAllowed(mb, policy.Measurements) {
			oc.Error = "launch measurement not in --measurements allowlist"
			return oc
		}
	}
	oc.Verified = true
	return oc
}

// minTCBFromCfg builds the verifier's min-TCB floor from the --min-tcb-* flags,
// or nil when none are set. buildPolicy already range-checked them (≤255).
func minTCBFromCfg(cfg config) *teetypes.SnpTcb {
	if cfg.minTCBBootloader == 0 && cfg.minTCBTEE == 0 && cfg.minTCBSNP == 0 && cfg.minTCBMicrocode == 0 {
		return nil
	}
	return &teetypes.SnpTcb{
		Bootloader: byte(cfg.minTCBBootloader),
		Tee:        byte(cfg.minTCBTEE),
		Snp:        byte(cfg.minTCBSNP),
		Microcode:  byte(cfg.minTCBMicrocode),
	}
}

// formatTCB renders the verified TCB for display: SNP shows its components, TDX
// the raw SVN. Returns "" when the verifier reported no TCB.
func formatTCB(tcb teetypes.TcbInfo) string {
	deref := func(p *uint8) uint8 {
		if p == nil {
			return 0
		}
		return *p
	}
	switch tcb.Type {
	case "Snp":
		s := fmt.Sprintf("bootloader=%d tee=%d snp=%d microcode=%d",
			deref(tcb.Bootloader), deref(tcb.Tee), deref(tcb.Snp), deref(tcb.Microcode))
		if tcb.FMC != nil {
			s += fmt.Sprintf(" fmc=%d", *tcb.FMC)
		}
		return s
	case "Tdx":
		if len(tcb.TCBSvn) > 0 {
			return "svn=" + hex.EncodeToString(tcb.TCBSvn)
		}
	}
	return ""
}

func render(cfg config, oc Outcome, out io.Writer) {
	if cfg.output == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(oc)
		return
	}
	renderText(cfg, oc, out)
}

func renderText(cfg config, oc Outcome, out io.Writer) {
	if oc.Verified {
		fmt.Fprintf(out, "✓ VERIFIED  (%s backend)\n", oc.Backend)
	} else {
		fmt.Fprintf(out, "✗ NOT VERIFIED  (%s backend)\n", oc.Backend)
	}
	fmt.Fprintf(out, "  source:       %s\n", oc.Source)
	fmt.Fprintf(out, "  verified at:  %s\n", oc.VerifiedAt.Format(time.RFC3339))
	if oc.Error != "" {
		fmt.Fprintf(out, "  reason:       %s\n", oc.Error)
		return
	}
	fmt.Fprintf(out, "  platform:     %s\n", oc.Platform)
	fmt.Fprintf(out, "  measurement:  %s\n", oc.Measurement)
	fmt.Fprintf(out, "  TCB:          %s   debug=%t smt=%t\n", oc.CurrentTCB, oc.Debug, oc.SMT)
	if oc.CertSHA256 != "" {
		fmt.Fprintf(out, "  cert sha256:  %s\n", oc.CertSHA256)
	}
	fmt.Fprintf(out, "  binding:      %s\n", oc.Binding)
	if oc.OperatorKeysAttestedDigest != "" {
		fmt.Fprintf(out, "  operator-keys digest (attested via config-claims): sha256:%s\n", oc.OperatorKeysAttestedDigest)
	}
	if oc.SeedAttestedDigest != "" {
		fmt.Fprintf(out, "  allowlist-seed digest (attested via config-claims): %s\n", oc.SeedAttestedDigest)
	}
	if oc.WorkloadAttestedDigest != "" {
		fmt.Fprintf(out, "  workload digest (attested via config-claims): sha256:%s\n", oc.WorkloadAttestedDigest)
	}
	if len(oc.OperatorKeys) > 0 {
		label := "operator keys (allowlist writes; CDS-reported config, NOT covered by the measurement):"
		if oc.OperatorKeysAttestedDigest != "" {
			label = "operator keys (allowlist writes; served list matches the attested digest):"
		}
		fmt.Fprintf(out, "  %s\n", label)
		for _, fp := range oc.OperatorKeys {
			fmt.Fprintf(out, "    sha256:%s\n", fp)
		}
	} else if oc.OperatorKeysNote != "" {
		fmt.Fprintf(out, "  operator keys: %s\n", oc.OperatorKeysNote)
	}
	if !oc.Fresh {
		fmt.Fprintf(out, "  note:         freshness NOT proven (no per-request nonce bound)\n")
	}
	if !oc.Pinned {
		fmt.Fprintf(out, "  WARNING:      no --measurements pinned — any genuine TEE is accepted (UNSAFE for production)\n")
	}
	if cfg.showEvidence {
		fmt.Fprintf(out, "  report_data:  %s\n", oc.ReportData)
	}
}
