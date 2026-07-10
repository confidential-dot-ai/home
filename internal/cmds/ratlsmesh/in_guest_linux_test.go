//go:build linux

package ratlsmesh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoadInGuestConfigDefaults(t *testing.T) {
	c := loadInGuestConfig(func(string) string { return "" })
	if c.platform != "sev-snp" {
		t.Errorf("platform default = %q, want sev-snp", c.platform)
	}
	if c.logLevel != "info" {
		t.Errorf("logLevel default = %q, want info", c.logLevel)
	}
	if c.attestationServiceURL != defaultInGuestAttestationServiceURL {
		t.Errorf("attestationServiceURL default = %q, want %q", c.attestationServiceURL, defaultInGuestAttestationServiceURL)
	}
}

func TestLoadInGuestConfigPopulatesFromEnv(t *testing.T) {
	envs := map[string]string{
		envWorkloadID:            "alice",
		envCDSURL:                "https://cds.c8s-system.svc:8443",
		envAttestationServiceURL: "http://127.0.0.1:8400",
		envLogLevel:              "debug",
		envPlatform:              "sev-snp",
		envCDSMeasurements:       "aa,bb",
		envMeshMeasurements:      "cc",
		envPodIP:                 "10.0.0.5",
	}
	c := loadInGuestConfig(func(k string) string { return envs[k] })
	if c.workloadID != "alice" {
		t.Errorf("workloadID = %q, want alice", c.workloadID)
	}
	if c.cdsURL != envs[envCDSURL] {
		t.Errorf("cdsURL = %q", c.cdsURL)
	}
	if c.attestationServiceURL != envs[envAttestationServiceURL] {
		t.Errorf("attestationServiceURL = %q", c.attestationServiceURL)
	}
	if c.logLevel != "debug" {
		t.Errorf("logLevel = %q", c.logLevel)
	}
	if c.podIP != "10.0.0.5" {
		t.Errorf("podIP = %q", c.podIP)
	}
}

func TestInGuestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     inGuestConfig
		wantErr string // "" = expect no error
	}{
		{
			name: "valid",
			cfg: inGuestConfig{
				workloadID:            "alice",
				cdsURL:                "https://cds:8443",
				attestationServiceURL: "http://127.0.0.1:8400",
				certTTL:               24 * time.Hour,
			},
		},
		{
			name: "missing workload id",
			cfg: inGuestConfig{
				cdsURL:                "https://cds:8443",
				attestationServiceURL: "http://127.0.0.1:8400",
				certTTL:               24 * time.Hour,
			},
			wantErr: envWorkloadID,
		},
		{
			name: "missing cds url",
			cfg: inGuestConfig{
				workloadID:            "alice",
				attestationServiceURL: "http://127.0.0.1:8400",
				certTTL:               24 * time.Hour,
			},
			wantErr: envCDSURL,
		},
		{
			name: "bare cds host (no scheme) is rejected",
			cfg: inGuestConfig{
				workloadID:            "alice",
				cdsURL:                "cds:8443",
				attestationServiceURL: "http://127.0.0.1:8400",
				certTTL:               24 * time.Hour,
			},
			wantErr: "must start with http://",
		},
		{
			name: "bare attestation URL (no scheme) is rejected",
			cfg: inGuestConfig{
				workloadID:            "alice",
				cdsURL:                "https://cds:8443",
				attestationServiceURL: "127.0.0.1:8400",
				certTTL:               24 * time.Hour,
			},
			wantErr: "must start with http://",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestResolvePodIPFromEnv(t *testing.T) {
	ip, err := resolvePodIP("10.42.0.7")
	if err != nil {
		t.Fatalf("resolvePodIP: %v", err)
	}
	if ip != "10.42.0.7" {
		t.Errorf("got %q, want 10.42.0.7", ip)
	}
}

func TestResolvePodIPRejectsInvalid(t *testing.T) {
	_, err := resolvePodIP("not-an-ip")
	if err == nil {
		t.Fatal("expected error for non-IP env value")
	}
	if !strings.Contains(err.Error(), "not a valid IP") {
		t.Errorf("error %v lacks 'not a valid IP'", err)
	}
}

func TestInGuestResolver(t *testing.T) {
	r := &inGuestResolver{podIP: "10.0.0.5"}

	// Local pod IP resolves to itself, local=true.
	gotIP, local := r.Resolve("10.0.0.5")
	if gotIP != "10.0.0.5" || !local {
		t.Errorf("Resolve(local) = (%q, %v), want (10.0.0.5, true)", gotIP, local)
	}

	// Remote pod IP resolves to itself, local=false.
	gotIP, local = r.Resolve("10.0.0.10")
	if gotIP != "10.0.0.10" || local {
		t.Errorf("Resolve(remote) = (%q, %v), want (10.0.0.10, false)", gotIP, local)
	}

	// ValidateOutboundDest: loopback rejected.
	ok, reason := r.ValidateOutboundDest("127.0.0.1")
	if ok || reason != "loopback" {
		t.Errorf("ValidateOutboundDest(127.0.0.1) = (%v, %q), want (false, loopback)", ok, reason)
	}

	// ValidateOutboundDest: garbage rejected.
	ok, reason = r.ValidateOutboundDest("not-an-ip")
	if ok || reason != "invalid_ip" {
		t.Errorf("ValidateOutboundDest(not-an-ip) = (%v, %q), want (false, invalid_ip)", ok, reason)
	}

	// ValidateOutboundDest: ordinary remote allowed.
	ok, _ = r.ValidateOutboundDest("10.0.0.10")
	if !ok {
		t.Errorf("ValidateOutboundDest(10.0.0.10) = false, want true")
	}

	// ValidateLocalDest: only the configured podIP matches.
	if !r.ValidateLocalDest("10.0.0.5") {
		t.Error("ValidateLocalDest(podIP) should be true")
	}
	if r.ValidateLocalDest("10.0.0.10") {
		t.Error("ValidateLocalDest(other) should be false")
	}
}

func TestBuildInGuestIptablesRules(t *testing.T) {
	rules := buildInGuestIptablesRules(inGuestOutboundPort, inGuestInboundPort, inGuestHealthPort, nil)
	if len(rules) == 0 {
		t.Fatal("expected non-empty rule set")
	}

	// Sanity: every rule should be on the nat table.
	for i, r := range rules {
		if r.table != "nat" {
			t.Errorf("rule %d table=%q, want nat", i, r.table)
		}
		if r.chain != chainName && r.chain != preroutingChainName {
			t.Errorf("rule %d chain=%q, want %s or %s", i, r.chain, chainName, preroutingChainName)
		}
	}

	// The OUTPUT chain must contain a proxy-uid RETURN somewhere before
	// the catch-all REDIRECT, otherwise the proxy will loop on itself.
	var sawUIDReturn, sawOutputRedirect bool
	for _, r := range rules {
		if r.chain != chainName {
			continue
		}
		if containsArgPair(r.args, "--uid-owner", "1337") && containsArg(r.args, "RETURN") {
			sawUIDReturn = true
		}
		if !sawOutputRedirect && containsArgPair(r.args, "-j", "REDIRECT") && containsArgPair(r.args, "--to-port", "15001") {
			sawOutputRedirect = true
			if !sawUIDReturn {
				t.Error("OUTPUT REDIRECT rule appears before the proxy-UID RETURN — proxy will loop on itself")
			}
		}
	}
	if !sawUIDReturn {
		t.Error("no proxy-UID RETURN rule on OUTPUT chain")
	}
	if !sawOutputRedirect {
		t.Error("no OUTPUT REDIRECT rule to 15001")
	}

	// The PREROUTING chain must end at a REDIRECT to 15006.
	var sawPreroutingRedirect bool
	for _, r := range rules {
		if r.chain != preroutingChainName {
			continue
		}
		if containsArgPair(r.args, "-j", "REDIRECT") && containsArgPair(r.args, "--to-port", "15006") {
			sawPreroutingRedirect = true
		}
	}
	if !sawPreroutingRedirect {
		t.Error("no PREROUTING REDIRECT rule to 15006")
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// The passthrough RETURN must sit on PREROUTING before the catch-all
// REDIRECT, and must never appear when no ports are configured.
func TestBuildInGuestIptablesRules_InboundPassthrough(t *testing.T) {
	rules := buildInGuestIptablesRules(inGuestOutboundPort, inGuestInboundPort, inGuestHealthPort, []int{8443, 9000})

	var sawPassthrough, sawRedirect bool
	for _, r := range rules {
		if r.chain != preroutingChainName {
			continue
		}
		if containsArgPair(r.args, "--dports", "8443,9000") && containsArgPair(r.args, "-j", "RETURN") {
			sawPassthrough = true
			if sawRedirect {
				t.Error("passthrough RETURN appears after the catch-all REDIRECT — it would never match")
			}
		}
		if containsArgPair(r.args, "-j", "REDIRECT") && containsArgPair(r.args, "--to-port", "15006") {
			sawRedirect = true
		}
	}
	if !sawPassthrough {
		t.Error("no PREROUTING passthrough RETURN for 8443,9000")
	}
	if !sawRedirect {
		t.Error("no PREROUTING REDIRECT rule to 15006")
	}

	for _, r := range buildInGuestIptablesRules(inGuestOutboundPort, inGuestInboundPort, inGuestHealthPort, nil) {
		if r.label == "in-guest-prerouting-passthrough" {
			t.Error("passthrough rule rendered with no ports configured")
		}
	}
}

// iptables' multiport match caps at 15 ports; a longer passthrough list must
// chunk across rules (all still ahead of the catch-all REDIRECT), not emit
// one over-long rule that fails at install time.
func TestBuildInGuestIptablesRules_PassthroughMultiportChunking(t *testing.T) {
	ports := make([]int, 17)
	for i := range ports {
		ports[i] = 8000 + i
	}
	rules := buildInGuestIptablesRules(inGuestOutboundPort, inGuestInboundPort, inGuestHealthPort, ports)

	var chunks []string
	sawRedirect := false
	for _, r := range rules {
		if r.chain != preroutingChainName {
			continue
		}
		if r.label == "in-guest-prerouting-passthrough" {
			if sawRedirect {
				t.Error("passthrough chunk appears after the catch-all REDIRECT — it would never match")
			}
			for i, a := range r.args {
				if a == "--dports" {
					chunks = append(chunks, r.args[i+1])
				}
			}
		}
		if containsArgPair(r.args, "-j", "REDIRECT") {
			sawRedirect = true
		}
	}
	if len(chunks) != 2 {
		t.Fatalf("got %d passthrough rules for 17 ports, want 2 (chunks: %v)", len(chunks), chunks)
	}
	if got := len(strings.Split(chunks[0], ",")); got != 15 {
		t.Errorf("first chunk carries %d ports, want 15", got)
	}
	if got := len(strings.Split(chunks[1], ",")); got != 2 {
		t.Errorf("second chunk carries %d ports, want 2", got)
	}
}

func TestParseInboundPassthrough(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		want    []int
		wantErr bool
	}{
		{raw: "", want: nil},
		{raw: "tcp:8443", want: []int{8443}},
		{raw: " tcp:8443 , tcp:9000 ", want: []int{8443, 9000}},
		{raw: "tcp:8443,tcp:8443", want: []int{8443}}, // deduped
		{raw: "udp:53", wantErr: true},                // redirect is tcp-only
		{raw: "8443", wantErr: true},                  // missing proto
		{raw: "tcp:0", wantErr: true},
		{raw: "tcp:65536", wantErr: true},
		{raw: "tcp:x", wantErr: true},
		{raw: "tcp:15006", wantErr: true}, // mesh listener port
		{raw: "tcp:15001", wantErr: true},
		{raw: "tcp:15021", wantErr: true},
	} {
		got, err := parseInboundPassthrough(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseInboundPassthrough(%q): want error, got %v", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseInboundPassthrough(%q): unexpected error %v", tc.raw, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("parseInboundPassthrough(%q) = %v, want %v", tc.raw, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseInboundPassthrough(%q) = %v, want %v", tc.raw, got, tc.want)
				break
			}
		}
	}
}

func containsArgPair(args []string, key, val string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == val {
			return true
		}
	}
	return false
}

// stubReadyServer returns an httptest.Server that responds to /ready
// with the configured status. The caller is responsible for closing the
// server.
func stubReadyServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
	return httptest.NewServer(mux)
}

func TestProbeReadinessHealthy(t *testing.T) {
	srv := stubReadyServer(t, http.StatusOK)
	defer srv.Close()

	res := probeReadiness(context.Background(), srv.URL+"/ready", 2*time.Second)
	if !res.OK {
		t.Fatalf("probeReadiness OK=false, status=%d err=%v", res.Status, res.Err)
	}
	if res.Status != http.StatusOK {
		t.Errorf("status=%d, want 200", res.Status)
	}
}

func TestProbeReadinessUnhealthy(t *testing.T) {
	srv := stubReadyServer(t, http.StatusServiceUnavailable)
	defer srv.Close()

	res := probeReadiness(context.Background(), srv.URL+"/ready", 2*time.Second)
	if res.OK {
		t.Fatal("probeReadiness OK=true, want false for 503")
	}
	if res.Status != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503", res.Status)
	}
}

func TestProbeReadinessUnreachable(t *testing.T) {
	// Closed port: no server listening at all.
	res := probeReadiness(context.Background(), "http://127.0.0.1:1/ready", 200*time.Millisecond)
	if res.OK {
		t.Fatal("probeReadiness OK=true for unreachable target, want false")
	}
	if res.Err == nil {
		t.Fatal("expected connection error, got nil")
	}
}

func TestReadinessCheckCommandSucceedsAgainstHealthy(t *testing.T) {
	srv := stubReadyServer(t, http.StatusOK)
	defer srv.Close()

	// Extract the port the stub bound on.
	addr := strings.TrimPrefix(srv.URL, "http://")
	host, port, found := strings.Cut(addr, ":")
	if !found || host != "127.0.0.1" {
		t.Fatalf("unexpected stub server addr %q", addr)
	}

	cmd := newReadinessCheckCommand()
	cmd.SetArgs([]string{
		"--health-port", port,
		"--retries", "0",
		"--timeout", "1s",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("readiness-check returned error against healthy stub: %v", err)
	}
}

func TestReadinessCheckCommandFailsAgainstUnreachable(t *testing.T) {
	cmd := newReadinessCheckCommand()
	cmd.SetArgs([]string{
		"--health-port", "1", // privileged port that nothing in this test binds
		"--retries", "0",
		"--timeout", "200ms",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := cmd.ExecuteContext(ctx)
	if err == nil {
		t.Fatal("expected readiness-check to fail when no server is listening")
	}
}
