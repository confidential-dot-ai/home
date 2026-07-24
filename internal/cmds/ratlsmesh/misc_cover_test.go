//go:build linux

package ratlsmesh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/ratls/cdsclient"
)

func TestHealthServerServe(t *testing.T) {
	h := newHealthServer(testMetrics(), nil, nil, 10, time.Second, time.Second)
	h.ready.Store(true)
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- h.serve(ctx, fmt.Sprintf("127.0.0.1:%d", port)) }()

	assertEventually(t, 5*time.Second, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/live", port))
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "health serve never answered /live")

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve() = %v, want nil after shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop on cancel")
	}

	// A second serve on an already-bound port errors immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := h.serve(context.Background(), ln.Addr().String()); err == nil {
		t.Fatal("serve on a bound port should error")
	}
}

func TestHealthReadyCertProvisioningGates(t *testing.T) {
	_, mgr, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:   "sev-snp",
		AttestFunc: fakeAttestFunc,
		CertTTL:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name           string
		server, client *ratls.CertManager
	}{
		{"server cert not provisioned", mgr, nil},
		{"client cert not provisioned", nil, mgr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHealthServer(testMetrics(), tc.server, tc.client, 10, time.Second, time.Second)
			h.ready.Store(true)
			rec := httptest.NewRecorder()
			h.handleReady(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
			if mgr.CertReady() {
				t.Skip("cert manager unexpectedly pre-provisioned")
			}
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "not provisioned") {
				t.Errorf("body = %q", rec.Body.String())
			}
		})
	}
}

func TestDefaultOrigDstFunc(t *testing.T) {
	// Not a TCP connection.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := defaultOrigDstFunc(a); err == nil {
		t.Error("expected error for non-TCP connection")
	}

	// A real TCP connection that was never REDIRECTed has no
	// SO_ORIGINAL_DST entry; both family lookups run and fail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 1)
			c.Read(buf)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if dst, err := defaultOrigDstFunc(conn); err == nil && dst == "" {
		t.Error("expected either an error or a non-empty destination")
	}
}

func TestNtohs(t *testing.T) {
	kernel := [2]byte{0x1f, 0x90} // 8080 in network byte order
	n := binary.NativeEndian.Uint16(kernel[:])
	if got := ntohs(n); got != 8080 {
		t.Errorf("ntohs = %d, want 8080", got)
	}
}

func TestIfaceAllowed(t *testing.T) {
	if !ifaceAllowed("cni0", []string{"lo", "cni0"}) {
		t.Error("cni0 should be allowed")
	}
	if ifaceAllowed("eth0", []string{"lo", "cni0"}) {
		t.Error("eth0 should not be allowed")
	}
}

func TestDefaultLocalRouteCheck(t *testing.T) {
	if ok, err := defaultLocalRouteCheck("10.0.0.1", nil); ok || err != nil {
		t.Errorf("empty allowlist: got (%v,%v), want (false,nil)", ok, err)
	}
	if ok, err := defaultLocalRouteCheck("not-an-ip", []string{"lo"}); ok || err != nil {
		t.Errorf("bad IP: got (%v,%v), want (false,nil)", ok, err)
	}
	// The kernel routes 127.0.0.1 via lo. Netlink route-get is read-only and
	// works unprivileged; tolerate environments where it does not.
	ok, err := defaultLocalRouteCheck("127.0.0.1", []string{"lo"})
	if err == nil && !ok {
		t.Error("route to 127.0.0.1 should use lo")
	}
	if ok2, err2 := defaultLocalRouteCheck("127.0.0.1", []string{"cni0"}); err2 == nil && ok2 {
		t.Error("route to 127.0.0.1 should not match cni0-only allowlist")
	}
}

func TestAddrIP(t *testing.T) {
	ipn := &net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)}
	if got := addrIP(ipn); !got.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("addrIP(IPNet) = %v", got)
	}
	ipa := &net.IPAddr{IP: net.ParseIP("fd00::1")}
	if got := addrIP(ipa); !got.Equal(net.ParseIP("fd00::1")) {
		t.Errorf("addrIP(IPAddr) = %v", got)
	}
	if got := addrIP(&net.TCPAddr{IP: net.ParseIP("10.0.0.1")}); got != nil {
		t.Errorf("addrIP(TCPAddr) = %v, want nil", got)
	}
}

func TestResolvePodIPAutoDetect(t *testing.T) {
	ip, err := resolvePodIP("")
	if err != nil {
		if !strings.Contains(err.Error(), "no usable") {
			t.Errorf("unexpected auto-detect error: %v", err)
		}
		return
	}
	if net.ParseIP(ip) == nil {
		t.Errorf("auto-detected pod IP %q is not a valid IP", ip)
	}
}

func TestK8sResolverCacheSize(t *testing.T) {
	r := &k8sResolver{
		nodeIP: "10.0.0.1",
		logger: testLogger(),
		podMap: map[string]podEntry{
			"10.244.0.5": {nodeIP: "10.0.0.1"},
			"10.244.0.6": {nodeIP: "10.0.0.2"},
		},
	}
	if got := r.CacheSize(); got != 2 {
		t.Errorf("CacheSize() = %d, want 2", got)
	}
}

func TestRunLocalCIDRRefreshLoop(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.244.0.0/24")
	r := &k8sResolver{
		nodeIP:          "10.0.0.1",
		logger:          testLogger(),
		podMap:          map[string]podEntry{},
		localRouteCheck: passthroughLocalRouteCheck,
		localCIDRSource: func(string) ([]localCIDR, error) {
			return testLocalCIDRs(cidr), nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.runLocalCIDRRefreshLoop(ctx, 5*time.Millisecond)
		close(done)
	}()
	assertEventually(t, 5*time.Second, func() bool { return r.LocalCIDRCount() == 1 }, "refresh loop never reconciled")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh loop did not stop on cancel")
	}
}

func TestTryAcquireAndReleaseSrc(t *testing.T) {
	p := &Proxy{maxConnsPerSrc: 2}
	c1, ok := p.tryAcquireSrc("10.0.0.1")
	if !ok || c1 == nil {
		t.Fatal("first acquire should succeed")
	}
	c2, ok := p.tryAcquireSrc("10.0.0.1")
	if !ok || c2 != c1 {
		t.Fatal("second acquire should succeed on the same counter")
	}
	if _, ok := p.tryAcquireSrc("10.0.0.1"); ok {
		t.Fatal("third acquire should hit the limit")
	}
	p.releaseSrc("10.0.0.1", c1)
	p.releaseSrc("10.0.0.1", c1)
	if len(p.srcConns) != 0 {
		t.Errorf("srcConns not cleaned up: %v", p.srcConns)
	}
	// A stale counter must not delete a newer one.
	fresh, _ := p.tryAcquireSrc("10.0.0.1")
	p.releaseSrc("10.0.0.1", c1) // stale: drops to -1, map entry is fresh's
	if got := p.srcConns["10.0.0.1"]; got != fresh {
		t.Error("stale release removed the fresh counter")
	}
	p.releaseSrc("10.0.0.1", fresh)
}

// TestServeConnectionLimits drives Proxy.Run so serve's semaphore and
// per-source budget branches execute in the real accept loop.
func TestServeConnectionLimits(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	for _, tc := range []struct {
		name    string
		sem     int
		perSrc  int
		counter func(m *metrics) float64
	}{
		{"global limit", 1, 0, func(m *metrics) float64 { return testutil.ToFloat64(m.connLimitRejected) }},
		{"per-source limit", 2, 1, func(m *metrics) float64 { return testutil.ToFloat64(m.connLimitPerSourceRejected) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testMetrics()
			hold := make(chan struct{})
			var holdOnce sync.Once
			releaseHold := func() { holdOnce.Do(func() { close(hold) }) }
			defer releaseHold()

			outPort := freePort(t)
			inPort := freePort(t)
			var sem chan struct{}
			if tc.sem > 0 {
				sem = make(chan struct{}, tc.sem)
			}
			ready := make(chan struct{})
			p := &Proxy{
				outboundAddr: fmt.Sprintf("127.0.0.1:%d", outPort),
				inboundAddr:  fmt.Sprintf("127.0.0.1:%d", inPort),
				serverTLS:    serverTLS,
				clientTLS:    clientTLS,
				nodeIP:       "127.0.0.1",
				inboundPort:  inPort,
				resolver:     &staticResolver{nodeIP: "127.0.0.1"},
				origDstFunc: func(net.Conn) (string, error) {
					<-hold
					return "", errors.New("held connection released")
				},
				logger:         testLogger(),
				metrics:        m,
				bufPool:        newBufPool(0),
				connSem:        sem,
				maxConnsPerSrc: tc.perSrc,
				drainTimeout:   200 * time.Millisecond,
				onReady:        func() { close(ready) },
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runDone := make(chan error, 1)
			go func() { runDone <- p.Run(ctx) }()
			select {
			case <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("proxy never became ready")
			}

			conn1, err := net.Dial("tcp", p.outboundAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn1.Close()
			// Wait until the first handler is actually holding its slot.
			assertEventually(t, 5*time.Second, func() bool {
				return testutil.ToFloat64(m.activeConnections.WithLabelValues("outbound")) >= 1
			}, "first connection never reached the handler")

			conn2, err := net.Dial("tcp", p.outboundAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn2.Close()
			assertEventually(t, 5*time.Second, func() bool { return tc.counter(m) >= 1 }, "limit rejection never counted")

			releaseHold()
			cancel()
			select {
			case <-runDone:
			case <-time.After(10 * time.Second):
				t.Fatal("proxy Run did not stop")
			}
		})
	}
}

func TestInGuestResolverInvalidIPs(t *testing.T) {
	r := &inGuestResolver{podIP: "10.42.0.5"}
	if node, local := r.Resolve("not-an-ip"); node != "not-an-ip" || local {
		t.Errorf("Resolve(bad) = (%q,%v)", node, local)
	}
	if r.ValidateLocalDest("not-an-ip") {
		t.Error("ValidateLocalDest(bad) = true")
	}
}

func TestRecordOutboundDestRejectedUnknownReason(t *testing.T) {
	m := testMetrics()
	m.recordOutboundDestRejected("some-new-reason")
	if got := testutil.ToFloat64(m.outboundDestRejected.WithLabelValues(outboundRejectUnknownPod)); got != 1 {
		t.Errorf("unknown reason not folded into unknown_pod bucket: %v", got)
	}
}

func TestIntOrDefaultAndWrapIdle(t *testing.T) {
	if got := intOrDefault(0, 5); got != 5 {
		t.Errorf("intOrDefault(0,5) = %d", got)
	}
	if got := intOrDefault(3, 5); got != 3 {
		t.Errorf("intOrDefault(3,5) = %d", got)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	p := &Proxy{idleTimeout: time.Second}
	if _, ok := p.wrapIdle(a).(*idleConn); !ok {
		t.Error("wrapIdle should wrap when idleTimeout > 0")
	}
	p2 := &Proxy{}
	if p2.wrapIdle(a) != a {
		t.Error("wrapIdle should be a no-op when idleTimeout == 0")
	}
}

func TestNewInGuestCommandFailsWithoutEnv(t *testing.T) {
	for _, k := range []string{envWorkloadID, envCDSURL, envAttestationServiceURL, envLogLevel, envPlatform, envPodIP, envCDSMeasurements, envMeshMeasurements, envInboundPassthrough} {
		t.Setenv(k, "")
	}
	cmd := newInGuestCommand()
	cmd.SetArgs(nil)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), envWorkloadID) {
		t.Fatalf("in-guest without env: err = %v, want %s requirement", err, envWorkloadID)
	}
}

func TestRunInGuestConfigErrors(t *testing.T) {
	valid := func() inGuestConfig {
		c := defaultInGuestConfig()
		c.workloadID = "wl"
		c.cdsURL = "http://127.0.0.1:1"
		c.attestationServiceURL = defaultInGuestAttestationServiceURL
		c.podIP = "10.42.0.9"
		return c
	}

	t.Run("bad log level", func(t *testing.T) {
		c := valid()
		c.logLevel = "shouty"
		if err := runInGuest(context.Background(), &c); err == nil || !strings.Contains(err.Error(), envLogLevel) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("validate failure", func(t *testing.T) {
		c := valid()
		c.workloadID = ""
		if err := runInGuest(context.Background(), &c); err == nil || !strings.Contains(err.Error(), envWorkloadID) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad pod IP", func(t *testing.T) {
		c := valid()
		c.podIP = "not-an-ip"
		if err := runInGuest(context.Background(), &c); err == nil || !strings.Contains(err.Error(), "resolve pod IP") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("iptables setup failure", func(t *testing.T) {
		// PATH without any iptables binary.
		t.Setenv("PATH", t.TempDir())
		c := valid()
		if err := runInGuest(context.Background(), &c); err == nil || !strings.Contains(err.Error(), "in-guest iptables setup") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad platform", func(t *testing.T) {
		installFakeNetfilter(t)
		c := valid()
		c.platform = "frobnitz"
		if err := runInGuest(context.Background(), &c); err == nil || !strings.Contains(err.Error(), "unsupported --platform") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad cds measurements", func(t *testing.T) {
		installFakeNetfilter(t)
		c := valid()
		c.cdsMeasurements = "zz"
		if err := runInGuest(context.Background(), &c); err == nil || !strings.Contains(err.Error(), envCDSMeasurements) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bad mesh measurements", func(t *testing.T) {
		installFakeNetfilter(t)
		c := valid()
		c.meshMeasurements = "zz"
		if err := runInGuest(context.Background(), &c); err == nil || !strings.Contains(err.Error(), envMeshMeasurements) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestRunInGuestFullLifecycle(t *testing.T) {
	installFakeNetfilter(t)

	cds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer cds.Close()

	c := defaultInGuestConfig()
	c.workloadID = "wl-test"
	c.cdsURL = cds.URL
	c.attestationServiceURL = "http://127.0.0.1:1"
	c.platform = "sev-snp"
	c.podIP = "10.42.0.9"
	c.logLevel = "error"
	c.cdsMeasurements = strings.Repeat("ab", 48)
	c.inboundPassthrough = "tcp:8443"
	c.rotationTimeout = 300 * time.Millisecond
	c.cdsRetryBackoff = 20 * time.Millisecond
	c.cdsRetryMaxBackoff = 40 * time.Millisecond
	c.cdsOpTimeout = 500 * time.Millisecond
	c.caPollInterval = 20 * time.Millisecond
	c.drainTimeout = time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runInGuest(ctx, &c) }()

	liveURL := fmt.Sprintf("http://127.0.0.1:%d/live", inGuestHealthPort)
	assertEventually(t, 10*time.Second, func() bool {
		resp, err := http.Get(liveURL)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "in-guest health server never came up")

	// Let the CA refresh ticker and the CDS retry loop take a few laps.
	time.Sleep(80 * time.Millisecond)

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runInGuest() = %v, want nil on cancel", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runInGuest did not shut down")
	}
}

func TestRunInGuestCDSUpgradeProviderError(t *testing.T) {
	// A config missing NodeIP makes provider creation fail; the goroutine
	// must log and return rather than panic or retry.
	c := defaultInGuestConfig()
	badCfg := &cdsclient.Config{
		CDSURL:            "http://127.0.0.1:1",
		AttestationApiURL: "http://127.0.0.1:1",
		CDSCAURL:          "http://127.0.0.1:1",
		// NodeIP intentionally missing.
	}
	done := make(chan struct{})
	go func() {
		runInGuestCDSUpgrade(context.Background(), testLogger(), &c, badCfg, nil, nil, testMetrics())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runInGuestCDSUpgrade did not return on provider error")
	}
}
