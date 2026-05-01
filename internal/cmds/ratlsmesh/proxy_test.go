package ratlsmesh

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lunal-dev/c8s/pkg/ratls"
)

// staticResolver treats loopback and the node's own IP as local;
// everything else is remote (using the pod IP as the node address).
// Used only in tests — production requires the k8s resolver.
type staticResolver struct {
	nodeIP string
}

func (r *staticResolver) Resolve(podIP string) (string, bool, error) {
	if podIP == r.nodeIP || podIP == "127.0.0.1" || podIP == "::1" {
		return r.nodeIP, true, nil
	}
	return podIP, false, nil
}

func (r *staticResolver) ValidateLocalDest(ip string) bool { return true }

// fakeAttestFunc builds a fake SNP report from the hex-encoded REPORTDATA.
// Suitable for TLS plumbing tests without AMD hardware.
func fakeAttestFunc(_ context.Context, customData string) (string, error) {
	var rd [64]byte
	fmt.Sscanf(customData, "%x", &rd)
	return string(fakeSNPReport(rd)), nil
}

// fakeSNPReport creates a minimal fake SEV-SNP report (1184 bytes).
func fakeSNPReport(reportData [64]byte) []byte {
	report := make([]byte, ratls.SNPReportSize)
	report[0] = 0x02
	report[0x0A] = 0x03
	copy(report[0x50:], reportData[:])
	return report
}

// testTLSConfigs creates server+client TLS configs for testing. Uses
// InsecureSkipVerify because fake reports lack valid AMD signatures.
func testTLSConfigs(t *testing.T) (server, client *tls.Config) {
	t.Helper()

	serverCfg, _, err := ratls.NewServerTLSConfig(&ratls.ServerConfig{
		Platform:   "sev-snp",
		AttestFunc: fakeAttestFunc,
		DNSNames:   []string{"localhost"},
		CertTTL:    1 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Don't require client certs in tests (fake reports can't pass verification).
	serverCfg.ClientAuth = tls.NoClientCert
	serverCfg.VerifyPeerCertificate = nil

	clientCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	return serverCfg, clientCfg
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testMetrics() *metrics {
	return newMetrics()
}

// startBackend creates a TCP server that echoes "hello from <name>".
func startBackend(t *testing.T, name string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				fmt.Fprintf(conn, "hello from %s (got %q)", name, buf[:n])
			}()
		}
	}()
	return ln.Addr().String()
}

func TestPipe(t *testing.T) {
	// Echo server as the "upstream" end.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	// Proxy that pipes a frontend connection to the echo server.
	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer frontLn.Close()
	go func() {
		front, err := frontLn.Accept()
		if err != nil {
			return
		}
		defer front.Close()
		back, err := net.Dial("tcp", echoLn.Addr().String())
		if err != nil {
			return
		}
		defer back.Close()
		(&Proxy{}).pipe(front, back)
	}()

	// Client sends a message through the pipe and reads it back.
	conn, err := net.Dial("tcp", frontLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := "test message"
	fmt.Fprint(conn, msg)
	conn.(*net.TCPConn).CloseWrite()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Errorf("got %q, want %q", got, msg)
	}
}

func TestInboundHandler(t *testing.T) {
	backend := startBackend(t, "backend")
	serverTLS, _ := testTLSConfigs(t)

	p := &Proxy{
		inboundAddr: "127.0.0.1:0",
		serverTLS:   serverTLS,
		resolver:    &staticResolver{nodeIP: "127.0.0.1"},
		logger:      testLogger(),
		metrics:     testMetrics(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start inbound listener manually to get the actual port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)
	defer ln.Close()

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Connect as RA-TLS client, send destination header, then data.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\n", backend)
	fmt.Fprint(conn, "ping")
	conn.CloseWrite()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	want := `hello from backend (got "ping")`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestOutboundLocal(t *testing.T) {
	backend := startBackend(t, "local-pod")

	host, _, _ := net.SplitHostPort(backend)

	p := &Proxy{
		nodeIP:      host,
		inboundPort: 15006,
		resolver:    &staticResolver{nodeIP: host},
		origDstFunc: func(_ net.Conn) (string, error) { return backend, nil },
		logger:      testLogger(),
		metrics:     testMetrics(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start outbound listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleOutbound(ctx, conn)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "ping")
	conn.(*net.TCPConn).CloseWrite()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	want := `hello from local-pod (got "ping")`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEndToEnd(t *testing.T) {
	// Simulates: app → node1 outbound → RA-TLS → node2 inbound → backend.
	backend := startBackend(t, "remote-pod")
	serverTLS, clientTLS := testTLSConfigs(t)

	// Node 2: inbound listener.
	node2Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer node2Ln.Close()
	node2TLSLn := tls.NewListener(node2Ln, serverTLS)
	_, node2PortStr, _ := net.SplitHostPort(node2Ln.Addr().String())

	node2 := &Proxy{logger: testLogger(), metrics: testMetrics(), resolver: &staticResolver{nodeIP: "127.0.0.1"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			conn, err := node2TLSLn.Accept()
			if err != nil {
				return
			}
			go node2.handleInbound(ctx, conn)
		}
	}()

	// Node 1: outbound proxy.
	var node2Port int
	fmt.Sscanf(node2PortStr, "%d", &node2Port)

	node1 := &Proxy{
		nodeIP:      "1.1.1.1", // Different from backend host → treated as remote.
		inboundPort: node2Port,
		clientTLS:   clientTLS,
		resolver: &staticResolver{
			nodeIP: "1.1.1.1",
		},
		origDstFunc: func(_ net.Conn) (string, error) { return backend, nil },
		logger:      testLogger(),
		metrics:     testMetrics(),
	}

	// The resolver returns backendHost as the "node IP" for the remote pod.
	// Since backendHost != nodeIP ("1.1.1.1"), it's treated as remote.
	// The outbound handler will dial backendHost:node2Port via RA-TLS.

	node1Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer node1Ln.Close()

	go func() {
		for {
			conn, err := node1Ln.Accept()
			if err != nil {
				return
			}
			go node1.handleOutbound(ctx, conn)
		}
	}()

	// App connects to node1 outbound.
	conn, err := net.Dial("tcp", node1Ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "e2e-ping")
	conn.(*net.TCPConn).CloseWrite()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	want := `hello from remote-pod (got "e2e-ping")`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestConcurrentConnections(t *testing.T) {
	backend := startBackend(t, "concurrent")
	serverTLS, clientTLS := testTLSConfigs(t)

	inboundLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inboundLn.Close()
	tlsLn := tls.NewListener(inboundLn, serverTLS)

	p := &Proxy{logger: testLogger(), metrics: testMetrics(), resolver: &staticResolver{nodeIP: "127.0.0.1"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)

	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := tls.Dial("tcp", inboundLn.Addr().String(), clientTLS)
			if err != nil {
				errs[idx] = err
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("msg-%d", idx)
			fmt.Fprintf(conn, "%s\n%s", backend, msg)
			conn.CloseWrite()

			got, err := io.ReadAll(conn)
			if err != nil {
				errs[idx] = err
				return
			}
			want := fmt.Sprintf("hello from concurrent (got %q)", msg)
			if string(got) != want {
				errs[idx] = fmt.Errorf("got %q, want %q", got, want)
			}
		}(i)
	}

	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}

func TestDestHeaderTimeout(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)

	p := &Proxy{
		inboundAddr:       "127.0.0.1:0",
		serverTLS:         serverTLS,
		destHeaderTimeout: 200 * time.Millisecond,
		resolver:          &staticResolver{nodeIP: "127.0.0.1"},
		logger:            testLogger(),
		metrics:           testMetrics(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)
	defer ln.Close()

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Connect but never send the destination header.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// The server should close the connection after destHeaderTimeout.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed by server, got data")
	}
}

func TestInvalidDestination(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)

	p := &Proxy{
		inboundAddr:       "127.0.0.1:0",
		serverTLS:         serverTLS,
		destHeaderTimeout: 5 * time.Second,
		resolver:          &staticResolver{nodeIP: "127.0.0.1"},
		logger:            testLogger(),
		metrics:           testMetrics(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)
	defer ln.Close()

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Send an invalid destination header (no port).
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "no-port\n")
	conn.CloseWrite()

	// Server should reject and close without sending data.
	got, _ := io.ReadAll(conn)
	if len(got) != 0 {
		t.Errorf("expected empty response for invalid dest, got %q", got)
	}
}

func TestGracefulDrain(t *testing.T) {
	backend := startBackend(t, "drain")
	serverTLS, _ := testTLSConfigs(t)

	p := &Proxy{
		inboundAddr:  "127.0.0.1:0",
		serverTLS:    serverTLS,
		drainTimeout: 5 * time.Second,
		resolver:     &staticResolver{nodeIP: "127.0.0.1"},
		logger:       testLogger(),
		metrics:      testMetrics(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)

	// Track active connections through the proxy.
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			p.activeConns.Add(1)
			go func() {
				defer p.activeConns.Done()
				p.handleInbound(ctx, conn)
			}()
		}
	}()

	// Establish a connection that will be in-flight during shutdown.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Send destination header + data.
	fmt.Fprintf(conn, "%s\n", backend)
	fmt.Fprint(conn, "drain-test")

	// Wait for the handler to complete the backend dial and start piping.
	// Without this, DialContext would fail on the already-cancelled context.
	time.Sleep(100 * time.Millisecond)

	// Cancel context (simulate shutdown) while connection is active.
	cancel()
	ln.Close()

	// The in-flight connection should still complete.
	conn.CloseWrite()
	got, err := io.ReadAll(conn)
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	want := `hello from drain (got "drain-test")`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// activeConns should drain within timeout.
	done := make(chan struct{})
	go func() { p.activeConns.Wait(); close(done) }()
	select {
	case <-done:
		// OK
	case <-time.After(3 * time.Second):
		t.Fatal("active connections did not drain")
	}
}

func TestStaticResolver(t *testing.T) {
	r := &staticResolver{nodeIP: "10.0.0.1"}

	tests := []struct {
		podIP     string
		wantNode  string
		wantLocal bool
	}{
		{"10.0.0.1", "10.0.0.1", true},      // node IP = local
		{"127.0.0.1", "10.0.0.1", true},     // loopback = local
		{"::1", "10.0.0.1", true},           // IPv6 loopback = local
		{"10.244.1.5", "10.244.1.5", false}, // unknown = remote
	}

	for _, tt := range tests {
		nodeIP, local, err := r.Resolve(tt.podIP)
		if err != nil {
			t.Errorf("Resolve(%q) error: %v", tt.podIP, err)
			continue
		}
		if nodeIP != tt.wantNode || local != tt.wantLocal {
			t.Errorf("Resolve(%q) = (%q, %v), want (%q, %v)",
				tt.podIP, nodeIP, local, tt.wantNode, tt.wantLocal)
		}
	}
}

func TestIPv6RemoteAddr(t *testing.T) {
	// Verify that IPv6 node IPs produce valid host:port addresses.
	p := &Proxy{
		inboundPort: 15006,
		nodeIP:      "2001:db8::1",
		resolver:    &staticResolver{nodeIP: "1.1.1.1"}, // force remote path
		origDstFunc: func(_ net.Conn) (string, error) {
			return "[2001:db8::2]:8080", nil
		},
		logger:  testLogger(),
		metrics: testMetrics(),
	}

	// The staticResolver returns podIP as nodeIP for remote. With an IPv6
	// pod IP, net.JoinHostPort must produce a bracketed address.
	nodeIP, local, _ := p.resolver.Resolve("2001:db8::2")
	if local {
		t.Fatal("expected remote")
	}
	addr := net.JoinHostPort(nodeIP, "15006")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) failed: %v", addr, err)
	}
	if host != "2001:db8::2" || port != "15006" {
		t.Errorf("got host=%q port=%q, want 2001:db8::2 / 15006", host, port)
	}
}

func TestConnectionLimit(t *testing.T) {
	backend := startBackend(t, "limited")
	serverTLS, _ := testTLSConfigs(t)

	m := testMetrics()
	p := &Proxy{
		serverTLS: serverTLS,
		resolver:  &staticResolver{nodeIP: "127.0.0.1"},
		logger:    testLogger(),
		metrics:   m,
		connSem:   make(chan struct{}, 1), // limit to 1 concurrent
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLS)

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}

			// Simulate the connection limit check from serve().
			select {
			case p.connSem <- struct{}{}:
			default:
				p.metrics.connLimitRejected.Add(1)
				conn.Close()
				continue
			}

			p.activeConns.Add(1)
			go func() {
				defer func() {
					<-p.connSem
					p.activeConns.Done()
				}()
				p.handleInbound(ctx, conn)
			}()
		}
	}()

	// First connection: should succeed.
	conn1, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn1, "%s\n", backend)

	// Give the handler time to start.
	time.Sleep(50 * time.Millisecond)

	// Second connection: should be rejected (limit=1, one in-flight).
	// Server closes the raw TCP connection before TLS handshake, so
	// tls.Dial itself may fail — that's the expected rejection.
	conn2, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	if err == nil {
		// If TLS handshake somehow completed, the read should still fail.
		conn2.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, err = conn2.Read(make([]byte, 1))
		if err == nil {
			t.Error("expected rejected connection to be closed")
		}
		conn2.Close()
	}

	// Finish first connection.
	fmt.Fprint(conn1, "done")
	conn1.CloseWrite()
	io.ReadAll(conn1)
	conn1.Close()

	if rejected := m.connLimitRejected.Load(); rejected == 0 {
		t.Error("expected connLimitRejected > 0")
	}
}

func TestIdleTimeout(t *testing.T) {
	// Create two connected pipes and wrap one end with idleConn.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	idle := &idleConn{Conn: server, idle: 100 * time.Millisecond}

	// Write should succeed immediately.
	go func() {
		idle.Write([]byte("hello"))
	}()
	buf := make([]byte, 10)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("got %q, want %q", buf[:n], "hello")
	}

	// After idle period, read on the idle-wrapped conn should timeout.
	time.Sleep(150 * time.Millisecond)
	_, err = idle.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected timeout error after idle period")
	}
}

func TestRouteErrorMetrics(t *testing.T) {
	m := testMetrics()
	p := &Proxy{
		nodeIP:      "10.0.0.1",
		inboundPort: 15006,
		resolver:    &staticResolver{nodeIP: "10.0.0.1"},
		origDstFunc: func(_ net.Conn) (string, error) {
			return "", fmt.Errorf("simulated SO_ORIGINAL_DST failure")
		},
		logger:  testLogger(),
		metrics: m,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleOutbound(ctx, conn)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(50 * time.Millisecond)

	if m.routeErrors.Load() == 0 {
		t.Error("expected routeErrors > 0 after origDst failure")
	}
}

func TestDestHeaderReadErrorMetrics(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)

	m := testMetrics()
	p := &Proxy{
		serverTLS:         serverTLS,
		destHeaderTimeout: 5 * time.Second,
		resolver:          &staticResolver{nodeIP: "127.0.0.1"},
		logger:            testLogger(),
		metrics:           m,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLS)

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Send an invalid destination header (no port).
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "no-port\n")
	conn.CloseWrite()
	io.ReadAll(conn)
	conn.Close()

	time.Sleep(50 * time.Millisecond)

	if m.destHeaderReadErrors.Load() == 0 {
		t.Error("expected destHeaderReadErrors > 0 after invalid header")
	}
}

func TestReadinessOnShutdown(t *testing.T) {
	m := testMetrics()
	health := newHealthServer(m, nil, nil, 10, 5*time.Second, 10*time.Second)

	p := &Proxy{
		outboundAddr: "127.0.0.1:0",
		inboundAddr:  "127.0.0.1:0",
		logger:       testLogger(),
		metrics:      m,
		onReady:      func() { health.ready.Store(true) },
		onShutdown:   func() { health.ready.Store(false) },
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	// Wait for ready.
	deadline := time.After(2 * time.Second)
	for !health.ready.Load() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for ready")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Shutdown.
	cancel()
	<-done

	if health.ready.Load() {
		t.Fatal("health.ready should be false after shutdown")
	}
}

func TestMetricsAccounting(t *testing.T) {
	backend := startBackend(t, "metrics")
	serverTLS, _ := testTLSConfigs(t)

	m := testMetrics()
	p := &Proxy{
		serverTLS: serverTLS,
		resolver:  &staticResolver{nodeIP: "127.0.0.1"},
		logger:    testLogger(),
		metrics:   m,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLS)

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Send a request through the inbound handler.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	fmt.Fprintf(conn, "%s\n", backend)
	fmt.Fprint(conn, "metrics-test")
	conn.CloseWrite()
	io.ReadAll(conn)
	conn.Close()

	// Allow metrics to be recorded.
	time.Sleep(50 * time.Millisecond)

	if m.connSuccessInbound.Load() == 0 {
		t.Error("expected connSuccessInbound > 0")
	}
	if m.bytesInboundFwd.Load() == 0 {
		t.Error("expected bytesInboundFwd > 0")
	}
	if m.bytesInboundRev.Load() == 0 {
		t.Error("expected bytesInboundRev > 0")
	}
}

func TestDialFailureMetrics(t *testing.T) {
	m := testMetrics()
	p := &Proxy{
		nodeIP:      "10.0.0.1",
		inboundPort: 15006,
		resolver:    &staticResolver{nodeIP: "10.0.0.1"},
		origDstFunc: func(_ net.Conn) (string, error) {
			// Return an address that will definitely fail to dial.
			return "127.0.0.1:1", nil
		},
		dialTimeout: 100 * time.Millisecond,
		logger:      testLogger(),
		metrics:     m,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleOutbound(ctx, conn)
		}
	}()

	// Trigger an outbound connection that will fail to dial the backend.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(200 * time.Millisecond)

	if m.dialFailures.Load() == 0 {
		t.Error("expected dialFailures > 0")
	}
	if m.connSuccessLocal.Load() != 0 {
		t.Error("expected connSuccessLocal == 0 after dial failure")
	}
	if m.connErrorLocal.Load() == 0 {
		t.Error("expected connErrorLocal > 0 after local dial failure")
	}
}

func TestRATLSDialFailureMetrics(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)

	m := testMetrics()
	p := &Proxy{
		nodeIP:      "1.1.1.1",
		inboundPort: 15006,
		clientTLS:   clientTLS,
		resolver: &staticResolver{
			nodeIP: "1.1.1.1",
		},
		origDstFunc: func(_ net.Conn) (string, error) {
			// Remote pod IP resolves to itself (not local).
			return "10.244.1.5:8080", nil
		},
		tlsDialTimeout: 100 * time.Millisecond,
		logger:         testLogger(),
		metrics:        m,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleOutbound(ctx, conn)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(200 * time.Millisecond)

	if m.tlsDialFailures.Load() == 0 {
		t.Error("expected tlsDialFailures > 0")
	}
	if m.connSuccessOutbound.Load() != 0 {
		t.Error("expected connSuccessOutbound == 0 after RA-TLS dial failure")
	}
	if m.connErrorOutbound.Load() == 0 {
		t.Error("expected connErrorOutbound > 0 after RA-TLS dial failure")
	}
}

func TestAcceptLoopBackoff(t *testing.T) {
	m := testMetrics()
	p := &Proxy{
		outboundAddr: "127.0.0.1:0",
		inboundAddr:  "127.0.0.1:0",
		logger:       testLogger(),
		metrics:      m,
		onReady:      func() {},
		onShutdown:   func() {},
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	// Wait briefly for listeners to bind.
	time.Sleep(100 * time.Millisecond)

	// Cancel to shut down. The accept loop should exit cleanly.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}

	// After clean shutdown, acceptErrors should be 0.
	if got := m.acceptErrors.Load(); got != 0 {
		t.Errorf("acceptErrors = %d after clean shutdown, want 0", got)
	}
}

// rejectResolver rejects all destinations as non-local.
type rejectResolver struct{}

func (r *rejectResolver) Resolve(podIP string) (string, bool, error) { return podIP, false, nil }
func (r *rejectResolver) ValidateLocalDest(ip string) bool           { return false }

func TestInboundDestRejected(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)

	m := testMetrics()
	p := &Proxy{
		serverTLS:         serverTLS,
		destHeaderTimeout: 5 * time.Second,
		resolver:          &rejectResolver{},
		logger:            testLogger(),
		metrics:           m,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLS)

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Send a valid destination header that the resolver rejects.
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "10.99.99.99:8080\n")
	conn.CloseWrite()
	io.ReadAll(conn)
	conn.Close()

	time.Sleep(50 * time.Millisecond)

	if m.inboundDestRejected.Load() == 0 {
		t.Error("expected inboundDestRejected > 0")
	}
	if m.connSuccessInbound.Load() != 0 {
		t.Error("expected no successful inbound connections")
	}
}
