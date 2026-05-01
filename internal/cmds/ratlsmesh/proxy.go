package ratlsmesh

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver maps pod IPs to node IPs for routing RA-TLS connections.
type Resolver interface {
	Resolve(podIP string) (nodeIP string, local bool, err error)
	// ValidateLocalDest returns true if ip is a valid destination for
	// inbound traffic on this node (i.e. a pod running here).
	ValidateLocalDest(ip string) bool
}

// Proxy is a transparent L4 TCP proxy that wraps inter-node traffic in RA-TLS
// mTLS. Outbound (:15001) intercepts app traffic and initiates RA-TLS to the
// remote node. Inbound (:15006) accepts RA-TLS from remote nodes and delivers
// to the local pod.
type Proxy struct {
	outboundAddr string
	inboundAddr  string
	serverTLS    *tls.Config
	clientTLS    *tls.Config
	nodeIP       string
	inboundPort  int
	resolver     Resolver
	origDstFunc  func(net.Conn) (string, error)
	logger       *slog.Logger
	metrics      *metrics
	accessLog    bool

	dialTimeout       time.Duration
	tlsDialTimeout    time.Duration
	destHeaderTimeout time.Duration
	drainTimeout      time.Duration
	keepAlive         time.Duration
	idleTimeout       time.Duration

	maxDestHeaderSize int
	pipeBufferSize    int
	bufPool           *sync.Pool

	connSem        chan struct{} // nil = unlimited
	maxConnsPerSrc int           // 0 = unlimited
	srcConnsMu     sync.Mutex
	srcConns       map[string]*atomic.Int64
	onReady        func()
	onShutdown     func()
	activeConns    sync.WaitGroup
	nextConnID     atomic.Uint64
}

func durOrDefault(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

func intOrDefault(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

// accessLogEntry holds flat fields for a structured per-connection access log.
type accessLogEntry struct {
	connID       uint64
	dir          string // "inbound", "outbound", "outbound_local"
	src          string
	dst          string
	node         string // remote node address (outbound-ratls only)
	local        string // local listener address
	bytesFwd     int64
	bytesRev     int64
	dur          time.Duration
	tlsHandshake time.Duration
	ttfb         time.Duration // time to first byte (accept → pipe start)
	certMode     string        // "self-signed" or "assam"
	result       string        // success, route_error, dial_error, tls_error, header_error, dest_rejected
	err          string
}

// logTo emits the access log entry via slog.Info if access logging is enabled.
func (e *accessLogEntry) logTo(log *slog.Logger, enabled bool) {
	if !enabled {
		return
	}
	attrs := []any{
		"conn_id", e.connID,
		"dir", e.dir,
		"src", e.src,
		"dst", e.dst,
		"bytes_fwd", e.bytesFwd,
		"bytes_rev", e.bytesRev,
		"dur", e.dur.Round(time.Microsecond),
		"cert_mode", e.certMode,
		"result", e.result,
	}
	if e.node != "" {
		attrs = append(attrs, "node", e.node)
	}
	if e.local != "" {
		attrs = append(attrs, "local", e.local)
	}
	if e.tlsHandshake > 0 {
		attrs = append(attrs, "tls_handshake", e.tlsHandshake.Round(time.Microsecond))
	}
	if e.ttfb > 0 {
		attrs = append(attrs, "ttfb", e.ttfb.Round(time.Microsecond))
	}
	if e.err != "" {
		attrs = append(attrs, "error", e.err)
	}
	log.Info("access", attrs...)
}

// certModeStr returns the current certificate mode as a string.
func (p *Proxy) certModeStr() string {
	if p.metrics.certMode.Load() == 1 {
		return "assam"
	}
	return "self-signed"
}

// histLabels returns the pre-formatted label string for histogram observation.
// The full label set is enumerable (3 directions × 2 cert modes), so each
// branch returns a constant — no allocation in the per-connection hot path.
func histLabels(dir, certMode string) string {
	assam := certMode == "assam"
	switch dir {
	case "outbound":
		if assam {
			return `direction="outbound",cert_mode="assam"`
		}
		return `direction="outbound",cert_mode="self-signed"`
	case "outbound_local":
		if assam {
			return `direction="outbound_local",cert_mode="assam"`
		}
		return `direction="outbound_local",cert_mode="self-signed"`
	case "inbound":
		if assam {
			return `direction="inbound",cert_mode="assam"`
		}
		return `direction="inbound",cert_mode="self-signed"`
	}
	return fmt.Sprintf(`direction="%s",cert_mode="%s"`, dir, certMode)
}

// Run starts both listeners and blocks until ctx is cancelled. On shutdown it
// waits for in-flight connections to drain (up to drainTimeout).
func (p *Proxy) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	outReady := make(chan struct{})
	inReady := make(chan struct{})

	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := p.serve(ctx, p.outboundAddr, nil, p.handleOutbound, outReady, &p.metrics.acceptConsecutiveOutbound); err != nil {
			errCh <- fmt.Errorf("outbound: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := p.serve(ctx, p.inboundAddr, p.serverTLS, p.handleInbound, inReady, &p.metrics.acceptConsecutiveInbound); err != nil {
			errCh <- fmt.Errorf("inbound: %w", err)
		}
	}()

	// Signal readiness after both listeners are bound.
	go func() {
		<-outReady
		<-inReady
		if p.onReady != nil {
			p.onReady()
		}
	}()

	<-ctx.Done()

	// Signal not-ready immediately so K8s stops routing traffic.
	if p.onShutdown != nil {
		p.onShutdown()
	}

	// Wait for listeners to close.
	wg.Wait()

	// Drain active connections with timeout.
	done := make(chan struct{})
	go func() { p.activeConns.Wait(); close(done) }()

	select {
	case <-done:
		p.logger.Info("all connections drained")
	case <-time.After(durOrDefault(p.drainTimeout, 30*time.Second)):
		p.logger.Warn("drain timeout exceeded, forcing shutdown")
	}

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// serve is the generic listen/accept loop. If tlsCfg is non-nil the listener
// is wrapped with TLS. The ready channel is closed once the listener is bound.
// consecutiveErrors is an atomic counter exposed as a metric for readiness gating.
func (p *Proxy) serve(ctx context.Context, addr string, tlsCfg *tls.Config, handler func(context.Context, net.Conn), ready chan<- struct{}, consecutiveErrors *atomic.Int64) error {
	ln, err := (&net.ListenConfig{
		KeepAlive: durOrDefault(p.keepAlive, 30*time.Second),
	}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}

	p.logger.Info("listener ready", "addr", ln.Addr(), "tls", tlsCfg != nil)
	close(ready)

	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			n := consecutiveErrors.Add(1)
			p.metrics.acceptErrors.Add(1)
			p.logger.Warn("accept error", "addr", addr, "error", err, "consecutive", n)

			// Exponential backoff: 5ms, 10ms, 20ms, … capped at 640ms.
			backoff := 5 * time.Millisecond
			for i := int64(1); i < n && i < 8; i++ {
				backoff *= 2
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		consecutiveErrors.Store(0)

		// Global connection limit: reject if at capacity.
		if p.connSem != nil {
			select {
			case p.connSem <- struct{}{}:
			default:
				p.metrics.connLimitRejected.Add(1)
				p.logger.Warn("connection limit reached", "addr", addr)
				conn.Close()
				continue
			}
		}

		// Per-source connection limit: reject if a single source exceeds its budget.
		var (
			srcKey string
			srcCnt *atomic.Int64
		)
		if p.maxConnsPerSrc > 0 {
			srcKey, _, _ = net.SplitHostPort(conn.RemoteAddr().String())
			if srcKey == "" {
				srcKey = conn.RemoteAddr().String()
			}
			cnt, ok := p.tryAcquireSrc(srcKey)
			if !ok {
				p.metrics.connLimitPerSourceRejected.Add(1)
				p.logger.Warn("per-source connection limit reached", "src", srcKey, "addr", addr)
				if p.connSem != nil {
					<-p.connSem
				}
				conn.Close()
				continue
			}
			srcCnt = cnt
		}

		p.activeConns.Add(1)
		go func() {
			defer func() {
				if srcCnt != nil {
					p.releaseSrc(srcKey, srcCnt)
				}
				if p.connSem != nil {
					<-p.connSem
				}
				p.activeConns.Done()
			}()
			handler(ctx, conn)
		}()
	}
}

func (p *Proxy) handleOutbound(ctx context.Context, downstream net.Conn) {
	defer downstream.Close()
	p.metrics.activeOutbound.Add(1)
	defer p.metrics.activeOutbound.Add(-1)
	connID := p.nextConnID.Add(1)
	log := p.logger.With("conn", connID)
	start := time.Now()
	cm := p.certModeStr()

	entry := &accessLogEntry{
		connID:   connID,
		src:      downstream.RemoteAddr().String(),
		local:    downstream.LocalAddr().String(),
		certMode: cm,
		result:   "success",
	}
	defer func() {
		entry.dur = time.Since(start)
		labels := histLabels(entry.dir, cm)
		p.metrics.connectionDuration.Observe(labels, entry.dur.Seconds())
		entry.logTo(log, p.accessLog)
	}()

	origDst, err := p.origDstFunc(downstream)
	if err != nil {
		p.metrics.routeErrors.Add(1)
		entry.dir = "outbound"
		entry.result = "route_error"
		entry.err = err.Error()
		log.Warn("failed to get original destination", "error", err)
		return
	}
	entry.dst = origDst

	host, _, err := net.SplitHostPort(origDst)
	if err != nil {
		p.metrics.routeErrors.Add(1)
		entry.dir = "outbound"
		entry.result = "route_error"
		entry.err = err.Error()
		log.Warn("invalid original destination", "dst", origDst, "error", err)
		return
	}

	nodeIP, local, err := p.resolver.Resolve(host)
	if err != nil {
		p.metrics.routeErrors.Add(1)
		entry.dir = "outbound"
		entry.result = "route_error"
		entry.err = err.Error()
		log.Warn("resolve failed", "podIP", host, "error", err)
		return
	}

	if local {
		entry.dir = "outbound_local"
		pipeStart := time.Now()
		fwd, rev := p.dialAndPipe(ctx, downstream, origDst, log)
		entry.ttfb = pipeStart.Sub(start)
		entry.bytesFwd = fwd.N
		entry.bytesRev = rev.N
		if fwd.Err != nil || rev.Err != nil {
			entry.result = "dial_error"
			if fwd.Err != nil {
				entry.err = fwd.Err.Error()
			} else {
				entry.err = rev.Err.Error()
			}
		}
		p.metrics.timeToFirstByte.Observe(histLabels("outbound_local", cm), entry.ttfb.Seconds())
		p.recordOutbound(fwd, rev, true)
		return
	}

	entry.dir = "outbound"
	remoteAddr := net.JoinHostPort(nodeIP, strconv.Itoa(p.inboundPort))
	entry.node = remoteAddr
	pipeStart := time.Now()
	fwd, rev, tlsDur := p.dialAndPipeRATLS(ctx, downstream, remoteAddr, origDst, log)
	entry.ttfb = pipeStart.Sub(start)
	entry.tlsHandshake = tlsDur
	entry.bytesFwd = fwd.N
	entry.bytesRev = rev.N
	if fwd.Err != nil || rev.Err != nil {
		if tlsDur == 0 {
			entry.result = "tls_error"
		} else {
			entry.result = "dial_error"
		}
		if fwd.Err != nil {
			entry.err = fwd.Err.Error()
		} else {
			entry.err = rev.Err.Error()
		}
	}
	labels := histLabels("outbound", cm)
	if tlsDur > 0 {
		p.metrics.tlsHandshakeDuration.Observe(labels, tlsDur.Seconds())
	}
	p.metrics.timeToFirstByte.Observe(labels, entry.ttfb.Seconds())
	p.recordOutbound(fwd, rev, false)
}

// dialAndPipe dials addr over plain TCP and pipes bytes to/from downstream.
func (p *Proxy) dialAndPipe(ctx context.Context, downstream net.Conn, addr string, log *slog.Logger) (fwd, rev pipeResult) {
	upstream, err := (&net.Dialer{
		Timeout:   durOrDefault(p.dialTimeout, 5*time.Second),
		KeepAlive: durOrDefault(p.keepAlive, 30*time.Second),
	}).DialContext(ctx, "tcp", addr)
	if err != nil {
		p.metrics.dialFailures.Add(1)
		log.Warn("dial failed", "addr", addr, "error", err)
		fwd.Err = err
		rev.Err = err
		return
	}
	defer upstream.Close()
	return p.pipe(p.wrapIdle(downstream), p.wrapIdle(upstream))
}

// dialAndPipeRATLS dials via RA-TLS, sends the destination header, then pipes.
// Returns the TLS handshake duration as the third value (zero if handshake failed).
func (p *Proxy) dialAndPipeRATLS(ctx context.Context, downstream net.Conn, remoteAddr, destHeader string, log *slog.Logger) (fwd, rev pipeResult, tlsHandshakeDur time.Duration) {
	tlsStart := time.Now()
	upstream, err := (&tls.Dialer{
		Config: p.clientTLS,
		NetDialer: &net.Dialer{
			Timeout:   durOrDefault(p.tlsDialTimeout, 10*time.Second),
			KeepAlive: durOrDefault(p.keepAlive, 30*time.Second),
		},
	}).DialContext(ctx, "tcp", remoteAddr)
	if err != nil {
		p.metrics.tlsDialFailures.Add(1)
		log.Warn("RA-TLS dial failed", "node", remoteAddr, "error", err)
		fwd.Err = err
		rev.Err = err
		return
	}
	tlsHandshakeDur = time.Since(tlsStart)
	defer upstream.Close()

	if tlsConn, ok := upstream.(*tls.Conn); ok && tlsConn.ConnectionState().DidResume {
		p.metrics.tlsSessionResumptions.Add(1)
	}

	if _, err := fmt.Fprintf(upstream, "%s\n", destHeader); err != nil {
		p.metrics.destHeaderWriteErrors.Add(1)
		log.Warn("destination header write failed", "error", err)
		fwd.Err = err
		rev.Err = err
		return
	}

	fwd, rev = p.pipe(p.wrapIdle(downstream), p.wrapIdle(upstream))
	return
}

func (p *Proxy) handleInbound(ctx context.Context, downstream net.Conn) {
	defer downstream.Close()
	p.metrics.activeInbound.Add(1)
	defer p.metrics.activeInbound.Add(-1)
	connID := p.nextConnID.Add(1)
	log := p.logger.With("conn", connID)
	start := time.Now()
	cm := p.certModeStr()

	entry := &accessLogEntry{
		connID:   connID,
		dir:      "inbound",
		src:      downstream.RemoteAddr().String(),
		local:    downstream.LocalAddr().String(),
		certMode: cm,
		result:   "success",
	}
	defer func() {
		entry.dur = time.Since(start)
		labels := histLabels("inbound", cm)
		p.metrics.connectionDuration.Observe(labels, entry.dur.Seconds())
		entry.logTo(log, p.accessLog)
	}()

	// Bounded read with deadline to prevent slow-loris and OOM.
	if err := downstream.SetReadDeadline(time.Now().Add(durOrDefault(p.destHeaderTimeout, 5*time.Second))); err != nil {
		log.Warn("failed to set read deadline", "error", err)
		entry.result = "header_error"
		entry.err = err.Error()
		return
	}

	// Bound the header read so ReadString cannot allocate beyond the limit,
	// even if a malicious peer sends infinite bytes without '\n'.
	maxHeader := intOrDefault(p.maxDestHeaderSize, 256)
	lr := &io.LimitedReader{R: downstream, N: int64(maxHeader + 1)}
	reader := bufio.NewReader(lr)
	dstLine, err := reader.ReadString('\n')
	if err != nil {
		p.metrics.destHeaderReadErrors.Add(1)
		log.Warn("failed to read destination header", "error", err)
		entry.result = "header_error"
		entry.err = err.Error()
		return
	}

	if len(dstLine) > maxHeader {
		p.metrics.destHeaderReadErrors.Add(1)
		log.Warn("destination header too large", "size", len(dstLine))
		entry.result = "header_error"
		entry.err = "header too large"
		return
	}

	// Lift the read limit for the relay phase. Any bytes already buffered
	// by reader are preserved; subsequent reads go to downstream via lr.
	lr.N = math.MaxInt64

	// Clear deadline for the data relay phase.
	if err := downstream.SetReadDeadline(time.Time{}); err != nil {
		log.Warn("failed to clear read deadline", "error", err)
		entry.result = "header_error"
		entry.err = err.Error()
		return
	}

	dst := strings.TrimSpace(dstLine)
	entry.dst = dst
	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		p.metrics.destHeaderReadErrors.Add(1)
		log.Warn("invalid destination header", "dst", dst, "error", err)
		entry.result = "header_error"
		entry.err = err.Error()
		return
	}

	if !p.resolver.ValidateLocalDest(host) {
		p.metrics.inboundDestRejected.Add(1)
		log.Warn("inbound destination rejected: not a local pod", "dst", dst)
		entry.result = "dest_rejected"
		return
	}

	pipeStart := time.Now()
	upstream, err := (&net.Dialer{
		Timeout:   durOrDefault(p.dialTimeout, 5*time.Second),
		KeepAlive: durOrDefault(p.keepAlive, 30*time.Second),
	}).DialContext(ctx, "tcp", dst)
	if err != nil {
		p.metrics.dialFailures.Add(1)
		log.Warn("local pod dial failed", "dst", dst, "error", err)
		entry.result = "dial_error"
		entry.err = err.Error()
		return
	}
	defer upstream.Close()

	entry.ttfb = pipeStart.Sub(start)
	labels := histLabels("inbound", cm)
	p.metrics.timeToFirstByte.Observe(labels, entry.ttfb.Seconds())

	fwd, rev := p.pipe(p.wrapIdle(&bufferedConn{downstream, reader}), p.wrapIdle(upstream))
	entry.bytesFwd = fwd.N
	entry.bytesRev = rev.N
	if fwd.Err != nil || rev.Err != nil {
		entry.result = "dial_error"
		if fwd.Err != nil {
			entry.err = fwd.Err.Error()
		} else {
			entry.err = rev.Err.Error()
		}
	}
	p.recordInbound(fwd, rev)
}

func (p *Proxy) recordOutbound(fwd, rev pipeResult, local bool) {
	p.metrics.bytesOutboundFwd.Add(fwd.N)
	p.metrics.bytesOutboundRev.Add(rev.N)
	if local {
		if fwd.Err != nil || rev.Err != nil {
			p.metrics.connErrorLocal.Add(1)
		} else {
			p.metrics.connSuccessLocal.Add(1)
		}
		return
	}
	if fwd.Err != nil || rev.Err != nil {
		p.metrics.connErrorOutbound.Add(1)
	} else {
		p.metrics.connSuccessOutbound.Add(1)
	}
}

func (p *Proxy) recordInbound(fwd, rev pipeResult) {
	p.metrics.bytesInboundFwd.Add(fwd.N)
	p.metrics.bytesInboundRev.Add(rev.N)
	if fwd.Err != nil || rev.Err != nil {
		p.metrics.connErrorInbound.Add(1)
	} else {
		p.metrics.connSuccessInbound.Add(1)
	}
}

// wrapIdle wraps a connection with idle timeout if configured.
func (p *Proxy) wrapIdle(c net.Conn) net.Conn {
	if p.idleTimeout > 0 {
		return &idleConn{Conn: c, idle: p.idleTimeout}
	}
	return c
}

// idleConn resets read/write deadlines on every I/O operation. If no data
// flows for the configured duration, the OS closes the connection.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// bufferedConn wraps a net.Conn with a bufio.Reader so bytes consumed while
// reading the destination header are not lost.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

var _ net.Conn = (*bufferedConn)(nil)

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// pipeResult holds the byte count and error for one direction of a pipe.
type pipeResult struct {
	N   int64
	Err error
}

func newBufPool(size int) *sync.Pool {
	if size <= 0 {
		size = 32 * 1024
	}
	return &sync.Pool{
		New: func() any {
			b := make([]byte, size)
			return &b
		},
	}
}

// tryAcquireSrc reserves a slot for srcIP under the maxConnsPerSrc budget.
// On success returns the counter that the caller must hand to releaseSrc;
// on failure (limit hit) returns nil, false.
//
// The mutex serialises increment-and-create with releaseSrc's
// decrement-and-delete so no goroutine ever holds a counter that has been
// removed from the map (which would otherwise race connection limits).
func (p *Proxy) tryAcquireSrc(srcIP string) (*atomic.Int64, bool) {
	p.srcConnsMu.Lock()
	defer p.srcConnsMu.Unlock()
	if p.srcConns == nil {
		p.srcConns = make(map[string]*atomic.Int64)
	}
	cnt, ok := p.srcConns[srcIP]
	if !ok {
		cnt = &atomic.Int64{}
		p.srcConns[srcIP] = cnt
	}
	if int(cnt.Add(1)) > p.maxConnsPerSrc {
		cnt.Add(-1)
		return nil, false
	}
	return cnt, true
}

// releaseSrc returns a slot to the budget and removes the map entry when
// the source has no in-flight connections, keeping srcConns bounded.
func (p *Proxy) releaseSrc(srcIP string, cnt *atomic.Int64) {
	p.srcConnsMu.Lock()
	defer p.srcConnsMu.Unlock()
	if cnt.Add(-1) > 0 {
		return
	}
	if existing, ok := p.srcConns[srcIP]; ok && existing == cnt {
		delete(p.srcConns, srcIP)
	}
}

// pipe copies bytes bidirectionally until both directions are done.
func (p *Proxy) pipe(a, b net.Conn) (fwd, rev pipeResult) {
	pool := p.bufPool
	if pool == nil {
		pool = newBufPool(0)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn, r *pipeResult) {
		defer wg.Done()
		bufp := pool.Get().(*[]byte)
		r.N, r.Err = io.CopyBuffer(dst, src, *bufp)
		pool.Put(bufp)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		}
	}
	go cp(a, b, &fwd)
	go cp(b, a, &rev)
	wg.Wait()
	return
}
